use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    time::Duration,
};

pub const DEFAULT_URL: &str = "http://127.0.0.1:8042";
const MAX_HEADERS: usize = 64 * 1024;
const MAX_RESPONSE: usize = 4 * 1024 * 1024;
const REMOTE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REMOTE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const USB_FILE_REQUEST_TIMEOUT: Duration = Duration::from_secs(150);
/// Bounds how long the single event worker can remain attached to a superseded endpoint.
const REMOTE_EVENT_STREAM_LIFETIME: Duration = Duration::from_secs(20);
const MAX_EVENT_LINE_BYTES: usize = 16 * 1024;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_DAEMON_ERROR_BYTES: usize = 512;

#[derive(Debug, Deserialize)]
struct DevicesResponse {
    devices: Vec<DeviceView>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    host: String,
    port: u16,
}

impl Endpoint {
    pub fn from_url(value: &str) -> Result<Self, ApiError> {
        let authority = value
            .strip_prefix("http://")
            .ok_or_else(|| ApiError::new("API endpoint must use http://127.0.0.1"))?
            .split('/')
            .next()
            .unwrap_or_default();
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| ApiError::new("API endpoint must include a port"))?;
        if host != "127.0.0.1" {
            return Err(ApiError::new("GUI refuses non-loopback API endpoints"));
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| ApiError::new("API endpoint port is invalid"))?;
        if port == 0 {
            return Err(ApiError::new("API endpoint port must be nonzero"));
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiError(String);

impl ApiError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ApiError {}

impl From<io::Error> for ApiError {
    fn from(error: io::Error) -> Self {
        Self::new(error.to_string())
    }
}

#[derive(Clone)]
pub struct ApiClient {
    endpoint: ApiEndpoint,
    token: String,
}

#[derive(Clone)]
enum ApiEndpoint {
    Unavailable,
    Local(Endpoint),
    Remote(Box<RemoteEndpoint>),
}

#[derive(Clone)]
struct RemoteEndpoint {
    address: IpAddr,
    port: u16,
    server_name: Option<String>,
    owner_route: Option<OwnerRouteAuthority>,
    request_agent: ureq::Agent,
    stream_agent: ureq::Agent,
}

#[derive(Clone)]
struct OwnerRouteAuthority {
    owner_id: [u8; 16],
    device_id: [u8; 16],
    controller_installation_id: [u8; 16],
    gateway_installation_id: [u8; 16],
    route_proof_secret: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRouteProofResponse {
    proof: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayYieldResponse {
    pub device_id: String,
    pub status: String,
    pub yield_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayHandoffResponse {
    pub transaction_id: uuid::Uuid,
    pub phase: String,
    pub terminal: bool,
    pub target_installation_id: String,
    pub previous_installation_id: String,
    pub target_ipv4: Option<String>,
    pub target_port: Option<u16>,
    pub target_control_port: Option<u16>,
    pub readiness_nonce: Option<String>,
    pub listener_generation: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Serialize)]
struct PrepareGatewayHandoffRequest<'a> {
    transaction_id: uuid::Uuid,
    previous_gateway_installation_id: &'a str,
}

#[derive(Serialize)]
struct StartGatewayHandoffRequest<'a> {
    transaction_id: uuid::Uuid,
    endpoint_session_id: String,
    proof_digest: String,
    readiness_nonce: &'a str,
    target_ipv4: &'a str,
    target_port: u16,
    target_control_port: u16,
}

#[derive(Serialize)]
struct StartLocalGatewayHandoffRequest<'a> {
    transaction_id: uuid::Uuid,
    target_installation_id: &'a str,
    previous_installation_id: &'a str,
    target_gateway_address: String,
    readiness_nonce: &'a str,
    target_ipv4: &'a str,
    target_port: u16,
    target_control_port: u16,
}

impl ApiClient {
    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            endpoint: ApiEndpoint::Unavailable,
            token: String::new(),
        }
    }

    #[must_use]
    pub fn is_available(&self) -> bool {
        !matches!(self.endpoint, ApiEndpoint::Unavailable)
    }

    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(self.endpoint, ApiEndpoint::Local(_))
    }

    #[must_use]
    pub fn owner_gateway_installation_id(&self) -> Option<[u8; 16]> {
        match &self.endpoint {
            ApiEndpoint::Remote(remote) => remote
                .owner_route
                .as_ref()
                .map(|authority| authority.gateway_installation_id),
            ApiEndpoint::Unavailable | ApiEndpoint::Local(_) => None,
        }
    }

    pub fn new(endpoint: Endpoint, token: impl Into<String>) -> Result<Self, ApiError> {
        let token = token.into();
        if token.is_empty() || token.chars().any(char::is_whitespace) {
            return Err(ApiError::new("local bearer token is empty or malformed"));
        }
        Ok(Self {
            endpoint: ApiEndpoint::Local(endpoint),
            token,
        })
    }

    pub fn for_verified_gateway(
        proof: &crate::gateway_probe::VerifiedGatewayProof,
        address: IpAddr,
        credential: &crate::gateway_probe::GatewayCredential,
    ) -> Result<Self, ApiError> {
        if proof.payload().api_version != crate::gateway_probe::SUPPORTED_GATEWAY_API_VERSION
            || !credential.matches(proof)
            || !keyferry_gateway::is_tailscale_ip(address)
        {
            return Err(ApiError::new(
                "remote gateway credential or API version does not match the verified gateway",
            ));
        }
        Ok(Self {
            endpoint: ApiEndpoint::Remote(Box::new(RemoteEndpoint {
                address,
                port: credential.port(),
                server_name: None,
                owner_route: None,
                request_agent: remote_agent(Some(REMOTE_REQUEST_TIMEOUT), false),
                stream_agent: remote_agent(Some(REMOTE_EVENT_STREAM_LIFETIME), true),
            })),
            token: credential.remote_bearer().to_owned(),
        })
    }

    pub fn for_owner_gateway(
        address: IpAddr,
        port: u16,
        gateway_installation_id: [u8; 16],
        installation_directory: impl AsRef<Path>,
    ) -> Result<Self, ApiError> {
        if !keyferry_gateway::is_tailscale_ip(address) || port == 0 {
            return Err(ApiError::new("owner gateway route is invalid"));
        }
        let credentials = keyferry_gateway::InstallationCredentials::load(installation_directory)
            .map_err(|error| {
            ApiError::new(format!("installation credentials are invalid: {error}"))
        })?;
        Self::for_owner_gateway_credentials(address, port, gateway_installation_id, &credentials)
    }

    pub fn for_owner_gateway_credentials(
        address: IpAddr,
        port: u16,
        gateway_installation_id: [u8; 16],
        credentials: &keyferry_gateway::InstallationCredentials,
    ) -> Result<Self, ApiError> {
        if !keyferry_gateway::is_tailscale_ip(address) || port == 0 {
            return Err(ApiError::new("owner gateway route is invalid"));
        }
        let server_name = keyferry_gateway::installation_gateway_name(&gateway_installation_id)
            .map_err(|_| ApiError::new("gateway installation identity is invalid"))?;
        let request_agent = owner_remote_agent(
            Some(REMOTE_REQUEST_TIMEOUT),
            false,
            address,
            port,
            &server_name,
            credentials,
        )?;
        let stream_agent = owner_remote_agent(
            Some(REMOTE_EVENT_STREAM_LIFETIME),
            true,
            address,
            port,
            &server_name,
            credentials,
        )?;
        Ok(Self {
            endpoint: ApiEndpoint::Remote(Box::new(RemoteEndpoint {
                address,
                port,
                server_name: Some(server_name),
                owner_route: Some(OwnerRouteAuthority {
                    owner_id: credentials.owner_id(),
                    device_id: credentials.device_id(),
                    controller_installation_id: credentials.installation_id(),
                    gateway_installation_id,
                    route_proof_secret: credentials.route_proof_secret(),
                }),
                request_agent,
                stream_agent,
            })),
            token: String::new(),
        })
    }

    pub fn from_environment() -> Result<Self, ApiError> {
        let endpoint = Endpoint::from_url(
            &env::var("KEYFERRY_URL").unwrap_or_else(|_| DEFAULT_URL.to_owned()),
        )?;
        let token_path = env::var_os("KEYFERRY_TOKEN_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(default_token_path);
        let token = fs::read_to_string(&token_path).map_err(|error| {
            ApiError::new(format!(
                "cannot read local daemon token {}: {error}",
                token_path.display()
            ))
        })?;
        Self::new(endpoint, token.trim())
    }

    pub fn devices(&self) -> Result<Vec<DeviceView>, ApiError> {
        let response: DevicesResponse = self.request_json("GET", "/v1/devices", None)?;
        Ok(response.devices)
    }

    pub fn verify_owner_route(
        &self,
        device_id: &str,
    ) -> Result<Option<keyferry_gateway::SignedRouteProof>, ApiError> {
        let ApiEndpoint::Remote(remote) = &self.endpoint else {
            return Ok(None);
        };
        let Some(authority) = &remote.owner_route else {
            return Ok(None);
        };
        if device_id != device_id_text(&authority.device_id) {
            return Err(ApiError::new(
                "owner credentials do not belong to the selected device",
            ));
        }
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce)
            .map_err(|_| ApiError::new("could not generate route-proof nonce"))?;
        let started = std::time::Instant::now();
        let path = format!(
            "/v2/devices/{device_id}/route-proof?nonce={}",
            encode_lower_hex(&nonce)
        );
        let response: WireRouteProofResponse = self.request_json("GET", &path, None)?;
        verify_owner_route_response(authority, nonce, started.elapsed(), &response.proof).map(Some)
    }

    pub fn yield_gateway(&self, device_id: &str) -> Result<GatewayYieldResponse, ApiError> {
        let ApiEndpoint::Remote(remote) = &self.endpoint else {
            return Err(ApiError::new(
                "gateway transfer must be requested through the current remote gateway",
            ));
        };
        if remote.owner_route.is_none() {
            return Err(ApiError::new(
                "gateway transfer requires owner-authenticated gateway access",
            ));
        }
        self.verify_owner_route(device_id)?.ok_or_else(|| {
            ApiError::new("gateway did not return an endpoint-backed route proof")
        })?;
        device_root_path(device_id)?;
        let path = format!("/v2/devices/{device_id}/gateway/yield");
        self.request_json("POST", &path, None)
    }

    pub fn prepare_gateway_handoff(
        &self,
        device_id: &str,
        transaction_id: uuid::Uuid,
        previous_gateway_installation_id: &str,
    ) -> Result<GatewayHandoffResponse, ApiError> {
        if !self.is_local() && self.owner_gateway_installation_id().is_none() {
            return Err(ApiError::new(
                "handoff readiness requires a local or owner-authenticated destination",
            ));
        }
        let path = format!("/v1/devices/{device_id}/gateway/handoffs");
        let body = serde_json::to_value(PrepareGatewayHandoffRequest {
            transaction_id,
            previous_gateway_installation_id,
        })
        .map_err(|error| ApiError::new(error.to_string()))?;
        self.request_json("POST", &path, Some(&body))
    }

    pub fn start_gateway_handoff(
        &self,
        device_id: &str,
        prepared: &GatewayHandoffResponse,
    ) -> Result<GatewayHandoffResponse, ApiError> {
        let ApiEndpoint::Remote(remote) = &self.endpoint else {
            return Err(ApiError::new(
                "targeted handoff must start through the current remote gateway",
            ));
        };
        if remote.owner_route.is_none() {
            return Err(ApiError::new(
                "targeted handoff requires owner-authenticated gateway access",
            ));
        }
        let proof = self.verify_owner_route(device_id)?.ok_or_else(|| {
            ApiError::new("gateway did not return an endpoint-backed route proof")
        })?;
        let proof_bytes = keyferry_gateway::encode_route_proof_response(&proof.input, &proof.tag)
            .map_err(|_| ApiError::new("endpoint route proof is invalid"))?;
        let proof_digest = Sha256::digest(proof_bytes);
        let readiness_nonce = prepared
            .readiness_nonce
            .as_deref()
            .ok_or_else(|| ApiError::new("receiving gateway did not return readiness evidence"))?;
        let target_ipv4 = prepared
            .target_ipv4
            .as_deref()
            .ok_or_else(|| ApiError::new("receiving gateway did not return a LAN route"))?;
        let target_port = prepared
            .target_port
            .ok_or_else(|| ApiError::new("receiving gateway did not return a LAN port"))?;
        let target_control_port = prepared
            .target_control_port
            .ok_or_else(|| ApiError::new("receiving gateway did not return a control port"))?;
        let path = format!("/v2/devices/{device_id}/gateway/handoffs");
        let body = serde_json::to_value(StartGatewayHandoffRequest {
            transaction_id: prepared.transaction_id,
            endpoint_session_id: encode_lower_hex(&proof.input.endpoint_session_id),
            proof_digest: encode_lower_hex(&proof_digest),
            readiness_nonce,
            target_ipv4,
            target_port,
            target_control_port,
        })
        .map_err(|error| ApiError::new(error.to_string()))?;
        self.request_json("POST", &path, Some(&body))
    }

    pub fn start_local_gateway_handoff(
        &self,
        device_id: &str,
        target_address: IpAddr,
        target_installation_id: [u8; 16],
        prepared: &GatewayHandoffResponse,
    ) -> Result<GatewayHandoffResponse, ApiError> {
        if !self.is_local() {
            return Err(ApiError::new(
                "local handoff orchestration requires the current local daemon",
            ));
        }
        let expected_target = encode_lower_hex(&target_installation_id);
        if prepared.target_installation_id != expected_target {
            return Err(ApiError::new(
                "prepared handoff does not match the selected destination",
            ));
        }
        let readiness_nonce = prepared
            .readiness_nonce
            .as_deref()
            .ok_or_else(|| ApiError::new("receiving gateway did not return readiness evidence"))?;
        let target_ipv4 = prepared
            .target_ipv4
            .as_deref()
            .ok_or_else(|| ApiError::new("receiving gateway did not return a LAN route"))?;
        let target_port = prepared
            .target_port
            .ok_or_else(|| ApiError::new("receiving gateway did not return a LAN port"))?;
        let target_control_port = prepared
            .target_control_port
            .ok_or_else(|| ApiError::new("receiving gateway did not return a control port"))?;
        let path = format!("{}/gateway/outgoing-handoff", device_root_path(device_id)?);
        let body = serde_json::to_value(StartLocalGatewayHandoffRequest {
            transaction_id: prepared.transaction_id,
            target_installation_id: &prepared.target_installation_id,
            previous_installation_id: &prepared.previous_installation_id,
            target_gateway_address: target_address.to_string(),
            readiness_nonce,
            target_ipv4,
            target_port,
            target_control_port,
        })
        .map_err(|error| ApiError::new(error.to_string()))?;
        self.request_json("POST", &path, Some(&body))
    }

    pub fn gateway_handoff_status(
        &self,
        device_id: &str,
        transaction_id: uuid::Uuid,
    ) -> Result<GatewayHandoffResponse, ApiError> {
        let path = format!("/v1/devices/{device_id}/gateway/handoffs/{transaction_id}");
        self.request_json("GET", &path, None)
    }

    pub fn cancel_gateway_handoff_reservation(
        &self,
        device_id: &str,
        transaction_id: uuid::Uuid,
    ) -> Result<GatewayHandoffResponse, ApiError> {
        if !self.is_local() && self.owner_gateway_installation_id().is_none() {
            return Err(ApiError::new(
                "handoff readiness cancellation requires its authenticated destination",
            ));
        }
        let path = format!("/v1/devices/{device_id}/gateway/handoffs/{transaction_id}");
        self.request_json("POST", &path, None)
    }

    pub fn device(&self, device_id: &str) -> Result<DeviceView, ApiError> {
        let path = device_root_path(device_id)?;
        self.request_json("GET", &path, None)
    }

    pub fn output_mode(&self, device_id: &str) -> Result<OutputModeStatus, ApiError> {
        let path = device_path(device_id, "output-mode")?;
        self.request_json("GET", &path, None)
    }

    pub fn set_output_mode(
        &self,
        device_id: &str,
        mode: OutputMode,
    ) -> Result<OutputModeStatus, ApiError> {
        self.request_device_mutation(
            device_id,
            "output-mode",
            Some(&serde_json::json!({ "mode": mode })),
        )
    }

    pub fn display_orientation(
        &self,
        device_id: &str,
    ) -> Result<DisplayOrientationStatus, ApiError> {
        let path = device_path(device_id, "display-orientation")?;
        self.request_json("GET", &path, None)
    }

    pub fn set_display_orientation(
        &self,
        device_id: &str,
        orientation: DisplayOrientation,
    ) -> Result<DisplayOrientationStatus, ApiError> {
        self.request_device_mutation(
            device_id,
            "display-orientation",
            Some(&serde_json::json!({ "orientation": orientation })),
        )
    }

    pub fn screen_power(&self, device_id: &str) -> Result<ScreenPowerStatus, ApiError> {
        let path = device_path(device_id, "screen-power")?;
        let status = self.request_json("GET", &path, None)?;
        validate_screen_power_status(status, device_id, None)
    }

    pub fn set_screen_power(
        &self,
        device_id: &str,
        power: ScreenPower,
    ) -> Result<ScreenPowerStatus, ApiError> {
        let status = self.request_device_mutation(
            device_id,
            "screen-power",
            Some(&serde_json::json!({ "power": power })),
        )?;
        validate_screen_power_status(status, device_id, Some(power))
    }

    pub fn reset_ble_hid_bond(&self, device_id: &str) -> Result<BleHidBondResetStatus, ApiError> {
        self.request_device_mutation(device_id, "ble-hid-bond/reset", None)
    }

    pub(crate) fn text_stream_capabilities<T: DeserializeOwned>(&self) -> Result<T, ApiError> {
        self.request_json("GET", "/v1/capabilities", None)
    }

    pub(crate) fn create_text_stream<T: DeserializeOwned>(
        &self,
        device_id: &str,
        body: &serde_json::Value,
    ) -> Result<T, ApiError> {
        self.request_device_mutation(device_id, "text-streams", Some(body))
    }

    pub(crate) fn submit_text_stream_part<T: DeserializeOwned>(
        &self,
        device_id: &str,
        job_id: &str,
        index: u64,
        body: &serde_json::Value,
        refresh_route: bool,
    ) -> Result<T, ApiError> {
        validate_path_segment(job_id, "text stream job ID")?;
        let operation = format!("text-streams/{job_id}/parts/{index}");
        if refresh_route {
            self.request_device_mutation(device_id, &operation, Some(body))
        } else {
            let root = device_root_path(device_id)?;
            self.request_json("POST", &format!("{root}/{operation}"), Some(body))
        }
    }

    pub(crate) fn finish_text_stream<T: DeserializeOwned>(
        &self,
        device_id: &str,
        job_id: &str,
        body: &serde_json::Value,
    ) -> Result<T, ApiError> {
        validate_path_segment(job_id, "text stream job ID")?;
        self.request_device_mutation(
            device_id,
            &format!("text-streams/{job_id}/finish"),
            Some(body),
        )
    }

    pub(crate) fn text_stream_status<T: DeserializeOwned>(
        &self,
        device_id: &str,
        job_id: &str,
    ) -> Result<T, ApiError> {
        let root = device_root_path(device_id)?;
        validate_path_segment(job_id, "text stream job ID")?;
        self.request_json("GET", &format!("{root}/text-streams/{job_id}"), None)
    }

    pub(crate) fn renew_text_stream<T: DeserializeOwned>(
        &self,
        device_id: &str,
        job_id: &str,
        body: &serde_json::Value,
    ) -> Result<T, ApiError> {
        let root = device_root_path(device_id)?;
        validate_path_segment(job_id, "text stream job ID")?;
        self.request_json(
            "POST",
            &format!("{root}/text-streams/{job_id}/lease"),
            Some(body),
        )
    }

    pub(crate) fn cancel_text_stream<T: DeserializeOwned>(
        &self,
        device_id: &str,
        job_id: &str,
        body: &serde_json::Value,
    ) -> Result<T, ApiError> {
        let root = device_root_path(device_id)?;
        validate_path_segment(job_id, "text stream job ID")?;
        self.request_json(
            "POST",
            &format!("{root}/text-streams/{job_id}/cancel"),
            Some(body),
        )
    }

    pub fn submit_text(
        &self,
        device_id: &str,
        text: &str,
        profile: &str,
        timing: &str,
    ) -> Result<CommandResponse, ApiError> {
        // Owner-authenticated remote mutations require a just-in-time endpoint proof.
        // This precedes daemon admission; the daemon still preserves command-scoped
        // ARM -> COMMAND adjacency after accepting the HTTP request.
        self.request_device_mutation(
            device_id,
            "type",
            Some(&serde_json::json!({
                "text": text,
                "profile": profile,
                "timing": timing,
            })),
        )
    }

    pub fn publish_usb_file(
        &self,
        device_id: &str,
        bytes: &[u8],
    ) -> Result<UsbFileStatus, ApiError> {
        if bytes.len() > keyferry_protocol::file::MAX_FILE_BYTES {
            return Err(ApiError::new("file exceeds the USB file size limit"));
        }
        self.request_device_mutation(
            device_id,
            "file",
            Some(&serde_json::json!({ "bytes": bytes })),
        )
    }

    pub fn clear_usb_file(&self, device_id: &str) -> Result<UsbFileStatus, ApiError> {
        self.verify_owner_route(device_id)?;
        self.request_json("DELETE", &device_path(device_id, "file")?, None)
    }

    pub fn publish_usb_files(
        &self,
        device_id: &str,
        files: &[(&str, &[u8])],
    ) -> Result<UsbFileStatus, ApiError> {
        use keyferry_protocol::file_set::{validate_names, MAX_FILE_BYTES};
        let names = files.iter().map(|(name, _)| *name).collect::<Vec<_>>();
        validate_names(&names).map_err(|_| ApiError::new("invalid USB file names"))?;
        let total = files
            .iter()
            .try_fold(0usize, |total, (_, bytes)| total.checked_add(bytes.len()));
        if total.is_none_or(|total| total > MAX_FILE_BYTES) {
            return Err(ApiError::new("file set exceeds the USB drive size limit"));
        }
        let files = files
            .iter()
            .map(|(name, bytes)| serde_json::json!({"name": name, "bytes": bytes}))
            .collect::<Vec<_>>();
        self.request_device_mutation(
            device_id,
            "files",
            Some(&serde_json::json!({"files": files})),
        )
    }

    pub fn clear_usb_files(&self, device_id: &str) -> Result<UsbFileStatus, ApiError> {
        self.verify_owner_route(device_id)?;
        self.request_json("DELETE", &device_path(device_id, "files")?, None)
    }

    pub fn usb_files(&self, device_id: &str) -> Result<UsbFileStatus, ApiError> {
        self.verify_owner_route(device_id)?;
        self.request_json("GET", &device_path(device_id, "files")?, None)
    }

    pub fn submit_actions(
        &self,
        device_id: &str,
        actions: &[ActionRequest],
        profile: &str,
    ) -> Result<CommandResponse, ApiError> {
        self.request_device_mutation(
            device_id,
            "actions",
            Some(&serde_json::json!({
                "actions": actions,
                "profile": profile,
            })),
        )
    }

    pub fn submit_sequence(
        &self,
        device_id: &str,
        sequence: &keyferry_layouts::KeyboardSequenceV1,
    ) -> Result<CommandResponse, ApiError> {
        // The GUI submits the same strict model as keyctl. The daemon remains
        // the command authority and performs its own compilation and bounds checks.
        let body = serde_json::to_value(sequence)
            .map_err(|_| ApiError::new("sequence serialization failed"))?;
        self.request_device_mutation(device_id, "sequences", Some(&body))
    }

    pub fn command_outcome(
        &self,
        device_id: &str,
        command_id: &str,
    ) -> Result<CommandResponse, ApiError> {
        let path = command_path(device_id, command_id)?;
        self.request_json("GET", &path, None)
    }

    pub fn arm(
        &self,
        device_id: &str,
        policy: &str,
        lease_ms: Option<u64>,
    ) -> Result<DeviceView, ApiError> {
        let mut body = serde_json::Map::new();
        body.insert(
            "policy".to_owned(),
            serde_json::Value::String(policy.to_owned()),
        );
        if let Some(lease_ms) = lease_ms {
            body.insert(
                "lease_ms".to_owned(),
                serde_json::Value::Number(lease_ms.into()),
            );
        }
        self.request_device_mutation(device_id, "arm", Some(&serde_json::Value::Object(body)))
    }

    pub fn disarm(&self, device_id: &str) -> Result<DeviceView, ApiError> {
        self.request_device_mutation(device_id, "disarm", None)
    }

    pub fn begin_maintenance(&self, device_id: &str) -> Result<DeviceView, ApiError> {
        self.local_endpoint()?;
        let path = device_path(device_id, "maintenance/begin")?;
        self.request_json("POST", &path, None)
    }

    pub fn finish_maintenance(&self, device_id: &str) -> Result<DeviceView, ApiError> {
        self.local_endpoint()?;
        let path = device_path(device_id, "maintenance/finish")?;
        self.request_json("POST", &path, None)
    }

    pub fn cancel(
        &self,
        device_id: &str,
        command_id: Option<&str>,
    ) -> Result<CommandResponse, ApiError> {
        let body = command_id
            .map(|id| serde_json::json!({ "command_id": id }))
            .unwrap_or_else(|| serde_json::json!({}));
        self.request_device_mutation(device_id, "cancel", Some(&body))
    }

    pub fn events(&self) -> Result<EventStream, ApiError> {
        let endpoint = match &self.endpoint {
            ApiEndpoint::Unavailable => {
                return Err(ApiError::new("no daemon endpoint is selected"));
            }
            ApiEndpoint::Remote(_) => return self.remote_events(),
            ApiEndpoint::Local(endpoint) => endpoint,
        };
        let mut stream = self.connect()?;
        let request = format!(
            "GET /v1/events HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n\r\n",
            endpoint.host, self.token
        );
        stream.write_all(request.as_bytes())?;
        let headers = read_headers(&mut stream)?;
        if headers.status >= 400 {
            return Err(ApiError::new(format!(
                "daemon rejected event stream with HTTP {}",
                headers.status
            )));
        }
        Ok(EventStream {
            reader: Box::new(BufReader::new(BodyReader::new(stream, headers.chunked))),
        })
    }

    fn request_json<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<T, ApiError> {
        let response = match &self.endpoint {
            ApiEndpoint::Unavailable => {
                return Err(ApiError::new("no daemon endpoint is selected"));
            }
            ApiEndpoint::Local(_) => self.request_local(method, path, body)?,
            ApiEndpoint::Remote(_) => self.request_remote(method, path, body)?,
        };
        serde_json::from_slice(&response.body)
            .map_err(|error| ApiError::new(format!("daemon returned invalid JSON: {error}")))
    }

    fn request_device_mutation<T: DeserializeOwned>(
        &self,
        device_id: &str,
        operation: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<T, ApiError> {
        self.verify_owner_route(device_id)?;
        let path = device_path(device_id, operation)?;
        self.request_json("POST", &path, body)
    }

    fn request_local(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<HttpResponse, ApiError> {
        if !path.starts_with('/') || path.chars().any(char::is_control) {
            return Err(ApiError::new("API path is malformed"));
        }
        let body = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|error| ApiError::new(format!("cannot encode API request: {error}")))?
            .unwrap_or_default();
        let mut stream = self.connect()?;
        let content_type = if body.is_empty() {
            String::new()
        } else {
            "Content-Type: application/json\r\n".to_owned()
        };
        if path.ends_with("/file") || path.ends_with("/files") {
            stream.set_read_timeout(Some(USB_FILE_REQUEST_TIMEOUT))?;
        }
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n{content_type}\r\n",
            self.local_endpoint()?.host,
            self.token,
            body.len()
        );
        stream.write_all(request.as_bytes())?;
        stream.write_all(&body)?;
        let headers = read_headers(&mut stream)?;
        let response_body = read_body(&mut stream, &headers)?;
        let _ = stream.shutdown(Shutdown::Both);
        if headers.status >= 400 {
            if path.ends_with("/file") {
                return Err(daemon_http_error("daemon", headers.status, &response_body));
            }
            return Err(ApiError::new(format!(
                "daemon returned HTTP {}",
                headers.status
            )));
        }
        Ok(HttpResponse {
            body: response_body,
        })
    }

    fn connect(&self) -> Result<TcpStream, ApiError> {
        let endpoint = self.local_endpoint()?;
        let address = format!("{}:{}", endpoint.host, endpoint.port);
        let address = address
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| ApiError::new("loopback API address did not resolve"))?;
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(stream)
    }

    fn local_endpoint(&self) -> Result<&Endpoint, ApiError> {
        match &self.endpoint {
            ApiEndpoint::Unavailable => Err(ApiError::new("no daemon endpoint is selected")),
            ApiEndpoint::Local(endpoint) => Ok(endpoint),
            ApiEndpoint::Remote(_) => Err(ApiError::new("API endpoint is not loopback")),
        }
    }

    fn request_remote(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<HttpResponse, ApiError> {
        validate_api_path(path)?;
        let ApiEndpoint::Remote(remote) = &self.endpoint else {
            return Err(ApiError::new("API endpoint is not remote"));
        };
        let url = remote_url(
            remote.address,
            remote.port,
            remote.server_name.as_deref(),
            path,
        );
        let authorization = (!self.token.is_empty()).then(|| format!("Bearer {}", self.token));
        let timeout = if path.ends_with("/file") || path.ends_with("/files") {
            USB_FILE_REQUEST_TIMEOUT
        } else {
            REMOTE_REQUEST_TIMEOUT
        };
        let mut response = match method {
            "GET" if body.is_none() => {
                let request = remote
                    .request_agent
                    .get(&url)
                    .header("Accept", "application/json");
                match authorization.as_deref() {
                    Some(value) => request.header("Authorization", value).call(),
                    None => request.call(),
                }
            }
            "POST" => {
                let request = remote
                    .request_agent
                    .post(&url)
                    .config()
                    .timeout_global(Some(timeout))
                    .build()
                    .header("Accept", "application/json");
                let request = match authorization.as_deref() {
                    Some(value) => request.header("Authorization", value),
                    None => request,
                };
                if let Some(body) = body {
                    let body = serde_json::to_vec(body).map_err(|error| {
                        ApiError::new(format!("cannot encode API request: {error}"))
                    })?;
                    request
                        .header("Content-Type", "application/json")
                        .send(body.as_slice())
                } else {
                    request.send_empty()
                }
            }
            "DELETE" if body.is_none() => {
                let request = remote
                    .request_agent
                    .delete(&url)
                    .header("Accept", "application/json");
                match authorization.as_deref() {
                    Some(value) => request.header("Authorization", value).call(),
                    None => request.call(),
                }
            }
            _ => return Err(ApiError::new("unsupported API method")),
        }
        .map_err(|error| ApiError::new(format!("remote daemon request failed: {error}")))?;
        let status = response.status().as_u16();
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE as u64 + 1)
            .read_to_vec()
            .map_err(|error| ApiError::new(format!("remote daemon response failed: {error}")))?;
        if bytes.len() > MAX_RESPONSE {
            return Err(ApiError::new("remote daemon response exceeds limit"));
        }
        if status >= 400 {
            return Err(daemon_http_error("remote daemon", status, &bytes));
        }
        Ok(HttpResponse { body: bytes })
    }

    fn remote_events(&self) -> Result<EventStream, ApiError> {
        let ApiEndpoint::Remote(remote) = &self.endpoint else {
            return Err(ApiError::new("API endpoint is not remote"));
        };
        let url = remote_url(
            remote.address,
            remote.port,
            remote.server_name.as_deref(),
            "/v1/events",
        );
        let request = remote
            .stream_agent
            .get(&url)
            .header("Accept", "text/event-stream");
        let response = match self.token.is_empty() {
            true => request.call(),
            false => request
                .header("Authorization", &format!("Bearer {}", self.token))
                .call(),
        }
        .map_err(|error| ApiError::new(format!("remote event stream failed: {error}")))?;
        Ok(EventStream {
            reader: Box::new(BufReader::new(response.into_body().into_reader())),
        })
    }
}

#[must_use]
pub fn default_installation_path() -> PathBuf {
    if let Some(path) = env::var_os("KEYFERRY_INSTALLATION") {
        return PathBuf::from(path);
    }
    #[cfg(windows)]
    if let Some(root) = env::var_os("LOCALAPPDATA") {
        return PathBuf::from(root).join("keyferry").join("installation");
    }
    #[cfg(target_os = "macos")]
    if let Some(root) = env::var_os("HOME") {
        return PathBuf::from(root)
            .join("Library")
            .join("Application Support")
            .join("keyferry")
            .join("installation");
    }
    if let Some(root) = env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(root).join("keyferry").join("installation");
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("state")
        .join("keyferry")
        .join("installation")
}

fn device_id_text(device_id: &[u8; 16]) -> String {
    let hex = encode_lower_hex(device_id);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn decode_lower_hex(value: &str, field: &'static str) -> Result<Vec<u8>, ApiError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::new(format!(
            "{field} is not lowercase hexadecimal"
        )));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = lower_hex_nibble(pair[0])
                .ok_or_else(|| ApiError::new(format!("{field} is malformed")))?;
            let low = lower_hex_nibble(pair[1])
                .ok_or_else(|| ApiError::new(format!("{field} is malformed")))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn verify_owner_route_response(
    authority: &OwnerRouteAuthority,
    nonce: [u8; 32],
    elapsed: Duration,
    encoded_proof: &str,
) -> Result<keyferry_gateway::SignedRouteProof, ApiError> {
    if elapsed > Duration::from_millis(keyferry_gateway::ROUTE_PROOF_TTL_MS as u64) {
        return Err(ApiError::new("endpoint route proof expired"));
    }
    let bytes = decode_lower_hex(encoded_proof, "route proof")?;
    let proof = keyferry_gateway::decode_route_proof_response(&bytes)
        .map_err(|_| ApiError::new("endpoint route proof is malformed"))?;
    if proof.input.owner_id != authority.owner_id
        || proof.input.device_id != authority.device_id
        || proof.input.gateway_installation_id != authority.gateway_installation_id
        || proof.input.controller_installation_id != authority.controller_installation_id
        || proof.input.controller_nonce != nonce
    {
        return Err(ApiError::new(
            "endpoint route proof does not match the selected route",
        ));
    }
    keyferry_gateway::verify_route_proof_tag(
        &authority.route_proof_secret,
        &proof.input,
        &proof.tag,
    )
    .map_err(|_| ApiError::new("endpoint route proof authentication failed"))?;
    Ok(proof)
}

fn remote_agent(global_timeout: Option<Duration>, http_status_as_error: bool) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .https_only(false)
        .proxy(None)
        .max_redirects(0)
        .max_response_header_size(MAX_HEADERS)
        .http_status_as_error(http_status_as_error)
        .timeout_connect(Some(REMOTE_CONNECT_TIMEOUT));
    let config = if let Some(timeout) = global_timeout {
        config
            .timeout_global(Some(timeout))
            .timeout_recv_body(Some(timeout))
    } else {
        config
    };
    config.build().into()
}

#[derive(Debug)]
struct FixedTailnetResolver {
    server_name: String,
    address: IpAddr,
    port: u16,
}

impl ureq::unversioned::resolver::Resolver for FixedTailnetResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        if uri.scheme_str() != Some("https")
            || uri.host() != Some(self.server_name.as_str())
            || uri.port_u16().unwrap_or(443) != self.port
        {
            return Err(ureq::Error::HostNotFound);
        }
        let mut addresses = self.empty();
        addresses.push(SocketAddr::new(self.address, self.port));
        Ok(addresses)
    }
}

fn owner_remote_agent(
    global_timeout: Option<Duration>,
    http_status_as_error: bool,
    address: IpAddr,
    port: u16,
    server_name: &str,
    credentials: &keyferry_gateway::InstallationCredentials,
) -> Result<ureq::Agent, ApiError> {
    use ureq::tls::{Certificate, ClientCert, PrivateKey, RootCerts, TlsConfig, TlsProvider};
    use ureq::unversioned::transport::DefaultConnector;

    let client_certificate =
        Certificate::from_der(credentials.desktop_client_certificate_der()).to_owned();
    let private_key_pem = rcgen::KeyPair::try_from(credentials.installation_key_der())
        .map_err(|_| ApiError::new("installation private key is invalid"))?
        .serialize_pem();
    let private_key = PrivateKey::from_pem(private_key_pem.as_bytes())
        .map_err(|_| ApiError::new("installation private key is invalid"))?;
    let owner_root = Certificate::from_der(credentials.owner_ca_der()).to_owned();
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256];
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .client_cert(Some(ClientCert::new_with_certs(
            &[client_certificate],
            private_key,
        )))
        .root_certs(RootCerts::new_with_certs(&[owner_root]))
        .unversioned_rustls_crypto_provider(std::sync::Arc::new(provider))
        .build();
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .max_response_header_size(MAX_HEADERS)
        .http_status_as_error(http_status_as_error)
        .timeout_connect(Some(REMOTE_CONNECT_TIMEOUT))
        .tls_config(tls);
    let config = if let Some(timeout) = global_timeout {
        config
            .timeout_global(Some(timeout))
            .timeout_recv_body(Some(timeout))
    } else {
        config
    };
    Ok(ureq::Agent::with_parts(
        config.build(),
        DefaultConnector::default(),
        FixedTailnetResolver {
            server_name: server_name.to_owned(),
            address,
            port,
        },
    ))
}

fn remote_url(address: IpAddr, port: u16, server_name: Option<&str>, path: &str) -> String {
    match server_name {
        Some(server_name) => format!("https://{server_name}:{port}{path}"),
        None => format!("http://{}:{port}{path}", url_host(address)),
    }
}

fn daemon_http_error(origin: &str, status: u16, body: &[u8]) -> ApiError {
    let detail = (body.len() <= MAX_DAEMON_ERROR_BYTES)
        .then(|| serde_json::from_slice::<serde_json::Value>(body).ok())
        .flatten()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|error| error.as_str())
                .map(str::to_owned)
        })
        .filter(|error| {
            !error.is_empty()
                && error.len() <= MAX_DAEMON_ERROR_BYTES
                && !error.chars().any(char::is_control)
        });
    match detail {
        Some(detail) => ApiError::new(format!("{origin} returned HTTP {status}: {detail}")),
        None => ApiError::new(format!("{origin} returned HTTP {status}")),
    }
}

fn url_host(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
    }
}

fn validate_api_path(path: &str) -> Result<(), ApiError> {
    if !path.starts_with('/') || path.chars().any(char::is_control) {
        return Err(ApiError::new("API path is malformed"));
    }
    Ok(())
}

fn device_path(device_id: &str, operation: &str) -> Result<String, ApiError> {
    Ok(format!("{}/{operation}", device_root_path(device_id)?))
}

fn device_root_path(device_id: &str) -> Result<String, ApiError> {
    if device_id.is_empty()
        || device_id.len() > 128
        || device_id
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)))
    {
        return Err(ApiError::new(
            "device ID contains unsupported path characters",
        ));
    }
    Ok(format!("/v1/devices/{device_id}"))
}

fn command_path(device_id: &str, command_id: &str) -> Result<String, ApiError> {
    let root = device_root_path(device_id)?;
    if command_id.is_empty()
        || command_id.len() > 128
        || command_id
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)))
    {
        return Err(ApiError::new(
            "command ID contains unsupported path characters",
        ));
    }
    Ok(format!("{root}/commands/{command_id}"))
}

fn validate_path_segment(value: &str, label: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)))
    {
        return Err(ApiError::new(format!(
            "{label} contains unsupported path characters"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct DeviceView {
    pub id: String,
    pub label: String,
    pub transport: String,
    #[serde(default)]
    pub link_path: Option<String>,
    #[serde(default)]
    pub via: Option<String>,
    pub link: String,
    #[serde(default)]
    pub usb: Option<String>,
    pub mode: String,
    pub armed: bool,
    #[serde(default)]
    pub maintenance: bool,
    pub arm_policy: String,
    #[serde(default)]
    pub active_host: Option<String>,
    #[serde(default)]
    pub firmware: Option<FirmwareView>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub active_command_id: Option<String>,
    #[serde(default)]
    pub active_outcome: Option<CommandOutcome>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct FirmwareView {
    pub endpoint: String,
    #[serde(default)]
    pub ble_hid_output_v1: bool,
    #[serde(default)]
    pub ble_hid_bond_reset_v1: bool,
    #[serde(default)]
    pub targeted_gateway_transfer_v1: bool,
    #[serde(default)]
    pub display_orientation_v1: bool,
    #[serde(default)]
    pub screen_power_v1: bool,
    #[serde(default)]
    pub usb_file_handoff_v1: bool,
    #[serde(default)]
    pub usb_file_set_v2: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UsbFileEntry {
    pub name: String,
    pub size: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UsbFileStatus {
    pub state: String,
    pub size_bytes: usize,
    pub received_bytes: usize,
    pub max_size_bytes: usize,
    #[serde(default)]
    pub bundle_size_bytes: usize,
    #[serde(default)]
    pub bundle_received_bytes: usize,
    #[serde(default)]
    pub files: Vec<UsbFileEntry>,
    #[serde(default)]
    pub max_files: usize,
    #[serde(default)]
    pub max_name_bytes: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputMode {
    UsbHid,
    BleHid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OutputModeStatus {
    pub schema: String,
    pub device_id: String,
    pub active: OutputMode,
    pub stored: OutputMode,
    pub restart_pending: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DisplayOrientation {
    Normal,
    #[serde(rename = "rotated-180")]
    Rotated180,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DisplayOrientationStatus {
    pub schema: String,
    pub device_id: String,
    pub active: DisplayOrientation,
    pub stored: DisplayOrientation,
    pub restart_pending: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScreenPower {
    Off,
    On,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScreenPowerStatus {
    pub schema: String,
    pub device_id: String,
    pub active: ScreenPower,
    pub stored: ScreenPower,
    pub available: bool,
}

fn validate_screen_power_status(
    status: ScreenPowerStatus,
    device_id: &str,
    requested: Option<ScreenPower>,
) -> Result<ScreenPowerStatus, ApiError> {
    if status.schema != "keyferry.screen-power.v1" || status.device_id != device_id {
        return Err(ApiError::new(
            "screen-power response named the wrong schema or device",
        ));
    }
    if requested.is_some_and(|power| status.stored != power) {
        return Err(ApiError::new(
            "screen-power response did not retain the requested setting",
        ));
    }
    Ok(status)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BleHidBondResetStatus {
    pub schema: String,
    pub device_id: String,
    pub bond_was_present: bool,
    pub restart_pending: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CommandResponse {
    pub command_id: String,
    pub device_id: String,
    #[serde(alias = "state")]
    pub outcome: CommandOutcome,
    pub message: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum CommandOutcome {
    Queued,
    Accepted,
    Started,
    Emitted,
    Aborted,
    Rejected,
    Unknown,
}

impl CommandOutcome {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Emitted | Self::Aborted | Self::Rejected | Self::Unknown
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct EventRecord {
    pub command_id: String,
    #[serde(default)]
    pub caller: String,
    pub device_id: String,
    pub profile: String,
    pub action_count: usize,
    pub char_count: usize,
    pub timestamp: String,
    pub duration_ms: Option<u64>,
    #[serde(alias = "state")]
    pub outcome: CommandOutcome,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(tag = "type")]
pub enum ActionRequest {
    #[serde(rename = "text")]
    Text {
        value: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        key_down_ms: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        release_gap_ms: Option<u16>,
    },
    #[serde(rename = "tap")]
    Tap {
        key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        key_down_ms: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        release_gap_ms: Option<u16>,
    },
    #[serde(rename = "chord")]
    Chord {
        keys: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        key_down_ms: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        release_gap_ms: Option<u16>,
    },
}

#[derive(Debug)]
enum ValidatedKey {
    Modifier(&'static str),
    Key(String),
}

impl ActionRequest {
    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text {
            value: value.into(),
            key_down_ms: None,
            release_gap_ms: None,
        }
    }

    pub fn tap(key: &str) -> Result<Self, ApiError> {
        let ValidatedKey::Key(key) = validate_key_name(key)? else {
            return Err(ApiError::new(
                "tap key must be a non-modifier key; use a named key or printable US-ASCII character",
            ));
        };
        Ok(Self::Tap {
            key,
            key_down_ms: None,
            release_gap_ms: None,
        })
    }

    pub fn chord(keys: Vec<String>) -> Result<Self, ApiError> {
        let mut non_modifier_seen = false;
        let mut modifier_names = Vec::new();
        let mut non_modifier = None;
        for key in keys {
            match validate_key_name(&key)? {
                ValidatedKey::Modifier(name) => {
                    if modifier_names.contains(&name) {
                        return Err(ApiError::new("chord modifier names must be unique"));
                    }
                    modifier_names.push(name);
                }
                ValidatedKey::Key(name) => {
                    if non_modifier_seen {
                        return Err(ApiError::new(
                            "chord requires modifiers plus exactly one non-modifier key",
                        ));
                    }
                    non_modifier_seen = true;
                    non_modifier = Some(name);
                }
            }
        }
        let Some(non_modifier) = non_modifier else {
            return Err(ApiError::new(
                "chord requires modifiers plus exactly one non-modifier key",
            ));
        };
        let mut normalized = modifier_names
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        normalized.push(non_modifier);
        Ok(Self::Chord {
            keys: normalized,
            key_down_ms: None,
            release_gap_ms: None,
        })
    }
}

fn validate_key_name(name: &str) -> Result<ValidatedKey, ApiError> {
    if name.is_empty() {
        return Err(ApiError::new("key name is empty"));
    }
    let uppercase = name.to_ascii_uppercase();
    let value = match uppercase.as_str() {
        "CTRL" | "CONTROL" => ValidatedKey::Modifier("CTRL"),
        "SHIFT" => ValidatedKey::Modifier("SHIFT"),
        "ALT" | "OPTION" => ValidatedKey::Modifier("ALT"),
        "GUI" | "META" | "WIN" | "SUPER" | "CMD" => ValidatedKey::Modifier("GUI"),
        "ENTER" | "RETURN" => ValidatedKey::Key("ENTER".to_owned()),
        "ESC" | "ESCAPE" => ValidatedKey::Key("ESC".to_owned()),
        "BACKSPACE" => ValidatedKey::Key("BACKSPACE".to_owned()),
        "TAB" => ValidatedKey::Key("TAB".to_owned()),
        "SPACE" => ValidatedKey::Key("SPACE".to_owned()),
        _ => {
            let mut characters = name.chars();
            let Some(character) = characters.next() else {
                return Err(ApiError::new("key name is empty"));
            };
            if characters.next().is_some() || !((' '..='~').contains(&character)) {
                return Err(ApiError::new(
                    "unsupported key name; use a supported modifier, named key, or printable US-ASCII character",
                ));
            }
            let canonical = if character == ' ' {
                "SPACE".to_owned()
            } else if character.is_ascii_alphabetic() {
                character.to_ascii_uppercase().to_string()
            } else {
                character.to_string()
            };
            ValidatedKey::Key(canonical)
        }
    };
    Ok(value)
}

pub struct EventStream {
    reader: Box<dyn BufRead + Send>,
}

impl EventStream {
    pub fn next_event(&mut self) -> Result<Option<EventRecord>, ApiError> {
        self.next_event_while(|| true)
    }

    pub fn next_event_while(
        &mut self,
        mut keep_reading: impl FnMut() -> bool,
    ) -> Result<Option<EventRecord>, ApiError> {
        let mut data = Vec::new();
        let mut data_bytes = 0_usize;
        loop {
            if !keep_reading() {
                return Ok(None);
            }
            let Some(line) = read_bounded_line(&mut *self.reader, MAX_EVENT_LINE_BYTES)? else {
                return Ok(None);
            };
            if !keep_reading() {
                return Ok(None);
            }
            let line = std::str::from_utf8(&line)
                .map_err(|_| ApiError::new("event stream line is not UTF-8"))?
                .trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                if data.is_empty() {
                    continue;
                }
                let event =
                    serde_json::from_str::<EventRecord>(&data.join("\n")).map_err(|error| {
                        ApiError::new(format!("event stream contained invalid JSON: {error}"))
                    })?;
                return Ok(Some(event));
            }
            if let Some(value) = line.strip_prefix("data:") {
                data_bytes = data_bytes.saturating_add(value.len() + 1);
                if data_bytes > MAX_EVENT_BYTES {
                    return Err(ApiError::new("event stream event exceeds limit"));
                }
                data.push(value.trim_start().to_owned());
            }
        }
    }
}

fn read_bounded_line(reader: &mut dyn BufRead, limit: usize) -> Result<Option<Vec<u8>>, ApiError> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len() + count > limit {
            return Err(ApiError::new("event stream line exceeds limit"));
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if line.ends_with(b"\n") {
            return Ok(Some(line));
        }
    }
}

struct HttpResponse {
    body: Vec<u8>,
}

struct ResponseHeaders {
    status: u16,
    chunked: bool,
    content_length: Option<usize>,
}

fn read_headers(stream: &mut TcpStream) -> Result<ResponseHeaders, ApiError> {
    let mut bytes = Vec::new();
    let mut one = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut one)?;
        bytes.push(one[0]);
        if bytes.len() > MAX_HEADERS {
            return Err(ApiError::new("HTTP headers exceed 64 KiB"));
        }
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| ApiError::new("HTTP headers are not UTF-8"))?;
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| ApiError::new("malformed HTTP status line"))?;
    let mut chunked = false;
    let mut content_length = None;
    for line in text.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.trim().eq_ignore_ascii_case("chunked")
        {
            chunked = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| ApiError::new("invalid HTTP content length"))?,
            );
        }
    }
    Ok(ResponseHeaders {
        status,
        chunked,
        content_length,
    })
}

fn read_body(stream: &mut TcpStream, headers: &ResponseHeaders) -> Result<Vec<u8>, ApiError> {
    if headers.chunked {
        return decode_chunked_stream(stream);
    }
    let mut body = Vec::new();
    if let Some(length) = headers.content_length {
        if length > MAX_RESPONSE {
            return Err(ApiError::new("HTTP response exceeds 4 MiB"));
        }
        let mut limited = stream.take(length as u64);
        limited.read_to_end(&mut body)?;
        if body.len() != length {
            return Err(ApiError::new("truncated HTTP response"));
        }
    } else {
        stream
            .take((MAX_RESPONSE + 1) as u64)
            .read_to_end(&mut body)?;
        if body.len() > MAX_RESPONSE {
            return Err(ApiError::new("HTTP response exceeds 4 MiB"));
        }
    }
    Ok(body)
}

fn decode_chunked_stream(stream: &mut TcpStream) -> Result<Vec<u8>, ApiError> {
    let mut output = Vec::new();
    loop {
        let line = read_crlf_line(stream)?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16)
            .map_err(|_| ApiError::new("malformed chunk size"))?;
        if size == 0 {
            let _ = read_crlf_line(stream)?;
            break;
        }
        if output.len().saturating_add(size) > MAX_RESPONSE {
            return Err(ApiError::new("HTTP response exceeds 4 MiB"));
        }
        let old_len = output.len();
        output.resize(old_len + size, 0);
        stream.read_exact(&mut output[old_len..])?;
        let delimiter = read_exact_two(stream)?;
        if delimiter != *b"\r\n" {
            return Err(ApiError::new("malformed chunk delimiter"));
        }
    }
    Ok(output)
}

fn read_crlf_line(stream: &mut TcpStream) -> Result<String, ApiError> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    while !line.ends_with(b"\r\n") {
        stream.read_exact(&mut byte)?;
        line.push(byte[0]);
        if line.len() > MAX_HEADERS {
            return Err(ApiError::new("HTTP line exceeds 64 KiB"));
        }
    }
    String::from_utf8(line[..line.len() - 2].to_vec())
        .map_err(|_| ApiError::new("HTTP line is not UTF-8"))
}

fn read_exact_two(stream: &mut TcpStream) -> Result<[u8; 2], ApiError> {
    let mut bytes = [0_u8; 2];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

struct BodyReader {
    stream: TcpStream,
    chunked: bool,
    remaining: usize,
    needs_delimiter: bool,
    finished: bool,
}

impl BodyReader {
    fn new(stream: TcpStream, chunked: bool) -> Self {
        Self {
            stream,
            chunked,
            remaining: 0,
            needs_delimiter: false,
            finished: false,
        }
    }
}

impl Read for BodyReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.chunked {
            return self.stream.read(buffer);
        }
        if self.finished || buffer.is_empty() {
            return Ok(0);
        }
        if self.needs_delimiter {
            let mut delimiter = [0_u8; 2];
            self.stream.read_exact(&mut delimiter)?;
            if delimiter != *b"\r\n" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed chunk delimiter",
                ));
            }
            self.needs_delimiter = false;
        }
        if self.remaining == 0 {
            let line = read_crlf_line(&mut self.stream)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            self.remaining =
                usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "malformed chunk size")
                    })?;
            if self.remaining == 0 {
                self.finished = true;
                return Ok(0);
            }
        }
        let requested = buffer.len().min(self.remaining);
        let count = self.stream.read(&mut buffer[..requested])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated event stream chunk",
            ));
        }
        self.remaining -= count;
        if self.remaining == 0 {
            self.needs_delimiter = true;
        }
        Ok(count)
    }
}

fn default_token_path() -> PathBuf {
    if let Ok(path) = env::var("KEYFERRY_TOKEN_FILE") {
        return PathBuf::from(path);
    }
    #[cfg(windows)]
    if let Ok(root) = env::var("LOCALAPPDATA") {
        return PathBuf::from(root).join("keyferry").join("token");
    }
    #[cfg(target_os = "macos")]
    if let Ok(root) = env::var("HOME") {
        return PathBuf::from(root)
            .join("Library")
            .join("Application Support")
            .join("keyferry")
            .join("token");
    }
    if let Ok(root) = env::var("XDG_STATE_HOME") {
        return PathBuf::from(root).join("keyferry").join("token");
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(".").to_path_buf())
        .join(".local")
        .join("state")
        .join("keyferry")
        .join("token")
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyferry_gateway::{sign_gateway_proof, verify_gateway_proof};
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
    };
    use std::{net::TcpListener, thread};

    fn test_client(listener: &TcpListener) -> ApiClient {
        let port = listener.local_addr().unwrap().port();
        ApiClient::new(
            Endpoint::from_url(&format!("http://127.0.0.1:{port}")).unwrap(),
            "test-bearer-token",
        )
        .unwrap()
    }

    fn owner_remote_test_client(listener: &TcpListener) -> ApiClient {
        let address = listener.local_addr().unwrap();
        ApiClient {
            endpoint: ApiEndpoint::Remote(Box::new(RemoteEndpoint {
                address: address.ip(),
                port: address.port(),
                server_name: None,
                owner_route: Some(OwnerRouteAuthority {
                    owner_id: [0x11; 16],
                    device_id: [0x22; 16],
                    controller_installation_id: [0x33; 16],
                    gateway_installation_id: [0x44; 16],
                    route_proof_secret: [0x55; 32],
                }),
                request_agent: remote_agent(Some(Duration::from_secs(2)), false),
                stream_agent: remote_agent(Some(Duration::from_secs(2)), true),
            })),
            token: "test-bearer-token".to_owned(),
        }
    }

    fn http_content_length(headers: &str) -> usize {
        headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap()
    }

    fn accept_http_headers(listener: &TcpListener) -> (TcpStream, String) {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        (stream, String::from_utf8(request).unwrap())
    }

    fn respond_to_owner_route_proof(
        listener: &TcpListener,
        authority: &OwnerRouteAuthority,
        expected_device_id: &str,
    ) {
        let (mut stream, request) = accept_http_headers(listener);
        let first_line = request.lines().next().unwrap();
        assert!(first_line.starts_with(&format!(
            "GET /v2/devices/{expected_device_id}/route-proof?nonce="
        )));
        let nonce_text = first_line
            .split("nonce=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap();
        let nonce_vec = decode_lower_hex(nonce_text, "nonce").unwrap();
        let mut nonce = [0_u8; 32];
        nonce.copy_from_slice(&nonce_vec);
        let input = keyferry_gateway::RouteProofInput {
            owner_id: authority.owner_id,
            device_id: authority.device_id,
            epoch: 1,
            policy_sequence: 1,
            policy_hash: [0x66; 32],
            gateway_installation_id: authority.gateway_installation_id,
            controller_installation_id: authority.controller_installation_id,
            controller_nonce: nonce,
            device_boot_nonce: [0x77; 16],
            endpoint_session_id: [0x88; 16],
            link_path: keyferry_gateway::GatewayLinkPath::Bluetooth,
            usb_ready: true,
        };
        let tag = keyferry_gateway::route_proof_tag(&authority.route_proof_secret, &input).unwrap();
        let proof = keyferry_gateway::encode_route_proof_response(&input, &tag).unwrap();
        let body = serde_json::json!({"proof": encode_lower_hex(&proof)}).to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    }

    #[test]
    fn unavailable_client_keeps_remote_only_controller_startup_fail_closed() {
        let client = ApiClient::unavailable();
        assert!(!client.is_available());
        assert!(!client.is_local());
        assert_eq!(
            client.devices().unwrap_err().to_string(),
            "no daemon endpoint is selected"
        );
        assert_eq!(
            client.events().err().unwrap().to_string(),
            "no daemon endpoint is selected"
        );
    }

    #[test]
    fn local_endpoint_kind_is_explicit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(test_client(&listener).is_local());
        assert!(!owner_remote_test_client(&listener).is_local());
    }

    #[test]
    fn maps_devices_and_preserves_authentication_and_path() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /v1/devices HTTP/1.1"));
            assert!(request.contains("Authorization: Bearer test-bearer-token\r\n"));
            let body = r#"{"devices":[{"id":"simulator-1","label":"office","transport":"tls","link_path":"bluetooth","link":"authenticated","mode":"keyboard","armed":false,"arm_policy":"command-scoped","active_command_id":null,"active_outcome":null}]}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let devices = client.devices().unwrap();
        worker.join().unwrap();
        assert_eq!(devices[0].id, "simulator-1");
        assert_eq!(devices[0].link_path.as_deref(), Some("bluetooth"));
        assert_eq!(devices[0].usb, None);
        assert_eq!(devices[0].capabilities, Vec::<String>::new());
    }

    #[test]
    fn maps_state_alias_for_command_response() {
        let response: CommandResponse = serde_json::from_str(
            r#"{"command_id":"c1","device_id":"d1","state":"UNKNOWN","message":"observe events"}"#,
        )
        .unwrap();
        assert_eq!(response.outcome, CommandOutcome::Unknown);
    }

    #[test]
    fn owner_text_submission_refreshes_route_proof_then_posts_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = owner_remote_test_client(&listener);
        let authority = match &client.endpoint {
            ApiEndpoint::Remote(remote) => remote.owner_route.clone().unwrap(),
            _ => unreachable!(),
        };
        let device_id = device_id_text(&authority.device_id);
        let expected_device_id = device_id.clone();
        let worker = thread::spawn(move || {
            respond_to_owner_route_proof(&listener, &authority, &expected_device_id);
            let (mut stream, headers) = accept_http_headers(&listener);
            assert!(headers.starts_with(&format!(
                "POST /v1/devices/{expected_device_id}/type HTTP/1.1"
            )));
            assert!(headers
                .to_ascii_lowercase()
                .contains("authorization: bearer test-bearer-token\r\n"));
            let content_length = http_content_length(&headers);
            let mut body = vec![0; content_length];
            stream.read_exact(&mut body).unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["profile"], "windows-us");
            assert_eq!(body["timing"], "desktop-safe");
            assert_eq!(body["text"], "hello");
            let response = format!(
                r#"{{"command_id":"c1","device_id":"{expected_device_id}","outcome":"QUEUED","message":null}}"#
            );
            write!(
                stream,
                "HTTP/1.1 202 Accepted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });
        let response = client
            .submit_text(&device_id, "hello", "windows-us", "desktop-safe")
            .unwrap();
        worker.join().unwrap();
        assert_eq!(response.command_id, "c1");
        assert_eq!(response.outcome, CommandOutcome::Queued);
    }

    #[test]
    fn text_stream_first_child_reuses_creation_route_and_later_children_refresh() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = owner_remote_test_client(&listener);
        let authority = match &client.endpoint {
            ApiEndpoint::Remote(remote) => remote.owner_route.clone().unwrap(),
            _ => unreachable!(),
        };
        let device_id = device_id_text(&authority.device_id);
        let expected_device_id = device_id.clone();
        let worker = thread::spawn(move || {
            let (mut stream, headers) = accept_http_headers(&listener);
            assert!(headers.starts_with(&format!(
                "POST /v1/devices/{expected_device_id}/text-streams/job-1/parts/0 HTTP/1.1"
            )));
            let content_length = http_content_length(&headers);
            let mut body = vec![0; content_length];
            stream.read_exact(&mut body).unwrap();
            let response = r#"{"ok":true}"#;
            write!(
                stream,
                "HTTP/1.1 202 Accepted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });
        let response: serde_json::Value = client
            .submit_text_stream_part(
                &device_id,
                "job-1",
                0,
                &serde_json::json!({"text":"a"}),
                false,
            )
            .unwrap();
        worker.join().unwrap();
        assert_eq!(response, serde_json::json!({"ok":true}));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = owner_remote_test_client(&listener);
        let authority = match &client.endpoint {
            ApiEndpoint::Remote(remote) => remote.owner_route.clone().unwrap(),
            _ => unreachable!(),
        };
        let device_id = device_id_text(&authority.device_id);
        let expected_device_id = device_id.clone();
        let worker = thread::spawn(move || {
            respond_to_owner_route_proof(&listener, &authority, &expected_device_id);
            let (mut stream, headers) = accept_http_headers(&listener);
            assert!(headers.starts_with(&format!(
                "POST /v1/devices/{expected_device_id}/text-streams/job-1/parts/1 HTTP/1.1"
            )));
            let content_length = http_content_length(&headers);
            let mut body = vec![0; content_length];
            stream.read_exact(&mut body).unwrap();
            let response = r#"{"ok":true}"#;
            write!(
                stream,
                "HTTP/1.1 202 Accepted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });
        let response: serde_json::Value = client
            .submit_text_stream_part(
                &device_id,
                "job-1",
                1,
                &serde_json::json!({"text":"b"}),
                true,
            )
            .unwrap();
        worker.join().unwrap();
        assert_eq!(response, serde_json::json!({"ok":true}));
    }

    #[test]
    fn command_scoped_arm_omits_a_lease() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let headers = String::from_utf8(request).unwrap();
            assert!(headers.starts_with("POST /v1/devices/device-1/arm HTTP/1.1"));
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let mut body = vec![0; content_length];
            stream.read_exact(&mut body).unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body, serde_json::json!({"policy": "command-scoped"}));

            let response = r#"{"id":"device-1","label":"test","transport":"tls","link":"authenticated","mode":"keyboard","armed":true,"arm_policy":"command-scoped","active_command_id":null,"active_outcome":null}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });

        let device = client.arm("device-1", "command-scoped", None).unwrap();
        worker.join().unwrap();
        assert!(device.armed);
        assert_eq!(device.arm_policy, "command-scoped");
    }

    #[test]
    fn output_mode_reads_and_sets_the_explicit_persistent_mode() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let worker = thread::spawn(move || {
            let (mut stream, headers) = accept_http_headers(&listener);
            assert!(headers.starts_with("GET /v1/devices/device-1/output-mode HTTP/1.1"));
            let response = r#"{"schema":"keyferry.output-mode.v1","device_id":"device-1","active":"usb-hid","stored":"usb-hid","restart_pending":false}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();

            let (mut stream, headers) = accept_http_headers(&listener);
            assert!(headers.starts_with("POST /v1/devices/device-1/output-mode HTTP/1.1"));
            let content_length = http_content_length(&headers);
            let mut body = vec![0; content_length];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"mode":"ble-hid"})
            );
            let response = r#"{"schema":"keyferry.output-mode.v1","device_id":"device-1","active":"usb-hid","stored":"ble-hid","restart_pending":true}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });

        let current = client.output_mode("device-1").unwrap();
        assert_eq!(current.active, OutputMode::UsbHid);
        let changed = client
            .set_output_mode("device-1", OutputMode::BleHid)
            .unwrap();
        worker.join().unwrap();
        assert_eq!(changed.active, OutputMode::UsbHid);
        assert_eq!(changed.stored, OutputMode::BleHid);
        assert!(changed.restart_pending);
    }

    #[test]
    fn screen_power_reads_and_sets_exact_device_without_claiming_unavailable_display() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let worker = thread::spawn(move || {
            let (mut stream, headers) = accept_http_headers(&listener);
            assert!(headers.starts_with("GET /v1/devices/device-1/screen-power HTTP/1.1"));
            let response = r#"{"schema":"keyferry.screen-power.v1","device_id":"device-1","active":"on","stored":"on","available":true}"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
            let (mut stream, headers) = accept_http_headers(&listener);
            assert!(headers.starts_with("POST /v1/devices/device-1/screen-power HTTP/1.1"));
            let mut body = vec![0; http_content_length(&headers)];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"power":"off"})
            );
            let response = r#"{"schema":"keyferry.screen-power.v1","device_id":"device-1","active":"on","stored":"off","available":false}"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
        });
        assert_eq!(
            client.screen_power("device-1").unwrap().active,
            ScreenPower::On
        );
        let changed = client
            .set_screen_power("device-1", ScreenPower::Off)
            .unwrap();
        assert_eq!(changed.stored, ScreenPower::Off);
        assert!(!changed.available);
        worker.join().unwrap();
    }

    #[test]
    fn screen_power_rejects_wrong_response_schema_device_or_stored_value() {
        for response in [
            r#"{"schema":"other","device_id":"device-1","active":"on","stored":"off","available":true}"#,
            r#"{"schema":"keyferry.screen-power.v1","device_id":"device-2","active":"on","stored":"off","available":true}"#,
            r#"{"schema":"keyferry.screen-power.v1","device_id":"device-1","active":"on","stored":"on","available":true}"#,
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = test_client(&listener);
            let worker = thread::spawn(move || {
                let (mut stream, headers) = accept_http_headers(&listener);
                assert!(headers.starts_with("POST /v1/devices/device-1/screen-power HTTP/1.1"));
                let mut body = vec![0; http_content_length(&headers)];
                stream.read_exact(&mut body).unwrap();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
            });
            assert!(client
                .set_screen_power("device-1", ScreenPower::Off)
                .is_err());
            worker.join().unwrap();
        }
    }

    #[test]
    fn display_orientation_reads_and_sets_the_per_device_preference() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let worker = thread::spawn(move || {
            let (mut stream, headers) = accept_http_headers(&listener);
            assert!(headers.starts_with("GET /v1/devices/device-1/display-orientation HTTP/1.1"));
            let response = r#"{"schema":"keyferry.display-orientation.v1","device_id":"device-1","active":"normal","stored":"normal","restart_pending":false}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();

            let (mut stream, headers) = accept_http_headers(&listener);
            assert!(headers.starts_with("POST /v1/devices/device-1/display-orientation HTTP/1.1"));
            let content_length = http_content_length(&headers);
            let mut body = vec![0; content_length];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"orientation":"rotated-180"})
            );
            let response = r#"{"schema":"keyferry.display-orientation.v1","device_id":"device-1","active":"normal","stored":"rotated-180","restart_pending":true}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });

        let current = client.display_orientation("device-1").unwrap();
        assert_eq!(current.active, DisplayOrientation::Normal);
        let changed = client
            .set_display_orientation("device-1", DisplayOrientation::Rotated180)
            .unwrap();
        worker.join().unwrap();
        assert_eq!(changed.active, DisplayOrientation::Normal);
        assert_eq!(changed.stored, DisplayOrientation::Rotated180);
        assert!(changed.restart_pending);
    }

    #[test]
    fn bluetooth_bond_reset_uses_the_guarded_device_mutation_route() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let worker = thread::spawn(move || {
            let (mut stream, headers) = accept_http_headers(&listener);
            assert!(headers.starts_with("POST /v1/devices/device-1/ble-hid-bond/reset HTTP/1.1"));
            assert_eq!(http_content_length(&headers), 0);
            let response = r#"{"schema":"keyferry.ble-hid-bond-reset.v1","device_id":"device-1","bond_was_present":true,"restart_pending":true}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });

        let status = client.reset_ble_hid_bond("device-1").unwrap();
        worker.join().unwrap();
        assert!(status.bond_was_present);
        assert!(status.restart_pending);
    }

    #[test]
    fn usb_file_preserves_bytes_and_clears_without_typing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let worker = thread::spawn(move || {
            for method in ["POST", "DELETE"] {
                let (mut stream, headers) = accept_http_headers(&listener);
                assert!(
                    headers.starts_with(&format!("{method} /v1/devices/device-1/file HTTP/1.1"))
                );
                let mut body = vec![0; http_content_length(&headers)];
                stream.read_exact(&mut body).unwrap();
                if method == "POST" {
                    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(body["bytes"], serde_json::json!([0, 255, 13, 10, 65]));
                } else {
                    assert!(body.is_empty());
                }
                let response = if method == "POST" {
                    r#"{"state":"published","size_bytes":5,"received_bytes":5,"max_size_bytes":32768}"#
                } else {
                    r#"{"state":"empty","size_bytes":0,"received_bytes":0,"max_size_bytes":32768}"#
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                )
                .unwrap();
            }
        });
        assert_eq!(
            client
                .publish_usb_file("device-1", &[0, 255, 13, 10, 65])
                .unwrap()
                .state,
            "published"
        );
        assert_eq!(client.clear_usb_file("device-1").unwrap().state, "empty");
        worker.join().unwrap();
        assert!(client
            .publish_usb_file(
                "device-1",
                &vec![0; keyferry_protocol::file::MAX_FILE_BYTES + 1]
            )
            .is_err());
    }

    #[test]
    fn usb_file_set_preserves_names_and_exact_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let worker = thread::spawn(move || {
            for method in ["POST", "GET", "DELETE"] {
                let (mut stream, headers) = accept_http_headers(&listener);
                assert!(
                    headers.starts_with(&format!("{method} /v1/devices/device-1/files HTTP/1.1"))
                );
                let mut body = vec![0; http_content_length(&headers)];
                stream.read_exact(&mut body).unwrap();
                if method == "POST" {
                    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(
                        body["files"][0],
                        serde_json::json!({"name":"A.TXT","bytes":[0,255]})
                    );
                    assert_eq!(
                        body["files"][1],
                        serde_json::json!({"name":"Empty.json","bytes":[]})
                    );
                } else {
                    assert!(body.is_empty());
                }
                let response = if method == "DELETE" {
                    r#"{"state":"empty","size_bytes":0,"received_bytes":0,"max_size_bytes":262144,"files":[],"max_files":16,"max_name_bytes":64,"bundle_size_bytes":0,"bundle_received_bytes":0}"#
                } else {
                    r#"{"state":"published","size_bytes":2,"received_bytes":2,"max_size_bytes":262144,"files":[{"name":"A.TXT","size":2},{"name":"Empty.json","size":0}],"max_files":16,"max_name_bytes":64,"bundle_size_bytes":0,"bundle_received_bytes":0}"#
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                )
                .unwrap();
            }
        });
        let files = [("A.TXT", &[0u8, 255][..]), ("Empty.json", &[][..])];
        let status = client.publish_usb_files("device-1", &files).unwrap();
        assert_eq!(status.size_bytes, 2);
        assert_eq!(status.files[1].name, "Empty.json");
        assert_eq!(client.usb_files("device-1").unwrap().files.len(), 2);
        assert_eq!(client.clear_usb_files("device-1").unwrap().state, "empty");
        worker.join().unwrap();
        assert!(client
            .publish_usb_files("device-1", &[("CON.txt", b"x")])
            .is_err());
        assert!(client
            .publish_usb_files("device-1", &[("A.txt", b"x"), ("a.TXT", b"y")])
            .is_err());
    }

    #[test]
    fn bounded_remote_daemon_error_preserves_safe_detail() {
        assert_eq!(
            daemon_http_error(
                "remote daemon",
                422,
                br#"{"error":"endpoint rejected arm","outcome":"REJECTED"}"#,
            )
            .to_string(),
            "remote daemon returned HTTP 422: endpoint rejected arm"
        );
        assert_eq!(
            daemon_http_error("remote daemon", 422, &[b'x'; MAX_DAEMON_ERROR_BYTES + 1])
                .to_string(),
            "remote daemon returned HTTP 422"
        );
    }

    #[test]
    fn owner_action_submission_refreshes_route_proof_and_maps_named_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = owner_remote_test_client(&listener);
        let authority = match &client.endpoint {
            ApiEndpoint::Remote(remote) => remote.owner_route.clone().unwrap(),
            _ => unreachable!(),
        };
        let device_id = device_id_text(&authority.device_id);
        let expected_device_id = device_id.clone();
        let worker = thread::spawn(move || {
            respond_to_owner_route_proof(&listener, &authority, &expected_device_id);
            let (mut stream, headers) = accept_http_headers(&listener);
            assert!(headers.starts_with(&format!(
                "POST /v1/devices/{expected_device_id}/actions HTTP/1.1"
            )));
            assert!(headers
                .to_ascii_lowercase()
                .contains("authorization: bearer test-bearer-token\r\n"));
            let content_length = http_content_length(&headers);
            let mut body = vec![0; content_length];
            stream.read_exact(&mut body).unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["profile"], "windows-us");
            assert_eq!(
                body["actions"][0],
                serde_json::json!({"type":"tap","key":"ENTER"})
            );
            assert_eq!(
                body["actions"][1],
                serde_json::json!({"type":"chord","keys":["CTRL","L"]})
            );
            assert_eq!(
                body["actions"][2],
                serde_json::json!({"type":"text","value":"example"})
            );
            for action in body["actions"].as_array().unwrap() {
                assert!(action.get("usage").is_none());
                assert!(action.get("modifiers").is_none());
                assert!(action.get("duration_ms").is_none());
            }
            let response = format!(
                r#"{{"command_id":"c1","device_id":"{expected_device_id}","outcome":"QUEUED","message":null}}"#
            );
            write!(
                stream,
                "HTTP/1.1 202 Accepted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });
        let response = client
            .submit_actions(
                &device_id,
                &[
                    ActionRequest::tap("enter").unwrap(),
                    ActionRequest::chord(vec!["control".to_owned(), "l".to_owned()]).unwrap(),
                    ActionRequest::text("example"),
                ],
                "windows-us",
            )
            .unwrap();
        worker.join().unwrap();
        assert_eq!(response.command_id, "c1");
        assert_eq!(response.outcome, CommandOutcome::Queued);
    }

    #[test]
    fn sequence_submission_uses_the_canonical_daemon_route_and_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let headers = String::from_utf8(request).unwrap();
            assert!(headers.starts_with("POST /v1/devices/device-1/sequences HTTP/1.1"));
            let content_length = http_content_length(&headers);
            let mut body = vec![0; content_length];
            stream.read_exact(&mut body).unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["schema"], "keyferry.keyboard-sequence.v1");
            assert_eq!(body["arm"], "command-scoped");
            assert_eq!(
                body["actions"][0],
                serde_json::json!({"type":"tap","key":"LEFT_GUI"})
            );
            assert_eq!(
                body["actions"][1],
                serde_json::json!({"type":"wait","ms":250})
            );
            assert_eq!(
                body["actions"][2],
                serde_json::json!({"type":"text","value":"notepad"})
            );
            assert_eq!(
                body["actions"][3],
                serde_json::json!({"type":"tap","key":"ENTER"})
            );
            let response = r#"{"command_id":"019d1234-5678-7abc-8123-456789abcdef","device_id":"device-1","outcome":"QUEUED","message":null}"#;
            write!(
                stream,
                "HTTP/1.1 202 Accepted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });
        let sequence: keyferry_layouts::KeyboardSequenceV1 = serde_json::from_str(
            r#"{"schema":"keyferry.keyboard-sequence.v1","command_id":"019d1234-5678-7abc-8123-456789abcdef","profile":"windows-us","arm":"command-scoped","start_within_ms":5000,"actions":[{"type":"tap","key":"LEFT_GUI"},{"type":"wait","ms":250},{"type":"text","value":"notepad"},{"type":"tap","key":"ENTER"}]}"#,
        )
        .unwrap();
        let response = client.submit_sequence("device-1", &sequence).unwrap();
        worker.join().unwrap();
        assert_eq!(response.command_id, "019d1234-5678-7abc-8123-456789abcdef");
        assert_eq!(response.outcome, CommandOutcome::Queued);
    }

    #[test]
    fn command_outcome_reconciliation_is_read_only_and_path_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let headers = String::from_utf8(request).unwrap();
            assert!(headers.starts_with(
                "GET /v1/devices/device-1/commands/019d1234-5678-7abc-8123-456789abcdef HTTP/1.1"
            ));
            let response = r#"{"command_id":"019d1234-5678-7abc-8123-456789abcdef","device_id":"device-1","outcome":"EMITTED","terminal":true,"possible_start":true,"terminal_zero_confirmed":true,"message":null}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });
        let response = client
            .command_outcome("device-1", "019d1234-5678-7abc-8123-456789abcdef")
            .unwrap();
        worker.join().unwrap();
        assert_eq!(response.outcome, CommandOutcome::Emitted);
        assert!(response.outcome.is_terminal());

        let error = client.command_outcome("device-1", "bad/id").unwrap_err();
        assert_eq!(
            error.to_string(),
            "command ID contains unsupported path characters"
        );
    }

    #[test]
    fn rejects_unsupported_key_name_client_side_without_echoing_it() {
        let error = ActionRequest::tap("F13").unwrap_err();
        assert_eq!(
            error.to_string(),
            "unsupported key name; use a supported modifier, named key, or printable US-ASCII character"
        );
        assert!(!error.to_string().contains("F13"));

        let error = ActionRequest::chord(vec!["CTRL".to_owned(), "F13".to_owned()]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unsupported key name; use a supported modifier, named key, or printable US-ASCII character"
        );
        assert!(!error.to_string().contains("F13"));
    }

    #[test]
    fn sends_an_empty_json_object_when_cancelling_the_current_command() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let headers = String::from_utf8(request).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let mut body = vec![0; content_length];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(body, br"{}");
            let response =
                r#"{"command_id":"c1","device_id":"device-1","outcome":"QUEUED","message":null}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });
        let response = client.cancel("device-1", None).unwrap();
        worker.join().unwrap();
        assert_eq!(response.command_id, "c1");
    }

    #[test]
    fn parses_chunked_sse_metadata_event() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /v1/events HTTP/1.1"));
            assert!(request.contains("Accept: text/event-stream\r\n"));
            let event = r#"{"command_id":"c1","caller":"local","device_id":"device-1","profile":"windows-us","action_count":4,"char_count":5,"timestamp":"2026-09-01T00:00:00Z","duration_ms":100,"outcome":"EMITTED"}"#;
            let data = format!("data: {event}\n\n");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n{:X}\r\n{}\r\n0\r\n\r\n",
                data.len(),
                data
            )
            .unwrap();
        });
        let mut events = client.events().unwrap();
        let event = events.next_event().unwrap().unwrap();
        worker.join().unwrap();
        assert_eq!(event.command_id, "c1");
        assert_eq!(event.outcome, CommandOutcome::Emitted);
        assert_eq!(event.char_count, 5);
    }

    #[test]
    fn remote_agents_are_direct_tailnet_http_and_stream_lifetime_is_bounded() {
        let request = remote_agent(Some(REMOTE_REQUEST_TIMEOUT), false);
        let request = request.config();
        assert!(!request.https_only());
        assert!(request.proxy().is_none());
        assert_eq!(request.max_redirects(), 0);
        assert_eq!(request.max_response_header_size(), MAX_HEADERS);
        assert_eq!(request.timeouts().connect, Some(REMOTE_CONNECT_TIMEOUT));
        assert_eq!(request.timeouts().global, Some(REMOTE_REQUEST_TIMEOUT));
        assert_eq!(request.timeouts().recv_body, Some(REMOTE_REQUEST_TIMEOUT));
        assert!(!request.http_status_as_error());

        let stream = remote_agent(Some(REMOTE_EVENT_STREAM_LIFETIME), true);
        let stream = stream.config();
        assert!(!stream.https_only());
        assert!(stream.proxy().is_none());
        assert_eq!(stream.max_redirects(), 0);
        assert_eq!(stream.timeouts().connect, Some(REMOTE_CONNECT_TIMEOUT));
        assert_eq!(stream.timeouts().global, Some(REMOTE_EVENT_STREAM_LIFETIME));
        assert_eq!(
            stream.timeouts().recv_body,
            Some(REMOTE_EVENT_STREAM_LIFETIME)
        );
        assert!(stream.http_status_as_error());
    }

    #[test]
    fn remote_client_requires_matching_credential_and_supported_signed_api() {
        let rng = SystemRandom::new();
        let private = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private.as_ref(), &rng)
                .unwrap();
        let mut spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        spki.extend_from_slice(pair.public_key().as_ref());
        let nonce = [0x11; 32];
        let credential_path = std::env::temp_dir().join(format!(
            "keyferry-api-credential-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let spki_hex = spki
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        fs::write(
            &credential_path,
            format!(
                r#"{{"schema_version":2,"port":18043,"gateway_spki_der":"{spki_hex}","remote_bearer":"{}"}}"#,
                "ab".repeat(32)
            ),
        )
        .unwrap();
        let credential = crate::gateway_probe::GatewayCredential::from_file(&credential_path)
            .expect("credential fixture");
        fs::remove_file(credential_path).unwrap();

        let current =
            sign_gateway_proof(private.as_ref(), nonce, [0x22; 16], 1, Vec::new()).unwrap();
        let current = verify_gateway_proof(&current, nonce, &spki).unwrap();
        let address = "100.90.118.120".parse().unwrap();
        let client = ApiClient::for_verified_gateway(&current, address, &credential)
            .expect("matched remote client");
        let ApiEndpoint::Remote(remote) = client.endpoint else {
            panic!("verified gateway must construct a remote endpoint");
        };
        assert_eq!(remote.address, address);
        assert_eq!(remote.port, 18043);

        assert!(ApiClient::for_verified_gateway(
            &current,
            "192.168.1.10".parse().unwrap(),
            &credential
        )
        .is_err());
        let future =
            sign_gateway_proof(private.as_ref(), nonce, [0x22; 16], 2, Vec::new()).unwrap();
        let future = verify_gateway_proof(&future, nonce, &spki).unwrap();
        assert!(ApiClient::for_verified_gateway(&future, address, &credential).is_err());
    }

    #[test]
    fn owner_route_response_requires_fresh_device_authenticated_binding() {
        let nonce = [0x51; 32];
        let authority = OwnerRouteAuthority {
            owner_id: [0x11; 16],
            device_id: [0x22; 16],
            controller_installation_id: [0x33; 16],
            gateway_installation_id: [0x44; 16],
            route_proof_secret: [0x55; 32],
        };
        let input = keyferry_gateway::RouteProofInput {
            owner_id: authority.owner_id,
            device_id: authority.device_id,
            epoch: 1,
            policy_sequence: 1,
            policy_hash: [0x66; 32],
            gateway_installation_id: authority.gateway_installation_id,
            controller_installation_id: authority.controller_installation_id,
            controller_nonce: nonce,
            device_boot_nonce: [0x77; 16],
            endpoint_session_id: [0x88; 16],
            link_path: keyferry_gateway::GatewayLinkPath::Bluetooth,
            usb_ready: true,
        };
        let tag = keyferry_gateway::route_proof_tag(&authority.route_proof_secret, &input).unwrap();
        let response = keyferry_gateway::encode_route_proof_response(&input, &tag).unwrap();
        let encoded = encode_lower_hex(&response);
        assert_eq!(
            verify_owner_route_response(&authority, nonce, Duration::from_millis(10), &encoded)
                .unwrap()
                .input,
            input
        );

        let mut wrong_gateway = authority.clone();
        wrong_gateway.gateway_installation_id[0] ^= 1;
        assert!(verify_owner_route_response(
            &wrong_gateway,
            nonce,
            Duration::from_millis(10),
            &encoded
        )
        .is_err());
        assert!(verify_owner_route_response(
            &authority,
            nonce,
            Duration::from_millis(keyferry_gateway::ROUTE_PROOF_TTL_MS as u64 + 1),
            &encoded
        )
        .is_err());
        let mut tampered = response;
        tampered[tampered.len() - 1] ^= 1;
        assert!(verify_owner_route_response(
            &authority,
            nonce,
            Duration::from_millis(10),
            &encode_lower_hex(&tampered)
        )
        .is_err());
    }

    #[test]
    fn gateway_yield_verifies_route_then_posts_once_and_parses_strict_acknowledgment() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = owner_remote_test_client(&listener);
        let authority = match &client.endpoint {
            ApiEndpoint::Remote(remote) => remote.owner_route.clone().unwrap(),
            _ => unreachable!(),
        };
        let device_id = device_id_text(&authority.device_id);
        let expected_device_id = device_id.clone();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            let first_line = request.lines().next().unwrap();
            assert!(first_line.starts_with(&format!(
                "GET /v2/devices/{expected_device_id}/route-proof?nonce="
            )));
            let nonce_text = first_line
                .split("nonce=")
                .nth(1)
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap();
            let nonce_vec = decode_lower_hex(nonce_text, "nonce").unwrap();
            let mut nonce = [0_u8; 32];
            nonce.copy_from_slice(&nonce_vec);
            let input = keyferry_gateway::RouteProofInput {
                owner_id: authority.owner_id,
                device_id: authority.device_id,
                epoch: 1,
                policy_sequence: 1,
                policy_hash: [0x66; 32],
                gateway_installation_id: authority.gateway_installation_id,
                controller_installation_id: authority.controller_installation_id,
                controller_nonce: nonce,
                device_boot_nonce: [0x77; 16],
                endpoint_session_id: [0x88; 16],
                link_path: keyferry_gateway::GatewayLinkPath::Bluetooth,
                usb_ready: true,
            };
            let tag =
                keyferry_gateway::route_proof_tag(&authority.route_proof_secret, &input).unwrap();
            let proof = keyferry_gateway::encode_route_proof_response(&input, &tag).unwrap();
            let body = serde_json::json!({"proof": encode_lower_hex(&proof)}).to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();

            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with(&format!(
                "POST /v2/devices/{expected_device_id}/gateway/yield HTTP/1.1"
            )));
            let body = format!(
                r#"{{"device_id":"{expected_device_id}","status":"yielding","yield_ms":20000}}"#
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        let response = client.yield_gateway(&device_id).unwrap();
        worker.join().unwrap();
        assert_eq!(response.device_id, device_id);
        assert_eq!(response.status, "yielding");
        assert_eq!(response.yield_ms, 20_000);
    }

    #[test]
    fn gateway_yield_refuses_local_and_legacy_remote_clients_before_network_io() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local = test_client(&listener);
        assert!(local.yield_gateway("device-1").is_err());

        let address = listener.local_addr().unwrap();
        let legacy = ApiClient {
            endpoint: ApiEndpoint::Remote(Box::new(RemoteEndpoint {
                address: address.ip(),
                port: address.port(),
                server_name: None,
                owner_route: None,
                request_agent: remote_agent(Some(Duration::from_secs(1)), false),
                stream_agent: remote_agent(Some(Duration::from_secs(1)), true),
            })),
            token: "legacy".to_owned(),
        };
        assert!(legacy.yield_gateway("device-1").is_err());
    }

    #[test]
    fn local_gateway_handoff_posts_one_strict_destination_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_client(&listener);
        let transaction_id = uuid::Uuid::now_v7();
        let prepared = GatewayHandoffResponse {
            transaction_id,
            phase: "ready".to_owned(),
            terminal: false,
            target_installation_id: "44".repeat(16),
            previous_installation_id: "33".repeat(16),
            target_ipv4: Some("192.168.30.50".to_owned()),
            target_port: Some(keyferry_protocol::roaming::DEVICE_TLS_PORT),
            target_control_port: Some(keyferry_gateway::OWNER_GATEWAY_CONTROL_PORT),
            readiness_nonce: Some("55".repeat(16)),
            listener_generation: Some(7),
            reason: None,
        };
        let expected = prepared.clone();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut headers = Vec::new();
            let mut byte = [0_u8; 1];
            while !headers.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
            }
            let headers = String::from_utf8(headers).unwrap();
            assert!(
                headers.starts_with("POST /v1/devices/device-1/gateway/outgoing-handoff HTTP/1.1")
            );
            let mut body = vec![0_u8; http_content_length(&headers)];
            stream.read_exact(&mut body).unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["transaction_id"], transaction_id.to_string());
            assert_eq!(body["target_installation_id"], "44".repeat(16));
            assert_eq!(body["previous_installation_id"], "33".repeat(16));
            assert_eq!(body["target_gateway_address"], "100.64.0.2");
            assert_eq!(body["readiness_nonce"], "55".repeat(16));
            let response = serde_json::to_vec(&expected).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(&response).unwrap();
        });

        let response = client
            .start_local_gateway_handoff(
                "device-1",
                "100.64.0.2".parse().unwrap(),
                [0x44; 16],
                &prepared,
            )
            .unwrap();
        worker.join().unwrap();
        assert_eq!(response, prepared);
    }

    #[test]
    fn event_stream_observes_generation_cancellation_at_keepalive_boundaries() {
        let event = r#"{"command_id":"c1","caller":"remote","device_id":"device-1","profile":"windows-us","action_count":1,"char_count":1,"timestamp":"2026-09-10T00:00:00Z","duration_ms":1,"outcome":"EMITTED"}"#;
        let bytes = format!(": keepalive\n\ndata: {event}\n\n");
        let mut stream = EventStream {
            reader: Box::new(BufReader::new(io::Cursor::new(bytes.into_bytes()))),
        };
        let mut checks = 0;
        let result = stream
            .next_event_while(|| {
                checks += 1;
                checks < 3
            })
            .expect("bounded cancellation");
        assert!(result.is_none());
    }

    #[test]
    fn event_stream_rejects_oversized_lines_and_events() {
        let mut oversized_line = vec![b'x'; MAX_EVENT_LINE_BYTES + 1];
        oversized_line.push(b'\n');
        let mut stream = EventStream {
            reader: Box::new(BufReader::new(io::Cursor::new(oversized_line))),
        };
        assert_eq!(
            stream.next_event().unwrap_err().to_string(),
            "event stream line exceeds limit"
        );

        let chunk = "x".repeat(16_000);
        let body = (0..5)
            .map(|_| format!("data: {chunk}\n"))
            .collect::<String>()
            + "\n";
        let mut stream = EventStream {
            reader: Box::new(BufReader::new(io::Cursor::new(body.into_bytes()))),
        };
        assert_eq!(
            stream.next_event().unwrap_err().to_string(),
            "event stream event exceeds limit"
        );
    }
}
