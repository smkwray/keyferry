//! Bounded wire parsing for application-authenticated tailnet gateway discovery.
//!
//! A structurally valid response remains untrusted until its nonce, gateway ID, and P-256
//! signature verify against a locally trusted SPKI.

use keyferry_gateway::{
    gateway_id_for_spki, validate_gateway_proof_structure, verify_gateway_proof, GatewayProofError,
    GATEWAY_PROOF_VERSION, MAX_GATEWAY_DEVICES,
};
pub use keyferry_gateway::{
    GatewayArmMode, GatewayDeviceSummary, GatewayLinkPath, GatewayProofPayload, SignedGatewayProof,
    VerifiedGatewayProof,
};
use serde::Deserialize;
use std::net::IpAddr;
use std::{
    env, fmt, fs, io,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

pub const MAX_GATEWAY_PROOF_BYTES: usize = 16 * 1024;
pub const MAX_P256_SIGNATURE_DER_BYTES: usize = 72;
pub const SUPPORTED_GATEWAY_API_VERSION: u16 = 1;
pub const MAX_TRUSTED_GATEWAYS: usize = 8;
const GATEWAY_BUNDLE_ENV: &str = "KEYFERRY_BUNDLE";
const GATEWAY_SPKI_ENV: &str = "KEYFERRY_GATEWAY_SPKI";
const GATEWAY_CREDENTIAL_ENV: &str = "KEYFERRY_GATEWAY_CREDENTIAL";
const GATEWAY_PORT_ENV: &str = "KEYFERRY_GATEWAY_PORT";
const DEFAULT_GATEWAY_BUNDLE: &str = "secrets/first-hil";
const DEFAULT_GATEWAY_PORT: u16 = 18_043;
const HOST_SPKI_RELATIVE_PATH: &str = "firmware/host-spki.der";
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const MAX_GATEWAY_PROOF_READ_BYTES: u64 = MAX_GATEWAY_PROOF_BYTES as u64 + 1;
const MAX_TRUSTED_SPKI_BYTES: u64 = 2_048;
const MAX_GATEWAY_CREDENTIAL_BYTES: u64 = 4_096;
const MAX_OWNER_CANDIDATE_BYTES: u64 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerGatewayRoute {
    pub address: IpAddr,
    pub gateway_installation_id: [u8; 16],
    pub control_port: u16,
}

#[derive(Clone, Debug)]
pub struct OwnerGatewayCandidateClient {
    agent: ureq::Agent,
    probe_port: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOwnerGatewayCandidate {
    schema_version: u16,
    installation_id: String,
}

impl OwnerGatewayCandidateClient {
    #[must_use]
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .https_only(false)
            .proxy(None)
            .max_redirects(0)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
            .timeout_connect(Some(PROBE_CONNECT_TIMEOUT))
            .timeout_global(Some(PROBE_TIMEOUT))
            .build();
        Self {
            agent: config.into(),
            probe_port: keyferry_gateway::OWNER_GATEWAY_PROBE_PORT,
        }
    }

    pub fn probe_tailnet_address(
        &self,
        address: IpAddr,
    ) -> Result<OwnerGatewayRoute, GatewayProbeClientError> {
        if !keyferry_gateway::is_tailscale_ip(address) {
            return Err(GatewayProbeClientError::InvalidTailnetAddress);
        }
        let host = match address {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        };
        let url = format!(
            "http://{host}:{}{}",
            self.probe_port,
            keyferry_gateway::OWNER_GATEWAY_CANDIDATE_PATH
        );
        let mut response = self
            .agent
            .get(&url)
            .call()
            .map_err(|error| GatewayProbeClientError::Request(error.to_string()))?;
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(MAX_OWNER_CANDIDATE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|error| GatewayProbeClientError::Request(error.to_string()))?;
        if body.len() as u64 > MAX_OWNER_CANDIDATE_BYTES {
            return Err(GatewayProbeClientError::ResponseTooLarge(body.len()));
        }
        parse_owner_gateway_candidate(address, &body)
    }
}

impl Default for OwnerGatewayCandidateClient {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_owner_gateway_candidate(
    address: IpAddr,
    body: &[u8],
) -> Result<OwnerGatewayRoute, GatewayProbeClientError> {
    let wire: WireOwnerGatewayCandidate =
        serde_json::from_slice(body).map_err(|_| GatewayProbeClientError::InvalidCandidate)?;
    if wire.schema_version != keyferry_gateway::OWNER_GATEWAY_CANDIDATE_VERSION {
        return Err(GatewayProbeClientError::InvalidCandidate);
    }
    let installation_id = decode_fixed::<16>(&wire.installation_id, "installation_id")
        .map_err(|_| GatewayProbeClientError::InvalidCandidate)?;
    let candidate = keyferry_gateway::OwnerGatewayCandidate::new(installation_id)
        .map_err(|_| GatewayProbeClientError::InvalidCandidate)?;
    Ok(OwnerGatewayRoute {
        address,
        gateway_installation_id: candidate.installation_id,
        control_port: keyferry_gateway::OWNER_GATEWAY_CONTROL_PORT,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedGatewayRegistry {
    spkis: Vec<Vec<u8>>,
}

impl TrustedGatewayRegistry {
    pub fn from_environment() -> Result<Self, GatewayProbeClientError> {
        if env::var_os(GATEWAY_CREDENTIAL_ENV).is_some() {
            let credential = GatewayCredential::from_environment()?;
            return Self::from_spkis(vec![credential.spki_der.clone()]);
        }
        if let Some(path) = env::var_os(GATEWAY_SPKI_ENV) {
            return Self::from_spki_file(path);
        }
        if let Some(bundle) = env::var_os(GATEWAY_BUNDLE_ENV) {
            return Self::from_bundle(bundle);
        }
        if default_gateway_credential_path().is_file() {
            let credential = GatewayCredential::from_environment()?;
            return Self::from_spkis(vec![credential.spki_der.clone()]);
        }
        Self::from_bundle(DEFAULT_GATEWAY_BUNDLE)
    }

    pub fn from_bundle(bundle: impl AsRef<Path>) -> Result<Self, GatewayProbeClientError> {
        let path = bundle.as_ref().join(HOST_SPKI_RELATIVE_PATH);
        Self::from_spki_file(path)
    }

    pub fn from_spki_file(path: impl AsRef<Path>) -> Result<Self, GatewayProbeClientError> {
        let mut spki = Vec::with_capacity(MAX_TRUSTED_SPKI_BYTES as usize);
        fs::File::open(path)
            .map_err(GatewayProbeClientError::TrustIo)?
            .take(MAX_TRUSTED_SPKI_BYTES + 1)
            .read_to_end(&mut spki)
            .map_err(GatewayProbeClientError::TrustIo)?;
        if spki.len() as u64 > MAX_TRUSTED_SPKI_BYTES {
            return Err(GatewayProbeClientError::InvalidTrust(
                GatewayProofError::InvalidTrustedSpki,
            ));
        }
        gateway_id_for_spki(&spki).map_err(GatewayProbeClientError::InvalidTrust)?;
        Ok(Self { spkis: vec![spki] })
    }

    pub fn from_spkis(spkis: Vec<Vec<u8>>) -> Result<Self, GatewayProbeClientError> {
        if spkis.is_empty() || spkis.len() > MAX_TRUSTED_GATEWAYS {
            return Err(GatewayProbeClientError::InvalidTrustCount(spkis.len()));
        }
        for spki in &spkis {
            gateway_id_for_spki(spki).map_err(GatewayProbeClientError::InvalidTrust)?;
        }
        Ok(Self { spkis })
    }

    #[must_use]
    pub fn spkis(&self) -> &[Vec<u8>] {
        &self.spkis
    }
}

#[derive(Clone)]
pub struct GatewayCredential {
    port: u16,
    spki_der: Vec<u8>,
    remote_bearer: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGatewayCredential {
    schema_version: u8,
    port: u16,
    gateway_spki_der: String,
    remote_bearer: String,
}

impl GatewayCredential {
    pub fn from_environment() -> Result<Self, GatewayProbeClientError> {
        let path = env::var_os(GATEWAY_CREDENTIAL_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(default_gateway_credential_path);
        Self::from_file(path)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, GatewayProbeClientError> {
        let mut bytes = Vec::new();
        fs::File::open(path)
            .map_err(GatewayProbeClientError::TrustIo)?
            .take(MAX_GATEWAY_CREDENTIAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(GatewayProbeClientError::TrustIo)?;
        if bytes.len() as u64 > MAX_GATEWAY_CREDENTIAL_BYTES {
            return Err(GatewayProbeClientError::InvalidCredential);
        }
        let wire: WireGatewayCredential = serde_json::from_slice(&bytes)
            .map_err(|_| GatewayProbeClientError::InvalidCredential)?;
        let spki_der = decode_bytes(&wire.gateway_spki_der, "gateway_spki_der")
            .map_err(|_| GatewayProbeClientError::InvalidCredential)?;
        gateway_id_for_spki(&spki_der).map_err(GatewayProbeClientError::InvalidTrust)?;
        if wire.schema_version != 2
            || wire.port == 0
            || wire.remote_bearer.len() != 64
            || !wire
                .remote_bearer
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(GatewayProbeClientError::InvalidCredential);
        }
        Ok(Self {
            port: wire.port,
            spki_der,
            remote_bearer: wire.remote_bearer,
        })
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn remote_bearer(&self) -> &str {
        &self.remote_bearer
    }

    #[must_use]
    pub fn matches(&self, proof: &VerifiedGatewayProof) -> bool {
        gateway_id_for_spki(&self.spki_der)
            .is_ok_and(|gateway_id| gateway_id == proof.payload().gateway_id)
    }
}

#[derive(Clone, Debug)]
pub struct GatewayProbeClient {
    agent: ureq::Agent,
    trust: TrustedGatewayRegistry,
    port: u16,
}

impl GatewayProbeClient {
    #[must_use]
    pub fn new(trust: TrustedGatewayRegistry) -> Self {
        let config = ureq::Agent::config_builder()
            .https_only(false)
            .proxy(None)
            .max_redirects(0)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
            .timeout_connect(Some(PROBE_CONNECT_TIMEOUT))
            .timeout_global(Some(PROBE_TIMEOUT))
            .build();
        Self {
            agent: config.into(),
            trust,
            port: DEFAULT_GATEWAY_PORT,
        }
    }

    pub fn from_environment() -> Result<Self, GatewayProbeClientError> {
        if env::var_os(GATEWAY_CREDENTIAL_ENV).is_some() {
            return Self::from_credential(&GatewayCredential::from_environment()?);
        }
        if env::var_os(GATEWAY_SPKI_ENV).is_none()
            && env::var_os(GATEWAY_BUNDLE_ENV).is_none()
            && default_gateway_credential_path().is_file()
        {
            return Self::from_credential(&GatewayCredential::from_environment()?);
        }
        let mut client = Self::new(TrustedGatewayRegistry::from_environment()?);
        if let Some(value) = env::var_os(GATEWAY_PORT_ENV) {
            client.port = value
                .to_str()
                .and_then(|value| value.parse::<u16>().ok())
                .filter(|port| *port != 0)
                .ok_or(GatewayProbeClientError::InvalidPort)?;
        }
        Ok(client)
    }

    pub fn from_credential(
        credential: &GatewayCredential,
    ) -> Result<Self, GatewayProbeClientError> {
        Self::new(TrustedGatewayRegistry::from_spkis(vec![credential
            .spki_der
            .clone()])?)
        .with_port(credential.port)
    }

    pub fn with_port(mut self, port: u16) -> Result<Self, GatewayProbeClientError> {
        if port == 0 {
            return Err(GatewayProbeClientError::InvalidPort);
        }
        self.port = port;
        Ok(self)
    }

    pub fn probe_tailnet_address(
        &self,
        address: IpAddr,
    ) -> Result<GatewayCandidateClassification, GatewayProbeClientError> {
        if !keyferry_gateway::is_tailscale_ip(address) {
            return Err(GatewayProbeClientError::InvalidTailnetAddress);
        }
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| GatewayProbeClientError::Random)?;
        let host = match address {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        };
        let url = format!(
            "http://{host}:{}/v1/gateway/probe?nonce={}",
            self.port,
            encode_hex(&nonce)
        );
        let mut response = self
            .agent
            .get(&url)
            .call()
            .map_err(|error| GatewayProbeClientError::Request(error.to_string()))?;
        classify_gateway_reader(response.body_mut().as_reader(), nonce, self.trust.spkis())
    }
}

fn classify_gateway_reader(
    reader: impl Read,
    nonce: [u8; 32],
    trusted_spkis: &[Vec<u8>],
) -> Result<GatewayCandidateClassification, GatewayProbeClientError> {
    let mut body = Vec::new();
    reader
        .take(MAX_GATEWAY_PROOF_READ_BYTES)
        .read_to_end(&mut body)
        .map_err(|error| GatewayProbeClientError::Request(error.to_string()))?;
    if body.len() > MAX_GATEWAY_PROOF_BYTES {
        return Err(GatewayProbeClientError::ResponseTooLarge(body.len()));
    }
    Ok(classify_gateway_response(&body, nonce, trusted_spkis))
}

#[derive(Debug)]
pub enum GatewayProbeClientError {
    TrustIo(io::Error),
    InvalidTrust(GatewayProofError),
    InvalidTrustCount(usize),
    InvalidTailnetAddress,
    InvalidPort,
    InvalidCredential,
    InvalidCandidate,
    Random,
    Request(String),
    ResponseTooLarge(usize),
}

impl fmt::Display for GatewayProbeClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrustIo(error) => write!(formatter, "could not read gateway trust: {error}"),
            Self::InvalidTrust(error) => write!(formatter, "gateway trust is invalid: {error}"),
            Self::InvalidTrustCount(count) => write!(
                formatter,
                "gateway trust contains {count} entries; expected 1 to {MAX_TRUSTED_GATEWAYS}"
            ),
            Self::InvalidTailnetAddress => {
                formatter.write_str("gateway address is not a Tailscale address")
            }
            Self::InvalidPort => formatter.write_str("gateway tailnet port is invalid"),
            Self::InvalidCredential => formatter.write_str("gateway credential is invalid"),
            Self::InvalidCandidate => {
                formatter.write_str("owner gateway candidate is malformed or incompatible")
            }
            Self::Random => formatter.write_str("could not generate gateway probe nonce"),
            Self::Request(error) => write!(formatter, "gateway tailnet probe failed: {error}"),
            Self::ResponseTooLarge(bytes) => write!(
                formatter,
                "gateway tailnet response is {bytes} bytes; limit is {MAX_GATEWAY_PROOF_BYTES}"
            ),
        }
    }
}

impl std::error::Error for GatewayProbeClientError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayCandidateClassification {
    AuthenticatedGateway(VerifiedGatewayProof),
    AuthenticatedIncompatible(VerifiedGatewayProof),
    /// The response is canonical and fresh, but its gateway ID is not in the local trust set.
    UntrustedKeyferry(SignedGatewayProof),
    NotKeyferry(GatewayProbeError),
    TrustConfigurationError(GatewayProofError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayProbeError {
    ResponseTooLarge(usize),
    InvalidJson,
    InvalidHex(&'static str),
    InvalidSignatureLength,
    UnsupportedProtocolVersion,
    NonceMismatch,
    TooManyDevices,
    NonCanonicalDeviceOrder,
    InconsistentDeviceState,
    InvalidProof(GatewayProofError),
}

impl fmt::Display for GatewayProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResponseTooLarge(bytes) => write!(
                formatter,
                "gateway proof is {bytes} bytes; limit is {MAX_GATEWAY_PROOF_BYTES}"
            ),
            Self::InvalidJson => formatter.write_str("gateway proof JSON is invalid"),
            Self::InvalidHex(field) => write!(formatter, "gateway proof {field} is invalid"),
            Self::InvalidSignatureLength => {
                formatter.write_str("gateway proof signature length is invalid")
            }
            Self::UnsupportedProtocolVersion => {
                formatter.write_str("gateway proof protocol version is unsupported")
            }
            Self::NonceMismatch => {
                formatter.write_str("gateway proof nonce does not match this request")
            }
            Self::TooManyDevices => formatter.write_str("gateway proof contains too many devices"),
            Self::NonCanonicalDeviceOrder => {
                formatter.write_str("gateway proof devices are not canonically ordered")
            }
            Self::InconsistentDeviceState => {
                formatter.write_str("gateway proof contains inconsistent device state")
            }
            Self::InvalidProof(error) => write!(formatter, "gateway proof is invalid: {error}"),
        }
    }
}

impl std::error::Error for GatewayProbeError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGatewayProof {
    protocol_version: u16,
    request_nonce: String,
    gateway_id: String,
    daemon_boot_id: String,
    api_version: u16,
    devices: Vec<WireDeviceSummary>,
    signature_der: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDeviceSummary {
    device_id: String,
    configured_here: bool,
    session_online: bool,
    link_path: WireLinkPath,
    tls_hmac_authenticated: bool,
    protocol_session_id: Option<String>,
    armed: bool,
    arm_mode: WireArmMode,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireLinkPath {
    Offline,
    Wifi,
    Bluetooth,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireArmMode {
    Disarmed,
    CommandScoped,
    Temporary,
    AlwaysReady,
}

/// Parse a metadata-only proof and bind it to the nonce generated for this request.
///
/// Success does not authenticate a gateway. The caller must pass the returned value to the
/// shared P-256/SPKI verifier before granting any authority.
pub fn parse_unverified_gateway_proof(
    bytes: &[u8],
    expected_nonce: [u8; 32],
) -> Result<SignedGatewayProof, GatewayProbeError> {
    if bytes.len() > MAX_GATEWAY_PROOF_BYTES {
        return Err(GatewayProbeError::ResponseTooLarge(bytes.len()));
    }
    let wire: WireGatewayProof =
        serde_json::from_slice(bytes).map_err(|_| GatewayProbeError::InvalidJson)?;
    if wire.protocol_version != GATEWAY_PROOF_VERSION {
        return Err(GatewayProbeError::UnsupportedProtocolVersion);
    }
    if wire.devices.len() > MAX_GATEWAY_DEVICES {
        return Err(GatewayProbeError::TooManyDevices);
    }

    let request_nonce = decode_fixed::<32>(&wire.request_nonce, "request_nonce")?;
    if request_nonce != expected_nonce {
        return Err(GatewayProbeError::NonceMismatch);
    }
    let gateway_id = decode_fixed::<32>(&wire.gateway_id, "gateway_id")?;
    let daemon_boot_id = decode_fixed::<16>(&wire.daemon_boot_id, "daemon_boot_id")?;
    let signature_der = decode_bytes(&wire.signature_der, "signature_der")?;
    if signature_der.is_empty() || signature_der.len() > MAX_P256_SIGNATURE_DER_BYTES {
        return Err(GatewayProbeError::InvalidSignatureLength);
    }

    let mut devices = Vec::with_capacity(wire.devices.len());
    for device in wire.devices {
        let device = GatewayDeviceSummary {
            device_id: decode_fixed::<16>(&device.device_id, "device_id")?,
            configured_here: device.configured_here,
            session_online: device.session_online,
            link_path: match device.link_path {
                WireLinkPath::Offline => GatewayLinkPath::Offline,
                WireLinkPath::Wifi => GatewayLinkPath::Wifi,
                WireLinkPath::Bluetooth => GatewayLinkPath::Bluetooth,
            },
            tls_hmac_authenticated: device.tls_hmac_authenticated,
            protocol_session_id: device
                .protocol_session_id
                .as_deref()
                .map(|value| decode_fixed::<16>(value, "protocol_session_id"))
                .transpose()?,
            armed: device.armed,
            arm_mode: match device.arm_mode {
                WireArmMode::Disarmed => GatewayArmMode::Disarmed,
                WireArmMode::CommandScoped => GatewayArmMode::CommandScoped,
                WireArmMode::Temporary => GatewayArmMode::Temporary,
                WireArmMode::AlwaysReady => GatewayArmMode::AlwaysReady,
            },
        };
        devices.push(device);
    }
    if devices
        .windows(2)
        .any(|pair| pair[0].device_id >= pair[1].device_id)
    {
        return Err(GatewayProbeError::NonCanonicalDeviceOrder);
    }

    let proof = SignedGatewayProof {
        payload: GatewayProofPayload {
            protocol_version: wire.protocol_version,
            request_nonce,
            gateway_id,
            daemon_boot_id,
            api_version: wire.api_version,
            devices,
        },
        signature_der,
    };
    validate_gateway_proof_structure(&proof).map_err(|error| match error {
        GatewayProofError::InconsistentDeviceState => GatewayProbeError::InconsistentDeviceState,
        error => GatewayProbeError::InvalidProof(error),
    })?;
    Ok(proof)
}

/// Parse and authenticate a gateway response against the local trusted-SPKI registry.
#[must_use]
pub fn classify_gateway_response(
    bytes: &[u8],
    expected_nonce: [u8; 32],
    trusted_spkis: &[Vec<u8>],
) -> GatewayCandidateClassification {
    let proof = match parse_unverified_gateway_proof(bytes, expected_nonce) {
        Ok(proof) => proof,
        Err(error) => return GatewayCandidateClassification::NotKeyferry(error),
    };
    let mut matching_spki = None;
    for spki in trusted_spkis {
        let gateway_id = match gateway_id_for_spki(spki) {
            Ok(gateway_id) => gateway_id,
            Err(error) => return GatewayCandidateClassification::TrustConfigurationError(error),
        };
        if gateway_id == proof.payload.gateway_id {
            matching_spki = Some(spki.as_slice());
            break;
        }
    }
    let Some(trusted_spki) = matching_spki else {
        return GatewayCandidateClassification::UntrustedKeyferry(proof);
    };
    match verify_gateway_proof(&proof, expected_nonce, trusted_spki) {
        Ok(verified) if verified.payload().api_version == SUPPORTED_GATEWAY_API_VERSION => {
            GatewayCandidateClassification::AuthenticatedGateway(verified)
        }
        Ok(verified) => GatewayCandidateClassification::AuthenticatedIncompatible(verified),
        Err(error) => {
            GatewayCandidateClassification::NotKeyferry(GatewayProbeError::InvalidProof(error))
        }
    }
}

fn decode_fixed<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], GatewayProbeError> {
    let bytes = decode_bytes(value, field)?;
    bytes
        .try_into()
        .map_err(|_| GatewayProbeError::InvalidHex(field))
}

fn decode_bytes(value: &str, field: &'static str) -> Result<Vec<u8>, GatewayProbeError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GatewayProbeError::InvalidHex(field));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(GatewayProbeError::InvalidHex(field))?;
            let low = hex_nibble(pair[1]).ok_or(GatewayProbeError::InvalidHex(field))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn default_gateway_credential_path() -> PathBuf {
    #[cfg(windows)]
    if let Ok(root) = env::var("LOCALAPPDATA") {
        return PathBuf::from(root).join("keyferry").join("gateway.json");
    }
    #[cfg(target_os = "macos")]
    if let Ok(root) = env::var("HOME") {
        return PathBuf::from(root)
            .join("Library")
            .join("Application Support")
            .join("keyferry")
            .join("gateway.json");
    }
    if let Ok(root) = env::var("XDG_STATE_HOME") {
        return PathBuf::from(root).join("keyferry").join("gateway.json");
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("state")
        .join("keyferry")
        .join("gateway.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyferry_gateway::sign_gateway_proof;
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
    };

    const NONCE: [u8; 32] = [0x11; 32];

    #[test]
    fn owner_gateway_candidate_is_untrusted_bounded_routing_metadata() {
        let address = "100.70.80.90".parse().unwrap();
        let route = parse_owner_gateway_candidate(
            address,
            br#"{"schema_version":2,"installation_id":"44444444444444444444444444444444"}"#,
        )
        .unwrap();
        assert_eq!(route.address, address);
        assert_eq!(route.gateway_installation_id, [0x44; 16]);
        assert_eq!(
            route.control_port,
            keyferry_gateway::OWNER_GATEWAY_CONTROL_PORT
        );

        for invalid in [
            br#"{"schema_version":1,"installation_id":"44444444444444444444444444444444"}"#
                .as_slice(),
            br#"{"schema_version":2,"installation_id":"00000000000000000000000000000000"}"#
                .as_slice(),
            br#"{"schema_version":2,"installation_id":"4444","extra":true}"#.as_slice(),
        ] {
            assert!(matches!(
                parse_owner_gateway_candidate(address, invalid),
                Err(GatewayProbeClientError::InvalidCandidate)
            ));
        }
    }

    fn proof_json(devices: &str) -> Vec<u8> {
        format!(
            r#"{{
                "protocol_version":1,
                "request_nonce":"{}",
                "gateway_id":"{}",
                "daemon_boot_id":"{}",
                "api_version":1,
                "devices":{devices},
                "signature_der":"3006020101020101"
            }}"#,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(16),
        )
        .into_bytes()
    }

    fn online_device(id: u8) -> String {
        format!(
            r#"{{
                "device_id":"{}",
                "configured_here":true,
                "session_online":true,
                "link_path":"bluetooth",
                "tls_hmac_authenticated":true,
                "protocol_session_id":"{}",
                "armed":false,
                "arm_mode":"disarmed"
            }}"#,
            format!("{id:02x}").repeat(16),
            "44".repeat(16),
        )
    }

    #[test]
    fn fresh_bounded_proof_with_unknown_key_is_only_untrusted() {
        let bytes = proof_json(&format!("[{}]", online_device(1)));
        let GatewayCandidateClassification::UntrustedKeyferry(proof) =
            classify_gateway_response(&bytes, NONCE, &[])
        else {
            panic!("valid wire proof must remain untrusted");
        };
        assert_eq!(proof.payload.request_nonce, NONCE);
        assert_eq!(proof.payload.gateway_id, [0x22; 32]);
        assert_eq!(proof.payload.devices.len(), 1);
        assert_eq!(
            proof.payload.devices[0].link_path,
            GatewayLinkPath::Bluetooth
        );
    }

    #[test]
    fn replayed_nonce_is_not_keyferry() {
        let bytes = proof_json("[]");
        assert!(matches!(
            classify_gateway_response(&bytes, [0x99; 32], &[]),
            GatewayCandidateClassification::NotKeyferry(GatewayProbeError::NonceMismatch)
        ));
    }

    #[test]
    fn trusted_gateway_is_authenticated_and_tampering_is_rejected() {
        let (private_key, spki) = signing_material();
        let proof = sign_gateway_proof(
            private_key.as_ref(),
            NONCE,
            [0x33; 16],
            1,
            vec![GatewayDeviceSummary {
                device_id: [1; 16],
                configured_here: true,
                session_online: true,
                link_path: GatewayLinkPath::Bluetooth,
                tls_hmac_authenticated: true,
                protocol_session_id: Some([0x44; 16]),
                armed: false,
                arm_mode: GatewayArmMode::Disarmed,
            }],
        )
        .unwrap();
        let json = proof_to_json(&proof);
        assert!(matches!(
            classify_gateway_response(&json, NONCE, std::slice::from_ref(&spki)),
            GatewayCandidateClassification::AuthenticatedGateway(_)
        ));

        let mut tampered = String::from_utf8(json).unwrap();
        tampered = tampered.replace("\"api_version\":1", "\"api_version\":2");
        assert!(matches!(
            classify_gateway_response(tampered.as_bytes(), NONCE, &[spki]),
            GatewayCandidateClassification::NotKeyferry(GatewayProbeError::InvalidProof(
                GatewayProofError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn correctly_signed_future_api_is_authenticated_but_not_usable() {
        let (private_key, spki) = signing_material();
        let proof = sign_gateway_proof(
            &private_key,
            NONCE,
            [0x33; 16],
            SUPPORTED_GATEWAY_API_VERSION + 1,
            Vec::new(),
        )
        .unwrap();
        assert!(matches!(
            classify_gateway_response(&proof_to_json(&proof), NONCE, &[spki]),
            GatewayCandidateClassification::AuthenticatedIncompatible(_)
        ));
    }

    #[test]
    fn malformed_oversized_or_noncanonical_proofs_fail_closed() {
        assert!(matches!(
            parse_unverified_gateway_proof(b"not json", NONCE),
            Err(GatewayProbeError::InvalidJson)
        ));
        assert!(matches!(
            parse_unverified_gateway_proof(&vec![b' '; MAX_GATEWAY_PROOF_BYTES + 1], NONCE),
            Err(GatewayProbeError::ResponseTooLarge(_))
        ));

        let descending = proof_json(&format!("[{},{}]", online_device(2), online_device(1)));
        assert!(matches!(
            parse_unverified_gateway_proof(&descending, NONCE),
            Err(GatewayProbeError::NonCanonicalDeviceOrder)
        ));

        let duplicate = proof_json(&format!("[{},{}]", online_device(1), online_device(1)));
        assert!(matches!(
            parse_unverified_gateway_proof(&duplicate, NONCE),
            Err(GatewayProbeError::NonCanonicalDeviceOrder)
        ));
    }

    #[test]
    fn unknown_fields_uppercase_hex_and_inconsistent_state_fail_closed() {
        let unknown = String::from_utf8(proof_json("[]"))
            .unwrap()
            .replace("\"api_version\":1", "\"api_version\":1,\"extra\":true");
        assert!(matches!(
            parse_unverified_gateway_proof(unknown.as_bytes(), NONCE),
            Err(GatewayProbeError::InvalidJson)
        ));

        let uppercase = String::from_utf8(proof_json("[]"))
            .unwrap()
            .replace(&"22".repeat(32), &"AA".repeat(32));
        assert!(matches!(
            parse_unverified_gateway_proof(uppercase.as_bytes(), NONCE),
            Err(GatewayProbeError::InvalidHex("gateway_id"))
        ));

        let inconsistent = online_device(1).replace(
            "\"protocol_session_id\":\"44444444444444444444444444444444\"",
            "\"protocol_session_id\":null",
        );
        assert!(matches!(
            parse_unverified_gateway_proof(&proof_json(&format!("[{inconsistent}]")), NONCE),
            Err(GatewayProbeError::InconsistentDeviceState)
        ));
    }

    #[test]
    fn device_and_signature_limits_are_enforced() {
        let devices = (1..=9).map(online_device).collect::<Vec<_>>().join(",");
        assert!(matches!(
            parse_unverified_gateway_proof(&proof_json(&format!("[{devices}]")), NONCE),
            Err(GatewayProbeError::TooManyDevices)
        ));

        let oversized_signature = String::from_utf8(proof_json("[]"))
            .unwrap()
            .replace("3006020101020101", &"01".repeat(73));
        assert!(matches!(
            parse_unverified_gateway_proof(oversized_signature.as_bytes(), NONCE),
            Err(GatewayProbeError::InvalidSignatureLength)
        ));
    }

    #[test]
    fn trust_registry_is_bounded() {
        assert!(matches!(
            TrustedGatewayRegistry::from_spkis(Vec::new()),
            Err(GatewayProbeClientError::InvalidTrustCount(0))
        ));
        assert!(matches!(
            TrustedGatewayRegistry::from_spkis(vec![vec![0; 91]]),
            Err(GatewayProbeClientError::InvalidTrust(
                GatewayProofError::InvalidTrustedSpki
            ))
        ));
    }

    #[test]
    fn production_probe_configuration_is_direct_tailnet_http_and_bounded() {
        let (_, spki) = signing_material();
        let client = GatewayProbeClient::new(
            TrustedGatewayRegistry::from_spkis(vec![spki]).expect("valid trust"),
        );
        let config = client.agent.config();
        assert!(!config.https_only());
        assert!(config.proxy().is_none());
        assert_eq!(config.max_redirects(), 0);
        assert_eq!(config.max_response_header_size(), MAX_RESPONSE_HEADER_BYTES);
        assert_eq!(config.timeouts().global, Some(PROBE_TIMEOUT));
        assert_eq!(config.timeouts().connect, Some(PROBE_CONNECT_TIMEOUT));
        assert_eq!(client.port, DEFAULT_GATEWAY_PORT);
        assert!(client.clone().with_port(0).is_err());
        assert_eq!(client.clone().with_port(9443).unwrap().port, 9443);
        assert!(matches!(
            client.probe_tailnet_address("192.168.1.1".parse().unwrap()),
            Err(GatewayProbeClientError::InvalidTailnetAddress)
        ));
    }

    #[test]
    fn trust_file_and_http_body_reader_stop_at_their_limits() {
        let path = std::env::temp_dir().join(format!(
            "keyferry-oversized-spki-{}-{}.der",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        fs::write(&path, vec![0x55; MAX_TRUSTED_SPKI_BYTES as usize + 1])
            .expect("write oversized trust fixture");
        assert!(matches!(
            TrustedGatewayRegistry::from_spki_file(&path),
            Err(GatewayProbeClientError::InvalidTrust(
                GatewayProofError::InvalidTrustedSpki
            ))
        ));
        fs::remove_file(path).expect("remove oversized trust fixture");

        assert!(matches!(
            classify_gateway_reader(
                io::Cursor::new(vec![b'x'; MAX_GATEWAY_PROOF_BYTES + 1]),
                NONCE,
                &[]
            ),
            Err(GatewayProbeClientError::ResponseTooLarge(bytes))
                if bytes == MAX_GATEWAY_PROOF_BYTES + 1
        ));

        let (private_key, spki) = signing_material();
        let proof = sign_gateway_proof(&private_key, NONCE, [0x33; 16], 1, Vec::new()).unwrap();
        assert!(matches!(
            classify_gateway_reader(io::Cursor::new(proof_to_json(&proof)), NONCE, &[spki]),
            Ok(GatewayCandidateClassification::AuthenticatedGateway(_))
        ));
    }

    #[test]
    fn minimal_gateway_credential_is_strict_and_matches_verified_identity() {
        let (private_key, spki) = signing_material();
        let signed = sign_gateway_proof(&private_key, NONCE, [0x33; 16], 1, Vec::new()).unwrap();
        let verified = verify_gateway_proof(&signed, NONCE, &spki).expect("signed proof");
        let path = temporary_path("gateway-credential-valid");
        let json = format!(
            r#"{{"schema_version":2,"port":18043,"gateway_spki_der":"{}","remote_bearer":"{}"}}"#,
            hex(&spki),
            "ab".repeat(32),
        );
        fs::write(&path, json).expect("write credential fixture");
        let credential = GatewayCredential::from_file(&path).expect("valid credential");
        fs::remove_file(&path).expect("remove credential fixture");

        assert_eq!(credential.port(), 18043);
        assert!(credential.matches(&verified));

        let (_, other_spki) = signing_material();
        let mismatched = GatewayCredential {
            port: 18043,
            spki_der: other_spki,
            remote_bearer: "cd".repeat(32),
        };
        assert!(!mismatched.matches(&verified));
    }

    #[test]
    fn malformed_or_oversized_gateway_credentials_fail_closed() {
        let (_, spki) = signing_material();
        let valid = format!(
            r#"{{"schema_version":2,"port":18043,"gateway_spki_der":"{}","remote_bearer":"{}"}}"#,
            hex(&spki),
            "ab".repeat(32),
        );
        let cases = [
            valid.replace("\"schema_version\":2", "\"schema_version\":1"),
            valid.replace("\"port\":18043", "\"port\":0"),
            valid.replace(&"ab".repeat(32), &"AB".repeat(32)),
            valid.replace(&"ab".repeat(32), &"ab".repeat(31)),
            valid.replace("}", ",\"unknown\":true}"),
            valid.replace("}", ",\"dns_name\":\"controller-a.tail.example\"}"),
        ];
        for (index, contents) in cases.into_iter().enumerate() {
            let path = temporary_path(&format!("gateway-credential-invalid-{index}"));
            fs::write(&path, contents).expect("write invalid credential fixture");
            assert!(matches!(
                GatewayCredential::from_file(&path),
                Err(GatewayProbeClientError::InvalidCredential)
            ));
            fs::remove_file(path).expect("remove invalid credential fixture");
        }

        let path = temporary_path("gateway-credential-oversized");
        fs::write(&path, vec![b'x'; MAX_GATEWAY_CREDENTIAL_BYTES as usize + 1])
            .expect("write oversized credential fixture");
        assert!(matches!(
            GatewayCredential::from_file(&path),
            Err(GatewayProbeClientError::InvalidCredential)
        ));
        fs::remove_file(path).expect("remove oversized credential fixture");
    }

    fn proof_to_json(proof: &SignedGatewayProof) -> Vec<u8> {
        let devices = proof
            .payload
            .devices
            .iter()
            .map(|device| {
                format!(
                    r#"{{"device_id":"{}","configured_here":{},"session_online":{},"link_path":"{}","tls_hmac_authenticated":{},"protocol_session_id":{},"armed":{},"arm_mode":"{}"}}"#,
                    hex(&device.device_id),
                    device.configured_here,
                    device.session_online,
                    match device.link_path {
                        GatewayLinkPath::Offline => "offline",
                        GatewayLinkPath::Wifi => "wifi",
                        GatewayLinkPath::Bluetooth => "bluetooth",
                    },
                    device.tls_hmac_authenticated,
                    device
                        .protocol_session_id
                        .map(|id| format!("\"{}\"", hex(&id)))
                        .unwrap_or_else(|| "null".to_owned()),
                    device.armed,
                    match device.arm_mode {
                        GatewayArmMode::Disarmed => "disarmed",
                        GatewayArmMode::CommandScoped => "command_scoped",
                        GatewayArmMode::Temporary => "temporary",
                        GatewayArmMode::AlwaysReady => "always_ready",
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"protocol_version":{},"request_nonce":"{}","gateway_id":"{}","daemon_boot_id":"{}","api_version":{},"devices":[{}],"signature_der":"{}"}}"#,
            proof.payload.protocol_version,
            hex(&proof.payload.request_nonce),
            hex(&proof.payload.gateway_id),
            hex(&proof.payload.daemon_boot_id),
            proof.payload.api_version,
            devices,
            hex(&proof.signature_der),
        )
        .into_bytes()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn signing_material() -> (Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let private_key =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private_key.as_ref(), &rng)
                .unwrap();
        let mut spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        spki.extend_from_slice(key_pair.public_key().as_ref());
        (private_key.as_ref().to_vec(), spki)
    }

    fn temporary_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "keyferry-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ))
    }
}
