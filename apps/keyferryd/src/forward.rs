//! Automatic forwarding to the owner controller that currently holds a stick.
//!
//! When this controller has no authenticated local link to a configured device, it asks its
//! tailnet peers, on demand and rate-limited, which owner controller holds an authenticated
//! session for that exact device. A peer is used only after owner-rooted mutual TLS and a fresh
//! endpoint route proof bound to this installation and to that peer. Forwarding is a client role
//! of the loopback API only: requests arriving on the owner-mTLS listener are always handled
//! locally, so a route never chains through a third controller.
//!
//! Nothing here stores or logs request bodies. Pins that keep follow-up requests on the holder
//! that received a command hold only identifiers, the route, and timestamps, in memory.

use super::{
    authorize, encode_hex, parse_fixed_lower_hex, parse_input_sequence_json, parse_payload_body,
    ActionsRequest, ApiError, BoxFuture, CancelRequest, CommandOutcome, CreateTextStreamRequest,
    Daemon, DaemonError, DeviceView, DevicesResponse, FirmwareView, InstallationTlsSecretSet,
    InstallationTlsSecretStore, KeyboardSequenceV1, TypeRequest, MAX_FILE_REQUEST_BODY,
    MAX_FILE_SET_REQUEST_BODY, MAX_SEQUENCE_REQUEST_BODY, MAX_TEXT_STREAM_PART_BODY,
    TEXT_STREAM_RECEIPT_RETENTION,
};
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use keyferry_gateway::{
    is_tailscale_ip, tailnet::TailStatus, OwnerGatewayCandidate, RouteProofBinding,
    OWNER_GATEWAY_CANDIDATE_PATH, OWNER_GATEWAY_CONTROL_PORT, OWNER_GATEWAY_PROBE_PORT,
    ROUTE_PROOF_RESPONSE_LEN, ROUTE_PROOF_TTL_MS,
};
use keyferry_layouts::{canonicalize_input_sequence_keys, canonicalize_sequence_keys};
use rustls::pki_types::ServerName;
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinSet,
    time,
};
use tokio_rustls::TlsConnector;
use uuid::Uuid;

/// A verified holder is re-proved with a fresh endpoint route proof at least this often.
const HOLDER_REVERIFY: Duration = Duration::from_secs(30);
/// A holder's displayed device state is re-read at most this often.
const HOLDER_VIEW_TTL: Duration = Duration::from_secs(1);
/// A full tailnet search for an unlocated device runs at most this often.
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(10);
/// `GET /v1/devices` waits at most this long for a search before reporting what it knows.
const STATUS_WAIT: Duration = Duration::from_secs(4);
/// A command for an unlocated device waits at most this long for a search.
const LOCATE_WAIT: Duration = Duration::from_secs(8);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Firmware builds at most one route proof per 100 ms for all controllers together and refuses a
/// faster request (esp_transport.cpp kRouteProofMinimumIntervalMs). A refused proof is asked again
/// after this delay; a proof types nothing on the target computer.
const PROOF_RETRY_DELAY: Duration = Duration::from_millis(150);
const PROOF_ATTEMPTS: usize = 4;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const FILE_TIMEOUT: Duration = Duration::from_secs(125);
const MAX_PROBE_RESPONSE: usize = 2 * 1024;
const MAX_FORWARD_RESPONSE: usize = 256 * 1024;
const MAX_RESPONSE_HEADER: usize = 16 * 1024;
const MAX_TAILNET_PEERS: usize = 64;
const MAX_FORWARD_PINS: usize = 4096;
const MAX_VIA_CHARS: usize = 63;
const DEFAULT_BODY_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const TAILNET_LINK_PATH: &str = "tailnet";

#[derive(Clone, Debug)]
pub(crate) struct TailnetPeer {
    pub(crate) name: Option<String>,
    pub(crate) address: IpAddr,
    pub(crate) probe_port: u16,
    pub(crate) control_port: u16,
}

/// Lists peers worth probing. Membership is a hint only; it grants no authority.
pub(crate) trait PeerSource: Send + Sync + 'static {
    fn peers(&self) -> BoxFuture<'_, Vec<TailnetPeer>>;
}

pub(crate) struct TailscalePeers;

impl PeerSource for TailscalePeers {
    fn peers(&self) -> BoxFuture<'_, Vec<TailnetPeer>> {
        Box::pin(async {
            crate::tailnet::tailscale_status()
                .await
                .map(|status| tailnet_peers(&status))
                .unwrap_or_default()
        })
    }
}

fn tailnet_peers(status: &TailStatus) -> Vec<TailnetPeer> {
    let local = status
        .local
        .addresses
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    status
        .online_peers()
        .filter_map(|peer| {
            let address = peer.addresses.iter().copied().find(|address| {
                address.is_ipv4() && is_tailscale_ip(*address) && !local.contains(address)
            })?;
            Some(TailnetPeer {
                name: Some(peer.hostname.clone()),
                address,
                probe_port: OWNER_GATEWAY_PROBE_PORT,
                control_port: OWNER_GATEWAY_CONTROL_PORT,
            })
        })
        .take(MAX_TAILNET_PEERS)
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Route {
    installation_id: [u8; 16],
    control: SocketAddr,
    name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct HolderView {
    id: String,
    link: String,
    #[serde(default)]
    link_path: Option<String>,
    #[serde(default)]
    armed: bool,
    #[serde(default)]
    maintenance: bool,
    #[serde(default)]
    arm_policy: Option<String>,
    #[serde(default)]
    firmware: Option<FirmwareView>,
    #[serde(default)]
    active_command_id: Option<String>,
    #[serde(default)]
    active_outcome: Option<CommandOutcome>,
}

impl HolderView {
    /// A holder must report its own authenticated Wi-Fi or Bluetooth session, never a relay.
    fn holds(&self, device: &str) -> bool {
        self.id == device
            && self.link == "authenticated"
            && matches!(self.link_path.as_deref(), Some("wifi" | "bluetooth"))
    }
}

#[derive(Clone)]
struct Holder {
    route: Route,
    verified_at: Instant,
    view: HolderView,
    view_at: Instant,
}

#[derive(Clone)]
struct CommandPin {
    device: String,
    route: Route,
    unknown: bool,
    touched_at: Instant,
}

#[derive(Clone)]
struct StreamPin {
    device: String,
    route: Route,
    remote_epoch: String,
    touched_at: Instant,
}

#[derive(Default)]
struct ForwardState {
    holders: HashMap<String, Holder>,
    commands: HashMap<Uuid, CommandPin>,
    streams: HashMap<Uuid, StreamPin>,
    last_discovery: Option<Instant>,
}

impl ForwardState {
    fn prune(&mut self) {
        let now = Instant::now();
        self.commands
            .retain(|_, pin| now.duration_since(pin.touched_at) < TEXT_STREAM_RECEIPT_RETENTION);
        self.streams
            .retain(|_, pin| now.duration_since(pin.touched_at) < TEXT_STREAM_RECEIPT_RETENTION);
    }

    fn make_room(&mut self) {
        self.prune();
        while self.commands.len() + self.streams.len() >= MAX_FORWARD_PINS {
            let oldest_command = self
                .commands
                .iter()
                .min_by_key(|(_, pin)| pin.touched_at)
                .map(|(id, pin)| (*id, pin.touched_at));
            let oldest_stream = self
                .streams
                .iter()
                .min_by_key(|(_, pin)| pin.touched_at)
                .map(|(id, pin)| (*id, pin.touched_at));
            match (oldest_command, oldest_stream) {
                (Some((id, at)), Some((_, stream_at))) if at <= stream_at => {
                    self.commands.remove(&id);
                }
                (_, Some((id, _))) => {
                    self.streams.remove(&id);
                }
                (Some((id, _)), None) => {
                    self.commands.remove(&id);
                }
                (None, None) => break,
            }
        }
    }
}

enum RouteCheck {
    Verified,
    Busy,
    Failed(String),
}

impl RouteCheck {
    fn failure(self) -> Option<String> {
        match self {
            Self::Verified => None,
            Self::Busy => Some("route_proof.busy".to_owned()),
            Self::Failed(reason) => Some(reason),
        }
    }
}

enum Proven {
    Route(Route),
    /// No holder is known; the local handler answers as it would without forwarding.
    Local,
    Refused(Response),
}

type CaptureInventory = Option<(Instant, Vec<Value>, Vec<Value>)>;

pub(crate) struct Forwarder {
    installation_id: [u8; 16],
    credentials: HashMap<String, InstallationTlsSecretStore>,
    connector: TlsConnector,
    peers: Box<dyn PeerSource>,
    state: Mutex<ForwardState>,
    refreshing: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    captures: Mutex<HashMap<String, (Route, String)>>,
    capture_inventory: tokio::sync::Mutex<CaptureInventory>,
}

impl Forwarder {
    pub(crate) fn new(
        stores: &InstallationTlsSecretSet,
        peers: Box<dyn PeerSource>,
    ) -> Result<Self, DaemonError> {
        let first = stores
            .iter()
            .next()
            .ok_or_else(|| DaemonError::Tls("forwarding requires an installation".to_owned()))?;
        let installation_id = first.installation_id();
        let mut credentials = HashMap::with_capacity(stores.len());
        for store in stores.iter() {
            if store.installation_id() != installation_id {
                return Err(DaemonError::Tls(
                    "forwarding credentials do not share one installation identity".to_owned(),
                ));
            }
            credentials.insert(
                Uuid::from_bytes(store.device_id()).to_string(),
                store.clone(),
            );
        }
        let connector = first
            .remote_tls_connector()
            .map_err(|error| DaemonError::Tls(error.to_string()))?;
        Ok(Self {
            installation_id,
            credentials,
            connector,
            peers,
            state: Mutex::new(ForwardState::default()),
            refreshing: Mutex::default(),
            captures: Mutex::new(HashMap::new()),
            capture_inventory: tokio::sync::Mutex::new(None),
        })
    }

    /// Capture discovery never trusts the plaintext hint: inventory must arrive over owner-mTLS.
    pub(crate) async fn capture_sources(self: &Arc<Self>) -> (Vec<Value>, Vec<Value>) {
        let mut inventory = self.capture_inventory.lock().await;
        if let Some((at, sources, errors)) = &*inventory {
            if at.elapsed() < DISCOVERY_INTERVAL {
                return (sources.clone(), errors.clone());
            }
        }
        let started = Instant::now();
        let mut tasks = JoinSet::new();
        for peer in self.peers.peers().await.into_iter().take(MAX_TAILNET_PEERS) {
            let this = self.clone();
            tasks.spawn(async move {
                let installation_id = probe_candidate(&peer).await?;
                if installation_id == this.installation_id {
                    return None;
                }
                let route = Route {
                    installation_id,
                    control: SocketAddr::new(peer.address, peer.control_port),
                    name: peer.name.as_deref().map(display_name),
                };
                // Devices are sorted only to make inventory deterministic, never to choose input.
                let mut devices = this.credentials.keys().cloned().collect::<Vec<_>>();
                devices.sort();
                for device in devices {
                    let path = format!("/v1/devices/{device}/capture/sources");
                    if let OwnerExchange::Response {
                        status: 200, body, ..
                    } = this
                        .exchange(&route, "GET", &path, None, CONTROL_TIMEOUT)
                        .await
                    {
                        let value: Value = serde_json::from_slice(&body).ok()?;
                        return Some((route, value));
                    }
                }
                None
            });
        }
        let mut sources = Vec::new();
        let mut errors = Vec::new();
        while let Ok(Some(result)) = time::timeout(
            STATUS_WAIT.saturating_sub(started.elapsed()),
            tasks.join_next(),
        )
        .await
        {
            if let Ok(Some((route, value))) = result {
                let controller = encode_hex(&route.installation_id);
                if let Some(error) = value["error"].as_str() {
                    errors.push(serde_json::json!({"controller":controller,"error":error}));
                }
                if value["sources"].as_array().is_none_or(|a| a.len() > 32) {
                    errors.push(serde_json::json!({"controller":controller,"error":"capture.invalid_inventory","count":value["sources"].as_array().map_or(1,Vec::len)}));
                    continue;
                }
                if let Some(entries) = value["sources"].as_array() {
                    for entry in entries.iter().take(32) {
                        let Some(local) = entry["id"]
                            .as_str()
                            .filter(|id| id.starts_with("local:") && id.len() <= 1024)
                        else {
                            errors.push(serde_json::json!({"controller":controller,"error":"capture.invalid_source","count":1}));
                            continue;
                        };
                        if !entry["recognized"].is_boolean()
                            || !entry["name"].is_string()
                            || entry["controller"] != "local"
                        {
                            errors.push(serde_json::json!({"controller":controller,"error":"capture.invalid_source","count":1}));
                            continue;
                        }
                        let id = format!("{controller}:{}", &local[6..]);
                        let mut entry = entry.clone();
                        entry["id"] = serde_json::json!(id);
                        entry["controller"] = serde_json::json!(controller);
                        let mut captures = self.captures.lock().expect("capture routes");
                        if captures.len() < MAX_TAILNET_PEERS * 32 || captures.contains_key(&id) {
                            captures.insert(id, (route.clone(), local.to_owned()));
                            sources.push(entry);
                        }
                    }
                }
            }
        }
        if !tasks.is_empty() {
            errors
                .push(serde_json::json!({"error":"capture.discovery_timeout","count":tasks.len()}));
        }
        sources.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        sources.dedup_by(|a, b| a["id"] == b["id"]);
        *inventory = Some((Instant::now(), sources.clone(), errors.clone()));
        (sources, errors)
    }

    pub(crate) async fn capture_prove_device(self: &Arc<Self>, device: &str) -> bool {
        matches!(self.prove_holder(device, None).await, Proven::Route(_))
    }

    pub(crate) async fn capture_frame(
        self: &Arc<Self>,
        daemon: &Daemon,
        mut request: crate::capture::FrameRequest,
    ) -> Response {
        if !self.handles(&request.device) {
            return ApiError::auth("capture.device_not_authorized").into_response();
        }
        let target = self
            .captures
            .lock()
            .expect("capture routes")
            .get(&request.source)
            .cloned();
        let Some((route, local)) = target else {
            return ApiError::unavailable("capture.peer_offline_or_select_source").into_response();
        };
        // Reprove the eyes peer if it holds the device. If eyes and hands differ, prove the
        // actual holder; the eyes daemon independently reproves its grant on every frame read.
        if !matches!(
            self.verify_route(&route, &request.device).await,
            RouteCheck::Verified
        ) && !daemon.local_link_authenticated(&request.device)
            && !self.capture_prove_device(&request.device).await
        {
            return ApiError::unavailable("capture.peer_offline_or_fresh_proof_failed")
                .into_response();
        }
        request.source = local;
        let path = format!("/v1/devices/{}/capture/frame", request.device);
        let Ok(body) = serde_json::to_vec(&request) else {
            return ApiError::bad_request("capture.request").into_response();
        };
        match owner_exchange(
            &self.connector,
            &route.installation_id,
            route.control,
            "POST",
            &path,
            Some(&body),
            keyferry_capture::frames::FRAME_WAIT + Duration::from_secs(5),
            crate::capture::MAX_WIRE + MAX_RESPONSE_HEADER,
        )
        .await
        {
            OwnerExchange::Response {
                status,
                content_type,
                body,
            } if body.len() <= crate::capture::MAX_WIRE => passthrough(status, content_type, body),
            OwnerExchange::Response { .. } => {
                ApiError::unavailable("capture.size_limit").into_response()
            }
            OwnerExchange::NotSent(_) | OwnerExchange::Uncertain(_) => {
                ApiError::unavailable("capture.peer_offline_or_invalid_frame").into_response()
            }
        }
    }

    pub(crate) fn device_ids(&self) -> impl Iterator<Item = &String> {
        self.credentials.keys()
    }

    fn handles(&self, device: &str) -> bool {
        self.credentials.contains_key(device)
    }

    fn state(&self) -> MutexGuard<'_, ForwardState> {
        self.state.lock().expect("forwarding state lock")
    }

    async fn exchange(
        &self,
        route: &Route,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        timeout: Duration,
    ) -> OwnerExchange {
        // A failed connection sent nothing. Read-only observations may also
        // be repeated after a lost response; mutating requests never are.
        for attempt in 0..3 {
            let response = owner_exchange(
                &self.connector,
                &route.installation_id,
                route.control,
                method,
                path,
                body,
                timeout,
                MAX_FORWARD_RESPONSE,
            )
            .await;
            if attempt == 2
                || !(matches!(response, OwnerExchange::NotSent(_))
                    || method == "GET" && matches!(response, OwnerExchange::Uncertain(_)))
            {
                return response;
            }
            time::sleep(Duration::from_millis(150)).await;
        }
        unreachable!("bounded exchange returns its last result")
    }

    /// Asks the peer's live endpoint for a proof addressed to this installation and verifies it
    /// under this installation's own device-scoped secret. A proof the holder reports refused or
    /// busy is asked for again, a bounded number of times, after the endpoint's minimum interval.
    async fn verify_route(&self, route: &Route, device: &str) -> RouteCheck {
        let mut attempt = 1;
        loop {
            match self.verify_route_once(route, device).await {
                Err(_) if attempt < PROOF_ATTEMPTS => {
                    attempt += 1;
                    time::sleep(PROOF_RETRY_DELAY).await;
                }
                Ok(check) | Err(check) => return check,
            }
        }
    }

    /// One proof request; `Err` carries a refusal that may clear once the endpoint is free.
    async fn verify_route_once(
        &self,
        route: &Route,
        device: &str,
    ) -> Result<RouteCheck, RouteCheck> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            proof: String,
        }
        let failed = |reason: &str| Ok(RouteCheck::Failed(reason.to_owned()));
        let Some(store) = self.credentials.get(device) else {
            return failed("route_proof.no_credential");
        };
        let mut nonce = [0_u8; 32];
        if getrandom::fill(&mut nonce).is_err() || nonce.iter().all(|byte| *byte == 0) {
            return failed("route_proof.nonce");
        }
        let path = format!(
            "/v2/devices/{device}/route-proof?nonce={}",
            encode_hex(&nonce)
        );
        let started = Instant::now();
        let body = match self
            .exchange(route, "GET", &path, None, CONTROL_TIMEOUT)
            .await
        {
            OwnerExchange::Response {
                status: 200, body, ..
            } => body,
            // The holder has an active command, or the endpoint is busy.
            OwnerExchange::Response { status: 409, .. } => return Err(RouteCheck::Busy),
            // The endpoint refused the proof, as it does inside its minimum interval.
            OwnerExchange::Response { status: 422, .. } => {
                return Err(RouteCheck::Failed(
                    "route_proof.endpoint_refused".to_owned(),
                ))
            }
            OwnerExchange::Response { status, body, .. } => {
                return Ok(RouteCheck::Failed(holder_reason(
                    "route_proof",
                    status,
                    &body,
                )))
            }
            OwnerExchange::NotSent(reason) | OwnerExchange::Uncertain(reason) => {
                return failed(reason)
            }
        };
        if started.elapsed() > Duration::from_millis(ROUTE_PROOF_TTL_MS as u64) {
            return failed("route_proof.expired");
        }
        let Ok(wire) = serde_json::from_slice::<Wire>(&body) else {
            return failed("route_proof.malformed");
        };
        let Ok(proof) = parse_fixed_lower_hex::<ROUTE_PROOF_RESPONSE_LEN>(&wire.proof, "proof")
        else {
            return failed("route_proof.malformed");
        };
        let binding = RouteProofBinding {
            owner_id: store.owner_id(),
            device_id: store.device_id(),
            gateway_installation_id: route.installation_id,
            controller_installation_id: self.installation_id,
            controller_nonce: nonce,
        };
        match keyferry_gateway::verify_route_proof_response(
            &store.route_proof_secret(),
            &binding,
            &proof,
        ) {
            Ok(_) => Ok(RouteCheck::Verified),
            Err(_) => failed("route_proof.invalid"),
        }
    }

    /// The holder's own view of `device`; `Err` is the reason it is not a usable holder.
    async fn fetch_view(&self, route: &Route, device: &str) -> Result<HolderView, String> {
        match self
            .exchange(
                route,
                "GET",
                &format!("/v1/devices/{device}"),
                None,
                CONTROL_TIMEOUT,
            )
            .await
        {
            OwnerExchange::Response {
                status: 200, body, ..
            } => match serde_json::from_slice::<HolderView>(&body) {
                Ok(view) if view.holds(device) => Ok(view),
                Ok(_) => Err("holder_view.not_holding".to_owned()),
                Err(_) => Err("holder_view.malformed".to_owned()),
            },
            OwnerExchange::Response { status, body, .. } => {
                Err(holder_reason("holder_view", status, &body))
            }
            OwnerExchange::NotSent(reason) | OwnerExchange::Uncertain(reason) => {
                Err(reason.to_owned())
            }
        }
    }

    /// Re-checks one device's cached holder and returns the device if it has none. One check
    /// per device runs at a time; different devices never wait on each other's holder.
    async fn refresh_holder(self: Arc<Self>, device: String) -> Option<String> {
        let flight = Arc::clone(
            self.refreshing
                .lock()
                .expect("holder refresh")
                .entry(device.clone())
                .or_default(),
        );
        let _flight = flight.lock().await;
        let Some(holder) = self.state().holders.get(&device).cloned() else {
            return Some(device);
        };
        let now = Instant::now();
        let reverify = now.duration_since(holder.verified_at) >= HOLDER_REVERIFY;
        if !reverify && now.duration_since(holder.view_at) < HOLDER_VIEW_TTL {
            return None;
        }
        let check = if reverify {
            self.verify_route(&holder.route, &device).await
        } else {
            RouteCheck::Busy
        };
        let view = match check {
            RouteCheck::Failed(reason) => Err(reason),
            RouteCheck::Verified | RouteCheck::Busy => {
                self.fetch_view(&holder.route, &device).await
            }
        };
        let mut state = self.state();
        match view {
            Ok(view) => {
                if let Some(entry) = state.holders.get_mut(&device) {
                    entry.view = view;
                    entry.view_at = Instant::now();
                    if reverify {
                        entry.verified_at = Instant::now();
                    }
                }
                None
            }
            Err(reason) => {
                state.holders.remove(&device);
                crate::daemon_log!(
                    "keyferryd lost the tailnet route to device {device} via {}: {reason}",
                    holder_name(&holder.route)
                );
                Some(device)
            }
        }
    }

    /// Brings the holder cache up to date for `devices`, each device on its own task; a full
    /// tailnet search runs only when a device has no holder and the last search is not recent.
    async fn refresh(self: Arc<Self>, devices: Vec<String>) {
        let mut checks = JoinSet::new();
        for device in devices {
            checks.spawn(Arc::clone(&self).refresh_holder(device));
        }
        let mut missing = Vec::new();
        while let Some(result) = checks.join_next().await {
            if let Ok(Some(device)) = result {
                missing.push(device);
            }
        }
        if missing.is_empty() {
            return;
        }
        {
            let mut state = self.state();
            if state
                .last_discovery
                .is_some_and(|at| at.elapsed() < DISCOVERY_INTERVAL)
            {
                return;
            }
            state.last_discovery = Some(Instant::now());
        }
        let mut probes = JoinSet::new();
        for peer in self.peers.peers().await {
            probes.spawn(async move {
                let installation_id = probe_candidate(&peer).await?;
                Some(Route {
                    installation_id,
                    control: SocketAddr::new(peer.address, peer.control_port),
                    name: peer.name.as_deref().map(display_name),
                })
            });
        }
        let mut candidates = Vec::<Route>::new();
        while let Some(result) = probes.join_next().await {
            if let Ok(Some(route)) = result {
                if route.installation_id != self.installation_id
                    && candidates
                        .iter()
                        .all(|known| known.installation_id != route.installation_id)
                {
                    candidates.push(route);
                }
            }
        }
        let mut checks = JoinSet::new();
        for device in &missing {
            for route in &candidates {
                let forwarder = Arc::clone(&self);
                let device = device.clone();
                let route = route.clone();
                checks.spawn(async move {
                    if !matches!(
                        forwarder.verify_route(&route, &device).await,
                        RouteCheck::Verified
                    ) {
                        return None;
                    }
                    let view = forwarder.fetch_view(&route, &device).await.ok()?;
                    Some((device, route, view))
                });
            }
        }
        while let Some(result) = checks.join_next().await {
            let Ok(Some((device, route, view))) = result else {
                continue;
            };
            let mut state = self.state();
            if state.holders.contains_key(&device) {
                continue;
            }
            crate::daemon_log!(
                "keyferryd reaches device {device} through owner controller {}",
                holder_name(&route)
            );
            let now = Instant::now();
            state.holders.insert(
                device,
                Holder {
                    route,
                    verified_at: now,
                    view,
                    view_at: now,
                },
            );
        }
    }

    /// Runs a refresh in the background and waits at most `wait` for it.
    async fn refresh_within(self: &Arc<Self>, devices: Vec<String>, wait: Duration) {
        let task = tokio::spawn(Arc::clone(self).refresh(devices));
        let _ = time::timeout(wait, task).await;
    }

    fn fresh_route(&self, device: &str) -> Option<Route> {
        self.state()
            .holders
            .get(device)
            .filter(|holder| holder.verified_at.elapsed() < HOLDER_REVERIFY)
            .map(|holder| holder.route.clone())
    }

    async fn locate(self: &Arc<Self>, device: &str) -> Option<Route> {
        if let Some(route) = self.fresh_route(device) {
            return Some(route);
        }
        self.refresh_within(vec![device.to_owned()], LOCATE_WAIT)
            .await;
        self.fresh_route(device)
    }

    fn forget_holder(&self, device: &str, route: &Route, reason: &str) {
        let mut state = self.state();
        if state
            .holders
            .get(device)
            .is_some_and(|holder| holder.route == *route)
        {
            state.holders.remove(device);
            // Direct evidence that the route is stale permits an immediate new search.
            state.last_discovery = None;
            crate::daemon_log!(
                "keyferryd lost the tailnet route to device {device} via {}: {reason}",
                holder_name(route)
            );
        }
    }

    /// A fresh proof also renews the cached holder, so the next command needs no extra proof.
    fn mark_verified(&self, device: &str, route: &Route) {
        if let Some(holder) = self.state().holders.get_mut(device) {
            if holder.route == *route {
                holder.verified_at = Instant::now();
            }
        }
    }

    /// Passes a holder's answer through, logging it first when the holder refused the request.
    fn answered(
        &self,
        device: &str,
        route: &Route,
        scope: &str,
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    ) -> Response {
        if status < 400 {
            return passthrough(status, content_type, body);
        }
        let reason = holder_reason(scope, status, &body);
        let response = passthrough(status, content_type, body);
        self.failed(device, None, Some(route), &reason, response)
    }

    /// Logs why forwarded work failed, as identifiers and a reason code only, and answers it.
    fn failed(
        &self,
        device: &str,
        command_id: Option<Uuid>,
        route: Option<&Route>,
        reason: &str,
        response: Response,
    ) -> Response {
        log_failure(
            device,
            command_id,
            route,
            response.status().as_u16(),
            reason,
        );
        response
    }

    /// Finds the holder for new work and proves it now. A stale holder is forgotten and the
    /// search repeats once; no request reaches any holder before its proof verifies.
    async fn prove_holder(self: &Arc<Self>, device: &str, command_id: Option<Uuid>) -> Proven {
        let mut lost: Option<(Route, String)> = None;
        for _ in 0..2 {
            let Some(route) = self.locate(device).await else {
                // No holder is known now; the local handler answers as without forwarding.
                if let Some((route, reason)) = &lost {
                    log_failure(device, command_id, Some(route), "local", reason);
                }
                return Proven::Local;
            };
            match self.verify_route(&route, device).await {
                RouteCheck::Verified => {
                    self.mark_verified(device, &route);
                    return Proven::Route(route);
                }
                RouteCheck::Busy => match self.fetch_view(&route, device).await {
                    Ok(view) => {
                        let response = match view.active_command_id {
                            Some(active) => ApiError::busy(active),
                            None => ApiError::conflict("tailnet_route.busy"),
                        };
                        return Proven::Refused(self.failed(
                            device,
                            command_id,
                            Some(&route),
                            "route_proof.busy",
                            response.into_response(),
                        ));
                    }
                    Err(reason) => {
                        self.forget_holder(device, &route, &reason);
                        lost = Some((route, reason));
                    }
                },
                RouteCheck::Failed(reason) => {
                    self.forget_holder(device, &route, &reason);
                    lost = Some((route, reason));
                }
            }
        }
        let (route, reason) = lost.expect("two located holders failed");
        Proven::Refused(self.failed(
            device,
            command_id,
            Some(&route),
            &reason,
            route_unavailable(),
        ))
    }

    async fn overlay(self: &Arc<Self>, views: &mut [DeviceView]) {
        let needed = views
            .iter()
            .filter(|view| view.link != "authenticated" && self.handles(&view.id))
            .map(|view| view.id.clone())
            .collect::<Vec<_>>();
        if needed.is_empty() {
            return;
        }
        self.refresh_within(needed, STATUS_WAIT).await;
        let state = self.state();
        for view in views.iter_mut().filter(|view| view.link != "authenticated") {
            if let Some(holder) = state
                .holders
                .get(&view.id)
                .filter(|holder| holder.view_at.elapsed() < HOLDER_REVERIFY)
            {
                apply_remote(view, &holder.route, &holder.view);
            }
        }
    }

    fn command_pin(&self, command_id: Uuid) -> Option<CommandPin> {
        let mut state = self.state();
        state.prune();
        state.commands.get(&command_id).cloned()
    }

    fn pin_command(&self, command_id: Uuid, device: &str, route: &Route) {
        let mut state = self.state();
        state.make_room();
        state.commands.insert(
            command_id,
            CommandPin {
                device: device.to_owned(),
                route: route.clone(),
                unknown: false,
                touched_at: Instant::now(),
            },
        );
    }

    fn unpin_command(&self, command_id: Uuid) {
        self.state().commands.remove(&command_id);
    }

    fn mark_unknown(&self, command_id: Uuid) {
        if let Some(pin) = self.state().commands.get_mut(&command_id) {
            pin.unknown = true;
        }
    }

    fn stream_pin(&self, job: Uuid) -> Option<StreamPin> {
        let mut state = self.state();
        state.prune();
        let pin = state.streams.get_mut(&job)?;
        pin.touched_at = Instant::now();
        Some(pin.clone())
    }

    fn pin_stream(&self, job: Uuid, device: &str, route: &Route, remote_epoch: &str) {
        let mut state = self.state();
        state.make_room();
        state.streams.insert(
            job,
            StreamPin {
                device: device.to_owned(),
                route: route.clone(),
                remote_epoch: remote_epoch.to_owned(),
                touched_at: Instant::now(),
            },
        );
    }

    fn unpin_stream(&self, job: Uuid) {
        self.state().streams.remove(&job);
    }

    /// The holder of the most recent forwarded work for `device`, for an unscoped cancel.
    fn active_route(&self, device: &str) -> Option<Route> {
        let mut state = self.state();
        state.prune();
        let command = state
            .commands
            .values()
            .filter(|pin| pin.device == device && !pin.unknown)
            .map(|pin| (pin.touched_at, &pin.route));
        let stream = state
            .streams
            .values()
            .filter(|pin| pin.device == device)
            .map(|pin| (pin.touched_at, &pin.route));
        command
            .chain(stream)
            .max_by_key(|(at, _)| *at)
            .map(|(_, route)| route.clone())
    }

    async fn dispatch(self: &Arc<Self>, daemon: &Daemon, op: Op, body: &Bytes) -> Option<Response> {
        match op {
            Op::List => {
                let mut views = daemon
                    .0
                    .devices
                    .keys()
                    .map(|id| daemon.device_view(id))
                    .collect::<Result<Vec<_>, _>>()
                    .ok()?;
                self.overlay(&mut views).await;
                Some(Json(DevicesResponse { devices: views }).into_response())
            }
            Op::Get { device } => {
                let mut view = daemon.device_view(&device).ok()?;
                self.overlay(std::slice::from_mut(&mut view)).await;
                Some(Json(view).into_response())
            }
            Op::File {
                device,
                method,
                set,
            } => self.file(daemon, &device, &method, set, body).await,
            Op::Command { device, kind } => self.command(daemon, &device, kind, body).await,
            Op::StreamCreate { device } => self.stream_create(daemon, &device, body).await,
            Op::Stream {
                device,
                job,
                action,
            } => self.stream(daemon, &device, job, action, body).await,
            Op::Control {
                device,
                segment,
                method,
            } => self.control(daemon, &device, segment, &method, body).await,
            Op::Cancel { device } => self.cancel(daemon, &device, body).await,
            Op::Outcome { device, command } => self.outcome(daemon, &device, command).await,
        }
    }

    async fn file(
        self: &Arc<Self>,
        daemon: &Daemon,
        device: &str,
        method: &Method,
        set: bool,
        body: &[u8],
    ) -> Option<Response> {
        if daemon.local_link_authenticated(device) {
            return None;
        }
        let route = match self.prove_holder(device, None).await {
            Proven::Route(route) => route,
            Proven::Local => return None,
            Proven::Refused(response) => return Some(response),
        };
        let path = format!(
            "/v1/devices/{device}/{}",
            if set { "files" } else { "file" }
        );
        let payload = (method == Method::POST).then_some(body);
        Some(
            match self
                .exchange(&route, method.as_str(), &path, payload, FILE_TIMEOUT)
                .await
            {
                OwnerExchange::Response {
                    status,
                    content_type,
                    body,
                } => self.answered(device, &route, "file", status, content_type, body),
                OwnerExchange::NotSent(reason) => {
                    self.failed(device, None, Some(&route), reason, route_unavailable())
                }
                OwnerExchange::Uncertain(reason) => {
                    self.failed(device, None, Some(&route), reason, route_uncertain(None))
                }
            },
        )
    }

    async fn command(
        self: &Arc<Self>,
        daemon: &Daemon,
        device: &str,
        kind: CommandKind,
        body: &[u8],
    ) -> Option<Response> {
        let (command_id, body) = prepare_command_body(kind, body)?;
        if daemon.knows_command(device, command_id) {
            return None;
        }
        let (route, new_pin) = match self.command_pin(command_id) {
            Some(pin) if pin.device != device => return None,
            // A command that may have started is never sent again.
            Some(pin) if pin.unknown => {
                return Some(unknown_command(command_id, device, StatusCode::ACCEPTED));
            }
            Some(pin) => {
                if let Some(reason) = self.verify_route(&pin.route, device).await.failure() {
                    return Some(self.failed(
                        device,
                        Some(command_id),
                        Some(&pin.route),
                        &reason,
                        route_unavailable(),
                    ));
                }
                (pin.route, false)
            }
            None => {
                if daemon.local_link_authenticated(device) {
                    return None;
                }
                match self.prove_holder(device, Some(command_id)).await {
                    Proven::Route(route) => (route, true),
                    Proven::Local => return None,
                    Proven::Refused(response) => return Some(response),
                }
            }
        };
        if new_pin {
            self.pin_command(command_id, device, &route);
        }
        let path = format!("/v1/devices/{device}/{}", kind.segment());
        Some(
            match self
                .exchange(&route, "POST", &path, Some(&body), COMMAND_TIMEOUT)
                .await
            {
                OwnerExchange::NotSent(reason) => {
                    if new_pin {
                        self.unpin_command(command_id);
                    }
                    self.failed(
                        device,
                        Some(command_id),
                        Some(&route),
                        reason,
                        route_unavailable(),
                    )
                }
                OwnerExchange::Response {
                    status,
                    content_type,
                    body,
                } if status >= 400 => {
                    if new_pin {
                        self.unpin_command(command_id);
                    }
                    let reason = holder_reason("command", status, &body);
                    let response = passthrough(status, content_type, body);
                    self.failed(device, Some(command_id), Some(&route), &reason, response)
                }
                OwnerExchange::Response {
                    status,
                    content_type,
                    body,
                } => passthrough(status, content_type, body),
                OwnerExchange::Uncertain(reason) => {
                    // Read-only reconciliation, never resubmission.
                    let outcome = format!("/v1/devices/{device}/commands/{command_id}");
                    match self
                        .exchange(&route, "GET", &outcome, None, CONTROL_TIMEOUT)
                        .await
                    {
                        OwnerExchange::Response {
                            status: 200,
                            content_type,
                            body,
                        } => passthrough(202, content_type, body),
                        _ => {
                            self.mark_unknown(command_id);
                            self.failed(
                                device,
                                Some(command_id),
                                Some(&route),
                                reason,
                                unknown_command(command_id, device, StatusCode::ACCEPTED),
                            )
                        }
                    }
                }
            },
        )
    }

    async fn outcome(&self, daemon: &Daemon, device: &str, command_id: Uuid) -> Option<Response> {
        if daemon.knows_command(device, command_id) {
            return None;
        }
        let pin = self
            .command_pin(command_id)
            .filter(|pin| pin.device == device)?;
        // Keep observing an uncertain command at its original holder. A
        // transient lost response must not permanently freeze its receipt.
        let path = format!("/v1/devices/{device}/commands/{command_id}");
        Some(
            match self
                .exchange(&pin.route, "GET", &path, None, CONTROL_TIMEOUT)
                .await
            {
                OwnerExchange::Response {
                    status,
                    content_type,
                    body,
                } => passthrough(status, content_type, body),
                OwnerExchange::NotSent(_) | OwnerExchange::Uncertain(_) if pin.unknown => {
                    unknown_command(command_id, device, StatusCode::OK)
                }
                OwnerExchange::NotSent(reason) | OwnerExchange::Uncertain(reason) => self.failed(
                    device,
                    Some(command_id),
                    Some(&pin.route),
                    reason,
                    route_unavailable(),
                ),
            },
        )
    }

    async fn control(
        self: &Arc<Self>,
        daemon: &Daemon,
        device: &str,
        segment: &'static str,
        method: &Method,
        body: &[u8],
    ) -> Option<Response> {
        if daemon.local_link_authenticated(device) {
            return None;
        }
        // Disarm needs no proof on the holder and must work while a command runs there.
        let route = if segment != "disarm" {
            match self.prove_holder(device, None).await {
                Proven::Route(route) => route,
                Proven::Local => return None,
                Proven::Refused(response) => return Some(response),
            }
        } else {
            self.locate(device).await?
        };
        let path = format!("/v1/devices/{device}/{segment}");
        let body = (!body.is_empty()).then_some(body);
        Some(
            match self
                .exchange(&route, method.as_str(), &path, body, CONTROL_TIMEOUT)
                .await
            {
                OwnerExchange::Response {
                    status: 200,
                    content_type,
                    body,
                } => {
                    let holder = serde_json::from_slice::<HolderView>(&body)
                        .ok()
                        .filter(|view| view.holds(device));
                    match (holder, daemon.device_view(device)) {
                        (Some(holder), Ok(mut view)) => {
                            apply_remote(&mut view, &route, &holder);
                            if let Some(entry) = self.state().holders.get_mut(device) {
                                if entry.route == route {
                                    entry.view = holder;
                                    entry.view_at = Instant::now();
                                }
                            }
                            Json(view).into_response()
                        }
                        _ => passthrough(200, content_type, body),
                    }
                }
                OwnerExchange::Response {
                    status,
                    content_type,
                    body,
                } => self.answered(device, &route, "control", status, content_type, body),
                OwnerExchange::NotSent(reason) => {
                    self.failed(device, None, Some(&route), reason, route_unavailable())
                }
                OwnerExchange::Uncertain(reason) if method == Method::GET => {
                    self.failed(device, None, Some(&route), reason, route_unavailable())
                }
                OwnerExchange::Uncertain(reason) => {
                    self.failed(device, None, Some(&route), reason, route_uncertain(None))
                }
            },
        )
    }

    async fn cancel(
        self: &Arc<Self>,
        daemon: &Daemon,
        device: &str,
        body: &[u8],
    ) -> Option<Response> {
        let request: CancelRequest = serde_json::from_slice(body).ok()?;
        let route = match request.command_id {
            Some(command_id) if daemon.knows_command(device, command_id) => return None,
            Some(command_id) => {
                self.command_pin(command_id)
                    .filter(|pin| pin.device == device)?
                    .route
            }
            None => {
                if daemon.local_link_authenticated(device) {
                    return None;
                }
                match self.active_route(device) {
                    Some(route) => route,
                    None => self.locate(device).await?,
                }
            }
        };
        let path = format!("/v1/devices/{device}/cancel");
        Some(
            match self
                .exchange(&route, "POST", &path, Some(body), CONTROL_TIMEOUT)
                .await
            {
                OwnerExchange::Response {
                    status,
                    content_type,
                    body,
                } => self.answered(device, &route, "cancel", status, content_type, body),
                OwnerExchange::NotSent(reason) => {
                    self.failed(device, None, Some(&route), reason, route_unavailable())
                }
                OwnerExchange::Uncertain(reason) => {
                    self.failed(device, None, Some(&route), reason, route_uncertain(None))
                }
            },
        )
    }

    async fn remote_epoch(&self, route: &Route) -> Option<String> {
        match self
            .exchange(route, "GET", "/v1/capabilities", None, CONTROL_TIMEOUT)
            .await
        {
            OwnerExchange::Response {
                status: 200, body, ..
            } => serde_json::from_slice::<Value>(&body)
                .ok()?
                .get("epoch")?
                .as_str()
                .map(str::to_owned),
            _ => None,
        }
    }

    async fn stream_create(
        self: &Arc<Self>,
        daemon: &Daemon,
        device: &str,
        body: &[u8],
    ) -> Option<Response> {
        let request: CreateTextStreamRequest = serde_json::from_slice(body).ok()?;
        let job = Uuid::parse_str(&request.job_id)
            .ok()
            .filter(|job| job.get_version_num() == 7)?;
        // The local epoch check keeps the local error contract for a stale client.
        let local_epoch = daemon.0.epoch.to_string();
        if daemon.knows_text_stream(device, job) || request.epoch != local_epoch {
            return None;
        }
        let (route, remote_epoch, new_pin) = match self.stream_pin(job) {
            Some(pin) if pin.device != device => return None,
            Some(pin) => {
                if let Some(reason) = self.verify_route(&pin.route, device).await.failure() {
                    return Some(self.failed(
                        device,
                        None,
                        Some(&pin.route),
                        &reason,
                        route_unavailable(),
                    ));
                }
                (pin.route, pin.remote_epoch, false)
            }
            None => {
                if daemon.local_link_authenticated(device) {
                    return None;
                }
                let route = match self.prove_holder(device, None).await {
                    Proven::Route(route) => route,
                    Proven::Local => return None,
                    Proven::Refused(response) => return Some(response),
                };
                let Some(epoch) = self.remote_epoch(&route).await else {
                    return Some(self.failed(
                        device,
                        None,
                        Some(&route),
                        "holder_epoch.unavailable",
                        route_unavailable(),
                    ));
                };
                (route, epoch, true)
            }
        };
        let body = with_epoch(body, &remote_epoch)?;
        if new_pin {
            self.pin_stream(job, device, &route, &remote_epoch);
        }
        let path = format!("/v1/devices/{device}/text-streams");
        Some(
            match self
                .exchange(&route, "POST", &path, Some(&body), CONTROL_TIMEOUT)
                .await
            {
                OwnerExchange::NotSent(reason) => {
                    if new_pin {
                        self.unpin_stream(job);
                    }
                    self.failed(device, None, Some(&route), reason, route_unavailable())
                }
                OwnerExchange::Response {
                    status,
                    content_type,
                    body,
                } => {
                    if status >= 400 && new_pin {
                        self.unpin_stream(job);
                    }
                    local_receipt(status, content_type, body, &remote_epoch, &local_epoch)
                }
                OwnerExchange::Uncertain(reason) => {
                    match self.stream_status(&route, device, job).await {
                        Some((content_type, body)) => {
                            local_receipt(201, content_type, body, &remote_epoch, &local_epoch)
                        }
                        None => {
                            self.failed(device, None, Some(&route), reason, route_uncertain(None))
                        }
                    }
                }
            },
        )
    }

    async fn stream_status(
        &self,
        route: &Route,
        device: &str,
        job: Uuid,
    ) -> Option<(Option<String>, Vec<u8>)> {
        let path = format!("/v1/devices/{device}/text-streams/{job}");
        match self
            .exchange(route, "GET", &path, None, CONTROL_TIMEOUT)
            .await
        {
            OwnerExchange::Response {
                status: 200,
                content_type,
                body,
            } => Some((content_type, body)),
            _ => None,
        }
    }

    async fn stream(
        self: &Arc<Self>,
        daemon: &Daemon,
        device: &str,
        job: Uuid,
        action: StreamAction,
        body: &[u8],
    ) -> Option<Response> {
        if daemon.knows_text_stream(device, job) {
            return None;
        }
        let pin = self.stream_pin(job).filter(|pin| pin.device == device)?;
        let local_epoch = daemon.0.epoch.to_string();
        let (method, suffix, needs_proof) = match &action {
            StreamAction::Part(index) => ("POST", format!("/parts/{index}"), true),
            StreamAction::Finish => ("POST", "/finish".to_owned(), true),
            StreamAction::Lease => ("POST", "/lease".to_owned(), false),
            StreamAction::Cancel => ("POST", "/cancel".to_owned(), false),
            StreamAction::Status => ("GET", String::new(), false),
        };
        let mut child_command_id = None;
        let body = if method == "POST" {
            let request = serde_json::from_slice::<Value>(body).ok()?;
            if request.get("epoch").and_then(Value::as_str) != Some(local_epoch.as_str()) {
                return Some(ApiError::conflict("text_stream.epoch").into_response());
            }
            child_command_id = request
                .get("child_command_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            Some(with_epoch(body, &pin.remote_epoch)?)
        } else {
            None
        };
        if needs_proof {
            if let Some(reason) = self.verify_route(&pin.route, device).await.failure() {
                return Some(self.failed(
                    device,
                    None,
                    Some(&pin.route),
                    &reason,
                    route_unavailable(),
                ));
            }
        }
        let path = format!("/v1/devices/{device}/text-streams/{job}{suffix}");
        let exchange = self
            .exchange(&pin.route, method, &path, body.as_deref(), CONTROL_TIMEOUT)
            .await;
        Some(match exchange {
            OwnerExchange::Response {
                status,
                content_type,
                body,
            } => local_receipt(status, content_type, body, &pin.remote_epoch, &local_epoch),
            OwnerExchange::NotSent(reason) => {
                self.failed(device, None, Some(&pin.route), reason, route_unavailable())
            }
            OwnerExchange::Uncertain(reason) => {
                // After a lost part or finish response, report the holder's receipt only when it
                // proves where the request ended; otherwise the result stays unknown.
                let reconciled = match &action {
                    StreamAction::Part(_) | StreamAction::Finish => {
                        self.stream_status(&pin.route, device, job).await
                    }
                    _ => None,
                }
                .filter(|(_, receipt)| {
                    settled_by_receipt(receipt, &action, child_command_id.as_deref())
                });
                match reconciled {
                    Some((content_type, receipt)) => {
                        let status = if matches!(action, StreamAction::Part(_)) {
                            202
                        } else {
                            200
                        };
                        local_receipt(
                            status,
                            content_type,
                            receipt,
                            &pin.remote_epoch,
                            &local_epoch,
                        )
                    }
                    None => self.failed(
                        device,
                        None,
                        Some(&pin.route),
                        reason,
                        route_uncertain(child_command_id),
                    ),
                }
            }
        })
    }
}

fn settled_by_receipt(receipt: &[u8], action: &StreamAction, child: Option<&str>) -> bool {
    let Ok(receipt) = serde_json::from_slice::<Value>(receipt) else {
        return false;
    };
    if receipt.get("terminal").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    match action {
        StreamAction::Part(index) => {
            let admitted = child.is_some()
                && receipt
                    .pointer("/current_child/command_id")
                    .and_then(Value::as_str)
                    == child;
            let passed = receipt
                .get("next_index")
                .and_then(Value::as_str)
                .and_then(|next| next.parse::<u64>().ok())
                .zip(index.parse::<u64>().ok())
                .is_some_and(|(next, index)| next > index);
            admitted || passed
        }
        StreamAction::Finish => {
            receipt.get("source_complete").and_then(Value::as_bool) == Some(true)
        }
        _ => false,
    }
}

#[derive(Clone, Copy, Debug)]
enum CommandKind {
    Type,
    Actions,
    Sequence,
    InputSequence,
}

impl CommandKind {
    const fn segment(self) -> &'static str {
        match self {
            Self::Type => "type",
            Self::Actions => "actions",
            Self::Sequence => "sequences",
            Self::InputSequence => "input-sequences",
        }
    }
}

#[derive(Debug)]
enum StreamAction {
    Part(String),
    Finish,
    Lease,
    Cancel,
    Status,
}

#[derive(Debug)]
enum Op {
    List,
    Get {
        device: String,
    },
    File {
        device: String,
        method: Method,
        set: bool,
    },
    Command {
        device: String,
        kind: CommandKind,
    },
    StreamCreate {
        device: String,
    },
    Stream {
        device: String,
        job: Uuid,
        action: StreamAction,
    },
    Control {
        device: String,
        segment: &'static str,
        method: Method,
    },
    Cancel {
        device: String,
    },
    Outcome {
        device: String,
        command: Uuid,
    },
}

impl Op {
    /// Recognizes device-state, command, and screen-power routes. Other configuration,
    /// maintenance, handoff, and event routes are never forwarded.
    fn classify(method: &Method, path: &str) -> Option<Self> {
        let rest = path.strip_prefix("/v1/devices")?;
        if rest.is_empty() {
            return (method == Method::GET).then_some(Self::List);
        }
        let segments = rest.strip_prefix('/')?.split('/').collect::<Vec<_>>();
        if segments
            .iter()
            .any(|segment| segment.is_empty() || segment.contains('%'))
        {
            return None;
        }
        let device = segments[0].to_owned();
        let get = method == Method::GET;
        let post = method == Method::POST;
        let stream = |job: &str, action| {
            Some(Self::Stream {
                device: device.clone(),
                job: Uuid::parse_str(job).ok()?,
                action,
            })
        };
        let command = |kind| {
            Some(Self::Command {
                device: device.clone(),
                kind,
            })
        };
        let control = |segment| {
            Some(Self::Control {
                device: device.clone(),
                segment,
                method: method.clone(),
            })
        };
        match &segments[1..] {
            [] if get => Some(Self::Get {
                device: device.clone(),
            }),
            ["type"] if post => command(CommandKind::Type),
            ["screen-power"] if get || post => control("screen-power"),
            ["file"] if get || post || method == Method::DELETE => Some(Self::File {
                device: device.clone(),
                method: method.clone(),
                set: false,
            }),
            ["files"] if get || post || method == Method::DELETE => Some(Self::File {
                device: device.clone(),
                method: method.clone(),
                set: true,
            }),
            ["actions"] if post => command(CommandKind::Actions),
            ["sequences"] if post => command(CommandKind::Sequence),
            ["input-sequences"] if post => command(CommandKind::InputSequence),
            ["text-streams"] if post => Some(Self::StreamCreate {
                device: device.clone(),
            }),
            ["text-streams", job] if get => stream(job, StreamAction::Status),
            ["text-streams", job, "parts", index] if post => {
                stream(job, StreamAction::Part((*index).to_owned()))
            }
            ["text-streams", job, "finish"] if post => stream(job, StreamAction::Finish),
            ["text-streams", job, "lease"] if post => stream(job, StreamAction::Lease),
            ["text-streams", job, "cancel"] if post => stream(job, StreamAction::Cancel),
            ["arm"] if post => control("arm"),
            ["arm", "renew"] if post => control("arm/renew"),
            ["disarm"] if post => control("disarm"),
            ["cancel"] if post => Some(Self::Cancel {
                device: device.clone(),
            }),
            ["commands", command_id] if get => Some(Self::Outcome {
                device: device.clone(),
                command: Uuid::parse_str(command_id).ok()?,
            }),
            _ => None,
        }
    }

    fn device(&self) -> Option<&str> {
        match self {
            Self::List => None,
            Self::Get { device }
            | Self::File { device, .. }
            | Self::Command { device, .. }
            | Self::StreamCreate { device }
            | Self::Stream { device, .. }
            | Self::Control { device, .. }
            | Self::Cancel { device }
            | Self::Outcome { device, .. } => Some(device),
        }
    }

    fn body_limit(&self) -> usize {
        match self {
            Self::Command {
                kind: CommandKind::Sequence | CommandKind::InputSequence,
                ..
            } => MAX_SEQUENCE_REQUEST_BODY,
            Self::StreamCreate { .. } | Self::Stream { .. } => MAX_TEXT_STREAM_PART_BODY,
            Self::File { set: false, .. } => MAX_FILE_REQUEST_BODY,
            Self::File { set: true, .. } => MAX_FILE_SET_REQUEST_BODY,
            _ => DEFAULT_BODY_LIMIT,
        }
    }
}

/// Loopback-router middleware: forwards a device request only when this daemon has no
/// authenticated local link and a verified owner controller holds the device.
pub(crate) async fn local_forwarding(
    State(daemon): State<Daemon>,
    request: Request,
    next: Next,
) -> Response {
    let Some(forwarder) = daemon.forwarder() else {
        return next.run(request).await;
    };
    let Some(op) = Op::classify(request.method(), request.uri().path()) else {
        return next.run(request).await;
    };
    if op.device().is_some_and(|device| !forwarder.handles(device))
        || authorize(request.headers(), &daemon).is_err()
    {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let Ok(body) = to_bytes(body, op.body_limit()).await else {
        return (StatusCode::PAYLOAD_TOO_LARGE, "length limit exceeded").into_response();
    };
    match forwarder.dispatch(&daemon, op, &body).await {
        Some(response) => response,
        None => next.run(Request::from_parts(parts, Body::from(body))).await,
    }
}

/// Validates a command body like the local handler and binds the command ID the holder keeps.
/// Sequence key aliases are sent as canonical names, so a holder that predates aliases accepts
/// the body from any client; the route proof binds identities and a nonce, never the body.
/// `None` leaves the request to the local handler, which returns its usual error.
fn prepare_command_body(kind: CommandKind, body: &[u8]) -> Option<(Uuid, Vec<u8>)> {
    let (command_id, body) = match kind {
        CommandKind::Type => (
            parse_payload_body::<TypeRequest>(body).ok()?.command_id,
            body.to_vec(),
        ),
        CommandKind::Actions => (
            parse_payload_body::<ActionsRequest>(body).ok()?.command_id,
            body.to_vec(),
        ),
        CommandKind::Sequence => {
            let mut request = parse_payload_body::<KeyboardSequenceV1>(body).ok()?;
            canonicalize_sequence_keys(&mut request);
            (
                Some(Uuid::parse_str(&request.command_id).ok()?),
                serde_json::to_vec(&request).ok()?,
            )
        }
        CommandKind::InputSequence => {
            let mut request = parse_input_sequence_json(body).ok()?;
            canonicalize_input_sequence_keys(&mut request);
            (
                Some(Uuid::parse_str(&request.command_id).ok()?),
                serde_json::to_vec(&request).ok()?,
            )
        }
    };
    match (kind, command_id) {
        (_, Some(command_id)) if command_id.get_version_num() != 7 => None,
        (CommandKind::Type | CommandKind::Actions, None) => {
            let command_id = Uuid::now_v7();
            let mut request = serde_json::from_slice::<Value>(&body).ok()?;
            request
                .as_object_mut()?
                .insert("command_id".to_owned(), command_id.to_string().into());
            Some((command_id, serde_json::to_vec(&request).ok()?))
        }
        (_, Some(command_id)) => Some((command_id, body)),
        (_, None) => None,
    }
}

fn with_epoch(body: &[u8], epoch: &str) -> Option<Vec<u8>> {
    let mut request = serde_json::from_slice::<Value>(body).ok()?;
    *request.as_object_mut()?.get_mut("epoch")? = Value::String(epoch.to_owned());
    serde_json::to_vec(&request).ok()
}

/// Presents a holder's text-stream receipt under this daemon's epoch.
fn local_receipt(
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
    remote_epoch: &str,
    local_epoch: &str,
) -> Response {
    if (200..300).contains(&status) {
        if let Ok(mut receipt) = serde_json::from_slice::<Value>(&body) {
            if receipt.get("epoch").and_then(Value::as_str) == Some(remote_epoch) {
                receipt["epoch"] = Value::String(local_epoch.to_owned());
                let status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
                return (status, Json(receipt)).into_response();
            }
        }
    }
    passthrough(status, content_type, body)
}

fn apply_remote(view: &mut DeviceView, route: &Route, holder: &HolderView) {
    view.link = "authenticated".to_owned();
    view.link_path = Some(TAILNET_LINK_PATH.to_owned());
    view.via.clone_from(&route.name);
    view.armed = holder.armed;
    view.maintenance = holder.maintenance;
    if let Some(policy) = &holder.arm_policy {
        view.arm_policy.clone_from(policy);
    }
    view.firmware.clone_from(&holder.firmware);
    view.active_command_id.clone_from(&holder.active_command_id);
    view.active_outcome = holder.active_outcome;
}

fn display_name(name: &str) -> String {
    name.chars()
        .filter(|character| !character.is_control())
        .take(MAX_VIA_CHARS)
        .collect()
}

/// Holder responses keep their status and body; a holder authorization refusal means the
/// route, not this caller's local credential, failed.
fn passthrough(status: u16, content_type: Option<String>, body: Vec<u8>) -> Response {
    let status = match status {
        401 | 403 => {
            return ApiError::unavailable("tailnet_route.holder_refused").into_response();
        }
        other => StatusCode::from_u16(other).unwrap_or(StatusCode::BAD_GATEWAY),
    };
    let content_type = content_type
        .and_then(|value| HeaderValue::from_str(&value).ok())
        .unwrap_or(HeaderValue::from_static("application/json"));
    let mut response = (status, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
}

/// Why forwarded work failed, as identifiers and a reason code only.
fn log_failure(
    device: &str,
    command_id: Option<Uuid>,
    route: Option<&Route>,
    status: impl std::fmt::Display,
    reason: &str,
) {
    crate::daemon_log!(
        "forwarding failed: device={device} command_id={} holder={} status={status} reason={reason}",
        command_id.map_or_else(|| "none".to_owned(), |id| id.to_string()),
        route.map_or_else(|| "none".to_owned(), holder_name),
    );
}

fn holder_name(route: &Route) -> String {
    route
        .name
        .clone()
        .unwrap_or_else(|| encode_hex(&route.installation_id))
}

/// A holder refusal as a reason code: its HTTP status and, only when it is one, its error code.
fn holder_reason(scope: &str, status: u16, body: &[u8]) -> String {
    let code = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")?
                .as_str()
                .filter(|code| keyferry_core::is_error_code(code))
                .map(str::to_owned)
        });
    match code {
        Some(code) => format!("{scope}.holder_status_{status}:{code}"),
        None => format!("{scope}.holder_status_{status}"),
    }
}

fn route_unavailable() -> Response {
    ApiError::unavailable("tailnet_route.unavailable").into_response()
}

fn route_uncertain(command_id: Option<String>) -> Response {
    ApiError::uncertain("tailnet_route.uncertain", command_id).into_response()
}

/// A forwarded command whose outcome could not be observed. The transport that would have
/// typed it is not known here, so `output_transport` is null.
fn unknown_command(command_id: Uuid, device: &str, status: StatusCode) -> Response {
    (
        status,
        Json(serde_json::json!({
            "command_id": command_id.to_string(),
            "device_id": device,
            "outcome": CommandOutcome::Unknown,
            "terminal": true,
            "possible_start": true,
            "terminal_zero_confirmed": false,
            "terminal_release_completed": false,
            "output_transport": null,
            "message": "tailnet_route.uncertain",
        })),
    )
        .into_response()
}

pub(crate) enum OwnerExchange {
    Response {
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    },
    /// Connecting or authenticating the owner route failed; no request byte was sent.
    NotSent(&'static str),
    /// The request may have been delivered but no complete response was read.
    Uncertain(&'static str),
}

/// One owner-mTLS HTTP/1.1 request to a peer controller, bounded in time and size.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn owner_exchange(
    connector: &TlsConnector,
    installation_id: &[u8; 16],
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    timeout: Duration,
    max_response: usize,
) -> OwnerExchange {
    let Ok(server_name) = keyferry_gateway::installation_gateway_name(installation_id) else {
        return OwnerExchange::NotSent("owner_route.server_name");
    };
    let Ok(tls_name) = ServerName::try_from(server_name.clone()) else {
        return OwnerExchange::NotSent("owner_route.server_name");
    };
    let connected = time::timeout(timeout, async {
        let tcp = TcpStream::connect(address)
            .await
            .map_err(|_| "owner_route.connect_failed")?;
        connector
            .connect(tls_name, tcp)
            .await
            .map_err(|_| "owner_route.tls_failed")
    })
    .await;
    let mut tls = match connected {
        Ok(Ok(tls)) => tls,
        Ok(Err(reason)) => return OwnerExchange::NotSent(reason),
        Err(_) => return OwnerExchange::NotSent("owner_route.connect_timeout"),
    };
    let body = body.unwrap_or_default();
    let content_type = if body.is_empty() {
        ""
    } else {
        "Content-Type: application/json\r\n"
    };
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {server_name}\r\nAccept: application/json\r\n{content_type}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let exchanged = time::timeout(timeout, async {
        tls.write_all(head.as_bytes()).await?;
        tls.write_all(body).await?;
        tls.flush().await?;
        read_http_response(&mut tls, max_response).await
    })
    .await;
    let response = match exchanged {
        Ok(Ok(response)) => response,
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return OwnerExchange::Uncertain("owner_route.response_eof")
        }
        Ok(Err(error)) if error.kind() == io::ErrorKind::InvalidData => {
            return OwnerExchange::Uncertain("owner_route.response_invalid")
        }
        Ok(Err(_)) => return OwnerExchange::Uncertain("owner_route.io_failed"),
        Err(_) => return OwnerExchange::Uncertain("owner_route.response_timeout"),
    };
    match parse_http_response(&response) {
        HttpParse::Complete {
            status,
            content_type,
            body,
        } => OwnerExchange::Response {
            status,
            content_type: content_type.map(str::to_owned),
            body: body.to_vec(),
        },
        HttpParse::Incomplete | HttpParse::Malformed => {
            OwnerExchange::Uncertain("owner_route.response_invalid")
        }
    }
}

/// Reads the plaintext discovery hint. Its installation ID is only the name the control route
/// must then prove under the owner CA.
async fn probe_candidate(peer: &TailnetPeer) -> Option<[u8; 16]> {
    let address = SocketAddr::new(peer.address, peer.probe_port);
    time::timeout(PROBE_TIMEOUT, async {
        let mut tcp = TcpStream::connect(address).await.ok()?;
        let head = format!(
            "GET {OWNER_GATEWAY_CANDIDATE_PATH} HTTP/1.1\r\nHost: {address}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        tcp.write_all(head.as_bytes()).await.ok()?;
        let response = read_http_response(&mut tcp, MAX_PROBE_RESPONSE).await.ok()?;
        match parse_http_response(&response) {
            HttpParse::Complete {
                status: 200, body, ..
            } => OwnerGatewayCandidate::from_json(body)
                .ok()
                .map(|candidate| candidate.installation_id),
            _ => None,
        }
    })
    .await
    .ok()
    .flatten()
}

async fn read_http_response<IO: AsyncRead + Unpin>(
    io: &mut IO,
    max_response: usize,
) -> io::Result<Vec<u8>> {
    let mut response = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 4096];
    loop {
        match parse_http_response(&response) {
            HttpParse::Complete { .. } => return Ok(response),
            HttpParse::Malformed => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "peer response is malformed",
                ))
            }
            HttpParse::Incomplete => {}
        }
        let read = io.read(&mut buffer).await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if response.len() + read > max_response {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer response is oversized",
            ));
        }
        response.extend_from_slice(&buffer[..read]);
    }
}

pub(crate) enum HttpParse<'a> {
    Incomplete,
    Malformed,
    Complete {
        status: u16,
        content_type: Option<&'a str>,
        body: &'a [u8],
    },
}

/// Accepts only an HTTP/1.1 response with exactly one Content-Length and no transfer coding.
pub(crate) fn parse_http_response(bytes: &[u8]) -> HttpParse<'_> {
    let Some(header_end) = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
    else {
        return if bytes.len() > MAX_RESPONSE_HEADER {
            HttpParse::Malformed
        } else {
            HttpParse::Incomplete
        };
    };
    let Ok(headers) = std::str::from_utf8(&bytes[..header_end]) else {
        return HttpParse::Malformed;
    };
    let mut lines = headers.split("\r\n");
    let Some(status) = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .filter(|rest| rest.len() == 3 || rest.as_bytes().get(3) == Some(&b' '))
        .and_then(|rest| rest.get(..3))
        .filter(|code| code.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|code| code.parse::<u16>().ok())
    else {
        return HttpParse::Malformed;
    };
    let mut content_length = None;
    let mut content_type = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return HttpParse::Malformed;
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return HttpParse::Malformed;
        }
        if name.eq_ignore_ascii_case("content-length") {
            let Ok(length) = value.trim().parse::<usize>() else {
                return HttpParse::Malformed;
            };
            if content_length.replace(length).is_some() {
                return HttpParse::Malformed;
            }
        }
        if name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value.trim());
        }
    }
    let Some(expected) = content_length else {
        return HttpParse::Malformed;
    };
    let body = &bytes[header_end..];
    match body.len().cmp(&expected) {
        std::cmp::Ordering::Less => HttpParse::Incomplete,
        std::cmp::Ordering::Equal => HttpParse::Complete {
            status,
            content_type,
            body,
        },
        std::cmp::Ordering::Greater => HttpParse::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        serve_owner_candidate_listener, serve_owner_mtls_listener, tls::test_support::TestOwner,
        ArmPolicy, Cancellation, DeviceTransport, GatewayAuthority, MemoryTokenStore, OutputMode,
        PlannedCommand, ProgressHandler, SimulatorTransport, TlsLinkPath, TlsSessionSnapshot,
        TlsTransport, TransportError, TransportOutcome, TransportOutputModeStatus,
    };
    use axum::http::header::AUTHORIZATION;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tokio::net::TcpListener;
    use tower_service::Service;

    const DEVICE: [u8; 16] = [0x22; 16];
    const OWNER: [u8; 16] = [0x11; 16];
    const HOLDER_SECRET: [u8; 32] = [0x51; 32];
    const FORWARDER_SECRET: [u8; 32] = [0x52; 32];
    const SESSION: [u8; 16] = [0x61; 16];
    const FORWARDER_TOKEN: &str = "forwarder-token-123456";

    fn device_id() -> String {
        Uuid::from_bytes(DEVICE).to_string()
    }

    /// A simulated endpoint that also answers route proofs the way firmware does: for any
    /// controller whose device-scoped secret it can derive, bound to its live session.
    struct ProvingTransport {
        inner: SimulatorTransport,
        gateway: [u8; 16],
        controllers: HashMap<[u8; 16], [u8; 32]>,
        file: Arc<Mutex<TestFile>>,
    }

    #[derive(Default)]
    struct TestFile {
        bytes: Vec<u8>,
        entries: Vec<(String, u32)>,
        expected_size: u32,
        digest: [u8; 32],
        receiving: bool,
        published: bool,
        commits: usize,
    }

    impl DeviceTransport for ProvingTransport {
        fn supports_input_sequence(&self) -> bool {
            self.inner.supports_input_sequence()
        }
        fn supports_extended_pointer(&self) -> bool {
            self.inner.supports_extended_pointer()
        }
        fn supports_file_handoff(&self) -> bool {
            true
        }

        fn file_request<'a>(
            &'a self,
            request: keyferry_protocol::file::Request,
        ) -> BoxFuture<'a, Result<keyferry_protocol::file::Status, TransportError>> {
            Box::pin(async move {
                use keyferry_protocol::file::{Error, Request, State, Status};
                let mut file = self.file.lock().unwrap();
                let error = match request {
                    Request::Begin { size, sha256 } => {
                        file.bytes.clear();
                        file.expected_size = size;
                        file.digest = sha256;
                        file.published = false;
                        file.receiving = true;
                        file.entries.clear();
                        Error::Ok
                    }
                    Request::Chunk { offset, bytes }
                        if !file.published && offset == file.bytes.len() as u32 =>
                    {
                        file.bytes.extend_from_slice(&bytes);
                        Error::Ok
                    }
                    Request::Chunk { .. } => Error::Order,
                    Request::Commit
                        if !file.published
                            && file.bytes.len() as u32 == file.expected_size
                            && <sha2::Sha256 as sha2::Digest>::digest(&file.bytes).as_slice()
                                == file.digest.as_slice() =>
                    {
                        file.published = true;
                        file.receiving = false;
                        file.commits += 1;
                        file.entries = vec![("MESSAGE.TXT".to_owned(), file.expected_size)];
                        Error::Ok
                    }
                    Request::Commit => Error::Digest,
                    Request::Clear => {
                        file.bytes.clear();
                        file.expected_size = 0;
                        file.published = false;
                        file.receiving = false;
                        file.entries.clear();
                        Error::Ok
                    }
                    Request::Status => Error::Ok,
                };
                Ok(Status {
                    state: if file.published {
                        State::Published
                    } else if file.receiving {
                        State::Receiving
                    } else {
                        State::Empty
                    },
                    error,
                    size: file.expected_size,
                    received: file.bytes.len() as u32,
                })
            })
        }
        fn supports_file_set(&self) -> bool {
            true
        }

        fn file_set_request<'a>(
            &'a self,
            request: keyferry_protocol::file_set::Request,
        ) -> BoxFuture<'a, Result<keyferry_protocol::file_set::Status, TransportError>> {
            Box::pin(async move {
                use keyferry_protocol::file_set::{Entry, Error, Request, State, Status};
                let mut file = self.file.lock().unwrap();
                let mut entry = None;
                let error = match request {
                    Request::Begin { size, sha256 } => {
                        file.bytes.clear();
                        file.entries.clear();
                        file.expected_size = size;
                        file.digest = sha256;
                        file.receiving = true;
                        file.published = false;
                        Error::Ok
                    }
                    Request::Chunk { offset, bytes }
                        if file.receiving && offset == file.bytes.len() as u32 =>
                    {
                        file.bytes.extend_from_slice(&bytes);
                        Error::Ok
                    }
                    Request::Chunk { .. } => Error::Order,
                    Request::Commit
                        if file.receiving
                            && file.bytes.len() as u32 == file.expected_size
                            && <sha2::Sha256 as sha2::Digest>::digest(&file.bytes).as_slice()
                                == file.digest.as_slice() =>
                    {
                        let count = file.bytes[0] as usize;
                        let mut cursor = 1;
                        let mut entries = Vec::new();
                        for _ in 0..count {
                            let name_len = file.bytes[cursor] as usize;
                            cursor += 1;
                            let name =
                                String::from_utf8(file.bytes[cursor..cursor + name_len].to_vec())
                                    .unwrap();
                            cursor += name_len;
                            let size = u32::from_le_bytes(
                                file.bytes[cursor..cursor + 4].try_into().unwrap(),
                            );
                            cursor += 4;
                            entries.push((name, size));
                        }
                        file.entries = entries;
                        file.published = true;
                        file.receiving = false;
                        file.commits += 1;
                        Error::Ok
                    }
                    Request::Commit => Error::Digest,
                    Request::Clear => {
                        file.bytes.clear();
                        file.entries.clear();
                        file.expected_size = 0;
                        file.receiving = false;
                        file.published = false;
                        Error::Ok
                    }
                    Request::Status { index: 255 } => Error::Ok,
                    Request::Status { index }
                        if file.published && (index as usize) < file.entries.len() =>
                    {
                        let (name, size) = &file.entries[index as usize];
                        entry = Some(Entry {
                            index,
                            name: name.clone(),
                            size: *size,
                        });
                        Error::Ok
                    }
                    Request::Status { .. } => Error::Limit,
                };
                Ok(Status {
                    state: if file.published {
                        State::Published
                    } else if file.receiving {
                        State::Receiving
                    } else {
                        State::Empty
                    },
                    error,
                    wire_size: file.expected_size,
                    received: file.bytes.len() as u32,
                    count: file.entries.len() as u8,
                    entry,
                })
            })
        }
        fn supports_output_mode(&self) -> bool {
            self.inner.supports_output_mode()
        }

        fn supports_screen_power(&self) -> bool {
            self.inner.supports_screen_power()
        }

        fn screen_power<'a>(
            &'a self,
            requested: Option<crate::ScreenPower>,
        ) -> BoxFuture<'a, Result<crate::TransportScreenPowerStatus, TransportError>> {
            self.inner.screen_power(requested)
        }

        fn output_mode<'a>(
            &'a self,
            requested: Option<OutputMode>,
        ) -> BoxFuture<'a, Result<TransportOutputModeStatus, TransportError>> {
            self.inner.output_mode(requested)
        }

        fn route_proof<'a>(
            &'a self,
            controller_installation_id: [u8; 16],
            controller_nonce: [u8; 32],
        ) -> BoxFuture<'a, Result<keyferry_gateway::SignedRouteProof, TransportError>> {
            Box::pin(async move {
                let secret = self
                    .controllers
                    .get(&controller_installation_id)
                    .ok_or(TransportError::ControlRejected)?;
                let input = keyferry_gateway::RouteProofInput {
                    owner_id: OWNER,
                    device_id: DEVICE,
                    epoch: 1,
                    policy_sequence: 1,
                    policy_hash: [0x31; 32],
                    gateway_installation_id: self.gateway,
                    controller_installation_id,
                    controller_nonce,
                    device_boot_nonce: [0x32; 16],
                    endpoint_session_id: SESSION,
                    link_path: keyferry_gateway::GatewayLinkPath::Wifi,
                    usb_ready: true,
                };
                let tag = keyferry_gateway::route_proof_tag(secret, &input)
                    .map_err(|_| TransportError::ControlRejected)?;
                Ok(keyferry_gateway::SignedRouteProof { input, tag })
            })
        }

        fn arm<'a>(
            &'a self,
            policy: ArmPolicy,
            lease_ms: u32,
        ) -> BoxFuture<'a, Result<(), TransportError>> {
            self.inner.arm(policy, lease_ms)
        }

        fn disarm<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
            self.inner.disarm()
        }

        fn renew_lease<'a>(&'a self, lease_ms: u32) -> BoxFuture<'a, Result<(), TransportError>> {
            self.inner.renew_lease(lease_ms)
        }

        fn accept<'a>(
            &'a self,
            command: &'a PlannedCommand,
        ) -> BoxFuture<'a, Result<(), TransportError>> {
            self.inner.accept(command)
        }

        fn execute<'a>(
            &'a self,
            command: &'a PlannedCommand,
            cancellation: Cancellation,
            progress: ProgressHandler,
        ) -> BoxFuture<'a, TransportOutcome> {
            self.inner.execute(command, cancellation, progress)
        }

        fn release_all<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
            self.inner.release_all()
        }
    }

    struct StaticPeers(Vec<TailnetPeer>);

    impl PeerSource for StaticPeers {
        fn peers(&self) -> BoxFuture<'_, Vec<TailnetPeer>> {
            let peers = self.0.clone();
            Box::pin(async move { peers })
        }
    }

    /// A TCP relay in front of the holder's owner-mTLS port. Once armed with `n`, it relays
    /// `n - 1` more connections, relays the next request but drops its response, then refuses.
    #[derive(Default)]
    struct Proxy {
        connections: AtomicUsize,
        drop_at: Mutex<Option<usize>>,
        refuse_once_at: Mutex<Option<usize>>,
    }

    impl Proxy {
        fn arm(&self, n: usize) {
            *self.drop_at.lock().unwrap() = Some(self.connections.load(Ordering::SeqCst) + n);
        }
    }

    async fn start_proxy(upstream: SocketAddr) -> (SocketAddr, Arc<Proxy>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = Arc::new(Proxy::default());
        let control = Arc::clone(&proxy);
        tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    continue;
                };
                let index = control.connections.fetch_add(1, Ordering::SeqCst) + 1;
                let drop_at = *control.drop_at.lock().unwrap();
                let refuse_once = *control.refuse_once_at.lock().unwrap() == Some(index);
                tokio::spawn(async move {
                    if refuse_once {
                        return;
                    }
                    match drop_at {
                        Some(at) if index > at => drop(client),
                        Some(at) if index == at => drop_response(client, upstream).await,
                        _ => {
                            let mut server = TcpStream::connect(upstream).await.unwrap();
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                        }
                    }
                });
            }
        });
        (address, proxy)
    }

    /// Relays the TLS handshake and the request, then closes the client at the first server
    /// application-data record: the holder has answered, but the caller never hears it.
    async fn drop_response(client: TcpStream, upstream: SocketAddr) {
        let server = TcpStream::connect(upstream).await.unwrap();
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();
        let request = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
        });
        loop {
            let mut record_header = [0_u8; 5];
            if server_read.read_exact(&mut record_header).await.is_err() {
                break;
            }
            let length = usize::from(u16::from_be_bytes([record_header[3], record_header[4]]));
            let mut record = vec![0_u8; length];
            if server_read.read_exact(&mut record).await.is_err() || record_header[0] == 23 {
                break;
            }
            if client_write.write_all(&record_header).await.is_err()
                || client_write.write_all(&record).await.is_err()
            {
                break;
            }
        }
        request.abort();
    }

    struct Harness {
        root: PathBuf,
        holder: Daemon,
        holder_device: SimulatorTransport,
        forwarder: Daemon,
        proxy: Arc<Proxy>,
        file: Arc<Mutex<TestFile>>,
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Each POST path and body the holder's owner-mTLS router received.
    type Received = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// The holder's production owner-mTLS listener and router, behind a layer that records each
    /// POST it receives, so a test sees exactly what crossed the tailnet.
    async fn serve_recording_holder(
        holder: Daemon,
        listener: TcpListener,
        installation: InstallationTlsSecretStore,
        received: Received,
    ) {
        holder
            .configure_owner_remote_installation(&installation)
            .unwrap();
        let listener = crate::OwnerTlsListener {
            control_port: listener.local_addr().unwrap().port(),
            listener,
            acceptor: installation
                .remote_tls_acceptor()
                .map_err(|error| error.to_string())
                .unwrap(),
        };
        let record = axum::middleware::from_fn(move |request: Request, next: Next| {
            let received = Arc::clone(&received);
            async move {
                let (parts, body) = request.into_parts();
                let body = to_bytes(body, DEFAULT_BODY_LIMIT).await.unwrap();
                if parts.method == Method::POST {
                    received
                        .lock()
                        .unwrap()
                        .push((parts.uri.path().to_owned(), body.to_vec()));
                }
                next.run(Request::from_parts(parts, Body::from(body))).await
            }
        });
        axum::serve(
            listener,
            holder
                .owner_remote_router()
                .layer(record)
                .into_make_service_with_connect_info::<crate::RemoteTlsPeer>(),
        )
        .await
        .unwrap();
    }

    async fn harness(local: Option<SimulatorTransport>, proof_secret: [u8; 32]) -> Harness {
        harness_with(local, proof_secret, None).await
    }

    async fn harness_with(
        local: Option<SimulatorTransport>,
        proof_secret: [u8; 32],
        received: Option<Received>,
    ) -> Harness {
        harness_with_wifi(local, proof_secret, received, false).await
    }

    async fn harness_with_wifi(
        local: Option<SimulatorTransport>,
        proof_secret: [u8; 32],
        received: Option<Received>,
        wifi: bool,
    ) -> Harness {
        let root = std::env::temp_dir().join(format!("keyferry-forward-{}", Uuid::now_v7()));
        let owner = TestOwner::new(OWNER);
        let (holder_id, _) = owner.issue(&root.join("holder"), DEVICE, HOLDER_SECRET);
        let (forwarder_id, _) = owner.issue(&root.join("forwarder"), DEVICE, FORWARDER_SECRET);
        let (eyes_id, _) = owner.issue(&root.join("eyes"), DEVICE, [0x62; 32]);
        let holder_set = InstallationTlsSecretSet::load(root.join("holder")).unwrap();
        let forwarder_set = InstallationTlsSecretSet::load(root.join("forwarder")).unwrap();
        let holder_store = holder_set.iter().next().unwrap().clone();

        let holder_device = SimulatorTransport::default()
            .with_extended_pointer()
            .with_output_mode(OutputMode::UsbHid)
            .with_screen_power(crate::ScreenPower::On);
        let file = Arc::new(Mutex::new(TestFile::default()));
        let gateway = TlsTransport::from_installation_store(&holder_store).unwrap();
        if !wifi {
            gateway.set_test_session_snapshot(TlsSessionSnapshot {
                link_path: TlsLinkPath::Wifi,
                protocol_session_id: SESSION,
                firmware_identity: None,
            });
        }
        let holder = if wifi {
            Daemon::with_tls_transports(
                MemoryTokenStore::new("holder-token-123456"),
                vec![(device_id(), "Holder".to_owned(), gateway.clone())],
            )
        } else {
            Daemon::with_device_transports_and_gateways(
                MemoryTokenStore::new("holder-token-123456"),
                vec![(
                    device_id(),
                    "Holder".to_owned(),
                    Arc::new(ProvingTransport {
                        inner: holder_device.clone(),
                        gateway: holder_id,
                        controllers: HashMap::from([
                            (forwarder_id, proof_secret),
                            (eyes_id, [0x62; 32]),
                        ]),
                        file: Arc::clone(&file),
                    }) as Arc<dyn DeviceTransport>,
                    Some(GatewayAuthority {
                        transport: gateway.clone(),
                        daemon_boot_id: [0x71; 16],
                    }),
                )],
            )
        }
        .unwrap();
        let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_address = control.local_addr().unwrap();
        match received {
            None => {
                tokio::spawn(serve_owner_mtls_listener(
                    holder.clone(),
                    control,
                    holder_store,
                ));
            }
            Some(received) => {
                tokio::spawn(serve_recording_holder(
                    holder.clone(),
                    control,
                    holder_store,
                    received,
                ));
            }
        }
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let probe_port = probe.local_addr().unwrap().port();
        tokio::spawn(serve_owner_candidate_listener(probe, holder_id));
        let (proxy_address, proxy) = start_proxy(control_address).await;

        let forwarder = match local {
            Some(transport) => Daemon::with_device_transport(
                MemoryTokenStore::new(FORWARDER_TOKEN),
                device_id(),
                "Forwarder".to_owned(),
                Arc::new(transport),
            ),
            None => Daemon::with_tls_transports(
                MemoryTokenStore::new(FORWARDER_TOKEN),
                vec![(
                    device_id(),
                    "Forwarder".to_owned(),
                    TlsTransport::from_installation_store(forwarder_set.iter().next().unwrap())
                        .unwrap(),
                )],
            ),
        }
        .unwrap();
        forwarder
            .enable_forwarding(
                Forwarder::new(
                    &forwarder_set,
                    Box::new(StaticPeers(vec![TailnetPeer {
                        name: Some("holder-host".to_owned()),
                        address: IpAddr::from([127, 0, 0, 1]),
                        probe_port,
                        control_port: proxy_address.port(),
                    }])),
                )
                .unwrap(),
            )
            .unwrap();
        Harness {
            root,
            holder,
            holder_device,
            forwarder,
            proxy,
            file,
        }
    }

    async fn call(
        daemon: &Daemon,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(AUTHORIZATION, format!("Bearer {FORWARDER_TOKEN}"));
        let body = match body {
            Some(body) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = daemon
            .router()
            .call(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    fn sequence(command_id: Uuid) -> Value {
        serde_json::json!({
            "schema": "keyferry.keyboard-sequence.v1",
            "command_id": command_id.to_string(),
            "profile": "windows-us",
            "arm": "command-scoped",
            "start_within_ms": 5000,
            "actions": [{"type": "tap", "key": "A"}],
        })
    }

    async fn wait_for_outcome(daemon: &Daemon, command_id: &str) -> Value {
        let uri = format!("/v1/devices/{}/commands/{command_id}", device_id());
        for _ in 0..200 {
            let (status, response) = call(daemon, "GET", &uri, None).await;
            assert_eq!(status, StatusCode::OK, "{response}");
            if response["terminal"] == true {
                return response;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        panic!("forwarded command did not finish");
    }

    /// The route-proof response a Wi-Fi fixture endpoint sends for a ROUTE_PROOF_REQUEST payload.
    fn fixture_route_proof(request: &[u8], gateway: [u8; 16], session: [u8; 16]) -> Vec<u8> {
        let input = keyferry_gateway::RouteProofInput {
            owner_id: OWNER,
            device_id: DEVICE,
            epoch: 1,
            policy_sequence: 1,
            policy_hash: [0x31; 32],
            gateway_installation_id: gateway,
            controller_installation_id: request[..16].try_into().unwrap(),
            controller_nonce: request[16..48].try_into().unwrap(),
            device_boot_nonce: [0x32; 16],
            endpoint_session_id: session,
            link_path: keyferry_gateway::GatewayLinkPath::Wifi,
            usb_ready: true,
        };
        let tag = keyferry_gateway::route_proof_tag(&FORWARDER_SECRET, &input).unwrap();
        keyferry_gateway::encode_route_proof_response(&input, &tag)
            .unwrap()
            .to_vec()
    }

    /// Firmware builds at most one route proof per 100 ms (esp_transport.cpp
    /// kRouteProofMinimumIntervalMs) and answers a faster request with ERROR BUSY. A status read
    /// that re-proves an aged holder, followed at once by a command, must not lose a healthy
    /// holder or reject the command.
    #[tokio::test]
    async fn consecutive_forwarded_commands_survive_the_endpoint_route_proof_interval() {
        use crate::discovery::{refresh_interfaces, BeaconPlan, PortableGatewayBinding};
        use crate::tls::{read_frame, send_frame, tests::respond_on_name};
        use keyferry_protocol::{error_code, message, result_code, Frame};

        let harness = harness_with_wifi(None, FORWARDER_SECRET, None, true).await;
        let transport = harness
            .holder
            .gateway(&device_id())
            .unwrap()
            .transport
            .clone();
        let binding = PortableGatewayBinding::Multi(
            InstallationTlsSecretSet::load(harness.root.join("holder")).unwrap(),
            vec![transport.clone()],
        );
        let reservation = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let plan = BeaconPlan::loopback_test(reservation.local_addr().unwrap().port());
        drop(reservation);
        let mut listeners = Vec::new();
        assert!(refresh_interfaces(&mut listeners, &[plan], transport.host_id(), &binding).await);

        let credentials = transport.test_credentials();
        let gateway_id = transport.host_id();
        let refused = Arc::new(AtomicUsize::new(0));
        let device_refused = Arc::clone(&refused);
        let device = tokio::spawn(async move {
            let tcp = TcpStream::connect(plan.listener_address()).await.unwrap();
            let name = keyferry_gateway::device_gateway_name(&DEVICE).unwrap();
            let (mut stream, ready) =
                respond_on_name(tcp, &credentials, &[0x33; 32], true, &name).await;
            let session: [u8; 16] = ready.payload[..16].try_into().unwrap();
            let mut last_proof: Option<Instant> = None;
            let mut executed = 0;
            while let Ok(frame) = read_frame(&mut stream).await {
                let replies = match frame.message_type {
                    message::ROUTE_PROOF_REQUEST
                        if last_proof
                            .is_some_and(|at| at.elapsed() < Duration::from_millis(100)) =>
                    {
                        device_refused.fetch_add(1, Ordering::SeqCst);
                        vec![(message::ERROR, error_code::BUSY.to_le_bytes().to_vec())]
                    }
                    message::ROUTE_PROOF_REQUEST => {
                        last_proof = Some(Instant::now());
                        vec![(
                            message::ROUTE_PROOF_RESPONSE,
                            fixture_route_proof(&frame.payload, gateway_id, session),
                        )]
                    }
                    message::ARM | message::DISARM => {
                        vec![(message::ACK, vec![frame.message_type, 0, 0])]
                    }
                    message::COMMAND => {
                        let id = &frame.payload[..16];
                        let execute = frame.payload[52] == 1;
                        executed += usize::from(execute);
                        let results: &[u8] = if execute {
                            &[
                                result_code::ACCEPTED,
                                result_code::STARTED,
                                result_code::EMITTED,
                            ]
                        } else {
                            &[result_code::ACCEPTED, result_code::EMITTED]
                        };
                        results
                            .iter()
                            .map(|result| (message::COMMAND_RESULT, [id, &[*result]].concat()))
                            .collect()
                    }
                    other => panic!("unexpected fixture message {other}"),
                };
                for (message_type, payload) in replies {
                    send_frame(
                        &mut stream,
                        Frame::v1(message_type, frame.sequence, payload),
                    )
                    .await
                    .unwrap();
                }
            }
            executed
        });
        for _ in 0..200 {
            if transport.is_ready() {
                break;
            }
            time::sleep(Duration::from_millis(5)).await;
        }
        assert!(transport.is_ready());

        let forwarder = harness.forwarder.forwarder().unwrap();
        for index in 0..6 {
            if index % 2 == 1 {
                // A pause longer than HOLDER_REVERIFY, as between routine checkpoints.
                if let Some(holder) = forwarder.state().holders.get_mut(&device_id()) {
                    holder.verified_at -= HOLDER_REVERIFY;
                }
            }
            // keyctl and the MCP server read device status before sending input.
            let (_, devices) = call(&harness.forwarder, "GET", "/v1/devices", None).await;
            assert_eq!(devices["devices"][0]["link_path"], TAILNET_LINK_PATH);
            let (status, receipt) = call(
                &harness.forwarder,
                "POST",
                &format!("/v1/devices/{}/sequences", device_id()),
                Some(sequence(Uuid::now_v7())),
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED, "command {index}: {receipt}");
            let result =
                wait_for_outcome(&harness.forwarder, receipt["command_id"].as_str().unwrap()).await;
            assert_eq!(result["outcome"], "EMITTED", "command {index}: {result}");
        }
        assert!(
            refused.load(Ordering::SeqCst) > 0,
            "proof interval never exercised"
        );
        transport.begin_maintenance().await.unwrap();
        assert_eq!(device.await.unwrap(), 6);
    }

    #[tokio::test]
    async fn ten_forwarded_300_character_commands_survive_holder_listener_replacement() {
        use crate::discovery::{refresh_interfaces, BeaconPlan, PortableGatewayBinding};
        use crate::tls::{read_frame, send_frame, tests::respond_on_name};
        use keyferry_protocol::{message, result_code, Frame};

        let harness = harness_with_wifi(None, FORWARDER_SECRET, None, true).await;
        let transport = harness
            .holder
            .gateway(&device_id())
            .unwrap()
            .transport
            .clone();
        let binding = PortableGatewayBinding::Multi(
            InstallationTlsSecretSet::load(harness.root.join("holder")).unwrap(),
            vec![transport.clone()],
        );
        let mut listeners = Vec::new();
        // macOS does not route arbitrary 127/8 aliases. Use two reserved local
        // ports so the real accept/session lifetime check runs on every OS.
        let reservations = [
            std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap(),
            std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap(),
        ];
        let first = BeaconPlan::loopback_test(reservations[0].local_addr().unwrap().port());
        let second = BeaconPlan::loopback_test(reservations[1].local_addr().unwrap().port());
        drop(reservations);
        assert!(
            refresh_interfaces(
                &mut listeners,
                &[second, first],
                transport.host_id(),
                &binding
            )
            .await
        );
        assert!(
            !refresh_interfaces(
                &mut listeners,
                &[first, second, first],
                transport.host_id(),
                &binding
            )
            .await
        );

        let credentials = transport.test_credentials();
        let gateway_id = transport.host_id();
        let started = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let device_started = Arc::clone(&started);
        let device_resume = Arc::clone(&resume);
        let controller = harness.forwarder.forwarder().unwrap().installation_id;
        let device = tokio::spawn(async move {
            let tcp = TcpStream::connect(first.listener_address()).await.unwrap();
            let name = keyferry_gateway::device_gateway_name(&DEVICE).unwrap();
            let (mut stream, ready) =
                respond_on_name(tcp, &credentials, &[0x33; 32], true, &name).await;
            let session: [u8; 16] = ready.payload[..16].try_into().unwrap();
            let mut paused = false;
            let mut commands = HashSet::new();
            while let Ok(frame) = read_frame(&mut stream).await {
                match frame.message_type {
                    message::ROUTE_PROOF_REQUEST => {
                        assert_eq!(&frame.payload[..16], &controller);
                        send_frame(
                            &mut stream,
                            Frame::v1(
                                message::ROUTE_PROOF_RESPONSE,
                                frame.sequence,
                                fixture_route_proof(&frame.payload, gateway_id, session),
                            ),
                        )
                        .await
                        .unwrap();
                    }
                    message::ARM | message::DISARM => {
                        send_frame(
                            &mut stream,
                            Frame::v1(message::ACK, frame.sequence, vec![frame.message_type, 0, 0]),
                        )
                        .await
                        .unwrap();
                    }
                    message::COMMAND => {
                        let execute = frame.payload[52] == 1;
                        let id: [u8; 16] = frame.payload[..16].try_into().unwrap();
                        if execute {
                            commands.insert(id);
                        }
                        let results: &[u8] = if execute {
                            &[
                                result_code::ACCEPTED,
                                result_code::STARTED,
                                result_code::EMITTED,
                            ]
                        } else {
                            &[result_code::ACCEPTED, result_code::EMITTED]
                        };
                        for result in results {
                            if execute && *result == result_code::EMITTED && !paused {
                                paused = true;
                                device_started.notify_one();
                                device_resume.notified().await;
                            }
                            let mut payload = id.to_vec();
                            payload.push(*result);
                            send_frame(
                                &mut stream,
                                Frame::v1(message::COMMAND_RESULT, frame.sequence, payload),
                            )
                            .await
                            .unwrap();
                        }
                    }
                    other => panic!("unexpected fixture message {other}"),
                }
            }
            commands.len()
        });
        for _ in 0..200 {
            if transport.is_ready() {
                break;
            }
            time::sleep(Duration::from_millis(5)).await;
        }
        assert!(transport.is_ready());
        let session = transport.session_snapshot().unwrap();
        let (_, devices) = call(&harness.forwarder, "GET", "/v1/devices", None).await;
        assert_eq!(devices["devices"][0]["link_path"], TAILNET_LINK_PATH);
        for index in 0..10 {
            let text: String = (0..300)
                .map(|n| char::from(b'a' + ((n * 17 + index) % 26) as u8))
                .collect();
            let (status, receipt) = call(
                &harness.forwarder,
                "POST",
                &format!("/v1/devices/{}/sequences", device_id()),
                Some(serde_json::json!({
                    "schema": "keyferry.keyboard-sequence.v1", "command_id": Uuid::now_v7().to_string(),
                    "profile": "windows-us", "arm": "command-scoped", "start_within_ms": 5000,
                    "timing": {"key_down_ms": 12, "release_gap_ms": 40},
                    "actions": [{"type": "text", "value": text}]
                })),
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED, "{receipt}");
            if index == 0 {
                time::timeout(Duration::from_secs(2), started.notified())
                    .await
                    .unwrap();
                // Remove the exact listener that accepted the in-flight command,
                // then bind it again. The session and command must survive both.
                assert!(refresh_interfaces(&mut listeners, &[second], gateway_id, &binding).await);
                assert!(
                    refresh_interfaces(&mut listeners, &[first, second], gateway_id, &binding)
                        .await
                );
                assert_eq!(transport.session_snapshot(), Some(session.clone()));
                resume.notify_one();
            }
            let result =
                wait_for_outcome(&harness.forwarder, receipt["command_id"].as_str().unwrap()).await;
            assert_eq!(result["outcome"], "EMITTED", "command {index}: {result}");
            assert_eq!(result["terminal_zero_confirmed"], true);
            assert_eq!(transport.session_snapshot(), Some(session.clone()));
        }
        transport.begin_maintenance().await.unwrap();
        assert_eq!(device.await.unwrap(), 10);
    }

    #[tokio::test]
    async fn offline_controller_forwards_through_the_verified_tailnet_holder() {
        let harness = harness(None, FORWARDER_SECRET).await;
        let forwarder = &harness.forwarder;
        let device = device_id();

        let (status, devices) = call(forwarder, "GET", "/v1/devices", None).await;
        assert_eq!(status, StatusCode::OK);
        let view = &devices["devices"][0];
        assert_eq!(view["id"], device.as_str());
        assert_eq!(view["label"], "Forwarder");
        assert_eq!(view["link"], "authenticated");
        assert_eq!(view["link_path"], TAILNET_LINK_PATH);
        assert_eq!(view["via"], "holder-host");
        assert_eq!(view["armed"], false);

        // Keyboard sequence: forwarded once, followed to its terminal outcome, deduplicated.
        let command_id = Uuid::now_v7();
        let uri = format!("/v1/devices/{device}/sequences");
        let (status, response) = call(forwarder, "POST", &uri, Some(sequence(command_id))).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{response}");
        assert_eq!(response["command_id"], command_id.to_string());
        let outcome = wait_for_outcome(forwarder, &command_id.to_string()).await;
        assert_eq!(outcome["outcome"], "EMITTED");
        let (status, duplicate) = call(forwarder, "POST", &uri, Some(sequence(command_id))).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(duplicate["outcome"], "EMITTED");
        assert_eq!(harness.holder_device.execution_count(command_id), 1);

        // Compatibility text without a command ID gets one bound before it leaves this computer.
        let (status, typed) = call(
            forwarder,
            "POST",
            &format!("/v1/devices/{device}/type"),
            Some(serde_json::json!({"text": "hi", "profile": "windows-us"})),
        )
        .await;
        // `type` requires an armed device; the holder refuses it before anything starts.
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{typed}");
        let (status, view) = call(
            forwarder,
            "POST",
            &format!("/v1/devices/{device}/arm"),
            Some(serde_json::json!({"policy": "temporary", "lease_ms": 60000})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["armed"], true);
        assert_eq!(view["via"], "holder-host");
        let (status, typed) = call(
            forwarder,
            "POST",
            &format!("/v1/devices/{device}/type"),
            Some(serde_json::json!({"text": "hi", "profile": "windows-us"})),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{typed}");
        let typed_id = typed["command_id"].as_str().unwrap().to_owned();
        assert_eq!(Uuid::parse_str(&typed_id).unwrap().get_version_num(), 7);
        assert_eq!(
            wait_for_outcome(forwarder, &typed_id).await["outcome"],
            "EMITTED"
        );
        let (status, view) = call(
            forwarder,
            "POST",
            &format!("/v1/devices/{device}/disarm"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["link_path"], TAILNET_LINK_PATH);
        assert_eq!(view["armed"], false);
        assert!(!harness.holder_device.is_remotely_armed());

        // Text stream: epochs are translated, the job stays on its holder, and it completes.
        let (_, capabilities) = call(forwarder, "GET", "/v1/capabilities", None).await;
        let epoch = capabilities["epoch"].as_str().unwrap().to_owned();
        assert_eq!(epoch, forwarder.0.epoch.to_string());
        let job_id = Uuid::now_v7();
        let streams = format!("/v1/devices/{device}/text-streams");
        let (status, receipt) = call(
            forwarder,
            "POST",
            &streams,
            Some(serde_json::json!({
                "schema": "keyferry.text-stream.v1",
                "epoch": epoch,
                "job_id": job_id.to_string(),
                "profile": "windows-us",
                "key_down_ms": 12,
                "key_gap_ms": 40,
                "send_after_seconds": 0,
                "source_kind": "text",
                "validation": "preflight",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{receipt}");
        assert_eq!(receipt["epoch"], epoch.as_str());
        let child_id = Uuid::now_v7();
        let (status, receipt) = call(
            forwarder,
            "POST",
            &format!("{streams}/{job_id}/parts/0"),
            Some(serde_json::json!({
                "epoch": epoch,
                "child_command_id": child_id.to_string(),
                "source_start": {"bytes": "0", "scalars": "0"},
                "text": "stream",
                "end_of_input": true,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{receipt}");
        assert_eq!(receipt["epoch"], epoch.as_str());
        let mut receipt = receipt;
        for _ in 0..200 {
            if receipt["terminal"] == true {
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
            receipt = call(forwarder, "GET", &format!("{streams}/{job_id}"), None)
                .await
                .1;
        }
        assert_eq!(receipt["outcome"], "EMITTED", "{receipt}");
        assert_eq!(receipt["epoch"], epoch.as_str());
        assert_eq!(harness.holder_device.execution_count(child_id), 1);
        // A stale epoch is refused here with the local contract.
        let (status, error) = call(
            forwarder,
            "POST",
            &format!("{streams}/{job_id}/lease"),
            Some(serde_json::json!({"epoch": Uuid::now_v7().to_string()})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(error["error"], "text_stream.epoch");
    }

    #[tokio::test]
    async fn forwarded_key_aliases_reach_the_holder_as_canonical_names_under_the_same_id() {
        let received = Received::default();
        let harness = harness_with(None, FORWARDER_SECRET, Some(Arc::clone(&received))).await;
        let forwarder = &harness.forwarder;
        let device = device_id();
        let posted = |segment: &str| -> Vec<Value> {
            let path = format!("/v1/devices/{device}/{segment}");
            received
                .lock()
                .unwrap()
                .iter()
                .filter(|(received, _)| *received == path)
                .map(|(_, body)| serde_json::from_slice(body).unwrap())
                .collect()
        };

        let command_id = Uuid::now_v7();
        let mut body = sequence(command_id);
        body["actions"] = serde_json::json!([
            {"type": "chord", "keys": ["CMD", "A"]},
            {"type": "repeat", "count": 2, "actions": [{"type": "tap", "key": "RETURN"}]}
        ]);
        let uri = format!("/v1/devices/{device}/sequences");
        let (status, response) = call(forwarder, "POST", &uri, Some(body)).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{response}");
        assert_eq!(response["command_id"], command_id.to_string());
        let outcome = wait_for_outcome(forwarder, &command_id.to_string()).await;
        assert_eq!(outcome["outcome"], "EMITTED");
        assert_eq!(harness.holder_device.execution_count(command_id), 1);
        let sent = posted("sequences");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["command_id"], command_id.to_string());
        assert_eq!(
            sent[0]["actions"],
            serde_json::json!([
                {"type": "chord", "keys": ["LEFT_GUI", "A"]},
                {"type": "repeat", "count": 2, "actions": [{"type": "tap", "key": "ENTER"}]}
            ])
        );

        let command_id = Uuid::now_v7();
        let (status, response) = call(
            forwarder,
            "POST",
            &format!("/v1/devices/{device}/input-sequences"),
            Some(serde_json::json!({
                "schema": "keyferry.input-sequence.v1",
                "command_id": command_id.to_string(),
                "keyboard_profile": "windows-us",
                "arm": "command-scoped",
                "start_within_ms": 5000,
                "actions": [
                    {"type": "click", "button": "button_1"},
                    {"type": "ordered_chord", "keys": ["OPT", "ESC"]}
                ],
            })),
        )
        .await;
        let sent = posted("input-sequences");
        assert_eq!(sent.len(), 1, "{status} {response}");
        assert_eq!(sent[0]["command_id"], command_id.to_string());
        assert_eq!(
            sent[0]["actions"],
            serde_json::json!([
                {"type": "click", "button": "button_1"},
                {"type": "ordered_chord", "keys": ["LEFT_ALT", "ESCAPE"]}
            ])
        );
    }

    #[tokio::test]
    async fn screen_power_follows_verified_holder_without_arming_or_replaying() {
        let harness = harness(None, FORWARDER_SECRET).await;
        let path = format!("/v1/devices/{}/screen-power", device_id());
        let (status, state) = call(&harness.forwarder, "GET", &path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(state["active"], "on");
        let (status, state) = call(
            &harness.forwarder,
            "POST",
            &path,
            Some(serde_json::json!({"power":"off"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(state["active"], "off");
        assert_eq!(state["stored"], "off");
        assert!(!harness.holder.device_view(&device_id()).unwrap().armed);
        let (status, _) = call(
            &harness.forwarder,
            "POST",
            &path,
            Some(serde_json::json!({"power":"invalid"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Fresh route proof passes; the on request arrives but its response is lost.
        harness.proxy.arm(2);
        let (status, _) = call(
            &harness.forwarder,
            "POST",
            &path,
            Some(serde_json::json!({"power":"on"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let connections = harness.proxy.connections.load(Ordering::SeqCst);
        time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            harness.proxy.connections.load(Ordering::SeqCst),
            connections
        );
        *harness.proxy.drop_at.lock().unwrap() = None;
        let (_, state) = call(&harness.forwarder, "GET", &path, None).await;
        assert_eq!(state["active"], "on");
        assert!(!harness.holder.device_view(&device_id()).unwrap().armed);

        let untrusted = self::harness(None, [0x99; 32]).await;
        let (status, _) = call(
            &untrusted.forwarder,
            "POST",
            &path,
            Some(serde_json::json!({"power":"off"})),
        )
        .await;
        assert!(!status.is_success());
        assert_eq!(
            untrusted
                .holder
                .screen_power(&device_id(), None)
                .await
                .unwrap()
                .active,
            crate::ScreenPower::On
        );
    }

    #[tokio::test]
    async fn lost_forwarded_response_is_unknown_and_never_resent() {
        let harness = harness(None, FORWARDER_SECRET).await;
        let forwarder = &harness.forwarder;
        let device = device_id();
        let (_, devices) = call(forwarder, "GET", "/v1/devices", None).await;
        assert_eq!(devices["devices"][0]["link_path"], TAILNET_LINK_PATH);

        // The route proof passes, the holder receives the command, its answer is lost, and
        // the read-only reconciliation cannot reach the holder.
        harness.proxy.arm(2);
        let command_id = Uuid::now_v7();
        let uri = format!("/v1/devices/{device}/sequences");
        let (status, response) = call(forwarder, "POST", &uri, Some(sequence(command_id))).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{response}");
        assert_eq!(response["outcome"], "UNKNOWN");
        assert_eq!(response["terminal"], true);
        assert_eq!(response["possible_start"], true);
        assert_eq!(response["output_transport"], Value::Null);
        for _ in 0..200 {
            if harness.holder_device.execution_count(command_id) == 1 {
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(harness.holder_device.execution_count(command_id), 1);

        // Resubmitting never contacts the holder. Read-only outcome reconciliation may.
        let connections = harness.proxy.connections.load(Ordering::SeqCst);
        let (status, again) = call(forwarder, "POST", &uri, Some(sequence(command_id))).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(again["outcome"], "UNKNOWN");
        assert_eq!(
            harness.proxy.connections.load(Ordering::SeqCst),
            connections
        );
        let (status, outcome) = call(
            forwarder,
            "GET",
            &format!("/v1/devices/{device}/commands/{command_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(outcome["outcome"], "UNKNOWN");
        assert!(harness.proxy.connections.load(Ordering::SeqCst) > connections);
        time::sleep(Duration::from_millis(50)).await;
        assert_eq!(harness.holder_device.execution_count(command_id), 1);
        // Once the holder is reachable, observe its terminal receipt without replay.
        *harness.proxy.drop_at.lock().unwrap() = None;
        let (_, recovered) = call(
            forwarder,
            "GET",
            &format!("/v1/devices/{device}/commands/{command_id}"),
            None,
        )
        .await;
        assert_eq!(recovered["outcome"], "EMITTED");
        assert_eq!(harness.holder_device.execution_count(command_id), 1);
    }

    #[tokio::test]
    async fn transient_holder_connection_failure_before_send_does_not_fail_command() {
        let harness = harness(None, FORWARDER_SECRET).await;
        let (_, devices) = call(&harness.forwarder, "GET", "/v1/devices", None).await;
        assert_eq!(devices["devices"][0]["link_path"], TAILNET_LINK_PATH);
        *harness.proxy.refuse_once_at.lock().unwrap() =
            Some(harness.proxy.connections.load(Ordering::SeqCst) + 1);
        let command_id = Uuid::now_v7();
        let (status, response) = call(
            &harness.forwarder,
            "POST",
            &format!("/v1/devices/{}/sequences", device_id()),
            Some(sequence(command_id)),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{response}");
        let result = wait_for_outcome(&harness.forwarder, &command_id.to_string()).await;
        assert_eq!(result["outcome"], "EMITTED");
        assert_eq!(harness.holder_device.execution_count(command_id), 1);
    }

    #[tokio::test]
    async fn local_link_wins_and_configuration_is_never_forwarded() {
        let local = SimulatorTransport::default();
        let harness = harness(Some(local.clone()), FORWARDER_SECRET).await;
        let forwarder = &harness.forwarder;
        let device = device_id();
        let uri = format!("/v1/devices/{device}/sequences");
        let set_local = |authenticated: bool| {
            let handle = forwarder.lookup(&device).unwrap();
            let mut runtime = handle.0.lock().unwrap();
            if authenticated {
                runtime.state.set_link_authenticated();
            } else {
                runtime.state.disconnect();
            }
        };

        let (_, devices) = call(forwarder, "GET", "/v1/devices", None).await;
        assert_eq!(devices["devices"][0]["link"], "authenticated");
        assert!(devices["devices"][0].get("via").is_none());
        let local_id = Uuid::now_v7();
        call(forwarder, "POST", &uri, Some(sequence(local_id))).await;
        wait_for_outcome(forwarder, &local_id.to_string()).await;
        assert_eq!(local.execution_count(local_id), 1);
        assert_eq!(harness.proxy.connections.load(Ordering::SeqCst), 0);

        set_local(false);
        let (_, devices) = call(forwarder, "GET", "/v1/devices", None).await;
        assert_eq!(devices["devices"][0]["via"], "holder-host");
        let remote_id = Uuid::now_v7();
        call(forwarder, "POST", &uri, Some(sequence(remote_id))).await;
        assert_eq!(
            wait_for_outcome(forwarder, &remote_id.to_string()).await["outcome"],
            "EMITTED"
        );
        assert_eq!(harness.holder_device.execution_count(remote_id), 1);
        assert_eq!(local.execution_count(remote_id), 0);

        // Configuration stays local even while the holder is known and reachable.
        let connections = harness.proxy.connections.load(Ordering::SeqCst);
        let (status, _) = call(
            forwarder,
            "POST",
            &format!("/v1/devices/{device}/output-mode"),
            Some(serde_json::json!({"mode": "ble-hid"})),
        )
        .await;
        assert!(!status.is_success());
        let (status, _) = call(
            forwarder,
            "GET",
            &format!("/v1/devices/{device}/output-mode"),
            None,
        )
        .await;
        assert!(!status.is_success());
        assert_eq!(
            harness.proxy.connections.load(Ordering::SeqCst),
            connections
        );
        assert_eq!(
            harness
                .holder_device
                .output_mode(None)
                .await
                .unwrap()
                .stored,
            OutputMode::UsbHid
        );

        // The stick came back: local wins at once, with no tailnet traffic.
        set_local(true);
        let back_id = Uuid::now_v7();
        call(forwarder, "POST", &uri, Some(sequence(back_id))).await;
        wait_for_outcome(forwarder, &back_id.to_string()).await;
        assert_eq!(local.execution_count(back_id), 1);
        assert_eq!(harness.holder_device.execution_count(back_id), 0);
        assert_eq!(
            harness.proxy.connections.load(Ordering::SeqCst),
            connections
        );
        // A command that ran on the holder still reports from the holder.
        assert_eq!(
            wait_for_outcome(forwarder, &remote_id.to_string()).await["outcome"],
            "EMITTED"
        );
    }

    #[tokio::test]
    async fn stale_holder_is_forgotten_before_any_command_is_sent() {
        let harness = harness(None, FORWARDER_SECRET).await;
        let forwarder = &harness.forwarder;
        let device = device_id();
        let (_, devices) = call(forwarder, "GET", "/v1/devices", None).await;
        assert_eq!(devices["devices"][0]["via"], "holder-host");

        // The stick left the holder (for example, it failed over after a restart).
        harness
            .holder
            .lookup(&device)
            .unwrap()
            .0
            .lock()
            .unwrap()
            .state
            .disconnect();
        let command_id = Uuid::now_v7();
        let (status, response) = call(
            forwarder,
            "POST",
            &format!("/v1/devices/{device}/sequences"),
            Some(sequence(command_id)),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{response}");
        assert_eq!(harness.holder_device.execution_count(command_id), 0);
        let (_, devices) = call(forwarder, "GET", "/v1/devices", None).await;
        assert_eq!(devices["devices"][0]["link"], "offline");
        assert!(devices["devices"][0].get("via").is_none());
    }

    #[tokio::test]
    async fn a_stalled_holder_never_delays_another_devices_refresh() {
        let harness = harness(None, FORWARDER_SECRET).await;
        let (_, devices) = call(&harness.forwarder, "GET", "/v1/devices", None).await;
        assert_eq!(devices["devices"][0]["via"], "holder-host");
        let forwarder = harness.forwarder.forwarder().unwrap();
        // A holder that accepts TCP and never answers TLS, due for a fresh route proof.
        let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stalled_address = stalled.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = stalled.accept().await {
                held.push(stream);
            }
        });
        // A holder that hangs up at once (Windows retries a refused loopback connect for ~2 s).
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_address = closed.local_addr().unwrap();
        tokio::spawn(async move { while closed.accept().await.is_ok() {} });
        let other = Uuid::from_bytes([0x23; 16]).to_string();
        {
            let mut state = forwarder.state();
            let mut holder = state.holders[&device_id()].clone();
            holder.route.control = stalled_address;
            holder.verified_at = Instant::now()
                .checked_sub(HOLDER_REVERIFY + Duration::from_secs(1))
                .unwrap();
            let mut gone = holder.clone();
            gone.route.control = closed_address;
            gone.verified_at = Instant::now();
            gone.view_at = holder.verified_at;
            state.holders.insert(device_id(), holder);
            state.holders.insert(other.clone(), gone);
            state.last_discovery = Some(Instant::now());
        }
        let slow = tokio::spawn(Arc::clone(&forwarder).refresh(vec![device_id()]));
        time::sleep(Duration::from_millis(50)).await;
        let started = Instant::now();
        Arc::clone(&forwarder).refresh(vec![other.clone()]).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        assert!(!forwarder.state().holders.contains_key(&other));
        assert!(!slow.is_finished());
        slow.abort();
    }

    #[tokio::test]
    async fn holder_without_a_valid_route_proof_is_never_used() {
        // The endpoint answers with a tag this installation cannot verify.
        let harness = harness(None, [0x5f; 32]).await;
        let forwarder = &harness.forwarder;
        let device = device_id();
        let (_, devices) = call(forwarder, "GET", "/v1/devices", None).await;
        assert_eq!(devices["devices"][0]["link"], "offline");
        assert!(devices["devices"][0].get("via").is_none());
        let command_id = Uuid::now_v7();
        let (status, _) = call(
            forwarder,
            "POST",
            &format!("/v1/devices/{device}/sequences"),
            Some(sequence(command_id)),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(harness.holder_device.execution_count(command_id), 0);
        assert!(harness.holder.metadata().is_empty());
    }

    #[tokio::test]
    async fn file_upload_status_and_clear_follow_verified_holder_route() {
        let harness = harness(None, FORWARDER_SECRET).await;
        let path = format!("/v1/devices/{}/file", device_id());
        let bytes = (0..=200).map(|value| value as u8).collect::<Vec<_>>();
        let (status, response) = call(
            &harness.forwarder,
            "POST",
            &path,
            Some(serde_json::json!({"bytes": bytes})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["state"], "published");
        assert_eq!(response["size_bytes"], 201);
        assert_eq!(harness.file.lock().unwrap().commits, 1);
        let (status, response) = call(&harness.forwarder, "GET", &path, None).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["received_bytes"], 201);
        let (status, response) = call(&harness.forwarder, "DELETE", &path, None).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["state"], "empty");
        assert!(harness.file.lock().unwrap().bytes.is_empty());
    }

    #[tokio::test]
    async fn maximum_binary_file_reaches_holder_through_production_route() {
        let harness = harness(None, FORWARDER_SECRET).await;
        let path = format!("/v1/devices/{}/file", device_id());
        let bytes = vec![0xff; keyferry_protocol::file::MAX_FILE_BYTES];
        let body = serde_json::json!({"bytes": bytes.clone()});
        assert!(body.to_string().len() <= MAX_FILE_REQUEST_BODY);
        let (status, response) = call(&harness.forwarder, "POST", &path, Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["size_bytes"].as_u64(), Some(bytes.len() as u64));
        let file = harness.file.lock().unwrap();
        assert!(file.published);
        assert_eq!(file.commits, 1);
        assert_eq!(file.bytes, bytes);
    }

    #[tokio::test]
    async fn maximum_file_set_reaches_exact_holder_and_lists_names() {
        let harness = harness(None, FORWARDER_SECRET).await;
        let path = format!("/v1/devices/{}/files", device_id());
        let files = serde_json::json!({"files": [
            {"name": "ONE.TXT", "bytes": vec![0xa5_u8; keyferry_protocol::file_set::MAX_FILE_BYTES - 1]},
            {"name": "TWO.txt", "bytes": [0x42]}
        ]});
        assert!(files.to_string().len() <= MAX_FILE_SET_REQUEST_BODY);
        let (status, response) = call(&harness.forwarder, "POST", &path, Some(files)).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(
            response["size_bytes"],
            keyferry_protocol::file_set::MAX_FILE_BYTES
        );
        assert_eq!(response["files"][0]["name"], "ONE.TXT");
        assert_eq!(response["files"][1]["name"], "TWO.txt");
        let (status, listed) = call(&harness.forwarder, "GET", &path, None).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["files"], response["files"]);
        let file = harness.file.lock().unwrap();
        assert_eq!(file.commits, 1);
        assert_eq!(file.entries.len(), 2);
        assert_eq!(
            file.bytes.len(),
            1 + (1 + 7 + 4) + (1 + 7 + 4) + keyferry_protocol::file_set::MAX_FILE_BYTES
        );
    }

    #[tokio::test]
    async fn v2_list_reports_legacy_empty_message_without_bundle_overhead() {
        let harness = harness(None, FORWARDER_SECRET).await;
        let device = device_id();
        let (status, posted) = call(
            &harness.forwarder,
            "POST",
            &format!("/v1/devices/{device}/file"),
            Some(serde_json::json!({"bytes": []})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{posted}");
        let (status, listed) = call(
            &harness.forwarder,
            "GET",
            &format!("/v1/devices/{device}/files"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["state"], "published");
        assert_eq!(listed["size_bytes"], 0);
        assert_eq!(listed["bundle_size_bytes"], 0);
        assert_eq!(
            listed["files"],
            serde_json::json!([{"name":"MESSAGE.TXT","size":0}])
        );
    }

    #[tokio::test]
    async fn lost_forwarded_file_set_response_is_uncertain_without_replay() {
        let harness = harness(None, FORWARDER_SECRET).await;
        let path = format!("/v1/devices/{}/files", device_id());
        let (_, devices) = call(&harness.forwarder, "GET", "/v1/devices", None).await;
        assert_eq!(devices["devices"][0]["link_path"], TAILNET_LINK_PATH);
        harness.proxy.arm(2);
        let (status, response) = call(
            &harness.forwarder,
            "POST",
            &path,
            Some(serde_json::json!({"files": [{"name": "ONE.TXT", "bytes": [1, 2]}]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{response}");
        let connections = harness.proxy.connections.load(Ordering::SeqCst);
        assert_eq!(harness.file.lock().unwrap().commits, 1);
        time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            harness.proxy.connections.load(Ordering::SeqCst),
            connections
        );
        assert_eq!(harness.file.lock().unwrap().commits, 1);
    }

    #[test]
    fn only_device_state_and_command_routes_are_forwardable() {
        let device = device_id();
        for (method, path) in [
            (Method::POST, format!("/v1/devices/{device}/output-mode")),
            (Method::GET, format!("/v1/devices/{device}/output-mode")),
            (
                Method::POST,
                format!("/v1/devices/{device}/display-orientation"),
            ),
            (
                Method::POST,
                format!("/v1/devices/{device}/ble-hid-bond/reset"),
            ),
            (
                Method::POST,
                format!("/v1/devices/{device}/maintenance/begin"),
            ),
            (
                Method::POST,
                format!("/v1/devices/{device}/gateway/handoffs"),
            ),
            (
                Method::POST,
                format!("/v1/devices/{device}/gateway/outgoing-handoff"),
            ),
            (Method::GET, "/v1/events".to_owned()),
            (Method::GET, "/v1/capabilities".to_owned()),
            (Method::GET, format!("/v1/devices/{device}/type")),
            (Method::POST, format!("/v1/devices/{device}/")),
            (Method::POST, format!("/v1/devices/{device}%2Ftype")),
            (Method::PUT, format!("/v1/devices/{device}/file")),
        ] {
            assert!(Op::classify(&method, &path).is_none(), "{method} {path}");
        }
        for (method, path) in [
            (Method::GET, "/v1/devices".to_owned()),
            (Method::GET, format!("/v1/devices/{device}/screen-power")),
            (Method::POST, format!("/v1/devices/{device}/screen-power")),
            (Method::POST, format!("/v1/devices/{device}/sequences")),
            (Method::POST, format!("/v1/devices/{device}/arm/renew")),
            (
                Method::POST,
                format!(
                    "/v1/devices/{device}/text-streams/{}/parts/3",
                    Uuid::now_v7()
                ),
            ),
            (
                Method::GET,
                format!("/v1/devices/{device}/commands/{}", Uuid::now_v7()),
            ),
            (Method::GET, format!("/v1/devices/{device}/file")),
            (Method::POST, format!("/v1/devices/{device}/file")),
            (Method::DELETE, format!("/v1/devices/{device}/file")),
        ] {
            assert!(Op::classify(&method, &path).is_some(), "{method} {path}");
        }
    }

    #[test]
    fn lost_part_is_settled_only_by_a_receipt_that_proves_where_it_ended() {
        let child = Uuid::now_v7().to_string();
        let part = StreamAction::Part("2".to_owned());
        let receipt = |value: Value| serde_json::to_vec(&value).unwrap();
        assert!(!settled_by_receipt(
            &receipt(serde_json::json!({"terminal": false, "next_index": "2"})),
            &part,
            Some(&child),
        ));
        assert!(settled_by_receipt(
            &receipt(serde_json::json!({
                "terminal": false,
                "next_index": "2",
                "current_child": {"command_id": child},
            })),
            &part,
            Some(&child),
        ));
        assert!(settled_by_receipt(
            &receipt(serde_json::json!({"terminal": false, "next_index": "3"})),
            &part,
            Some(&child),
        ));
        assert!(settled_by_receipt(
            &receipt(serde_json::json!({"terminal": true})),
            &StreamAction::Finish,
            None,
        ));
    }

    #[test]
    fn tailnet_peers_are_online_ipv4_tailnet_addresses_other_than_this_computer() {
        let status = keyferry_gateway::tailnet::parse_status_json(
            br#"{
                "Self":{"HostName":"this","TailscaleIPs":["100.64.0.1"]},
                "Peer":{
                    "a":{"HostName":"holder","TailscaleIPs":["fd7a:115c:a1e0::2","100.64.0.2"],"Online":true},
                    "b":{"HostName":"asleep","TailscaleIPs":["100.64.0.3"],"Online":false},
                    "c":{"HostName":"hello","DNSName":"hello.ipn.dev.","TailscaleIPs":["100.64.0.4"],"Online":true},
                    "d":{"HostName":"lan","TailscaleIPs":["192.168.1.5"],"Online":true},
                    "e":{"HostName":"alias","TailscaleIPs":["100.64.0.1"],"Online":true}
                }
            }"#,
        )
        .unwrap();
        let peers = tailnet_peers(&status);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name.as_deref(), Some("holder"));
        assert_eq!(peers[0].address, IpAddr::from([100, 64, 0, 2]));
        assert_eq!(peers[0].probe_port, OWNER_GATEWAY_PROBE_PORT);
        assert_eq!(peers[0].control_port, OWNER_GATEWAY_CONTROL_PORT);
    }
    fn fake_capture(daemon: &Daemon) {
        daemon.0.capture.fake.lock().unwrap().insert(
            "fake-hdmi".into(),
            keyferry_capture::frames::Frame {
                width: 320,
                height: 240,
                native: (640, 480),
                rgb: vec![72; 320 * 240 * 3],
                serial: 1,
                generation: 1,
                at: Instant::now(),
            },
        );
    }
    async fn capture_source(daemon: &Daemon) -> String {
        // Bypass local FFmpeg discovery only: actual owner-mTLS inventory is production code.
        let (sources, errors) = daemon.forwarder().unwrap().capture_sources().await;
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(sources.len(), 1);
        sources[0]["id"].as_str().unwrap().to_owned()
    }
    fn frame_request(source: &str) -> Value {
        serde_json::json!({"device":device_id(),"source":source})
    }

    #[tokio::test]
    async fn remote_frames_and_click_use_real_owner_mtls_without_frame_logs() {
        use base64::Engine;
        let harness = harness(None, FORWARDER_SECRET).await;
        fake_capture(&harness.holder);
        let source = capture_source(&harness.forwarder).await;
        let (status, frame) = call(
            &harness.forwarder,
            "POST",
            "/v1/capture/frame",
            Some(frame_request(&source)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{frame}");
        let png = base64::engine::general_purpose::STANDARD
            .decode(frame["png"].as_str().unwrap())
            .unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(frame["width"], 320);
        assert!(!harness.holder_device.is_remotely_armed());
        assert!(harness.holder.metadata().is_empty());
        assert!(harness.forwarder.metadata().is_empty());
        // Agent controller has no local capture or stick. Screenshot coordinates drive the
        // holder's pointer compiler through the same production input-sequence admission.
        let command = Uuid::now_v7();
        let (status,receipt)=call(&harness.forwarder,"POST",&format!("/v1/devices/{}/input-sequences",device_id()),
            Some(serde_json::json!({"schema":"keyferry.input-sequence.v2","command_id":command,"arm":"command-scoped","start_within_ms":5000,
                "actions":[{"type":"move_absolute","x":0.5,"y":0.5},{"type":"click","button":"button_1"}]}))).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{receipt}");
        let outcome = wait_for_outcome(&harness.forwarder, &command.to_string()).await;
        assert_eq!(outcome["outcome"], "EMITTED");
        assert_eq!(outcome["terminal_zero_confirmed"], true);
        assert!(!harness.holder_device.is_remotely_armed());
        let events = serde_json::to_string(&harness.holder.metadata()).unwrap();
        assert!(!events.contains(frame["png"].as_str().unwrap()));
        assert!(!events.contains("png"));
    }

    #[tokio::test]
    async fn remote_frames_refuse_untrusted_proof_oversize_and_offline_peer() {
        let bad = harness(None, [0xee; 32]).await;
        fake_capture(&bad.holder);
        let source = capture_source(&bad.forwarder).await;
        let (status, _) = call(
            &bad.forwarder,
            "POST",
            "/v1/capture/frame",
            Some(frame_request(&source)),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(bad.holder.metadata().is_empty());

        let good = harness(None, FORWARDER_SECRET).await;
        fake_capture(&good.holder);
        let source = capture_source(&good.forwarder).await;
        let mut request = frame_request(&source);
        request["max_width"] = serde_json::json!(keyferry_capture::frames::MAX_SIDE + 1);
        let (status, error) =
            call(&good.forwarder, "POST", "/v1/capture/frame", Some(request)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error["error"], "capture.scale");
        // A source emitting an oversized frame is rejected before encoding or allocating a crop.
        good.holder
            .0
            .capture
            .fake
            .lock()
            .unwrap()
            .get_mut("fake-hdmi")
            .unwrap()
            .width = 1281;
        time::sleep(Duration::from_millis(110)).await;
        let (status, error) = call(
            &good.forwarder,
            "POST",
            "/v1/capture/frame",
            Some(frame_request(&source)),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error["error"], "capture.size_limit");
        good.proxy.arm(1);
        let (status, error) = call(
            &good.forwarder,
            "POST",
            "/v1/capture/frame",
            Some(frame_request(&source)),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(error["error"].as_str().unwrap().contains("offline"));
    }

    #[tokio::test]
    async fn capture_routes_are_loopback_or_owner_mtls_only_and_proof_is_required() {
        let h = harness(None, FORWARDER_SECRET).await;
        fake_capture(&h.holder);
        let forwarder = h.forwarder.forwarder().unwrap();
        let _ = call(&h.forwarder, "GET", "/v1/devices", None).await;
        let route = forwarder.fresh_route(&device_id()).unwrap();
        h.holder.0.owner_routes.lock().unwrap().clear();
        let body = serde_json::to_vec(&frame_request("local:fake-hdmi")).unwrap();
        let path = format!("/v1/devices/{}/capture/frame", device_id());
        let response = forwarder
            .exchange(&route, "POST", &path, Some(&body), CONTROL_TIMEOUT)
            .await;
        assert!(matches!(
            response,
            OwnerExchange::Response { status: 401, .. }
        ));
        // Plain HTTP cannot reach the owner-mTLS router, even with the holder's loopback bearer.
        let mut tcp = TcpStream::connect(route.control).await.unwrap();
        tcp.write_all(format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer holder-token-123456\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
        let mut bytes = [0; 128];
        let n = time::timeout(Duration::from_secs(2), tcp.read(&mut bytes))
            .await
            .unwrap()
            .unwrap_or(0);
        assert!(!bytes[..n].starts_with(b"HTTP/1.1 200"));
        let mut local = h.holder.router();
        let response = local
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/v1/capture/frame")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn eyes_controller_can_differ_from_the_authenticated_stick_holder() {
        let h = harness(None, FORWARDER_SECRET).await;
        let _ = call(&h.forwarder, "GET", "/v1/devices", None).await;
        let holder_route = h
            .forwarder
            .forwarder()
            .unwrap()
            .fresh_route(&device_id())
            .unwrap();
        let eyes_stores = InstallationTlsSecretSet::load(h.root.join("eyes")).unwrap();
        let eyes_store = eyes_stores.iter().next().unwrap().clone();
        let eyes = Daemon::with_tls_transports(
            MemoryTokenStore::new("eyes-token-123456"),
            vec![(
                device_id(),
                "Eyes".into(),
                TlsTransport::from_installation_store(&eyes_store).unwrap(),
            )],
        )
        .unwrap();
        // Seed a discovered holder route from the same authenticated test exchange. Frame serving
        // still reproves it using the eyes controller's own distinct device secret every request.
        let eyes_forwarder = Forwarder::new(&eyes_stores, Box::new(StaticPeers(vec![]))).unwrap();
        let view = h
            .forwarder
            .forwarder()
            .unwrap()
            .fetch_view(&holder_route, &device_id())
            .await
            .unwrap();
        eyes_forwarder.state().holders.insert(
            device_id(),
            Holder {
                route: holder_route,
                view,
                view_at: Instant::now(),
                verified_at: Instant::now(),
            },
        );
        eyes.enable_forwarding(eyes_forwarder).unwrap();
        fake_capture(&eyes);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let route = Route {
            installation_id: eyes_store.installation_id(),
            control: address,
            name: None,
        };
        tokio::spawn(serve_owner_mtls_listener(
            eyes.clone(),
            listener,
            eyes_store,
        ));
        let caller = h.forwarder.forwarder().unwrap();
        caller
            .captures
            .lock()
            .unwrap()
            .insert("eyes:fake-hdmi".into(), (route, "local:fake-hdmi".into()));
        let (status, frame) = call(
            &h.forwarder,
            "POST",
            "/v1/capture/frame",
            Some(frame_request("eyes:fake-hdmi")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{frame}");
        assert!(eyes.metadata().is_empty());
        assert!(!eyes.local_link_authenticated(&device_id()));
        assert!(!h.holder_device.is_remotely_armed());
    }
    #[tokio::test]
    async fn oversized_frame_response_is_refused_by_the_real_owner_mtls_transport() {
        let h = harness(None, FORWARDER_SECRET).await;
        fake_capture(&h.holder);
        let source = capture_source(&h.forwarder).await;
        let store = InstallationTlsSecretSet::load(h.root.join("holder"))
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let listener = crate::OwnerTlsListener {
            control_port: address.port(),
            listener,
            acceptor: store.remote_tls_acceptor().unwrap(),
        };
        let app = h
            .holder
            .owner_remote_router()
            .layer(axum::middleware::from_fn(
                |request: Request, next: Next| async move {
                    let frame = request.uri().path().ends_with("/capture/frame");
                    let response = next.run(request).await;
                    if frame && response.status() == StatusCode::OK {
                        (
                            StatusCode::OK,
                            [(header::CONTENT_TYPE, "application/json")],
                            vec![b'x'; crate::capture::MAX_WIRE + MAX_RESPONSE_HEADER + 1],
                        )
                            .into_response()
                    } else {
                        response
                    }
                },
            ));
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<crate::RemoteTlsPeer>(),
            )
            .await
            .unwrap();
        });
        h.forwarder
            .forwarder()
            .unwrap()
            .captures
            .lock()
            .unwrap()
            .get_mut(&source)
            .unwrap()
            .0
            .control = address;
        let (status, error) = call(
            &h.forwarder,
            "POST",
            "/v1/capture/frame",
            Some(frame_request(&source)),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error["error"], "capture.peer_offline_or_invalid_frame");
        assert!(h.holder.metadata().is_empty());
        task.abort();
    }
}
