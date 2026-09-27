#![forbid(unsafe_code)]

use axum::{
    body::Bytes,
    extract::{
        connect_info::Connected, ConnectInfo, DefaultBodyLimit, Path, RawQuery, Request, State,
    },
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{sse, IntoResponse, Response},
    routing::{get, post},
    serve::{IncomingStream, Listener},
    Json, Router,
};
use hmac::{Hmac, Mac};
use keyferry_core::{
    ArmPolicy, CommandState, DeviceState, OperationalMode, StateError, TransportDiagnostic,
};
#[cfg(test)]
use keyferry_layouts::plan_text_us;
use keyferry_layouts::text_stream::{
    text_stream_child_capacity, validate_text_stream_part, UnsupportedTextPolicy,
    TEXT_STREAM_RECEIPT_SCHEMA_V1, TEXT_STREAM_SCHEMA_V1,
};
use keyferry_layouts::{
    chord_from_names, compile_input_sequence, compile_sequence, parse_input_sequence_json,
    stroke_for_key_name, CompiledInputSequence, CompiledSequence, InputSequenceV1, KeyClass,
    KeyboardReport, KeyboardSequenceV1, Keystroke, ReportStep, SequenceAction, SequenceArmPolicy,
    SequenceError, TypingTiming, KEYBOARD_KEYS, SEQUENCE_SCHEMA_V1,
};
use keyferry_sim::{execute_input_gestures, SimulatedEndpoint};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{hash_map::DefaultHasher, HashMap, VecDeque},
    convert::Infallible,
    fmt,
    fs::{self, OpenOptions},
    hash::{Hash, Hasher},
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{broadcast, mpsc, watch},
    time,
};
use tokio_rustls::{server::TlsStream as ServerTlsStream, TlsAcceptor};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use uuid::Uuid;

mod ble;
mod discovery;
mod forward;
mod tailnet;
mod tls;
pub use ble::{run_ble_gateway, run_ble_gateways, BleGatewayError};
pub use discovery::{BeaconPlan, GatewayListenerRegistry, HostBeacon};
pub use keyferry_gateway::{
    is_tailscale_ip, sign_gateway_proof, verify_gateway_proof, GatewayArmMode,
    GatewayDeviceSummary, GatewayLinkPath, GatewayProofError, GatewayProofPayload,
    SignedGatewayProof, GATEWAY_PROOF_VERSION, MAX_GATEWAY_DEVICES,
};
pub use tailnet::discover_local_tailscale_ipv4;
pub use tls::{
    auth_hmac, FileTlsSecretStore, HostIdentity, InstallationTlsSecretSet,
    InstallationTlsSecretStore, MemoryTlsSecretStore, MultiTlsListener, MultiTlsRouter,
    TlsCredentials, TlsLinkPath, TlsListener, TlsSecretStore, TlsSessionSnapshot, TlsTransport,
    TlsTransportError,
};

pub const SIMULATOR_DEVICE_ID: &str = "simulator-1";
pub const DEFAULT_PORT: u16 = 8042;
pub const DEFAULT_REMOTE_PORT: u16 = 18_043;
pub const MAX_CHUNK_EXPECTED_MS: u32 = 500;
pub const MAX_CHUNK_ACTIONS: usize = 64;
pub const MAX_NETWORK_COMMAND_BODY: usize = keyferry_protocol::MAX_PAYLOAD - (16 + 4 + 32 + 1 + 2);
pub const MAX_COMMAND_EXPIRY_MS: u32 = 5_000;
pub const MAX_TEXT_CHARS: usize = 4_096;
pub const MAX_SEQUENCE_REQUEST_BODY: usize = 65_536;
// Compact JSON for {"bytes":[255,...]} takes at most four bytes per u8,
// plus the fixed object framing. Leave bounded room for harmless whitespace.
pub const MAX_FILE_REQUEST_BODY: usize = keyferry_protocol::file::MAX_FILE_BYTES * 4 + 64;
pub const MAX_FILE_SET_REQUEST_BODY: usize = keyferry_protocol::file_set::MAX_FILE_BYTES * 4
    + keyferry_protocol::file_set::MAX_FILES * (keyferry_protocol::file_set::MAX_NAME_BYTES + 32)
    + 128;
const FILE_BEGIN_BUSY_WAIT: Duration = Duration::from_secs(20);
const FILE_UPLOAD_LIMIT: Duration = Duration::from_secs(110);
pub const MAX_TEMPORARY_ARM_MS: u64 = 600_000;
pub const MAX_SEQUENCE_EXECUTION_MS: u64 = 120_000;
pub const MAX_TEXT_STREAM_PART_BODY: usize = 16_384;
pub const MAX_TEXT_STREAM_PARENTS: usize = 256;
const TEXT_STREAM_LEASE: Duration = Duration::from_secs(15);
const TEXT_STREAM_SOURCE_IDLE: Duration = Duration::from_secs(30);
const TEXT_STREAM_RECEIPT_RETENTION: Duration = Duration::from_secs(10 * 60);
const DEFAULT_TEMPORARY_ARM_MS: u64 = 30_000;
const COMMAND_RECOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const GATEWAY_API_VERSION: u16 = 1;
const VERIFIED_CALLER_HEADER: HeaderName = HeaderName::from_static("x-keyferry-caller");
const VERIFIED_OWNER_CALLER_HEADER: HeaderName = HeaderName::from_static("x-keyferry-owner-caller");

#[derive(Debug)]
pub enum DaemonError {
    Io(io::Error),
    Token(String),
    Server(io::Error),
    Tls(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairedRuntimeFile {
    schema_version: u8,
    tls_bind: String,
    tls_device_id: String,
    tls_secret_dir: String,
    #[serde(default)]
    discovery_netmask: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PairedRuntimeConfig {
    bind: SocketAddr,
    device_id: Uuid,
    secret_dir: PathBuf,
    beacon_plan: Option<BeaconPlan>,
}

impl PairedRuntimeConfig {
    pub fn load(path: impl AsRef<FsPath>) -> Result<Self, DaemonError> {
        let path = path.as_ref();
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(DaemonError::Tls(
                "paired runtime configuration exceeds 4096 bytes".to_owned(),
            ));
        }
        let file: PairedRuntimeFile = serde_json::from_slice(&bytes)
            .map_err(|_| DaemonError::Tls("paired runtime configuration is invalid".to_owned()))?;
        if file.schema_version != 1 || file.tls_secret_dir != "secrets" {
            return Err(DaemonError::Tls(
                "paired runtime configuration has unsupported values".to_owned(),
            ));
        }
        let bind = file
            .tls_bind
            .parse::<SocketAddr>()
            .map_err(|_| DaemonError::Tls("paired TLS bind address is invalid".to_owned()))?;
        if bind.ip().is_unspecified() || bind.ip().is_multicast() {
            return Err(DaemonError::Tls(
                "paired TLS bind must select one local interface".to_owned(),
            ));
        }
        let device_id = file
            .tls_device_id
            .parse::<Uuid>()
            .map_err(|_| DaemonError::Tls("paired device identifier is invalid".to_owned()))?;
        if device_id.get_version_num() != 4 {
            return Err(DaemonError::Tls(
                "paired device identifier must be UUID v4".to_owned(),
            ));
        }
        let beacon_plan = match file.discovery_netmask {
            Some(netmask) => {
                let interface = match bind.ip() {
                    std::net::IpAddr::V4(address) => address,
                    std::net::IpAddr::V6(_) => {
                        return Err(DaemonError::Tls(
                            "discovery requires an explicitly selected IPv4 interface".to_owned(),
                        ));
                    }
                };
                let netmask = netmask.parse().map_err(|_| {
                    DaemonError::Tls("paired discovery netmask is invalid".to_owned())
                })?;
                Some(
                    BeaconPlan::new(interface, netmask)
                        .map_err(|message| DaemonError::Tls(message.to_owned()))?,
                )
            }
            None => None,
        };
        let parent = path.parent().ok_or_else(|| {
            DaemonError::Tls("paired runtime configuration has no parent directory".to_owned())
        })?;
        Ok(Self {
            bind,
            device_id,
            secret_dir: parent.join("secrets"),
            beacon_plan,
        })
    }

    #[must_use]
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    #[must_use]
    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    #[must_use]
    pub fn beacon_plan(&self) -> Option<BeaconPlan> {
        self.beacon_plan
    }

    #[must_use]
    pub fn secret_dir(&self) -> &FsPath {
        &self.secret_dir
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Token(error) => write!(f, "token error: {error}"),
            Self::Server(error) => write!(f, "server error: {error}"),
            Self::Tls(error) => write!(f, "TLS error: {error}"),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<io::Error> for DaemonError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub trait TokenStore: Send + Sync {
    fn load_or_create(&self) -> io::Result<String>;

    fn remove_legacy_text_stream_receipts(&self) {}
}

#[derive(Clone, Debug)]
pub struct FileTokenStore {
    path: PathBuf,
}

impl FileTokenStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// A token store reserved for the Tailscale-proxied API surface.
    ///
    /// It is intentionally distinct from the localhost client token.
    #[must_use]
    pub fn remote_default() -> Self {
        Self::new(default_remote_token_path())
    }
}

impl Default for FileTokenStore {
    fn default() -> Self {
        Self::new(default_token_path())
    }
}

impl TokenStore for FileTokenStore {
    fn load_or_create(&self) -> io::Result<String> {
        if let Ok(token) = read_token(&self.path) {
            return Ok(token);
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let token = random_token()?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&self.path) {
            Ok(mut file) => {
                file.write_all(token.as_bytes())?;
                file.write_all(b"\n")?;
                file.sync_all()?;
                Ok(token)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_token(&self.path),
            Err(error) => Err(error),
        }
    }

    // Earlier builds kept text-stream metadata (exact lengths, offsets, caller, and timing)
    // in `<token>.text-stream-receipts.v1` beside the token. Nothing writes that file any
    // more; delete a leftover copy on start. Best effort: a failure must not stop the daemon.
    fn remove_legacy_text_stream_receipts(&self) {
        if let Some(name) = self.path.file_name().and_then(|name| name.to_str()) {
            let _ = fs::remove_file(
                self.path
                    .with_file_name(format!("{name}.text-stream-receipts.v1")),
            );
        }
    }
}

fn random_token() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(token, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(token)
}

#[derive(Clone, Debug)]
pub struct MemoryTokenStore {
    token: String,
}

impl MemoryTokenStore {
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl TokenStore for MemoryTokenStore {
    fn load_or_create(&self) -> io::Result<String> {
        Ok(self.token.clone())
    }
}

fn read_token(path: &FsPath) -> io::Result<String> {
    let token = fs::read_to_string(path)?.trim().to_owned();
    if token.len() < 16 || token.chars().any(char::is_whitespace) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local bearer token is malformed",
        ));
    }
    Ok(token)
}

fn default_token_path() -> PathBuf {
    if let Ok(path) = std::env::var("KEYFERRY_TOKEN_FILE") {
        return PathBuf::from(path);
    }
    #[cfg(windows)]
    if let Ok(root) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(root).join("keyferry").join("token");
    }
    #[cfg(target_os = "macos")]
    if let Ok(root) = std::env::var("HOME") {
        return PathBuf::from(root)
            .join("Library")
            .join("Application Support")
            .join("keyferry")
            .join("token");
    }
    if let Ok(root) = std::env::var("XDG_STATE_HOME") {
        return PathBuf::from(root).join("keyferry").join("token");
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("state")
        .join("keyferry")
        .join("token")
}

fn default_remote_token_path() -> PathBuf {
    if let Ok(path) = std::env::var("KEYFERRY_REMOTE_TOKEN_FILE") {
        return PathBuf::from(path);
    }
    default_token_path().parent().map_or_else(
        || PathBuf::from("remote-token"),
        |parent| parent.join("remote-token"),
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Emitted | Self::Aborted | Self::Rejected | Self::Unknown
        )
    }
}

impl From<CommandState> for CommandOutcome {
    fn from(value: CommandState) -> Self {
        match value {
            CommandState::Queued => Self::Queued,
            CommandState::Accepted => Self::Accepted,
            CommandState::Started => Self::Started,
            CommandState::Emitted => Self::Emitted,
            CommandState::Aborted => Self::Aborted,
            CommandState::Rejected => Self::Rejected,
            CommandState::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputTransport {
    UsbHid,
    BleHid,
    Simulator,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventRecord {
    pub command_id: String,
    pub caller: String,
    pub device_id: String,
    pub profile: String,
    pub action_count: usize,
    pub char_count: usize,
    pub timestamp: String,
    pub duration_ms: Option<u64>,
    pub outcome: CommandOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommandResponse {
    pub command_id: String,
    pub device_id: String,
    pub outcome: CommandOutcome,
    pub terminal: bool,
    pub possible_start: bool,
    pub terminal_zero_confirmed: bool,
    pub terminal_release_completed: bool,
    pub output_transport: OutputTransport,
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic_code: Option<&'static str>,
}

fn command_response(
    command_id: Uuid,
    device_id: &str,
    outcome: CommandOutcome,
    observed_start: bool,
    output_transport: OutputTransport,
    message: Option<String>,
) -> CommandResponse {
    command_response_with_diagnostic(
        command_id,
        device_id,
        outcome,
        observed_start,
        output_transport,
        message,
        None,
    )
}

fn command_response_with_diagnostic(
    command_id: Uuid,
    device_id: &str,
    outcome: CommandOutcome,
    observed_start: bool,
    output_transport: OutputTransport,
    message: Option<String>,
    diagnostic: Option<TransportDiagnostic>,
) -> CommandResponse {
    let terminal_release_completed = matches!(
        outcome,
        CommandOutcome::Emitted | CommandOutcome::Aborted | CommandOutcome::Rejected
    );
    CommandResponse {
        command_id: command_id.to_string(),
        device_id: device_id.to_owned(),
        outcome,
        terminal: outcome.is_terminal(),
        possible_start: observed_start || outcome == CommandOutcome::Unknown,
        terminal_zero_confirmed: terminal_release_completed
            && output_transport != OutputTransport::BleHid,
        terminal_release_completed,
        output_transport,
        message,
        diagnostic_code: diagnostic.map(TransportDiagnostic::code),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceView {
    pub id: String,
    pub label: String,
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_path: Option<String>,
    pub link: String,
    /// The owner controller holding the device's session when `link_path` is `tailnet`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    pub mode: String,
    pub armed: bool,
    pub maintenance: bool,
    pub arm_policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware: Option<FirmwareView>,
    pub active_command_id: Option<String>,
    pub active_outcome: Option<CommandOutcome>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FirmwareView {
    pub endpoint: String,
    pub elf_sha256: String,
    pub board_compatibility_id: u32,
    pub protocol_major: u8,
    pub protocol_min_minor: u8,
    pub protocol_max_minor: u8,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileSetEntryView {
    pub name: String,
    pub size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileSetStatusView {
    pub state: &'static str,
    pub size_bytes: u32,
    pub received_bytes: u32,
    pub bundle_size_bytes: u32,
    pub bundle_received_bytes: u32,
    pub max_size_bytes: usize,
    pub files: Vec<FileSetEntryView>,
    pub max_files: usize,
    pub max_name_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileStatusView {
    pub state: &'static str,
    pub size_bytes: u32,
    pub received_bytes: u32,
    pub max_size_bytes: usize,
}

impl From<keyferry_protocol::file::Status> for FileStatusView {
    fn from(status: keyferry_protocol::file::Status) -> Self {
        let state = match status.state {
            keyferry_protocol::file::State::Empty => "empty",
            keyferry_protocol::file::State::Receiving => "receiving",
            keyferry_protocol::file::State::Published => "published",
        };
        Self {
            state,
            size_bytes: status.size,
            received_bytes: status.received,
            max_size_bytes: keyferry_protocol::file::MAX_FILE_BYTES,
        }
    }
}

fn file_status_view(status: keyferry_protocol::file::Status) -> Result<FileStatusView, ApiError> {
    use keyferry_protocol::file::Error;
    match status.error {
        Error::Ok => Ok(status.into()),
        Error::Busy => Err(ApiError::conflict("file.busy")),
        Error::Limit => Err(ApiError::bad_request("file.limit")),
        Error::Order => Err(ApiError::conflict("file.order")),
        Error::Digest => Err(ApiError::rejected("file.digest")),
        Error::Memory => Err(ApiError::unavailable("file.memory")),
        Error::Unavailable => Err(ApiError::unavailable("file.unavailable")),
    }
}

fn file_set_status_error(error: keyferry_protocol::file_set::Error) -> Result<(), ApiError> {
    use keyferry_protocol::file_set::Error;
    match error {
        Error::Ok => Ok(()),
        Error::Busy => Err(ApiError::conflict("file.busy")),
        Error::Limit => Err(ApiError::bad_request("file.limit")),
        Error::Order => Err(ApiError::conflict("file.order")),
        Error::Digest => Err(ApiError::rejected("file.digest")),
        Error::Memory => Err(ApiError::unavailable("file.memory")),
        Error::Unavailable => Err(ApiError::unavailable("file.unavailable")),
    }
}

fn map_file_transport_error(error: TransportError) -> ApiError {
    match error {
        TransportError::AcceptedButLost => ApiError::uncertain("file.outcome_unknown", None),
        other => map_transport_control_error("file request", other),
    }
}

pub const OUTPUT_MODE_SCHEMA_V1: &str = "keyferry.output-mode.v1";
pub const DISPLAY_ORIENTATION_SCHEMA_V1: &str = "keyferry.display-orientation.v1";
pub const SCREEN_POWER_SCHEMA_V1: &str = "keyferry.screen-power.v1";
pub const BLE_HID_BOND_RESET_SCHEMA_V1: &str = "keyferry.ble-hid-bond-reset.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputMode {
    UsbHid,
    BleHid,
}

impl OutputMode {
    pub(crate) const fn to_wire(self) -> u8 {
        match self {
            Self::UsbHid => keyferry_protocol::output_mode::USB_HID,
            Self::BleHid => keyferry_protocol::output_mode::BLE_HID,
        }
    }

    pub(crate) const fn from_wire(value: u8) -> Option<Self> {
        match value {
            keyferry_protocol::output_mode::USB_HID => Some(Self::UsbHid),
            keyferry_protocol::output_mode::BLE_HID => Some(Self::BleHid),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportOutputModeStatus {
    pub active: OutputMode,
    pub stored: OutputMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutputModeStatus {
    pub schema: &'static str,
    pub device_id: String,
    pub active: OutputMode,
    pub stored: OutputMode,
    pub restart_pending: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BleHidBondResetStatus {
    pub schema: &'static str,
    pub device_id: String,
    pub bond_was_present: bool,
    pub restart_pending: bool,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetOutputModeRequest {
    pub mode: OutputMode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DisplayOrientation {
    Normal,
    #[serde(rename = "rotated-180")]
    Rotated180,
}

impl DisplayOrientation {
    pub(crate) const fn to_wire(self) -> u8 {
        match self {
            Self::Normal => keyferry_protocol::display_orientation::NORMAL,
            Self::Rotated180 => keyferry_protocol::display_orientation::ROTATED_180,
        }
    }

    pub(crate) const fn from_wire(value: u8) -> Option<Self> {
        match value {
            keyferry_protocol::display_orientation::NORMAL => Some(Self::Normal),
            keyferry_protocol::display_orientation::ROTATED_180 => Some(Self::Rotated180),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportDisplayOrientationStatus {
    pub active: DisplayOrientation,
    pub stored: DisplayOrientation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DisplayOrientationStatus {
    pub schema: &'static str,
    pub device_id: String,
    pub active: DisplayOrientation,
    pub stored: DisplayOrientation,
    pub restart_pending: bool,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetDisplayOrientationRequest {
    pub orientation: DisplayOrientation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScreenPower {
    Off,
    On,
}

impl ScreenPower {
    pub(crate) const fn to_wire(self) -> u8 {
        match self {
            Self::Off => keyferry_protocol::screen_power::OFF,
            Self::On => keyferry_protocol::screen_power::ON,
        }
    }

    pub(crate) const fn from_wire(value: u8) -> Option<Self> {
        match value {
            keyferry_protocol::screen_power::OFF => Some(Self::Off),
            keyferry_protocol::screen_power::ON => Some(Self::On),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportScreenPowerStatus {
    pub active: ScreenPower,
    pub stored: ScreenPower,
    pub available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScreenPowerStatus {
    pub schema: &'static str,
    pub device_id: String,
    pub active: ScreenPower,
    pub stored: ScreenPower,
    pub available: bool,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetScreenPowerRequest {
    pub power: ScreenPower,
}

#[derive(Clone, Debug, Serialize)]
struct DevicesResponse {
    devices: Vec<DeviceView>,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
struct GatewayProbeResponse {
    protocol_version: u16,
    request_nonce: String,
    gateway_id: String,
    daemon_boot_id: String,
    api_version: u16,
    devices: Vec<GatewayProbeDevice>,
    signature_der: String,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
struct GatewayProbeDevice {
    device_id: String,
    configured_here: bool,
    session_online: bool,
    link_path: String,
    tls_hmac_authenticated: bool,
    protocol_session_id: Option<String>,
    armed: bool,
    arm_mode: String,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
struct RouteProofResponse {
    proof: String,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
struct GatewayYieldResponse {
    device_id: String,
    status: String,
    yield_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareGatewayHandoffRequest {
    transaction_id: Uuid,
    previous_gateway_installation_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartGatewayHandoffRequest {
    transaction_id: Uuid,
    endpoint_session_id: String,
    proof_digest: String,
    readiness_nonce: String,
    target_ipv4: String,
    target_port: u16,
    target_control_port: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartLocalGatewayHandoffRequest {
    transaction_id: Uuid,
    target_installation_id: String,
    previous_installation_id: String,
    target_gateway_address: String,
    readiness_nonce: String,
    target_ipv4: String,
    target_port: u16,
    target_control_port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfirmGatewayHandoffReadyRequest {
    challenge: String,
    readiness_nonce: String,
    proof_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfirmGatewayHandoffReadyResponse {
    transaction_id: Uuid,
    challenge: String,
    readiness_nonce: String,
    proof_digest: String,
    target_installation_id: String,
    listener_generation: u64,
    daemon_boot_id: Uuid,
    remaining_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReportGatewayHandoffOutcomeRequest {
    phase: String,
    reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
struct GatewayHandoffResponse {
    transaction_id: Uuid,
    phase: String,
    terminal: bool,
    target_installation_id: String,
    previous_installation_id: String,
    target_ipv4: Option<String>,
    target_port: Option<u16>,
    target_control_port: Option<u16>,
    readiness_nonce: Option<String>,
    listener_generation: Option<u64>,
    reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ErrorResponse {
    error: String,
    outcome: Option<CommandOutcome>,
    command_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TypeRequest {
    pub text: String,
    #[serde(default = "default_profile", alias = "target_profile")]
    pub profile: String,
    #[serde(default = "default_timing")]
    pub timing: String,
    #[serde(default)]
    pub expires_in_ms: Option<u32>,
    #[serde(default)]
    pub command_id: Option<Uuid>,
}

fn default_profile() -> String {
    "windows-us".to_owned()
}

fn default_timing() -> String {
    "desktop-safe".to_owned()
}

#[derive(Clone, Debug, Deserialize)]
pub struct ActionsRequest {
    pub actions: Vec<ActionRequest>,
    #[serde(default = "default_profile", alias = "target_profile")]
    pub profile: String,
    #[serde(default)]
    pub expires_in_ms: Option<u32>,
    #[serde(default)]
    pub command_id: Option<Uuid>,
}

/// A public typed action. Version 1 accepts only `text`, `tap`, and `chord`,
/// addressed by key NAME. Raw HID usages are an internal representation and are
/// deliberately not accepted here (`docs/api-v1.md`): the host owns the mapping.
/// Unknown fields are rejected so a raw-HID attempt fails loudly.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    #[serde(rename = "type", alias = "kind")]
    pub action_type: String,
    /// Literal text for a `text` action.
    #[serde(default)]
    pub value: Option<String>,
    /// Key name for a `tap` action, e.g. "ENTER".
    #[serde(default)]
    pub key: Option<String>,
    /// Key names for a `chord`: modifiers plus exactly one key, e.g. ["CTRL","L"].
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default = "default_key_down")]
    pub key_down_ms: u16,
    #[serde(default = "default_release_gap")]
    pub release_gap_ms: u16,
}

fn default_key_down() -> u16 {
    TypingTiming::DESKTOP_SAFE.key_down_ms
}

fn default_release_gap() -> u16 {
    TypingTiming::DESKTOP_SAFE.release_gap_ms
}

#[derive(Clone, Debug, Deserialize)]
pub struct ArmRequest {
    #[serde(default = "default_arm_policy")]
    pub policy: String,
    #[serde(default)]
    pub lease_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub struct LeaseRenewRequest {
    pub lease_ms: u32,
}

fn default_arm_policy() -> String {
    "command-scoped".to_owned()
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct CancelRequest {
    pub command_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TextStreamSourceKind {
    Text,
    FileArmor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TextStreamValidation {
    Preflight,
    Incremental,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTextStreamRequest {
    pub schema: String,
    pub epoch: String,
    pub job_id: String,
    pub profile: String,
    pub key_down_ms: u16,
    pub key_gap_ms: u16,
    pub send_after_seconds: u16,
    pub source_kind: TextStreamSourceKind,
    pub validation: TextStreamValidation,
    #[serde(default)]
    pub unsupported: UnsupportedTextPolicy,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextStreamPartRequest {
    pub epoch: String,
    pub child_command_id: String,
    pub source_start: TextStreamCursor,
    #[serde(default)]
    pub source_end: Option<TextStreamCursor>,
    pub text: String,
    pub end_of_input: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextStreamFinishRequest {
    pub epoch: String,
    pub next_index: String,
    pub final_position: TextStreamCursor,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextStreamControlRequest {
    pub epoch: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextStreamCancelRequest {
    pub epoch: String,
    pub reason: TextStreamCancelReason,
    #[serde(default)]
    pub source_error: Option<TextStreamCursor>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TextStreamCancelReason {
    UserCancel,
    ProducerLost,
    SourceInvalid,
    SourceChanged,
    SourceIo,
}

impl TextStreamCancelReason {
    const fn code(self) -> &'static str {
        match self {
            Self::UserCancel => "user_cancel",
            Self::ProducerLost => "producer_lost",
            Self::SourceInvalid => "source_invalid",
            Self::SourceChanged => "source_changed",
            Self::SourceIo => "source_io",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TextStreamCursor {
    pub bytes: String,
    pub scalars: String,
}

impl TextStreamCursor {
    fn from_counts(bytes: u64, scalars: u64) -> Self {
        Self {
            bytes: bytes.to_string(),
            scalars: scalars.to_string(),
        }
    }

    fn counts(&self) -> Result<(u64, u64), ApiError> {
        let bytes = parse_decimal_counter(&self.bytes)?;
        let scalars = parse_decimal_counter(&self.scalars)?;
        Ok((bytes, scalars))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TextStreamPhase {
    Ready,
    Running,
    Stopping,
    Terminal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TextStreamConfirmedPrefix {
    pub bytes: String,
    pub scalars: String,
    pub children: String,
    pub gestures: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TextStreamRange {
    pub start: TextStreamCursor,
    pub end: TextStreamCursor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TextStreamCurrentChild {
    pub index: String,
    pub command_id: String,
    pub outcome: CommandOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TextStreamReceipt {
    pub schema: &'static str,
    pub epoch: String,
    pub job_id: String,
    pub device_id: String,
    pub source_kind: TextStreamSourceKind,
    pub unsupported: UnsupportedTextPolicy,
    pub phase: TextStreamPhase,
    pub outcome: Option<CommandOutcome>,
    pub terminal: bool,
    pub reason: Option<String>,
    pub source_complete: bool,
    pub source_total_bytes: Option<String>,
    pub source_total_scalars: Option<String>,
    pub confirmed_prefix: TextStreamConfirmedPrefix,
    pub uncertain_range: Option<TextStreamRange>,
    pub not_dispatched_from: TextStreamCursor,
    pub next_index: String,
    pub current_child: Option<TextStreamCurrentChild>,
    pub possible_start: bool,
    pub terminal_zero_confirmed: bool,
    pub continuation_allowed: bool,
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TextStreamCapabilities {
    pub schema: &'static str,
    pub epoch: String,
    pub text_stream: &'static str,
    pub child_budget_ms: u16,
    pub source_read_bytes: usize,
    pub lease_ms: u64,
    pub source_idle_ms: u64,
    pub receipt_retention_ms: u64,
}

#[derive(Clone, Debug)]
pub struct PlannedChunk {
    pub steps: Vec<ReportStep>,
    pub expected_ms: u32,
}

#[derive(Clone, Debug)]
pub struct PlannedCommand {
    pub command_id: Uuid,
    pub chunks: Vec<PlannedChunk>,
    pub action_count: usize,
    pub char_count: usize,
    pub profile: String,
    pub expires_at: Instant,
    pub arm_before_first: bool,
    pub input: Option<CompiledInputSequence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationFault {
    None,
    BeforeAccept,
    AcceptedButLost,
    CancelBeforeStart,
    LostAfterStart,
    CancelAfterStart,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    Busy,
    LostBeforeAccept,
    AcceptedButLost,
    ControlRejected,
    NotImplemented,
    Simulation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportOutcome {
    Emitted,
    Aborted,
    Rejected,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProgress {
    Accepted,
    Started,
}

pub type ProgressHandler = Arc<dyn Fn(TransportProgress) + Send + Sync>;

#[derive(Clone, Debug)]
pub struct Cancellation(Arc<std::sync::atomic::AtomicBool>);

impl Cancellation {
    fn new() -> Self {
        Self(Arc::new(std::sync::atomic::AtomicBool::new(false)))
    }

    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
type FileTransportAccess = (Arc<dyn DeviceTransport>, Arc<tokio::sync::Mutex<()>>);

pub trait DeviceTransport: Send + Sync {
    fn is_ready(&self) -> bool {
        true
    }

    fn transport_name(&self) -> &'static str {
        "device"
    }

    fn set_ready_handler(&self, _handler: Arc<dyn Fn() + Send + Sync>) {}

    fn set_fault_handler(&self, _handler: Arc<dyn Fn() + Send + Sync>) {}

    fn take_diagnostic(&self) -> Option<TransportDiagnostic> {
        None
    }

    fn supports_input_sequence(&self) -> bool {
        false
    }

    fn supports_output_mode(&self) -> bool {
        false
    }

    fn supports_display_orientation(&self) -> bool {
        false
    }

    fn supports_screen_power(&self) -> bool {
        false
    }

    fn supports_ble_hid_bond_reset(&self) -> bool {
        false
    }

    fn supports_targeted_gateway_transfer(&self) -> bool {
        false
    }

    fn supports_file_handoff(&self) -> bool {
        false
    }

    fn supports_file_set(&self) -> bool {
        false
    }

    fn file_request<'a>(
        &'a self,
        _request: keyferry_protocol::file::Request,
    ) -> BoxFuture<'a, Result<keyferry_protocol::file::Status, TransportError>> {
        Box::pin(async { Err(TransportError::NotImplemented) })
    }

    fn file_set_request<'a>(
        &'a self,
        _request: keyferry_protocol::file_set::Request,
    ) -> BoxFuture<'a, Result<keyferry_protocol::file_set::Status, TransportError>> {
        Box::pin(async { Err(TransportError::NotImplemented) })
    }

    fn gateway_handoff<'a>(
        &'a self,
        _request: keyferry_protocol::gateway_handoff::Request,
    ) -> BoxFuture<'a, Result<keyferry_protocol::gateway_handoff::Status, TransportError>> {
        Box::pin(async { Err(TransportError::NotImplemented) })
    }

    fn output_transport(&self) -> OutputTransport {
        OutputTransport::UsbHid
    }

    fn output_mode<'a>(
        &'a self,
        _requested: Option<OutputMode>,
    ) -> BoxFuture<'a, Result<TransportOutputModeStatus, TransportError>> {
        Box::pin(async { Err(TransportError::NotImplemented) })
    }

    fn display_orientation<'a>(
        &'a self,
        _requested: Option<DisplayOrientation>,
    ) -> BoxFuture<'a, Result<TransportDisplayOrientationStatus, TransportError>> {
        Box::pin(async { Err(TransportError::NotImplemented) })
    }

    fn screen_power<'a>(
        &'a self,
        _requested: Option<ScreenPower>,
    ) -> BoxFuture<'a, Result<TransportScreenPowerStatus, TransportError>> {
        Box::pin(async { Err(TransportError::NotImplemented) })
    }

    fn reset_ble_hid_bond<'a>(&'a self) -> BoxFuture<'a, Result<(bool, bool), TransportError>> {
        Box::pin(async { Err(TransportError::NotImplemented) })
    }

    fn route_proof<'a>(
        &'a self,
        _controller_installation_id: [u8; 16],
        _controller_nonce: [u8; 32],
    ) -> BoxFuture<'a, Result<keyferry_gateway::SignedRouteProof, TransportError>> {
        Box::pin(async { Err(TransportError::NotImplemented) })
    }

    fn arm<'a>(
        &'a self,
        policy: ArmPolicy,
        lease_ms: u32,
    ) -> BoxFuture<'a, Result<(), TransportError>>;
    fn disarm<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>>;
    fn renew_lease<'a>(&'a self, lease_ms: u32) -> BoxFuture<'a, Result<(), TransportError>>;
    fn accept<'a>(
        &'a self,
        command: &'a PlannedCommand,
    ) -> BoxFuture<'a, Result<(), TransportError>>;
    fn execute<'a>(
        &'a self,
        command: &'a PlannedCommand,
        cancellation: Cancellation,
        progress: ProgressHandler,
    ) -> BoxFuture<'a, TransportOutcome>;
    fn release_all<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>>;

    fn release_input_all<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
        self.release_all()
    }
}

#[derive(Clone, Debug)]
pub struct SimulatorTransport {
    faults: Arc<Mutex<VecDeque<SimulationFault>>>,
    pending_faults: Arc<Mutex<HashMap<Uuid, SimulationFault>>>,
    executions: Arc<Mutex<HashMap<Uuid, usize>>>,
    control: Arc<Mutex<SimulatorControl>>,
    route_proof: Arc<Mutex<Option<keyferry_gateway::SignedRouteProof>>>,
    accept_delay: Duration,
    chunk_delay: Duration,
    input_sequence_supported: bool,
    output_mode: Option<Arc<Mutex<TransportOutputModeStatus>>>,
    display_orientation: Option<Arc<Mutex<TransportDisplayOrientationStatus>>>,
    screen_power: Option<Arc<Mutex<TransportScreenPowerStatus>>>,
    ble_hid_bond: Option<Arc<Mutex<bool>>>,
}

#[derive(Clone, Copy, Debug, Default)]
struct SimulatorControl {
    armed_policy: Option<ArmPolicy>,
    lease_ms: u32,
    arm_requests: usize,
    disarm_requests: usize,
    renewal_requests: usize,
}

impl Default for SimulatorTransport {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl SimulatorTransport {
    #[must_use]
    pub fn new(faults: impl IntoIterator<Item = SimulationFault>) -> Self {
        Self {
            faults: Arc::new(Mutex::new(faults.into_iter().collect())),
            pending_faults: Arc::new(Mutex::new(HashMap::new())),
            executions: Arc::new(Mutex::new(HashMap::new())),
            control: Arc::new(Mutex::new(SimulatorControl::default())),
            route_proof: Arc::new(Mutex::new(None)),
            accept_delay: Duration::ZERO,
            chunk_delay: Duration::ZERO,
            input_sequence_supported: false,
            output_mode: None,
            display_orientation: None,
            screen_power: None,
            ble_hid_bond: None,
        }
    }

    #[must_use]
    pub fn with_accept_delay(mut self, delay: Duration) -> Self {
        self.accept_delay = delay;
        self
    }

    #[must_use]
    pub fn with_chunk_delay(mut self, delay: Duration) -> Self {
        self.chunk_delay = delay;
        self
    }

    #[must_use]
    pub fn with_input_sequence(mut self) -> Self {
        self.input_sequence_supported = true;
        self
    }

    #[must_use]
    pub fn with_output_mode(mut self, mode: OutputMode) -> Self {
        self.output_mode = Some(Arc::new(Mutex::new(TransportOutputModeStatus {
            active: mode,
            stored: mode,
        })));
        self
    }

    #[must_use]
    pub fn with_display_orientation(mut self, orientation: DisplayOrientation) -> Self {
        self.display_orientation = Some(Arc::new(Mutex::new(TransportDisplayOrientationStatus {
            active: orientation,
            stored: orientation,
        })));
        self
    }

    #[must_use]
    pub fn with_screen_power(mut self, power: ScreenPower) -> Self {
        self.screen_power = Some(Arc::new(Mutex::new(TransportScreenPowerStatus {
            active: power,
            stored: power,
            available: true,
        })));
        self
    }

    #[must_use]
    pub fn with_ble_hid_bond(mut self, present: bool) -> Self {
        self.ble_hid_bond = Some(Arc::new(Mutex::new(present)));
        self
    }

    #[must_use]
    pub fn with_route_proof(mut self, proof: keyferry_gateway::SignedRouteProof) -> Self {
        self.route_proof = Arc::new(Mutex::new(Some(proof)));
        self
    }

    #[must_use]
    pub fn execution_count(&self, command_id: Uuid) -> usize {
        self.executions
            .lock()
            .expect("simulator execution lock")
            .get(&command_id)
            .copied()
            .unwrap_or(0)
    }

    #[must_use]
    pub fn is_remotely_armed(&self) -> bool {
        self.control
            .lock()
            .expect("simulator control lock")
            .armed_policy
            .is_some()
    }

    #[must_use]
    pub fn control_request_counts(&self) -> (usize, usize, usize) {
        let control = self.control.lock().expect("simulator control lock");
        (
            control.arm_requests,
            control.disarm_requests,
            control.renewal_requests,
        )
    }

    fn next_fault(&self) -> SimulationFault {
        self.faults
            .lock()
            .expect("simulator fault lock")
            .pop_front()
            .unwrap_or(SimulationFault::None)
    }
}

impl DeviceTransport for SimulatorTransport {
    fn supports_input_sequence(&self) -> bool {
        self.input_sequence_supported
    }

    fn supports_output_mode(&self) -> bool {
        self.output_mode.is_some()
    }

    fn supports_display_orientation(&self) -> bool {
        self.display_orientation.is_some()
    }

    fn supports_screen_power(&self) -> bool {
        self.screen_power.is_some()
    }

    fn supports_ble_hid_bond_reset(&self) -> bool {
        self.ble_hid_bond.is_some()
    }

    fn output_transport(&self) -> OutputTransport {
        self.output_mode
            .as_ref()
            .map_or(OutputTransport::Simulator, |state| {
                match state.lock().expect("simulator output-mode lock").active {
                    OutputMode::UsbHid => OutputTransport::UsbHid,
                    OutputMode::BleHid => OutputTransport::BleHid,
                }
            })
    }

    fn output_mode<'a>(
        &'a self,
        requested: Option<OutputMode>,
    ) -> BoxFuture<'a, Result<TransportOutputModeStatus, TransportError>> {
        Box::pin(async move {
            let state = self
                .output_mode
                .as_ref()
                .ok_or(TransportError::NotImplemented)?;
            let mut state = state.lock().expect("simulator output-mode lock");
            if let Some(mode) = requested {
                state.active = mode;
                state.stored = mode;
            }
            Ok(*state)
        })
    }

    fn display_orientation<'a>(
        &'a self,
        requested: Option<DisplayOrientation>,
    ) -> BoxFuture<'a, Result<TransportDisplayOrientationStatus, TransportError>> {
        Box::pin(async move {
            let state = self
                .display_orientation
                .as_ref()
                .ok_or(TransportError::NotImplemented)?;
            let mut state = state.lock().expect("simulator display-orientation lock");
            if let Some(orientation) = requested {
                state.stored = orientation;
            }
            Ok(*state)
        })
    }

    fn screen_power<'a>(
        &'a self,
        requested: Option<ScreenPower>,
    ) -> BoxFuture<'a, Result<TransportScreenPowerStatus, TransportError>> {
        Box::pin(async move {
            let state = self
                .screen_power
                .as_ref()
                .ok_or(TransportError::NotImplemented)?;
            let mut state = state.lock().expect("simulator screen-power lock");
            if let Some(power) = requested {
                state.active = power;
                state.stored = power;
            }
            Ok(*state)
        })
    }

    fn reset_ble_hid_bond<'a>(&'a self) -> BoxFuture<'a, Result<(bool, bool), TransportError>> {
        Box::pin(async move {
            let bond = self
                .ble_hid_bond
                .as_ref()
                .ok_or(TransportError::NotImplemented)?;
            let mut present = bond.lock().expect("simulator BLE-HID bond lock");
            let was_present = *present;
            *present = false;
            Ok((was_present, true))
        })
    }

    fn route_proof<'a>(
        &'a self,
        controller_installation_id: [u8; 16],
        controller_nonce: [u8; 32],
    ) -> BoxFuture<'a, Result<keyferry_gateway::SignedRouteProof, TransportError>> {
        Box::pin(async move {
            let proof = self
                .route_proof
                .lock()
                .expect("simulator route proof lock")
                .clone()
                .ok_or(TransportError::NotImplemented)?;
            if proof.input.controller_installation_id != controller_installation_id
                || proof.input.controller_nonce != controller_nonce
            {
                return Err(TransportError::ControlRejected);
            }
            Ok(proof)
        })
    }

    fn arm<'a>(
        &'a self,
        policy: ArmPolicy,
        lease_ms: u32,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let valid = match policy {
                ArmPolicy::CommandScoped | ArmPolicy::AlwaysReady => lease_ms == 0,
                ArmPolicy::Temporary => (1..=MAX_TEMPORARY_ARM_MS as u32).contains(&lease_ms),
            };
            if !valid {
                return Err(TransportError::ControlRejected);
            }
            let mut control = self.control.lock().expect("simulator control lock");
            control.armed_policy = Some(policy);
            control.lease_ms = lease_ms;
            control.arm_requests += 1;
            Ok(())
        })
    }

    fn disarm<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let mut control = self.control.lock().expect("simulator control lock");
            control.armed_policy = None;
            control.lease_ms = 0;
            control.disarm_requests += 1;
            Ok(())
        })
    }

    fn renew_lease<'a>(&'a self, lease_ms: u32) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let mut control = self.control.lock().expect("simulator control lock");
            if lease_ms == 0 || control.armed_policy != Some(ArmPolicy::Temporary) {
                return Err(TransportError::ControlRejected);
            }
            control.lease_ms = lease_ms;
            control.renewal_requests += 1;
            Ok(())
        })
    }

    fn accept<'a>(
        &'a self,
        command: &'a PlannedCommand,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            if !self.accept_delay.is_zero() {
                time::sleep(self.accept_delay).await;
            }
            if !command.arm_before_first && !self.is_remotely_armed() {
                return Err(TransportError::ControlRejected);
            }
            match self.next_fault() {
                SimulationFault::BeforeAccept => Err(TransportError::LostBeforeAccept),
                fault @ (SimulationFault::AcceptedButLost
                | SimulationFault::CancelBeforeStart
                | SimulationFault::LostAfterStart
                | SimulationFault::CancelAfterStart) => {
                    self.pending_faults
                        .lock()
                        .expect("simulator pending fault lock")
                        .insert(command.command_id, fault);
                    if fault == SimulationFault::AcceptedButLost {
                        Err(TransportError::AcceptedButLost)
                    } else {
                        Ok(())
                    }
                }
                SimulationFault::None => Ok(()),
            }
        })
    }

    fn execute<'a>(
        &'a self,
        command: &'a PlannedCommand,
        cancellation: Cancellation,
        progress: ProgressHandler,
    ) -> BoxFuture<'a, TransportOutcome> {
        Box::pin(async move {
            {
                let mut control = self.control.lock().expect("simulator control lock");
                if command.arm_before_first {
                    control.armed_policy = Some(ArmPolicy::CommandScoped);
                    control.lease_ms = 0;
                    control.arm_requests += 1;
                }
                if control.armed_policy.is_none() {
                    return TransportOutcome::Rejected;
                }
                if control.armed_policy == Some(ArmPolicy::CommandScoped) {
                    control.armed_policy = None;
                    control.lease_ms = 0;
                }
            }
            let fault = self
                .pending_faults
                .lock()
                .expect("simulator pending fault lock")
                .remove(&command.command_id)
                .unwrap_or(SimulationFault::None);
            progress(TransportProgress::Accepted);
            if matches!(fault, SimulationFault::CancelBeforeStart) {
                return TransportOutcome::Aborted;
            }
            progress(TransportProgress::Started);
            if matches!(fault, SimulationFault::LostAfterStart) {
                self.record_execution(command.command_id);
                return TransportOutcome::Unknown;
            }
            if matches!(fault, SimulationFault::CancelAfterStart) {
                self.record_execution(command.command_id);
                return TransportOutcome::Aborted;
            }

            self.record_execution(command.command_id);
            if let Some(input) = &command.input {
                if execute_input_gestures(&input.gestures, 1).is_err() {
                    self.release_all().await.ok();
                    return TransportOutcome::Aborted;
                }
                if !self.chunk_delay.is_zero() {
                    time::sleep(self.chunk_delay).await;
                }
                return if cancellation.is_cancelled() {
                    self.release_all().await.ok();
                    TransportOutcome::Aborted
                } else {
                    TransportOutcome::Emitted
                };
            }
            for chunk in &command.chunks {
                if cancellation.is_cancelled() {
                    self.release_all().await.ok();
                    return TransportOutcome::Aborted;
                }
                if SimulatedEndpoint::default().execute(&chunk.steps).is_err() {
                    self.release_all().await.ok();
                    return TransportOutcome::Aborted;
                }
                if !self.chunk_delay.is_zero() {
                    time::sleep(self.chunk_delay).await;
                }
            }
            if cancellation.is_cancelled() {
                self.release_all().await.ok();
                TransportOutcome::Aborted
            } else {
                TransportOutcome::Emitted
            }
        })
    }

    fn release_all<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async { Ok(()) })
    }
}

impl SimulatorTransport {
    fn record_execution(&self, command_id: Uuid) {
        self.executions
            .lock()
            .expect("simulator execution lock")
            .entry(command_id)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandFingerprint {
    Keyboard(u64),
    Input([u8; 32]),
}

struct CommandMeta {
    fingerprint: CommandFingerprint,
    response: watch::Sender<CommandOutcome>,
    started_at: Option<Instant>,
    event: Option<EventRecord>,
    cancellation: Cancellation,
    diagnostic: Option<TransportDiagnostic>,
    stream: Option<StreamChildMeta>,
    terminal_at: Option<Instant>,
    output_transport: OutputTransport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StreamChildMeta {
    parent_id: Uuid,
    index: u64,
    start_bytes: u64,
    end_bytes: u64,
    start_scalars: u64,
    end_scalars: u64,
    gestures: u64,
    end_of_input: bool,
}

#[derive(Clone)]
struct TextStreamParent {
    caller: String,
    request: CreateTextStreamRequest,
    phase: TextStreamPhase,
    outcome: Option<CommandOutcome>,
    reason: Option<String>,
    next_index: u64,
    confirmed_bytes: u64,
    confirmed_scalars: u64,
    confirmed_children: u64,
    confirmed_gestures: u64,
    uncertain: Option<TextStreamRange>,
    current: Option<StreamChildMeta>,
    current_command_id: Option<Uuid>,
    current_outcome: Option<CommandOutcome>,
    source_complete: bool,
    total_bytes: Option<u64>,
    total_scalars: Option<u64>,
    possible_start: bool,
    terminal_zero_confirmed: bool,
    lease_deadline: Instant,
    idle_deadline: Instant,
    terminal_at: Option<Instant>,
}

struct WorkItem {
    command: PlannedCommand,
    cancellation: Cancellation,
}

struct DeviceRuntime {
    device_id: String,
    state: DeviceState,
    label: String,
    transport_name: String,
    transport: Arc<dyn DeviceTransport>,
    file_gate: Arc<tokio::sync::Mutex<()>>,
    commands: HashMap<Uuid, CommandMeta>,
    current: Option<Uuid>,
    text_streams: HashMap<Uuid, TextStreamParent>,
    stream_reservation: Option<Uuid>,
    arm_until: Option<Instant>,
    maintenance: bool,
    maintenance_epoch: u64,
    gateway_handoff: Option<GatewayHandoffReservation>,
    outgoing_gateway_handoff: Option<OutgoingGatewayHandoff>,
    work_tx: mpsc::Sender<WorkItem>,
}

#[derive(Clone)]
struct GatewayHandoffReservation {
    transaction_id: Uuid,
    previous_installation_id: [u8; 16],
    target_installation_id: [u8; 16],
    readiness_nonce: [u8; 16],
    target_address: SocketAddr,
    listener_generation: u64,
    target_control_port: u16,
    proof_digest: Option<[u8; 32]>,
    expires_at: Instant,
    phase: String,
    reason: Option<String>,
}

#[derive(Clone)]
struct OutgoingGatewayHandoff {
    transaction_id: Uuid,
    target_installation_id: [u8; 16],
    target_control_address: SocketAddr,
    phase: String,
    reason: Option<String>,
    expires_at: Instant,
}

#[derive(Clone)]
struct DeviceHandle(Arc<Mutex<DeviceRuntime>>);

struct DaemonInner {
    token: String,
    epoch: Uuid,
    devices: HashMap<String, DeviceHandle>,
    #[cfg(test)]
    metadata: Mutex<Vec<EventRecord>>,
    events: broadcast::Sender<EventRecord>,
    gateways: HashMap<String, GatewayAuthority>,
    owner_routes: Mutex<HashMap<(String, [u8; 16]), OwnerRouteLease>>,
    gateway_listeners: GatewayListenerRegistry,
    owner_installation: Mutex<Option<InstallationTlsSecretStore>>,
    owner_control_listener: Mutex<OwnerControlListenerState>,
    forwarder: std::sync::OnceLock<Arc<forward::Forwarder>>,
}

#[derive(Clone, Copy, Default)]
struct OwnerControlListenerState {
    generation: u64,
    address: Option<SocketAddr>,
}

#[derive(Clone, Copy)]
struct OwnerRouteLease {
    endpoint_session_id: [u8; 16],
    proof_digest: [u8; 32],
    expires_at: Instant,
}

struct GatewayAuthority {
    transport: TlsTransport,
    daemon_boot_id: [u8; 16],
}

type DeviceTransportEntry = (
    String,
    String,
    Arc<dyn DeviceTransport>,
    Option<GatewayAuthority>,
);

fn should_capture_diagnostic_events(receiver_count: usize, test_probe: bool) -> bool {
    test_probe || receiver_count != 0
}

#[derive(Clone)]
pub struct Daemon(Arc<DaemonInner>);

#[derive(Clone)]
pub struct RemoteApiPolicy {
    token: String,
}

impl RemoteApiPolicy {
    pub fn new(store: impl TokenStore) -> Result<Self, DaemonError> {
        let token = store
            .load_or_create()
            .map_err(|error| DaemonError::Token(error.to_string()))?;
        if token.len() != 64
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DaemonError::Token(
                "remote bearer token must be exactly 256 bits encoded as lowercase hex".to_owned(),
            ));
        }
        Ok(Self { token })
    }

    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }
}

#[derive(Clone)]
struct RemoteMiddlewareState {
    local_token: String,
    policy: RemoteApiPolicy,
}

#[derive(Clone)]
struct OwnerRemoteMiddlewareState {
    local_token: String,
}

#[derive(Clone, Debug)]
struct RemoteTlsPeer {
    installation_id: [u8; 16],
    address: SocketAddr,
    control_port: u16,
}

struct OwnerTlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    control_port: u16,
}

impl Listener for OwnerTlsListener {
    type Io = ServerTlsStream<tokio::net::TcpStream>;
    type Addr = RemoteTlsPeer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((stream, socket_addr)) = self.listener.accept().await else {
                time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            let Ok(Ok(stream)) =
                time::timeout(Duration::from_secs(10), self.acceptor.accept(stream)).await
            else {
                continue;
            };
            let Some(peer_certificate) = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certificates| certificates.first())
            else {
                continue;
            };
            let Ok(installation_id) =
                tls::installation_id_from_peer_certificate(peer_certificate.as_ref())
            else {
                continue;
            };
            return (
                stream,
                RemoteTlsPeer {
                    installation_id,
                    address: socket_addr,
                    control_port: self.control_port,
                },
            );
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(RemoteTlsPeer {
            // `axum::serve` requires a local address of the listener's address
            // type; it is never attached to an accepted request.
            installation_id: [0; 16],
            address: SocketAddr::from(([127, 0, 0, 1], 0)),
            control_port: self.control_port,
        })
    }
}

impl Connected<IncomingStream<'_, OwnerTlsListener>> for RemoteTlsPeer {
    fn connect_info(stream: IncomingStream<'_, OwnerTlsListener>) -> Self {
        stream.remote_addr().clone()
    }
}

impl Daemon {
    pub fn new(store: impl TokenStore + 'static) -> Result<Self, DaemonError> {
        Self::with_transport(store, Arc::new(SimulatorTransport::default()))
    }

    pub fn with_transport(
        store: impl TokenStore + 'static,
        transport: Arc<dyn DeviceTransport>,
    ) -> Result<Self, DaemonError> {
        Self::with_device_transport(
            store,
            SIMULATOR_DEVICE_ID.to_owned(),
            "Simulator keyboard".to_owned(),
            transport,
        )
    }

    pub fn with_device_transport(
        store: impl TokenStore + 'static,
        device_id: String,
        label: String,
        transport: Arc<dyn DeviceTransport>,
    ) -> Result<Self, DaemonError> {
        Self::with_device_transport_and_gateway(store, device_id, label, transport, None)
    }

    pub fn with_tls_transport(
        store: impl TokenStore + 'static,
        device_id: String,
        label: String,
        transport: TlsTransport,
    ) -> Result<Self, DaemonError> {
        Self::with_tls_transports(store, vec![(device_id, label, transport)])
    }

    pub fn with_tls_transports(
        store: impl TokenStore + 'static,
        devices: Vec<(String, String, TlsTransport)>,
    ) -> Result<Self, DaemonError> {
        if devices.is_empty() || devices.len() > keyferry_gateway::MAX_GATEWAY_DEVICES {
            return Err(DaemonError::Tls(
                "TLS daemon requires between one and eight devices".to_owned(),
            ));
        }
        let mut daemon_boot_id = [0_u8; 16];
        getrandom::fill(&mut daemon_boot_id)
            .map_err(|error| DaemonError::Io(io::Error::other(error.to_string())))?;
        let installation_id = devices[0].2.host_id();
        let mut entries = Vec::with_capacity(devices.len());
        for (device_id, label, transport) in devices {
            let configured_device = Uuid::parse_str(&device_id)
                .map_err(|_| DaemonError::Tls("paired device identifier is invalid".to_owned()))?;
            if configured_device.as_bytes() != &transport.device_id() {
                return Err(DaemonError::Tls(
                    "paired device identifier does not match TLS credentials".to_owned(),
                ));
            }
            if transport.host_id() != installation_id {
                return Err(DaemonError::Tls(
                    "multi-device transports do not share one installation identity".to_owned(),
                ));
            }
            entries.push((
                device_id,
                label,
                Arc::new(transport.clone()) as Arc<dyn DeviceTransport>,
                Some(GatewayAuthority {
                    transport,
                    daemon_boot_id,
                }),
            ));
        }
        Self::with_device_transports_and_gateways(store, entries)
    }

    fn with_device_transport_and_gateway(
        store: impl TokenStore + 'static,
        device_id: String,
        label: String,
        transport: Arc<dyn DeviceTransport>,
        gateway: Option<GatewayAuthority>,
    ) -> Result<Self, DaemonError> {
        Self::with_device_transports_and_gateways(
            store,
            vec![(device_id, label, transport, gateway)],
        )
    }

    fn with_device_transports_and_gateways(
        store: impl TokenStore + 'static,
        entries: Vec<DeviceTransportEntry>,
    ) -> Result<Self, DaemonError> {
        store.remove_legacy_text_stream_receipts();
        let token = store
            .load_or_create()
            .map_err(|error| DaemonError::Token(error.to_string()))?;
        let epoch = Uuid::now_v7();
        let (events, _) = broadcast::channel(256);
        let mut devices = HashMap::with_capacity(entries.len());
        let mut gateways = HashMap::with_capacity(entries.len());
        let mut pending = Vec::with_capacity(entries.len());
        for (device_id, label, transport, gateway) in entries {
            if devices.contains_key(&device_id) {
                return Err(DaemonError::Tls(
                    "multi-device daemon contains a duplicate device".to_owned(),
                ));
            }
            let (work_tx, work_rx) = mpsc::channel(1);
            let mut state = DeviceState::default();
            if transport.is_ready() {
                state.set_link_authenticated();
            }
            let runtime = Arc::new(Mutex::new(DeviceRuntime {
                device_id: device_id.clone(),
                state,
                label,
                transport_name: transport.transport_name().to_owned(),
                transport: transport.clone(),
                file_gate: Arc::new(tokio::sync::Mutex::new(())),
                commands: HashMap::new(),
                current: None,
                text_streams: HashMap::new(),
                stream_reservation: None,
                arm_until: None,
                maintenance: false,
                maintenance_epoch: 0,
                gateway_handoff: None,
                outgoing_gateway_handoff: None,
                work_tx,
            }));
            devices.insert(device_id.clone(), DeviceHandle(Arc::clone(&runtime)));
            if let Some(gateway) = gateway {
                gateways.insert(device_id, gateway);
            }
            pending.push((runtime, transport, work_rx));
        }
        let daemon = Self(Arc::new(DaemonInner {
            token,
            epoch,
            devices,
            #[cfg(test)]
            metadata: Mutex::new(Vec::new()),
            events,
            gateways,
            owner_routes: Mutex::new(HashMap::new()),
            gateway_listeners: GatewayListenerRegistry::default(),
            owner_installation: Mutex::new(None),
            owner_control_listener: Mutex::new(OwnerControlListenerState::default()),
            forwarder: std::sync::OnceLock::new(),
        }));
        for (runtime, transport, work_rx) in pending {
            let weak_daemon = Arc::downgrade(&daemon.0);
            let ready_runtime = Arc::clone(&runtime);
            transport.set_ready_handler(Arc::new(move || {
                if let Some(inner) = weak_daemon.upgrade() {
                    let daemon = Daemon(inner);
                    daemon.mark_transport_ready(&ready_runtime);
                }
            }));
            let weak_daemon = Arc::downgrade(&daemon.0);
            let fault_runtime = Arc::clone(&runtime);
            transport.set_fault_handler(Arc::new(move || {
                if let Some(inner) = weak_daemon.upgrade() {
                    let daemon = Daemon(inner);
                    daemon.mark_transport_disconnected(&fault_runtime);
                }
            }));
            daemon.spawn_worker(Arc::clone(&runtime), work_rx);
            daemon.spawn_stream_supervisor(Arc::clone(&runtime));
            daemon.spawn_gateway_handoff_supervisor(runtime);
        }
        Ok(daemon)
    }

    #[must_use]
    pub fn token(&self) -> &str {
        &self.0.token
    }

    #[must_use]
    pub fn gateway_listener_registry(&self) -> GatewayListenerRegistry {
        self.0.gateway_listeners.clone()
    }

    fn gateway(&self, device_id: &str) -> Option<&GatewayAuthority> {
        self.0.gateways.get(device_id)
    }

    fn configure_owner_remote_installation(
        &self,
        installation: &InstallationTlsSecretStore,
    ) -> Result<(), DaemonError> {
        if self
            .0
            .gateways
            .values()
            .any(|gateway| gateway.transport.host_id() != installation.installation_id())
        {
            return Err(DaemonError::Tls(
                "owner-control identity does not match the gateway installation".to_owned(),
            ));
        }
        *self
            .0
            .owner_installation
            .lock()
            .expect("owner installation lock") = Some(installation.clone());
        Ok(())
    }

    /// Lets the loopback API reach a configured device through the owner controller that holds
    /// it on the tailnet whenever this computer has no authenticated local link to it.
    pub fn enable_tailnet_forwarding(
        &self,
        stores: &InstallationTlsSecretSet,
    ) -> Result<(), DaemonError> {
        self.enable_forwarding(forward::Forwarder::new(
            stores,
            Box::new(forward::TailscalePeers),
        )?)
    }

    fn enable_forwarding(&self, forwarder: forward::Forwarder) -> Result<(), DaemonError> {
        if forwarder
            .device_ids()
            .any(|id| !self.0.devices.contains_key(id))
        {
            return Err(DaemonError::Tls(
                "forwarding credentials name a device this daemon does not configure".to_owned(),
            ));
        }
        self.0
            .forwarder
            .set(Arc::new(forwarder))
            .map_err(|_| DaemonError::Tls("tailnet forwarding is already enabled".to_owned()))
    }

    fn forwarder(&self) -> Option<Arc<forward::Forwarder>> {
        self.0.forwarder.get().cloned()
    }

    fn local_link_authenticated(&self, id: &str) -> bool {
        self.0.devices.get(id).is_some_and(|handle| {
            handle.0.lock().expect("device runtime lock").state.link
                == keyferry_core::LinkState::Authenticated
        })
    }

    fn knows_command(&self, id: &str, command_id: Uuid) -> bool {
        self.0.devices.get(id).is_some_and(|handle| {
            handle
                .0
                .lock()
                .expect("device runtime lock")
                .commands
                .contains_key(&command_id)
        })
    }

    fn knows_text_stream(&self, id: &str, job_id: Uuid) -> bool {
        self.0.devices.get(id).is_some_and(|handle| {
            handle
                .0
                .lock()
                .expect("device runtime lock")
                .text_streams
                .contains_key(&job_id)
        })
    }

    pub fn router(&self) -> Router {
        Self::base_routes()
            .route(
                "/v1/devices/{id}/maintenance/begin",
                post(begin_maintenance),
            )
            .route(
                "/v1/devices/{id}/maintenance/finish",
                post(finish_maintenance),
            )
            .route(
                "/v1/devices/{id}/gateway/outgoing-handoff",
                post(start_local_gateway_handoff),
            )
            .with_state(self.clone())
            .layer(middleware::from_fn_with_state(
                self.clone(),
                forward::local_forwarding,
            ))
    }

    fn base_routes() -> Router<Daemon> {
        Router::new()
            .route("/v1/capabilities", get(capabilities))
            .route("/v1/gateway/probe", get(gateway_probe))
            .route("/v1/devices", get(list_devices))
            .route("/v1/devices/{id}", get(get_device))
            .route(
                "/v1/devices/{id}/file",
                get(get_file)
                    .post(post_file)
                    .delete(clear_file)
                    .layer(DefaultBodyLimit::max(MAX_FILE_REQUEST_BODY)),
            )
            .route(
                "/v1/devices/{id}/files",
                get(get_files)
                    .post(post_files)
                    .delete(clear_files)
                    .layer(DefaultBodyLimit::max(MAX_FILE_SET_REQUEST_BODY)),
            )
            .route(
                "/v1/devices/{id}/gateway/handoffs",
                post(prepare_gateway_handoff),
            )
            .route(
                "/v1/devices/{id}/gateway/handoffs/{transaction_id}",
                get(get_gateway_handoff).post(cancel_gateway_handoff_reservation),
            )
            .route(
                "/v1/devices/{id}/output-mode",
                get(get_output_mode).post(set_output_mode),
            )
            .route(
                "/v1/devices/{id}/display-orientation",
                get(get_display_orientation).post(set_display_orientation),
            )
            .route(
                "/v1/devices/{id}/screen-power",
                get(get_screen_power).post(set_screen_power),
            )
            .route(
                "/v1/devices/{id}/ble-hid-bond/reset",
                post(reset_ble_hid_bond),
            )
            .route("/v1/devices/{id}/commands/{command_id}", get(get_command))
            .route("/v1/events", get(events))
            .route("/v1/devices/{id}/type", post(type_text))
            .route("/v1/devices/{id}/actions", post(actions))
            .route(
                "/v1/devices/{id}/sequences",
                post(sequence).layer(DefaultBodyLimit::max(MAX_SEQUENCE_REQUEST_BODY)),
            )
            .route(
                "/v1/devices/{id}/input-sequences",
                post(input_sequence).layer(DefaultBodyLimit::max(MAX_SEQUENCE_REQUEST_BODY)),
            )
            .route(
                "/v1/devices/{id}/text-streams",
                post(create_text_stream).layer(DefaultBodyLimit::max(MAX_TEXT_STREAM_PART_BODY)),
            )
            .route(
                "/v1/devices/{id}/text-streams/{job_id}/parts/{index}",
                post(text_stream_part).layer(DefaultBodyLimit::max(MAX_TEXT_STREAM_PART_BODY)),
            )
            .route(
                "/v1/devices/{id}/text-streams/{job_id}/finish",
                post(finish_text_stream).layer(DefaultBodyLimit::max(MAX_TEXT_STREAM_PART_BODY)),
            )
            .route(
                "/v1/devices/{id}/text-streams/{job_id}",
                get(get_text_stream),
            )
            .route(
                "/v1/devices/{id}/text-streams/{job_id}/lease",
                post(renew_text_stream).layer(DefaultBodyLimit::max(MAX_TEXT_STREAM_PART_BODY)),
            )
            .route(
                "/v1/devices/{id}/text-streams/{job_id}/cancel",
                post(cancel_text_stream).layer(DefaultBodyLimit::max(MAX_TEXT_STREAM_PART_BODY)),
            )
            .route("/v1/devices/{id}/arm", post(arm))
            .route("/v1/devices/{id}/arm/renew", post(renew_arm_lease))
            .route("/v1/devices/{id}/disarm", post(disarm))
            .route("/v1/devices/{id}/cancel", post(cancel))
    }

    pub fn remote_router(&self, policy: RemoteApiPolicy) -> Result<Router, DaemonError> {
        if secure_token_equal(self.token(), policy.token()) {
            return Err(DaemonError::Tls(
                "remote and local bearer tokens must be distinct".to_owned(),
            ));
        }
        let middleware_state = RemoteMiddlewareState {
            local_token: self.token().to_owned(),
            policy,
        };
        Ok(Self::base_routes()
            .with_state(self.clone())
            .layer(middleware::from_fn_with_state(
                middleware_state,
                authorize_remote_request,
            )))
    }

    fn owner_remote_router(&self) -> Router {
        let middleware_state = OwnerRemoteMiddlewareState {
            local_token: self.token().to_owned(),
        };
        Self::base_routes()
            .route("/v2/devices/{id}/route-proof", get(route_proof))
            .route(
                "/v2/devices/{id}/gateway/handoffs",
                post(start_gateway_handoff),
            )
            .route(
                "/v2/devices/{id}/gateway/handoffs/{transaction_id}/ready",
                post(confirm_gateway_handoff_ready),
            )
            .route(
                "/v2/devices/{id}/gateway/handoffs/{transaction_id}/outcome",
                post(receive_gateway_handoff_outcome),
            )
            .route("/v2/devices/{id}/gateway/yield", post(yield_gateway))
            .with_state(self.clone())
            .layer(middleware::from_fn_with_state(
                middleware_state,
                authorize_owner_remote_request,
            ))
    }

    fn spawn_worker(
        &self,
        runtime: Arc<Mutex<DeviceRuntime>>,
        mut work_rx: mpsc::Receiver<WorkItem>,
    ) {
        let daemon = self.clone();
        tokio::spawn(async move {
            while let Some(work) = work_rx.recv().await {
                daemon.run_work(runtime.clone(), work).await;
            }
        });
    }

    fn spawn_stream_supervisor(&self, runtime: Arc<Mutex<DeviceRuntime>>) {
        let weak_daemon = Arc::downgrade(&self.0);
        tokio::spawn(async move {
            loop {
                time::sleep(Duration::from_secs(1)).await;
                if weak_daemon.upgrade().is_none() {
                    return;
                }
                let mut device = runtime.lock().expect("device runtime lock");
                let Some(job_id) = device.stream_reservation else {
                    prune_text_stream_records(&mut device);
                    continue;
                };
                let now = Instant::now();
                let Some(parent) = device.text_streams.get_mut(&job_id) else {
                    device.stream_reservation = None;
                    continue;
                };
                let lease_expired = now >= parent.lease_deadline;
                let source_idle = parent.current.is_none() && now >= parent.idle_deadline;
                if !lease_expired && !source_idle {
                    continue;
                }
                let reason = if lease_expired {
                    "producer_lease_expired"
                } else {
                    "source_idle"
                };
                if let Some(command_id) = parent.current_command_id {
                    parent.phase = TextStreamPhase::Stopping;
                    parent.reason = Some(reason.to_owned());
                    if let Some(command) = device.commands.get(&command_id) {
                        command.cancellation.cancel();
                    }
                } else {
                    finish_idle_stream(&mut device, job_id, reason);
                }
            }
        });
    }

    fn spawn_gateway_handoff_supervisor(&self, runtime: Arc<Mutex<DeviceRuntime>>) {
        let weak_daemon = Arc::downgrade(&self.0);
        tokio::spawn(async move {
            loop {
                time::sleep(Duration::from_secs(1)).await;
                let Some(inner) = weak_daemon.upgrade() else {
                    return;
                };
                let daemon = Daemon(inner);
                let (cancel_reservation, device_id) = {
                    let mut device = runtime.lock().expect("device runtime lock");
                    let Some(reservation) = device.gateway_handoff.as_mut() else {
                        continue;
                    };
                    if Instant::now() < reservation.expires_at
                        || matches!(
                            reservation.phase.as_str(),
                            "transferred"
                                | "failed_restored"
                                | "failed_unchanged"
                                | "recovery_unavailable"
                                | "uncertain"
                        )
                    {
                        continue;
                    }
                    let never_connected =
                        matches!(reservation.phase.as_str(), "ready" | "confirmed_ready");
                    reservation.phase = if never_connected {
                        "failed_unchanged".to_owned()
                    } else {
                        "uncertain".to_owned()
                    };
                    reservation.reason = Some("readiness_expired".to_owned());
                    (never_connected, device.device_id.clone())
                };
                if cancel_reservation {
                    if let Some(gateway) = daemon.gateway(&device_id) {
                        gateway.transport.cancel_gateway_handoff_candidate();
                    }
                }
            }
        });
    }

    fn mark_transport_ready(&self, runtime: &Arc<Mutex<DeviceRuntime>>) {
        let ready_device_id = runtime
            .lock()
            .expect("device runtime lock")
            .device_id
            .clone();
        self.0
            .owner_routes
            .lock()
            .expect("owner route lock")
            .retain(|(device_id, _), _| device_id != &ready_device_id);
        let (should_accept_handoff, handoff_pending, outgoing_pending) = {
            let mut device = runtime.lock().expect("device runtime lock");
            let handoff_pending = device.gateway_handoff.as_ref().is_some_and(|reservation| {
                !gateway_handoff_phase_is_terminal(&reservation.phase)
                    && Instant::now() < reservation.expires_at
            });
            let outgoing_pending =
                device
                    .outgoing_gateway_handoff
                    .as_ref()
                    .is_some_and(|handoff| {
                        !gateway_handoff_phase_is_terminal(&handoff.phase)
                            && Instant::now() < handoff.expires_at
                    });
            let should_accept = device.gateway_handoff.as_mut().is_some_and(|reservation| {
                if matches!(reservation.phase.as_str(), "ready" | "confirmed_ready")
                    && reservation.proof_digest.is_some()
                    && Instant::now() < reservation.expires_at
                {
                    reservation.phase = "accepting".to_owned();
                    true
                } else {
                    false
                }
            });
            // A connection that arrives while a target reservation is not yet
            // fully bound must never become ordinary command authority. The
            // endpoint will either complete the correlated handoff or its
            // bounded recovery path; until then this daemon stays fail-closed.
            if !should_accept && !handoff_pending && !outgoing_pending {
                device.state.set_link_authenticated();
                device.arm_until = None;
            }
            (should_accept, handoff_pending, outgoing_pending)
        };
        if should_accept_handoff {
            let daemon = self.clone();
            let runtime = Arc::clone(runtime);
            tokio::spawn(async move {
                daemon.complete_target_gateway_handoff(runtime).await;
            });
        } else if outgoing_pending {
            let daemon = self.clone();
            let runtime = Arc::clone(runtime);
            tokio::spawn(async move {
                daemon.reconcile_previous_gateway_handoff(runtime).await;
            });
        } else if handoff_pending {
            self.mark_transport_disconnected(runtime);
        }
    }

    async fn reconcile_previous_gateway_handoff(&self, runtime: Arc<Mutex<DeviceRuntime>>) {
        let (transaction_id, target_installation_id, target_control_address, device_id) = {
            let device = runtime.lock().expect("device runtime lock");
            let Some(handoff) = device.outgoing_gateway_handoff.as_ref() else {
                return;
            };
            (
                handoff.transaction_id,
                handoff.target_installation_id,
                handoff.target_control_address,
                device.device_id.clone(),
            )
        };
        let Some(gateway) = self.gateway(&device_id) else {
            return;
        };
        let query = keyferry_protocol::gateway_handoff::Request::Query(
            keyferry_protocol::gateway_handoff::Query {
                transaction_id: *transaction_id.as_bytes(),
            },
        );
        let result = gateway.transport.gateway_handoff_request(query).await;
        let (phase, reason, recovered_here) = match result {
            Ok(status) if status.phase == keyferry_protocol::gateway_handoff_phase::RESTORED => (
                "failed_restored".to_owned(),
                endpoint_handoff_reason(&status),
                true,
            ),
            Ok(status) if status.phase == keyferry_protocol::gateway_handoff_phase::NOT_STARTED => {
                (
                    "failed_unchanged".to_owned(),
                    endpoint_handoff_reason(&status),
                    true,
                )
            }
            Ok(status)
                if status.phase
                    == keyferry_protocol::gateway_handoff_phase::RECOVERY_UNAVAILABLE =>
            {
                (
                    "recovery_unavailable".to_owned(),
                    endpoint_handoff_reason(&status),
                    false,
                )
            }
            Ok(status) => (
                "uncertain".to_owned(),
                Some(format!("endpoint_phase_{}", status.phase)),
                false,
            ),
            Err(_) => (
                "uncertain".to_owned(),
                Some("rollback_status_unresolved".to_owned()),
                false,
            ),
        };
        {
            let mut device = runtime.lock().expect("device runtime lock");
            let Some(handoff) = device.outgoing_gateway_handoff.as_mut() else {
                return;
            };
            if handoff.transaction_id != transaction_id
                || handoff.target_installation_id != target_installation_id
            {
                return;
            }
            handoff.phase.clone_from(&phase);
            handoff.reason.clone_from(&reason);
            if recovered_here {
                device.state.set_link_authenticated();
                device.arm_until = None;
            }
        }
        let device_id = runtime
            .lock()
            .expect("device runtime lock")
            .device_id
            .clone();
        let _ = report_gateway_handoff_outcome(
            self,
            &device_id,
            transaction_id,
            target_installation_id,
            target_control_address,
            &phase,
            reason.as_deref(),
        )
        .await;
    }

    async fn complete_target_gateway_handoff(&self, runtime: Arc<Mutex<DeviceRuntime>>) {
        let (
            transaction_id,
            readiness_nonce,
            expected_proof_digest,
            listener_generation,
            device_id,
        ) = {
            let device = runtime.lock().expect("device runtime lock");
            let Some(reservation) = device.gateway_handoff.as_ref() else {
                return;
            };
            let Some(proof_digest) = reservation.proof_digest else {
                return;
            };
            (
                reservation.transaction_id,
                reservation.readiness_nonce,
                proof_digest,
                reservation.listener_generation,
                device.device_id.clone(),
            )
        };
        let Some(gateway) = self.gateway(&device_id) else {
            return;
        };
        let listener = self.0.gateway_listeners.snapshot();
        let owner_control = *self
            .0
            .owner_control_listener
            .lock()
            .expect("owner control listener lock");
        let listener_still_ready = {
            let device = runtime.lock().expect("device runtime lock");
            device.gateway_handoff.as_ref().is_some_and(|reservation| {
                reservation.transaction_id == transaction_id
                    && reservation.proof_digest == Some(expected_proof_digest)
                    && listener.generation == listener_generation
                    && listener.addresses.contains(&reservation.target_address)
                    && owner_control.address.map(|address| address.port())
                        == Some(reservation.target_control_port)
                    && Instant::now() < reservation.expires_at
            })
        };
        if !listener_still_ready {
            self.finish_target_gateway_handoff(
                &runtime,
                "uncertain",
                Some("listener_generation_changed".to_owned()),
                false,
            );
            return;
        }
        let mut controller_nonce = [0_u8; 32];
        if getrandom::fill(&mut controller_nonce).is_err()
            || controller_nonce.iter().all(|byte| *byte == 0)
        {
            self.finish_target_gateway_handoff(
                &runtime,
                "uncertain",
                Some("route_nonce_generation_failed".to_owned()),
                false,
            );
            return;
        }
        let proof = match gateway
            .transport
            .route_proof(gateway.transport.host_id(), controller_nonce)
            .await
        {
            Ok(proof) => proof,
            Err(_) => {
                self.finish_target_gateway_handoff(
                    &runtime,
                    "uncertain",
                    Some("target_route_proof_failed".to_owned()),
                    false,
                );
                return;
            }
        };
        let proof_bytes =
            match keyferry_gateway::encode_route_proof_response(&proof.input, &proof.tag) {
                Ok(bytes) => bytes,
                Err(_) => {
                    self.finish_target_gateway_handoff(
                        &runtime,
                        "uncertain",
                        Some("target_route_proof_invalid".to_owned()),
                        false,
                    );
                    return;
                }
            };
        let proof_digest: [u8; 32] = Sha256::digest(proof_bytes).into();
        let request = keyferry_protocol::gateway_handoff::Request::Accept(
            keyferry_protocol::gateway_handoff::Accept {
                transaction_id: *transaction_id.as_bytes(),
                readiness_nonce,
                proof_digest,
            },
        );
        match gateway.transport.gateway_handoff_request(request).await {
            Ok(status) if status.phase == keyferry_protocol::gateway_handoff_phase::TRANSFERRED => {
                self.finish_target_gateway_handoff(&runtime, "transferred", None, true);
            }
            Ok(status) => self.finish_target_gateway_handoff(
                &runtime,
                "uncertain",
                Some(format!("endpoint_phase_{}", status.phase)),
                false,
            ),
            Err(_) => self.finish_target_gateway_handoff(
                &runtime,
                "uncertain",
                Some("target_acceptance_unresolved".to_owned()),
                false,
            ),
        }
    }

    fn finish_target_gateway_handoff(
        &self,
        runtime: &Arc<Mutex<DeviceRuntime>>,
        phase: &str,
        reason: Option<String>,
        authenticated: bool,
    ) {
        let mut device = runtime.lock().expect("device runtime lock");
        if let Some(reservation) = device.gateway_handoff.as_mut() {
            reservation.phase = phase.to_owned();
            reservation.reason = reason;
        }
        if authenticated {
            device.state.set_link_authenticated();
            device.arm_until = None;
        }
    }

    fn diagnostic_events_requested(&self) -> bool {
        should_capture_diagnostic_events(self.0.events.receiver_count(), cfg!(test))
    }

    fn publish_event(&self, record: Option<EventRecord>) {
        let Some(record) = record else { return };
        #[cfg(test)]
        self.0
            .metadata
            .lock()
            .expect("metadata event lock")
            .push(record.clone());
        let _ = self.0.events.send(record);
    }

    fn mark_transport_disconnected(&self, runtime: &Arc<Mutex<DeviceRuntime>>) {
        let disconnected_device_id = runtime
            .lock()
            .expect("device runtime lock")
            .device_id
            .clone();
        self.0
            .owner_routes
            .lock()
            .expect("owner route lock")
            .retain(|(device_id, _), _| device_id != &disconnected_device_id);
        let active = {
            let mut device = runtime.lock().expect("device runtime lock");
            for command in device.commands.values() {
                if !(*command.response.borrow()).is_terminal() {
                    command.cancellation.cancel();
                }
            }
            let active = device.state.disconnect();
            device.current = None;
            device.arm_until = None;
            match active {
                Some(active) => {
                    let diagnostic = device.transport.take_diagnostic();
                    let command_id = Uuid::from_bytes(active.command_id);
                    let next = match active.state {
                        CommandState::Queued => CommandOutcome::Rejected,
                        CommandState::Accepted | CommandState::Started => CommandOutcome::Unknown,
                        CommandState::Emitted => CommandOutcome::Emitted,
                        CommandState::Aborted => CommandOutcome::Aborted,
                        CommandState::Rejected => CommandOutcome::Rejected,
                        CommandState::Unknown => CommandOutcome::Unknown,
                    };
                    if let Some(meta) = device.commands.get_mut(&command_id) {
                        if let Some(diagnostic) = diagnostic {
                            meta.diagnostic.get_or_insert(diagnostic);
                        }
                    }
                    Some((command_id, next))
                }
                None => None,
            }
        };
        if let Some((command_id, next)) = active {
            self.apply_terminal_transition(runtime, command_id, next, true);
        } else {
            let mut device = runtime.lock().expect("device runtime lock");
            let Some(job_id) = device.stream_reservation else {
                return;
            };
            let Some(parent) = device.text_streams.get_mut(&job_id) else {
                device.stream_reservation = None;
                return;
            };
            if parent.current.is_some() {
                parent.phase = TextStreamPhase::Stopping;
                parent.reason = Some("transport_disconnected".to_owned());
            } else {
                finish_idle_stream(&mut device, job_id, "transport_disconnected");
            }
        }
    }

    async fn run_work(&self, runtime: Arc<Mutex<DeviceRuntime>>, work: WorkItem) {
        if Instant::now() >= work.command.expires_at || work.cancellation.is_cancelled() {
            self.transition_terminal(
                &runtime,
                work.command.command_id,
                if work.cancellation.is_cancelled() {
                    CommandOutcome::Aborted
                } else {
                    CommandOutcome::Rejected
                },
            );
            return;
        }

        let transport = runtime
            .lock()
            .expect("device runtime lock")
            .transport
            .clone();
        match transport.accept(&work.command).await {
            Ok(()) => {
                if work.cancellation.is_cancelled() || Instant::now() >= work.command.expires_at {
                    release_for_command(&transport, &work.command).await.ok();
                    self.transition_terminal(
                        &runtime,
                        work.command.command_id,
                        if work.cancellation.is_cancelled() {
                            CommandOutcome::Aborted
                        } else {
                            CommandOutcome::Rejected
                        },
                    );
                    return;
                }
                // Transport readiness is only a preflight. The endpoint's
                // COMMAND_RESULT is the authority for ACCEPTED and STARTED.
            }
            Err(TransportError::AcceptedButLost) => {
                release_for_command(&transport, &work.command).await.ok();
                self.transition_terminal(
                    &runtime,
                    work.command.command_id,
                    CommandOutcome::Unknown,
                );
                return;
            }
            Err(
                TransportError::LostBeforeAccept
                | TransportError::ControlRejected
                | TransportError::NotImplemented
                | TransportError::Busy,
            ) => {
                self.transition_terminal(
                    &runtime,
                    work.command.command_id,
                    CommandOutcome::Rejected,
                );
                return;
            }
            Err(TransportError::Simulation) => {
                self.transition_terminal(
                    &runtime,
                    work.command.command_id,
                    CommandOutcome::Rejected,
                );
                return;
            }
        }

        if work.cancellation.is_cancelled() || Instant::now() >= work.command.expires_at {
            release_for_command(&transport, &work.command).await.ok();
            self.transition_terminal(&runtime, work.command.command_id, CommandOutcome::Aborted);
            return;
        }
        let progress_daemon = self.clone();
        let progress_runtime = runtime.clone();
        let command_id = work.command.command_id;
        let (accepted_tx, accepted_rx) = watch::channel(false);
        let ever_accepted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let progress_accepted = Arc::clone(&ever_accepted);
        let progress: ProgressHandler = Arc::new(move |event| {
            if event == TransportProgress::Accepted {
                progress_accepted.store(true, std::sync::atomic::Ordering::Release);
                accepted_tx.send_replace(true);
            }
            progress_daemon.transition_progress(
                &progress_runtime,
                command_id,
                match event {
                    TransportProgress::Accepted => CommandOutcome::Accepted,
                    TransportProgress::Started => CommandOutcome::Started,
                },
            );
        });
        let execution = transport.execute(&work.command, work.cancellation.clone(), progress);
        tokio::pin!(execution);
        let deadline = command_deadline(
            work.command.expires_at,
            Duration::from_millis(MAX_SEQUENCE_EXECUTION_MS),
            accepted_rx,
        );
        tokio::pin!(deadline);
        let mut outcome = tokio::select! {
            outcome = &mut execution => outcome,
            deadline = &mut deadline => {
                work.cancellation.cancel();
                match time::timeout(COMMAND_RECOVERY_TIMEOUT, &mut execution).await {
                    Ok(TransportOutcome::Unknown) => TransportOutcome::Unknown,
                    Ok(_) => deadline.recovered_outcome(
                        ever_accepted.load(std::sync::atomic::Ordering::Acquire)
                    ),
                    Err(_) => match time::timeout(
                        COMMAND_RECOVERY_TIMEOUT,
                        release_for_command(&transport, &work.command),
                    ).await {
                        Ok(Ok(())) => deadline.recovered_outcome(
                            ever_accepted.load(std::sync::atomic::Ordering::Acquire)
                        ),
                        Ok(Err(_)) | Err(_) => TransportOutcome::Unknown,
                    },
                }
            }
        };
        // A transport ABORTED result already includes terminal-zero evidence;
        // only UNKNOWN needs a separate release recovery attempt.
        if outcome == TransportOutcome::Unknown {
            let terminal_zero_confirmed =
                release_for_command(&transport, &work.command).await.is_ok();
            outcome = reduce_after_release(
                outcome,
                work.cancellation.is_cancelled(),
                terminal_zero_confirmed,
            );
        }
        if let Some(diagnostic) = transport.take_diagnostic() {
            let mut device = runtime.lock().expect("device runtime lock");
            if let Some(command) = device.commands.get_mut(&work.command.command_id) {
                command.diagnostic.get_or_insert(diagnostic);
            }
        }
        self.transition_terminal(
            &runtime,
            work.command.command_id,
            match outcome {
                TransportOutcome::Emitted => CommandOutcome::Emitted,
                TransportOutcome::Aborted => CommandOutcome::Aborted,
                TransportOutcome::Rejected => CommandOutcome::Rejected,
                TransportOutcome::Unknown => CommandOutcome::Unknown,
            },
        );
    }

    fn transition_progress(
        &self,
        runtime: &Arc<Mutex<DeviceRuntime>>,
        command_id: Uuid,
        next: CommandOutcome,
    ) {
        debug_assert!(!next.is_terminal());
        let record = {
            let mut device = runtime.lock().expect("device runtime lock");
            if device.state.active.is_none() {
                return;
            }
            let core_next = core_state(next);
            if device.state.transition(core_next).is_err() {
                return;
            }
            let started_at = if core_next == CommandState::Started {
                let started = Instant::now();
                if let Some(meta) = device.commands.get_mut(&command_id) {
                    meta.started_at = Some(started);
                }
                Some(started)
            } else {
                device
                    .commands
                    .get(&command_id)
                    .and_then(|meta| meta.started_at)
            };
            let (record, stream) = {
                let Some(meta) = device.commands.get_mut(&command_id) else {
                    return;
                };
                // send() fails when no receiver is currently subscribed, which would
                // silently discard a terminal outcome for anyone who asks later.
                // send_replace always stores it, so late subscribers see the result.
                meta.response.send_replace(next);
                let record = meta.event.as_mut().map(|record| {
                    record.timestamp = timestamp_now();
                    record.outcome = next;
                    record.duration_ms =
                        started_at.map(|started| started.elapsed().as_millis() as u64);
                    record.clone()
                });
                (record, meta.stream.clone())
            };
            if let Some(stream) = stream.as_ref() {
                if let Some(parent) = device.text_streams.get_mut(&stream.parent_id) {
                    parent.current_outcome = Some(next);
                    if matches!(next, CommandOutcome::Started | CommandOutcome::Emitted) {
                        parent.possible_start = true;
                    }
                }
            }
            record
        };
        self.publish_event(record);
    }

    fn transition_terminal(
        &self,
        runtime: &Arc<Mutex<DeviceRuntime>>,
        command_id: Uuid,
        next: CommandOutcome,
    ) {
        debug_assert!(next.is_terminal());
        self.apply_terminal_transition(runtime, command_id, next, false);
    }

    fn apply_terminal_transition(
        &self,
        runtime: &Arc<Mutex<DeviceRuntime>>,
        command_id: Uuid,
        next: CommandOutcome,
        state_already_finished: bool,
    ) {
        let record = {
            let mut device = runtime.lock().expect("device runtime lock");
            if !state_already_finished {
                if device.state.active.is_none()
                    || device.state.transition(core_state(next)).is_err()
                {
                    return;
                }
                device.current = None;
                let _ = device.state.finish();
            }
            let Some(meta) = device.commands.get(&command_id) else {
                return;
            };
            let started_at = meta.started_at;
            let Some(stream) = meta.stream.clone() else {
                let record = finish_command_transition(&mut device, command_id, next, started_at);
                drop(device);
                self.publish_event(record);
                return;
            };
            let Some(parent) = device.text_streams.get_mut(&stream.parent_id) else {
                return;
            };
            if parent.current_command_id != Some(command_id) {
                return;
            }
            reduce_text_stream_child(parent, command_id, stream, next, started_at.is_some());
            if parent.phase == TextStreamPhase::Terminal {
                device.stream_reservation = None;
            }
            let record = finish_command_transition(&mut device, command_id, next, started_at);
            device.commands.remove(&command_id);
            record
        };
        self.publish_event(record);
    }

    fn lookup(&self, id: &str) -> Result<DeviceHandle, ApiError> {
        self.0
            .devices
            .get(id)
            .cloned()
            .ok_or_else(|| ApiError::not_found("device not found"))
    }

    fn device_view(&self, id: &str) -> Result<DeviceView, ApiError> {
        let handle = self.lookup(id)?;
        let device = handle.0.lock().expect("device runtime lock");
        let mut view = view_from_runtime(id, &device, self.current_link_path(id));
        view.firmware = self.current_firmware(id);
        Ok(view)
    }

    fn current_link_path(&self, device_id: &str) -> Option<String> {
        let authority = self.gateway(device_id)?;
        Some(
            authority
                .transport
                .session_snapshot()
                .map_or("offline", |snapshot| match snapshot.link_path {
                    TlsLinkPath::Wifi => "wifi",
                    TlsLinkPath::Bluetooth => "bluetooth",
                })
                .to_owned(),
        )
    }

    fn current_firmware(&self, device_id: &str) -> Option<FirmwareView> {
        let identity = self
            .gateway(device_id)?
            .transport
            .session_snapshot()?
            .firmware_identity?;
        Some(FirmwareView {
            endpoint: identity.release,
            elf_sha256: encode_hex(&identity.elf_sha256),
            board_compatibility_id: identity.board_compatibility_id,
            protocol_major: keyferry_protocol::VERSION_MAJOR,
            protocol_min_minor: identity.protocol_min_minor,
            protocol_max_minor: identity.protocol_max_minor,
            ble_hid_output_v1: identity.device_capability_mask
                & keyferry_protocol::capability::BLE_HID_OUTPUT_V1
                != 0,
            ble_hid_bond_reset_v1: identity.device_capability_mask
                & keyferry_protocol::capability::BLE_HID_BOND_RESET_V1
                != 0,
            targeted_gateway_transfer_v1: identity.device_capability_mask
                & keyferry_protocol::capability::TARGETED_GATEWAY_TRANSFER_V1
                != 0,
            display_orientation_v1: identity.device_capability_mask
                & keyferry_protocol::capability::DISPLAY_ORIENTATION_V1
                != 0,
            screen_power_v1: identity.device_capability_mask
                & keyferry_protocol::capability::SCREEN_POWER_V1
                != 0,
            usb_file_handoff_v1: identity.device_capability_mask
                & keyferry_protocol::capability::USB_FILE_HANDOFF_V1
                != 0,
            usb_file_set_v2: identity.device_capability_mask
                & keyferry_protocol::capability::USB_FILE_SET_V2
                != 0,
        })
    }

    #[cfg(test)]
    pub fn metadata(&self) -> Vec<EventRecord> {
        self.0.metadata.lock().expect("metadata event lock").clone()
    }

    /// Return the daemon's retained state for a previously submitted command.
    /// This is a read-only snapshot: it neither resubmits the command nor waits
    /// for a future transition.
    pub fn command_outcome(
        &self,
        device_id: &str,
        command_id: Uuid,
    ) -> Result<CommandResponse, ApiError> {
        let handle = self.lookup(device_id)?;
        let device = handle.0.lock().expect("device runtime lock");
        let command = device
            .commands
            .get(&command_id)
            .ok_or_else(|| ApiError::not_found("command not found"))?;
        let outcome = *command.response.borrow();
        Ok(command_response_with_diagnostic(
            command_id,
            device_id,
            outcome,
            command.started_at.is_some(),
            command.output_transport,
            None,
            command.diagnostic,
        ))
    }

    pub async fn submit_text(
        &self,
        id: &str,
        caller: String,
        request: TypeRequest,
    ) -> Result<CommandResponse, ApiError> {
        if request.text.is_empty() || request.text.chars().count() > MAX_TEXT_CHARS {
            return Err(ApiError::bad_request(
                "text must contain 1 to 4096 characters",
            ));
        }
        let timing = match request.timing.as_str() {
            "desktop-safe" => TypingTiming::DESKTOP_SAFE,
            "compatibility" => TypingTiming::COMPATIBILITY,
            _ => return Err(ApiError::bad_request("unsupported timing preset")),
        };
        let compatibility = KeyboardSequenceV1 {
            schema: SEQUENCE_SCHEMA_V1.to_owned(),
            command_id: "019d0000-0000-7000-8000-000000000000".to_owned(),
            profile: "windows-us".to_owned(),
            arm: SequenceArmPolicy::RequireExisting,
            start_within_ms: request.expires_in_ms.unwrap_or(MAX_COMMAND_EXPIRY_MS),
            timing: Some(timing),
            actions: vec![SequenceAction::Text {
                value: request.text.clone(),
                timing: None,
            }],
        };
        let compiled = compile_sequence(&compatibility).map_err(sequence_error)?;
        self.submit(
            id,
            caller,
            request.profile,
            request.command_id,
            compiled.steps,
            compiled.text_characters,
            request.expires_in_ms,
            false,
        )
        .await
    }

    pub async fn submit_actions(
        &self,
        id: &str,
        caller: String,
        request: ActionsRequest,
    ) -> Result<CommandResponse, ApiError> {
        if request.actions.is_empty() || request.actions.len() > MAX_CHUNK_ACTIONS {
            return Err(ApiError::bad_request("actions must contain 1 to 64 items"));
        }
        let compiled = action_steps(&request.actions).map_err(ApiError::bad_request)?;
        self.submit(
            id,
            caller,
            request.profile,
            request.command_id,
            compiled.steps,
            compiled.text_characters,
            request.expires_in_ms,
            false,
        )
        .await
    }

    pub async fn submit_sequence(
        &self,
        id: &str,
        caller: String,
        request: KeyboardSequenceV1,
    ) -> Result<CommandResponse, ApiError> {
        let command_id = Uuid::parse_str(&request.command_id)
            .map_err(|_| ApiError::bad_request("command_id must be UUID v7"))?;
        if command_id.get_version_num() != 7 {
            return Err(ApiError::bad_request("command_id must be UUID v7"));
        }
        let arm_before_first = request.arm == SequenceArmPolicy::CommandScoped;
        let compiled = compile_sequence(&request).map_err(sequence_error)?;
        self.submit(
            id,
            caller,
            request.profile,
            Some(command_id),
            compiled.steps,
            compiled.text_characters,
            Some(request.start_within_ms),
            arm_before_first,
        )
        .await
    }

    pub fn capabilities(&self) -> TextStreamCapabilities {
        TextStreamCapabilities {
            schema: "keyferry.capabilities.v1",
            epoch: self.0.epoch.to_string(),
            text_stream: TEXT_STREAM_SCHEMA_V1,
            child_budget_ms: keyferry_layouts::text_stream::TEXT_STREAM_CHILD_BUDGET_MS,
            source_read_bytes: keyferry_layouts::text_stream::TEXT_STREAM_READ_BYTES,
            lease_ms: TEXT_STREAM_LEASE.as_millis() as u64,
            source_idle_ms: TEXT_STREAM_SOURCE_IDLE.as_millis() as u64,
            receipt_retention_ms: TEXT_STREAM_RECEIPT_RETENTION.as_millis() as u64,
        }
    }

    pub fn create_text_stream(
        &self,
        id: &str,
        caller: String,
        request: CreateTextStreamRequest,
    ) -> Result<TextStreamReceipt, ApiError> {
        validate_text_stream_create(&request, self.0.epoch)?;
        let job_id = parse_uuid_v7(&request.job_id, "text_stream.job_id")?;
        let handle = self.lookup(id)?;
        let mut device = handle.0.lock().expect("device runtime lock");
        prune_text_stream_records(&mut device);
        if let Some(parent) = device.text_streams.get(&job_id) {
            if parent.caller == caller && parent.request == request {
                return Ok(text_stream_receipt(id, job_id, parent));
            }
            return Err(ApiError::conflict("text_stream.id_conflict"));
        }
        if device.text_streams.len() >= MAX_TEXT_STREAM_PARENTS {
            return Err(ApiError::busy("text_stream.capacity".to_owned()));
        }
        if let Some(active) = device.stream_reservation {
            return Err(ApiError::busy(active.to_string()));
        }
        if let Some(active) = device.current {
            return Err(ApiError::busy(active.to_string()));
        }
        if device.maintenance {
            return Err(ApiError::conflict("device is paused for local maintenance"));
        }
        let now = Instant::now();
        let parent = TextStreamParent {
            caller,
            request,
            phase: TextStreamPhase::Ready,
            outcome: None,
            reason: None,
            next_index: 0,
            confirmed_bytes: 0,
            confirmed_scalars: 0,
            confirmed_children: 0,
            confirmed_gestures: 0,
            uncertain: None,
            current: None,
            current_command_id: None,
            current_outcome: None,
            source_complete: false,
            total_bytes: None,
            total_scalars: None,
            possible_start: false,
            terminal_zero_confirmed: true,
            lease_deadline: now + TEXT_STREAM_LEASE,
            idle_deadline: now + TEXT_STREAM_SOURCE_IDLE,
            terminal_at: None,
        };
        device.stream_reservation = Some(job_id);
        device.text_streams.insert(job_id, parent);
        Ok(text_stream_receipt(
            id,
            job_id,
            device.text_streams.get(&job_id).expect("inserted stream"),
        ))
    }

    pub async fn submit_text_stream_part(
        &self,
        id: &str,
        caller: String,
        job_id: Uuid,
        index: u64,
        request: TextStreamPartRequest,
    ) -> Result<TextStreamReceipt, ApiError> {
        require_epoch(&request.epoch, self.0.epoch)?;
        let command_id = parse_uuid_v7(&request.child_command_id, "text_stream.child_command_id")?;
        let (start_bytes, start_scalars) = request.source_start.counts()?;
        let (parent_request, stream_meta) = {
            let handle = self.lookup(id)?;
            let mut device = handle.0.lock().expect("device runtime lock");
            let parent = device
                .text_streams
                .get_mut(&job_id)
                .ok_or_else(|| ApiError::not_found("text_stream.not_found"))?;
            require_text_stream_owner(parent, &caller)?;
            if parent.phase == TextStreamPhase::Terminal || parent.source_complete {
                return Err(ApiError::conflict("text_stream.terminal"));
            }
            if index != parent.next_index {
                return Err(ApiError::conflict("text_stream.index"));
            }
            if parent.current.is_some() {
                return Err(ApiError::busy("text_stream.child_in_flight".to_owned()));
            }
            if (start_bytes, start_scalars) != (parent.confirmed_bytes, parent.confirmed_scalars) {
                return Err(ApiError::conflict("text_stream.source_position"));
            }
            let timing = TypingTiming {
                key_down_ms: parent.request.key_down_ms,
                release_gap_ms: parent.request.key_gap_ms,
            };
            let part = validate_text_stream_part(&request.text, timing, request.end_of_input)
                .map_err(|error| ApiError::bad_request(error.code()))?;
            let computed_end_bytes = start_bytes
                .checked_add(part.end_bytes)
                .ok_or_else(|| ApiError::bad_request("input.counter_overflow"))?;
            let computed_end_scalars = start_scalars
                .checked_add(part.end_scalars)
                .ok_or_else(|| ApiError::bad_request("input.counter_overflow"))?;
            let (end_bytes, end_scalars) =
                match (parent.request.unsupported, request.source_end.as_ref()) {
                    (UnsupportedTextPolicy::Reject, None) => {
                        (computed_end_bytes, computed_end_scalars)
                    }
                    (UnsupportedTextPolicy::Reject, Some(cursor)) => {
                        let declared = cursor.counts()?;
                        if declared != (computed_end_bytes, computed_end_scalars) {
                            return Err(ApiError::conflict("text_stream.source_position"));
                        }
                        declared
                    }
                    (UnsupportedTextPolicy::Replace, Some(cursor)) => {
                        let (declared_bytes, declared_scalars) = cursor.counts()?;
                        let scalar_delta = declared_scalars
                            .checked_sub(start_scalars)
                            .ok_or_else(|| ApiError::conflict("text_stream.source_position"))?;
                        let byte_delta = declared_bytes
                            .checked_sub(start_bytes)
                            .ok_or_else(|| ApiError::conflict("text_stream.source_position"))?;
                        if scalar_delta != part.end_scalars
                            || byte_delta < scalar_delta
                            || byte_delta > scalar_delta.saturating_mul(4)
                        {
                            return Err(ApiError::conflict("text_stream.source_position"));
                        }
                        (declared_bytes, declared_scalars)
                    }
                    (UnsupportedTextPolicy::Replace, None) => {
                        return Err(ApiError::bad_request("text_stream.source_end_required"));
                    }
                };
            let stream_meta = StreamChildMeta {
                parent_id: job_id,
                index,
                start_bytes,
                end_bytes,
                start_scalars,
                end_scalars,
                gestures: u64::from(part.gestures),
                end_of_input: request.end_of_input,
            };
            parent.phase = TextStreamPhase::Running;
            parent.current = Some(stream_meta.clone());
            parent.current_command_id = Some(command_id);
            parent.current_outcome = Some(CommandOutcome::Queued);
            parent.lease_deadline = Instant::now() + TEXT_STREAM_LEASE;
            parent.idle_deadline = Instant::now() + TEXT_STREAM_SOURCE_IDLE;
            (parent.request.clone(), stream_meta)
        };

        let timing = TypingTiming {
            key_down_ms: parent_request.key_down_ms,
            release_gap_ms: parent_request.key_gap_ms,
        };
        let mut actions = Vec::with_capacity(2);
        if index == 0 && parent_request.send_after_seconds != 0 {
            actions.push(SequenceAction::Wait {
                ms: parent_request.send_after_seconds * 1_000,
            });
        }
        actions.push(SequenceAction::Text {
            value: request.text,
            timing: None,
        });
        let sequence = KeyboardSequenceV1 {
            schema: SEQUENCE_SCHEMA_V1.to_owned(),
            command_id: command_id.to_string(),
            profile: parent_request.profile,
            arm: SequenceArmPolicy::CommandScoped,
            start_within_ms: MAX_COMMAND_EXPIRY_MS,
            timing: Some(timing),
            actions,
        };
        let compiled = compile_sequence(&sequence).map_err(sequence_error)?;
        let chunks = plan_chunks(compiled.steps).map_err(ApiError::bad_request)?;
        let fingerprint = CommandFingerprint::Keyboard(fingerprint(
            &sequence.profile,
            &chunks,
            compiled.text_characters,
            sequence.start_within_ms,
            true,
        ));
        let command = PlannedCommand {
            command_id,
            chunks,
            action_count: compiled.gestures,
            char_count: compiled.text_characters,
            profile: sequence.profile,
            expires_at: Instant::now() + Duration::from_millis(MAX_COMMAND_EXPIRY_MS.into()),
            arm_before_first: true,
            input: None,
        };
        if let Err(error) = self
            .enqueue(id, caller.clone(), command, fingerprint, Some(stream_meta))
            .await
        {
            let handle = self.lookup(id)?;
            let mut device = handle.0.lock().expect("device runtime lock");
            stop_prepared_stream(&mut device, job_id, command_id, "child.admission_failed");
            return Err(error);
        }
        self.text_stream_status(id, caller, job_id)
    }

    pub fn finish_text_stream(
        &self,
        id: &str,
        caller: String,
        job_id: Uuid,
        request: TextStreamFinishRequest,
    ) -> Result<TextStreamReceipt, ApiError> {
        require_epoch(&request.epoch, self.0.epoch)?;
        let next_index = parse_decimal_counter(&request.next_index)?;
        let final_position = request.final_position.counts()?;
        let handle = self.lookup(id)?;
        let mut device = handle.0.lock().expect("device runtime lock");
        let parent = device
            .text_streams
            .get_mut(&job_id)
            .ok_or_else(|| ApiError::not_found("text_stream.not_found"))?;
        require_text_stream_owner(parent, &caller)?;
        if parent.current.is_some() {
            return Err(ApiError::busy("text_stream.child_in_flight".to_owned()));
        }
        if next_index != parent.next_index
            || final_position != (parent.confirmed_bytes, parent.confirmed_scalars)
        {
            return Err(ApiError::conflict("text_stream.source_position"));
        }
        if parent.phase == TextStreamPhase::Terminal {
            return Ok(text_stream_receipt(id, job_id, parent));
        }
        parent.phase = TextStreamPhase::Terminal;
        parent.outcome = Some(if parent.confirmed_children == 0 {
            CommandOutcome::Rejected
        } else {
            CommandOutcome::Emitted
        });
        parent.reason = (parent.confirmed_children == 0).then(|| "input.empty".to_owned());
        parent.source_complete = true;
        parent.total_bytes = Some(parent.confirmed_bytes);
        parent.total_scalars = Some(parent.confirmed_scalars);
        parent.terminal_at = Some(Instant::now());
        let receipt = text_stream_receipt(id, job_id, parent);
        device.stream_reservation = None;
        Ok(receipt)
    }

    pub fn text_stream_status(
        &self,
        id: &str,
        caller: String,
        job_id: Uuid,
    ) -> Result<TextStreamReceipt, ApiError> {
        let handle = self.lookup(id)?;
        let device = handle.0.lock().expect("device runtime lock");
        let parent = device
            .text_streams
            .get(&job_id)
            .ok_or_else(|| ApiError::not_found("text_stream.not_found"))?;
        require_text_stream_owner(parent, &caller)?;
        Ok(text_stream_receipt(id, job_id, parent))
    }

    pub fn renew_text_stream(
        &self,
        id: &str,
        caller: String,
        job_id: Uuid,
        request: TextStreamControlRequest,
    ) -> Result<TextStreamReceipt, ApiError> {
        require_epoch(&request.epoch, self.0.epoch)?;
        let handle = self.lookup(id)?;
        let mut device = handle.0.lock().expect("device runtime lock");
        let parent = device
            .text_streams
            .get_mut(&job_id)
            .ok_or_else(|| ApiError::not_found("text_stream.not_found"))?;
        require_text_stream_owner(parent, &caller)?;
        if parent.phase == TextStreamPhase::Terminal {
            return Err(ApiError::conflict("text_stream.terminal"));
        }
        parent.lease_deadline = Instant::now() + TEXT_STREAM_LEASE;
        Ok(text_stream_receipt(id, job_id, parent))
    }

    pub fn cancel_text_stream(
        &self,
        id: &str,
        caller: String,
        job_id: Uuid,
        request: TextStreamCancelRequest,
    ) -> Result<TextStreamReceipt, ApiError> {
        require_epoch(&request.epoch, self.0.epoch)?;
        if request.reason == TextStreamCancelReason::SourceInvalid && request.source_error.is_none()
        {
            return Err(ApiError::bad_request("text_stream.source_error_required"));
        }
        let handle = self.lookup(id)?;
        let mut device = handle.0.lock().expect("device runtime lock");
        let command_id = {
            let parent = device
                .text_streams
                .get_mut(&job_id)
                .ok_or_else(|| ApiError::not_found("text_stream.not_found"))?;
            require_text_stream_owner(parent, &caller)?;
            if parent.phase == TextStreamPhase::Terminal {
                return Ok(text_stream_receipt(id, job_id, parent));
            }
            if parent.current_command_id.is_some() {
                parent.phase = TextStreamPhase::Stopping;
                parent.reason = Some(request.reason.code().to_owned());
            }
            parent.current_command_id
        };
        if let Some(command_id) = command_id {
            if let Some(command) = device.commands.get(&command_id) {
                command.cancellation.cancel();
            }
            return Ok(text_stream_receipt(
                id,
                job_id,
                device.text_streams.get(&job_id).expect("stream exists"),
            ));
        }
        finish_idle_stream(&mut device, job_id, request.reason.code());
        Ok(text_stream_receipt(
            id,
            job_id,
            device.text_streams.get(&job_id).expect("stream exists"),
        ))
    }

    pub async fn submit_input_sequence(
        &self,
        id: &str,
        caller: String,
        request: InputSequenceV1,
    ) -> Result<CommandResponse, ApiError> {
        let command_id = Uuid::parse_str(&request.command_id)
            .map_err(|_| ApiError::bad_request("input.command_id"))?;
        let compiled = compile_input_sequence(&request)
            .map_err(|error| ApiError::bad_request(error.code()))?;
        let fingerprint = CommandFingerprint::Input(compiled.fingerprint);
        let command = PlannedCommand {
            command_id,
            chunks: Vec::new(),
            action_count: compiled.effectful_gestures,
            char_count: compiled.text_characters,
            // The existing authenticated command envelope accepts this profile.
            // Pointer-only plans remain profile-independent in their fingerprint.
            profile: "windows-us".to_owned(),
            expires_at: Instant::now() + Duration::from_millis(request.start_within_ms),
            arm_before_first: true,
            input: Some(compiled),
        };
        self.enqueue(id, caller, command, fingerprint, None).await
    }

    // Eight distinct command parameters on one private call path; bundling them
    // into a struct would add indirection without making it clearer.
    #[allow(clippy::too_many_arguments)]
    async fn submit(
        &self,
        id: &str,
        caller: String,
        profile: String,
        command_id: Option<Uuid>,
        steps: Vec<ReportStep>,
        char_count: usize,
        expires_in_ms: Option<u32>,
        arm_before_first: bool,
    ) -> Result<CommandResponse, ApiError> {
        let command_id = command_id.unwrap_or_else(Uuid::now_v7);
        if command_id.get_version_num() != 7 {
            return Err(ApiError::bad_request("command_id must be UUID v7"));
        }
        if !valid_profile(&profile) {
            return Err(ApiError::bad_request("unsupported target profile"));
        }
        let expiry = expires_in_ms.unwrap_or(MAX_COMMAND_EXPIRY_MS);
        if expiry == 0 || expiry > MAX_COMMAND_EXPIRY_MS {
            return Err(ApiError::bad_request(
                "expires_in_ms must be between 1 and 5000",
            ));
        }
        let chunks = plan_chunks(steps).map_err(ApiError::bad_request)?;
        let action_count = chunks.iter().map(|chunk| chunk.steps.len()).sum();
        let fingerprint = CommandFingerprint::Keyboard(fingerprint(
            &profile,
            &chunks,
            char_count,
            expiry,
            arm_before_first,
        ));
        let command = PlannedCommand {
            command_id,
            chunks,
            action_count,
            char_count,
            profile,
            expires_at: Instant::now() + Duration::from_millis(u64::from(expiry)),
            arm_before_first,
            input: None,
        };
        self.enqueue(id, caller, command, fingerprint, None).await
    }

    async fn enqueue(
        &self,
        id: &str,
        caller: String,
        command: PlannedCommand,
        fingerprint: CommandFingerprint,
        stream: Option<StreamChildMeta>,
    ) -> Result<CommandResponse, ApiError> {
        let handle = self.lookup(id)?;
        let command_id = command.command_id;
        let diagnostic_events_requested = self.diagnostic_events_requested();
        let cancellation = Cancellation::new();
        // The watch sender is cloned into the command record below; this outer
        // binding only needs to live long enough for the block to return.
        let (work_tx, _response, queued_record, output_transport) = {
            let mut device = handle.0.lock().expect("device runtime lock");
            expire_arm(&mut device);
            prune_text_stream_records(&mut device);
            if let Some(existing) = device.commands.get(&command_id) {
                let outcome = *existing.response.borrow();
                if existing.fingerprint == fingerprint && existing.stream == stream {
                    return Ok(command_response_with_diagnostic(
                        command_id,
                        id,
                        outcome,
                        existing.started_at.is_some(),
                        existing.output_transport,
                        Some("duplicate command returned existing outcome".to_owned()),
                        existing.diagnostic,
                    ));
                }
                return Err(ApiError::conflict(
                    "command_id already has different content",
                ));
            }
            if let Some(active) = device.current {
                return Err(ApiError::busy(active.to_string()));
            }
            match (device.stream_reservation, stream.as_ref()) {
                (Some(parent_id), Some(meta)) if parent_id == meta.parent_id => {}
                (Some(parent_id), _) => return Err(ApiError::busy(parent_id.to_string())),
                (None, Some(_)) => return Err(ApiError::conflict("text_stream.not_reserved")),
                (None, None) => {}
            }
            if device.maintenance {
                return Err(ApiError::conflict("device is paused for local maintenance"));
            }
            if device.state.link != keyferry_core::LinkState::Authenticated {
                return Err(ApiError::unauthorized_command(
                    "device link is not authenticated",
                ));
            }
            if !device.transport.is_ready() {
                return Err(ApiError::unauthorized_command("device link is not ready"));
            }
            if device.state.mode != OperationalMode::Keyboard {
                return Err(ApiError::rejected("device mode rejects keyboard input"));
            }
            if command.input.is_some() && !device.transport.supports_input_sequence() {
                return Err(ApiError::rejected("device lacks input-sequence capability"));
            }
            if let Some(meta) = stream.as_ref() {
                let parent = device
                    .text_streams
                    .get(&meta.parent_id)
                    .ok_or_else(|| ApiError::not_found("text_stream.not_found"))?;
                if parent.phase != TextStreamPhase::Running
                    || parent.current.as_ref() != Some(meta)
                    || parent.current_command_id != Some(command_id)
                {
                    return Err(ApiError::conflict("text_stream.not_ready"));
                }
            }
            if command.arm_before_first {
                device
                    .state
                    .arm(ArmPolicy::CommandScoped)
                    .map_err(map_state_error)?;
                device.arm_until = None;
            } else if !device.state.armed {
                return Err(ApiError::rejected("device is not armed"));
            }
            device
                .state
                .submit(command_id.into_bytes())
                .map_err(map_state_error)?;
            device.current = Some(command_id);
            let output_transport = device.transport.output_transport();
            let (response, _) = watch::channel(CommandOutcome::Queued);
            let event = diagnostic_events_requested.then(|| EventRecord {
                command_id: command_id.to_string(),
                caller,
                device_id: id.to_owned(),
                profile: command.profile.clone(),
                action_count: command.action_count,
                char_count: command.char_count,
                timestamp: timestamp_now(),
                duration_ms: None,
                outcome: CommandOutcome::Queued,
            });
            device.commands.insert(
                command_id,
                CommandMeta {
                    fingerprint,
                    response: response.clone(),
                    started_at: None,
                    event: event.clone(),
                    cancellation: cancellation.clone(),
                    diagnostic: None,
                    stream,
                    terminal_at: None,
                    output_transport,
                },
            );
            (device.work_tx.clone(), response, event, output_transport)
        };
        self.publish_event(queued_record);
        if work_tx
            .send(WorkItem {
                command,
                cancellation,
            })
            .await
            .is_err()
        {
            self.transition_terminal(&handle.0, command_id, CommandOutcome::Rejected);
            return Err(ApiError::internal("simulator worker stopped"));
        }
        Ok(command_response(
            command_id,
            id,
            CommandOutcome::Queued,
            false,
            output_transport,
            None,
        ))
    }

    pub async fn arm_device(&self, id: &str, request: ArmRequest) -> Result<DeviceView, ApiError> {
        let handle = self.lookup(id)?;
        let policy = parse_arm_policy(&request.policy)
            .ok_or_else(|| ApiError::bad_request("unsupported arm policy"))?;
        let lease = match policy {
            ArmPolicy::CommandScoped | ArmPolicy::AlwaysReady => {
                if !matches!(request.lease_ms, None | Some(0)) {
                    return Err(ApiError::bad_request(
                        "command-scoped and always-ready require lease_ms=0",
                    ));
                }
                0
            }
            ArmPolicy::Temporary => {
                let lease = request.lease_ms.unwrap_or(DEFAULT_TEMPORARY_ARM_MS);
                if lease == 0 || lease > MAX_TEMPORARY_ARM_MS {
                    return Err(ApiError::bad_request(
                        "temporary lease_ms must be between 1 and 600000",
                    ));
                }
                lease as u32
            }
        };
        let transport = {
            let device = handle.0.lock().expect("device runtime lock");
            if let Some(active) = device.stream_reservation {
                return Err(ApiError::busy(active.to_string()));
            }
            if device.maintenance {
                return Err(ApiError::conflict("device is paused for local maintenance"));
            }
            let mut prospective = device.state.clone();
            prospective.arm(policy).map_err(map_state_error)?;
            device.transport.clone()
        };
        transport
            .arm(policy, lease)
            .await
            .map_err(|error| map_transport_control_error("arm", error))?;

        let link_path = self.current_link_path(id);
        let committed = {
            let mut device = handle.0.lock().expect("device runtime lock");
            device.state.arm(policy).map_err(map_state_error).map(|()| {
                device.arm_until = (policy == ArmPolicy::Temporary)
                    .then(|| Instant::now() + Duration::from_millis(u64::from(lease)));
                view_from_runtime(id, &device, link_path)
            })
        };
        if committed.is_err() {
            transport.disarm().await.ok();
        }
        committed
    }

    fn file_transport(&self, id: &str) -> Result<FileTransportAccess, ApiError> {
        let handle = self.lookup(id)?;
        let device = handle.0.lock().expect("device runtime lock");
        if !device.transport.supports_file_handoff() {
            return Err(ApiError::rejected(
                "device lacks USB file handoff capability",
            ));
        }
        if device.maintenance
            || device.current.is_some()
            || device.stream_reservation.is_some()
            || device.state.armed
        {
            return Err(ApiError::conflict(
                "device must be idle and disarmed for file handoff",
            ));
        }
        Ok((device.transport.clone(), device.file_gate.clone()))
    }

    fn file_set_transport(&self, id: &str) -> Result<FileTransportAccess, ApiError> {
        let handle = self.lookup(id)?;
        let device = handle.0.lock().expect("device runtime lock");
        if !device.transport.supports_file_set() {
            return Err(ApiError::rejected("device lacks USB file-set capability"));
        }
        if device.maintenance
            || device.current.is_some()
            || device.stream_reservation.is_some()
            || device.state.armed
        {
            return Err(ApiError::conflict(
                "device must be idle and disarmed for file handoff",
            ));
        }
        Ok((device.transport.clone(), device.file_gate.clone()))
    }

    async fn file_set_view(
        transport: &Arc<dyn DeviceTransport>,
    ) -> Result<FileSetStatusView, ApiError> {
        use keyferry_protocol::file_set::{
            Request, State, MAX_FILES, MAX_FILE_BYTES, MAX_NAME_BYTES,
        };
        let summary = transport
            .file_set_request(Request::Status { index: 255 })
            .await
            .map_err(map_file_transport_error)?;
        file_set_status_error(summary.error)?;
        if summary.entry.is_some() || (summary.state == State::Published && summary.count == 0) {
            return Err(ApiError::uncertain("file.status_unknown", None));
        }
        let mut files = Vec::new();
        let mut content_size = 0u32;
        if summary.state == State::Published {
            for index in 0..summary.count {
                let page = transport
                    .file_set_request(Request::Status { index })
                    .await
                    .map_err(map_file_transport_error)?;
                file_set_status_error(page.error)?;
                if page.state != State::Published
                    || page.wire_size != summary.wire_size
                    || page.received != summary.received
                    || page.count != summary.count
                {
                    return Err(ApiError::uncertain("file.status_changed", None));
                }
                let entry = page
                    .entry
                    .ok_or_else(|| ApiError::uncertain("file.status_missing_entry", None))?;
                if entry.index != index {
                    return Err(ApiError::uncertain("file.status_wrong_entry", None));
                }
                content_size = content_size
                    .checked_add(entry.size)
                    .filter(|size| *size <= MAX_FILE_BYTES as u32)
                    .ok_or_else(|| ApiError::uncertain("file.status_invalid_size", None))?;
                files.push(FileSetEntryView {
                    name: entry.name,
                    size: entry.size,
                });
            }
            let names = files
                .iter()
                .map(|file| file.name.as_str())
                .collect::<Vec<_>>();
            keyferry_protocol::file_set::validate_names(&names)
                .map_err(|_| ApiError::uncertain("file.status_invalid_names", None))?;
            if summary.wire_size < content_size || summary.received != summary.wire_size {
                return Err(ApiError::uncertain("file.status_invalid_bundle", None));
            }
        } else if summary.count != 0 {
            return Err(ApiError::uncertain("file.status_invalid_count", None));
        }
        Ok(FileSetStatusView {
            state: match summary.state {
                State::Empty => "empty",
                State::Receiving => "receiving",
                State::Published => "published",
            },
            size_bytes: content_size,
            received_bytes: if summary.state == State::Published {
                content_size
            } else {
                0
            },
            bundle_size_bytes: summary.wire_size,
            bundle_received_bytes: summary.received,
            max_size_bytes: MAX_FILE_BYTES,
            files,
            max_files: MAX_FILES,
            max_name_bytes: MAX_NAME_BYTES,
        })
    }

    pub async fn file_set_status(&self, id: &str) -> Result<FileSetStatusView, ApiError> {
        let (transport, gate) = self.file_set_transport(id)?;
        let _guard = gate.lock().await;
        Self::file_set_view(&transport).await
    }

    pub async fn file_set_clear(&self, id: &str) -> Result<FileSetStatusView, ApiError> {
        use keyferry_protocol::file_set::{Error, Request, State};
        let (transport, gate) = self.file_set_transport(id)?;
        let _guard = gate.lock().await;
        let deadline = Instant::now() + FILE_BEGIN_BUSY_WAIT;
        loop {
            let status = match transport.file_set_request(Request::Clear).await {
                Err(TransportError::LostBeforeAccept) if Instant::now() < deadline => {
                    time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
                result => result.map_err(map_file_transport_error)?,
            };
            if status.error == Error::Busy && Instant::now() < deadline {
                time::sleep(Duration::from_millis(250)).await;
                continue;
            }
            file_set_status_error(status.error)?;
            if status.state != State::Empty || status.count != 0 {
                return Err(ApiError::uncertain("file.clear_state_unknown", None));
            }
            return Self::file_set_view(&transport).await;
        }
    }

    pub async fn file_set_publish(
        &self,
        id: &str,
        files: Vec<keyferry_protocol::file_set::File>,
    ) -> Result<FileSetStatusView, ApiError> {
        use keyferry_protocol::file_set::{Error, Request, State, MAX_CHUNK_BYTES};
        let bundle = keyferry_protocol::file_set::encode_bundle(&files)
            .map_err(|_| ApiError::bad_request("file.invalid_set"))?;
        let (transport, gate) = self.file_set_transport(id)?;
        let _guard = gate.lock().await;
        let size = bundle.len() as u32;
        let digest: [u8; 32] = Sha256::digest(&bundle).into();
        let started = Instant::now();
        let deadline = started + FILE_BEGIN_BUSY_WAIT;
        loop {
            let status = match transport
                .file_set_request(Request::Begin {
                    size,
                    sha256: digest,
                })
                .await
            {
                Err(TransportError::LostBeforeAccept) if Instant::now() < deadline => {
                    time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
                result => result.map_err(map_file_transport_error)?,
            };
            if status.error == Error::Busy && Instant::now() < deadline {
                time::sleep(Duration::from_millis(250)).await;
                continue;
            }
            file_set_status_error(status.error)?;
            if status.state != State::Receiving || status.wire_size != size || status.received != 0
            {
                return Err(ApiError::uncertain("file.begin_state_unknown", None));
            }
            break;
        }
        for (index, chunk) in bundle.chunks(MAX_CHUNK_BYTES).enumerate() {
            if started.elapsed() >= FILE_UPLOAD_LIMIT {
                return Err(ApiError::uncertain("file.upload_timeout", None));
            }
            let offset = (index * MAX_CHUNK_BYTES) as u32;
            let status = transport
                .file_set_request(Request::Chunk {
                    offset,
                    bytes: chunk.to_vec(),
                })
                .await
                .map_err(map_file_transport_error)?;
            file_set_status_error(status.error)?;
            if status.state != State::Receiving
                || status.wire_size != size
                || status.received != offset + chunk.len() as u32
            {
                return Err(ApiError::uncertain("file.chunk_state_unknown", None));
            }
        }
        if started.elapsed() >= FILE_UPLOAD_LIMIT {
            return Err(ApiError::uncertain("file.upload_timeout", None));
        }
        let status = transport
            .file_set_request(Request::Commit)
            .await
            .map_err(map_file_transport_error)?;
        file_set_status_error(status.error)?;
        if status.state != State::Published
            || status.wire_size != size
            || status.received != size
            || status.count as usize != files.len()
        {
            return Err(ApiError::uncertain("file.commit_state_unknown", None));
        }
        let view = Self::file_set_view(&transport).await?;
        if view.bundle_size_bytes != size
            || view.files.iter().zip(&files).any(|(actual, expected)| {
                actual.name != expected.name || actual.size as usize != expected.bytes.len()
            })
            || view.files.len() != files.len()
        {
            return Err(ApiError::uncertain("file.published_set_unknown", None));
        }
        Ok(view)
    }

    pub async fn file_status(&self, id: &str) -> Result<FileStatusView, ApiError> {
        let (transport, gate) = self.file_transport(id)?;
        let _guard = gate.lock().await;
        let status = transport
            .file_request(keyferry_protocol::file::Request::Status)
            .await
            .map_err(map_file_transport_error)?;
        file_status_view(status)
    }

    pub async fn file_clear(&self, id: &str) -> Result<FileStatusView, ApiError> {
        use keyferry_protocol::file::{Error, Request, State};
        let (transport, gate) = self.file_transport(id)?;
        let _guard = gate.lock().await;
        let deadline = Instant::now() + FILE_BEGIN_BUSY_WAIT;
        loop {
            let status = match transport.file_request(Request::Clear).await {
                Err(TransportError::LostBeforeAccept) if Instant::now() < deadline => {
                    time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
                result => result.map_err(map_file_transport_error)?,
            };
            if status.error == Error::Busy && Instant::now() < deadline {
                time::sleep(Duration::from_millis(250)).await;
                continue;
            }
            file_status_view(status)?;
            if status.state != State::Empty {
                return Err(ApiError::uncertain("file.clear_state_unknown", None));
            }
            return Ok(status.into());
        }
    }

    pub async fn file_publish(&self, id: &str, bytes: Vec<u8>) -> Result<FileStatusView, ApiError> {
        use keyferry_protocol::file::{Error, Request, State, MAX_CHUNK_BYTES, MAX_FILE_BYTES};
        if bytes.len() > MAX_FILE_BYTES {
            return Err(ApiError::bad_request("file.limit"));
        }
        let (transport, gate) = self.file_transport(id)?;
        let _guard = gate.lock().await;
        let size = bytes.len() as u32;
        let upload_started = Instant::now();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let begin = Request::Begin {
            size,
            sha256: digest,
        };
        let deadline = Instant::now() + FILE_BEGIN_BUSY_WAIT;
        loop {
            let status = match transport.file_request(begin.clone()).await {
                Err(TransportError::LostBeforeAccept) if Instant::now() < deadline => {
                    time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
                result => result.map_err(map_file_transport_error)?,
            };
            if status.error == Error::Busy && Instant::now() < deadline {
                time::sleep(Duration::from_millis(250)).await;
                continue;
            }
            file_status_view(status)?;
            if status.state != State::Receiving || status.size != size || status.received != 0 {
                return Err(ApiError::conflict("file.begin_state"));
            }
            break;
        }
        for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
            if upload_started.elapsed() >= FILE_UPLOAD_LIMIT {
                return Err(ApiError::uncertain("file.upload_timeout", None));
            }
            let offset = (index * MAX_CHUNK_BYTES) as u32;
            let status = transport
                .file_request(Request::Chunk {
                    offset,
                    bytes: chunk.to_vec(),
                })
                .await
                .map_err(map_file_transport_error)?;
            file_status_view(status)?;
            if status.state != State::Receiving
                || status.size != size
                || status.received != offset + chunk.len() as u32
            {
                return Err(ApiError::uncertain("file.chunk_state_unknown", None));
            }
        }
        if upload_started.elapsed() >= FILE_UPLOAD_LIMIT {
            return Err(ApiError::uncertain("file.upload_timeout", None));
        }
        let status = transport
            .file_request(Request::Commit)
            .await
            .map_err(map_file_transport_error)?;
        file_status_view(status)?;
        if status.state != State::Published || status.size != size || status.received != size {
            return Err(ApiError::uncertain("file.commit_state_unknown", None));
        }
        Ok(FileStatusView::from(status))
    }

    pub async fn output_mode(
        &self,
        id: &str,
        requested: Option<OutputMode>,
    ) -> Result<OutputModeStatus, ApiError> {
        let handle = self.lookup(id)?;
        let transport = {
            let device = handle.0.lock().expect("device runtime lock");
            if !device.transport.supports_output_mode() {
                return Err(ApiError::rejected(
                    "device lacks direct Bluetooth keyboard capability",
                ));
            }
            if requested.is_some() {
                if let Some(active) = device.stream_reservation.or(device.current) {
                    return Err(ApiError::busy(active.to_string()));
                }
                if device.maintenance {
                    return Err(ApiError::conflict("device is paused for local maintenance"));
                }
                if device.state.armed {
                    return Err(ApiError::conflict(
                        "device must be disarmed before changing output mode",
                    ));
                }
            }
            device.transport.clone()
        };
        let status = transport
            .output_mode(requested)
            .await
            .map_err(|error| map_transport_control_error("output-mode request", error))?;
        Ok(OutputModeStatus {
            schema: OUTPUT_MODE_SCHEMA_V1,
            device_id: id.to_owned(),
            active: status.active,
            stored: status.stored,
            restart_pending: status.active != status.stored,
        })
    }

    pub async fn display_orientation(
        &self,
        id: &str,
        requested: Option<DisplayOrientation>,
    ) -> Result<DisplayOrientationStatus, ApiError> {
        let handle = self.lookup(id)?;
        let transport = {
            let device = handle.0.lock().expect("device runtime lock");
            if !device.transport.supports_display_orientation() {
                return Err(ApiError::rejected(
                    "device lacks runtime display-orientation capability",
                ));
            }
            if requested.is_some() {
                if let Some(active) = device.stream_reservation.or(device.current) {
                    return Err(ApiError::busy(active.to_string()));
                }
                if device.maintenance {
                    return Err(ApiError::conflict("device is paused for local maintenance"));
                }
                if device.state.armed {
                    return Err(ApiError::conflict(
                        "device must be disarmed before changing display orientation",
                    ));
                }
            }
            device.transport.clone()
        };
        let status = transport
            .display_orientation(requested)
            .await
            .map_err(|error| map_transport_control_error("display-orientation request", error))?;
        Ok(DisplayOrientationStatus {
            schema: DISPLAY_ORIENTATION_SCHEMA_V1,
            device_id: id.to_owned(),
            active: status.active,
            stored: status.stored,
            restart_pending: status.active != status.stored,
        })
    }

    pub async fn screen_power(
        &self,
        id: &str,
        requested: Option<ScreenPower>,
    ) -> Result<ScreenPowerStatus, ApiError> {
        let handle = self.lookup(id)?;
        let (transport, file_gate) = {
            let device = handle.0.lock().expect("device runtime lock");
            if !device.transport.supports_screen_power() {
                return Err(ApiError::rejected(
                    "device lacks runtime screen-power capability",
                ));
            }
            if requested.is_some() {
                if let Some(active) = device.stream_reservation.or(device.current) {
                    return Err(ApiError::busy(active.to_string()));
                }
                if device.maintenance {
                    return Err(ApiError::conflict("device is paused for local maintenance"));
                }
                if device.state.armed {
                    return Err(ApiError::conflict(
                        "device must be disarmed before changing screen power",
                    ));
                }
            }
            (device.transport.clone(), device.file_gate.clone())
        };
        let _file_guard =
            if requested.is_some() {
                Some(file_gate.try_lock().map_err(|_| {
                    ApiError::conflict("USB file handoff is running on this device")
                })?)
            } else {
                None
            };
        let status = transport
            .screen_power(requested)
            .await
            .map_err(|error| map_transport_control_error("screen-power request", error))?;
        Ok(ScreenPowerStatus {
            schema: SCREEN_POWER_SCHEMA_V1,
            device_id: id.to_owned(),
            active: status.active,
            stored: status.stored,
            available: status.available,
        })
    }

    pub async fn reset_ble_hid_bond(&self, id: &str) -> Result<BleHidBondResetStatus, ApiError> {
        let handle = self.lookup(id)?;
        let transport = {
            let device = handle.0.lock().expect("device runtime lock");
            if !device.transport.supports_ble_hid_bond_reset() {
                return Err(ApiError::rejected(
                    "device lacks Bluetooth keyboard bond-reset capability",
                ));
            }
            if device.transport.output_transport() != OutputTransport::BleHid {
                return Err(ApiError::conflict(
                    "Bluetooth keyboard output must be active before forgetting its pairing",
                ));
            }
            if let Some(active) = device.stream_reservation.or(device.current) {
                return Err(ApiError::busy(active.to_string()));
            }
            if device.maintenance {
                return Err(ApiError::conflict("device is paused for local maintenance"));
            }
            if device.state.armed {
                return Err(ApiError::conflict(
                    "device must be disarmed before forgetting Bluetooth pairing",
                ));
            }
            device.transport.clone()
        };
        let (bond_was_present, restart_pending) = transport
            .reset_ble_hid_bond()
            .await
            .map_err(|error| map_transport_control_error("Bluetooth bond-reset request", error))?;
        Ok(BleHidBondResetStatus {
            schema: BLE_HID_BOND_RESET_SCHEMA_V1,
            device_id: id.to_owned(),
            bond_was_present,
            restart_pending,
        })
    }

    pub async fn begin_device_maintenance(&self, id: &str) -> Result<DeviceView, ApiError> {
        let handle = self.lookup(id)?;
        let authority = self
            .gateway(id)
            .ok_or_else(|| ApiError::unavailable("local maintenance requires a TLS device"))?;
        let epoch = {
            let mut device = handle.0.lock().expect("device runtime lock");
            if let Some(active) = device.stream_reservation {
                return Err(ApiError::busy(active.to_string()));
            }
            if let Some(active) = device.current {
                return Err(ApiError::busy(active.to_string()));
            }
            device.state.disarm();
            device.arm_until = None;
            device.maintenance = true;
            device.maintenance_epoch = device.maintenance_epoch.wrapping_add(1);
            device.maintenance_epoch
        };
        if let Err(error) = authority.transport.begin_maintenance().await {
            let should_resume = {
                let mut device = handle.0.lock().expect("device runtime lock");
                if device.maintenance && device.maintenance_epoch == epoch {
                    device.maintenance = false;
                    true
                } else {
                    false
                }
            };
            if should_resume {
                authority.transport.finish_maintenance();
            }
            return Err(map_transport_control_error("begin maintenance", error));
        }
        self.device_view(id)
    }

    /// Stops all device work before the process exits. New work is refused, running commands are
    /// cancelled and given time to release, and each endpoint is then disarmed and its session
    /// closed through the maintenance path. Everything is bounded by `grace`; a socket still open
    /// afterwards closes with the process, and the endpoint's disconnect path releases every key.
    pub async fn shutdown(&self, grace: Duration) {
        let mut pending = Vec::with_capacity(self.0.devices.len());
        for (id, handle) in &self.0.devices {
            let running = {
                let mut device = handle.0.lock().expect("device runtime lock");
                device.maintenance = true;
                device.maintenance_epoch = device.maintenance_epoch.wrapping_add(1);
                device
                    .current
                    .and_then(|command_id| device.commands.get(&command_id))
                    .map(|command| {
                        command.cancellation.cancel();
                        command.response.subscribe()
                    })
            };
            let transport = self
                .gateway(id)
                .map(|authority| authority.transport.clone());
            pending.push((running, transport));
        }
        let mut closing = tokio::task::JoinSet::new();
        for (running, transport) in pending {
            closing.spawn(async move {
                if let Some(mut outcome) = running {
                    let _ = outcome.wait_for(|outcome| outcome.is_terminal()).await;
                }
                if let Some(transport) = transport {
                    let _ = transport.begin_maintenance().await;
                }
            });
        }
        let _ = time::timeout(grace, async {
            while closing.join_next().await.is_some() {}
        })
        .await;
    }

    pub fn finish_device_maintenance(&self, id: &str) -> Result<DeviceView, ApiError> {
        let handle = self.lookup(id)?;
        let authority = self
            .gateway(id)
            .ok_or_else(|| ApiError::unavailable("local maintenance requires a TLS device"))?;
        {
            let mut device = handle.0.lock().expect("device runtime lock");
            device.maintenance = false;
            device.maintenance_epoch = device.maintenance_epoch.wrapping_add(1);
        }
        authority.transport.finish_maintenance();
        self.device_view(id)
    }

    #[cfg(test)]
    async fn yield_device_gateway(
        &self,
        id: &str,
        duration: Duration,
    ) -> Result<GatewayYieldResponse, ApiError> {
        let handle = self.lookup(id)?;
        let authority = self
            .gateway(id)
            .ok_or_else(|| ApiError::unavailable("gateway transfer requires a TLS device"))?;
        let epoch = {
            let mut device = handle.0.lock().expect("device runtime lock");
            if device.state.link != keyferry_core::LinkState::Authenticated {
                return Err(ApiError::conflict(
                    "device must be authenticated before gateway transfer",
                ));
            }
            if device.maintenance {
                return Err(ApiError::conflict("device is already paused"));
            }
            if device.state.armed {
                return Err(ApiError::conflict(
                    "device must be disarmed before gateway transfer",
                ));
            }
            if let Some(active) = device.current {
                return Err(ApiError::busy(active.to_string()));
            }
            if let Some(active) = device.stream_reservation {
                return Err(ApiError::busy(active.to_string()));
            }
            device.state.disarm();
            device.arm_until = None;
            device.maintenance = true;
            device.maintenance_epoch = device.maintenance_epoch.wrapping_add(1);
            device.maintenance_epoch
        };

        if let Err(error) = authority.transport.begin_maintenance().await {
            let should_resume = {
                let mut device = handle.0.lock().expect("device runtime lock");
                if device.maintenance && device.maintenance_epoch == epoch {
                    device.maintenance = false;
                    true
                } else {
                    false
                }
            };
            if should_resume {
                authority.transport.finish_maintenance();
            }
            return Err(map_transport_control_error("gateway transfer", error));
        }

        let runtime = Arc::clone(&handle.0);
        let transport = authority.transport.clone();
        tokio::spawn(async move {
            time::sleep(duration).await;
            let should_resume = {
                let mut device = runtime.lock().expect("device runtime lock");
                if device.maintenance && device.maintenance_epoch == epoch {
                    device.maintenance = false;
                    true
                } else {
                    false
                }
            };
            if should_resume {
                transport.finish_maintenance();
            }
        });

        Ok(GatewayYieldResponse {
            device_id: id.to_owned(),
            status: "yielding".to_owned(),
            yield_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        })
    }

    pub async fn disarm_device(&self, id: &str) -> Result<DeviceView, ApiError> {
        let handle = self.lookup(id)?;
        let transport = {
            let mut device = handle.0.lock().expect("device runtime lock");
            device.state.disarm();
            device.arm_until = None;
            if let Some(job_id) = device.stream_reservation {
                if let Some(parent) = device.text_streams.get_mut(&job_id) {
                    if parent.current.is_some() {
                        parent.phase = TextStreamPhase::Stopping;
                        parent.reason = Some("device_disarmed".to_owned());
                    } else {
                        finish_idle_stream(&mut device, job_id, "device_disarmed");
                    }
                }
            }
            if let Some(command_id) = device.current {
                if let Some(command) = device.commands.get(&command_id) {
                    command.cancellation.cancel();
                }
            }
            device.transport.clone()
        };
        transport
            .disarm()
            .await
            .map_err(|error| map_transport_control_error("disarm", error))?;
        let link_path = self.current_link_path(id);
        let mut device = handle.0.lock().expect("device runtime lock");
        expire_arm(&mut device);
        Ok(view_from_runtime(id, &device, link_path))
    }

    pub async fn renew_arm_lease(&self, id: &str, lease_ms: u32) -> Result<DeviceView, ApiError> {
        if lease_ms == 0 || u64::from(lease_ms) > MAX_TEMPORARY_ARM_MS {
            return Err(ApiError::bad_request(
                "temporary lease_ms must be between 1 and 600000",
            ));
        }
        let handle = self.lookup(id)?;
        let transport = {
            let device = handle.0.lock().expect("device runtime lock");
            if !device.state.armed || device.state.arm_policy != ArmPolicy::Temporary {
                return Err(ApiError::rejected(
                    "only an active temporary arm can be renewed",
                ));
            }
            device.transport.clone()
        };
        transport
            .renew_lease(lease_ms)
            .await
            .map_err(|error| map_transport_control_error("renew arm lease", error))?;
        let link_path = self.current_link_path(id);
        let view = {
            let mut device = handle.0.lock().expect("device runtime lock");
            if !device.state.armed || device.state.arm_policy != ArmPolicy::Temporary {
                None
            } else {
                device.arm_until =
                    Some(Instant::now() + Duration::from_millis(u64::from(lease_ms)));
                Some(view_from_runtime(id, &device, link_path))
            }
        };
        if let Some(view) = view {
            Ok(view)
        } else {
            transport.disarm().await.ok();
            Err(ApiError::rejected(
                "arm state changed while renewing its lease",
            ))
        }
    }

    pub async fn cancel_command(
        &self,
        id: &str,
        request: CancelRequest,
    ) -> Result<CommandResponse, ApiError> {
        let handle = self.lookup(id)?;
        let device = handle.0.lock().expect("device runtime lock");
        let command_id = request
            .command_id
            .or(device.current)
            .ok_or_else(|| ApiError::not_found("no active command"))?;
        let command = device
            .commands
            .get(&command_id)
            .ok_or_else(|| ApiError::not_found("command not found"))?;
        let outcome = *command.response.borrow();
        if outcome.is_terminal() {
            return Ok(command_response_with_diagnostic(
                command_id,
                id,
                outcome,
                command.started_at.is_some(),
                command.output_transport,
                Some("command was already terminal".to_owned()),
                command.diagnostic,
            ));
        }
        command.cancellation.cancel();
        Ok(command_response(
            command_id,
            id,
            outcome,
            command.started_at.is_some(),
            command.output_transport,
            Some("cancellation requested; observe events for ABORTED or UNKNOWN".to_owned()),
        ))
    }

    pub async fn wait_for_terminal(&self, id: Uuid) -> Option<CommandOutcome> {
        for handle in self.0.devices.values() {
            let receiver = {
                let device = handle.0.lock().expect("device runtime lock");
                device
                    .commands
                    .get(&id)
                    .map(|command| command.response.subscribe())
            };
            // Skip devices that do not own this command rather than abandoning
            // the search: only the owning device can report a terminal outcome.
            let Some(mut receiver) = receiver else {
                continue;
            };
            loop {
                let outcome = *receiver.borrow_and_update();
                if outcome.is_terminal() {
                    return Some(outcome);
                }
                if receiver.changed().await.is_err() {
                    return None;
                }
            }
        }
        None
    }
}

async fn release_for_command(
    transport: &Arc<dyn DeviceTransport>,
    command: &PlannedCommand,
) -> Result<(), TransportError> {
    if command.input.is_some() {
        transport.release_input_all().await
    } else {
        transport.release_all().await
    }
}

fn reduce_after_release(
    outcome: TransportOutcome,
    cancellation_requested: bool,
    terminal_zero_confirmed: bool,
) -> TransportOutcome {
    if outcome == TransportOutcome::Unknown && cancellation_requested && terminal_zero_confirmed {
        TransportOutcome::Aborted
    } else {
        outcome
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandDeadline {
    Start,
    Execution,
}

impl CommandDeadline {
    fn recovered_outcome(self, ever_accepted: bool) -> TransportOutcome {
        match (self, ever_accepted) {
            (Self::Start, false) => TransportOutcome::Rejected,
            (Self::Start | Self::Execution, true) | (Self::Execution, false) => {
                TransportOutcome::Aborted
            }
        }
    }
}

async fn command_deadline(
    start_expires_at: Instant,
    execution_limit: Duration,
    mut accepted: watch::Receiver<bool>,
) -> CommandDeadline {
    if !*accepted.borrow() {
        let start_deadline = time::sleep_until(time::Instant::from_std(start_expires_at));
        tokio::pin!(start_deadline);
        loop {
            tokio::select! {
                () = &mut start_deadline => return CommandDeadline::Start,
                changed = accepted.changed() => {
                    if changed.is_err() {
                        return CommandDeadline::Start;
                    }
                    if *accepted.borrow_and_update() {
                        break;
                    }
                }
            }
        }
    }
    time::sleep(execution_limit).await;
    CommandDeadline::Execution
}

pub async fn serve(daemon: Daemon, address: SocketAddr) -> Result<(), DaemonError> {
    if !address.ip().is_loopback() || address.ip().is_unspecified() {
        return Err(DaemonError::Server(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "keyferryd accepts loopback addresses only",
        )));
    }
    let listener = TcpListener::bind(address)
        .await
        .map_err(DaemonError::Server)?;
    axum::serve(listener, daemon.router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(DaemonError::Server)
}

pub async fn serve_tailnet(
    daemon: Daemon,
    address: SocketAddr,
    policy: RemoteApiPolicy,
) -> Result<(), DaemonError> {
    if address.ip().is_unspecified() || !is_tailscale_ip(address.ip()) {
        return Err(DaemonError::Server(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the remote API accepts a Tailscale address only",
        )));
    }
    let router = daemon.remote_router(policy)?;
    let listener = TcpListener::bind(address)
        .await
        .map_err(DaemonError::Server)?;
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(DaemonError::Server)
}

pub async fn serve_tailnet_mtls(
    daemon: Daemon,
    address: SocketAddr,
    installation: InstallationTlsSecretStore,
) -> Result<(), DaemonError> {
    if address.ip().is_unspecified() || !is_tailscale_ip(address.ip()) {
        return Err(DaemonError::Server(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the owner-authenticated remote API accepts a Tailscale address only",
        )));
    }
    let listener = TcpListener::bind(address)
        .await
        .map_err(DaemonError::Server)?;
    serve_owner_mtls_listener(daemon, listener, installation).await
}

async fn serve_owner_mtls_listener(
    daemon: Daemon,
    listener: TcpListener,
    installation: InstallationTlsSecretStore,
) -> Result<(), DaemonError> {
    daemon.configure_owner_remote_installation(&installation)?;
    let acceptor = installation
        .remote_tls_acceptor()
        .map_err(|error| DaemonError::Tls(error.to_string()))?;
    let bound_address = listener.local_addr().map_err(DaemonError::Server)?;
    let generation = {
        let mut state = daemon
            .0
            .owner_control_listener
            .lock()
            .expect("owner control listener lock");
        state.generation = state.generation.wrapping_add(1).max(1);
        state.address = Some(bound_address);
        state.generation
    };
    let _listener_guard = OwnerControlListenerGuard {
        daemon: Arc::downgrade(&daemon.0),
        generation,
    };
    let listener = OwnerTlsListener {
        listener,
        acceptor,
        control_port: bound_address.port(),
    };
    axum::serve(
        listener,
        daemon
            .owner_remote_router()
            .into_make_service_with_connect_info::<RemoteTlsPeer>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    .map_err(DaemonError::Server)
}

struct OwnerControlListenerGuard {
    daemon: std::sync::Weak<DaemonInner>,
    generation: u64,
}

impl Drop for OwnerControlListenerGuard {
    fn drop(&mut self) {
        let Some(daemon) = self.daemon.upgrade() else {
            return;
        };
        let mut state = daemon
            .owner_control_listener
            .lock()
            .expect("owner control listener lock");
        if state.generation == self.generation {
            state.address = None;
        }
    }
}

/// Serves only an untrusted routing hint on the fixed discovery port.
///
/// The response deliberately contains no device status or command surface. A controller must use
/// the returned installation ID as SNI and complete owner-rooted mutual TLS on the separate control
/// port before it trusts the candidate.
pub async fn serve_tailnet_candidate(
    address: SocketAddr,
    installation_id: [u8; 16],
) -> Result<(), DaemonError> {
    if address.ip().is_unspecified() || !is_tailscale_ip(address.ip()) {
        return Err(DaemonError::Server(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the owner gateway probe accepts a Tailscale address only",
        )));
    }
    let listener = TcpListener::bind(address)
        .await
        .map_err(DaemonError::Server)?;
    serve_owner_candidate_listener(listener, installation_id).await
}

async fn serve_owner_candidate_listener(
    listener: TcpListener,
    installation_id: [u8; 16],
) -> Result<(), DaemonError> {
    let router = owner_gateway_candidate_router(installation_id)?;
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(DaemonError::Server)
}

fn owner_gateway_candidate_router(installation_id: [u8; 16]) -> Result<Router, DaemonError> {
    let body = keyferry_gateway::OwnerGatewayCandidate::new(installation_id)
        .map_err(|error| DaemonError::Tls(error.to_string()))?
        .to_json();
    Ok(Router::new().route(
        keyferry_gateway::OWNER_GATEWAY_CANDIDATE_PATH,
        get(move || {
            let body = body.clone();
            async move { ([(header::CONTENT_TYPE, "application/json")], body) }
        }),
    ))
}

async fn authorize_owner_remote_request(
    State(state): State<OwnerRemoteMiddlewareState>,
    ConnectInfo(peer): ConnectInfo<RemoteTlsPeer>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let untrusted_keyferry_headers = request
        .headers()
        .keys()
        .filter(|name| name.as_str().starts_with("x-keyferry-"))
        .cloned()
        .collect::<Vec<_>>();
    for name in untrusted_keyferry_headers {
        request.headers_mut().remove(name);
    }
    request.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", state.local_token))
            .map_err(|_| ApiError::internal("local authorization state is invalid"))?,
    );
    request.headers_mut().insert(
        VERIFIED_CALLER_HEADER,
        HeaderValue::from_str(&installation_id_text(&peer.installation_id))
            .map_err(|_| ApiError::internal("verified caller identity is invalid"))?,
    );
    request.headers_mut().insert(
        VERIFIED_OWNER_CALLER_HEADER,
        HeaderValue::from_str(&installation_id_text(&peer.installation_id))
            .map_err(|_| ApiError::internal("verified owner identity is invalid"))?,
    );
    Ok(next.run(request).await)
}

fn installation_id_text(installation_id: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in installation_id {
        use fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

async fn authorize_remote_request(
    State(state): State<RemoteMiddlewareState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let is_probe = request.uri().path() == "/v1/gateway/probe";
    if !is_probe {
        let supplied = bearer_token(request.headers())?;
        if !secure_token_equal(supplied, state.policy.token()) {
            return Err(ApiError::auth("invalid remote bearer token"));
        }
    }

    let untrusted_keyferry_headers = request
        .headers()
        .keys()
        .filter(|name| name.as_str().starts_with("x-keyferry-"))
        .cloned()
        .collect::<Vec<_>>();
    for name in untrusted_keyferry_headers {
        request.headers_mut().remove(name);
    }
    request.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", state.local_token))
            .map_err(|_| ApiError::internal("local authorization state is invalid"))?,
    );
    request
        .headers_mut()
        .insert(VERIFIED_CALLER_HEADER, HeaderValue::from_static("tailnet"));
    Ok(next.run(request).await)
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::auth("missing or invalid bearer token"))
}

fn secure_token_equal(left: &str, right: &str) -> bool {
    let mut expected =
        Hmac::<Sha256>::new_from_slice(left.as_bytes()).expect("HMAC accepts keys of any size");
    expected.update(b"keyferry-bearer-comparison-v1");
    let expected = expected.finalize().into_bytes();
    let mut candidate =
        Hmac::<Sha256>::new_from_slice(right.as_bytes()).expect("HMAC accepts keys of any size");
    candidate.update(b"keyferry-bearer-comparison-v1");
    candidate.verify_slice(&expected).is_ok()
}

async fn gateway_probe(
    State(daemon): State<Daemon>,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<GatewayProbeResponse>, ApiError> {
    let nonce = parse_gateway_probe_nonce(raw_query.as_deref())?;
    let signing_authority = daemon
        .0
        .gateways
        .values()
        .next()
        .ok_or_else(|| ApiError::unavailable("gateway proof is not configured"))?;
    if daemon.0.devices.len() != daemon.0.gateways.len() {
        return Err(ApiError::internal(
            "gateway proof device/runtime configuration is inconsistent",
        ));
    }
    let mut devices = Vec::with_capacity(daemon.0.devices.len());
    for (id, handle) in &daemon.0.devices {
        let authority = daemon
            .gateway(id)
            .ok_or_else(|| ApiError::internal("configured device has no gateway authority"))?;
        let session = authority
            .transport
            .is_ready()
            .then(|| authority.transport.session_snapshot())
            .flatten();
        let device_id = Uuid::parse_str(id)
            .map_err(|_| ApiError::internal("configured device identifier is invalid"))?
            .into_bytes();
        let mut runtime = handle.0.lock().expect("device runtime lock");
        expire_arm(&mut runtime);
        let online = session.is_some();
        let armed = online && runtime.state.armed;
        let (link_path, protocol_session_id) = match &session {
            Some(snapshot) => (
                match snapshot.link_path {
                    TlsLinkPath::Wifi => GatewayLinkPath::Wifi,
                    TlsLinkPath::Bluetooth => GatewayLinkPath::Bluetooth,
                },
                Some(snapshot.protocol_session_id),
            ),
            None => (GatewayLinkPath::Offline, None),
        };
        devices.push(GatewayDeviceSummary {
            device_id,
            configured_here: true,
            session_online: online,
            link_path,
            tls_hmac_authenticated: online,
            protocol_session_id,
            armed,
            arm_mode: if !armed {
                GatewayArmMode::Disarmed
            } else {
                match runtime.state.arm_policy {
                    ArmPolicy::CommandScoped => GatewayArmMode::CommandScoped,
                    ArmPolicy::Temporary => GatewayArmMode::Temporary,
                    ArmPolicy::AlwaysReady => GatewayArmMode::AlwaysReady,
                }
            },
        });
    }
    let proof = signing_authority
        .transport
        .sign_gateway_proof(
            nonce,
            signing_authority.daemon_boot_id,
            GATEWAY_API_VERSION,
            devices,
        )
        .map_err(|_| ApiError::internal("gateway proof signing failed"))?;
    Ok(Json(gateway_probe_response(proof)))
}

async fn route_proof(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<RouteProofResponse>, ApiError> {
    authorize(&headers, &daemon)?;
    let controller_installation_id = headers
        .get(VERIFIED_OWNER_CALLER_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::auth("verified controller identity is absent"))
        .and_then(|value| parse_fixed_lower_hex::<16>(value, "controller identity"))?;
    let controller_nonce = parse_gateway_probe_nonce(raw_query.as_deref())?;
    let handle = daemon.lookup(&id)?;
    let transport = {
        let device = handle.0.lock().expect("device runtime lock");
        if device.state.link != keyferry_core::LinkState::Authenticated || device.current.is_some()
        {
            return Err(ApiError::conflict(
                "route proof requires an authenticated device with no active command",
            ));
        }
        device.transport.clone()
    };
    let proof = transport
        .route_proof(controller_installation_id, controller_nonce)
        .await
        .map_err(|error| map_transport_control_error("produce a route proof", error))?;
    let expected_device_id = Uuid::parse_str(&id)
        .map_err(|_| ApiError::internal("configured device identifier is invalid"))?;
    if proof.input.device_id != *expected_device_id.as_bytes()
        || proof.input.controller_installation_id != controller_installation_id
        || proof.input.controller_nonce != controller_nonce
    {
        return Err(ApiError::internal(
            "endpoint route proof does not match the selected route",
        ));
    }
    let bytes = keyferry_gateway::encode_route_proof_response(&proof.input, &proof.tag)
        .map_err(|_| ApiError::internal("endpoint route proof is invalid"))?;
    let proof_digest: [u8; 32] = Sha256::digest(bytes).into();
    daemon
        .0
        .owner_routes
        .lock()
        .expect("owner route lock")
        .insert(
            (id, controller_installation_id),
            OwnerRouteLease {
                endpoint_session_id: proof.input.endpoint_session_id,
                proof_digest,
                expires_at: Instant::now()
                    + Duration::from_millis(keyferry_gateway::ROUTE_PROOF_TTL_MS as u64),
            },
        );
    Ok(Json(RouteProofResponse {
        proof: encode_hex(&bytes),
    }))
}

async fn yield_gateway(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<GatewayYieldResponse>, ApiError> {
    authorize(&headers, &daemon)?;
    let _ = id;
    Err(ApiError::conflict(
        "untargeted gateway yield is retired; use a targeted handoff",
    ))
}

async fn prepare_gateway_handoff(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<PrepareGatewayHandoffRequest>,
) -> Result<Json<GatewayHandoffResponse>, ApiError> {
    authorize(&headers, &daemon)?;
    if request.transaction_id.get_version_num() != 7 {
        return Err(ApiError::bad_request("handoff.transaction_id"));
    }
    let previous_installation_id = parse_fixed_lower_hex::<16>(
        &request.previous_gateway_installation_id,
        "previous gateway identity",
    )?;
    let gateway = daemon
        .gateway(&id)
        .ok_or_else(|| ApiError::conflict("targeted handoff is not configured here"))?;
    let target_installation_id = gateway.transport.host_id();
    if target_installation_id == previous_installation_id {
        return Err(ApiError::conflict(
            "this computer already identifies as the current gateway",
        ));
    }
    let configured_installation = daemon
        .0
        .owner_installation
        .lock()
        .expect("owner installation lock")
        .clone()
        .ok_or_else(|| ApiError::unavailable("owner-authenticated control is not configured"))?;
    if configured_installation.installation_id() != target_installation_id {
        return Err(ApiError::internal(
            "owner-control identity does not match this gateway",
        ));
    }
    let owner_control = *daemon
        .0
        .owner_control_listener
        .lock()
        .expect("owner control listener lock");
    let target_control_address = owner_control.address.ok_or_else(|| {
        ApiError::unavailable("owner-authenticated control listener is not ready")
    })?;
    let listener = daemon.0.gateway_listeners.snapshot();
    let target_address = listener
        .addresses
        .iter()
        .copied()
        .find(|address| address.is_ipv4())
        .ok_or_else(|| ApiError::unavailable("no selected LAN listener is ready"))?;
    if target_address.port() != keyferry_protocol::roaming::DEVICE_TLS_PORT {
        return Err(ApiError::internal(
            "selected LAN listener uses the wrong device TLS port",
        ));
    }
    let handle = daemon.lookup(&id)?;
    {
        let mut device = handle.0.lock().expect("device runtime lock");
        if device
            .gateway_handoff
            .as_ref()
            .is_some_and(|reservation| gateway_handoff_phase_is_terminal(&reservation.phase))
        {
            device.gateway_handoff = None;
        }
        if device.current.is_some()
            || device.stream_reservation.is_some()
            || device.maintenance
            || device.gateway_handoff.is_some()
        {
            return Err(ApiError::conflict(
                "device is busy or already has a gateway handoff",
            ));
        }
        if device.state.link == keyferry_core::LinkState::Authenticated {
            return Err(ApiError::conflict(
                "device is already authenticated to this gateway",
            ));
        }
    }
    gateway
        .transport
        .reserve_gateway_handoff_candidate()
        .await
        .map_err(|error| map_transport_control_error("reserve handoff capacity", error))?;
    let mut readiness_nonce = [0_u8; 16];
    if getrandom::fill(&mut readiness_nonce).is_err()
        || readiness_nonce.iter().all(|byte| *byte == 0)
    {
        gateway.transport.cancel_gateway_handoff_candidate();
        return Err(ApiError::internal(
            "could not create handoff readiness nonce",
        ));
    }
    let reservation = GatewayHandoffReservation {
        transaction_id: request.transaction_id,
        previous_installation_id,
        target_installation_id,
        readiness_nonce,
        target_address,
        listener_generation: listener.generation,
        target_control_port: target_control_address.port(),
        proof_digest: None,
        expires_at: Instant::now()
            + Duration::from_millis(
                keyferry_protocol::roaming::GATEWAY_HANDOFF_RESERVATION_MS as u64,
            ),
        phase: "ready".to_owned(),
        reason: None,
    };
    {
        let mut device = handle.0.lock().expect("device runtime lock");
        if device.gateway_handoff.is_some() {
            gateway.transport.cancel_gateway_handoff_candidate();
            return Err(ApiError::conflict("gateway handoff raced another request"));
        }
        device.gateway_handoff = Some(reservation.clone());
    }
    Ok(Json(gateway_handoff_response(&reservation)))
}

async fn get_gateway_handoff(
    Path((id, transaction_id)): Path<(String, Uuid)>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<GatewayHandoffResponse>, ApiError> {
    authorize(&headers, &daemon)?;
    let handle = daemon.lookup(&id)?;
    let device = handle.0.lock().expect("device runtime lock");
    let reservation = device
        .gateway_handoff
        .as_ref()
        .filter(|reservation| reservation.transaction_id == transaction_id)
        .ok_or_else(|| ApiError::not_found("gateway handoff was not found"))?;
    Ok(Json(gateway_handoff_response(reservation)))
}

async fn cancel_gateway_handoff_reservation(
    Path((id, transaction_id)): Path<(String, Uuid)>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<GatewayHandoffResponse>, ApiError> {
    authorize(&headers, &daemon)?;
    let handle = daemon.lookup(&id)?;
    let response = {
        let mut device = handle.0.lock().expect("device runtime lock");
        let reservation = device
            .gateway_handoff
            .as_ref()
            .filter(|reservation| reservation.transaction_id == transaction_id)
            .ok_or_else(|| ApiError::not_found("gateway handoff was not found"))?;
        if !matches!(reservation.phase.as_str(), "ready" | "confirmed_ready") {
            return Err(ApiError::conflict(
                "gateway handoff may already have reached the endpoint",
            ));
        }
        let mut response = gateway_handoff_response(reservation);
        response.phase = "failed_unchanged".to_owned();
        response.terminal = true;
        response.reason = Some("local_reservation_cancelled".to_owned());
        device.gateway_handoff = None;
        response
    };
    if let Some(gateway) = daemon.gateway(&id) {
        gateway.transport.cancel_gateway_handoff_candidate();
    }
    Ok(Json(response))
}

async fn confirm_gateway_handoff_ready(
    Path((id, transaction_id)): Path<(String, Uuid)>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<ConfirmGatewayHandoffReadyRequest>,
) -> Result<Json<ConfirmGatewayHandoffReadyResponse>, ApiError> {
    authorize(&headers, &daemon)?;
    let caller = headers
        .get(VERIFIED_OWNER_CALLER_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::auth("verified owner identity is absent"))?;
    let caller_installation_id = parse_fixed_lower_hex::<16>(caller, "owner caller identity")?;
    let challenge = parse_fixed_lower_hex::<16>(&request.challenge, "readiness challenge")?;
    let readiness_nonce = parse_fixed_lower_hex::<16>(&request.readiness_nonce, "readiness nonce")?;
    let proof_digest = parse_fixed_lower_hex::<32>(&request.proof_digest, "proof digest")?;
    let listener = daemon.0.gateway_listeners.snapshot();
    let owner_control = *daemon
        .0
        .owner_control_listener
        .lock()
        .expect("owner control listener lock");
    let handle = daemon.lookup(&id)?;
    let (target_installation_id, listener_generation, daemon_boot_id, remaining_ms) = {
        let mut device = handle.0.lock().expect("device runtime lock");
        let reservation = device
            .gateway_handoff
            .as_mut()
            .filter(|reservation| reservation.transaction_id == transaction_id)
            .ok_or_else(|| ApiError::not_found("gateway handoff was not found"))?;
        if Instant::now() >= reservation.expires_at
            || !matches!(reservation.phase.as_str(), "ready" | "confirmed_ready")
        {
            return Err(ApiError::conflict("gateway handoff readiness expired"));
        }
        if caller_installation_id != reservation.previous_installation_id
            || readiness_nonce != reservation.readiness_nonce
            || listener.generation != reservation.listener_generation
            || !listener.addresses.contains(&reservation.target_address)
            || owner_control.address.map(|address| address.port())
                != Some(reservation.target_control_port)
        {
            return Err(ApiError::conflict("gateway handoff readiness changed"));
        }
        if reservation
            .proof_digest
            .is_some_and(|existing| existing != proof_digest)
        {
            return Err(ApiError::conflict("gateway handoff proof binding changed"));
        }
        reservation.proof_digest = Some(proof_digest);
        reservation.phase = "confirmed_ready".to_owned();
        (
            reservation.target_installation_id,
            reservation.listener_generation,
            daemon.0.epoch,
            reservation
                .expires_at
                .saturating_duration_since(Instant::now())
                .as_millis() as u64,
        )
    };
    Ok(Json(ConfirmGatewayHandoffReadyResponse {
        transaction_id,
        challenge: encode_hex(&challenge),
        readiness_nonce: encode_hex(&readiness_nonce),
        proof_digest: encode_hex(&proof_digest),
        target_installation_id: encode_hex(&target_installation_id),
        listener_generation,
        daemon_boot_id,
        remaining_ms,
    }))
}

async fn receive_gateway_handoff_outcome(
    Path((id, transaction_id)): Path<(String, Uuid)>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<ReportGatewayHandoffOutcomeRequest>,
) -> Result<Json<GatewayHandoffResponse>, ApiError> {
    authorize(&headers, &daemon)?;
    let caller = headers
        .get(VERIFIED_OWNER_CALLER_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::auth("verified owner identity is absent"))?;
    let caller_installation_id = parse_fixed_lower_hex::<16>(caller, "owner caller identity")?;
    if !matches!(
        request.phase.as_str(),
        "failed_restored" | "failed_unchanged" | "recovery_unavailable" | "uncertain"
    ) || request
        .reason
        .as_ref()
        .is_some_and(|reason| reason.is_empty() || reason.len() > 96 || !reason.is_ascii())
    {
        return Err(ApiError::bad_request("handoff.outcome"));
    }
    let handle = daemon.lookup(&id)?;
    let response = {
        let mut device = handle.0.lock().expect("device runtime lock");
        let reservation = device
            .gateway_handoff
            .as_mut()
            .filter(|reservation| reservation.transaction_id == transaction_id)
            .ok_or_else(|| ApiError::not_found("gateway handoff was not found"))?;
        if caller_installation_id != reservation.previous_installation_id {
            return Err(ApiError::auth(
                "handoff outcome came from the wrong previous gateway",
            ));
        }
        if reservation.phase == "transferred" {
            return Err(ApiError::conflict(
                "a completed transfer cannot be replaced by a rollback outcome",
            ));
        }
        if gateway_handoff_phase_is_terminal(&reservation.phase)
            && (reservation.phase != request.phase || reservation.reason != request.reason)
        {
            return Err(ApiError::conflict("gateway handoff outcome changed"));
        }
        reservation.phase.clone_from(&request.phase);
        reservation.reason.clone_from(&request.reason);
        gateway_handoff_response(reservation)
    };
    if let Some(gateway) = daemon.gateway(&id) {
        gateway.transport.cancel_gateway_handoff_candidate();
    }
    Ok(Json(response))
}

async fn start_gateway_handoff(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    ConnectInfo(peer): ConnectInfo<RemoteTlsPeer>,
    headers: HeaderMap,
    Json(request): Json<StartGatewayHandoffRequest>,
) -> Result<Json<GatewayHandoffResponse>, ApiError> {
    if request.transaction_id.get_version_num() != 7 {
        return Err(ApiError::bad_request("handoff.transaction_id"));
    }
    let (target_installation_id, route) = verified_owner_route(&headers, &daemon, &id)?;
    if peer.installation_id != target_installation_id
        || !is_tailscale_ip(peer.address.ip())
        || request.target_control_port != peer.control_port
    {
        return Err(ApiError::auth("handoff target identity is inconsistent"));
    }
    let target_control_address = SocketAddr::new(peer.address.ip(), request.target_control_port);
    start_gateway_handoff_core(
        daemon,
        id,
        request,
        target_installation_id,
        route,
        target_control_address,
    )
    .await
}

async fn start_local_gateway_handoff(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<StartLocalGatewayHandoffRequest>,
) -> Result<Json<GatewayHandoffResponse>, ApiError> {
    authorize(&headers, &daemon)?;
    if request.transaction_id.get_version_num() != 7 {
        return Err(ApiError::bad_request("handoff.transaction_id"));
    }
    let target_installation_id =
        parse_fixed_lower_hex::<16>(&request.target_installation_id, "target gateway identity")?;
    let previous_installation_id = parse_fixed_lower_hex::<16>(
        &request.previous_installation_id,
        "previous gateway identity",
    )?;
    let gateway = daemon
        .gateway(&id)
        .ok_or_else(|| ApiError::conflict("targeted handoff is not configured here"))?;
    if gateway.transport.host_id() != previous_installation_id
        || target_installation_id == previous_installation_id
    {
        return Err(ApiError::conflict(
            "handoff source or target identity is inconsistent",
        ));
    }
    let target_gateway_address = request
        .target_gateway_address
        .parse::<std::net::IpAddr>()
        .map_err(|_| ApiError::bad_request("handoff.target_gateway_address"))?;
    if !is_tailscale_ip(target_gateway_address) || request.target_control_port == 0 {
        return Err(ApiError::bad_request("handoff.target_gateway_route"));
    }
    let route = create_owner_route_for_target(&daemon, &id, target_installation_id).await?;
    let target_control_address =
        SocketAddr::new(target_gateway_address, request.target_control_port);
    let start = StartGatewayHandoffRequest {
        transaction_id: request.transaction_id,
        endpoint_session_id: encode_hex(&route.endpoint_session_id),
        proof_digest: encode_hex(&route.proof_digest),
        readiness_nonce: request.readiness_nonce,
        target_ipv4: request.target_ipv4,
        target_port: request.target_port,
        target_control_port: request.target_control_port,
    };
    start_gateway_handoff_core(
        daemon,
        id,
        start,
        target_installation_id,
        route,
        target_control_address,
    )
    .await
}

async fn create_owner_route_for_target(
    daemon: &Daemon,
    id: &str,
    target_installation_id: [u8; 16],
) -> Result<OwnerRouteLease, ApiError> {
    let handle = daemon.lookup(id)?;
    let transport = {
        let device = handle.0.lock().expect("device runtime lock");
        if device.state.link != keyferry_core::LinkState::Authenticated || device.current.is_some()
        {
            return Err(ApiError::conflict(
                "route proof requires an authenticated device with no active command",
            ));
        }
        device.transport.clone()
    };
    let mut controller_nonce = [0_u8; 32];
    if getrandom::fill(&mut controller_nonce).is_err()
        || controller_nonce.iter().all(|byte| *byte == 0)
    {
        return Err(ApiError::internal("could not create route-proof nonce"));
    }
    let proof = transport
        .route_proof(target_installation_id, controller_nonce)
        .await
        .map_err(|error| map_transport_control_error("produce a route proof", error))?;
    let expected_device_id = Uuid::parse_str(id)
        .map_err(|_| ApiError::internal("configured device identifier is invalid"))?;
    if proof.input.device_id != *expected_device_id.as_bytes()
        || proof.input.controller_installation_id != target_installation_id
        || proof.input.controller_nonce != controller_nonce
    {
        return Err(ApiError::internal(
            "endpoint route proof does not match the selected target",
        ));
    }
    let bytes = keyferry_gateway::encode_route_proof_response(&proof.input, &proof.tag)
        .map_err(|_| ApiError::internal("endpoint route proof is invalid"))?;
    let route = OwnerRouteLease {
        endpoint_session_id: proof.input.endpoint_session_id,
        proof_digest: Sha256::digest(bytes).into(),
        expires_at: Instant::now()
            + Duration::from_millis(keyferry_gateway::ROUTE_PROOF_TTL_MS as u64),
    };
    let current_session = daemon
        .gateway(id)
        .and_then(|gateway| gateway.transport.session_snapshot())
        .ok_or_else(|| ApiError::auth("the endpoint session is absent after route proof"))?;
    if current_session.protocol_session_id != route.endpoint_session_id {
        return Err(ApiError::auth(
            "the endpoint session changed after route proof",
        ));
    }
    daemon
        .0
        .owner_routes
        .lock()
        .expect("owner route lock")
        .insert((id.to_owned(), target_installation_id), route);
    Ok(route)
}

async fn start_gateway_handoff_core(
    daemon: Daemon,
    id: String,
    request: StartGatewayHandoffRequest,
    target_installation_id: [u8; 16],
    route: OwnerRouteLease,
    target_control_address: SocketAddr,
) -> Result<Json<GatewayHandoffResponse>, ApiError> {
    let endpoint_session_id =
        parse_fixed_lower_hex::<16>(&request.endpoint_session_id, "endpoint session")?;
    let proof_digest = parse_fixed_lower_hex::<32>(&request.proof_digest, "proof digest")?;
    let readiness_nonce = parse_fixed_lower_hex::<16>(&request.readiness_nonce, "readiness nonce")?;
    if route.endpoint_session_id != endpoint_session_id || route.proof_digest != proof_digest {
        return Err(ApiError::auth(
            "handoff does not match the fresh endpoint route proof",
        ));
    }
    let target_ipv4 = request
        .target_ipv4
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| ApiError::bad_request("handoff.target_ipv4"))?;
    if !target_ipv4.is_private()
        || request.target_port != keyferry_protocol::roaming::DEVICE_TLS_PORT
        || request.target_control_port == 0
    {
        return Err(ApiError::bad_request("handoff.target_route"));
    }
    let handle = daemon.lookup(&id)?;
    let transport = {
        let device = handle.0.lock().expect("device runtime lock");
        if device.state.link != keyferry_core::LinkState::Authenticated
            || device.current.is_some()
            || device.stream_reservation.is_some()
            || device.maintenance
            || device.state.armed
        {
            return Err(ApiError::conflict(
                "handoff requires an authenticated, disarmed, idle endpoint",
            ));
        }
        if !device.transport.supports_targeted_gateway_transfer() {
            return Err(ApiError::conflict("targeted_handoff_unsupported"));
        }
        device.transport.clone()
    };
    confirm_target_gateway_readiness(
        &daemon,
        &id,
        request.transaction_id,
        target_installation_id,
        target_control_address,
        readiness_nonce,
        proof_digest,
    )
    .await?;
    let start = keyferry_protocol::gateway_handoff::Start {
        transaction_id: *request.transaction_id.as_bytes(),
        target_installation_id,
        readiness_nonce,
        proof_digest,
        target_ipv4: target_ipv4.octets(),
        target_port: request.target_port,
        target_valid_ms: keyferry_protocol::roaming::GATEWAY_HANDOFF_TARGET_VALID_MS as u32,
        recovery_ms: keyferry_protocol::roaming::GATEWAY_HANDOFF_RECOVERY_MS as u32,
    };
    {
        let mut device = handle.0.lock().expect("device runtime lock");
        if let Some(handoff) = device.outgoing_gateway_handoff.as_mut() {
            if Instant::now() >= handoff.expires_at
                && !gateway_handoff_phase_is_terminal(&handoff.phase)
            {
                handoff.phase = "uncertain".to_owned();
                handoff.reason = Some("handoff_reconciliation_expired".to_owned());
            }
        }
        if device.current.is_some()
            || device.stream_reservation.is_some()
            || device.maintenance
            || device.state.armed
            || device
                .outgoing_gateway_handoff
                .as_ref()
                .is_some_and(|handoff| !gateway_handoff_phase_is_terminal(&handoff.phase))
        {
            return Err(ApiError::conflict(
                "device changed while the target gateway was being verified",
            ));
        }
        device.outgoing_gateway_handoff = Some(OutgoingGatewayHandoff {
            transaction_id: request.transaction_id,
            target_installation_id,
            target_control_address,
            phase: "starting".to_owned(),
            reason: None,
            expires_at: Instant::now()
                + Duration::from_millis(
                    (keyferry_protocol::roaming::GATEWAY_HANDOFF_TARGET_VALID_MS
                        + keyferry_protocol::roaming::GATEWAY_HANDOFF_RECOVERY_MS
                        + keyferry_protocol::roaming::GATEWAY_HANDOFF_RESERVATION_MS)
                        as u64,
                ),
        });
    }
    let endpoint_status = match transport
        .gateway_handoff(keyferry_protocol::gateway_handoff::Request::Start(start))
        .await
    {
        Ok(status) => status,
        Err(error) => {
            let mut device = handle.0.lock().expect("device runtime lock");
            if let Some(handoff) = device.outgoing_gateway_handoff.as_mut() {
                if error == TransportError::AcceptedButLost {
                    handoff.phase = "start_unresolved".to_owned();
                    handoff.reason = Some("start_confirmation_lost".to_owned());
                } else {
                    device.outgoing_gateway_handoff = None;
                }
            }
            return Err(map_transport_control_error("start targeted handoff", error));
        }
    };
    {
        let mut device = handle.0.lock().expect("device runtime lock");
        if let Some(handoff) = device.outgoing_gateway_handoff.as_mut() {
            let response = endpoint_handoff_response(
                request.transaction_id,
                &endpoint_status,
                Some(target_ipv4.to_string()),
                Some(request.target_port),
            );
            handoff.phase = response.phase;
            handoff.reason = response.reason;
        }
    }
    daemon
        .0
        .owner_routes
        .lock()
        .expect("owner route lock")
        .remove(&(id.clone(), target_installation_id));
    Ok(Json(endpoint_handoff_response(
        request.transaction_id,
        &endpoint_status,
        Some(target_ipv4.to_string()),
        Some(request.target_port),
    )))
}

fn gateway_handoff_response(reservation: &GatewayHandoffReservation) -> GatewayHandoffResponse {
    let terminal = gateway_handoff_phase_is_terminal(&reservation.phase);
    GatewayHandoffResponse {
        transaction_id: reservation.transaction_id,
        phase: reservation.phase.clone(),
        terminal,
        target_installation_id: encode_hex(&reservation.target_installation_id),
        previous_installation_id: encode_hex(&reservation.previous_installation_id),
        target_ipv4: Some(reservation.target_address.ip().to_string()),
        target_port: Some(reservation.target_address.port()),
        target_control_port: Some(reservation.target_control_port),
        readiness_nonce: (!terminal).then(|| encode_hex(&reservation.readiness_nonce)),
        listener_generation: Some(reservation.listener_generation),
        reason: reservation.reason.clone(),
    }
}

fn gateway_handoff_phase_is_terminal(phase: &str) -> bool {
    matches!(
        phase,
        "transferred"
            | "failed_restored"
            | "failed_unchanged"
            | "recovery_unavailable"
            | "uncertain"
    )
}

fn endpoint_handoff_response(
    transaction_id: Uuid,
    status: &keyferry_protocol::gateway_handoff::Status,
    target_ipv4: Option<String>,
    target_port: Option<u16>,
) -> GatewayHandoffResponse {
    let phase = match status.phase {
        keyferry_protocol::gateway_handoff_phase::RELEASING => "releasing",
        keyferry_protocol::gateway_handoff_phase::TARGETING => "targeting",
        keyferry_protocol::gateway_handoff_phase::TARGET_PROVISIONAL => "target_provisional",
        keyferry_protocol::gateway_handoff_phase::TRANSFERRED => "transferred",
        keyferry_protocol::gateway_handoff_phase::RESTORED => "failed_restored",
        keyferry_protocol::gateway_handoff_phase::NOT_STARTED => "failed_unchanged",
        keyferry_protocol::gateway_handoff_phase::RECOVERY_UNAVAILABLE => "recovery_unavailable",
        _ => "uncertain",
    }
    .to_owned();
    let terminal = matches!(
        status.phase,
        keyferry_protocol::gateway_handoff_phase::TRANSFERRED
            | keyferry_protocol::gateway_handoff_phase::RESTORED
            | keyferry_protocol::gateway_handoff_phase::NOT_STARTED
            | keyferry_protocol::gateway_handoff_phase::RECOVERY_UNAVAILABLE
    );
    GatewayHandoffResponse {
        transaction_id,
        phase,
        terminal,
        target_installation_id: encode_hex(&status.target_installation_id),
        previous_installation_id: encode_hex(&status.previous_installation_id),
        target_ipv4,
        target_port,
        target_control_port: None,
        readiness_nonce: None,
        listener_generation: None,
        reason: endpoint_handoff_reason(status),
    }
}

fn endpoint_handoff_reason(status: &keyferry_protocol::gateway_handoff::Status) -> Option<String> {
    if status.reason != keyferry_protocol::gateway_handoff_reason::NONE {
        Some(format!("endpoint_reason_{}", status.reason))
    } else if status.status != keyferry_protocol::gateway_handoff_status::OK {
        Some(format!("endpoint_status_{}", status.status))
    } else {
        None
    }
}

async fn report_gateway_handoff_outcome(
    daemon: &Daemon,
    device_id: &str,
    transaction_id: Uuid,
    target_installation_id: [u8; 16],
    target_control_address: SocketAddr,
    phase: &str,
    reason: Option<&str>,
) -> Result<(), ApiError> {
    let body = serde_json::to_vec(&ReportGatewayHandoffOutcomeRequest {
        phase: phase.to_owned(),
        reason: reason.map(str::to_owned),
    })
    .map_err(|_| ApiError::internal("could not encode handoff outcome"))?;
    owner_callback(
        daemon,
        target_installation_id,
        target_control_address,
        &format!("/v2/devices/{device_id}/gateway/handoffs/{transaction_id}/outcome"),
        &body,
        "target gateway outcome callback failed",
        "target gateway did not accept the handoff outcome",
    )
    .await
    .map(|_| ())
}

/// Posts one bounded owner-mTLS callback to a peer gateway and requires HTTP 200.
async fn owner_callback(
    daemon: &Daemon,
    target_installation_id: [u8; 16],
    target_control_address: SocketAddr,
    path: &str,
    body: &[u8],
    failed: &'static str,
    unsuccessful: &'static str,
) -> Result<Vec<u8>, ApiError> {
    const CALLBACK_TIMEOUT: Duration = Duration::from_secs(2);
    const MAX_RESPONSE_BYTES: usize = 4096;
    let installation = daemon
        .0
        .owner_installation
        .lock()
        .expect("owner installation lock")
        .clone()
        .ok_or_else(|| ApiError::conflict("targeted_handoff_unsupported"))?;
    let connector = installation
        .remote_tls_connector()
        .map_err(|_| ApiError::internal("handoff callback TLS is unavailable"))?;
    match forward::owner_exchange(
        &connector,
        &target_installation_id,
        target_control_address,
        "POST",
        path,
        Some(body),
        CALLBACK_TIMEOUT,
        MAX_RESPONSE_BYTES,
    )
    .await
    {
        forward::OwnerExchange::Response {
            status: 200, body, ..
        } => Ok(body),
        forward::OwnerExchange::Response { .. } => Err(ApiError::unavailable(unsuccessful)),
        forward::OwnerExchange::NotSent | forward::OwnerExchange::Uncertain => {
            Err(ApiError::unavailable(failed))
        }
    }
}

async fn confirm_target_gateway_readiness(
    daemon: &Daemon,
    device_id: &str,
    transaction_id: Uuid,
    target_installation_id: [u8; 16],
    target_control_address: SocketAddr,
    readiness_nonce: [u8; 16],
    proof_digest: [u8; 32],
) -> Result<(), ApiError> {
    keyferry_gateway::installation_gateway_name(&target_installation_id)
        .map_err(|_| ApiError::bad_request("handoff.target_identity"))?;
    let mut challenge = [0_u8; 16];
    if getrandom::fill(&mut challenge).is_err() || challenge.iter().all(|byte| *byte == 0) {
        return Err(ApiError::internal(
            "could not create handoff readiness challenge",
        ));
    }
    let body = serde_json::to_vec(&ConfirmGatewayHandoffReadyRequest {
        challenge: encode_hex(&challenge),
        readiness_nonce: encode_hex(&readiness_nonce),
        proof_digest: encode_hex(&proof_digest),
    })
    .map_err(|_| ApiError::internal("could not encode handoff readiness"))?;
    let response_body = owner_callback(
        daemon,
        target_installation_id,
        target_control_address,
        &format!("/v2/devices/{device_id}/gateway/handoffs/{transaction_id}/ready"),
        &body,
        "target gateway readiness failed",
        "target gateway did not confirm readiness",
    )
    .await?;
    let ready: ConfirmGatewayHandoffReadyResponse = serde_json::from_slice(&response_body)
        .map_err(|_| ApiError::unavailable("target gateway readiness was malformed"))?;
    if ready.transaction_id != transaction_id
        || ready.challenge != encode_hex(&challenge)
        || ready.readiness_nonce != encode_hex(&readiness_nonce)
        || ready.proof_digest != encode_hex(&proof_digest)
        || ready.target_installation_id != encode_hex(&target_installation_id)
        || ready.listener_generation == 0
        || ready.remaining_ms == 0
    {
        return Err(ApiError::unavailable(
            "target gateway readiness binding did not match",
        ));
    }
    Ok(())
}

fn parse_fixed_lower_hex<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], ApiError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::auth(format!("verified {field} is malformed")));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| ApiError::auth(format!("verified {field} is malformed")))?;
    }
    Ok(output)
}

fn parse_gateway_probe_nonce(raw_query: Option<&str>) -> Result<[u8; 32], ApiError> {
    let query = raw_query.ok_or_else(|| ApiError::bad_request("nonce is required"))?;
    let value = query
        .strip_prefix("nonce=")
        .filter(|value| !value.contains('&'))
        .ok_or_else(|| ApiError::bad_request("nonce query is malformed"))?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(
            "nonce must be exactly 32 bytes of hexadecimal",
        ));
    }
    let mut nonce = [0_u8; 32];
    for (index, byte) in nonce.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| ApiError::bad_request("nonce is malformed"))?;
    }
    Ok(nonce)
}

fn gateway_probe_response(proof: SignedGatewayProof) -> GatewayProbeResponse {
    GatewayProbeResponse {
        protocol_version: proof.payload.protocol_version,
        request_nonce: encode_hex(&proof.payload.request_nonce),
        gateway_id: encode_hex(&proof.payload.gateway_id),
        daemon_boot_id: encode_hex(&proof.payload.daemon_boot_id),
        api_version: proof.payload.api_version,
        devices: proof
            .payload
            .devices
            .into_iter()
            .map(|device| GatewayProbeDevice {
                device_id: encode_hex(&device.device_id),
                configured_here: device.configured_here,
                session_online: device.session_online,
                link_path: match device.link_path {
                    GatewayLinkPath::Offline => "offline",
                    GatewayLinkPath::Wifi => "wifi",
                    GatewayLinkPath::Bluetooth => "bluetooth",
                }
                .to_owned(),
                tls_hmac_authenticated: device.tls_hmac_authenticated,
                protocol_session_id: device
                    .protocol_session_id
                    .map(|session_id| encode_hex(&session_id)),
                armed: device.armed,
                arm_mode: match device.arm_mode {
                    GatewayArmMode::Disarmed => "disarmed",
                    GatewayArmMode::CommandScoped => "command_scoped",
                    GatewayArmMode::Temporary => "temporary",
                    GatewayArmMode::AlwaysReady => "always_ready",
                }
                .to_owned(),
            })
            .collect(),
        signature_der: encode_hex(&proof.signature_der),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn authorize(headers: &HeaderMap, daemon: &Daemon) -> Result<String, ApiError> {
    let supplied = bearer_token(headers)?;
    if !secure_token_equal(supplied, daemon.token()) {
        return Err(ApiError::auth("invalid bearer token"));
    }
    Ok(headers
        .get("x-keyferry-caller")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .unwrap_or("local")
        .to_owned())
}

fn authorize_owner_mutation(
    headers: &HeaderMap,
    daemon: &Daemon,
    device_id: &str,
) -> Result<String, ApiError> {
    let caller = authorize(headers, daemon)?;
    let Some(owner_caller) = headers
        .get(VERIFIED_OWNER_CALLER_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(caller);
    };
    let installation_id = parse_fixed_lower_hex::<16>(owner_caller, "owner caller identity")?;
    let key = (device_id.to_owned(), installation_id);
    let now = Instant::now();
    let mut routes = daemon.0.owner_routes.lock().expect("owner route lock");
    routes.retain(|_, route| route.expires_at > now);
    let route = routes
        .get(&key)
        .ok_or_else(|| ApiError::auth("a fresh endpoint route proof is required"))?;
    let current_session = daemon
        .gateway(device_id)
        .and_then(|gateway| gateway.transport.session_snapshot())
        .ok_or_else(|| ApiError::auth("the endpoint session is absent after route proof"))?;
    if current_session.protocol_session_id != route.endpoint_session_id {
        routes.remove(&key);
        return Err(ApiError::auth(
            "the endpoint session changed after route proof",
        ));
    }
    Ok(caller)
}

fn verified_owner_route(
    headers: &HeaderMap,
    daemon: &Daemon,
    device_id: &str,
) -> Result<([u8; 16], OwnerRouteLease), ApiError> {
    authorize(headers, daemon)?;
    let owner_caller = headers
        .get(VERIFIED_OWNER_CALLER_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::auth("verified controller identity is absent"))?;
    let installation_id = parse_fixed_lower_hex::<16>(owner_caller, "owner caller identity")?;
    let key = (device_id.to_owned(), installation_id);
    let now = Instant::now();
    let mut routes = daemon.0.owner_routes.lock().expect("owner route lock");
    routes.retain(|_, route| route.expires_at > now);
    let route = routes
        .get(&key)
        .copied()
        .ok_or_else(|| ApiError::auth("a fresh endpoint route proof is required"))?;
    let current_session = daemon
        .gateway(device_id)
        .and_then(|gateway| gateway.transport.session_snapshot())
        .ok_or_else(|| ApiError::auth("the endpoint session is absent after route proof"))?;
    if current_session.protocol_session_id != route.endpoint_session_id {
        routes.remove(&key);
        return Err(ApiError::auth(
            "the endpoint session changed after route proof",
        ));
    }
    Ok((installation_id, route))
}

async fn capabilities(
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<TextStreamCapabilities>, ApiError> {
    authorize(&headers, &daemon)?;
    Ok(Json(daemon.capabilities()))
}

async fn create_text_stream(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<CreateTextStreamRequest>,
) -> Result<(StatusCode, Json<TextStreamReceipt>), ApiError> {
    let caller = authorize_owner_mutation(&headers, &daemon, &id)?;
    Ok((
        StatusCode::CREATED,
        Json(daemon.create_text_stream(&id, caller, request)?),
    ))
}

async fn text_stream_part(
    Path((id, job_id, index)): Path<(String, String, String)>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<TextStreamReceipt>), ApiError> {
    let caller = authorize_owner_mutation(&headers, &daemon, &id)?;
    let request: TextStreamPartRequest = parse_payload_body(&body)?;
    let job_id = parse_uuid_v7(&job_id, "text_stream.job_id")?;
    let index = parse_decimal_counter(&index)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(
            daemon
                .submit_text_stream_part(&id, caller, job_id, index, request)
                .await?,
        ),
    ))
}

async fn finish_text_stream(
    Path((id, job_id)): Path<(String, String)>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<TextStreamFinishRequest>,
) -> Result<Json<TextStreamReceipt>, ApiError> {
    let caller = authorize_owner_mutation(&headers, &daemon, &id)?;
    let job_id = parse_uuid_v7(&job_id, "text_stream.job_id")?;
    Ok(Json(
        daemon.finish_text_stream(&id, caller, job_id, request)?,
    ))
}

async fn get_text_stream(
    Path((id, job_id)): Path<(String, String)>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<TextStreamReceipt>, ApiError> {
    let caller = authorize(&headers, &daemon)?;
    let job_id = parse_uuid_v7(&job_id, "text_stream.job_id")?;
    Ok(Json(daemon.text_stream_status(&id, caller, job_id)?))
}

async fn renew_text_stream(
    Path((id, job_id)): Path<(String, String)>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<TextStreamControlRequest>,
) -> Result<Json<TextStreamReceipt>, ApiError> {
    let caller = authorize(&headers, &daemon)?;
    let job_id = parse_uuid_v7(&job_id, "text_stream.job_id")?;
    Ok(Json(
        daemon.renew_text_stream(&id, caller, job_id, request)?,
    ))
}

async fn cancel_text_stream(
    Path((id, job_id)): Path<(String, String)>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<TextStreamCancelRequest>,
) -> Result<Json<TextStreamReceipt>, ApiError> {
    let caller = authorize(&headers, &daemon)?;
    let job_id = parse_uuid_v7(&job_id, "text_stream.job_id")?;
    Ok(Json(
        daemon.cancel_text_stream(&id, caller, job_id, request)?,
    ))
}

async fn list_devices(
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<DevicesResponse>, ApiError> {
    authorize(&headers, &daemon)?;
    let devices = daemon
        .0
        .devices
        .keys()
        .map(|id| daemon.device_view(id))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(DevicesResponse { devices }))
}

async fn get_device(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<DeviceView>, ApiError> {
    authorize(&headers, &daemon)?;
    Ok(Json(daemon.device_view(&id)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePublishRequest {
    bytes: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSetPublishRequest {
    files: Vec<FileSetUpload>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSetUpload {
    name: String,
    bytes: Vec<u8>,
}

async fn post_files(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<FileSetStatusView>, ApiError> {
    authorize_owner_mutation(&headers, &daemon, &id)?;
    let request: FileSetPublishRequest = parse_payload_body(&body)?;
    let files = request
        .files
        .into_iter()
        .map(|file| keyferry_protocol::file_set::File {
            name: file.name,
            bytes: file.bytes,
        })
        .collect();
    Ok(Json(daemon.file_set_publish(&id, files).await?))
}

async fn get_files(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<FileSetStatusView>, ApiError> {
    authorize(&headers, &daemon)?;
    Ok(Json(daemon.file_set_status(&id).await?))
}

async fn clear_files(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<FileSetStatusView>, ApiError> {
    authorize_owner_mutation(&headers, &daemon, &id)?;
    Ok(Json(daemon.file_set_clear(&id).await?))
}

async fn post_file(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<FileStatusView>, ApiError> {
    authorize_owner_mutation(&headers, &daemon, &id)?;
    let request: FilePublishRequest = parse_payload_body(&body)?;
    Ok(Json(daemon.file_publish(&id, request.bytes).await?))
}

async fn get_file(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<FileStatusView>, ApiError> {
    authorize(&headers, &daemon)?;
    Ok(Json(daemon.file_status(&id).await?))
}

async fn clear_file(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<FileStatusView>, ApiError> {
    authorize_owner_mutation(&headers, &daemon, &id)?;
    Ok(Json(daemon.file_clear(&id).await?))
}

async fn get_command(
    Path((id, command_id)): Path<(String, String)>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<CommandResponse>, ApiError> {
    authorize(&headers, &daemon)?;
    let command_id = Uuid::parse_str(&command_id)
        .map_err(|_| ApiError::bad_request("command_id must be a UUID"))?;
    Ok(Json(daemon.command_outcome(&id, command_id)?))
}

async fn events(
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<sse::Sse<impl tokio_stream::Stream<Item = Result<sse::Event, Infallible>>>, ApiError> {
    authorize(&headers, &daemon)?;
    let stream = BroadcastStream::new(daemon.0.events.subscribe()).filter_map(|event| {
        event.ok().and_then(|record| {
            serde_json::to_string(&record)
                .ok()
                .map(|data| Ok(sse::Event::default().event("command").data(data)))
        })
    });
    Ok(sse::Sse::new(stream).keep_alive(sse::KeepAlive::default()))
}

async fn type_text(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<CommandResponse>), ApiError> {
    let caller = authorize_owner_mutation(&headers, &daemon, &id)?;
    let request: TypeRequest = parse_payload_body(&body)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(daemon.submit_text(&id, caller, request).await?),
    ))
}

async fn actions(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<CommandResponse>), ApiError> {
    let caller = authorize_owner_mutation(&headers, &daemon, &id)?;
    let request: ActionsRequest = parse_payload_body(&body)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(daemon.submit_actions(&id, caller, request).await?),
    ))
}

async fn sequence(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<CommandResponse>), ApiError> {
    let caller = authorize_owner_mutation(&headers, &daemon, &id)?;
    let request: KeyboardSequenceV1 = parse_payload_body(&body)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(daemon.submit_sequence(&id, caller, request).await?),
    ))
}

/// Parses a body that may carry typed content. serde's messages quote input fragments, so
/// every parse failure maps to one fixed, payload-free code.
fn parse_payload_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError::bad_request("input.json"))
}

async fn input_sequence(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<CommandResponse>), ApiError> {
    let caller = authorize_owner_mutation(&headers, &daemon, &id)?;
    let request =
        parse_input_sequence_json(&body).map_err(|error| ApiError::bad_request(error.code()))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(daemon.submit_input_sequence(&id, caller, request).await?),
    ))
}

async fn arm(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<ArmRequest>,
) -> Result<Json<DeviceView>, ApiError> {
    authorize_owner_mutation(&headers, &daemon, &id)?;
    Ok(Json(daemon.arm_device(&id, request).await?))
}

async fn get_output_mode(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<OutputModeStatus>, ApiError> {
    authorize(&headers, &daemon)?;
    Ok(Json(daemon.output_mode(&id, None).await?))
}

async fn set_output_mode(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<SetOutputModeRequest>,
) -> Result<Json<OutputModeStatus>, ApiError> {
    authorize_owner_mutation(&headers, &daemon, &id)?;
    Ok(Json(daemon.output_mode(&id, Some(request.mode)).await?))
}

async fn get_display_orientation(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<DisplayOrientationStatus>, ApiError> {
    authorize(&headers, &daemon)?;
    Ok(Json(daemon.display_orientation(&id, None).await?))
}

async fn set_display_orientation(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<SetDisplayOrientationRequest>,
) -> Result<Json<DisplayOrientationStatus>, ApiError> {
    authorize_owner_mutation(&headers, &daemon, &id)?;
    Ok(Json(
        daemon
            .display_orientation(&id, Some(request.orientation))
            .await?,
    ))
}

async fn get_screen_power(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<ScreenPowerStatus>, ApiError> {
    authorize(&headers, &daemon)?;
    Ok(Json(daemon.screen_power(&id, None).await?))
}

async fn set_screen_power(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<SetScreenPowerRequest>,
) -> Result<Json<ScreenPowerStatus>, ApiError> {
    authorize_owner_mutation(&headers, &daemon, &id)?;
    Ok(Json(daemon.screen_power(&id, Some(request.power)).await?))
}

async fn reset_ble_hid_bond(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<BleHidBondResetStatus>, ApiError> {
    authorize_owner_mutation(&headers, &daemon, &id)?;
    Ok(Json(daemon.reset_ble_hid_bond(&id).await?))
}

async fn disarm(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<DeviceView>, ApiError> {
    authorize(&headers, &daemon)?;
    Ok(Json(daemon.disarm_device(&id).await?))
}

async fn begin_maintenance(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<DeviceView>, ApiError> {
    authorize(&headers, &daemon)?;
    Ok(Json(daemon.begin_device_maintenance(&id).await?))
}

async fn finish_maintenance(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<DeviceView>, ApiError> {
    authorize(&headers, &daemon)?;
    Ok(Json(daemon.finish_device_maintenance(&id)?))
}

async fn cancel(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<CancelRequest>,
) -> Result<Json<CommandResponse>, ApiError> {
    authorize(&headers, &daemon)?;
    Ok(Json(daemon.cancel_command(&id, request).await?))
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
    command_id: Option<String>,
    outcome: CommandOutcome,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            command_id: None,
            outcome: CommandOutcome::Rejected,
        }
    }
    fn auth(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }
    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }
    fn rejected(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, message)
    }
    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }
    fn unauthorized_command(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }
    fn busy(command_id: String) -> Self {
        Self {
            command_id: Some(command_id),
            ..Self::new(StatusCode::CONFLICT, "device has an active command")
        }
    }
    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
    /// A forwarded request may have reached the holding controller, but its result was lost.
    fn uncertain(message: impl Into<String>, command_id: Option<String>) -> Self {
        Self {
            command_id,
            outcome: CommandOutcome::Unknown,
            ..Self::new(StatusCode::BAD_GATEWAY, message)
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
                outcome: Some(self.outcome),
                command_id: self.command_id,
            }),
        )
            .into_response()
    }
}

fn core_state(value: CommandOutcome) -> CommandState {
    match value {
        CommandOutcome::Queued => CommandState::Queued,
        CommandOutcome::Accepted => CommandState::Accepted,
        CommandOutcome::Started => CommandState::Started,
        CommandOutcome::Emitted => CommandState::Emitted,
        CommandOutcome::Aborted => CommandState::Aborted,
        CommandOutcome::Rejected => CommandState::Rejected,
        CommandOutcome::Unknown => CommandState::Unknown,
    }
}

fn finish_command_transition(
    device: &mut DeviceRuntime,
    command_id: Uuid,
    next: CommandOutcome,
    started_at: Option<Instant>,
) -> Option<EventRecord> {
    let meta = device.commands.get_mut(&command_id)?;
    meta.response.send_replace(next);
    meta.terminal_at = Some(Instant::now());
    meta.event.as_mut().map(|record| {
        record.timestamp = timestamp_now();
        record.outcome = next;
        record.duration_ms = started_at.map(|started| started.elapsed().as_millis() as u64);
        record.clone()
    })
}

fn map_state_error(error: StateError) -> ApiError {
    match error {
        StateError::NotAuthenticated => ApiError::unauthorized_command(error.to_string()),
        StateError::NotArmed | StateError::InvalidMode => ApiError::rejected(error.to_string()),
        StateError::Busy => ApiError::conflict(error.to_string()),
        other => ApiError::internal(other.to_string()),
    }
}

async fn renew_arm_lease(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<LeaseRenewRequest>,
) -> Result<Json<DeviceView>, ApiError> {
    authorize_owner_mutation(&headers, &daemon, &id)?;
    Ok(Json(daemon.renew_arm_lease(&id, request.lease_ms).await?))
}

fn map_transport_control_error(action: &str, error: TransportError) -> ApiError {
    match error {
        TransportError::ControlRejected => {
            ApiError::rejected(format!("endpoint rejected {action}"))
        }
        TransportError::LostBeforeAccept | TransportError::NotImplemented => {
            ApiError::unavailable(format!("endpoint did not accept {action}"))
        }
        TransportError::AcceptedButLost => ApiError::unavailable(format!(
            "endpoint {action} confirmation was lost; the session was closed"
        )),
        TransportError::Simulation => {
            ApiError::internal(format!("simulated endpoint failed to {action}"))
        }
        TransportError::Busy => ApiError::conflict(format!("endpoint is busy during {action}")),
    }
}

fn sequence_error(error: SequenceError) -> ApiError {
    ApiError::bad_request(error.code())
}

fn parse_uuid_v7(value: &str, code: &str) -> Result<Uuid, ApiError> {
    let id = Uuid::parse_str(value).map_err(|_| ApiError::bad_request(code))?;
    if id.get_version_num() != 7 {
        return Err(ApiError::bad_request(code));
    }
    Ok(id)
}

fn parse_decimal_counter(value: &str) -> Result<u64, ApiError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ApiError::bad_request("text_stream.counter"));
    }
    value
        .parse()
        .map_err(|_| ApiError::bad_request("text_stream.counter"))
}

fn require_epoch(value: &str, epoch: Uuid) -> Result<(), ApiError> {
    if value != epoch.to_string() {
        return Err(ApiError::conflict("text_stream.epoch"));
    }
    Ok(())
}

fn validate_text_stream_create(
    request: &CreateTextStreamRequest,
    epoch: Uuid,
) -> Result<(), ApiError> {
    if request.schema != TEXT_STREAM_SCHEMA_V1 {
        return Err(ApiError::bad_request("text_stream.schema"));
    }
    require_epoch(&request.epoch, epoch)?;
    if request.profile != "windows-us" {
        return Err(ApiError::bad_request("text_stream.profile"));
    }
    let timing = TypingTiming {
        key_down_ms: request.key_down_ms,
        release_gap_ms: request.key_gap_ms,
    };
    timing
        .validate()
        .map_err(|_| ApiError::bad_request("text_stream.timing"))?;
    if request.send_after_seconds > 10 || text_stream_child_capacity(timing) == 0 {
        return Err(ApiError::bad_request("text_stream.delay"));
    }
    Ok(())
}

fn require_text_stream_owner(parent: &TextStreamParent, caller: &str) -> Result<(), ApiError> {
    if parent.caller != caller {
        return Err(ApiError::not_found("text_stream.not_found"));
    }
    Ok(())
}

fn text_stream_receipt(
    device_id: &str,
    job_id: Uuid,
    parent: &TextStreamParent,
) -> TextStreamReceipt {
    let current_child =
        parent
            .current
            .as_ref()
            .zip(parent.current_command_id)
            .map(|(child, command_id)| TextStreamCurrentChild {
                index: child.index.to_string(),
                command_id: command_id.to_string(),
                outcome: parent.current_outcome.unwrap_or(CommandOutcome::Queued),
            });
    let not_dispatched = parent.uncertain.as_ref().map_or_else(
        || TextStreamCursor::from_counts(parent.confirmed_bytes, parent.confirmed_scalars),
        |range| range.end.clone(),
    );
    TextStreamReceipt {
        schema: TEXT_STREAM_RECEIPT_SCHEMA_V1,
        epoch: parent.request.epoch.clone(),
        job_id: job_id.to_string(),
        device_id: device_id.to_owned(),
        source_kind: parent.request.source_kind,
        unsupported: parent.request.unsupported,
        phase: parent.phase,
        outcome: parent.outcome,
        terminal: parent.phase == TextStreamPhase::Terminal,
        reason: parent.reason.clone(),
        source_complete: parent.source_complete,
        source_total_bytes: parent.total_bytes.map(|value| value.to_string()),
        source_total_scalars: parent.total_scalars.map(|value| value.to_string()),
        confirmed_prefix: TextStreamConfirmedPrefix {
            bytes: parent.confirmed_bytes.to_string(),
            scalars: parent.confirmed_scalars.to_string(),
            children: parent.confirmed_children.to_string(),
            gestures: parent.confirmed_gestures.to_string(),
        },
        uncertain_range: parent.uncertain.clone(),
        not_dispatched_from: not_dispatched,
        next_index: parent.next_index.to_string(),
        current_child,
        possible_start: parent.possible_start,
        terminal_zero_confirmed: parent.terminal_zero_confirmed,
        continuation_allowed: parent.phase == TextStreamPhase::Ready && !parent.source_complete,
        expires_at: parent.terminal_at.map(|terminal| {
            let remaining = TEXT_STREAM_RECEIPT_RETENTION.saturating_sub(terminal.elapsed());
            timestamp_at(SystemTime::now() + remaining)
        }),
    }
}

fn reduce_text_stream_child(
    parent: &mut TextStreamParent,
    command_id: Uuid,
    child: StreamChildMeta,
    outcome: CommandOutcome,
    started: bool,
) {
    if parent.current_command_id != Some(command_id) {
        return;
    }
    parent.current = None;
    parent.current_command_id = None;
    parent.current_outcome = None;
    let was_stopping = parent.phase == TextStreamPhase::Stopping;
    match outcome {
        CommandOutcome::Emitted => {
            parent.confirmed_bytes = child.end_bytes;
            parent.confirmed_scalars = child.end_scalars;
            parent.confirmed_children = parent.confirmed_children.saturating_add(1);
            parent.confirmed_gestures = parent.confirmed_gestures.saturating_add(child.gestures);
            parent.next_index = parent.next_index.saturating_add(1);
            parent.possible_start = true;
            parent.terminal_zero_confirmed = true;
            parent.idle_deadline = Instant::now() + TEXT_STREAM_SOURCE_IDLE;
            if child.end_of_input {
                parent.source_complete = true;
                parent.total_bytes = Some(child.end_bytes);
                parent.total_scalars = Some(child.end_scalars);
                parent.phase = TextStreamPhase::Terminal;
                parent.outcome = Some(CommandOutcome::Emitted);
                parent.terminal_at = Some(Instant::now());
            } else if was_stopping {
                parent.phase = TextStreamPhase::Terminal;
                parent.outcome = Some(CommandOutcome::Aborted);
                parent.terminal_at = Some(Instant::now());
            } else {
                parent.phase = TextStreamPhase::Ready;
            }
        }
        CommandOutcome::Rejected | CommandOutcome::Aborted | CommandOutcome::Unknown => {
            let uncertain =
                started || matches!(outcome, CommandOutcome::Aborted | CommandOutcome::Unknown);
            if uncertain {
                parent.uncertain = Some(TextStreamRange {
                    start: TextStreamCursor::from_counts(child.start_bytes, child.start_scalars),
                    end: TextStreamCursor::from_counts(child.end_bytes, child.end_scalars),
                });
                parent.possible_start = true;
            }
            parent.phase = TextStreamPhase::Terminal;
            parent.terminal_zero_confirmed = outcome == CommandOutcome::Aborted
                || (outcome == CommandOutcome::Rejected && !uncertain);
            parent.outcome = Some(
                if outcome == CommandOutcome::Rejected
                    && parent.confirmed_children == 0
                    && !uncertain
                {
                    CommandOutcome::Rejected
                } else if parent.terminal_zero_confirmed {
                    CommandOutcome::Aborted
                } else {
                    CommandOutcome::Unknown
                },
            );
            parent.reason.get_or_insert_with(|| {
                format!("child.{}", format!("{outcome:?}").to_ascii_lowercase())
            });
            parent.terminal_at = Some(Instant::now());
        }
        CommandOutcome::Queued | CommandOutcome::Accepted | CommandOutcome::Started => {}
    }
}

fn finish_stopped_stream(device: &mut DeviceRuntime, job_id: Uuid) {
    let Some(parent) = device.text_streams.get_mut(&job_id) else {
        return;
    };
    parent.phase = TextStreamPhase::Terminal;
    parent.outcome = Some(if parent.possible_start || parent.confirmed_children != 0 {
        CommandOutcome::Aborted
    } else {
        CommandOutcome::Rejected
    });
    parent.terminal_zero_confirmed = true;
    parent.terminal_at = Some(Instant::now());
    device.stream_reservation = None;
}

fn stop_prepared_stream(device: &mut DeviceRuntime, job_id: Uuid, command_id: Uuid, reason: &str) {
    let Some(parent) = device.text_streams.get_mut(&job_id) else {
        return;
    };
    if parent.phase == TextStreamPhase::Terminal {
        return;
    }
    if parent.current_command_id == Some(command_id) {
        parent.current = None;
        parent.current_command_id = None;
        parent.current_outcome = None;
    }
    parent.phase = TextStreamPhase::Stopping;
    parent.reason = Some(reason.to_owned());
    finish_stopped_stream(device, job_id);
}

fn finish_idle_stream(device: &mut DeviceRuntime, job_id: Uuid, reason: &str) {
    let Some(parent) = device.text_streams.get_mut(&job_id) else {
        return;
    };
    if parent.current.is_some() || parent.phase == TextStreamPhase::Terminal {
        return;
    }
    parent.reason = Some(reason.to_owned());
    finish_stopped_stream(device, job_id);
}

fn prune_text_stream_records(device: &mut DeviceRuntime) {
    let now = Instant::now();
    // Parent IDs remain consumed for the whole daemon epoch. This bounded map
    // stops accepting new parents at capacity instead of making a pruned ID
    // executable again.
    device.commands.retain(|_, command| {
        command
            .terminal_at
            .is_none_or(|terminal| now.duration_since(terminal) < TEXT_STREAM_RECEIPT_RETENTION)
    });
}

fn valid_profile(profile: &str) -> bool {
    matches!(profile, "windows-us" | "us-ascii")
}

fn parse_arm_policy(policy: &str) -> Option<ArmPolicy> {
    match policy {
        "command-scoped" => Some(ArmPolicy::CommandScoped),
        "temporary" => Some(ArmPolicy::Temporary),
        "always-ready" => Some(ArmPolicy::AlwaysReady),
        _ => None,
    }
}

fn expire_arm(device: &mut DeviceRuntime) {
    if device
        .arm_until
        .is_some_and(|deadline| Instant::now() >= deadline)
    {
        device.arm_until = None;
        device.state.disarm();
    }
}

fn view_from_runtime(id: &str, device: &DeviceRuntime, link_path: Option<String>) -> DeviceView {
    let armed = device.state.armed
        && device
            .arm_until
            .is_none_or(|deadline| Instant::now() < deadline);
    DeviceView {
        id: id.to_owned(),
        label: device.label.clone(),
        transport: device.transport_name.clone(),
        link_path,
        link: match device.state.link {
            keyferry_core::LinkState::Authenticated => "authenticated",
            keyferry_core::LinkState::Connecting => "connecting",
            keyferry_core::LinkState::Offline => "offline",
        }
        .to_owned(),
        via: None,
        mode: "keyboard".to_owned(),
        armed,
        maintenance: device.maintenance,
        arm_policy: match device.state.arm_policy {
            ArmPolicy::CommandScoped => "command-scoped",
            ArmPolicy::Temporary => "temporary",
            ArmPolicy::AlwaysReady => "always-ready",
        }
        .to_owned(),
        firmware: None,
        active_command_id: device.current.map(|id| id.to_string()),
        active_outcome: device
            .current
            .and_then(|command_id| device.commands.get(&command_id))
            .map(|command| *command.response.borrow()),
    }
}

fn action_steps(actions: &[ActionRequest]) -> Result<CompiledSequence, String> {
    let mut canonical = Vec::with_capacity(actions.len());
    for action in actions {
        let timing = TypingTiming {
            key_down_ms: action.key_down_ms,
            release_gap_ms: action.release_gap_ms,
        };
        match action.action_type.as_str() {
            "text" => {
                if action.key.is_some() || !action.keys.is_empty() {
                    return Err("text action contains an inapplicable field".to_owned());
                }
                let value = action
                    .value
                    .as_deref()
                    .ok_or_else(|| "text action requires value".to_owned())?;
                canonical.push(SequenceAction::Text {
                    value: value.to_owned(),
                    timing: Some(timing),
                });
            }
            "tap" => {
                if action.value.is_some() || !action.keys.is_empty() {
                    return Err("tap action contains an inapplicable field".to_owned());
                }
                let name = action
                    .key
                    .as_deref()
                    .ok_or_else(|| "tap action requires key".to_owned())?;
                let stroke = stroke_for_key_name(name)
                    .map_err(|_| "tap key is not a supported key name".to_owned())?;
                canonical.push(canonical_action_for_stroke(stroke, timing)?);
            }
            "chord" => {
                if action.value.is_some() || action.key.is_some() {
                    return Err("chord action contains an inapplicable field".to_owned());
                }
                if action.keys.is_empty() {
                    return Err("chord action requires keys".to_owned());
                }
                let stroke = chord_from_names(&action.keys)
                    .map_err(|_| "chord must name modifiers plus one supported key".to_owned())?;
                canonical.push(canonical_action_for_stroke(stroke, timing)?);
            }
            _ => return Err("action type must be text, tap, or chord".to_owned()),
        }
    }
    let request = KeyboardSequenceV1 {
        schema: SEQUENCE_SCHEMA_V1.to_owned(),
        command_id: "019d0000-0000-7000-8000-000000000000".to_owned(),
        profile: "windows-us".to_owned(),
        arm: SequenceArmPolicy::RequireExisting,
        start_within_ms: MAX_COMMAND_EXPIRY_MS,
        timing: None,
        actions: canonical,
    };
    compile_sequence(&request).map_err(|error| error.code().to_owned())
}

fn canonical_action_for_stroke(
    stroke: Keystroke,
    timing: TypingTiming,
) -> Result<SequenceAction, String> {
    let mut keys = Vec::with_capacity(9);
    for (bit, name) in [
        (0x01, "LEFT_CONTROL"),
        (0x02, "LEFT_SHIFT"),
        (0x04, "LEFT_ALT"),
        (0x08, "LEFT_GUI"),
        (0x10, "RIGHT_CONTROL"),
        (0x20, "RIGHT_SHIFT"),
        (0x40, "RIGHT_ALT"),
        (0x80, "RIGHT_GUI"),
    ] {
        if stroke.modifiers & bit != 0 {
            keys.push(name.to_owned());
        }
    }
    let key = KEYBOARD_KEYS
        .iter()
        .find(|key| key.class == KeyClass::NonModifier && key.code == stroke.usage)
        .ok_or_else(|| "compatibility key has no canonical registry entry".to_owned())?;
    keys.push(key.name.to_owned());
    Ok(if keys.len() == 1 {
        SequenceAction::Tap {
            key: keys.pop().expect("one canonical key"),
            timing: Some(timing),
        }
    } else {
        SequenceAction::Chord {
            keys,
            timing: Some(timing),
        }
    })
}

pub fn plan_chunks(steps: Vec<ReportStep>) -> Result<Vec<PlannedChunk>, String> {
    if steps.is_empty() {
        return Err("command has no executable steps".to_owned());
    }
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut expected_ms = 0;
    let mut payload_len = 0_usize;
    for step in steps {
        let (step_ms, step_payload_len) = step_metrics(step);
        if step_ms > 100 {
            return Err("a wait action cannot exceed 100 ms".to_owned());
        }
        if current.is_empty() && matches!(step, ReportStep::WaitMs(_)) {
            current.push(ReportStep::Report(KeyboardReport::RELEASED));
            payload_len = 2;
        }
        let mut would_overflow = !current.is_empty()
            && (current.len() >= MAX_CHUNK_ACTIONS
                || expected_ms + step_ms > MAX_CHUNK_EXPECTED_MS
                || payload_len + step_payload_len > MAX_NETWORK_COMMAND_BODY);
        if would_overflow {
            if !ends_released(&current) {
                let last_release = current
                    .iter()
                    .rposition(|candidate| {
                        matches!(candidate, ReportStep::Report(report) if report.is_released())
                    });
                let held_start = last_release.map_or(0, |index| index + 1);
                let boundary = current[held_start..]
                    .iter()
                    .position(|candidate| {
                        matches!(candidate, ReportStep::Report(report) if !report.is_released())
                    })
                    .map(|index| held_start + index)
                    .ok_or_else(|| "one held-key gesture exceeds chunk limits".to_owned())?;
                if boundary == 0 {
                    return Err("one held-key gesture exceeds chunk limits".to_owned());
                }
                let tail = current.split_off(boundary);
                let (prefix_ms, _) = chunk_metrics(&current);
                chunks.push(PlannedChunk {
                    steps: current,
                    expected_ms: prefix_ms,
                });
                current = tail;
                (expected_ms, payload_len) = chunk_metrics(&current);
            } else {
                chunks.push(PlannedChunk {
                    steps: current,
                    expected_ms,
                });
                current = Vec::new();
                expected_ms = 0;
                payload_len = 0;
            }
            if current.is_empty() && matches!(step, ReportStep::WaitMs(_)) {
                current.push(ReportStep::Report(KeyboardReport::RELEASED));
                payload_len = 2;
            }
            would_overflow = !current.is_empty()
                && (current.len() >= MAX_CHUNK_ACTIONS
                    || expected_ms + step_ms > MAX_CHUNK_EXPECTED_MS
                    || payload_len + step_payload_len > MAX_NETWORK_COMMAND_BODY);
            if would_overflow {
                return Err("one released action segment exceeds chunk limits".to_owned());
            }
        }
        current.push(step);
        expected_ms += step_ms;
        payload_len += step_payload_len;
    }
    if !ends_released(&current) {
        return Err("command must end with a release report".to_owned());
    }
    chunks.push(PlannedChunk {
        steps: current,
        expected_ms,
    });
    Ok(chunks)
}

fn step_metrics(step: ReportStep) -> (u32, usize) {
    match step {
        ReportStep::WaitMs(duration) => (u32::from(duration), 4),
        ReportStep::Report(report) if report.is_released() => (0, 2),
        ReportStep::Report(_) => (0, 10),
    }
}

fn chunk_metrics(steps: &[ReportStep]) -> (u32, usize) {
    steps.iter().copied().map(step_metrics).fold(
        (0_u32, 0_usize),
        |(duration, payload), (step_ms, step_payload)| (duration + step_ms, payload + step_payload),
    )
}

fn ends_released(steps: &[ReportStep]) -> bool {
    steps.iter().rev().find_map(|step| match step {
        ReportStep::Report(report) => Some(report.is_released()),
        ReportStep::WaitMs(_) => None,
    }) == Some(true)
}

fn fingerprint(
    profile: &str,
    chunks: &[PlannedChunk],
    char_count: usize,
    expiry: u32,
    arm_before_first: bool,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    profile.hash(&mut hasher);
    char_count.hash(&mut hasher);
    expiry.hash(&mut hasher);
    arm_before_first.hash(&mut hasher);
    for chunk in chunks {
        chunk.expected_ms.hash(&mut hasher);
        for step in &chunk.steps {
            match step {
                ReportStep::Report(report) => {
                    0_u8.hash(&mut hasher);
                    report.modifiers.hash(&mut hasher);
                    report.keys.hash(&mut hasher);
                }
                ReportStep::WaitMs(ms) => {
                    1_u8.hash(&mut hasher);
                    ms.hash(&mut hasher);
                }
            }
        }
    }
    hasher.finish()
}

fn timestamp_now() -> String {
    timestamp_at(SystemTime::now())
}

fn timestamp_at(timestamp: SystemTime) -> String {
    let elapsed = timestamp.duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{}.{:03}Z", elapsed.as_secs(), elapsed.subsec_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{HeaderValue, Request},
    };
    use tokio::time::timeout;
    use tower_service::Service;

    const REMOTE_TOKEN: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    const REMOTE_BEARER: &str =
        "Bearer cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    #[test]
    fn rejected_handoff_preserves_endpoint_status_when_no_reason_exists() {
        let status = keyferry_protocol::gateway_handoff::Status {
            reply_operation: keyferry_protocol::gateway_handoff_operation::START,
            status: keyferry_protocol::gateway_handoff_status::BUSY,
            transaction_id: [0x11; 16],
            phase: keyferry_protocol::gateway_handoff_phase::NOT_STARTED,
            reason: keyferry_protocol::gateway_handoff_reason::NONE,
            remaining_phase_ms: 0,
            remaining_recovery_ms: 0,
            target_installation_id: [0; 16],
            previous_installation_id: [0; 16],
            device_boot_nonce: [0x22; 16],
            current_endpoint_session: [0x33; 16],
        };

        let response = endpoint_handoff_response(Uuid::now_v7(), &status, None, None);
        assert_eq!(response.phase, "failed_unchanged");
        assert_eq!(response.reason.as_deref(), Some("endpoint_status_1"));
    }

    #[derive(Default)]
    struct UnknownOnCancelTransport {
        started: tokio::sync::Notify,
        releases: std::sync::atomic::AtomicUsize,
        confirmed_abort: bool,
        fail_release: bool,
        diagnostic: std::sync::Mutex<Option<TransportDiagnostic>>,
        fault_handler: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    }

    impl DeviceTransport for UnknownOnCancelTransport {
        fn set_fault_handler(&self, handler: Arc<dyn Fn() + Send + Sync>) {
            *self.fault_handler.lock().expect("test fault handler lock") = Some(handler);
        }

        fn take_diagnostic(&self) -> Option<TransportDiagnostic> {
            self.diagnostic.lock().expect("test diagnostic lock").take()
        }

        fn arm<'a>(
            &'a self,
            _policy: ArmPolicy,
            _lease_ms: u32,
        ) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn disarm<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn renew_lease<'a>(&'a self, _lease_ms: u32) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn accept<'a>(
            &'a self,
            _command: &'a PlannedCommand,
        ) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn execute<'a>(
            &'a self,
            _command: &'a PlannedCommand,
            cancellation: Cancellation,
            progress: ProgressHandler,
        ) -> BoxFuture<'a, TransportOutcome> {
            Box::pin(async move {
                progress(TransportProgress::Accepted);
                progress(TransportProgress::Started);
                self.started.notify_one();
                while !cancellation.is_cancelled() {
                    time::sleep(Duration::from_millis(1)).await;
                }
                if self.fail_release {
                    *self.diagnostic.lock().expect("test diagnostic lock") =
                        Some(TransportDiagnostic::CancelActiveResultTransport);
                    if let Some(handler) = self
                        .fault_handler
                        .lock()
                        .expect("test fault handler lock")
                        .clone()
                    {
                        handler();
                    }
                }
                if self.confirmed_abort {
                    TransportOutcome::Aborted
                } else {
                    TransportOutcome::Unknown
                }
            })
        }

        fn release_all<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async move {
                self.releases
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if self.fail_release {
                    Err(TransportError::AcceptedButLost)
                } else {
                    Ok(())
                }
            })
        }
    }

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut decoded = [0_u8; N];
        for (index, byte) in decoded.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        decoded
    }

    fn decode_hex_vec(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    fn identity_spki(identity: &HostIdentity) -> Vec<u8> {
        use rustls::{
            crypto::ring::sign::any_ecdsa_type,
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        };
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            identity.private_key_der().to_vec(),
        ));
        any_ecdsa_type(&private_key)
            .unwrap()
            .public_key()
            .unwrap()
            .as_ref()
            .to_vec()
    }

    fn daemon() -> Daemon {
        Daemon::new(MemoryTokenStore::new("test-token-123456")).expect("daemon")
    }

    struct FileSetProbeTransport {
        base: SimulatorTransport,
        fail_operation: u8,
        calls: Mutex<Vec<u8>>,
        size: Mutex<u32>,
        received: Mutex<u32>,
    }

    impl FileSetProbeTransport {
        fn new(fail_operation: u8) -> Self {
            Self {
                base: SimulatorTransport::default(),
                fail_operation,
                calls: Mutex::new(Vec::new()),
                size: Mutex::new(0),
                received: Mutex::new(0),
            }
        }
    }

    impl DeviceTransport for FileSetProbeTransport {
        fn supports_file_set(&self) -> bool {
            true
        }
        fn file_set_request<'a>(
            &'a self,
            request: keyferry_protocol::file_set::Request,
        ) -> BoxFuture<'a, Result<keyferry_protocol::file_set::Status, TransportError>> {
            Box::pin(async move {
                use keyferry_protocol::file_set::{Error, Request, State, Status};
                let operation = match &request {
                    Request::Begin { .. } => 1,
                    Request::Chunk { .. } => 2,
                    Request::Commit => 3,
                    Request::Clear => 4,
                    Request::Status { .. } => 5,
                };
                self.calls.lock().unwrap().push(operation);
                if operation == self.fail_operation {
                    return Err(TransportError::AcceptedButLost);
                }
                let state = match request {
                    Request::Begin { size, .. } => {
                        *self.size.lock().unwrap() = size;
                        *self.received.lock().unwrap() = 0;
                        State::Receiving
                    }
                    Request::Chunk { offset, bytes } => {
                        assert_eq!(offset, *self.received.lock().unwrap());
                        *self.received.lock().unwrap() += bytes.len() as u32;
                        State::Receiving
                    }
                    Request::Commit => State::Published,
                    _ => State::Empty,
                };
                Ok(Status {
                    state,
                    error: Error::Ok,
                    wire_size: *self.size.lock().unwrap(),
                    received: *self.received.lock().unwrap(),
                    count: u8::from(state == State::Published),
                    entry: None,
                })
            })
        }
        fn arm<'a>(
            &'a self,
            policy: ArmPolicy,
            lease_ms: u32,
        ) -> BoxFuture<'a, Result<(), TransportError>> {
            self.base.arm(policy, lease_ms)
        }
        fn disarm<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
            self.base.disarm()
        }
        fn renew_lease<'a>(&'a self, lease_ms: u32) -> BoxFuture<'a, Result<(), TransportError>> {
            self.base.renew_lease(lease_ms)
        }
        fn accept<'a>(
            &'a self,
            command: &'a PlannedCommand,
        ) -> BoxFuture<'a, Result<(), TransportError>> {
            self.base.accept(command)
        }
        fn execute<'a>(
            &'a self,
            command: &'a PlannedCommand,
            cancellation: Cancellation,
            progress: ProgressHandler,
        ) -> BoxFuture<'a, TransportOutcome> {
            self.base.execute(command, cancellation, progress)
        }
        fn release_all<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
            self.base.release_all()
        }
    }

    #[tokio::test]
    async fn file_set_validates_before_contact_and_never_replays_uncertain_steps() {
        use keyferry_protocol::file_set::File;
        for fail_operation in [1, 2, 3] {
            let transport = Arc::new(FileSetProbeTransport::new(fail_operation));
            let daemon = Daemon::with_transport(
                MemoryTokenStore::new("test-token-123456"),
                transport.clone(),
            )
            .unwrap();
            let invalid = vec![File {
                name: "CON.txt".to_owned(),
                bytes: vec![1],
            }];
            let error = daemon
                .file_set_publish(SIMULATOR_DEVICE_ID, invalid)
                .await
                .unwrap_err();
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert!(transport.calls.lock().unwrap().is_empty());
            let valid = vec![File {
                name: "OK.txt".to_owned(),
                bytes: vec![1],
            }];
            let error = daemon
                .file_set_publish(SIMULATOR_DEVICE_ID, valid)
                .await
                .unwrap_err();
            assert_eq!(error.outcome, CommandOutcome::Unknown);
            let calls = transport.calls.lock().unwrap().clone();
            assert_eq!(
                calls
                    .iter()
                    .filter(|operation| **operation == fail_operation)
                    .count(),
                1
            );
            assert_eq!(calls.last(), Some(&fail_operation));
        }
    }

    fn owner_peer(installation_id: [u8; 16]) -> ConnectInfo<RemoteTlsPeer> {
        ConnectInfo(RemoteTlsPeer {
            installation_id,
            address: SocketAddr::from(([100, 64, 0, 2], 49_152)),
            control_port: keyferry_gateway::OWNER_GATEWAY_CONTROL_PORT,
        })
    }

    async fn arm(daemon: &Daemon) {
        daemon
            .arm_device(
                SIMULATOR_DEVICE_ID,
                ArmRequest {
                    policy: "command-scoped".to_owned(),
                    lease_ms: None,
                },
            )
            .await
            .expect("arm");
    }

    #[tokio::test]
    async fn multi_device_runtime_control_is_independent() {
        let first_id = "11111111-1111-4111-8111-111111111111".to_owned();
        let second_id = "22222222-2222-4222-8222-222222222222".to_owned();
        let first = Arc::new(SimulatorTransport::default());
        let second = Arc::new(SimulatorTransport::default());
        let daemon = Daemon::with_device_transports_and_gateways(
            MemoryTokenStore::new("test-token-123456"),
            vec![
                (
                    first_id.clone(),
                    "First".to_owned(),
                    first.clone() as Arc<dyn DeviceTransport>,
                    None,
                ),
                (
                    second_id.clone(),
                    "Second".to_owned(),
                    second.clone() as Arc<dyn DeviceTransport>,
                    None,
                ),
            ],
        )
        .unwrap();

        daemon
            .arm_device(
                &first_id,
                ArmRequest {
                    policy: "always-ready".to_owned(),
                    lease_ms: None,
                },
            )
            .await
            .unwrap();
        assert!(first.is_remotely_armed());
        assert!(!second.is_remotely_armed());

        daemon
            .arm_device(
                &second_id,
                ArmRequest {
                    policy: "always-ready".to_owned(),
                    lease_ms: None,
                },
            )
            .await
            .unwrap();
        daemon.disarm_device(&first_id).await.unwrap();
        assert!(!first.is_remotely_armed());
        assert!(second.is_remotely_armed());
        assert_eq!(first.control_request_counts(), (1, 1, 0));
        assert_eq!(second.control_request_counts(), (1, 0, 0));
        assert_eq!(daemon.device_view(&first_id).unwrap().label, "First");
        assert_eq!(daemon.device_view(&second_id).unwrap().label, "Second");
    }

    #[tokio::test]
    async fn same_command_uuid_is_independently_deduplicated_per_device() {
        let first_id = "11111111-1111-4111-8111-111111111111".to_owned();
        let second_id = "22222222-2222-4222-8222-222222222222".to_owned();
        let first = Arc::new(SimulatorTransport::default());
        let second = Arc::new(SimulatorTransport::default());
        let daemon = Daemon::with_device_transports_and_gateways(
            MemoryTokenStore::new("test-token-123456"),
            vec![
                (
                    first_id.clone(),
                    "First".to_owned(),
                    first.clone() as Arc<dyn DeviceTransport>,
                    None,
                ),
                (
                    second_id.clone(),
                    "Second".to_owned(),
                    second.clone() as Arc<dyn DeviceTransport>,
                    None,
                ),
            ],
        )
        .unwrap();
        let command_id = Uuid::now_v7();
        let request = KeyboardSequenceV1 {
            schema: keyferry_layouts::SEQUENCE_SCHEMA_V1.to_owned(),
            command_id: command_id.to_string(),
            profile: "windows-us".to_owned(),
            arm: SequenceArmPolicy::CommandScoped,
            start_within_ms: 5_000,
            timing: None,
            actions: vec![keyferry_layouts::SequenceAction::Tap {
                key: "A".to_owned(),
                timing: None,
            }],
        };

        let (first_result, second_result) = tokio::join!(
            daemon.submit_sequence(&first_id, "test".to_owned(), request.clone()),
            daemon.submit_sequence(&second_id, "test".to_owned(), request),
        );
        assert_eq!(first_result.unwrap().command_id, command_id.to_string());
        assert_eq!(second_result.unwrap().command_id, command_id.to_string());

        time::timeout(Duration::from_secs(1), async {
            loop {
                let first_done = daemon
                    .command_outcome(&first_id, command_id)
                    .is_ok_and(|response| response.outcome == CommandOutcome::Emitted);
                let second_done = daemon
                    .command_outcome(&second_id, command_id)
                    .is_ok_and(|response| response.outcome == CommandOutcome::Emitted);
                if first_done && second_done {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both devices complete independently");
        assert_eq!(first.execution_count(command_id), 1);
        assert_eq!(second.execution_count(command_id), 1);
    }

    #[tokio::test]
    async fn transport_lifecycle_invalidates_only_that_devices_route_proofs() {
        let first_id = "11111111-1111-4111-8111-111111111111".to_owned();
        let second_id = "22222222-2222-4222-8222-222222222222".to_owned();
        let daemon = Daemon::with_device_transports_and_gateways(
            MemoryTokenStore::new("test-token-123456"),
            vec![
                (
                    first_id.clone(),
                    "First".to_owned(),
                    Arc::new(SimulatorTransport::default()) as Arc<dyn DeviceTransport>,
                    None,
                ),
                (
                    second_id.clone(),
                    "Second".to_owned(),
                    Arc::new(SimulatorTransport::default()) as Arc<dyn DeviceTransport>,
                    None,
                ),
            ],
        )
        .unwrap();
        let owner = [0x5a; 16];
        let lease = || OwnerRouteLease {
            endpoint_session_id: [0x44; 16],
            proof_digest: [0x45; 32],
            expires_at: Instant::now() + Duration::from_secs(1),
        };
        daemon.0.owner_routes.lock().unwrap().extend([
            ((first_id.clone(), owner), lease()),
            ((second_id.clone(), owner), lease()),
        ]);

        let first_runtime = Arc::clone(&daemon.0.devices.get(&first_id).unwrap().0);
        daemon.mark_transport_ready(&first_runtime);
        let routes = daemon.0.owner_routes.lock().unwrap();
        assert!(!routes.contains_key(&(first_id.clone(), owner)));
        assert!(routes.contains_key(&(second_id.clone(), owner)));
        drop(routes);

        let second_runtime = Arc::clone(&daemon.0.devices.get(&second_id).unwrap().0);
        daemon.mark_transport_disconnected(&second_runtime);
        assert!(daemon.0.owner_routes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn file_upload_rejects_oversize_and_old_firmware_without_content_in_error() {
        let daemon = daemon();
        assert_eq!(
            daemon
                .file_publish(
                    SIMULATOR_DEVICE_ID,
                    vec![0x41; keyferry_protocol::file::MAX_FILE_BYTES + 1],
                )
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
        let error = daemon
            .file_publish(SIMULATOR_DEVICE_ID, b"private content".to_vec())
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!error.message.contains("private content"));
    }

    #[tokio::test]
    async fn output_mode_is_strict_capability_gated_and_requires_idle_disarmed_state() {
        assert!(
            serde_json::from_str::<SetOutputModeRequest>(r#"{"mode":"ble-hid","extra":true}"#)
                .is_err()
        );

        let unsupported = daemon();
        assert_eq!(
            unsupported
                .output_mode(SIMULATOR_DEVICE_ID, None)
                .await
                .unwrap_err()
                .status,
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let transport =
            Arc::new(SimulatorTransport::default().with_output_mode(OutputMode::UsbHid));
        let daemon = Daemon::with_transport(MemoryTokenStore::new("test-token-123456"), transport)
            .expect("daemon");
        assert_eq!(
            daemon
                .output_mode(SIMULATOR_DEVICE_ID, None)
                .await
                .expect("read output mode")
                .active,
            OutputMode::UsbHid
        );
        arm(&daemon).await;
        assert_eq!(
            daemon
                .output_mode(SIMULATOR_DEVICE_ID, Some(OutputMode::BleHid))
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        daemon
            .disarm_device(SIMULATOR_DEVICE_ID)
            .await
            .expect("disarm");
        let status = daemon
            .output_mode(SIMULATOR_DEVICE_ID, Some(OutputMode::BleHid))
            .await
            .expect("set output mode");
        assert_eq!(status.active, OutputMode::BleHid);
        assert_eq!(status.stored, OutputMode::BleHid);
        assert!(!status.restart_pending);

        arm(&daemon).await;
        let response = daemon
            .submit_text(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                TypeRequest {
                    text: "a".to_owned(),
                    profile: default_profile(),
                    timing: default_timing(),
                    expires_in_ms: None,
                    command_id: None,
                },
            )
            .await
            .expect("submit through BLE-mode simulator");
        let command_id = Uuid::parse_str(&response.command_id).expect("command ID");
        assert_eq!(response.output_transport, OutputTransport::BleHid);
        assert_eq!(
            daemon.wait_for_terminal(command_id).await,
            Some(CommandOutcome::Emitted)
        );
        let terminal = daemon
            .command_outcome(SIMULATOR_DEVICE_ID, command_id)
            .expect("terminal result");
        assert!(terminal.terminal_release_completed);
        assert!(!terminal.terminal_zero_confirmed);
        assert_eq!(terminal.output_transport, OutputTransport::BleHid);
    }

    #[tokio::test]
    async fn display_orientation_is_strict_capability_gated_and_requires_disarm() {
        assert!(serde_json::from_str::<SetDisplayOrientationRequest>(
            r#"{"orientation":"rotated-180","extra":true}"#
        )
        .is_err());

        let unsupported = daemon();
        assert_eq!(
            unsupported
                .display_orientation(SIMULATOR_DEVICE_ID, None)
                .await
                .unwrap_err()
                .status,
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let transport = Arc::new(
            SimulatorTransport::default().with_display_orientation(DisplayOrientation::Normal),
        );
        let daemon = Daemon::with_transport(MemoryTokenStore::new("test-token-123456"), transport)
            .expect("daemon");
        assert_eq!(
            daemon
                .display_orientation(SIMULATOR_DEVICE_ID, None)
                .await
                .expect("read orientation")
                .active,
            DisplayOrientation::Normal
        );
        arm(&daemon).await;
        assert_eq!(
            daemon
                .display_orientation(SIMULATOR_DEVICE_ID, Some(DisplayOrientation::Rotated180),)
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        daemon
            .disarm_device(SIMULATOR_DEVICE_ID)
            .await
            .expect("disarm");
        let status = daemon
            .display_orientation(SIMULATOR_DEVICE_ID, Some(DisplayOrientation::Rotated180))
            .await
            .expect("set orientation");
        assert_eq!(status.active, DisplayOrientation::Normal);
        assert_eq!(status.stored, DisplayOrientation::Rotated180);
        assert!(status.restart_pending);
    }

    #[tokio::test]
    async fn screen_power_targets_one_capable_idle_device_and_requires_strict_body() {
        assert!(
            serde_json::from_str::<SetScreenPowerRequest>(r#"{"power":"off","extra":true}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<SetScreenPowerRequest>(r#"{"power":"dim"}"#).is_err());
        let unsupported = daemon();
        assert_eq!(
            unsupported
                .screen_power(SIMULATOR_DEVICE_ID, None)
                .await
                .unwrap_err()
                .status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let transport = Arc::new(SimulatorTransport::default().with_screen_power(ScreenPower::On));
        let daemon = Daemon::with_transport(MemoryTokenStore::new("test-token-123456"), transport)
            .expect("daemon");
        assert!(daemon
            .screen_power("another-device", Some(ScreenPower::Off))
            .await
            .is_err());
        assert_eq!(
            daemon
                .screen_power(SIMULATOR_DEVICE_ID, None)
                .await
                .unwrap()
                .active,
            ScreenPower::On
        );
        arm(&daemon).await;
        assert_eq!(
            daemon
                .screen_power(SIMULATOR_DEVICE_ID, Some(ScreenPower::Off))
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        daemon.disarm_device(SIMULATOR_DEVICE_ID).await.unwrap();
        let status = daemon
            .screen_power(SIMULATOR_DEVICE_ID, Some(ScreenPower::Off))
            .await
            .unwrap();
        assert_eq!(status.device_id, SIMULATOR_DEVICE_ID);
        assert_eq!(status.active, ScreenPower::Off);
        assert_eq!(status.stored, ScreenPower::Off);
        assert!(status.available);
    }

    #[tokio::test]
    async fn bluetooth_bond_reset_is_capability_gated_ble_only_and_disarmed() {
        let unsupported = daemon();
        assert_eq!(
            unsupported
                .reset_ble_hid_bond(SIMULATOR_DEVICE_ID)
                .await
                .unwrap_err()
                .status,
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let usb_transport = Arc::new(
            SimulatorTransport::default()
                .with_output_mode(OutputMode::UsbHid)
                .with_ble_hid_bond(true),
        );
        let usb_daemon =
            Daemon::with_transport(MemoryTokenStore::new("test-token-123456"), usb_transport)
                .expect("daemon");
        assert_eq!(
            usb_daemon
                .reset_ble_hid_bond(SIMULATOR_DEVICE_ID)
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );

        let transport = Arc::new(
            SimulatorTransport::default()
                .with_output_mode(OutputMode::BleHid)
                .with_ble_hid_bond(true),
        );
        let daemon = Daemon::with_transport(MemoryTokenStore::new("test-token-123456"), transport)
            .expect("daemon");
        arm(&daemon).await;
        assert_eq!(
            daemon
                .reset_ble_hid_bond(SIMULATOR_DEVICE_ID)
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        daemon
            .disarm_device(SIMULATOR_DEVICE_ID)
            .await
            .expect("disarm");

        let first = daemon
            .reset_ble_hid_bond(SIMULATOR_DEVICE_ID)
            .await
            .expect("forget bond");
        assert_eq!(first.schema, BLE_HID_BOND_RESET_SCHEMA_V1);
        assert!(first.bond_was_present);
        assert!(first.restart_pending);

        let second = daemon
            .reset_ble_hid_bond(SIMULATOR_DEVICE_ID)
            .await
            .expect("idempotent no-bond reset");
        assert!(!second.bond_was_present);
        assert!(second.restart_pending);
    }

    #[tokio::test]
    async fn command_scoped_arm_is_confirmed_by_and_consumed_on_the_endpoint() {
        let transport = Arc::new(SimulatorTransport::default());
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");

        assert!(!daemon.device_view(SIMULATOR_DEVICE_ID).unwrap().armed);
        assert!(!transport.is_remotely_armed());
        arm(&daemon).await;
        assert!(daemon.device_view(SIMULATOR_DEVICE_ID).unwrap().armed);
        assert!(transport.is_remotely_armed());
        assert_eq!(transport.control_request_counts(), (1, 0, 0));

        let response = daemon
            .submit_text(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                TypeRequest {
                    text: "a".to_owned(),
                    profile: default_profile(),
                    timing: default_timing(),
                    expires_in_ms: None,
                    command_id: None,
                },
            )
            .await
            .expect("submit");
        assert_eq!(
            daemon
                .wait_for_terminal(Uuid::parse_str(&response.command_id).unwrap())
                .await,
            Some(CommandOutcome::Emitted)
        );
        assert!(!daemon.device_view(SIMULATOR_DEVICE_ID).unwrap().armed);
        assert!(!transport.is_remotely_armed());
        let command_id = response.command_id;
        assert_eq!(
            daemon
                .metadata()
                .into_iter()
                .filter(|event| event.command_id == command_id)
                .map(|event| event.outcome)
                .collect::<Vec<_>>(),
            vec![
                CommandOutcome::Queued,
                CommandOutcome::Accepted,
                CommandOutcome::Started,
                CommandOutcome::Emitted,
            ]
        );
    }

    #[tokio::test]
    async fn sequence_command_scoped_arm_needs_no_separate_arm_request() {
        let transport = Arc::new(SimulatorTransport::default());
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");
        let command_id = Uuid::now_v7();
        let response = daemon
            .submit_sequence(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                KeyboardSequenceV1 {
                    schema: keyferry_layouts::SEQUENCE_SCHEMA_V1.to_owned(),
                    command_id: command_id.to_string(),
                    profile: "windows-us".to_owned(),
                    arm: SequenceArmPolicy::CommandScoped,
                    start_within_ms: 5_000,
                    timing: None,
                    actions: vec![keyferry_layouts::SequenceAction::Tap {
                        key: "LEFT_GUI".to_owned(),
                        timing: None,
                    }],
                },
            )
            .await
            .expect("atomic sequence submission");
        assert_eq!(response.command_id, command_id.to_string());
        assert_eq!(
            daemon.wait_for_terminal(command_id).await,
            Some(CommandOutcome::Emitted)
        );
        assert_eq!(transport.control_request_counts(), (1, 0, 0));
        assert!(!daemon.device_view(SIMULATOR_DEVICE_ID).unwrap().armed);
        assert!(!transport.is_remotely_armed());
    }

    #[tokio::test]
    async fn sequence_route_accepts_the_canonical_json_contract() {
        let daemon = daemon();
        let command_id = Uuid::now_v7();
        let body = serde_json::json!({
            "schema": keyferry_layouts::SEQUENCE_SCHEMA_V1,
            "command_id": command_id.to_string(),
            "profile": "windows-us",
            "arm": "command-scoped",
            "start_within_ms": 5000,
            "actions": [
                {"type": "chord", "keys": ["LEFT_GUI", "R"]},
                {"type": "wait", "ms": 250},
                {"type": "text", "value": "notepad"},
                {"type": "tap", "key": "ENTER"}
            ]
        });
        let mut router = daemon.router();
        let response = router
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/devices/{SIMULATOR_DEVICE_ID}/sequences"))
                    .header(header::AUTHORIZATION, "Bearer test-token-123456")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response["command_id"], command_id.to_string());
        assert_eq!(
            daemon.wait_for_terminal(command_id).await,
            Some(CommandOutcome::Emitted)
        );
    }

    #[tokio::test]
    async fn payload_route_parse_errors_do_not_echo_the_body() {
        let daemon = daemon();
        let mut router = daemon.router();
        let marker = "hunter2-do-not-echo";
        let device = format!("/v1/devices/{SIMULATOR_DEVICE_ID}");
        for (uri, body) in [
            (
                format!("{device}/type"),
                serde_json::json!({"text": "abc", "expires_in_ms": marker}),
            ),
            (
                format!("{device}/actions"),
                serde_json::json!({"actions": [], "expires_in_ms": marker}),
            ),
            (
                format!("{device}/sequences"),
                serde_json::json!({"start_within_ms": marker}),
            ),
            (
                format!("{device}/text-streams/{}/parts/0", Uuid::now_v7()),
                serde_json::json!({"text": "abc", "end_of_input": marker}),
            ),
        ] {
            let (status, error) = call_json(&mut router, "POST", uri.clone(), Some(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            assert_eq!(error["error"], "input.json", "{uri}");
            assert!(!error.to_string().contains(marker), "{uri}");
        }
    }

    fn text_stream_request(daemon: &Daemon, job_id: Uuid) -> CreateTextStreamRequest {
        CreateTextStreamRequest {
            schema: TEXT_STREAM_SCHEMA_V1.to_owned(),
            epoch: daemon.0.epoch.to_string(),
            job_id: job_id.to_string(),
            profile: "windows-us".to_owned(),
            key_down_ms: 100,
            key_gap_ms: 100,
            send_after_seconds: 0,
            source_kind: TextStreamSourceKind::Text,
            validation: TextStreamValidation::Preflight,
            unsupported: UnsupportedTextPolicy::Reject,
        }
    }

    fn text_stream_part_request(
        daemon: &Daemon,
        command_id: Uuid,
        start: u64,
        text: &str,
        end_of_input: bool,
    ) -> TextStreamPartRequest {
        TextStreamPartRequest {
            epoch: daemon.0.epoch.to_string(),
            child_command_id: command_id.to_string(),
            source_start: TextStreamCursor::from_counts(start, start),
            source_end: None,
            text: text.to_owned(),
            end_of_input,
        }
    }

    fn private_state_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("keyferry-state-test-{}", Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn state_dir_entries(dir: &FsPath) -> Vec<String> {
        let mut names = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    async fn call_json(
        router: &mut Router,
        method: &str,
        uri: String,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let response = router
            .call(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::AUTHORIZATION, "Bearer test-token-123456")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn daemon_start_removes_the_legacy_text_stream_receipt_file() {
        let dir = private_state_dir();
        let token = dir.join("token");
        let legacy = dir.join("token.text-stream-receipts.v1");
        fs::write(&token, "test-token-123456\n").unwrap();
        fs::write(&legacy, b"KFTRCPT1 legacy lengths").unwrap();
        let _daemon = Daemon::new(FileTokenStore::new(&token)).unwrap();
        assert!(!legacy.exists());
        assert_eq!(state_dir_entries(&dir), ["token"]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn text_stream_through_the_daemon_router_writes_nothing_to_disk() {
        let dir = private_state_dir();
        let token = dir.join("token");
        fs::write(&token, "test-token-123456\n").unwrap();
        let daemon = Daemon::new(FileTokenStore::new(&token)).unwrap();
        let mut router = daemon.router();
        let job_id = Uuid::now_v7();
        let child_id = Uuid::now_v7();
        let streams = format!("/v1/devices/{SIMULATOR_DEVICE_ID}/text-streams");
        let (status, _) = call_json(
            &mut router,
            "POST",
            streams.clone(),
            Some(serde_json::to_value(text_stream_request(&daemon, job_id)).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _) = call_json(
            &mut router,
            "POST",
            format!("{streams}/{job_id}/parts/0"),
            Some(serde_json::json!({
                "epoch": daemon.0.epoch.to_string(),
                "child_command_id": child_id.to_string(),
                "source_start": {"bytes": "0", "scalars": "0"},
                "text": "secret",
                "end_of_input": true,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            daemon.wait_for_terminal(child_id).await,
            Some(CommandOutcome::Emitted)
        );
        let (status, receipt) =
            call_json(&mut router, "GET", format!("{streams}/{job_id}"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(receipt["outcome"], "EMITTED");
        assert_eq!(state_dir_entries(&dir), ["token"]);

        // A restarted daemon has no record of the job; clients must treat it as unknown.
        drop(router);
        drop(daemon);
        let restarted = Daemon::new(FileTokenStore::new(&token)).unwrap();
        let (status, error) = call_json(
            &mut restarted.router(),
            "GET",
            format!("{streams}/{job_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(error["error"], "text_stream.not_found");
        assert_eq!(state_dir_entries(&dir), ["token"]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn text_stream_reserves_writer_across_released_children() {
        let daemon = daemon();
        let job_id = Uuid::now_v7();
        daemon
            .create_text_stream(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                text_stream_request(&daemon, job_id),
            )
            .unwrap();
        let first_id = Uuid::now_v7();
        daemon
            .submit_text_stream_part(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                job_id,
                0,
                text_stream_part_request(&daemon, first_id, 0, "1234567890", false),
            )
            .await
            .unwrap();
        assert_eq!(
            daemon.wait_for_terminal(first_id).await,
            Some(CommandOutcome::Emitted)
        );
        let status = daemon
            .text_stream_status(SIMULATOR_DEVICE_ID, "test".to_owned(), job_id)
            .unwrap();
        assert_eq!(status.phase, TextStreamPhase::Ready);
        assert_eq!(status.confirmed_prefix.bytes, "10");

        let interloper = daemon
            .submit_sequence(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                KeyboardSequenceV1 {
                    schema: SEQUENCE_SCHEMA_V1.to_owned(),
                    command_id: Uuid::now_v7().to_string(),
                    profile: "windows-us".to_owned(),
                    arm: SequenceArmPolicy::CommandScoped,
                    start_within_ms: 5_000,
                    timing: None,
                    actions: vec![SequenceAction::Tap {
                        key: "ENTER".to_owned(),
                        timing: None,
                    }],
                },
            )
            .await;
        assert!(interloper.is_err());

        let second_id = Uuid::now_v7();
        daemon
            .submit_text_stream_part(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                job_id,
                1,
                text_stream_part_request(&daemon, second_id, 10, "tail", true),
            )
            .await
            .unwrap();
        assert_eq!(
            daemon.wait_for_terminal(second_id).await,
            Some(CommandOutcome::Emitted)
        );
        let status = daemon
            .text_stream_status(SIMULATOR_DEVICE_ID, "test".to_owned(), job_id)
            .unwrap();
        assert_eq!(status.outcome, Some(CommandOutcome::Emitted));
        assert_eq!(status.confirmed_prefix.bytes, "14");
        assert!(status.source_complete);
    }

    #[tokio::test]
    async fn replacement_stream_tracks_original_source_offsets() {
        let daemon = daemon();
        let job_id = Uuid::now_v7();
        let mut create = text_stream_request(&daemon, job_id);
        create.unsupported = UnsupportedTextPolicy::Replace;
        daemon
            .create_text_stream(SIMULATOR_DEVICE_ID, "test".to_owned(), create)
            .unwrap();

        let child_id = Uuid::now_v7();
        let mut part = text_stream_part_request(&daemon, child_id, 0, "a?b", true);
        part.source_end = Some(TextStreamCursor::from_counts(5, 3));
        daemon
            .submit_text_stream_part(SIMULATOR_DEVICE_ID, "test".to_owned(), job_id, 0, part)
            .await
            .unwrap();
        assert_eq!(
            daemon.wait_for_terminal(child_id).await,
            Some(CommandOutcome::Emitted)
        );
        let status = daemon
            .text_stream_status(SIMULATOR_DEVICE_ID, "test".to_owned(), job_id)
            .unwrap();
        assert_eq!(status.unsupported, UnsupportedTextPolicy::Replace);
        assert_eq!(status.confirmed_prefix.bytes, "5");
        assert_eq!(status.confirmed_prefix.scalars, "3");
        assert_eq!(status.confirmed_prefix.gestures, "3");
        assert!(status.source_complete);

        let missing_job = Uuid::now_v7();
        let mut create = text_stream_request(&daemon, missing_job);
        create.unsupported = UnsupportedTextPolicy::Replace;
        daemon
            .create_text_stream(SIMULATOR_DEVICE_ID, "test".to_owned(), create)
            .unwrap();
        let error = daemon
            .submit_text_stream_part(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                missing_job,
                0,
                text_stream_part_request(&daemon, Uuid::now_v7(), 0, "x", true),
            )
            .await
            .unwrap_err();
        assert_eq!(error.message, "text_stream.source_end_required");
    }

    #[tokio::test]
    async fn later_child_rejection_preserves_confirmed_prefix() {
        let transport = Arc::new(SimulatorTransport::new([
            SimulationFault::None,
            SimulationFault::BeforeAccept,
        ]));
        let daemon =
            Daemon::with_transport(MemoryTokenStore::new("test-token-123456"), transport).unwrap();
        let job_id = Uuid::now_v7();
        daemon
            .create_text_stream(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                text_stream_request(&daemon, job_id),
            )
            .unwrap();
        let first_id = Uuid::now_v7();
        daemon
            .submit_text_stream_part(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                job_id,
                0,
                text_stream_part_request(&daemon, first_id, 0, "1234567890", false),
            )
            .await
            .unwrap();
        assert_eq!(
            daemon.wait_for_terminal(first_id).await,
            Some(CommandOutcome::Emitted)
        );
        let second_id = Uuid::now_v7();
        daemon
            .submit_text_stream_part(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                job_id,
                1,
                text_stream_part_request(&daemon, second_id, 10, "tail", true),
            )
            .await
            .unwrap();
        assert_eq!(
            daemon.wait_for_terminal(second_id).await,
            Some(CommandOutcome::Rejected)
        );
        let status = daemon
            .text_stream_status(SIMULATOR_DEVICE_ID, "test".to_owned(), job_id)
            .unwrap();
        assert_eq!(status.outcome, Some(CommandOutcome::Aborted));
        assert_eq!(status.confirmed_prefix.bytes, "10");
        assert_eq!(status.not_dispatched_from.bytes, "10");
        assert!(status.uncertain_range.is_none());
    }

    #[tokio::test]
    async fn disarm_stops_a_stream_between_children_before_writer_release() {
        let daemon = daemon();
        let job_id = Uuid::now_v7();
        daemon
            .create_text_stream(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                text_stream_request(&daemon, job_id),
            )
            .unwrap();
        let child_id = Uuid::now_v7();
        daemon
            .submit_text_stream_part(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                job_id,
                0,
                text_stream_part_request(&daemon, child_id, 0, "1234567890", false),
            )
            .await
            .unwrap();
        while daemon
            .text_stream_status(SIMULATOR_DEVICE_ID, "test".to_owned(), job_id)
            .unwrap()
            .phase
            != TextStreamPhase::Ready
        {
            time::sleep(Duration::from_millis(1)).await;
        }
        daemon.disarm_device(SIMULATOR_DEVICE_ID).await.unwrap();
        let status = daemon
            .text_stream_status(SIMULATOR_DEVICE_ID, "test".to_owned(), job_id)
            .unwrap();
        assert_eq!(status.phase, TextStreamPhase::Terminal);
        assert_eq!(status.outcome, Some(CommandOutcome::Aborted));
        assert_eq!(status.reason.as_deref(), Some("device_disarmed"));
        assert_eq!(status.confirmed_prefix.bytes, "10");
        assert!(status.terminal_zero_confirmed);
    }

    fn pointer_input_request(command_id: Uuid) -> InputSequenceV1 {
        InputSequenceV1 {
            schema: keyferry_layouts::INPUT_SEQUENCE_SCHEMA_V1.to_owned(),
            command_id: command_id.to_string(),
            keyboard_profile: None,
            arm: keyferry_layouts::InputArmPolicy::CommandScoped,
            start_within_ms: 5_000,
            keyboard_timing: None,
            actions: vec![keyferry_layouts::InputAction::MoveRelative {
                dx_counts: 10,
                dy_counts: -5,
            }],
        }
    }

    #[tokio::test]
    async fn input_sequence_requires_capability_before_arm_or_execution() {
        let transport = Arc::new(SimulatorTransport::default());
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");
        let error = daemon
            .submit_input_sequence(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                pointer_input_request(Uuid::now_v7()),
            )
            .await
            .expect_err("missing capability must reject");
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(error.message, "device lacks input-sequence capability");
        assert_eq!(transport.control_request_counts(), (0, 0, 0));
    }

    #[tokio::test]
    async fn input_sequence_route_is_strict_and_payload_free() {
        let transport = Arc::new(SimulatorTransport::default().with_input_sequence());
        let daemon = Daemon::with_transport(MemoryTokenStore::new("test-token-123456"), transport)
            .expect("daemon");
        let command_id = Uuid::now_v7();
        let body = format!(
            r#"{{"schema":"keyferry.input-sequence.v1","command_id":"{command_id}","arm":"command-scoped","start_within_ms":5000,"actions":[{{"type":"click","button":"button_1","button":"button_2"}}]}}"#
        );
        let mut router = daemon.router();
        let response = router
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/devices/{SIMULATOR_DEVICE_ID}/input-sequences"))
                    .header(header::AUTHORIZATION, "Bearer test-token-123456")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response["error"], "input.duplicate_field");
        let encoded = response.to_string();
        assert!(!encoded.contains("button_1"));
        assert!(!encoded.contains("button_2"));
    }

    #[tokio::test]
    async fn input_sequence_deduplicates_same_plan_and_conflicts_on_change() {
        let transport = Arc::new(SimulatorTransport::default().with_input_sequence());
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");
        let command_id = Uuid::now_v7();
        let request = pointer_input_request(command_id);
        let first = daemon
            .submit_input_sequence(SIMULATOR_DEVICE_ID, "test".to_owned(), request.clone())
            .await
            .expect("first submission");
        assert_eq!(
            daemon.wait_for_terminal(command_id).await,
            Some(CommandOutcome::Emitted)
        );
        let duplicate = daemon
            .submit_input_sequence(SIMULATOR_DEVICE_ID, "test".to_owned(), request.clone())
            .await
            .expect("identical duplicate");
        assert_eq!(duplicate.command_id, first.command_id);
        assert_eq!(duplicate.outcome, CommandOutcome::Emitted);
        assert_eq!(transport.execution_count(command_id), 1);

        let mut changed = request;
        changed.actions = vec![keyferry_layouts::InputAction::MoveRelative {
            dx_counts: 11,
            dy_counts: -5,
        }];
        let error = daemon
            .submit_input_sequence(SIMULATOR_DEVICE_ID, "test".to_owned(), changed)
            .await
            .expect_err("same id with changed plan must conflict");
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(transport.execution_count(command_id), 1);
    }

    #[tokio::test]
    async fn sequence_route_rejects_bodies_over_65536_bytes() {
        let daemon = daemon();
        let mut router = daemon.router();
        let response = router
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/devices/{SIMULATOR_DEVICE_ID}/sequences"))
                    .header(header::AUTHORIZATION, "Bearer test-token-123456")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(" ".repeat(MAX_SEQUENCE_REQUEST_BODY + 1)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn sequence_require_existing_rejects_before_endpoint_contact() {
        let transport = Arc::new(SimulatorTransport::default());
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");
        let result = daemon
            .submit_sequence(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                KeyboardSequenceV1 {
                    schema: keyferry_layouts::SEQUENCE_SCHEMA_V1.to_owned(),
                    command_id: Uuid::now_v7().to_string(),
                    profile: "windows-us".to_owned(),
                    arm: SequenceArmPolicy::RequireExisting,
                    start_within_ms: 5_000,
                    timing: None,
                    actions: vec![keyferry_layouts::SequenceAction::Tap {
                        key: "ENTER".to_owned(),
                        timing: None,
                    }],
                },
            )
            .await;
        assert_eq!(result.unwrap_err().status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(transport.control_request_counts(), (0, 0, 0));
    }

    #[tokio::test]
    async fn retained_outcome_query_is_read_only_and_observes_terminal_state() {
        let transport =
            Arc::new(SimulatorTransport::default().with_accept_delay(Duration::from_millis(25)));
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");
        arm(&daemon).await;

        let submitted = daemon
            .submit_text(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                TypeRequest {
                    text: "a".to_owned(),
                    profile: default_profile(),
                    timing: default_timing(),
                    expires_in_ms: None,
                    command_id: None,
                },
            )
            .await
            .expect("submit");
        let command_id = Uuid::parse_str(&submitted.command_id).expect("command UUID");
        let initial = daemon
            .command_outcome(SIMULATOR_DEVICE_ID, command_id)
            .expect("initial outcome");
        assert_eq!(initial.command_id, submitted.command_id);
        assert_eq!(initial.device_id, SIMULATOR_DEVICE_ID);
        assert!(!initial.outcome.is_terminal());

        assert_eq!(
            daemon.wait_for_terminal(command_id).await,
            Some(CommandOutcome::Emitted)
        );
        let event_count = daemon.metadata().len();
        let terminal = daemon
            .command_outcome(SIMULATOR_DEVICE_ID, command_id)
            .expect("terminal outcome");
        let repeated = daemon
            .command_outcome(SIMULATOR_DEVICE_ID, command_id)
            .expect("repeated outcome");
        assert_eq!(terminal.outcome, CommandOutcome::Emitted);
        assert_eq!(repeated, terminal);
        assert_eq!(daemon.metadata().len(), event_count);
        assert_eq!(transport.execution_count(command_id), 1);

        let missing = daemon
            .command_outcome(SIMULATOR_DEVICE_ID, Uuid::now_v7())
            .expect_err("unknown command must fail");
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn temporary_renew_and_disarm_are_sent_to_the_endpoint() {
        let transport = Arc::new(SimulatorTransport::default());
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");

        daemon
            .arm_device(
                SIMULATOR_DEVICE_ID,
                ArmRequest {
                    policy: "temporary".to_owned(),
                    lease_ms: Some(1_000),
                },
            )
            .await
            .expect("temporary arm");
        daemon
            .renew_arm_lease(SIMULATOR_DEVICE_ID, 2_000)
            .await
            .expect("renew lease");
        assert!(transport.is_remotely_armed());
        assert_eq!(transport.control_request_counts(), (1, 0, 1));

        daemon
            .disarm_device(SIMULATOR_DEVICE_ID)
            .await
            .expect("disarm");
        assert!(!daemon.device_view(SIMULATOR_DEVICE_ID).unwrap().armed);
        assert!(!transport.is_remotely_armed());
        assert_eq!(transport.control_request_counts(), (1, 1, 1));
    }

    #[tokio::test]
    async fn invalid_command_scoped_lease_is_rejected_before_endpoint_contact() {
        let transport = Arc::new(SimulatorTransport::default());
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");

        let error = daemon
            .arm_device(
                SIMULATOR_DEVICE_ID,
                ArmRequest {
                    policy: "command-scoped".to_owned(),
                    lease_ms: Some(1),
                },
            )
            .await
            .expect_err("nonzero command-scoped lease must fail");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(transport.control_request_counts(), (0, 0, 0));
    }

    #[test]
    fn documented_action_json_is_accepted_and_mapped() {
        // The exact shapes in docs/api-v1.md, which apps/keyferry serializes verbatim.
        // If either side drifts this fails here instead of at runtime.
        let json = r#"[
            {"type":"text","value":"hi"},
            {"type":"tap","key":"ENTER"},
            {"type":"chord","keys":["CTRL","L"]}
        ]"#;
        let actions: Vec<ActionRequest> =
            serde_json::from_str(json).expect("documented shape parses");
        let steps = action_steps(&actions)
            .expect("documented actions map to reports")
            .steps;
        assert_eq!(steps.len(), 8 + 4 + 4, "two characters, one tap, one chord");
        // Ctrl+L must not smuggle in an implicit Shift.
        assert_eq!(
            steps[12],
            ReportStep::Report(KeyboardReport::single(0x01, 0x0f))
        );
    }

    #[test]
    fn compatibility_tap_keeps_legacy_layout_derived_shift() {
        let action: ActionRequest =
            serde_json::from_str(r#"{"type":"tap","key":"A"}"#).expect("action parses");
        let compiled = action_steps(&[action]).expect("legacy tap compiles through sequence IR");
        assert_eq!(
            compiled.steps[0],
            ReportStep::Report(KeyboardReport::single(0x02, 0x04))
        );
    }

    #[test]
    fn raw_hid_action_json_is_refused() {
        // Raw HID is an internal representation; ordinary clients must not send it.
        let json = r#"[{"type":"tap","usage":4,"modifiers":1}]"#;
        assert!(
            serde_json::from_str::<Vec<ActionRequest>>(json).is_err(),
            "raw HID fields must be rejected outright, not silently ignored"
        );
    }

    #[test]
    fn compatibility_actions_reject_fields_from_another_variant() {
        let action: ActionRequest =
            serde_json::from_str(r#"{"type":"tap","key":"ENTER","value":"must-not-be-ignored"}"#)
                .expect("known compatibility fields parse before semantic validation");
        assert_eq!(
            action_steps(&[action]),
            Err("tap action contains an inapplicable field".to_owned())
        );
    }

    #[tokio::test]
    async fn api_auth_requires_exact_bearer_token() {
        let daemon = daemon();
        let missing = authorize(&HeaderMap::new(), &daemon);
        assert!(matches!(
            missing,
            Err(ApiError {
                status: StatusCode::UNAUTHORIZED,
                ..
            })
        ));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        assert!(matches!(
            authorize(&headers, &daemon),
            Err(ApiError {
                status: StatusCode::UNAUTHORIZED,
                ..
            })
        ));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-token-123456"),
        );
        assert_eq!(authorize(&headers, &daemon).unwrap(), "local");

        let mut router = daemon.router();
        let response = router
            .call(
                Request::builder()
                    .uri("/v1/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn remote_listener_accepts_only_tailscale_address_ranges() {
        assert!(is_tailscale_ip("100.64.0.1".parse().unwrap()));
        assert!(is_tailscale_ip("100.127.255.254".parse().unwrap()));
        assert!(is_tailscale_ip("fd7a:115c:a1e0::1".parse().unwrap()));
        for address in ["127.0.0.1", "0.0.0.0", "100.128.0.1", "192.168.1.10", "::1"] {
            assert!(!is_tailscale_ip(address.parse().unwrap()));
        }
    }

    #[tokio::test]
    async fn remote_router_requires_distinct_strong_bearer_for_control() {
        let same_token = "abababababababababababababababababababababababababababababababab";
        let same_token_daemon =
            Daemon::new(MemoryTokenStore::new(same_token)).expect("same-token daemon");
        assert!(same_token_daemon
            .remote_router(RemoteApiPolicy::new(MemoryTokenStore::new(same_token)).unwrap())
            .is_err());
        assert!(RemoteApiPolicy::new(MemoryTokenStore::new("weak-human-token")).is_err());
        assert!(RemoteApiPolicy::new(MemoryTokenStore::new(
            "CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"
        ))
        .is_err());
        let daemon = daemon();
        let policy = RemoteApiPolicy::new(MemoryTokenStore::new(REMOTE_TOKEN)).unwrap();
        let mut router = daemon.remote_router(policy).unwrap();

        let missing_bearer = router
            .call(
                Request::builder()
                    .uri("/v1/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_bearer.status(), StatusCode::UNAUTHORIZED);

        let authenticated = router
            .call(
                Request::builder()
                    .uri("/v1/devices")
                    .header(header::AUTHORIZATION, REMOTE_BEARER)
                    .header("x-keyferry-caller", "spoofed")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated.status(), StatusCode::OK);

        let arm_response = router
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/devices/{SIMULATOR_DEVICE_ID}/arm"))
                    .header(header::AUTHORIZATION, REMOTE_BEARER)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"policy":"command-scoped"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(arm_response.status(), StatusCode::OK);
        let command_response = router
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/devices/{SIMULATOR_DEVICE_ID}/type"))
                    .header(header::AUTHORIZATION, REMOTE_BEARER)
                    .header("X-Keyferry-Caller", "spoofed")
                    .header("x-keyferry-extra", "also-spoofed")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"text":"a","profile":"windows-us","timing":"desktop-safe"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(command_response.status(), StatusCode::ACCEPTED);
        assert_eq!(daemon.metadata().last().unwrap().caller, "tailnet");

        let maintenance = router
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/devices/{SIMULATOR_DEVICE_ID}/maintenance/begin"
                    ))
                    .header(header::AUTHORIZATION, REMOTE_BEARER)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(maintenance.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn owner_remote_router_uses_verified_tls_installation_identity() {
        let identity = HostIdentity::generate().unwrap();
        let gateway_transport =
            TlsTransport::new(TlsCredentials::new(identity, [0x22; 16], [0x77; 32])).unwrap();
        gateway_transport.set_test_session_snapshot(tls::TlsSessionSnapshot {
            link_path: tls::TlsLinkPath::Wifi,
            protocol_session_id: [0x44; 16],
            firmware_identity: None,
        });
        let daemon = Daemon::with_device_transport_and_gateway(
            MemoryTokenStore::new("test-token-123456"),
            SIMULATOR_DEVICE_ID.to_owned(),
            "Simulator keyboard".to_owned(),
            Arc::new(SimulatorTransport::default()),
            Some(GatewayAuthority {
                transport: gateway_transport,
                daemon_boot_id: [0x33; 16],
            }),
        )
        .unwrap();
        let mut router = daemon.owner_remote_router();
        let installation_id = [0x5a; 16];
        daemon.0.owner_routes.lock().unwrap().insert(
            (SIMULATOR_DEVICE_ID.to_owned(), installation_id),
            OwnerRouteLease {
                endpoint_session_id: [0x44; 16],
                proof_digest: [0x45; 32],
                expires_at: Instant::now() + Duration::from_secs(1),
            },
        );

        let mut arm_request = Request::builder()
            .method("POST")
            .uri(format!("/v1/devices/{SIMULATOR_DEVICE_ID}/arm"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-keyferry-caller", "spoofed")
            .body(Body::from(r#"{"policy":"command-scoped"}"#))
            .unwrap();
        arm_request
            .extensions_mut()
            .insert(owner_peer(installation_id));
        assert_eq!(
            router.call(arm_request).await.unwrap().status(),
            StatusCode::OK
        );

        let mut type_request = Request::builder()
            .method("POST")
            .uri(format!("/v1/devices/{SIMULATOR_DEVICE_ID}/type"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-keyferry-caller", "spoofed")
            .body(Body::from(
                r#"{"text":"a","profile":"windows-us","timing":"desktop-safe"}"#,
            ))
            .unwrap();
        type_request
            .extensions_mut()
            .insert(owner_peer(installation_id));
        assert_eq!(
            router.call(type_request).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            daemon.metadata().last().unwrap().caller,
            "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
        );
    }

    #[tokio::test]
    async fn owner_remote_mutation_requires_fresh_route_but_disarm_does_not() {
        let daemon = daemon();
        let mut router = daemon.owner_remote_router();
        let peer = owner_peer([0x5a; 16]);
        let mut arm_request = Request::builder()
            .method("POST")
            .uri(format!("/v1/devices/{SIMULATOR_DEVICE_ID}/arm"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"policy":"command-scoped"}"#))
            .unwrap();
        arm_request.extensions_mut().insert(peer.clone());
        assert_eq!(
            router.call(arm_request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let mut disarm_request = Request::builder()
            .method("POST")
            .uri(format!("/v1/devices/{SIMULATOR_DEVICE_ID}/disarm"))
            .body(Body::empty())
            .unwrap();
        disarm_request.extensions_mut().insert(peer);
        assert_eq!(
            router.call(disarm_request).await.unwrap().status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn targeted_handoff_readiness_is_bound_to_the_live_target_and_previous_gateway() {
        let daemon = daemon();
        let transaction_id = Uuid::now_v7();
        let target_address = SocketAddr::from(([192, 168, 30, 50], 7443));
        daemon
            .0
            .gateway_listeners
            .set_test_snapshot(discovery::GatewayListenerSnapshot {
                generation: 7,
                addresses: vec![target_address],
            });
        *daemon.0.owner_control_listener.lock().unwrap() = OwnerControlListenerState {
            generation: 4,
            address: Some(SocketAddr::from((
                [100, 64, 0, 2],
                keyferry_gateway::OWNER_GATEWAY_CONTROL_PORT,
            ))),
        };
        daemon
            .lookup(SIMULATOR_DEVICE_ID)
            .unwrap()
            .0
            .lock()
            .unwrap()
            .gateway_handoff = Some(GatewayHandoffReservation {
            transaction_id,
            previous_installation_id: [0x5a; 16],
            target_installation_id: [0x6b; 16],
            readiness_nonce: [0x77; 16],
            target_address,
            listener_generation: 7,
            target_control_port: keyferry_gateway::OWNER_GATEWAY_CONTROL_PORT,
            proof_digest: None,
            expires_at: Instant::now() + Duration::from_secs(10),
            phase: "ready".to_owned(),
            reason: None,
        });
        let body = serde_json::json!({
            "challenge": "11".repeat(16),
            "readiness_nonce": "77".repeat(16),
            "proof_digest": "88".repeat(32),
        });
        let mut request = Request::builder()
            .method("POST")
            .uri(format!(
                "/v2/devices/{SIMULATOR_DEVICE_ID}/gateway/handoffs/{transaction_id}/ready"
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        request.extensions_mut().insert(owner_peer([0x5a; 16]));
        let response = daemon.owner_remote_router().call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response: ConfirmGatewayHandoffReadyResponse =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(response.transaction_id, transaction_id);
        assert_eq!(response.challenge, "11".repeat(16));
        assert_eq!(response.proof_digest, "88".repeat(32));
        let runtime = daemon.lookup(SIMULATOR_DEVICE_ID).unwrap();
        let device = runtime.0.lock().unwrap();
        let reservation = device.gateway_handoff.as_ref().unwrap();
        assert_eq!(reservation.phase, "confirmed_ready");
        assert_eq!(reservation.proof_digest, Some([0x88; 32]));
    }

    #[tokio::test]
    async fn targeted_handoff_rejects_unbound_connection_and_accepts_exact_rollback_report() {
        let daemon = daemon();
        let transaction_id = Uuid::now_v7();
        let runtime = daemon.lookup(SIMULATOR_DEVICE_ID).unwrap().0;
        {
            let mut device = runtime.lock().unwrap();
            device.state.disconnect();
            device.gateway_handoff = Some(GatewayHandoffReservation {
                transaction_id,
                previous_installation_id: [0x5a; 16],
                target_installation_id: [0x6b; 16],
                readiness_nonce: [0x77; 16],
                target_address: SocketAddr::from(([192, 168, 30, 50], 7443)),
                listener_generation: 7,
                target_control_port: keyferry_gateway::OWNER_GATEWAY_CONTROL_PORT,
                proof_digest: None,
                expires_at: Instant::now() + Duration::from_secs(10),
                phase: "ready".to_owned(),
                reason: None,
            });
        }

        daemon.mark_transport_ready(&runtime);
        assert_eq!(
            runtime.lock().unwrap().state.link,
            keyferry_core::LinkState::Offline
        );

        let body = serde_json::to_vec(&ReportGatewayHandoffOutcomeRequest {
            phase: "failed_restored".to_owned(),
            reason: Some("endpoint_reason_1".to_owned()),
        })
        .unwrap();
        let uri =
            format!("/v2/devices/{SIMULATOR_DEVICE_ID}/gateway/handoffs/{transaction_id}/outcome");
        let mut wrong = Request::builder()
            .method("POST")
            .uri(&uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.clone()))
            .unwrap();
        wrong.extensions_mut().insert(owner_peer([0x4a; 16]));
        assert_eq!(
            daemon
                .owner_remote_router()
                .call(wrong)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let mut exact = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        exact.extensions_mut().insert(owner_peer([0x5a; 16]));
        let response = daemon.owner_remote_router().call(exact).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response: GatewayHandoffResponse =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(response.phase, "failed_restored");
        assert!(response.terminal);
    }

    #[test]
    fn owner_callback_http_response_requires_one_exact_content_length() {
        let response = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";
        assert!(matches!(
            forward::parse_http_response(response),
            forward::HttpParse::Complete {
                status: 200,
                body: b"{}",
                ..
            }
        ));
        assert!(matches!(
            forward::parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}"),
            forward::HttpParse::Incomplete
        ));
        for malformed in [
            &b"HTTP/1.1 200 OK\r\n\r\n{}"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{}"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}"[..],
            &b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}"[..],
            &b"HTTP/1.1 2000 OK\r\nContent-Length: 2\r\n\r\n{}"[..],
        ] {
            assert!(matches!(
                forward::parse_http_response(malformed),
                forward::HttpParse::Malformed
            ));
        }
    }

    #[tokio::test]
    async fn untargeted_gateway_yield_is_retired_and_is_not_on_other_routers() {
        let identity = HostIdentity::generate().unwrap();
        let device_id = Uuid::parse_str("cc48680b-4365-42c0-a195-5823677bbc47").unwrap();
        let transport = TlsTransport::new(TlsCredentials::new(
            identity,
            *device_id.as_bytes(),
            [0x77; 32],
        ))
        .unwrap();
        let daemon = Daemon::with_tls_transport(
            MemoryTokenStore::new("test-token-123456"),
            device_id.to_string(),
            "Paired keyboard".to_owned(),
            transport.clone(),
        )
        .unwrap();
        daemon
            .lookup(&device_id.to_string())
            .unwrap()
            .0
            .lock()
            .unwrap()
            .state
            .set_link_authenticated();
        let installation_id = [0x5a; 16];
        let peer = owner_peer(installation_id);
        let uri = format!("/v2/devices/{device_id}/gateway/yield");

        let mut owner = daemon.owner_remote_router();
        let mut request = Request::builder()
            .method("POST")
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(peer.clone());
        assert_eq!(
            owner.call(request).await.unwrap().status(),
            StatusCode::CONFLICT
        );
        assert!(!transport.is_in_maintenance());

        let mut request = Request::builder()
            .method("POST")
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(peer);
        let response = owner.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(!transport.is_in_maintenance());

        let response = daemon
            .router()
            .call(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header(header::AUTHORIZATION, "Bearer test-token-123456")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut legacy = daemon
            .remote_router(RemoteApiPolicy::new(MemoryTokenStore::new(REMOTE_TOKEN)).unwrap())
            .unwrap();
        let response = legacy
            .call(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::AUTHORIZATION, REMOTE_BEARER)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn outgoing_gateway_handoff_orchestration_is_local_only() {
        let daemon = daemon();
        let body = serde_json::json!({
            "transaction_id": Uuid::now_v7(),
            "target_installation_id": "44".repeat(16),
            "previous_installation_id": "33".repeat(16),
            "target_gateway_address": "100.64.0.2",
            "readiness_nonce": "55".repeat(16),
            "target_ipv4": "192.168.30.50",
            "target_port": keyferry_protocol::roaming::DEVICE_TLS_PORT,
            "target_control_port": keyferry_gateway::OWNER_GATEWAY_CONTROL_PORT,
        });
        let uri = format!("/v1/devices/{SIMULATOR_DEVICE_ID}/gateway/outgoing-handoff");
        let response = daemon
            .router()
            .call(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header(header::AUTHORIZATION, "Bearer test-token-123456")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let mut owner_request = Request::builder()
            .method("POST")
            .uri(&uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        owner_request
            .extensions_mut()
            .insert(owner_peer([0x44; 16]));
        assert_eq!(
            daemon
                .owner_remote_router()
                .call(owner_request)
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );

        let mut legacy = daemon
            .remote_router(RemoteApiPolicy::new(MemoryTokenStore::new(REMOTE_TOKEN)).unwrap())
            .unwrap();
        let response = legacy
            .call(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::AUTHORIZATION, REMOTE_BEARER)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn gateway_yield_auto_resumes_without_clearing_newer_maintenance() {
        let identity = HostIdentity::generate().unwrap();
        let device_id = Uuid::parse_str("cc48680b-4365-42c0-a195-5823677bbc47").unwrap();
        let transport = TlsTransport::new(TlsCredentials::new(
            identity,
            *device_id.as_bytes(),
            [0x77; 32],
        ))
        .unwrap();
        let daemon = Daemon::with_tls_transport(
            MemoryTokenStore::new("test-token-123456"),
            device_id.to_string(),
            "Paired keyboard".to_owned(),
            transport.clone(),
        )
        .unwrap();
        daemon
            .lookup(&device_id.to_string())
            .unwrap()
            .0
            .lock()
            .unwrap()
            .state
            .set_link_authenticated();

        daemon
            .yield_device_gateway(&device_id.to_string(), Duration::from_millis(20))
            .await
            .unwrap();
        assert!(
            daemon
                .device_view(&device_id.to_string())
                .unwrap()
                .maintenance
        );
        assert!(transport.is_in_maintenance());
        daemon
            .begin_device_maintenance(&device_id.to_string())
            .await
            .unwrap();
        time::sleep(Duration::from_millis(40)).await;
        assert!(
            daemon
                .device_view(&device_id.to_string())
                .unwrap()
                .maintenance
        );
        assert!(transport.is_in_maintenance());

        daemon
            .finish_device_maintenance(&device_id.to_string())
            .unwrap();
        assert!(
            !daemon
                .device_view(&device_id.to_string())
                .unwrap()
                .maintenance
        );
        assert!(!transport.is_in_maintenance());

        daemon
            .lookup(&device_id.to_string())
            .unwrap()
            .0
            .lock()
            .unwrap()
            .state
            .set_link_authenticated();
        daemon
            .yield_device_gateway(&device_id.to_string(), Duration::from_millis(20))
            .await
            .unwrap();
        time::sleep(Duration::from_millis(40)).await;
        assert!(
            !daemon
                .device_view(&device_id.to_string())
                .unwrap()
                .maintenance
        );
        assert!(!transport.is_in_maintenance());
    }

    #[tokio::test]
    async fn gateway_yield_rejects_unsafe_device_states_before_transport_pause() {
        let identity = HostIdentity::generate().unwrap();
        let device_id = Uuid::parse_str("cc48680b-4365-42c0-a195-5823677bbc47").unwrap();
        let transport = TlsTransport::new(TlsCredentials::new(
            identity,
            *device_id.as_bytes(),
            [0x77; 32],
        ))
        .unwrap();
        let daemon = Daemon::with_tls_transport(
            MemoryTokenStore::new("test-token-123456"),
            device_id.to_string(),
            "Paired keyboard".to_owned(),
            transport.clone(),
        )
        .unwrap();
        let handle = daemon.lookup(&device_id.to_string()).unwrap();

        assert!(daemon
            .yield_device_gateway(&device_id.to_string(), Duration::from_millis(20))
            .await
            .is_err());
        assert!(!transport.is_in_maintenance());

        {
            let mut device = handle.0.lock().unwrap();
            device.state.set_link_authenticated();
            device.state.arm(ArmPolicy::AlwaysReady).unwrap();
        }
        assert!(daemon
            .yield_device_gateway(&device_id.to_string(), Duration::from_millis(20))
            .await
            .is_err());
        assert!(!transport.is_in_maintenance());

        {
            let mut device = handle.0.lock().unwrap();
            device.state.disarm();
            device.current = Some(Uuid::now_v7());
        }
        assert!(daemon
            .yield_device_gateway(&device_id.to_string(), Duration::from_millis(20))
            .await
            .is_err());
        assert!(!transport.is_in_maintenance());

        {
            let mut device = handle.0.lock().unwrap();
            device.current = None;
            device.maintenance = true;
        }
        assert!(daemon
            .yield_device_gateway(&device_id.to_string(), Duration::from_millis(20))
            .await
            .is_err());
        assert!(!transport.is_in_maintenance());
    }

    #[tokio::test]
    async fn owner_gateway_candidate_discloses_only_untrusted_route_identity() {
        let installation_id = [0x5a; 16];
        let mut router = owner_gateway_candidate_router(installation_id).unwrap();
        let response = router
            .call(
                Request::builder()
                    .uri(keyferry_gateway::OWNER_GATEWAY_CANDIDATE_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 512).await.unwrap();
        assert_eq!(
            keyferry_gateway::OwnerGatewayCandidate::from_json(&body)
                .unwrap()
                .installation_id,
            installation_id
        );
        assert!(owner_gateway_candidate_router([0; 16]).is_err());

        let response = router
            .call(
                Request::builder()
                    .uri("/v1/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn owner_route_proof_is_bound_to_verified_caller_and_selected_device() {
        let controller_installation_id = [0x5a; 16];
        let controller_nonce = [0x6b; 32];
        let device_id = Uuid::parse_str("cc48680b-4365-42c0-a195-5823677bbc47").unwrap();
        let proof = keyferry_gateway::SignedRouteProof {
            input: keyferry_gateway::RouteProofInput {
                owner_id: [0x11; 16],
                device_id: *device_id.as_bytes(),
                epoch: 1,
                policy_sequence: 1,
                policy_hash: [0x22; 32],
                gateway_installation_id: [0x33; 16],
                controller_installation_id,
                controller_nonce,
                device_boot_nonce: [0x44; 16],
                endpoint_session_id: [0x55; 16],
                link_path: GatewayLinkPath::Bluetooth,
                usb_ready: true,
            },
            tag: [0x66; 32],
        };
        let transport = Arc::new(SimulatorTransport::default().with_route_proof(proof.clone()));
        let daemon = Daemon::with_device_transport(
            MemoryTokenStore::new("test-token-123456"),
            device_id.to_string(),
            "Keyferry".to_owned(),
            transport,
        )
        .unwrap();
        let mut router = daemon.owner_remote_router();
        let mut request = Request::builder()
            .uri(format!(
                "/v2/devices/{device_id}/route-proof?nonce={}",
                encode_hex(&controller_nonce)
            ))
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(owner_peer(controller_installation_id));
        let response = router.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let response: RouteProofResponse = serde_json::from_slice(&body).unwrap();
        let decoded = decode_hex_vec(&response.proof);
        assert_eq!(
            keyferry_gateway::decode_route_proof_response(&decoded).unwrap(),
            proof
        );

        let mut request = Request::builder()
            .uri(format!(
                "/v2/devices/{device_id}/route-proof?nonce={}",
                encode_hex(&controller_nonce)
            ))
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(owner_peer([0x7c; 16]));
        assert_eq!(
            router.call(request).await.unwrap().status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn remote_probe_needs_no_bearer_but_still_uses_signed_proof() {
        let daemon = daemon();
        let policy = RemoteApiPolicy::new(MemoryTokenStore::new(REMOTE_TOKEN)).unwrap();
        let mut router = daemon.remote_router(policy).unwrap();
        let response = router
            .call(
                Request::builder()
                    .uri(format!("/v1/gateway/probe?nonce={}", "11".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn gateway_probe_needs_no_bearer_and_returns_a_verifiable_nonce_bound_proof() {
        let identity = HostIdentity::generate().unwrap();
        let trusted_spki = identity_spki(&identity);
        let device_id = Uuid::parse_str("cc48680b-4365-42c0-a195-5823677bbc47").unwrap();
        let transport = TlsTransport::new(TlsCredentials::new(
            identity,
            *device_id.as_bytes(),
            [0x77; 32],
        ))
        .unwrap();
        let daemon = Daemon::with_tls_transport(
            MemoryTokenStore::new("test-token-123456"),
            device_id.to_string(),
            "Paired keyboard".to_owned(),
            transport,
        )
        .unwrap();
        assert_eq!(
            daemon
                .device_view(&device_id.to_string())
                .unwrap()
                .link_path
                .as_deref(),
            Some("offline")
        );
        let nonce = [0x5a; 32];
        let mut router = daemon.router();
        let response = router
            .call(
                Request::builder()
                    .uri(format!("/v1/gateway/probe?nonce={}", encode_hex(&nonce)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        assert!(matches!(
            keyferry::gateway_probe::classify_gateway_response(
                &body,
                nonce,
                std::slice::from_ref(&trusted_spki)
            ),
            keyferry::gateway_probe::GatewayCandidateClassification::AuthenticatedGateway(_)
        ));
        let response: GatewayProbeResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(response.request_nonce, encode_hex(&nonce));
        assert!(response
            .request_nonce
            .bytes()
            .all(|byte| !byte.is_ascii_uppercase()));
        assert_eq!(response.devices.len(), 1);
        assert_eq!(
            response.devices[0].device_id,
            encode_hex(device_id.as_bytes())
        );
        assert!(response.devices[0].configured_here);
        assert!(!response.devices[0].session_online);
        assert_eq!(response.devices[0].link_path, "offline");
        assert!(!response.devices[0].armed);

        let proof = SignedGatewayProof {
            payload: GatewayProofPayload {
                protocol_version: response.protocol_version,
                request_nonce: decode_hex(&response.request_nonce),
                gateway_id: decode_hex(&response.gateway_id),
                daemon_boot_id: decode_hex(&response.daemon_boot_id),
                api_version: response.api_version,
                devices: response
                    .devices
                    .into_iter()
                    .map(|device| GatewayDeviceSummary {
                        device_id: decode_hex(&device.device_id),
                        configured_here: device.configured_here,
                        session_online: device.session_online,
                        link_path: match device.link_path.as_str() {
                            "offline" => GatewayLinkPath::Offline,
                            "wifi" => GatewayLinkPath::Wifi,
                            "bluetooth" => GatewayLinkPath::Bluetooth,
                            _ => panic!("unexpected link path"),
                        },
                        tls_hmac_authenticated: device.tls_hmac_authenticated,
                        protocol_session_id: device.protocol_session_id.as_deref().map(decode_hex),
                        armed: device.armed,
                        arm_mode: match device.arm_mode.as_str() {
                            "disarmed" => GatewayArmMode::Disarmed,
                            "command_scoped" => GatewayArmMode::CommandScoped,
                            "temporary" => GatewayArmMode::Temporary,
                            "always_ready" => GatewayArmMode::AlwaysReady,
                            _ => panic!("unexpected arm mode"),
                        },
                    })
                    .collect(),
            },
            signature_der: decode_hex_vec(&response.signature_der),
        };
        verify_gateway_proof(&proof, nonce, &trusted_spki).unwrap();
        assert_eq!(
            verify_gateway_proof(&proof, [0x5b; 32], &trusted_spki),
            Err(GatewayProofError::NonceMismatch)
        );
    }

    #[tokio::test]
    async fn gateway_probe_rejects_missing_malformed_or_ambiguous_nonce() {
        let identity = HostIdentity::generate().unwrap();
        let device_id = Uuid::parse_str("cc48680b-4365-42c0-a195-5823677bbc47").unwrap();
        let transport = TlsTransport::new(TlsCredentials::new(
            identity,
            *device_id.as_bytes(),
            [0x77; 32],
        ))
        .unwrap();
        let daemon = Daemon::with_tls_transport(
            MemoryTokenStore::new("test-token-123456"),
            device_id.to_string(),
            "Paired keyboard".to_owned(),
            transport,
        )
        .unwrap();
        for uri in [
            "/v1/gateway/probe",
            "/v1/gateway/probe?nonce=00",
            "/v1/gateway/probe?nonce=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "/v1/gateway/probe?nonce=0000000000000000000000000000000000000000000000000000000000000000&nonce=1111111111111111111111111111111111111111111111111111111111111111",
        ] {
            let mut router = daemon.router();
            let response = router
                .call(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
    }

    #[tokio::test]
    async fn command_outcome_api_exposes_retained_state_by_id() {
        let daemon = daemon();
        arm(&daemon).await;
        let submitted = daemon
            .submit_text(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                TypeRequest {
                    text: "a".to_owned(),
                    profile: default_profile(),
                    timing: default_timing(),
                    expires_in_ms: None,
                    command_id: None,
                },
            )
            .await
            .expect("submit");
        let command_id = Uuid::parse_str(&submitted.command_id).expect("command UUID");
        assert_eq!(
            daemon.wait_for_terminal(command_id).await,
            Some(CommandOutcome::Emitted)
        );

        let mut router = daemon.router();
        let response = router
            .call(
                Request::builder()
                    .uri(format!(
                        "/v1/devices/{SIMULATOR_DEVICE_ID}/commands/{command_id}"
                    ))
                    .header(header::AUTHORIZATION, "Bearer test-token-123456")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096)
            .await
            .expect("outcome response body");
        let outcome: serde_json::Value =
            serde_json::from_slice(&body).expect("outcome response JSON");
        assert_eq!(outcome["command_id"], command_id.to_string());
        assert_eq!(outcome["device_id"], SIMULATOR_DEVICE_ID);
        assert_eq!(outcome["outcome"], "EMITTED");
        assert_eq!(outcome["terminal"], true);
        assert_eq!(outcome["possible_start"], true);
        assert_eq!(outcome["terminal_zero_confirmed"], true);
        assert!(outcome.get("text").is_none());
        assert!(outcome.get("actions").is_none());

        let response = router
            .call(
                Request::builder()
                    .uri(format!(
                        "/v1/devices/{SIMULATOR_DEVICE_ID}/commands/not-a-uuid"
                    ))
                    .header(header::AUTHORIZATION, "Bearer test-token-123456")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn chunks_never_exceed_duration_or_hold_keys() {
        for timing in [TypingTiming::DESKTOP_SAFE, TypingTiming::COMPATIBILITY] {
            let steps = plan_text_us(&"a".repeat(100), timing).expect("layout");
            let chunks = plan_chunks(steps).expect("chunks");
            assert!(chunks.iter().all(|chunk| {
                let (_, payload_len) = chunk_metrics(&chunk.steps);
                chunk.expected_ms <= MAX_CHUNK_EXPECTED_MS
                    && chunk.steps.len() <= MAX_CHUNK_ACTIONS
                    && payload_len <= MAX_NETWORK_COMMAND_BODY
                    && ends_released(&chunk.steps)
            }));
            assert!(chunks.len() > 1);
        }
    }

    #[test]
    fn ordered_nonmodifier_chord_stays_within_one_released_chunk() {
        let caps = keyferry_layouts::keyboard_key("CAPS_LOCK").unwrap().code;
        let space = keyferry_layouts::keyboard_key("SPACE").unwrap().code;
        let prefix = KeyboardReport::from_keys(0, &[caps]).unwrap();
        let both = KeyboardReport::from_keys(0, &[caps, space]).unwrap();
        let mut steps = plan_text_us(&"a".repeat(20), TypingTiming::DESKTOP_SAFE).unwrap();
        steps.extend([
            ReportStep::Report(prefix),
            ReportStep::WaitMs(20),
            ReportStep::Report(both),
            ReportStep::WaitMs(12),
            ReportStep::Report(prefix),
            ReportStep::WaitMs(10),
            ReportStep::Report(KeyboardReport::RELEASED),
            ReportStep::WaitMs(40),
        ]);
        let chunks = plan_chunks(steps).unwrap();
        assert!(chunks.len() > 1);
        assert!(chunks.iter().all(|chunk| ends_released(&chunk.steps)));
        assert!(chunks.iter().any(|chunk| {
            let reports: Vec<_> = chunk
                .steps
                .iter()
                .filter_map(|step| match step {
                    ReportStep::Report(report) => Some(*report),
                    ReportStep::WaitMs(_) => None,
                })
                .collect();
            reports
                .windows(4)
                .any(|window| window == [prefix, both, prefix, KeyboardReport::RELEASED])
        }));
    }

    #[test]
    fn wait_only_continuation_chunks_receive_explicit_release() {
        let mut steps = vec![ReportStep::Report(KeyboardReport::RELEASED)];
        steps.extend((0..100).map(|_| ReportStep::WaitMs(100)));
        steps.extend(plan_text_us("a", TypingTiming::DESKTOP_SAFE).expect("trailing key gesture"));
        let chunks = plan_chunks(steps).expect("long released wait chunks");
        assert!(chunks.len() > 10);
        assert!(chunks.iter().all(|chunk| {
            let wait_only = !chunk
                .steps
                .iter()
                .any(|step| matches!(step, ReportStep::Report(report) if !report.is_released()));
            (!wait_only
                || matches!(
                    chunk.steps.first(),
                    Some(ReportStep::Report(report)) if report.is_released()
                ))
                && ends_released(&chunk.steps)
                && chunk.expected_ms <= MAX_CHUNK_EXPECTED_MS
                && chunk.steps.len() <= MAX_CHUNK_ACTIONS
                && chunk_metrics(&chunk.steps).1 <= MAX_NETWORK_COMMAND_BODY
        }));
    }

    #[tokio::test]
    async fn start_expiry_does_not_cap_total_planned_duration() {
        let daemon = daemon();
        arm(&daemon).await;
        let submitted = daemon
            .submit_text(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                TypeRequest {
                    text: "a".repeat(251),
                    profile: default_profile(),
                    timing: default_timing(),
                    expires_in_ms: Some(MAX_COMMAND_EXPIRY_MS),
                    command_id: None,
                },
            )
            .await
            .expect("a plan longer than its start deadline is valid");
        assert_eq!(
            daemon
                .wait_for_terminal(Uuid::parse_str(&submitted.command_id).unwrap())
                .await,
            Some(CommandOutcome::Emitted)
        );
    }

    #[tokio::test]
    async fn hard_deadline_begins_only_after_endpoint_acceptance() {
        let (_accepted_tx, accepted_rx) = watch::channel(false);
        assert_eq!(
            command_deadline(
                Instant::now() + Duration::from_millis(10),
                Duration::from_secs(1),
                accepted_rx,
            )
            .await,
            CommandDeadline::Start
        );

        let (accepted_tx, accepted_rx) = watch::channel(false);
        accepted_tx.send_replace(true);
        let started = Instant::now();
        assert_eq!(
            command_deadline(
                Instant::now() + Duration::from_secs(1),
                Duration::from_millis(10),
                accepted_rx,
            )
            .await,
            CommandDeadline::Execution
        );
        assert!(started.elapsed() >= Duration::from_millis(10));
        assert_eq!(
            CommandDeadline::Start.recovered_outcome(false),
            TransportOutcome::Rejected
        );
        assert_eq!(
            CommandDeadline::Start.recovered_outcome(true),
            TransportOutcome::Aborted
        );
        assert_eq!(
            CommandDeadline::Execution.recovered_outcome(false),
            TransportOutcome::Aborted
        );
    }

    #[test]
    fn cancelled_unknown_becomes_aborted_only_after_terminal_zero() {
        assert_eq!(
            reduce_after_release(TransportOutcome::Unknown, true, true),
            TransportOutcome::Aborted
        );
        assert_eq!(
            reduce_after_release(TransportOutcome::Unknown, true, false),
            TransportOutcome::Unknown
        );
        assert_eq!(
            reduce_after_release(TransportOutcome::Unknown, false, true),
            TransportOutcome::Unknown
        );
        assert_eq!(
            reduce_after_release(TransportOutcome::Aborted, true, true),
            TransportOutcome::Aborted
        );
    }

    #[tokio::test]
    async fn cancelled_unknown_with_confirmed_release_is_aborted() {
        let transport = Arc::new(UnknownOnCancelTransport::default());
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");
        arm(&daemon).await;
        let started = transport.started.notified();
        let submitted = daemon
            .submit_text(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                TypeRequest {
                    text: "a".to_owned(),
                    profile: default_profile(),
                    timing: default_timing(),
                    expires_in_ms: None,
                    command_id: None,
                },
            )
            .await
            .expect("submit");
        timeout(Duration::from_secs(1), started)
            .await
            .expect("transport started");
        daemon
            .cancel_command(
                SIMULATOR_DEVICE_ID,
                CancelRequest {
                    command_id: Some(Uuid::parse_str(&submitted.command_id).unwrap()),
                },
            )
            .await
            .expect("cancel");
        assert_eq!(
            daemon
                .wait_for_terminal(Uuid::parse_str(&submitted.command_id).unwrap())
                .await,
            Some(CommandOutcome::Aborted)
        );
        assert_eq!(
            transport
                .releases
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn cancelled_confirmed_abort_does_not_send_redundant_release() {
        let transport = Arc::new(UnknownOnCancelTransport {
            confirmed_abort: true,
            ..UnknownOnCancelTransport::default()
        });
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");
        arm(&daemon).await;
        let started = transport.started.notified();
        let submitted = daemon
            .submit_text(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                TypeRequest {
                    text: "a".to_owned(),
                    profile: default_profile(),
                    timing: default_timing(),
                    expires_in_ms: None,
                    command_id: None,
                },
            )
            .await
            .expect("submit");
        timeout(Duration::from_secs(1), started)
            .await
            .expect("transport started");
        let command_id = Uuid::parse_str(&submitted.command_id).unwrap();
        daemon
            .cancel_command(
                SIMULATOR_DEVICE_ID,
                CancelRequest {
                    command_id: Some(command_id),
                },
            )
            .await
            .expect("cancel");
        assert_eq!(
            daemon.wait_for_terminal(command_id).await,
            Some(CommandOutcome::Aborted)
        );
        assert_eq!(
            transport
                .releases
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn cancelled_unknown_retains_payload_free_transport_diagnostic() {
        let transport = Arc::new(UnknownOnCancelTransport {
            fail_release: true,
            ..UnknownOnCancelTransport::default()
        });
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");
        arm(&daemon).await;
        let started = transport.started.notified();
        let submitted = daemon
            .submit_text(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                TypeRequest {
                    text: "diagnostic payload must stay private".to_owned(),
                    profile: default_profile(),
                    timing: default_timing(),
                    expires_in_ms: None,
                    command_id: None,
                },
            )
            .await
            .expect("submit");
        timeout(Duration::from_secs(1), started)
            .await
            .expect("transport started");
        let command_id = Uuid::parse_str(&submitted.command_id).unwrap();
        daemon
            .cancel_command(
                SIMULATOR_DEVICE_ID,
                CancelRequest {
                    command_id: Some(command_id),
                },
            )
            .await
            .expect("cancel");
        assert_eq!(
            daemon.wait_for_terminal(command_id).await,
            Some(CommandOutcome::Unknown)
        );
        let retained = daemon
            .command_outcome(SIMULATOR_DEVICE_ID, command_id)
            .expect("retained outcome");
        assert_eq!(
            retained.diagnostic_code,
            Some("cancel.active_result.transport")
        );
        let json = serde_json::to_string(&retained).unwrap();
        assert!(!json.contains("diagnostic payload must stay private"));
    }

    #[tokio::test]
    async fn outcome_transitions_dedup_expiry_and_cancel_are_explicit() {
        let daemon = daemon();
        arm(&daemon).await;
        let request = TypeRequest {
            text: "a".to_owned(),
            profile: default_profile(),
            timing: default_timing(),
            expires_in_ms: None,
            command_id: Some(Uuid::now_v7()),
        };
        let first = daemon
            .submit_text(SIMULATOR_DEVICE_ID, "test".to_owned(), request.clone())
            .await
            .expect("submit");
        let duplicate = daemon
            .submit_text(SIMULATOR_DEVICE_ID, "test".to_owned(), request)
            .await
            .expect("dedup");
        assert_eq!(first.command_id, duplicate.command_id);
        assert_eq!(duplicate.outcome, CommandOutcome::Queued);
        assert_eq!(
            daemon
                .wait_for_terminal(Uuid::parse_str(&first.command_id).unwrap())
                .await,
            Some(CommandOutcome::Emitted)
        );
        assert!(!daemon.device_view(SIMULATOR_DEVICE_ID).unwrap().armed);

        // Expiry must elapse before the transport accepts. The minimum tap plan is
        // 5 ms down + 5 ms gap, so the expiry is 10 ms and accept is delayed past it.
        let delayed =
            Arc::new(SimulatorTransport::default().with_accept_delay(Duration::from_millis(50)));
        let daemon = Daemon::with_transport(MemoryTokenStore::new("test-token-123456"), delayed)
            .expect("delayed expiry daemon");
        arm(&daemon).await;
        let expired = daemon
            .submit_actions(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                ActionsRequest {
                    actions: vec![ActionRequest {
                        action_type: "tap".to_owned(),
                        value: None,
                        key: Some("ENTER".to_owned()),
                        keys: Vec::new(),
                        key_down_ms: 5,
                        release_gap_ms: 5,
                    }],
                    profile: default_profile(),
                    expires_in_ms: Some(10),
                    command_id: None,
                },
            )
            .await
            .expect("submit expired");
        time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            daemon
                .wait_for_terminal(Uuid::parse_str(&expired.command_id).unwrap())
                .await,
            Some(CommandOutcome::Rejected)
        );

        let delayed =
            Arc::new(SimulatorTransport::default().with_chunk_delay(Duration::from_millis(5)));
        let daemon = Daemon::with_transport(MemoryTokenStore::new("test-token-123456"), delayed)
            .expect("delayed daemon");
        arm(&daemon).await;
        let cancellable = daemon
            .submit_actions(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                ActionsRequest {
                    actions: vec![ActionRequest {
                        action_type: "chord".to_owned(),
                        value: None,
                        key: None,
                        keys: vec!["CTRL".to_owned(), "A".to_owned()],
                        key_down_ms: 100,
                        release_gap_ms: 100,
                    }],
                    profile: default_profile(),
                    expires_in_ms: None,
                    command_id: None,
                },
            )
            .await
            .expect("submit cancellable");
        let cancelled = daemon
            .cancel_command(
                SIMULATOR_DEVICE_ID,
                CancelRequest {
                    command_id: Some(Uuid::parse_str(&cancellable.command_id).unwrap()),
                },
            )
            .await
            .expect("cancel");
        assert!(matches!(
            cancelled.outcome,
            CommandOutcome::Queued | CommandOutcome::Started
        ));
        assert_eq!(
            daemon
                .wait_for_terminal(Uuid::parse_str(&cancellable.command_id).unwrap())
                .await,
            Some(CommandOutcome::Aborted)
        );
    }

    #[tokio::test]
    async fn compatibility_actions_and_sequence_share_command_identity() {
        let transport = Arc::new(SimulatorTransport::default());
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");
        arm(&daemon).await;
        let command_id = Uuid::now_v7();

        let first = daemon
            .submit_actions(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                ActionsRequest {
                    actions: vec![ActionRequest {
                        action_type: "text".to_owned(),
                        value: Some("a".to_owned()),
                        key: None,
                        keys: Vec::new(),
                        key_down_ms: 12,
                        release_gap_ms: 40,
                    }],
                    profile: default_profile(),
                    expires_in_ms: None,
                    command_id: Some(command_id),
                },
            )
            .await
            .expect("compatibility submission");
        let duplicate = daemon
            .submit_sequence(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                KeyboardSequenceV1 {
                    schema: SEQUENCE_SCHEMA_V1.to_owned(),
                    command_id: command_id.to_string(),
                    profile: "windows-us".to_owned(),
                    arm: SequenceArmPolicy::RequireExisting,
                    start_within_ms: MAX_COMMAND_EXPIRY_MS,
                    timing: None,
                    actions: vec![SequenceAction::Text {
                        value: "a".to_owned(),
                        timing: None,
                    }],
                },
            )
            .await
            .expect("canonical duplicate");

        assert_eq!(duplicate.command_id, first.command_id);
        assert_eq!(
            duplicate.message.as_deref(),
            Some("duplicate command returned existing outcome")
        );
        assert_eq!(
            daemon.wait_for_terminal(command_id).await,
            Some(CommandOutcome::Emitted)
        );
        assert_eq!(transport.execution_count(command_id), 1);

        arm(&daemon).await;
        let text_command_id = Uuid::now_v7();
        daemon
            .submit_text(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                TypeRequest {
                    text: "b".to_owned(),
                    profile: default_profile(),
                    timing: default_timing(),
                    expires_in_ms: None,
                    command_id: Some(text_command_id),
                },
            )
            .await
            .expect("text compatibility submission");
        daemon
            .submit_sequence(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                KeyboardSequenceV1 {
                    schema: SEQUENCE_SCHEMA_V1.to_owned(),
                    command_id: text_command_id.to_string(),
                    profile: "windows-us".to_owned(),
                    arm: SequenceArmPolicy::RequireExisting,
                    start_within_ms: MAX_COMMAND_EXPIRY_MS,
                    timing: None,
                    actions: vec![SequenceAction::Text {
                        value: "b".to_owned(),
                        timing: None,
                    }],
                },
            )
            .await
            .expect("canonical text duplicate");
        assert_eq!(
            daemon.wait_for_terminal(text_command_id).await,
            Some(CommandOutcome::Emitted)
        );
        assert_eq!(transport.execution_count(text_command_id), 1);
    }

    #[tokio::test]
    async fn no_retry_after_start_and_fixed_outcomes_cover_1000_commands() {
        let faults = (0..1000).map(|index| match index % 6 {
            0 => SimulationFault::None,
            1 => SimulationFault::BeforeAccept,
            2 => SimulationFault::AcceptedButLost,
            3 => SimulationFault::CancelBeforeStart,
            4 => SimulationFault::LostAfterStart,
            _ => SimulationFault::CancelAfterStart,
        });
        let transport = Arc::new(SimulatorTransport::new(faults));
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .expect("daemon");
        let mut command_ids = Vec::with_capacity(1000);
        for index in 0..1000 {
            arm(&daemon).await;
            let response = daemon
                .submit_text(
                    SIMULATOR_DEVICE_ID,
                    format!("caller-{index}"),
                    TypeRequest {
                        text: "x".to_owned(),
                        profile: default_profile(),
                        timing: default_timing(),
                        expires_in_ms: None,
                        command_id: None,
                    },
                )
                .await
                .expect("submit");
            let command_id = Uuid::parse_str(&response.command_id).unwrap();
            command_ids.push(command_id);
            let outcome = timeout(Duration::from_secs(1), daemon.wait_for_terminal(command_id))
                .await
                .expect("terminal timeout")
                .expect("outcome");
            assert!(matches!(
                outcome,
                CommandOutcome::Emitted
                    | CommandOutcome::Aborted
                    | CommandOutcome::Rejected
                    | CommandOutcome::Unknown
            ));
        }
        for (index, command_id) in command_ids.iter().copied().enumerate() {
            if index % 6 == 4 || index % 6 == 5 {
                assert_eq!(transport.execution_count(command_id), 1);
            } else {
                assert!(transport.execution_count(command_id) <= 1);
            }
        }
        let metadata = daemon.metadata();
        assert!(metadata.len() >= 1000);
        assert!(metadata.iter().all(|event| event.outcome.is_terminal()
            || event.outcome == CommandOutcome::Queued
            || event.outcome == CommandOutcome::Accepted
            || event.outcome == CommandOutcome::Started));
        assert!(metadata
            .iter()
            .any(|event| event.outcome == CommandOutcome::Unknown));
    }

    #[test]
    fn metadata_serialization_never_contains_payload() {
        let event = EventRecord {
            command_id: "018f0000-0000-7000-8000-000000000001".to_owned(),
            caller: "unit-test".to_owned(),
            device_id: SIMULATOR_DEVICE_ID.to_owned(),
            profile: "windows-us".to_owned(),
            action_count: 4,
            char_count: 7,
            timestamp: "0.000Z".to_owned(),
            duration_ms: Some(20),
            outcome: CommandOutcome::Emitted,
        };
        let serialized = serde_json::to_string(&event).expect("event json");
        assert!(!serialized.contains("secret payload"));
        assert!(!serialized.contains("text"));
        assert!(!serialized.contains("actions"));
    }

    #[test]
    fn production_diagnostics_are_capture_off_until_a_client_subscribes() {
        assert!(!should_capture_diagnostic_events(0, false));
        assert!(should_capture_diagnostic_events(1, false));
        assert!(should_capture_diagnostic_events(0, true));
    }

    #[test]
    fn file_token_store_is_stable_and_256_bit() {
        let path = std::env::temp_dir().join(format!("keyferry-token-{}", Uuid::now_v7()));
        let store = FileTokenStore::new(path.clone());
        let first = store.load_or_create().expect("create token");
        let second = store.load_or_create().expect("read token");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        fs::remove_file(path).expect("remove test token");
    }

    #[test]
    fn paired_runtime_config_resolves_private_store_without_secret_arguments() {
        let root = std::env::temp_dir().join(format!("keyferry-runtime-{}", Uuid::now_v7()));
        fs::create_dir_all(root.join("secrets")).expect("create test config directory");
        let path = root.join("runtime.json");
        fs::write(
            &path,
            br#"{
                "schema_version": 1,
                "tls_bind": "192.0.2.10:7443",
                "tls_device_id": "00112233-4455-4677-8899-aabbccddeeff",
                "tls_secret_dir": "secrets"
            }"#,
        )
        .expect("write test config");
        let config = PairedRuntimeConfig::load(&path).expect("load paired config");
        assert_eq!(config.bind(), "192.0.2.10:7443".parse().unwrap());
        assert_eq!(config.secret_dir(), root.join("secrets"));
        assert_eq!(config.beacon_plan(), None);

        fs::write(
            &path,
            br#"{
                "schema_version": 1,
                "tls_bind": "192.0.2.10:7443",
                "tls_device_id": "00112233-4455-4677-8899-aabbccddeeff",
                "tls_secret_dir": "secrets",
                "discovery_netmask": "255.255.255.0"
            }"#,
        )
        .expect("write discovery config");
        let config = PairedRuntimeConfig::load(&path).expect("load discovery config");
        assert_eq!(
            config.beacon_plan().expect("beacon plan").destination(),
            "192.0.2.255:43917".parse().unwrap()
        );

        fs::write(
            &path,
            br#"{
                "schema_version": 1,
                "tls_bind": "192.0.2.10:7443",
                "tls_device_id": "00112233-4455-4677-8899-aabbccddeeff",
                "tls_secret_dir": "secrets",
                "discovery_netmask": "255.0.255.0"
            }"#,
        )
        .expect("write invalid discovery config");
        assert!(PairedRuntimeConfig::load(&path).is_err());

        fs::write(
            &path,
            br#"{
                "schema_version": 1,
                "tls_bind": "192.0.2.10:7443",
                "tls_device_id": "00112233-4455-4677-8899-aabbccddeeff",
                "tls_secret_dir": "../escape"
            }"#,
        )
        .expect("write invalid config");
        assert!(PairedRuntimeConfig::load(&path).is_err());
        fs::remove_dir_all(root).expect("remove test config directory");
    }

    #[tokio::test]
    async fn tls_transport_is_not_ready_before_the_listener_authenticates() {
        let identity = HostIdentity::generate().expect("host identity");
        let transport = TlsTransport::new(TlsCredentials::new(identity, [0x11; 16], [0x22; 32]))
            .expect("TLS transport");
        let command = PlannedCommand {
            command_id: Uuid::now_v7(),
            chunks: Vec::new(),
            action_count: 0,
            char_count: 0,
            profile: "windows-us".to_owned(),
            expires_at: Instant::now() + Duration::from_secs(1),
            arm_before_first: false,
            input: None,
        };
        assert_eq!(
            transport.accept(&command).await,
            Err(TransportError::LostBeforeAccept)
        );
    }

    fn long_sequence(command_id: Uuid) -> KeyboardSequenceV1 {
        KeyboardSequenceV1 {
            schema: SEQUENCE_SCHEMA_V1.to_owned(),
            command_id: command_id.to_string(),
            profile: "windows-us".to_owned(),
            arm: SequenceArmPolicy::CommandScoped,
            start_within_ms: 5_000,
            timing: None,
            actions: vec![SequenceAction::Text {
                value: "abcdefghijklmnopqrstuvwxyz".to_owned(),
                timing: None,
            }],
        }
    }

    #[tokio::test]
    async fn shutdown_cancels_running_work_and_refuses_new_work() {
        let transport =
            Arc::new(SimulatorTransport::default().with_chunk_delay(Duration::from_millis(200)));
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            transport.clone(),
        )
        .unwrap();
        let command_id = Uuid::now_v7();
        daemon
            .submit_sequence(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                long_sequence(command_id),
            )
            .await
            .unwrap();
        while daemon
            .command_outcome(SIMULATOR_DEVICE_ID, command_id)
            .unwrap()
            .outcome
            != CommandOutcome::Started
        {
            time::sleep(Duration::from_millis(5)).await;
        }

        let started = Instant::now();
        daemon.shutdown(Duration::from_secs(5)).await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            daemon
                .command_outcome(SIMULATOR_DEVICE_ID, command_id)
                .unwrap()
                .outcome,
            CommandOutcome::Aborted
        );
        assert_eq!(transport.execution_count(command_id), 1);
        let refused = daemon
            .submit_sequence(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                long_sequence(Uuid::now_v7()),
            )
            .await
            .unwrap_err();
        assert_eq!(refused.status, StatusCode::CONFLICT);
    }

    struct StuckTransport;

    impl DeviceTransport for StuckTransport {
        fn arm<'a>(
            &'a self,
            _policy: ArmPolicy,
            _lease_ms: u32,
        ) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn disarm<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn renew_lease<'a>(&'a self, _lease_ms: u32) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn accept<'a>(
            &'a self,
            _command: &'a PlannedCommand,
        ) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn execute<'a>(
            &'a self,
            _command: &'a PlannedCommand,
            _cancellation: Cancellation,
            progress: ProgressHandler,
        ) -> BoxFuture<'a, TransportOutcome> {
            Box::pin(async move {
                progress(TransportProgress::Accepted);
                progress(TransportProgress::Started);
                std::future::pending().await
            })
        }

        fn release_all<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn shutdown_is_bounded_when_a_command_never_finishes() {
        let daemon = Daemon::with_transport(
            MemoryTokenStore::new("test-token-123456"),
            Arc::new(StuckTransport),
        )
        .unwrap();
        let command_id = Uuid::now_v7();
        daemon
            .submit_sequence(
                SIMULATOR_DEVICE_ID,
                "test".to_owned(),
                long_sequence(command_id),
            )
            .await
            .unwrap();
        time::sleep(Duration::from_millis(20)).await;
        let started = Instant::now();
        daemon.shutdown(Duration::from_millis(100)).await;
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(100) && elapsed < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn shutdown_stops_new_endpoint_sessions() {
        let identity = HostIdentity::generate().unwrap();
        let device_id = Uuid::parse_str("cc48680b-4365-42c0-a195-5823677bbc47").unwrap();
        let transport = TlsTransport::new(TlsCredentials::new(
            identity,
            *device_id.as_bytes(),
            [0x77; 32],
        ))
        .unwrap();
        let daemon = Daemon::with_tls_transport(
            MemoryTokenStore::new("test-token-123456"),
            device_id.to_string(),
            "Paired keyboard".to_owned(),
            transport.clone(),
        )
        .unwrap();
        daemon.shutdown(Duration::from_secs(1)).await;
        assert!(transport.is_in_maintenance());
        assert!(
            daemon
                .device_view(&device_id.to_string())
                .unwrap()
                .maintenance
        );
    }
}
