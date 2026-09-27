use super::{
    BoxFuture, Cancellation, DeviceTransport, DisplayOrientation, OutputMode, OutputTransport,
    PlannedCommand, ProgressHandler, ScreenPower, TransportDiagnostic,
    TransportDisplayOrientationStatus, TransportError, TransportOutcome, TransportOutputModeStatus,
    TransportProgress, TransportScreenPowerStatus,
};
use hmac::{Hmac, Mac};
use keyferry_core::ArmPolicy;
use keyferry_gateway::{
    installation_id_for_spki, InstallationCredentialSet, InstallationCredentials,
};
use keyferry_layouts::ReportStep;
use keyferry_protocol::{decode_wire, encode_wire, Frame, MAX_DECODED_FRAME, MAX_PAYLOAD};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ProducesTickets, ResolvesServerCertUsingSni, WebPkiClientVerifier},
    sign::CertifiedKey,
    ClientConfig, RootCertStore, ServerConfig,
};
use sha2::{Digest, Sha256};
use socket2::{SockRef, TcpKeepalive};
use std::{
    collections::HashMap,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Mutex, OwnedSemaphorePermit, Semaphore},
    time::{self, Duration},
};
use tokio_rustls::{server::TlsStream, TlsAcceptor, TlsConnector};
use x509_parser::parse_x509_certificate;

pub const TLS_MAX_FRAGMENT_SIZE: usize = 512;
pub const AUTH_DOMAIN: &[u8] = b"hidbridge-auth-v1";
pub const HOST_LEASE_MS: u32 = 30_000;
pub const RENEW_EVERY_MS: u32 = 10_000;
pub const COMMAND_MAX_MS: u32 = 5_000;
const AUTH_CHALLENGE_LEN: usize = 16 + 16 + 32 + 1 + 1;
const AUTH_RESPONSE_LEN: usize = 16 + 32 + 32;
const SESSION_READY_LEN: usize = 16 + 1 + 1 + 4 + 4 + 4 + 4;
const COMMAND_RESULT_LEN: usize = 16 + 1;
const INPUT_COMMAND_RESULT_LEN: usize = 16 + 1 + 1 + 1 + 2;
const DUAL_NEUTRAL_MASK: u8 = 0x03;
const INPUT_EFFECT_OCCURRED: u8 = 0x01;
const CONTROL_ACK_LEN: usize = 1 + 2;
const MAX_WIRE_FRAME: usize = MAX_DECODED_FRAME + 4;
const COMMAND_KIND_EXECUTE: u8 = 0x01;
const COMMAND_KIND_CANCEL: u8 = 0x02;
const COMMAND_KIND_RELEASE_ALL: u8 = 0x03;
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(3);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(1);
const TCP_KEEPALIVE_RETRIES: u32 = 3;
const AUTHENTICATION_TIMEOUT: Duration =
    Duration::from_millis(keyferry_protocol::ble_transport::AUTHENTICATION_TIMEOUT_MS as u64);
const MAX_AUTHENTICATION_CANDIDATES: usize = 2;

type HmacSha256 = Hmac<Sha256>;
type Handler = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsLinkPath {
    Wifi,
    Bluetooth,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsSessionSnapshot {
    pub link_path: TlsLinkPath,
    pub protocol_session_id: [u8; 16],
    pub firmware_identity: Option<keyferry_protocol::firmware_identity::FirmwareIdentityV1>,
}

#[derive(Debug)]
pub enum TlsTransportError {
    Io(io::Error),
    Tls(String),
    Protocol(String),
    Authentication,
    DeviceRejected,
    InvalidConfiguration(String),
    AlreadyAccepted,
    Maintenance,
    AuthenticationTimeout,
    FirmwareIdentityUnavailable,
    SessionSetup {
        stage: &'static str,
        source: Box<TlsTransportError>,
    },
    Diagnosed {
        diagnostic: TransportDiagnostic,
        source: Box<TlsTransportError>,
    },
}

impl fmt::Display for TlsTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "TLS I/O error: {error}"),
            Self::Tls(error) => write!(f, "TLS error: {error}"),
            Self::Protocol(error) => write!(f, "protocol error: {error}"),
            Self::Authentication => write!(f, "device authentication failed"),
            Self::DeviceRejected => write!(f, "device rejected the control request"),
            Self::InvalidConfiguration(error) => write!(f, "invalid TLS configuration: {error}"),
            Self::AlreadyAccepted => {
                write!(
                    f,
                    "TLS transport already has a live session or two pending candidates"
                )
            }
            Self::Maintenance => write!(f, "TLS transport is paused for local maintenance"),
            Self::AuthenticationTimeout => write!(f, "TLS authentication timed out"),
            Self::FirmwareIdentityUnavailable => {
                write!(
                    f,
                    "firmware identity unavailable; reconnect once in legacy mode"
                )
            }
            Self::SessionSetup { stage, source } => {
                write!(f, "TLS session setup failed during {stage}: {source}")
            }
            Self::Diagnosed { diagnostic, source } => {
                write!(f, "{}: {source}", diagnostic.code())
            }
        }
    }
}

impl std::error::Error for TlsTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::SessionSetup { source, .. } | Self::Diagnosed { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl TlsTransportError {
    fn diagnostic(&self) -> Option<TransportDiagnostic> {
        match self {
            Self::Diagnosed { diagnostic, .. } => Some(*diagnostic),
            Self::SessionSetup { source, .. } => source.diagnostic(),
            _ => None,
        }
    }
}

impl From<io::Error> for TlsTransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn session_setup_error(stage: &'static str, source: TlsTransportError) -> TlsTransportError {
    TlsTransportError::SessionSetup {
        stage,
        source: Box::new(source),
    }
}

fn diagnosed_error(
    diagnostic: TransportDiagnostic,
    source: TlsTransportError,
) -> TlsTransportError {
    TlsTransportError::Diagnosed {
        diagnostic,
        source: Box::new(source),
    }
}

fn cancellation_error(
    source: TlsTransportError,
    transport: TransportDiagnostic,
    protocol: TransportDiagnostic,
) -> TlsTransportError {
    fn is_protocol(source: &TlsTransportError) -> bool {
        match source {
            TlsTransportError::Protocol(_)
            | TlsTransportError::Authentication
            | TlsTransportError::DeviceRejected
            | TlsTransportError::InvalidConfiguration(_) => true,
            TlsTransportError::SessionSetup { source, .. }
            | TlsTransportError::Diagnosed { source, .. } => is_protocol(source),
            TlsTransportError::Io(_)
            | TlsTransportError::Tls(_)
            | TlsTransportError::AlreadyAccepted
            | TlsTransportError::Maintenance
            | TlsTransportError::AuthenticationTimeout
            | TlsTransportError::FirmwareIdentityUnavailable => false,
        }
    }
    let diagnostic = if is_protocol(&source) {
        protocol
    } else {
        transport
    };
    diagnosed_error(diagnostic, source)
}

#[derive(Clone, Eq, PartialEq)]
pub struct HostIdentity {
    host_id: [u8; 16],
    private_key_der: Vec<u8>,
    certificate_der: Vec<u8>,
}

impl fmt::Debug for HostIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostIdentity")
            .field("host_id", &self.host_id)
            .field("private_key_der", &"[secret key elided]")
            .field("certificate_der_len", &self.certificate_der.len())
            .finish()
    }
}

impl HostIdentity {
    pub fn generate() -> io::Result<Self> {
        let host_id = random_array()?;
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let params = CertificateParams::new(vec!["keyferry.local".to_owned()])
            .map_err(|error| io::Error::other(error.to_string()))?;
        let certificate = params
            .self_signed(&key_pair)
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(Self {
            host_id,
            private_key_der: key_pair.serialize_der(),
            certificate_der: certificate.der().to_vec(),
        })
    }

    pub fn from_der(
        host_id: [u8; 16],
        private_key_der: Vec<u8>,
        certificate_der: Vec<u8>,
    ) -> io::Result<Self> {
        if private_key_der.is_empty() || certificate_der.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS host key or certificate is empty",
            ));
        }
        Ok(Self {
            host_id,
            private_key_der,
            certificate_der,
        })
    }

    #[must_use]
    pub fn host_id(&self) -> [u8; 16] {
        self.host_id
    }

    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    #[must_use]
    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }
}

#[derive(Clone)]
pub struct TlsCredentials {
    identity: HostIdentity,
    device_id: [u8; 16],
    link_secret: [u8; 32],
}

impl fmt::Debug for TlsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsCredentials")
            .field("identity", &self.identity)
            .field("device_id", &self.device_id)
            .field("link_secret", &"[secret elided]")
            .finish()
    }
}

impl TlsCredentials {
    pub fn new(identity: HostIdentity, device_id: [u8; 16], link_secret: [u8; 32]) -> Self {
        Self {
            identity,
            device_id,
            link_secret,
        }
    }

    #[must_use]
    pub fn host_id(&self) -> [u8; 16] {
        self.identity.host_id()
    }

    #[must_use]
    pub fn device_id(&self) -> [u8; 16] {
        self.device_id
    }

    #[must_use]
    pub fn identity(&self) -> &HostIdentity {
        &self.identity
    }
}

pub trait TlsSecretStore: Send + Sync {
    fn load_or_create_host_identity(&self) -> io::Result<HostIdentity>;
    fn load_link_secret(&self, device_id: [u8; 16]) -> io::Result<[u8; 32]>;
}

#[derive(Clone, Debug)]
pub struct FileTlsSecretStore {
    root: PathBuf,
}

/// Read-only device-facing credentials issued from an encrypted owner kit.
///
/// This store never creates or repairs credentials. A partial, mismatched, or
/// malformed installation directory fails closed before a radio is opened.
#[derive(Clone)]
pub struct InstallationTlsSecretStore {
    credentials: InstallationCredentials,
    identity: HostIdentity,
}

#[derive(Clone, Debug)]
pub struct InstallationTlsSecretSet {
    stores: Vec<InstallationTlsSecretStore>,
}

impl fmt::Debug for InstallationTlsSecretStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallationTlsSecretStore")
            .field("credentials", &self.credentials)
            .field("identity", &self.identity)
            .finish()
    }
}

impl InstallationTlsSecretStore {
    pub fn load(root: impl Into<PathBuf>) -> io::Result<Self> {
        let set = InstallationCredentialSet::load(root.into())?;
        if set.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "single-device TLS store cannot load a multi-device installation",
            ));
        }
        let credentials = set
            .iter()
            .next()
            .expect("one credential was required")
            .clone();
        Self::from_credentials(credentials)
    }

    fn from_credentials(credentials: InstallationCredentials) -> io::Result<Self> {
        let identity = HostIdentity::from_der(
            credentials.installation_id(),
            credentials.installation_key_der().to_vec(),
            credentials.device_server_certificate_der().to_vec(),
        )?;
        server_config(&identity).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("device-facing certificate is invalid: {error}"),
            )
        })?;
        server_config_exact_sni(&identity, credentials.device_server_name()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("device-facing certificate profile is invalid: {error}"),
            )
        })?;
        let desktop_identity = HostIdentity::from_der(
            credentials.installation_id(),
            credentials.installation_key_der().to_vec(),
            credentials.desktop_server_certificate_der().to_vec(),
        )?;
        server_config_exact_sni(&desktop_identity, credentials.desktop_server_name()).map_err(
            |error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("desktop server certificate profile is invalid: {error}"),
                )
            },
        )?;

        Ok(Self {
            credentials,
            identity,
        })
    }

    #[must_use]
    pub fn device_id(&self) -> [u8; 16] {
        self.credentials.device_id()
    }

    #[must_use]
    pub fn device_server_name(&self) -> &str {
        self.credentials.device_server_name()
    }

    #[must_use]
    pub fn installation_id(&self) -> [u8; 16] {
        self.credentials.installation_id()
    }

    #[must_use]
    pub fn installation_spki_der(&self) -> &[u8] {
        self.credentials.installation_spki_der()
    }

    #[must_use]
    pub fn owner_id(&self) -> [u8; 16] {
        self.credentials.owner_id()
    }

    /// This installation's device-scoped key for verifying fresh endpoint route proofs.
    pub(crate) fn route_proof_secret(&self) -> [u8; 32] {
        self.credentials.route_proof_secret()
    }

    #[must_use]
    pub fn owner_ca_der(&self) -> &[u8] {
        self.credentials.owner_ca_der()
    }

    #[must_use]
    pub fn desktop_server_name(&self) -> &str {
        self.credentials.desktop_server_name()
    }

    pub fn desktop_server_identity(&self) -> io::Result<HostIdentity> {
        HostIdentity::from_der(
            self.credentials.installation_id(),
            self.credentials.installation_key_der().to_vec(),
            self.credentials.desktop_server_certificate_der().to_vec(),
        )
    }

    pub fn desktop_client_identity(&self) -> io::Result<HostIdentity> {
        HostIdentity::from_der(
            self.credentials.installation_id(),
            self.credentials.installation_key_der().to_vec(),
            self.credentials.desktop_client_certificate_der().to_vec(),
        )
    }

    pub(crate) fn remote_tls_acceptor(&self) -> Result<TlsAcceptor, TlsTransportError> {
        let identity = self
            .desktop_server_identity()
            .map_err(TlsTransportError::Io)?;
        remote_server_config(
            &identity,
            self.credentials.owner_ca_der(),
            self.credentials.desktop_server_name(),
        )
        .map(TlsAcceptor::from)
    }

    pub(crate) fn remote_tls_connector(&self) -> Result<TlsConnector, TlsTransportError> {
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites =
            vec![rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256];
        provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.owner_ca_der().to_vec()))
            .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?;
        let identity = self
            .desktop_client_identity()
            .map_err(TlsTransportError::Io)?;
        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![CertificateDer::from(identity.certificate_der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    identity.private_key_der().to_vec(),
                )),
            )
            .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?;
        config.resumption = rustls::client::Resumption::disabled();
        config.alpn_protocols.clear();
        Ok(TlsConnector::from(Arc::new(config)))
    }
}

impl InstallationTlsSecretSet {
    pub fn load(root: impl Into<PathBuf>) -> io::Result<Self> {
        let credentials = InstallationCredentialSet::load(root.into())?;
        let stores = credentials
            .iter()
            .cloned()
            .map(InstallationTlsSecretStore::from_credentials)
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { stores })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.stores.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stores.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &InstallationTlsSecretStore> {
        self.stores.iter()
    }

    pub fn transports(&self) -> Result<Vec<TlsTransport>, TlsTransportError> {
        self.stores
            .iter()
            .map(TlsTransport::from_installation_store)
            .collect()
    }
}

impl TlsSecretStore for InstallationTlsSecretStore {
    fn load_or_create_host_identity(&self) -> io::Result<HostIdentity> {
        Ok(self.identity.clone())
    }

    fn load_link_secret(&self, device_id: [u8; 16]) -> io::Result<[u8; 32]> {
        if device_id != self.credentials.device_id() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "installation credentials do not belong to the requested device",
            ));
        }
        Ok(self.credentials.device_link_secret())
    }
}

impl FileTlsSecretStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn store_link_secret(&self, device_id: [u8; 16], secret: [u8; 32]) -> io::Result<()> {
        let pairings = self.root.join("pairings");
        fs::create_dir_all(&pairings)?;
        write_new_private(
            &pairings.join(format!("{}.link", hex_id(&device_id))),
            &secret,
        )
    }

    fn identity_paths(&self) -> [PathBuf; 3] {
        [
            self.root.join("host-id"),
            self.root.join("host-key.der"),
            self.root.join("host-cert.der"),
        ]
    }
}

impl TlsSecretStore for FileTlsSecretStore {
    fn load_or_create_host_identity(&self) -> io::Result<HostIdentity> {
        let [host_id_path, key_path, cert_path] = self.identity_paths();
        let exists = [host_id_path.exists(), key_path.exists(), cert_path.exists()];
        if exists.iter().all(|present| *present) {
            let host_id = read_fixed::<16>(&host_id_path)?;
            return HostIdentity::from_der(host_id, fs::read(key_path)?, fs::read(cert_path)?);
        }
        if exists.iter().any(|present| *present) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS host identity is incomplete",
            ));
        }

        fs::create_dir_all(&self.root)?;
        let identity = HostIdentity::generate()?;
        let writes = [
            (host_id_path, identity.host_id.to_vec()),
            (key_path, identity.private_key_der.clone()),
            (cert_path, identity.certificate_der.clone()),
        ];
        for (path, bytes) in writes {
            if let Err(error) = write_new_private(&path, &bytes) {
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
                return self.load_or_create_host_identity();
            }
        }
        Ok(identity)
    }

    fn load_link_secret(&self, device_id: [u8; 16]) -> io::Result<[u8; 32]> {
        read_fixed(
            &self
                .root
                .join("pairings")
                .join(format!("{}.link", hex_id(&device_id))),
        )
    }
}

#[derive(Clone, Debug)]
pub struct MemoryTlsSecretStore {
    identity: HostIdentity,
    link_secrets: HashMap<[u8; 16], [u8; 32]>,
}

impl MemoryTlsSecretStore {
    #[must_use]
    pub fn new(identity: HostIdentity) -> Self {
        Self {
            identity,
            link_secrets: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_link_secret(mut self, device_id: [u8; 16], secret: [u8; 32]) -> Self {
        self.link_secrets.insert(device_id, secret);
        self
    }
}

impl TlsSecretStore for MemoryTlsSecretStore {
    fn load_or_create_host_identity(&self) -> io::Result<HostIdentity> {
        Ok(self.identity.clone())
    }

    fn load_link_secret(&self, device_id: [u8; 16]) -> io::Result<[u8; 32]> {
        self.link_secrets
            .get(&device_id)
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "link secret is not paired"))
    }
}

#[derive(Clone)]
pub struct TlsTransport {
    inner: Arc<TlsTransportInner>,
}

struct TlsTransportInner {
    credentials: TlsCredentials,
    acceptor: TlsAcceptor,
    session: Mutex<Option<mpsc::Sender<TransportRequest>>>,
    session_snapshot: std::sync::RwLock<Option<TlsSessionSnapshot>>,
    ready: AtomicBool,
    candidate_slots: Arc<Semaphore>,
    handoff_candidate: std::sync::Mutex<Option<OwnedSemaphorePermit>>,
    ready_handler: std::sync::Mutex<Option<Handler>>,
    fault_handler: std::sync::Mutex<Option<Handler>>,
    command_diagnostic: std::sync::Mutex<Option<TransportDiagnostic>>,
    maintenance: AtomicBool,
    legacy_wifi_reconnect: AtomicBool,
    legacy_bluetooth_reconnect: AtomicBool,
}

enum TransportRequest {
    RouteProof {
        controller_installation_id: [u8; 16],
        controller_nonce: [u8; 32],
        reply: oneshot::Sender<Result<keyferry_gateway::SignedRouteProof, TransportError>>,
    },
    Control {
        message_type: u8,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(), TransportError>>,
    },
    OutputMode {
        requested: Option<OutputMode>,
        reply: oneshot::Sender<Result<TransportOutputModeStatus, TransportError>>,
    },
    DisplayOrientation {
        requested: Option<DisplayOrientation>,
        reply: oneshot::Sender<Result<TransportDisplayOrientationStatus, TransportError>>,
    },
    ScreenPower {
        requested: Option<ScreenPower>,
        reply: oneshot::Sender<Result<TransportScreenPowerStatus, TransportError>>,
    },
    ResetBleHidBond {
        reply: oneshot::Sender<Result<(bool, bool), TransportError>>,
    },
    Execute {
        command: PlannedCommand,
        cancellation: Cancellation,
        progress: ProgressHandler,
        reply: oneshot::Sender<TransportOutcome>,
    },
    ReleaseAll {
        reply: oneshot::Sender<Result<(), TransportError>>,
    },
    ReleaseInputAll {
        reply: oneshot::Sender<Result<(), TransportError>>,
    },
    EnterMaintenance {
        reply: oneshot::Sender<Result<(), TransportError>>,
    },
    GatewayHandoff {
        request: keyferry_protocol::gateway_handoff::Request,
        reply: oneshot::Sender<Result<keyferry_protocol::gateway_handoff::Status, TransportError>>,
    },
    File {
        request: keyferry_protocol::file::Request,
        reply: oneshot::Sender<Result<keyferry_protocol::file::Status, TransportError>>,
    },
    FileSet {
        request: keyferry_protocol::file_set::Request,
        reply: oneshot::Sender<Result<keyferry_protocol::file_set::Status, TransportError>>,
    },
}

impl fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsTransport")
            .field("host_id", &self.inner.credentials.host_id())
            .field("device_id", &self.inner.credentials.device_id())
            .field("ready", &self.is_ready())
            .finish()
    }
}

impl TlsTransport {
    pub fn new(credentials: TlsCredentials) -> Result<Self, TlsTransportError> {
        let config = server_config(credentials.identity())?;
        Ok(Self::with_config(credentials, config))
    }

    fn with_config(credentials: TlsCredentials, config: Arc<ServerConfig>) -> Self {
        Self {
            inner: Arc::new(TlsTransportInner {
                credentials,
                acceptor: TlsAcceptor::from(config),
                session: Mutex::new(None),
                session_snapshot: std::sync::RwLock::new(None),
                ready: AtomicBool::new(false),
                candidate_slots: Arc::new(Semaphore::new(MAX_AUTHENTICATION_CANDIDATES)),
                handoff_candidate: std::sync::Mutex::new(None),
                ready_handler: std::sync::Mutex::new(None),
                fault_handler: std::sync::Mutex::new(None),
                command_diagnostic: std::sync::Mutex::new(None),
                maintenance: AtomicBool::new(false),
                legacy_wifi_reconnect: AtomicBool::new(false),
                legacy_bluetooth_reconnect: AtomicBool::new(false),
            }),
        }
    }

    fn clear_command_diagnostic(&self) {
        *self
            .inner
            .command_diagnostic
            .lock()
            .expect("TLS command diagnostic lock") = None;
    }

    fn record_command_diagnostic(&self, error: &TlsTransportError) {
        let Some(diagnostic) = error.diagnostic() else {
            return;
        };
        let mut slot = self
            .inner
            .command_diagnostic
            .lock()
            .expect("TLS command diagnostic lock");
        slot.get_or_insert(diagnostic);
    }

    pub fn from_secret_store<S: TlsSecretStore>(
        store: &S,
        device_id: [u8; 16],
    ) -> Result<Self, TlsTransportError> {
        let identity = store
            .load_or_create_host_identity()
            .map_err(TlsTransportError::Io)?;
        let link_secret = store
            .load_link_secret(device_id)
            .map_err(TlsTransportError::Io)?;
        Self::new(TlsCredentials::new(identity, device_id, link_secret))
    }

    pub fn from_installation_store(
        store: &InstallationTlsSecretStore,
    ) -> Result<Self, TlsTransportError> {
        let identity = store
            .load_or_create_host_identity()
            .map_err(TlsTransportError::Io)?;
        let link_secret = store
            .load_link_secret(store.device_id())
            .map_err(TlsTransportError::Io)?;
        let credentials = TlsCredentials::new(identity, store.device_id(), link_secret);
        let config = server_config_exact_sni(credentials.identity(), store.device_server_name())?;
        Ok(Self::with_config(credentials, config))
    }

    #[must_use]
    pub fn device_id(&self) -> [u8; 16] {
        self.inner.credentials.device_id()
    }

    #[must_use]
    pub fn host_id(&self) -> [u8; 16] {
        self.inner.credentials.host_id()
    }

    #[must_use]
    pub fn host_certificate_der(&self) -> &[u8] {
        self.inner.credentials.identity().certificate_der()
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.inner.ready.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn session_snapshot(&self) -> Option<TlsSessionSnapshot> {
        self.inner
            .session_snapshot
            .read()
            .expect("TLS session snapshot lock")
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn set_test_session_snapshot(&self, snapshot: TlsSessionSnapshot) {
        *self
            .inner
            .session_snapshot
            .write()
            .expect("TLS session snapshot lock") = Some(snapshot);
    }

    #[must_use]
    pub fn is_in_maintenance(&self) -> bool {
        self.inner.maintenance.load(Ordering::Acquire)
    }

    /// Prevent new authenticated sessions and close the current one only after
    /// the endpoint has acknowledged disarm and a terminal all-zero report.
    pub async fn begin_maintenance(&self) -> Result<(), TransportError> {
        self.inner.maintenance.store(true, Ordering::Release);
        let sender = self.inner.session.lock().await.clone();
        let Some(sender) = sender else {
            return Ok(());
        };
        let (reply, response) = oneshot::channel();
        if sender
            .send(TransportRequest::EnterMaintenance { reply })
            .await
            .is_err()
        {
            return Err(TransportError::AcceptedButLost);
        }
        response
            .await
            .unwrap_or(Err(TransportError::AcceptedButLost))
    }

    pub fn finish_maintenance(&self) {
        self.inner.maintenance.store(false, Ordering::Release);
    }

    pub async fn reserve_gateway_handoff_candidate(&self) -> Result<(), TransportError> {
        if self.is_in_maintenance() || self.inner.session.lock().await.is_some() {
            return Err(TransportError::Busy);
        }
        let mut reservation = self
            .inner
            .handoff_candidate
            .lock()
            .expect("gateway handoff candidate reservation");
        if reservation.is_some() {
            return Err(TransportError::Busy);
        }
        let permit = self
            .inner
            .candidate_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| TransportError::Busy)?;
        *reservation = Some(permit);
        Ok(())
    }

    pub fn cancel_gateway_handoff_candidate(&self) {
        self.inner
            .handoff_candidate
            .lock()
            .expect("gateway handoff candidate reservation")
            .take();
    }

    pub async fn gateway_handoff_request(
        &self,
        request: keyferry_protocol::gateway_handoff::Request,
    ) -> Result<keyferry_protocol::gateway_handoff::Status, TransportError> {
        let sender = self.inner.session.lock().await.clone();
        let Some(sender) = sender else {
            return Err(TransportError::LostBeforeAccept);
        };
        let (reply, response) = oneshot::channel();
        if sender
            .send(TransportRequest::GatewayHandoff { request, reply })
            .await
            .is_err()
        {
            return Err(TransportError::AcceptedButLost);
        }
        response
            .await
            .unwrap_or(Err(TransportError::AcceptedButLost))
    }

    pub async fn file_request(
        &self,
        request: keyferry_protocol::file::Request,
    ) -> Result<keyferry_protocol::file::Status, TransportError> {
        let sender = self.inner.session.lock().await.clone();
        let Some(sender) = sender else {
            return Err(TransportError::LostBeforeAccept);
        };
        let (reply, response) = oneshot::channel();
        sender
            .send(TransportRequest::File { request, reply })
            .await
            .map_err(|_| TransportError::AcceptedButLost)?;
        response
            .await
            .unwrap_or(Err(TransportError::AcceptedButLost))
    }

    pub async fn file_set_request(
        &self,
        request: keyferry_protocol::file_set::Request,
    ) -> Result<keyferry_protocol::file_set::Status, TransportError> {
        let sender = self.inner.session.lock().await.clone();
        let Some(sender) = sender else {
            return Err(TransportError::LostBeforeAccept);
        };
        let (reply, response) = oneshot::channel();
        sender
            .send(TransportRequest::FileSet { request, reply })
            .await
            .map_err(|_| TransportError::AcceptedButLost)?;
        response
            .await
            .unwrap_or(Err(TransportError::AcceptedButLost))
    }

    pub(crate) fn sign_gateway_proof(
        &self,
        request_nonce: [u8; 32],
        daemon_boot_id: [u8; 16],
        api_version: u16,
        devices: Vec<crate::GatewayDeviceSummary>,
    ) -> Result<crate::SignedGatewayProof, crate::GatewayProofError> {
        crate::sign_gateway_proof(
            self.inner.credentials.identity().private_key_der(),
            request_nonce,
            daemon_boot_id,
            api_version,
            devices,
        )
    }

    #[must_use]
    pub fn acceptor(&self) -> TlsAcceptor {
        self.inner.acceptor.clone()
    }

    fn set_ready(&self) {
        self.inner.ready.store(true, Ordering::Release);
        invoke_handler(&self.inner.ready_handler);
    }

    fn notify_fault(&self) {
        *self
            .inner
            .session_snapshot
            .write()
            .expect("TLS session snapshot lock") = None;
        self.inner.ready.store(false, Ordering::Release);
        invoke_handler(&self.inner.fault_handler);
    }

    async fn install_connection<IO>(
        &self,
        stream: TlsStream<IO>,
        next_sequence: u32,
        session_id: [u8; 16],
        link_path: TlsLinkPath,
        firmware_identity: Option<keyferry_protocol::firmware_identity::FirmwareIdentityV1>,
    ) -> Result<(), TlsTransportError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if self.is_in_maintenance() {
            return Err(TlsTransportError::Maintenance);
        }
        let (request_tx, request_rx) = mpsc::channel(1);
        let mut session = self.inner.session.lock().await;
        if session.is_some() {
            return Err(TlsTransportError::AlreadyAccepted);
        }
        *session = Some(request_tx);
        *self
            .inner
            .session_snapshot
            .write()
            .expect("TLS session snapshot lock") = Some(TlsSessionSnapshot {
            link_path,
            protocol_session_id: session_id,
            firmware_identity,
        });
        drop(session);
        self.set_ready();
        tokio::spawn(connection_actor(
            self.clone(),
            stream,
            next_sequence,
            request_rx,
            session_id,
        ));
        Ok(())
    }

    /// Authenticate and install one byte stream carrying the Keyferry TLS
    /// session. TCP listeners and BLE gateways share this sole admission path.
    pub async fn accept_stream<IO>(&self, stream: IO) -> Result<(), TlsTransportError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.accept_stream_on(stream, TlsLinkPath::Wifi).await
    }

    /// Authenticate a candidate on a known physical path. The path becomes
    /// visible only after TLS, device HMAC, and SESSION_READY all succeed.
    pub async fn accept_stream_on<IO>(
        &self,
        stream: IO,
        link_path: TlsLinkPath,
    ) -> Result<(), TlsTransportError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.accept_stream_with_timeout(stream, AUTHENTICATION_TIMEOUT, link_path)
            .await
    }

    pub async fn accept_tls_stream_on<IO>(
        &self,
        stream: TlsStream<IO>,
        link_path: TlsLinkPath,
    ) -> Result<(), TlsTransportError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if self.is_in_maintenance() {
            return Err(TlsTransportError::Maintenance);
        }
        let _candidate = self
            .inner
            .handoff_candidate
            .lock()
            .expect("gateway handoff candidate reservation")
            .take()
            .map_or_else(
                || {
                    self.inner
                        .candidate_slots
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| TlsTransportError::AlreadyAccepted)
                },
                Ok,
            )?;
        time::timeout(
            AUTHENTICATION_TIMEOUT,
            self.authenticate_tls_and_install(stream, link_path),
        )
        .await
        .map_err(|_| TlsTransportError::AuthenticationTimeout)?
    }

    async fn accept_stream_with_timeout<IO>(
        &self,
        stream: IO,
        authentication_timeout: Duration,
        link_path: TlsLinkPath,
    ) -> Result<(), TlsTransportError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if self.is_in_maintenance() {
            return Err(TlsTransportError::Maintenance);
        }
        let _candidate = self
            .inner
            .handoff_candidate
            .lock()
            .expect("gateway handoff candidate reservation")
            .take()
            .map_or_else(
                || {
                    self.inner
                        .candidate_slots
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| TlsTransportError::AlreadyAccepted)
                },
                Ok,
            )?;
        time::timeout(
            authentication_timeout,
            self.authenticate_and_install(stream, link_path),
        )
        .await
        .map_err(|_| TlsTransportError::AuthenticationTimeout)?
    }

    async fn authenticate_and_install<IO>(
        &self,
        stream: IO,
        link_path: TlsLinkPath,
    ) -> Result<(), TlsTransportError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if self.is_in_maintenance() {
            return Err(TlsTransportError::Maintenance);
        }
        if self.inner.session.lock().await.is_some() {
            return Err(TlsTransportError::AlreadyAccepted);
        }
        let legacy_reconnect = match link_path {
            TlsLinkPath::Wifi => self
                .inner
                .legacy_wifi_reconnect
                .swap(false, Ordering::AcqRel),
            TlsLinkPath::Bluetooth => self
                .inner
                .legacy_bluetooth_reconnect
                .swap(false, Ordering::AcqRel),
        };
        let result = authenticate_stream(
            &self.acceptor(),
            stream,
            &self.inner.credentials,
            !legacy_reconnect,
        )
        .await;
        self.finish_authentication(result, link_path, legacy_reconnect)
            .await
    }

    async fn authenticate_tls_and_install<IO>(
        &self,
        stream: TlsStream<IO>,
        link_path: TlsLinkPath,
    ) -> Result<(), TlsTransportError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if self.is_in_maintenance() {
            return Err(TlsTransportError::Maintenance);
        }
        if self.inner.session.lock().await.is_some() {
            return Err(TlsTransportError::AlreadyAccepted);
        }
        let legacy_reconnect = match link_path {
            TlsLinkPath::Wifi => self
                .inner
                .legacy_wifi_reconnect
                .swap(false, Ordering::AcqRel),
            TlsLinkPath::Bluetooth => self
                .inner
                .legacy_bluetooth_reconnect
                .swap(false, Ordering::AcqRel),
        };
        let result =
            authenticate_tls_stream(stream, &self.inner.credentials, !legacy_reconnect).await;
        self.finish_authentication(result, link_path, legacy_reconnect)
            .await
    }

    async fn finish_authentication<IO>(
        &self,
        result: AuthenticationResult<IO>,
        link_path: TlsLinkPath,
        legacy_reconnect: bool,
    ) -> Result<(), TlsTransportError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (stream, next_sequence, session_id, firmware_identity) = match result {
            Err(TlsTransportError::FirmwareIdentityUnavailable) if !legacy_reconnect => {
                match link_path {
                    TlsLinkPath::Wifi => self
                        .inner
                        .legacy_wifi_reconnect
                        .store(true, Ordering::Release),
                    TlsLinkPath::Bluetooth => self
                        .inner
                        .legacy_bluetooth_reconnect
                        .store(true, Ordering::Release),
                }
                return Err(TlsTransportError::FirmwareIdentityUnavailable);
            }
            result => result?,
        };
        self.install_connection(
            stream,
            next_sequence,
            session_id,
            link_path,
            firmware_identity,
        )
        .await
    }
}

type AuthenticationResult<IO> = Result<
    (
        TlsStream<IO>,
        u32,
        [u8; 16],
        Option<keyferry_protocol::firmware_identity::FirmwareIdentityV1>,
    ),
    TlsTransportError,
>;

impl DeviceTransport for TlsTransport {
    fn is_ready(&self) -> bool {
        self.is_ready()
    }

    fn transport_name(&self) -> &'static str {
        "tls"
    }

    fn supports_input_sequence(&self) -> bool {
        self.session_snapshot()
            .and_then(|snapshot| snapshot.firmware_identity)
            .is_some_and(|identity| {
                identity.device_capability_mask & keyferry_protocol::capability::MOUSE_RELATIVE_V1
                    != 0
            })
    }

    fn supports_output_mode(&self) -> bool {
        self.session_snapshot()
            .and_then(|snapshot| snapshot.firmware_identity)
            .is_some_and(|identity| {
                identity.device_capability_mask & keyferry_protocol::capability::BLE_HID_OUTPUT_V1
                    != 0
            })
    }

    fn supports_display_orientation(&self) -> bool {
        self.session_snapshot()
            .and_then(|snapshot| snapshot.firmware_identity)
            .is_some_and(|identity| {
                identity.device_capability_mask
                    & keyferry_protocol::capability::DISPLAY_ORIENTATION_V1
                    != 0
            })
    }

    fn supports_screen_power(&self) -> bool {
        self.session_snapshot()
            .and_then(|snapshot| snapshot.firmware_identity)
            .is_some_and(|identity| {
                identity.device_capability_mask & keyferry_protocol::capability::SCREEN_POWER_V1
                    != 0
            })
    }

    fn supports_ble_hid_bond_reset(&self) -> bool {
        self.session_snapshot()
            .and_then(|snapshot| snapshot.firmware_identity)
            .is_some_and(|identity| {
                identity.device_capability_mask
                    & keyferry_protocol::capability::BLE_HID_BOND_RESET_V1
                    != 0
            })
    }

    fn supports_targeted_gateway_transfer(&self) -> bool {
        self.session_snapshot()
            .and_then(|snapshot| snapshot.firmware_identity)
            .is_some_and(|identity| {
                identity.device_capability_mask
                    & keyferry_protocol::capability::TARGETED_GATEWAY_TRANSFER_V1
                    != 0
            })
    }

    fn supports_file_handoff(&self) -> bool {
        self.session_snapshot()
            .and_then(|snapshot| snapshot.firmware_identity)
            .is_some_and(|identity| {
                identity.device_capability_mask & keyferry_protocol::capability::USB_FILE_HANDOFF_V1
                    != 0
            })
    }

    fn supports_file_set(&self) -> bool {
        self.session_snapshot()
            .and_then(|snapshot| snapshot.firmware_identity)
            .is_some_and(|identity| {
                identity.device_capability_mask & keyferry_protocol::capability::USB_FILE_SET_V2
                    != 0
            })
    }

    fn file_request<'a>(
        &'a self,
        request: keyferry_protocol::file::Request,
    ) -> BoxFuture<'a, Result<keyferry_protocol::file::Status, TransportError>> {
        Box::pin(async move { self.file_request(request).await })
    }

    fn file_set_request<'a>(
        &'a self,
        request: keyferry_protocol::file_set::Request,
    ) -> BoxFuture<'a, Result<keyferry_protocol::file_set::Status, TransportError>> {
        Box::pin(async move { self.file_set_request(request).await })
    }

    fn gateway_handoff<'a>(
        &'a self,
        request: keyferry_protocol::gateway_handoff::Request,
    ) -> BoxFuture<'a, Result<keyferry_protocol::gateway_handoff::Status, TransportError>> {
        Box::pin(async move { self.gateway_handoff_request(request).await })
    }

    fn output_transport(&self) -> OutputTransport {
        let Some(identity) = self
            .session_snapshot()
            .and_then(|snapshot| snapshot.firmware_identity)
        else {
            return OutputTransport::UsbHid;
        };
        if identity.device_capability_mask & keyferry_protocol::capability::BLE_HID_OUTPUT_V1 != 0
            && identity.device_capability_mask & keyferry_protocol::capability::MOUSE_RELATIVE_V1
                == 0
        {
            OutputTransport::BleHid
        } else {
            OutputTransport::UsbHid
        }
    }

    fn output_mode<'a>(
        &'a self,
        requested: Option<OutputMode>,
    ) -> BoxFuture<'a, Result<TransportOutputModeStatus, TransportError>> {
        Box::pin(async move {
            let sender = self.inner.session.lock().await.clone();
            let Some(sender) = sender else {
                return Err(TransportError::LostBeforeAccept);
            };
            let (reply, response) = oneshot::channel();
            if sender
                .send(TransportRequest::OutputMode { requested, reply })
                .await
                .is_err()
            {
                return Err(TransportError::AcceptedButLost);
            }
            response
                .await
                .unwrap_or(Err(TransportError::AcceptedButLost))
        })
    }

    fn reset_ble_hid_bond<'a>(&'a self) -> BoxFuture<'a, Result<(bool, bool), TransportError>> {
        Box::pin(async move {
            let sender = self.inner.session.lock().await.clone();
            let Some(sender) = sender else {
                return Err(TransportError::LostBeforeAccept);
            };
            let (reply, response) = oneshot::channel();
            if sender
                .send(TransportRequest::ResetBleHidBond { reply })
                .await
                .is_err()
            {
                return Err(TransportError::AcceptedButLost);
            }
            response
                .await
                .unwrap_or(Err(TransportError::AcceptedButLost))
        })
    }

    fn display_orientation<'a>(
        &'a self,
        requested: Option<DisplayOrientation>,
    ) -> BoxFuture<'a, Result<TransportDisplayOrientationStatus, TransportError>> {
        Box::pin(async move {
            let sender = self.inner.session.lock().await.clone();
            let Some(sender) = sender else {
                return Err(TransportError::LostBeforeAccept);
            };
            let (reply, response) = oneshot::channel();
            if sender
                .send(TransportRequest::DisplayOrientation { requested, reply })
                .await
                .is_err()
            {
                return Err(TransportError::AcceptedButLost);
            }
            response
                .await
                .unwrap_or(Err(TransportError::AcceptedButLost))
        })
    }

    fn screen_power<'a>(
        &'a self,
        requested: Option<ScreenPower>,
    ) -> BoxFuture<'a, Result<TransportScreenPowerStatus, TransportError>> {
        Box::pin(async move {
            let sender = self.inner.session.lock().await.clone();
            let Some(sender) = sender else {
                return Err(TransportError::LostBeforeAccept);
            };
            let (reply, response) = oneshot::channel();
            if sender
                .send(TransportRequest::ScreenPower { requested, reply })
                .await
                .is_err()
            {
                return Err(TransportError::AcceptedButLost);
            }
            response
                .await
                .unwrap_or(Err(TransportError::AcceptedButLost))
        })
    }

    fn set_ready_handler(&self, handler: Handler) {
        *self
            .inner
            .ready_handler
            .lock()
            .expect("TLS ready handler lock") = Some(handler);
    }

    fn set_fault_handler(&self, handler: Handler) {
        *self
            .inner
            .fault_handler
            .lock()
            .expect("TLS fault handler lock") = Some(handler);
    }

    fn take_diagnostic(&self) -> Option<TransportDiagnostic> {
        self.inner
            .command_diagnostic
            .lock()
            .expect("TLS command diagnostic lock")
            .take()
    }

    fn route_proof<'a>(
        &'a self,
        controller_installation_id: [u8; 16],
        controller_nonce: [u8; 32],
    ) -> BoxFuture<'a, Result<keyferry_gateway::SignedRouteProof, TransportError>> {
        Box::pin(async move {
            let sender = self.inner.session.lock().await.clone();
            let Some(sender) = sender else {
                return Err(TransportError::LostBeforeAccept);
            };
            let (reply, response) = oneshot::channel();
            if sender
                .send(TransportRequest::RouteProof {
                    controller_installation_id,
                    controller_nonce,
                    reply,
                })
                .await
                .is_err()
            {
                return Err(TransportError::AcceptedButLost);
            }
            response
                .await
                .unwrap_or(Err(TransportError::AcceptedButLost))
        })
    }

    fn arm<'a>(
        &'a self,
        policy: ArmPolicy,
        lease_ms: u32,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        let policy = match policy {
            ArmPolicy::CommandScoped => keyferry_protocol::arm_policy::COMMAND_SCOPED,
            ArmPolicy::Temporary => keyferry_protocol::arm_policy::TEMPORARY,
            ArmPolicy::AlwaysReady => keyferry_protocol::arm_policy::ALWAYS_READY,
        };
        let mut payload = Vec::with_capacity(5);
        payload.push(policy);
        payload.extend_from_slice(&lease_ms.to_le_bytes());
        self.control_request(keyferry_protocol::message::ARM, payload)
    }

    fn disarm<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
        self.control_request(keyferry_protocol::message::DISARM, Vec::new())
    }

    fn renew_lease<'a>(&'a self, lease_ms: u32) -> BoxFuture<'a, Result<(), TransportError>> {
        self.control_request(
            keyferry_protocol::message::LEASE_RENEW,
            lease_ms.to_le_bytes().to_vec(),
        )
    }

    fn accept<'a>(
        &'a self,
        _command: &'a PlannedCommand,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            if self.is_ready() {
                Ok(())
            } else {
                Err(TransportError::LostBeforeAccept)
            }
        })
    }

    fn execute<'a>(
        &'a self,
        command: &'a PlannedCommand,
        cancellation: Cancellation,
        progress: ProgressHandler,
    ) -> BoxFuture<'a, TransportOutcome> {
        self.clear_command_diagnostic();
        Box::pin(async move {
            let sender = self.inner.session.lock().await.clone();
            let Some(sender) = sender else {
                return TransportOutcome::Unknown;
            };
            let (reply, response) = oneshot::channel();
            if sender
                .send(TransportRequest::Execute {
                    command: command.clone(),
                    cancellation,
                    progress,
                    reply,
                })
                .await
                .is_err()
            {
                return TransportOutcome::Unknown;
            }
            response.await.unwrap_or(TransportOutcome::Unknown)
        })
    }

    fn release_all<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let sender = self.inner.session.lock().await.clone();
            let Some(sender) = sender else {
                return Err(TransportError::LostBeforeAccept);
            };
            let (reply, response) = oneshot::channel();
            if sender
                .send(TransportRequest::ReleaseAll { reply })
                .await
                .is_err()
            {
                return Err(TransportError::AcceptedButLost);
            }
            response
                .await
                .unwrap_or(Err(TransportError::AcceptedButLost))
        })
    }

    fn release_input_all<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let sender = self.inner.session.lock().await.clone();
            let Some(sender) = sender else {
                return Err(TransportError::LostBeforeAccept);
            };
            let (reply, response) = oneshot::channel();
            if sender
                .send(TransportRequest::ReleaseInputAll { reply })
                .await
                .is_err()
            {
                return Err(TransportError::AcceptedButLost);
            }
            response
                .await
                .unwrap_or(Err(TransportError::AcceptedButLost))
        })
    }
}

impl TlsTransport {
    fn control_request(
        &self,
        message_type: u8,
        payload: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            let sender = self.inner.session.lock().await.clone();
            let Some(sender) = sender else {
                return Err(TransportError::LostBeforeAccept);
            };
            let (reply, response) = oneshot::channel();
            if sender
                .send(TransportRequest::Control {
                    message_type,
                    payload,
                    reply,
                })
                .await
                .is_err()
            {
                return Err(TransportError::AcceptedButLost);
            }
            response
                .await
                .unwrap_or(Err(TransportError::AcceptedButLost))
        })
    }
}

pub struct TlsListener {
    listener: TcpListener,
    transport: TlsTransport,
}

pub struct MultiTlsListener {
    listener: TcpListener,
    router: MultiTlsRouter,
}

#[derive(Clone)]
pub struct MultiTlsRouter {
    acceptor: TlsAcceptor,
    transports: Arc<HashMap<String, TlsTransport>>,
}

impl fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsListener")
            .field("local_addr", &self.listener.local_addr().ok())
            .field(
                "available_candidate_slots",
                &self.transport.inner.candidate_slots.available_permits(),
            )
            .finish()
    }
}

impl TlsListener {
    pub async fn bind(
        address: SocketAddr,
        transport: TlsTransport,
    ) -> Result<Self, TlsTransportError> {
        if address.ip().is_unspecified() {
            return Err(TlsTransportError::InvalidConfiguration(
                "TLS listener requires an explicitly selected local interface".to_owned(),
            ));
        }
        Ok(Self {
            listener: TcpListener::bind(address).await?,
            transport,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn accept_one(&self) -> Result<SocketAddr, TlsTransportError> {
        let (stream, peer) = accept_with_keepalive(&self.listener).await?;
        self.transport.accept_stream(stream).await?;
        Ok(peer)
    }
}

impl MultiTlsListener {
    pub async fn bind(
        address: SocketAddr,
        stores: &InstallationTlsSecretSet,
        transports: Vec<TlsTransport>,
    ) -> Result<Self, TlsTransportError> {
        if address.ip().is_unspecified() {
            return Err(TlsTransportError::InvalidConfiguration(
                "TLS listener requires an explicitly selected local interface".to_owned(),
            ));
        }
        let router = MultiTlsRouter::new(stores, transports)?;
        Ok(Self {
            listener: TcpListener::bind(address).await?,
            router,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn accept_one(&self) -> Result<(SocketAddr, [u8; 16]), TlsTransportError> {
        let (stream, peer) = accept_with_keepalive(&self.listener).await?;
        let device_id = self
            .router
            .accept_stream_on(stream, TlsLinkPath::Wifi)
            .await?;
        Ok((peer, device_id))
    }
}

impl MultiTlsRouter {
    pub fn new(
        stores: &InstallationTlsSecretSet,
        transports: Vec<TlsTransport>,
    ) -> Result<Self, TlsTransportError> {
        if stores.is_empty() || stores.len() != transports.len() {
            return Err(TlsTransportError::InvalidConfiguration(
                "multi-device listener credentials and transports do not match".to_owned(),
            ));
        }
        let config = server_config_exact_sni_set(stores)?;
        let mut by_device = transports
            .into_iter()
            .map(|transport| (transport.device_id(), transport))
            .collect::<HashMap<_, _>>();
        if by_device.len() != stores.len() {
            return Err(TlsTransportError::InvalidConfiguration(
                "multi-device listener contains duplicate transports".to_owned(),
            ));
        }
        let mut by_name = HashMap::with_capacity(stores.len());
        for store in stores.iter() {
            let transport = by_device.remove(&store.device_id()).ok_or_else(|| {
                TlsTransportError::InvalidConfiguration(
                    "multi-device listener is missing an exact device transport".to_owned(),
                )
            })?;
            by_name.insert(store.device_server_name().to_owned(), transport);
        }
        if !by_device.is_empty() {
            return Err(TlsTransportError::InvalidConfiguration(
                "multi-device listener has an unconfigured transport".to_owned(),
            ));
        }
        Ok(Self {
            acceptor: TlsAcceptor::from(config),
            transports: Arc::new(by_name),
        })
    }

    pub async fn accept_stream_on<IO>(
        &self,
        stream: IO,
        link_path: TlsLinkPath,
    ) -> Result<[u8; 16], TlsTransportError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let stream = time::timeout(AUTHENTICATION_TIMEOUT, self.acceptor.accept(stream))
            .await
            .map_err(|_| TlsTransportError::AuthenticationTimeout)?
            .map_err(|error| TlsTransportError::Tls(error.to_string()))?;
        let server_name = stream
            .get_ref()
            .1
            .server_name()
            .ok_or(TlsTransportError::Authentication)?
            .to_owned();
        let transport = self
            .transports
            .get(&server_name)
            .ok_or(TlsTransportError::Authentication)?;
        let device_id = transport.device_id();
        transport.accept_tls_stream_on(stream, link_path).await?;
        Ok(device_id)
    }
}

async fn accept_with_keepalive(
    listener: &TcpListener,
) -> Result<(TcpStream, SocketAddr), TlsTransportError> {
    let (stream, peer) = listener.accept().await?;
    let keepalive = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL)
        .with_retries(TCP_KEEPALIVE_RETRIES);
    SockRef::from(&stream).set_tcp_keepalive(&keepalive)?;
    Ok((stream, peer))
}

async fn connection_actor<IO>(
    transport: TlsTransport,
    mut stream: TlsStream<IO>,
    mut next_sequence: u32,
    mut requests: mpsc::Receiver<TransportRequest>,
    actor_session_id: [u8; 16],
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let request = tokio::select! {
            frame = read_frame(&mut stream) => {
                let _ = frame;
                fail_connection(
                    &transport,
                    &mut stream,
                    next_sequence,
                    actor_session_id,
                )
                .await;
                return;
            }
            request = requests.recv() => request,
        };
        let Some(request) = request else {
            fail_connection(&transport, &mut stream, next_sequence, actor_session_id).await;
            return;
        };
        match request {
            TransportRequest::RouteProof {
                controller_installation_id,
                controller_nonce,
                reply,
            } => match send_route_proof_request(
                &mut stream,
                &mut next_sequence,
                controller_installation_id,
                controller_nonce,
            )
            .await
            {
                Ok(proof) => {
                    let _ = reply.send(Ok(proof));
                }
                Err(TlsTransportError::DeviceRejected) => {
                    let _ = reply.send(Err(TransportError::ControlRejected));
                }
                Err(_) => {
                    let _ = reply.send(Err(TransportError::AcceptedButLost));
                    fail_connection(&transport, &mut stream, next_sequence, actor_session_id).await;
                    return;
                }
            },
            TransportRequest::Control {
                message_type,
                payload,
                reply,
            } => {
                match send_control_request(&mut stream, &mut next_sequence, message_type, &payload)
                    .await
                {
                    Ok(()) => {
                        let _ = reply.send(Ok(()));
                    }
                    Err(TlsTransportError::DeviceRejected) => {
                        let _ = reply.send(Err(TransportError::ControlRejected));
                    }
                    Err(_) => {
                        let _ = reply.send(Err(TransportError::AcceptedButLost));
                        fail_connection(&transport, &mut stream, next_sequence, actor_session_id)
                            .await;
                        return;
                    }
                }
            }
            TransportRequest::OutputMode { requested, reply } => {
                match send_output_mode_request(&mut stream, &mut next_sequence, requested).await {
                    Ok(status) => {
                        let _ = reply.send(Ok(status));
                    }
                    Err(TlsTransportError::DeviceRejected) => {
                        let _ = reply.send(Err(TransportError::ControlRejected));
                    }
                    Err(_) => {
                        let _ = reply.send(Err(TransportError::AcceptedButLost));
                        fail_connection(&transport, &mut stream, next_sequence, actor_session_id)
                            .await;
                        return;
                    }
                }
            }
            TransportRequest::DisplayOrientation { requested, reply } => {
                match send_display_orientation_request(&mut stream, &mut next_sequence, requested)
                    .await
                {
                    Ok(status) => {
                        let _ = reply.send(Ok(status));
                    }
                    Err(TlsTransportError::DeviceRejected) => {
                        let _ = reply.send(Err(TransportError::ControlRejected));
                    }
                    Err(_) => {
                        let _ = reply.send(Err(TransportError::AcceptedButLost));
                        fail_connection(&transport, &mut stream, next_sequence, actor_session_id)
                            .await;
                        return;
                    }
                }
            }
            TransportRequest::ScreenPower { requested, reply } => {
                match send_screen_power_request(&mut stream, &mut next_sequence, requested).await {
                    Ok(status) => {
                        let _ = reply.send(Ok(status));
                    }
                    Err(TlsTransportError::DeviceRejected) => {
                        let _ = reply.send(Err(TransportError::ControlRejected));
                    }
                    Err(_) => {
                        let _ = reply.send(Err(TransportError::AcceptedButLost));
                        fail_connection(&transport, &mut stream, next_sequence, actor_session_id)
                            .await;
                        return;
                    }
                }
            }
            TransportRequest::ResetBleHidBond { reply } => {
                match send_ble_hid_bond_reset_request(&mut stream, &mut next_sequence).await {
                    Ok(status) => {
                        let _ = reply.send(Ok(status));
                    }
                    Err(TlsTransportError::DeviceRejected) => {
                        let _ = reply.send(Err(TransportError::ControlRejected));
                    }
                    Err(_) => {
                        let _ = reply.send(Err(TransportError::AcceptedButLost));
                        fail_connection(&transport, &mut stream, next_sequence, actor_session_id)
                            .await;
                        return;
                    }
                }
            }
            TransportRequest::Execute {
                command,
                cancellation,
                progress,
                reply,
            } => match execute_connection(
                &mut stream,
                &mut next_sequence,
                &command,
                cancellation,
                &progress,
            )
            .await
            {
                Ok(outcome) => {
                    let _ = reply.send(outcome);
                }
                Err(error) => {
                    transport.record_command_diagnostic(&error);
                    let _ = reply.send(TransportOutcome::Unknown);
                    fail_connection(&transport, &mut stream, next_sequence, actor_session_id).await;
                    return;
                }
            },
            TransportRequest::ReleaseAll { reply } => {
                let result = send_release_all_and_wait(&mut stream, &mut next_sequence).await;
                if result.is_err() {
                    let _ = reply.send(Err(TransportError::AcceptedButLost));
                    fail_connection(&transport, &mut stream, next_sequence, actor_session_id).await;
                    return;
                }
                let _ = reply.send(Ok(()));
            }
            TransportRequest::ReleaseInputAll { reply } => {
                let result = send_input_release_all_and_wait(&mut stream, &mut next_sequence).await;
                if result.is_err() {
                    let _ = reply.send(Err(TransportError::AcceptedButLost));
                    fail_connection(&transport, &mut stream, next_sequence, actor_session_id).await;
                    return;
                }
                let _ = reply.send(Ok(()));
            }
            TransportRequest::GatewayHandoff { request, reply } => {
                match send_gateway_handoff_request(&mut stream, &mut next_sequence, &request).await
                {
                    Ok(status) => {
                        let committed_start = matches!(
                            request,
                            keyferry_protocol::gateway_handoff::Request::Start(_)
                        ) && status.status
                            == keyferry_protocol::gateway_handoff_status::OK
                            && status.phase == keyferry_protocol::gateway_handoff_phase::TARGETING;
                        let _ = reply.send(Ok(status));
                        if committed_start {
                            clear_connection(&transport, actor_session_id).await;
                            return;
                        }
                    }
                    Err(TlsTransportError::DeviceRejected) => {
                        let _ = reply.send(Err(TransportError::ControlRejected));
                    }
                    Err(_) => {
                        let _ = reply.send(Err(TransportError::AcceptedButLost));
                        clear_connection(&transport, actor_session_id).await;
                        return;
                    }
                }
            }
            TransportRequest::File { request, reply } => {
                match time::timeout(
                    Duration::from_secs(15),
                    send_file_request(&mut stream, &mut next_sequence, &request),
                )
                .await
                {
                    Ok(Ok(status)) => {
                        let _ = reply.send(Ok(status));
                    }
                    Ok(Err(TlsTransportError::DeviceRejected)) => {
                        let _ = reply.send(Err(TransportError::ControlRejected));
                    }
                    _ => {
                        let _ = reply.send(Err(TransportError::AcceptedButLost));
                        fail_connection(&transport, &mut stream, next_sequence, actor_session_id)
                            .await;
                        return;
                    }
                }
            }
            TransportRequest::FileSet { request, reply } => {
                match time::timeout(
                    Duration::from_secs(15),
                    send_file_set_request(&mut stream, &mut next_sequence, &request),
                )
                .await
                {
                    Ok(Ok(status)) => {
                        let _ = reply.send(Ok(status));
                    }
                    Ok(Err(TlsTransportError::DeviceRejected)) => {
                        let _ = reply.send(Err(TransportError::ControlRejected));
                    }
                    _ => {
                        let _ = reply.send(Err(TransportError::AcceptedButLost));
                        fail_connection(&transport, &mut stream, next_sequence, actor_session_id)
                            .await;
                        return;
                    }
                }
            }
            TransportRequest::EnterMaintenance { reply } => {
                let disarm = send_control_request(
                    &mut stream,
                    &mut next_sequence,
                    keyferry_protocol::message::DISARM,
                    &[],
                )
                .await;
                // The endpoint deliberately defers the DISARM ACK until the
                // all-zero USB report completes. A second RELEASE_ALL command
                // is redundant and can be rejected once disarm has taken
                // effect.
                let result = if disarm.is_ok() {
                    Ok(())
                } else {
                    Err(TransportError::AcceptedButLost)
                };
                let _ = stream.shutdown().await;
                clear_connection(&transport, actor_session_id).await;
                let _ = reply.send(result);
                return;
            }
        }
    }
}

async fn clear_connection(transport: &TlsTransport, actor_session_id: [u8; 16]) {
    let mut session = transport.inner.session.lock().await;
    let is_current = transport
        .inner
        .session_snapshot
        .read()
        .expect("TLS session snapshot lock")
        .as_ref()
        .is_some_and(|snapshot| snapshot.protocol_session_id == actor_session_id);
    if !is_current {
        return;
    }
    session.take();
    drop(session);
    transport.notify_fault();
}

async fn fail_connection<IO>(
    transport: &TlsTransport,
    stream: &mut TlsStream<IO>,
    next_sequence: u32,
    actor_session_id: [u8; 16],
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let _ = send_release_all(stream, next_sequence).await;
    clear_connection(transport, actor_session_id).await;
}

async fn execute_connection<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
    command: &PlannedCommand,
    cancellation: Cancellation,
    progress: &ProgressHandler,
) -> Result<TransportOutcome, TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if command.input.is_some() {
        return execute_input_connection(stream, next_sequence, command, cancellation, progress)
            .await;
    }
    let mut ever_started = false;
    let mut terminal_zero_confirmed = false;
    for (chunk_index, chunk) in command.chunks.iter().enumerate() {
        let expects_started = chunk
            .steps
            .iter()
            .any(|step| matches!(step, ReportStep::Report(report) if !report.is_released()));
        let mut accepted = false;
        let mut started = false;
        if chunk_index == 0 && std::time::Instant::now() >= command.expires_at {
            return Ok(TransportOutcome::Rejected);
        }
        if cancellation.is_cancelled() {
            send_release_all_and_wait(stream, next_sequence).await?;
            return Ok(TransportOutcome::Aborted);
        }
        if command.arm_before_first || chunk_index != 0 {
            let arm_result = send_control_request(
                stream,
                next_sequence,
                keyferry_protocol::message::ARM,
                &[keyferry_protocol::arm_policy::COMMAND_SCOPED, 0, 0, 0, 0],
            )
            .await;
            if let Err(error) = arm_result {
                return match error {
                    TlsTransportError::DeviceRejected if !ever_started => {
                        Ok(TransportOutcome::Rejected)
                    }
                    TlsTransportError::DeviceRejected if terminal_zero_confirmed => {
                        Ok(TransportOutcome::Aborted)
                    }
                    TlsTransportError::DeviceRejected => Ok(TransportOutcome::Unknown),
                    other => Err(other),
                };
            }
        }
        if cancellation.is_cancelled() {
            send_release_all_and_wait(stream, next_sequence).await?;
            return Ok(TransportOutcome::Aborted);
        }
        if chunk_index == 0 && std::time::Instant::now() >= command.expires_at {
            send_release_all_and_wait(stream, next_sequence).await?;
            return Ok(TransportOutcome::Rejected);
        }
        let body = encode_report_body(chunk)?;
        let sequence = *next_sequence;
        if sequence == u32::MAX {
            return Err(TlsTransportError::Protocol(
                "network sequence exhausted".to_owned(),
            ));
        }
        let valid_for_ms = if chunk_index == 0 {
            remaining_start_validity(command)
        } else {
            COMMAND_MAX_MS
        };
        send_command(
            stream,
            sequence,
            command,
            COMMAND_KIND_EXECUTE,
            &body,
            valid_for_ms,
        )
        .await?;
        *next_sequence += 1;
        loop {
            let result = tokio::select! {
                result = read_command_result(stream, sequence, command.command_id) => Some(result),
                () = wait_for_cancellation(cancellation.clone()) => None,
            };
            let Some(result) = result else {
                return cancel_connection(
                    stream,
                    next_sequence,
                    command,
                    sequence,
                    ever_started,
                    chunk_index + 1 < command.chunks.len(),
                )
                .await;
            };
            match result? {
                DeviceCommandResult::Accepted if !started => {
                    accepted = true;
                    progress(TransportProgress::Accepted);
                }
                DeviceCommandResult::Started if accepted && expects_started => {
                    started = true;
                    ever_started = true;
                    terminal_zero_confirmed = false;
                    progress(TransportProgress::Started);
                }
                DeviceCommandResult::Emitted if started || (accepted && !expects_started) => {
                    terminal_zero_confirmed = true;
                    break;
                }
                DeviceCommandResult::Accepted
                | DeviceCommandResult::Started
                | DeviceCommandResult::Emitted => {
                    return Err(TlsTransportError::Protocol(
                        "command result lifecycle is out of order".to_owned(),
                    ));
                }
                DeviceCommandResult::Aborted => return Ok(TransportOutcome::Aborted),
                DeviceCommandResult::Rejected => {
                    return Ok(if !ever_started {
                        TransportOutcome::Rejected
                    } else if terminal_zero_confirmed {
                        TransportOutcome::Aborted
                    } else {
                        TransportOutcome::Unknown
                    });
                }
                DeviceCommandResult::Unknown => return Ok(TransportOutcome::Unknown),
            }
        }
    }
    Ok(TransportOutcome::Emitted)
}

async fn execute_input_connection<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
    command: &PlannedCommand,
    cancellation: Cancellation,
    progress: &ProgressHandler,
) -> Result<TransportOutcome, TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let input = command.input.as_ref().ok_or_else(|| {
        TlsTransportError::Protocol("input command is missing its compiled plan".to_owned())
    })?;
    let mut ever_started = false;
    let mut terminal_dual_neutral = false;
    for (chunk_index, chunk) in input.chunks.iter().enumerate() {
        if chunk_index == 0 && std::time::Instant::now() >= command.expires_at {
            return Ok(TransportOutcome::Rejected);
        }
        if cancellation.is_cancelled() {
            send_input_release_all_and_wait(stream, next_sequence).await?;
            return Ok(TransportOutcome::Aborted);
        }
        if let Err(error) = send_control_request(
            stream,
            next_sequence,
            keyferry_protocol::message::ARM,
            &[keyferry_protocol::arm_policy::COMMAND_SCOPED, 0, 0, 0, 0],
        )
        .await
        {
            return match error {
                TlsTransportError::DeviceRejected if !ever_started => {
                    Ok(TransportOutcome::Rejected)
                }
                TlsTransportError::DeviceRejected if terminal_dual_neutral => {
                    Ok(TransportOutcome::Aborted)
                }
                TlsTransportError::DeviceRejected => Ok(TransportOutcome::Unknown),
                other => Err(other),
            };
        }
        if cancellation.is_cancelled() {
            send_input_release_all_and_wait(stream, next_sequence).await?;
            return Ok(TransportOutcome::Aborted);
        }
        if chunk_index == 0 && std::time::Instant::now() >= command.expires_at {
            send_input_release_all_and_wait(stream, next_sequence).await?;
            return Ok(TransportOutcome::Rejected);
        }
        let sequence = *next_sequence;
        if sequence == u32::MAX {
            return Err(TlsTransportError::Protocol(
                "network sequence exhausted".to_owned(),
            ));
        }
        let valid_for_ms = if chunk_index == 0 {
            remaining_start_validity(command)
        } else {
            COMMAND_MAX_MS
        };
        send_command(
            stream,
            sequence,
            command,
            keyferry_protocol::command_kind::EXECUTE_INPUT_CHUNK_V1,
            &chunk.body,
            valid_for_ms,
        )
        .await?;
        *next_sequence += 1;
        let mut accepted = false;
        let mut started = false;
        loop {
            let result = tokio::select! {
                result = read_input_command_result(stream, sequence, command.command_id) => Some(result),
                () = wait_for_cancellation(cancellation.clone()) => None,
            };
            let Some(result) = result else {
                return cancel_input_connection(
                    stream,
                    next_sequence,
                    command,
                    sequence,
                    ever_started,
                    chunk_index + 1 < input.chunks.len(),
                )
                .await;
            };
            let evidence = result?;
            match evidence.result {
                DeviceCommandResult::Accepted if !accepted && !started => {
                    accepted = true;
                    progress(TransportProgress::Accepted);
                }
                DeviceCommandResult::Started if accepted && !started && chunk.effectful => {
                    started = true;
                    ever_started = true;
                    terminal_dual_neutral = false;
                    progress(TransportProgress::Started);
                }
                DeviceCommandResult::Emitted
                    if accepted && evidence.dual_neutral() && (started || !chunk.effectful) =>
                {
                    terminal_dual_neutral = true;
                    break;
                }
                DeviceCommandResult::Aborted if evidence.dual_neutral() => {
                    return Ok(TransportOutcome::Aborted);
                }
                DeviceCommandResult::Rejected if !accepted && !ever_started => {
                    return Ok(TransportOutcome::Rejected);
                }
                DeviceCommandResult::Rejected if !accepted && terminal_dual_neutral => {
                    return Ok(TransportOutcome::Aborted);
                }
                DeviceCommandResult::Rejected if !accepted => {
                    return Ok(TransportOutcome::Unknown);
                }
                DeviceCommandResult::Unknown => return Ok(TransportOutcome::Unknown),
                DeviceCommandResult::Accepted
                | DeviceCommandResult::Started
                | DeviceCommandResult::Emitted
                | DeviceCommandResult::Aborted
                | DeviceCommandResult::Rejected => {
                    return Err(TlsTransportError::Protocol(
                        "input command result lifecycle is out of order".to_owned(),
                    ));
                }
            }
        }
    }
    Ok(TransportOutcome::Emitted)
}

async fn authenticate_stream<IO>(
    acceptor: &TlsAcceptor,
    stream: IO,
    credentials: &TlsCredentials,
    request_firmware_identity: bool,
) -> Result<
    (
        TlsStream<IO>,
        u32,
        [u8; 16],
        Option<keyferry_protocol::firmware_identity::FirmwareIdentityV1>,
    ),
    TlsTransportError,
>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let stream = acceptor
        .accept(stream)
        .await
        .map_err(|error| TlsTransportError::Tls(error.to_string()))
        .map_err(|error| session_setup_error("TLS handshake", error))?;
    authenticate_tls_stream(stream, credentials, request_firmware_identity).await
}

async fn authenticate_tls_stream<IO>(
    mut stream: TlsStream<IO>,
    credentials: &TlsCredentials,
    request_firmware_identity: bool,
) -> Result<
    (
        TlsStream<IO>,
        u32,
        [u8; 16],
        Option<keyferry_protocol::firmware_identity::FirmwareIdentityV1>,
    ),
    TlsTransportError,
>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let host_boot_nonce = random_array::<16>()
        .map_err(TlsTransportError::Io)
        .map_err(|error| session_setup_error("preparing authentication challenge", error))?;
    let challenge = random_array::<32>()
        .map_err(TlsTransportError::Io)
        .map_err(|error| session_setup_error("preparing authentication challenge", error))?;
    let mut challenge_payload = Vec::with_capacity(AUTH_CHALLENGE_LEN);
    challenge_payload.extend_from_slice(&credentials.host_id());
    challenge_payload.extend_from_slice(&host_boot_nonce);
    challenge_payload.extend_from_slice(&challenge);
    challenge_payload.push(keyferry_protocol::VERSION_MAJOR);
    challenge_payload.push(keyferry_protocol::VERSION_MINOR);
    send_frame(
        &mut stream,
        Frame::v1(
            keyferry_protocol::message::AUTH_CHALLENGE,
            0,
            challenge_payload,
        ),
    )
    .await
    .map_err(|error| session_setup_error("sending authentication challenge", error))?;

    let response = read_frame(&mut stream)
        .await
        .map_err(|error| session_setup_error("reading authentication response", error))?;
    verify_auth_response(&response, credentials, &host_boot_nonce, &challenge)
        .map_err(|error| session_setup_error("verifying authentication response", error))?;

    let session_id = random_array::<16>()
        .map_err(TlsTransportError::Io)
        .map_err(|error| session_setup_error("preparing session-ready response", error))?;
    let mut ready_payload = Vec::with_capacity(SESSION_READY_LEN);
    ready_payload.extend_from_slice(&session_id);
    ready_payload.push(keyferry_protocol::VERSION_MAJOR);
    ready_payload.push(keyferry_protocol::VERSION_MINOR);
    let advertised_capabilities = if request_firmware_identity {
        keyferry_protocol::capability::KEYBOARD
            | keyferry_protocol::capability::FIRMWARE_IDENTITY_V1
            | keyferry_protocol::capability::MOUSE_RELATIVE_V1
            | keyferry_protocol::capability::USB_FILE_HANDOFF_V1
            | keyferry_protocol::capability::USB_FILE_SET_V2
    } else {
        keyferry_protocol::capability::KEYBOARD
    };
    ready_payload.extend_from_slice(&advertised_capabilities.to_le_bytes());
    ready_payload.extend_from_slice(&HOST_LEASE_MS.to_le_bytes());
    ready_payload.extend_from_slice(&RENEW_EVERY_MS.to_le_bytes());
    ready_payload.extend_from_slice(&COMMAND_MAX_MS.to_le_bytes());
    send_frame(
        &mut stream,
        Frame::v1(keyferry_protocol::message::SESSION_READY, 1, ready_payload),
    )
    .await
    .map_err(|error| session_setup_error("sending session-ready response", error))?;
    let firmware_identity = if request_firmware_identity {
        let response = time::timeout(Duration::from_secs(2), read_frame(&mut stream))
            .await
            .map_err(|_| TlsTransportError::FirmwareIdentityUnavailable)?
            .map_err(|error| session_setup_error("reading firmware identity", error))?;
        if response.message_type != keyferry_protocol::message::CAPABILITIES
            || response.sequence != 1
        {
            return Err(session_setup_error(
                "verifying firmware identity",
                TlsTransportError::Protocol("unexpected firmware identity frame".to_owned()),
            ));
        }
        Some(
            keyferry_protocol::firmware_identity::decode_v1(&response.payload).map_err(
                |error| {
                    session_setup_error(
                        "verifying firmware identity",
                        TlsTransportError::Protocol(error.code().to_owned()),
                    )
                },
            )?,
        )
    } else {
        None
    };
    Ok((stream, 2, session_id, firmware_identity))
}

#[allow(clippy::too_many_arguments)]
pub fn auth_hmac(
    link_secret: &[u8; 32],
    host_id: &[u8; 16],
    device_id: &[u8; 16],
    host_boot_nonce: &[u8; 16],
    challenge: &[u8; 32],
    device_nonce: &[u8; 32],
    major: u8,
    minor: u8,
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(link_secret).expect("HMAC accepts a 32-byte key");
    mac.update(AUTH_DOMAIN);
    mac.update(host_id);
    mac.update(device_id);
    mac.update(host_boot_nonce);
    mac.update(challenge);
    mac.update(device_nonce);
    mac.update(&[major, minor]);
    mac.finalize().into_bytes().into()
}

fn verify_auth_response(
    frame: &Frame,
    credentials: &TlsCredentials,
    host_boot_nonce: &[u8; 16],
    challenge: &[u8; 32],
) -> Result<(), TlsTransportError> {
    if frame.message_type != keyferry_protocol::message::AUTH_RESPONSE
        || frame.sequence != 0
        || frame.payload.len() != AUTH_RESPONSE_LEN
    {
        return Err(TlsTransportError::Authentication);
    }
    let mut device_id = [0_u8; 16];
    device_id.copy_from_slice(&frame.payload[..16]);
    let mut device_nonce = [0_u8; 32];
    device_nonce.copy_from_slice(&frame.payload[16..48]);
    if device_id != credentials.device_id() {
        return Err(TlsTransportError::Authentication);
    }
    let mut verifier =
        HmacSha256::new_from_slice(&credentials.link_secret).expect("HMAC accepts a 32-byte key");
    verifier.update(AUTH_DOMAIN);
    verifier.update(&credentials.host_id());
    verifier.update(&device_id);
    verifier.update(host_boot_nonce);
    verifier.update(challenge);
    verifier.update(&device_nonce);
    verifier.update(&[
        keyferry_protocol::VERSION_MAJOR,
        keyferry_protocol::VERSION_MINOR,
    ]);
    verifier
        .verify_slice(&frame.payload[48..])
        .map_err(|_| TlsTransportError::Authentication)?;
    Ok(())
}

async fn send_frame<IO>(stream: &mut IO, frame: Frame) -> Result<(), TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let wire =
        encode_wire(&frame).map_err(|error| TlsTransportError::Protocol(error.to_string()))?;
    if wire.len() > MAX_WIRE_FRAME {
        return Err(TlsTransportError::Protocol(
            "encoded frame exceeds bounded wire buffer".to_owned(),
        ));
    }
    stream.write_all(&wire).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame<IO>(stream: &mut IO) -> Result<Frame, TlsTransportError>
where
    IO: AsyncRead + Unpin,
{
    let mut wire = Vec::with_capacity(MAX_WIRE_FRAME);
    loop {
        if wire.len() >= MAX_WIRE_FRAME {
            return Err(TlsTransportError::Protocol(
                "wire frame exceeds bounded input buffer".to_owned(),
            ));
        }
        let byte = stream.read_u8().await?;
        wire.push(byte);
        if byte == 0 {
            return decode_wire(&wire)
                .map_err(|error| TlsTransportError::Protocol(error.to_string()));
        }
    }
}

fn server_config(identity: &HostIdentity) -> Result<Arc<ServerConfig>, TlsTransportError> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256];
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(identity.certificate_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.private_key_der.clone())),
        )
        .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?;
    config.max_fragment_size = Some(TLS_MAX_FRAGMENT_SIZE);
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.ticketer = Arc::new(NoTickets);
    config.alpn_protocols.clear();
    Ok(Arc::new(config))
}

fn server_config_exact_sni(
    identity: &HostIdentity,
    server_name: &str,
) -> Result<Arc<ServerConfig>, TlsTransportError> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256];
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
    let certified_key = CertifiedKey::from_der(
        vec![CertificateDer::from(identity.certificate_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.private_key_der.clone())),
        &provider,
    )
    .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?;
    let mut resolver = ResolvesServerCertUsingSni::new();
    resolver
        .add(server_name, certified_key)
        .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.max_fragment_size = Some(TLS_MAX_FRAGMENT_SIZE);
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.ticketer = Arc::new(NoTickets);
    config.alpn_protocols.clear();
    Ok(Arc::new(config))
}

fn server_config_exact_sni_set(
    stores: &InstallationTlsSecretSet,
) -> Result<Arc<ServerConfig>, TlsTransportError> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256];
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
    let mut resolver = ResolvesServerCertUsingSni::new();
    for store in stores.iter() {
        let certified_key = CertifiedKey::from_der(
            vec![CertificateDer::from(store.identity.certificate_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                store.identity.private_key_der.clone(),
            )),
            &provider,
        )
        .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?;
        resolver
            .add(store.device_server_name(), certified_key)
            .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?;
    }
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.max_fragment_size = Some(TLS_MAX_FRAGMENT_SIZE);
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.ticketer = Arc::new(NoTickets);
    config.alpn_protocols.clear();
    Ok(Arc::new(config))
}

fn remote_server_config(
    identity: &HostIdentity,
    owner_ca_der: &[u8],
    server_name: &str,
) -> Result<Arc<ServerConfig>, TlsTransportError> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256];
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
    let provider = Arc::new(provider);

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(owner_ca_der.to_vec()))
        .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?;
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?;
    let certified_key = CertifiedKey::from_der(
        vec![CertificateDer::from(identity.certificate_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.private_key_der.clone())),
        &provider,
    )
    .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?;
    let mut resolver = ResolvesServerCertUsingSni::new();
    resolver
        .add(server_name, certified_key)
        .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?;

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .map_err(|error| TlsTransportError::InvalidConfiguration(error.to_string()))?
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(Arc::new(resolver));
    config.max_fragment_size = Some(TLS_MAX_FRAGMENT_SIZE);
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.ticketer = Arc::new(NoTickets);
    config.alpn_protocols.clear();
    Ok(Arc::new(config))
}

pub(crate) fn installation_id_from_peer_certificate(
    certificate_der: &[u8],
) -> Result<[u8; 16], TlsTransportError> {
    let (remainder, certificate) =
        parse_x509_certificate(certificate_der).map_err(|_| TlsTransportError::Authentication)?;
    if !remainder.is_empty() {
        return Err(TlsTransportError::Authentication);
    }
    installation_id_for_spki(certificate.tbs_certificate.subject_pki.raw)
        .map_err(|_| TlsTransportError::Authentication)
}

#[derive(Debug)]
struct NoTickets;

impl ProducesTickets for NoTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

fn encode_report_body(chunk: &super::PlannedChunk) -> Result<Vec<u8>, TlsTransportError> {
    let mut body = Vec::new();
    for step in &chunk.steps {
        match step {
            ReportStep::Report(report) if report.is_released() => {
                body.extend_from_slice(&[keyferry_protocol::action::RELEASE_ALL_ACTION, 0]);
            }
            ReportStep::Report(report) => {
                body.extend_from_slice(&[keyferry_protocol::action::KEY_REPORT, 8]);
                body.push(report.modifiers);
                body.push(0);
                body.extend_from_slice(&report.keys);
            }
            ReportStep::WaitMs(duration) => {
                body.extend_from_slice(&[keyferry_protocol::action::WAIT_MS, 2]);
                body.extend_from_slice(&duration.to_le_bytes());
            }
        }
    }
    if body.len() > super::MAX_NETWORK_COMMAND_BODY {
        return Err(TlsTransportError::Protocol(
            "command body exceeds protocol payload limit".to_owned(),
        ));
    }
    Ok(body)
}

fn send_command<'a, IO>(
    stream: &'a mut IO,
    sequence: u32,
    command: &super::PlannedCommand,
    kind: u8,
    body: &[u8],
    valid_for_ms: u32,
) -> impl std::future::Future<Output = Result<(), TlsTransportError>> + 'a
where
    IO: AsyncRead + AsyncWrite + Unpin + 'a,
{
    let payload = command_payload(command, kind, body, valid_for_ms);
    async move {
        let payload = payload?;
        send_frame(
            stream,
            Frame::v1(keyferry_protocol::message::COMMAND, sequence, payload),
        )
        .await
    }
}

async fn send_control_request<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
    message_type: u8,
    payload: &[u8],
) -> Result<(), TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let sequence = *next_sequence;
    if sequence == u32::MAX {
        return Err(TlsTransportError::Protocol(
            "network sequence exhausted".to_owned(),
        ));
    }
    send_frame(stream, Frame::v1(message_type, sequence, payload.to_vec())).await?;
    *next_sequence += 1;
    read_control_ack(stream, sequence, message_type).await
}

async fn send_output_mode_request<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
    requested: Option<OutputMode>,
) -> Result<TransportOutputModeStatus, TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let sequence = *next_sequence;
    if sequence == u32::MAX {
        return Err(TlsTransportError::Protocol(
            "network sequence exhausted".to_owned(),
        ));
    }
    let (message_type, payload) = requested.map_or_else(
        || (keyferry_protocol::message::GET_OUTPUT_MODE, Vec::new()),
        |mode| {
            (
                keyferry_protocol::message::SET_OUTPUT_MODE,
                vec![mode.to_wire()],
            )
        },
    );
    send_frame(stream, Frame::v1(message_type, sequence, payload)).await?;
    *next_sequence += 1;
    let frame = read_frame(stream).await?;
    if frame.sequence != sequence {
        return Err(TlsTransportError::Protocol(
            "output-mode response sequence does not match its request".to_owned(),
        ));
    }
    if frame.message_type == keyferry_protocol::message::ERROR {
        return Err(TlsTransportError::DeviceRejected);
    }
    if frame.message_type != keyferry_protocol::message::OUTPUT_MODE_STATUS {
        return Err(TlsTransportError::Protocol(
            "output-mode response has the wrong message type".to_owned(),
        ));
    }
    let [active, stored] = frame.payload.as_slice() else {
        return Err(TlsTransportError::Protocol(
            "output-mode response has the wrong payload length".to_owned(),
        ));
    };
    let active = OutputMode::from_wire(*active).ok_or_else(|| {
        TlsTransportError::Protocol("output-mode response has an invalid active mode".to_owned())
    })?;
    let stored = OutputMode::from_wire(*stored).ok_or_else(|| {
        TlsTransportError::Protocol("output-mode response has an invalid stored mode".to_owned())
    })?;
    if requested.is_some_and(|mode| mode != stored) {
        return Err(TlsTransportError::Protocol(
            "output-mode response did not retain the requested mode".to_owned(),
        ));
    }
    Ok(TransportOutputModeStatus { active, stored })
}

async fn send_ble_hid_bond_reset_request<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
) -> Result<(bool, bool), TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let sequence = *next_sequence;
    if sequence == u32::MAX {
        return Err(TlsTransportError::Protocol(
            "network sequence exhausted".to_owned(),
        ));
    }
    send_frame(
        stream,
        Frame::v1(
            keyferry_protocol::message::RESET_BLE_HID_BOND,
            sequence,
            Vec::new(),
        ),
    )
    .await?;
    *next_sequence += 1;
    let frame = read_frame(stream).await?;
    if frame.sequence != sequence {
        return Err(TlsTransportError::Protocol(
            "Bluetooth bond-reset response sequence does not match its request".to_owned(),
        ));
    }
    if frame.message_type == keyferry_protocol::message::ERROR {
        return Err(TlsTransportError::DeviceRejected);
    }
    if frame.message_type != keyferry_protocol::message::BLE_HID_BOND_STATUS {
        return Err(TlsTransportError::Protocol(
            "Bluetooth bond-reset response has the wrong message type".to_owned(),
        ));
    }
    let [result, restart_pending] = frame.payload.as_slice() else {
        return Err(TlsTransportError::Protocol(
            "Bluetooth bond-reset response has the wrong payload length".to_owned(),
        ));
    };
    let bond_was_present = match *result {
        0 => false,
        1 => true,
        2 => return Err(TlsTransportError::DeviceRejected),
        _ => {
            return Err(TlsTransportError::Protocol(
                "Bluetooth bond-reset response has an invalid result".to_owned(),
            ))
        }
    };
    let restart_pending = match *restart_pending {
        0 => false,
        1 => true,
        _ => {
            return Err(TlsTransportError::Protocol(
                "Bluetooth bond-reset response has an invalid restart flag".to_owned(),
            ))
        }
    };
    if !restart_pending {
        return Err(TlsTransportError::Protocol(
            "successful Bluetooth bond reset did not schedule a restart".to_owned(),
        ));
    }
    Ok((bond_was_present, restart_pending))
}

async fn send_display_orientation_request<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
    requested: Option<DisplayOrientation>,
) -> Result<TransportDisplayOrientationStatus, TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let sequence = *next_sequence;
    if sequence == u32::MAX {
        return Err(TlsTransportError::Protocol(
            "network sequence exhausted".to_owned(),
        ));
    }
    let (message_type, payload) = requested.map_or_else(
        || {
            (
                keyferry_protocol::message::GET_DISPLAY_ORIENTATION,
                Vec::new(),
            )
        },
        |orientation| {
            (
                keyferry_protocol::message::SET_DISPLAY_ORIENTATION,
                vec![orientation.to_wire()],
            )
        },
    );
    send_frame(stream, Frame::v1(message_type, sequence, payload)).await?;
    *next_sequence += 1;
    let frame = read_frame(stream).await?;
    if frame.sequence != sequence {
        return Err(TlsTransportError::Protocol(
            "display-orientation response sequence does not match its request".to_owned(),
        ));
    }
    if frame.message_type == keyferry_protocol::message::ERROR {
        return Err(TlsTransportError::DeviceRejected);
    }
    if frame.message_type != keyferry_protocol::message::DISPLAY_ORIENTATION_STATUS {
        return Err(TlsTransportError::Protocol(
            "display-orientation response has the wrong message type".to_owned(),
        ));
    }
    let [active, stored] = frame.payload.as_slice() else {
        return Err(TlsTransportError::Protocol(
            "display-orientation response has the wrong payload length".to_owned(),
        ));
    };
    let active = DisplayOrientation::from_wire(*active).ok_or_else(|| {
        TlsTransportError::Protocol(
            "display-orientation response has an invalid active value".to_owned(),
        )
    })?;
    let stored = DisplayOrientation::from_wire(*stored).ok_or_else(|| {
        TlsTransportError::Protocol(
            "display-orientation response has an invalid stored value".to_owned(),
        )
    })?;
    if requested.is_some_and(|orientation| orientation != stored) {
        return Err(TlsTransportError::Protocol(
            "display-orientation response did not retain the requested value".to_owned(),
        ));
    }
    Ok(TransportDisplayOrientationStatus { active, stored })
}

async fn send_screen_power_request<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
    requested: Option<ScreenPower>,
) -> Result<TransportScreenPowerStatus, TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let sequence = *next_sequence;
    if sequence == u32::MAX {
        return Err(TlsTransportError::Protocol(
            "network sequence exhausted".to_owned(),
        ));
    }
    let (message_type, payload) = requested.map_or_else(
        || (keyferry_protocol::message::GET_SCREEN_POWER, Vec::new()),
        |power| {
            (
                keyferry_protocol::message::SET_SCREEN_POWER,
                vec![power.to_wire()],
            )
        },
    );
    send_frame(stream, Frame::v1(message_type, sequence, payload)).await?;
    *next_sequence += 1;
    let frame = read_frame(stream).await?;
    if frame.sequence != sequence {
        return Err(TlsTransportError::Protocol(
            "screen-power response sequence does not match its request".to_owned(),
        ));
    }
    if frame.message_type == keyferry_protocol::message::ERROR {
        return Err(TlsTransportError::DeviceRejected);
    }
    if frame.message_type != keyferry_protocol::message::SCREEN_POWER_STATUS {
        return Err(TlsTransportError::Protocol(
            "screen-power response has the wrong message type".to_owned(),
        ));
    }
    let [active, stored, available] = frame.payload.as_slice() else {
        return Err(TlsTransportError::Protocol(
            "screen-power response has the wrong payload length".to_owned(),
        ));
    };
    let active = ScreenPower::from_wire(*active).ok_or_else(|| {
        TlsTransportError::Protocol("screen-power response has an invalid active value".to_owned())
    })?;
    let stored = ScreenPower::from_wire(*stored).ok_or_else(|| {
        TlsTransportError::Protocol("screen-power response has an invalid stored value".to_owned())
    })?;
    let available = match available {
        0 => false,
        1 => true,
        _ => {
            return Err(TlsTransportError::Protocol(
                "screen-power response has an invalid availability value".to_owned(),
            ))
        }
    };
    if requested.is_some_and(|power| power != stored) {
        return Err(TlsTransportError::Protocol(
            "screen-power response did not retain the requested value".to_owned(),
        ));
    }
    Ok(TransportScreenPowerStatus {
        active,
        stored,
        available,
    })
}

async fn send_route_proof_request<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
    controller_installation_id: [u8; 16],
    controller_nonce: [u8; 32],
) -> Result<keyferry_gateway::SignedRouteProof, TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if controller_installation_id.iter().all(|byte| *byte == 0)
        || controller_nonce.iter().all(|byte| *byte == 0)
    {
        return Err(TlsTransportError::Protocol(
            "route proof request identity or nonce is zero".to_owned(),
        ));
    }
    let sequence = *next_sequence;
    if sequence == u32::MAX {
        return Err(TlsTransportError::Protocol(
            "network sequence exhausted".to_owned(),
        ));
    }
    let mut payload = Vec::with_capacity(48);
    payload.extend_from_slice(&controller_installation_id);
    payload.extend_from_slice(&controller_nonce);
    send_frame(
        stream,
        Frame::v1(
            keyferry_protocol::message::ROUTE_PROOF_REQUEST,
            sequence,
            payload,
        ),
    )
    .await?;
    *next_sequence += 1;
    let frame = read_frame(stream).await?;
    if frame.sequence != sequence {
        return Err(TlsTransportError::Protocol(
            "route proof response sequence does not match its request".to_owned(),
        ));
    }
    if frame.message_type == keyferry_protocol::message::ERROR {
        return Err(TlsTransportError::DeviceRejected);
    }
    if frame.message_type != keyferry_protocol::message::ROUTE_PROOF_RESPONSE {
        return Err(TlsTransportError::Protocol(
            "route proof response has the wrong message type".to_owned(),
        ));
    }
    let proof = keyferry_gateway::decode_route_proof_response(&frame.payload)
        .map_err(|error| TlsTransportError::Protocol(error.to_string()))?;
    if proof.input.controller_installation_id != controller_installation_id
        || proof.input.controller_nonce != controller_nonce
    {
        return Err(TlsTransportError::Protocol(
            "route proof response does not match its request".to_owned(),
        ));
    }
    Ok(proof)
}

async fn send_file_request<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
    request: &keyferry_protocol::file::Request,
) -> Result<keyferry_protocol::file::Status, TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let sequence = *next_sequence;
    if sequence == u32::MAX {
        return Err(TlsTransportError::Protocol(
            "network sequence exhausted".to_owned(),
        ));
    }
    let payload = request
        .encode()
        .map_err(|error| TlsTransportError::Protocol(error.to_string()))?;
    send_frame(
        stream,
        Frame::v1(keyferry_protocol::message::FILE_REQUEST, sequence, payload),
    )
    .await?;
    *next_sequence += 1;
    let frame = read_frame(stream).await?;
    if frame.sequence != sequence || frame.message_type != keyferry_protocol::message::FILE_STATUS {
        return Err(TlsTransportError::Protocol(
            "file response did not match its request".to_owned(),
        ));
    }
    keyferry_protocol::file::Status::decode(&frame.payload)
        .map_err(|error| TlsTransportError::Protocol(error.to_string()))
}

async fn send_file_set_request<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
    request: &keyferry_protocol::file_set::Request,
) -> Result<keyferry_protocol::file_set::Status, TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let sequence = *next_sequence;
    if sequence == u32::MAX {
        return Err(TlsTransportError::Protocol(
            "network sequence exhausted".to_owned(),
        ));
    }
    let payload = request
        .encode()
        .map_err(|error| TlsTransportError::Protocol(error.to_string()))?;
    send_frame(
        stream,
        Frame::v1(
            keyferry_protocol::message::FILE_SET_REQUEST,
            sequence,
            payload,
        ),
    )
    .await?;
    *next_sequence += 1;
    let frame = read_frame(stream).await?;
    if frame.sequence != sequence
        || frame.message_type != keyferry_protocol::message::FILE_SET_STATUS
    {
        return Err(TlsTransportError::Protocol(
            "file-set response did not match its request".to_owned(),
        ));
    }
    let status = keyferry_protocol::file_set::Status::decode(&frame.payload)
        .map_err(|error| TlsTransportError::Protocol(error.to_string()))?;
    match (request, status.entry.as_ref()) {
        (keyferry_protocol::file_set::Request::Status { index: 255 }, Some(_)) => {
            return Err(TlsTransportError::Protocol(
                "file-set summary returned an entry".to_owned(),
            ));
        }
        (keyferry_protocol::file_set::Request::Status { index }, Some(entry))
            if status.state == keyferry_protocol::file_set::State::Published
                && status.error == keyferry_protocol::file_set::Error::Ok
                && (*index as usize) < status.count as usize
                && entry.index == *index => {}
        (keyferry_protocol::file_set::Request::Status { index }, _)
            if status.state == keyferry_protocol::file_set::State::Published
                && status.error == keyferry_protocol::file_set::Error::Ok
                && (*index as usize) < status.count as usize =>
        {
            return Err(TlsTransportError::Protocol(
                "file-set entry did not match its request".to_owned(),
            ));
        }
        (_, Some(_)) => {
            return Err(TlsTransportError::Protocol(
                "unexpected file-set entry".to_owned(),
            ));
        }
        _ => {}
    }
    Ok(status)
}

async fn send_gateway_handoff_request<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
    request: &keyferry_protocol::gateway_handoff::Request,
) -> Result<keyferry_protocol::gateway_handoff::Status, TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let sequence = *next_sequence;
    if sequence == u32::MAX {
        return Err(TlsTransportError::Protocol(
            "network sequence exhausted".to_owned(),
        ));
    }
    let payload = keyferry_protocol::gateway_handoff::encode_request(request);
    // Decode locally as the final fail-closed validation before network I/O.
    keyferry_protocol::gateway_handoff::decode_request(&payload)
        .map_err(|error| TlsTransportError::Protocol(error.to_string()))?;
    send_frame(
        stream,
        Frame::v1(
            keyferry_protocol::message::GATEWAY_HANDOFF,
            sequence,
            payload,
        ),
    )
    .await?;
    *next_sequence += 1;
    let frame = read_frame(stream).await?;
    if frame.sequence != sequence {
        return Err(TlsTransportError::Protocol(
            "gateway handoff response sequence does not match its request".to_owned(),
        ));
    }
    if frame.message_type == keyferry_protocol::message::ERROR {
        return Err(TlsTransportError::DeviceRejected);
    }
    if frame.message_type != keyferry_protocol::message::GATEWAY_HANDOFF_STATUS {
        return Err(TlsTransportError::Protocol(
            "gateway handoff response has the wrong message type".to_owned(),
        ));
    }
    let status = keyferry_protocol::gateway_handoff::decode_status(&frame.payload)
        .map_err(|error| TlsTransportError::Protocol(error.to_string()))?;
    let transaction_id = match request {
        keyferry_protocol::gateway_handoff::Request::Start(value) => value.transaction_id,
        keyferry_protocol::gateway_handoff::Request::Accept(value) => value.transaction_id,
        keyferry_protocol::gateway_handoff::Request::Query(value) => value.transaction_id,
    };
    let reply_operation = match request {
        keyferry_protocol::gateway_handoff::Request::Start(_) => {
            keyferry_protocol::gateway_handoff_operation::START
        }
        keyferry_protocol::gateway_handoff::Request::Accept(_) => {
            keyferry_protocol::gateway_handoff_operation::ACCEPT
        }
        keyferry_protocol::gateway_handoff::Request::Query(_) => {
            keyferry_protocol::gateway_handoff_operation::QUERY
        }
    };
    if status.transaction_id != transaction_id || status.reply_operation != reply_operation {
        return Err(TlsTransportError::Protocol(
            "gateway handoff response does not match its transaction".to_owned(),
        ));
    }
    Ok(status)
}

async fn read_control_ack<IO>(
    stream: &mut IO,
    sequence: u32,
    message_type: u8,
) -> Result<(), TlsTransportError>
where
    IO: AsyncRead + Unpin,
{
    let frame = read_frame(stream).await?;
    if frame.sequence != sequence {
        return Err(TlsTransportError::Protocol(
            "control response sequence does not match its request".to_owned(),
        ));
    }
    if frame.message_type == keyferry_protocol::message::ERROR {
        return Err(TlsTransportError::DeviceRejected);
    }
    if frame.message_type != keyferry_protocol::message::ACK
        || frame.payload.len() != CONTROL_ACK_LEN
        || frame.payload[0] != message_type
    {
        return Err(TlsTransportError::Protocol(
            "control ACK does not match its request".to_owned(),
        ));
    }
    let status = u16::from_le_bytes([frame.payload[1], frame.payload[2]]);
    if status != 0 {
        return Err(TlsTransportError::DeviceRejected);
    }
    Ok(())
}

fn command_payload(
    command: &super::PlannedCommand,
    kind: u8,
    body: &[u8],
    valid_for_ms: u32,
) -> Result<Vec<u8>, TlsTransportError> {
    if body.len() > u16::MAX as usize {
        return Err(TlsTransportError::Protocol(
            "command body length does not fit protocol field".to_owned(),
        ));
    }
    if valid_for_ms == 0 || valid_for_ms > COMMAND_MAX_MS {
        return Err(TlsTransportError::Protocol(
            "command validity is outside protocol bounds".to_owned(),
        ));
    }
    let mut profile_hash = Sha256::new();
    profile_hash.update(command.profile.as_bytes());
    let profile_hash = profile_hash.finalize();
    let mut payload = Vec::with_capacity(16 + 4 + 32 + 1 + 2 + body.len());
    payload.extend_from_slice(command.command_id.as_bytes());
    payload.extend_from_slice(&valid_for_ms.to_le_bytes());
    payload.extend_from_slice(&profile_hash);
    payload.push(kind);
    payload.extend_from_slice(&(body.len() as u16).to_le_bytes());
    payload.extend_from_slice(body);
    if payload.len() > MAX_PAYLOAD {
        return Err(TlsTransportError::Protocol(
            "command envelope exceeds protocol payload limit".to_owned(),
        ));
    }
    Ok(payload)
}

fn remaining_start_validity(command: &super::PlannedCommand) -> u32 {
    command
        .expires_at
        .saturating_duration_since(std::time::Instant::now())
        .as_millis()
        .clamp(1, u128::from(COMMAND_MAX_MS)) as u32
}

fn empty_command(sequence: u32) -> super::PlannedCommand {
    super::PlannedCommand {
        command_id: uuid::Uuid::from_u128(u128::from(sequence)),
        chunks: Vec::new(),
        action_count: 0,
        char_count: 0,
        profile: "".to_owned(),
        expires_at: std::time::Instant::now() + Duration::from_secs(1),
        arm_before_first: false,
        input: None,
    }
}

async fn send_release_all<IO>(stream: &mut IO, sequence: u32) -> Result<(), TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let command = empty_command(sequence);
    send_command(
        stream,
        sequence,
        &command,
        COMMAND_KIND_RELEASE_ALL,
        &[],
        COMMAND_MAX_MS,
    )
    .await
}

async fn send_release_all_and_wait<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
) -> Result<(), TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let sequence = *next_sequence;
    if sequence == u32::MAX {
        return Err(TlsTransportError::Protocol(
            "network sequence exhausted".to_owned(),
        ));
    }
    let command = empty_command(sequence);
    send_command(
        stream,
        sequence,
        &command,
        COMMAND_KIND_RELEASE_ALL,
        &[],
        COMMAND_MAX_MS,
    )
    .await
    .map_err(|error| {
        cancellation_error(
            error,
            TransportDiagnostic::CancelReleaseSendTransport,
            TransportDiagnostic::CancelReleaseSendProtocol,
        )
    })?;
    *next_sequence += 1;
    if read_command_result(stream, sequence, command.command_id)
        .await
        .map_err(|error| {
            cancellation_error(
                error,
                TransportDiagnostic::CancelReleaseAcceptedTransport,
                TransportDiagnostic::CancelReleaseAcceptedProtocol,
            )
        })?
        != DeviceCommandResult::Accepted
    {
        return Err(diagnosed_error(
            TransportDiagnostic::CancelReleaseAcceptedProtocol,
            TlsTransportError::Protocol("release-all was not accepted".to_owned()),
        ));
    }
    if read_command_result(stream, sequence, command.command_id)
        .await
        .map_err(|error| {
            cancellation_error(
                error,
                TransportDiagnostic::CancelReleaseEmittedTransport,
                TransportDiagnostic::CancelReleaseEmittedProtocol,
            )
        })?
        != DeviceCommandResult::Emitted
    {
        return Err(diagnosed_error(
            TransportDiagnostic::CancelReleaseEmittedProtocol,
            TlsTransportError::Protocol("release-all did not complete".to_owned()),
        ));
    }
    Ok(())
}

async fn send_input_release_all_and_wait<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
) -> Result<(), TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let sequence = *next_sequence;
    if sequence == u32::MAX {
        return Err(diagnosed_error(
            TransportDiagnostic::CancelReleaseSendProtocol,
            TlsTransportError::Protocol("network sequence exhausted".to_owned()),
        ));
    }
    let command = empty_command(sequence);
    send_command(
        stream,
        sequence,
        &command,
        keyferry_protocol::command_kind::RELEASE_INPUT_ALL_V1,
        &[],
        COMMAND_MAX_MS,
    )
    .await
    .map_err(|error| {
        cancellation_error(
            error,
            TransportDiagnostic::CancelReleaseSendTransport,
            TransportDiagnostic::CancelReleaseSendProtocol,
        )
    })?;
    *next_sequence += 1;
    let accepted = read_input_command_result(stream, sequence, command.command_id)
        .await
        .map_err(|error| {
            cancellation_error(
                error,
                TransportDiagnostic::CancelReleaseAcceptedTransport,
                TransportDiagnostic::CancelReleaseAcceptedProtocol,
            )
        })?;
    if accepted.result != DeviceCommandResult::Accepted {
        return Err(diagnosed_error(
            TransportDiagnostic::CancelReleaseAcceptedProtocol,
            TlsTransportError::Protocol("input release-all was not accepted".to_owned()),
        ));
    }
    let emitted = read_input_command_result(stream, sequence, command.command_id)
        .await
        .map_err(|error| {
            cancellation_error(
                error,
                TransportDiagnostic::CancelReleaseEmittedTransport,
                TransportDiagnostic::CancelReleaseEmittedProtocol,
            )
        })?;
    if emitted.result != DeviceCommandResult::Emitted || !emitted.dual_neutral() {
        return Err(diagnosed_error(
            TransportDiagnostic::CancelReleaseEmittedProtocol,
            TlsTransportError::Protocol(
                "input release-all did not confirm both neutral reports".to_owned(),
            ),
        ));
    }
    Ok(())
}

async fn wait_for_cancellation(cancellation: Cancellation) {
    while !cancellation.is_cancelled() {
        time::sleep(Duration::from_millis(5)).await;
    }
}

async fn cancel_connection<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
    command: &super::PlannedCommand,
    active_sequence: u32,
    ever_started: bool,
    has_remaining_chunks: bool,
) -> Result<TransportOutcome, TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let cancel_sequence = *next_sequence;
    if cancel_sequence == u32::MAX {
        return Err(diagnosed_error(
            TransportDiagnostic::CancelSendProtocol,
            TlsTransportError::Protocol("network sequence exhausted".to_owned()),
        ));
    }
    send_command(
        stream,
        cancel_sequence,
        command,
        COMMAND_KIND_CANCEL,
        &[],
        COMMAND_MAX_MS,
    )
    .await
    .map_err(|error| {
        cancellation_error(
            error,
            TransportDiagnostic::CancelSendTransport,
            TransportDiagnostic::CancelSendProtocol,
        )
    })?;
    *next_sequence += 1;
    let outcome = loop {
        match read_command_result(stream, active_sequence, command.command_id)
            .await
            .map_err(|error| {
                cancellation_error(
                    error,
                    TransportDiagnostic::CancelActiveResultTransport,
                    TransportDiagnostic::CancelActiveResultProtocol,
                )
            })? {
            DeviceCommandResult::Accepted | DeviceCommandResult::Started => {}
            DeviceCommandResult::Emitted => break TransportOutcome::Emitted,
            DeviceCommandResult::Aborted => break TransportOutcome::Aborted,
            DeviceCommandResult::Rejected => break TransportOutcome::Rejected,
            DeviceCommandResult::Unknown => break TransportOutcome::Unknown,
        }
    };
    if matches!(
        outcome,
        TransportOutcome::Emitted | TransportOutcome::Rejected
    ) && read_command_result(stream, cancel_sequence, command.command_id)
        .await
        .map_err(|error| {
            cancellation_error(
                error,
                TransportDiagnostic::CancelLateResultTransport,
                TransportDiagnostic::CancelLateResultProtocol,
            )
        })?
        != DeviceCommandResult::Rejected
    {
        return Err(diagnosed_error(
            TransportDiagnostic::CancelLateResultProtocol,
            TlsTransportError::Protocol("late cancellation was not rejected".to_owned()),
        ));
    }
    // ABORTED and EMITTED are emitted by the endpoint only after its terminal
    // zero report completes. Confirm release separately only when the endpoint
    // itself could not establish that terminal boundary.
    if outcome == TransportOutcome::Unknown {
        send_release_all_and_wait(stream, next_sequence).await?;
    }
    Ok(match outcome {
        TransportOutcome::Emitted if !has_remaining_chunks => TransportOutcome::Emitted,
        TransportOutcome::Rejected if !ever_started => TransportOutcome::Rejected,
        TransportOutcome::Emitted
        | TransportOutcome::Aborted
        | TransportOutcome::Rejected
        | TransportOutcome::Unknown => TransportOutcome::Aborted,
    })
}

async fn cancel_input_connection<IO>(
    stream: &mut IO,
    next_sequence: &mut u32,
    command: &super::PlannedCommand,
    active_sequence: u32,
    ever_started: bool,
    has_remaining_chunks: bool,
) -> Result<TransportOutcome, TlsTransportError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let cancel_sequence = *next_sequence;
    if cancel_sequence == u32::MAX {
        return Err(diagnosed_error(
            TransportDiagnostic::CancelSendProtocol,
            TlsTransportError::Protocol("network sequence exhausted".to_owned()),
        ));
    }
    send_command(
        stream,
        cancel_sequence,
        command,
        keyferry_protocol::command_kind::CANCEL_INPUT_SEQUENCE_V1,
        &[],
        COMMAND_MAX_MS,
    )
    .await
    .map_err(|error| {
        cancellation_error(
            error,
            TransportDiagnostic::CancelSendTransport,
            TransportDiagnostic::CancelSendProtocol,
        )
    })?;
    *next_sequence += 1;
    let evidence = loop {
        let evidence = read_input_command_result(stream, active_sequence, command.command_id)
            .await
            .map_err(|error| {
                cancellation_error(
                    error,
                    TransportDiagnostic::CancelActiveResultTransport,
                    TransportDiagnostic::CancelActiveResultProtocol,
                )
            })?;
        match evidence.result {
            DeviceCommandResult::Accepted | DeviceCommandResult::Started => {}
            DeviceCommandResult::Emitted
            | DeviceCommandResult::Aborted
            | DeviceCommandResult::Rejected
            | DeviceCommandResult::Unknown => break evidence,
        }
    };
    if matches!(
        evidence.result,
        DeviceCommandResult::Emitted | DeviceCommandResult::Rejected
    ) {
        let late = read_input_command_result(stream, cancel_sequence, command.command_id)
            .await
            .map_err(|error| {
                cancellation_error(
                    error,
                    TransportDiagnostic::CancelLateResultTransport,
                    TransportDiagnostic::CancelLateResultProtocol,
                )
            })?;
        if late.result != DeviceCommandResult::Rejected {
            return Err(diagnosed_error(
                TransportDiagnostic::CancelLateResultProtocol,
                TlsTransportError::Protocol("late input cancellation was not rejected".to_owned()),
            ));
        }
    }
    if evidence.result == DeviceCommandResult::Unknown {
        send_input_release_all_and_wait(stream, next_sequence).await?;
        return Ok(TransportOutcome::Aborted);
    }
    Ok(match evidence.result {
        DeviceCommandResult::Emitted if !has_remaining_chunks => TransportOutcome::Emitted,
        DeviceCommandResult::Rejected if !ever_started => TransportOutcome::Rejected,
        DeviceCommandResult::Emitted
        | DeviceCommandResult::Aborted
        | DeviceCommandResult::Rejected => {
            if evidence.dual_neutral()
                || evidence.result == DeviceCommandResult::Rejected && !ever_started
            {
                TransportOutcome::Aborted
            } else {
                TransportOutcome::Unknown
            }
        }
        DeviceCommandResult::Accepted
        | DeviceCommandResult::Started
        | DeviceCommandResult::Unknown => TransportOutcome::Unknown,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeviceCommandResult {
    Accepted,
    Started,
    Emitted,
    Aborted,
    Rejected,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InputCommandEvidence {
    result: DeviceCommandResult,
    neutral_mask: u8,
    effect_flags: u8,
    reason: u16,
}

impl InputCommandEvidence {
    fn dual_neutral(self) -> bool {
        self.neutral_mask == DUAL_NEUTRAL_MASK
    }
}

async fn read_input_command_result<IO>(
    stream: &mut IO,
    sequence: u32,
    command_id: uuid::Uuid,
) -> Result<InputCommandEvidence, TlsTransportError>
where
    IO: AsyncRead + Unpin,
{
    let frame = read_frame(stream).await?;
    if frame.message_type != keyferry_protocol::message::INPUT_COMMAND_RESULT_V1
        || frame.sequence != sequence
        || frame.payload.len() != INPUT_COMMAND_RESULT_LEN
        || frame.payload[..16] != *command_id.as_bytes()
    {
        return Err(TlsTransportError::Protocol(
            "input result does not match the outstanding command".to_owned(),
        ));
    }
    let result = match frame.payload[16] {
        keyferry_protocol::result_code::ACCEPTED => DeviceCommandResult::Accepted,
        keyferry_protocol::result_code::STARTED => DeviceCommandResult::Started,
        keyferry_protocol::result_code::EMITTED => DeviceCommandResult::Emitted,
        keyferry_protocol::result_code::ABORTED => DeviceCommandResult::Aborted,
        keyferry_protocol::result_code::REJECTED => DeviceCommandResult::Rejected,
        keyferry_protocol::result_code::UNKNOWN => DeviceCommandResult::Unknown,
        _ => {
            return Err(TlsTransportError::Protocol(
                "input result has an unknown result code".to_owned(),
            ))
        }
    };
    let evidence = InputCommandEvidence {
        result,
        neutral_mask: frame.payload[17],
        effect_flags: frame.payload[18],
        reason: u16::from_le_bytes([frame.payload[19], frame.payload[20]]),
    };
    if !valid_input_evidence(evidence) {
        return Err(TlsTransportError::Protocol(
            "input result evidence is internally inconsistent".to_owned(),
        ));
    }
    Ok(evidence)
}

fn valid_input_evidence(evidence: InputCommandEvidence) -> bool {
    if evidence.neutral_mask & !DUAL_NEUTRAL_MASK != 0
        || evidence.effect_flags & !INPUT_EFFECT_OCCURRED != 0
        || !known_input_reason(evidence.reason)
    {
        return false;
    }
    let effect = evidence.effect_flags & INPUT_EFFECT_OCCURRED != 0;
    let dual = evidence.dual_neutral();
    let reason = evidence.reason != 0;
    match evidence.result {
        DeviceCommandResult::Accepted => !effect && evidence.neutral_mask == 0 && !reason,
        DeviceCommandResult::Started => effect && evidence.neutral_mask == 0 && !reason,
        DeviceCommandResult::Emitted => dual && !reason,
        DeviceCommandResult::Aborted => dual && reason,
        DeviceCommandResult::Rejected => !effect && evidence.neutral_mask == 0 && reason,
        DeviceCommandResult::Unknown => !dual && reason,
    }
}

fn known_input_reason(reason: u16) -> bool {
    reason == 0
        || matches!(
            reason,
            keyferry_protocol::error_code::MALFORMED
                | keyferry_protocol::error_code::UNSUPPORTED_VERSION
                | keyferry_protocol::error_code::UNKNOWN_CRITICAL_FIELD
                | keyferry_protocol::error_code::NOT_AUTHENTICATED
                | keyferry_protocol::error_code::NOT_ARMED
                | keyferry_protocol::error_code::EXPIRED
                | keyferry_protocol::error_code::DUPLICATE
                | keyferry_protocol::error_code::BUSY
                | keyferry_protocol::error_code::INVALID_MODE
                | keyferry_protocol::error_code::USB_UNAVAILABLE
                | keyferry_protocol::error_code::LEGACY_UART_FAULT_RESERVED
                | keyferry_protocol::error_code::CAPABILITY_REQUIRED
                | keyferry_protocol::error_code::LIMIT_EXCEEDED
                | keyferry_protocol::error_code::NEUTRAL_UNCONFIRMED
                | keyferry_protocol::error_code::REPLAY_WINDOW_FULL
                | keyferry_protocol::error_code::CANCELLED
                | keyferry_protocol::error_code::WATCHDOG
                | keyferry_protocol::error_code::INTERNAL
        )
}

async fn read_command_result<IO>(
    stream: &mut IO,
    sequence: u32,
    command_id: uuid::Uuid,
) -> Result<DeviceCommandResult, TlsTransportError>
where
    IO: AsyncRead + Unpin,
{
    let frame = read_frame(stream).await?;
    if frame.message_type != keyferry_protocol::message::COMMAND_RESULT
        || frame.sequence != sequence
        || frame.payload.len() != COMMAND_RESULT_LEN
        || frame.payload[..16] != *command_id.as_bytes()
    {
        return Err(TlsTransportError::Protocol(
            "command result does not match the outstanding command".to_owned(),
        ));
    }
    match frame.payload[16] {
        keyferry_protocol::result_code::ACCEPTED => Ok(DeviceCommandResult::Accepted),
        keyferry_protocol::result_code::STARTED => Ok(DeviceCommandResult::Started),
        keyferry_protocol::result_code::EMITTED => Ok(DeviceCommandResult::Emitted),
        keyferry_protocol::result_code::ABORTED => Ok(DeviceCommandResult::Aborted),
        keyferry_protocol::result_code::REJECTED => Ok(DeviceCommandResult::Rejected),
        keyferry_protocol::result_code::UNKNOWN => Ok(DeviceCommandResult::Unknown),
        _ => Err(TlsTransportError::Protocol(
            "command result has an unknown result code".to_owned(),
        )),
    }
}

fn invoke_handler(slot: &std::sync::Mutex<Option<Handler>>) {
    if let Some(handler) = slot.lock().expect("TLS handler lock").clone() {
        handler();
    }
}

fn random_array<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(bytes)
}

fn hex_id(bytes: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in bytes {
        use fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn read_fixed<const N: usize>(path: &Path) -> io::Result<[u8; N]> {
    let bytes = fs::read(path)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} has {} bytes, expected {N}", path.display(), bytes.len()),
        )
    })
}

fn write_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Issues owner-rooted singleton installations for multi-controller tests.

    use super::write_new_private;
    use keyferry_gateway::{
        device_gateway_name, installation_gateway_name, installation_id_for_spki,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, PublicKeyData, PKCS_ECDSA_P256_SHA256,
    };
    use std::{fs, path::Path};

    pub(crate) struct TestOwner {
        owner_id: [u8; 16],
        issuer: CertifiedIssuer<'static, KeyPair>,
    }

    impl TestOwner {
        pub(crate) fn new(owner_id: [u8; 16]) -> Self {
            let owner_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("owner key");
            let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
            parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            Self {
                owner_id,
                issuer: CertifiedIssuer::self_signed(parameters, owner_key).expect("owner CA"),
            }
        }

        /// Writes one singleton installation for `device_id` and returns its identity and SPKI.
        pub(crate) fn issue(
            &self,
            root: &Path,
            device_id: [u8; 16],
            route_proof_secret: [u8; 32],
        ) -> ([u8; 16], Vec<u8>) {
            fs::create_dir_all(root).expect("create installation root");
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("installation key");
            let key_der = key.serialize_der();
            let spki = key.subject_public_key_info();
            let installation_id = installation_id_for_spki(&spki).expect("installation ID");
            let mut device_parameters =
                CertificateParams::new(vec![device_gateway_name(&device_id).unwrap()]).unwrap();
            device_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let device_certificate = device_parameters
                .signed_by(&key, &self.issuer)
                .expect("device-facing certificate");
            let desktop_name = installation_gateway_name(&installation_id).unwrap();
            let mut server_parameters = CertificateParams::new(vec![desktop_name.clone()]).unwrap();
            server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let server_certificate = server_parameters
                .signed_by(&key, &self.issuer)
                .expect("desktop server certificate");
            let mut client_parameters = CertificateParams::new(vec![desktop_name]).unwrap();
            client_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let client_certificate = client_parameters
                .signed_by(&key, &self.issuer)
                .expect("desktop client certificate");
            for (name, bytes) in [
                ("owner-id.bin", self.owner_id.as_slice()),
                ("device-id.bin", device_id.as_slice()),
                ("installation-id.bin", installation_id.as_slice()),
                ("installation-spki.der", spki.as_slice()),
                ("installation-key.der", key_der.as_slice()),
                ("device-server-cert.der", device_certificate.der().as_ref()),
                ("owner-ca.der", self.issuer.der().as_ref()),
                ("desktop-server-cert.der", server_certificate.der().as_ref()),
                ("desktop-client-cert.der", client_certificate.der().as_ref()),
                ("device-link-secret.bin", [0x33; 32].as_slice()),
                ("route-proof-secret.bin", route_proof_secret.as_slice()),
            ] {
                write_new_private(&root.join(name), bytes).expect("write installation artifact");
            }
            (installation_id, spki)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{ServerName, UnixTime},
        DigitallySignedStruct, Error, SignatureScheme,
    };
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{duplex, ReadBuf};
    use tokio_rustls::TlsConnector;

    fn credentials() -> TlsCredentials {
        TlsCredentials::new(
            HostIdentity::generate().expect("host identity"),
            [0x22; 16],
            [0x33; 32],
        )
    }

    async fn send_input_evidence<IO>(
        stream: &mut IO,
        sequence: u32,
        command_id: uuid::Uuid,
        result: u8,
        neutral_mask: u8,
        effect_flags: u8,
        reason: u16,
    ) where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let mut payload = command_id.as_bytes().to_vec();
        payload.push(result);
        payload.push(neutral_mask);
        payload.push(effect_flags);
        payload.extend_from_slice(&reason.to_le_bytes());
        send_frame(
            stream,
            Frame::v1(
                keyferry_protocol::message::INPUT_COMMAND_RESULT_V1,
                sequence,
                payload,
            ),
        )
        .await
        .expect("send input evidence");
    }

    fn mixed_input_command(command_id: uuid::Uuid) -> super::PlannedCommand {
        let request = keyferry_layouts::InputSequenceV1 {
            schema: keyferry_layouts::INPUT_SEQUENCE_SCHEMA_V1.to_owned(),
            command_id: command_id.to_string(),
            keyboard_profile: Some("windows-us".to_owned()),
            arm: keyferry_layouts::InputArmPolicy::CommandScoped,
            start_within_ms: 5_000,
            keyboard_timing: None,
            actions: vec![
                keyferry_layouts::InputAction::MoveRelative {
                    dx_counts: 240,
                    dy_counts: -40,
                },
                keyferry_layouts::InputAction::Click {
                    button: keyferry_layouts::ClickButton::Button1,
                    hold_ms: None,
                    release_gap_ms: None,
                },
                keyferry_layouts::InputAction::Tap {
                    key: "ENTER".to_owned(),
                    timing: None,
                },
            ],
        };
        let input = keyferry_layouts::compile_input_sequence(&request).expect("compile input");
        super::PlannedCommand {
            command_id,
            chunks: Vec::new(),
            action_count: input.effectful_gestures,
            char_count: input.text_characters,
            profile: "windows-us".to_owned(),
            expires_at: std::time::Instant::now() + Duration::from_secs(5),
            arm_before_first: true,
            input: Some(input),
        }
    }

    async fn connect_and_respond(
        address: SocketAddr,
        credentials: &TlsCredentials,
        link_secret: &[u8; 32],
    ) -> (tokio_rustls::client::TlsStream<TcpStream>, Frame) {
        let stream = TcpStream::connect(address).await.expect("connect device");
        respond_on(stream, credentials, link_secret).await
    }

    async fn respond_on<IO>(
        stream: IO,
        credentials: &TlsCredentials,
        link_secret: &[u8; 32],
    ) -> (tokio_rustls::client::TlsStream<IO>, Frame)
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        respond_on_mode(stream, credentials, link_secret, true).await
    }

    async fn respond_on_mode<IO>(
        stream: IO,
        credentials: &TlsCredentials,
        link_secret: &[u8; 32],
        send_identity: bool,
    ) -> (tokio_rustls::client::TlsStream<IO>, Frame)
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let connector = pinned_connector(credentials, credentials.identity().certificate_der());
        let mut stream = connector
            .connect(ServerName::try_from("keyferry.local").unwrap(), stream)
            .await
            .expect("complete TLS handshake");
        let challenge = read_frame(&mut stream).await.expect("read challenge");
        let (host_id, boot_nonce, challenge_bytes) = parse_challenge(&challenge);
        let device_nonce = [0x44; 32];
        let mut payload = Vec::with_capacity(AUTH_RESPONSE_LEN);
        payload.extend_from_slice(&credentials.device_id());
        payload.extend_from_slice(&device_nonce);
        payload.extend_from_slice(&auth_hmac(
            link_secret,
            &host_id,
            &credentials.device_id(),
            &boot_nonce,
            &challenge_bytes,
            &device_nonce,
            1,
            0,
        ));
        send_frame(
            &mut stream,
            Frame::v1(keyferry_protocol::message::AUTH_RESPONSE, 0, payload),
        )
        .await
        .expect("send authentication response");
        let ready = read_frame(&mut stream).await.expect("read session ready");
        assert_eq!(
            ready.message_type,
            keyferry_protocol::message::SESSION_READY
        );
        let capabilities =
            u32::from_le_bytes(ready.payload[18..22].try_into().expect("capabilities"));
        if send_identity && capabilities & keyferry_protocol::capability::FIRMWARE_IDENTITY_V1 != 0
        {
            assert_ne!(
                capabilities & keyferry_protocol::capability::USB_FILE_HANDOFF_V1,
                0
            );
            assert_ne!(
                capabilities & keyferry_protocol::capability::USB_FILE_SET_V2,
                0
            );
            send_frame(
                &mut stream,
                Frame::v1(
                    keyferry_protocol::message::CAPABILITIES,
                    1,
                    firmware_identity_payload(),
                ),
            )
            .await
            .expect("send firmware identity");
        }
        (stream, ready)
    }

    fn firmware_identity_payload() -> Vec<u8> {
        let mut payload = vec![0_u8; keyferry_protocol::firmware_identity::PAYLOAD_LEN];
        payload[0] = keyferry_protocol::firmware_identity::SCHEMA_V1;
        payload[1..5].copy_from_slice(
            &(keyferry_protocol::capability::KEYBOARD
                | keyferry_protocol::capability::FIRMWARE_IDENTITY_V1
                | keyferry_protocol::capability::MOUSE_RELATIVE_V1
                | keyferry_protocol::capability::BLE_HID_OUTPUT_V1
                | keyferry_protocol::capability::USB_FILE_SET_V2)
                .to_le_bytes(),
        );
        payload[5] = keyferry_protocol::VERSION_MAJOR;
        payload[6] = keyferry_protocol::VERSION_MINOR;
        payload[7] = keyferry_protocol::VERSION_MINOR;
        payload[8..13].copy_from_slice(b"0.1.0");
        payload[40..44].copy_from_slice(
            &keyferry_protocol::firmware_identity::BOARD_WAVESHARE_GEEK_V1_1_REFERENCE
                .to_le_bytes(),
        );
        payload[44] = keyferry_protocol::firmware_identity::DIGEST_ESP_APP_ELF_SHA256;
        for (index, byte) in payload[45..].iter_mut().enumerate() {
            *byte = u8::try_from(index + 1).expect("fixture byte");
        }
        payload
    }

    async fn connect_authenticated(
        address: SocketAddr,
        credentials: &TlsCredentials,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let (stream, _) = connect_and_respond(address, credentials, &credentials.link_secret).await;
        stream
    }

    #[tokio::test]
    async fn maintenance_blocks_new_candidates_until_explicitly_finished() {
        let transport = TlsTransport::new(credentials()).expect("TLS transport");
        transport
            .begin_maintenance()
            .await
            .expect("offline maintenance begins");
        assert!(transport.is_in_maintenance());
        let (candidate, _peer) = duplex(64);
        assert!(matches!(
            transport
                .accept_stream_on(candidate, TlsLinkPath::Bluetooth)
                .await,
            Err(TlsTransportError::Maintenance)
        ));
        transport.finish_maintenance();
        assert!(!transport.is_in_maintenance());
    }

    #[test]
    fn auth_vector_uses_the_documented_input_order() {
        let actual = auth_hmac(
            &[0x00; 32],
            &[0x01; 16],
            &[0x02; 16],
            &[0x03; 16],
            &[0x04; 32],
            &[0x05; 32],
            1,
            0,
        );
        assert_eq!(
            hex(&actual),
            "33434a1a8aacccc20b12fb8843f740cd4dfde60842aecf5003e93c42562846fe"
        );
    }

    #[tokio::test]
    async fn arm_control_frame_uses_exact_payload_and_correlated_ack() {
        let (mut host, mut device) = duplex(4096);
        let device = tokio::spawn(async move {
            let frame = read_frame(&mut device).await.expect("read ARM");
            assert_eq!(frame.message_type, keyferry_protocol::message::ARM);
            assert_eq!(frame.sequence, 2);
            assert_eq!(
                frame.payload,
                vec![keyferry_protocol::arm_policy::COMMAND_SCOPED, 0, 0, 0, 0]
            );
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::ACK,
                    frame.sequence,
                    vec![keyferry_protocol::message::ARM, 0, 0],
                ),
            )
            .await
            .expect("send ARM ACK");
        });
        let mut next_sequence = 2;
        let payload = [keyferry_protocol::arm_policy::COMMAND_SCOPED, 0, 0, 0, 0];
        send_control_request(
            &mut host,
            &mut next_sequence,
            keyferry_protocol::message::ARM,
            &payload,
        )
        .await
        .expect("ARM accepted");
        device.await.expect("device task");
        assert_eq!(next_sequence, 3);
    }

    #[tokio::test]
    async fn output_mode_get_and_set_use_strict_correlated_status() {
        let (mut host, mut device) = duplex(4096);
        let device = tokio::spawn(async move {
            let get = read_frame(&mut device).await.expect("read GET_OUTPUT_MODE");
            assert_eq!(
                get.message_type,
                keyferry_protocol::message::GET_OUTPUT_MODE
            );
            assert_eq!(get.sequence, 7);
            assert!(get.payload.is_empty());
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::OUTPUT_MODE_STATUS,
                    get.sequence,
                    vec![
                        keyferry_protocol::output_mode::USB_HID,
                        keyferry_protocol::output_mode::USB_HID,
                    ],
                ),
            )
            .await
            .expect("send output-mode status");

            let set = read_frame(&mut device).await.expect("read SET_OUTPUT_MODE");
            assert_eq!(
                set.message_type,
                keyferry_protocol::message::SET_OUTPUT_MODE
            );
            assert_eq!(set.sequence, 8);
            assert_eq!(set.payload, vec![keyferry_protocol::output_mode::BLE_HID]);
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::OUTPUT_MODE_STATUS,
                    set.sequence,
                    vec![
                        keyferry_protocol::output_mode::USB_HID,
                        keyferry_protocol::output_mode::BLE_HID,
                    ],
                ),
            )
            .await
            .expect("send retained output-mode status");
        });
        let mut next_sequence = 7;
        assert_eq!(
            send_output_mode_request(&mut host, &mut next_sequence, None)
                .await
                .expect("get output mode"),
            TransportOutputModeStatus {
                active: OutputMode::UsbHid,
                stored: OutputMode::UsbHid,
            }
        );
        assert_eq!(
            send_output_mode_request(&mut host, &mut next_sequence, Some(OutputMode::BleHid))
                .await
                .expect("set output mode"),
            TransportOutputModeStatus {
                active: OutputMode::UsbHid,
                stored: OutputMode::BleHid,
            }
        );
        device.await.expect("device task");
        assert_eq!(next_sequence, 9);
    }

    #[tokio::test]
    async fn display_orientation_get_and_set_use_strict_correlated_status() {
        let (mut host, mut device) = duplex(4096);
        let device = tokio::spawn(async move {
            let get = read_frame(&mut device)
                .await
                .expect("read GET_DISPLAY_ORIENTATION");
            assert_eq!(
                get.message_type,
                keyferry_protocol::message::GET_DISPLAY_ORIENTATION
            );
            assert_eq!(get.sequence, 11);
            assert!(get.payload.is_empty());
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::DISPLAY_ORIENTATION_STATUS,
                    get.sequence,
                    vec![
                        keyferry_protocol::display_orientation::NORMAL,
                        keyferry_protocol::display_orientation::NORMAL,
                    ],
                ),
            )
            .await
            .expect("send display-orientation status");

            let set = read_frame(&mut device)
                .await
                .expect("read SET_DISPLAY_ORIENTATION");
            assert_eq!(
                set.message_type,
                keyferry_protocol::message::SET_DISPLAY_ORIENTATION
            );
            assert_eq!(set.sequence, 12);
            assert_eq!(
                set.payload,
                vec![keyferry_protocol::display_orientation::ROTATED_180]
            );
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::DISPLAY_ORIENTATION_STATUS,
                    set.sequence,
                    vec![
                        keyferry_protocol::display_orientation::NORMAL,
                        keyferry_protocol::display_orientation::ROTATED_180,
                    ],
                ),
            )
            .await
            .expect("send retained display-orientation status");
        });
        let mut next_sequence = 11;
        assert_eq!(
            send_display_orientation_request(&mut host, &mut next_sequence, None)
                .await
                .expect("get display orientation"),
            TransportDisplayOrientationStatus {
                active: DisplayOrientation::Normal,
                stored: DisplayOrientation::Normal,
            }
        );
        assert_eq!(
            send_display_orientation_request(
                &mut host,
                &mut next_sequence,
                Some(DisplayOrientation::Rotated180),
            )
            .await
            .expect("set display orientation"),
            TransportDisplayOrientationStatus {
                active: DisplayOrientation::Normal,
                stored: DisplayOrientation::Rotated180,
            }
        );
        device.await.expect("device task");
        assert_eq!(next_sequence, 13);
    }

    #[tokio::test]
    async fn screen_power_is_correlated_and_rejects_malformed_status() {
        let (mut host, mut device) = duplex(4096);
        let device = tokio::spawn(async move {
            let get = read_frame(&mut device).await.expect("screen-power GET");
            assert_eq!(
                get.message_type,
                keyferry_protocol::message::GET_SCREEN_POWER
            );
            assert!(get.payload.is_empty());
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::SCREEN_POWER_STATUS,
                    get.sequence,
                    vec![
                        keyferry_protocol::screen_power::ON,
                        keyferry_protocol::screen_power::ON,
                        1,
                    ],
                ),
            )
            .await
            .expect("screen-power status");
            let set = read_frame(&mut device).await.expect("screen-power SET");
            assert_eq!(
                set.message_type,
                keyferry_protocol::message::SET_SCREEN_POWER
            );
            assert_eq!(set.payload, vec![keyferry_protocol::screen_power::OFF]);
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::SCREEN_POWER_STATUS,
                    set.sequence,
                    vec![
                        keyferry_protocol::screen_power::ON,
                        keyferry_protocol::screen_power::OFF,
                        1,
                    ],
                ),
            )
            .await
            .expect("screen-power pending status");
        });
        let mut sequence = 17;
        assert_eq!(
            send_screen_power_request(&mut host, &mut sequence, None)
                .await
                .unwrap(),
            TransportScreenPowerStatus {
                active: ScreenPower::On,
                stored: ScreenPower::On,
                available: true
            }
        );
        assert_eq!(
            send_screen_power_request(&mut host, &mut sequence, Some(ScreenPower::Off))
                .await
                .unwrap(),
            TransportScreenPowerStatus {
                active: ScreenPower::On,
                stored: ScreenPower::Off,
                available: true
            }
        );
        device.await.unwrap();
        for (offset, payload) in [
            (0, vec![1, 2]),
            (0, vec![0, 2, 1]),
            (0, vec![1, 0, 1]),
            (0, vec![1, 2, 2]),
            (1, vec![1, 2, 1]),
        ] {
            let (mut host, mut device) = duplex(4096);
            let task = tokio::spawn(async move {
                let request = read_frame(&mut device).await.unwrap();
                send_frame(
                    &mut device,
                    Frame::v1(
                        keyferry_protocol::message::SCREEN_POWER_STATUS,
                        request.sequence + offset,
                        payload,
                    ),
                )
                .await
                .unwrap();
            });
            let mut sequence = 5;
            assert!(matches!(
                send_screen_power_request(&mut host, &mut sequence, Some(ScreenPower::Off)).await,
                Err(TlsTransportError::Protocol(_))
            ));
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn output_mode_rejects_invalid_or_mismatched_status() {
        for payload in [
            vec![keyferry_protocol::output_mode::USB_HID],
            vec![0xff, keyferry_protocol::output_mode::USB_HID],
            vec![
                keyferry_protocol::output_mode::USB_HID,
                keyferry_protocol::output_mode::USB_HID,
            ],
        ] {
            let (mut host, mut device) = duplex(4096);
            let device = tokio::spawn(async move {
                let request = read_frame(&mut device)
                    .await
                    .expect("read output-mode request");
                send_frame(
                    &mut device,
                    Frame::v1(
                        keyferry_protocol::message::OUTPUT_MODE_STATUS,
                        request.sequence,
                        payload,
                    ),
                )
                .await
                .expect("send invalid output-mode status");
            });
            let mut next_sequence = 4;
            assert!(matches!(
                send_output_mode_request(&mut host, &mut next_sequence, Some(OutputMode::BleHid),)
                    .await,
                Err(TlsTransportError::Protocol(_))
            ));
            device.await.expect("device task");
        }
    }

    #[tokio::test]
    async fn bluetooth_bond_reset_uses_strict_correlated_status() {
        let (mut host, mut device) = duplex(4096);
        let device = tokio::spawn(async move {
            let request = read_frame(&mut device)
                .await
                .expect("read Bluetooth bond-reset request");
            assert_eq!(
                request.message_type,
                keyferry_protocol::message::RESET_BLE_HID_BOND
            );
            assert_eq!(request.sequence, 11);
            assert!(request.payload.is_empty());
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::BLE_HID_BOND_STATUS,
                    request.sequence,
                    vec![1, 1],
                ),
            )
            .await
            .expect("send Bluetooth bond-reset status");
        });
        let mut next_sequence = 11;
        assert_eq!(
            send_ble_hid_bond_reset_request(&mut host, &mut next_sequence)
                .await
                .expect("reset bond"),
            (true, true)
        );
        device.await.expect("device task");
        assert_eq!(next_sequence, 12);
    }

    #[tokio::test]
    async fn bluetooth_bond_reset_rejects_failure_and_malformed_status() {
        for payload in [vec![2, 0], vec![1], vec![1, 2], vec![3, 1], vec![0, 0]] {
            let (mut host, mut device) = duplex(4096);
            let device = tokio::spawn(async move {
                let request = read_frame(&mut device)
                    .await
                    .expect("read Bluetooth bond-reset request");
                send_frame(
                    &mut device,
                    Frame::v1(
                        keyferry_protocol::message::BLE_HID_BOND_STATUS,
                        request.sequence,
                        payload,
                    ),
                )
                .await
                .expect("send invalid Bluetooth bond-reset status");
            });
            let mut next_sequence = 4;
            assert!(
                send_ble_hid_bond_reset_request(&mut host, &mut next_sequence)
                    .await
                    .is_err()
            );
            device.await.expect("device task");
        }
    }

    #[tokio::test]
    async fn mixed_input_uses_new_kind_and_requires_dual_neutral_evidence() {
        let (mut host, mut device) = duplex(4096);
        let command_id = uuid::Uuid::now_v7();
        let command = mixed_input_command(command_id);
        let expected_body = command.input.as_ref().unwrap().chunks[0].body.clone();
        let device = tokio::spawn(async move {
            let arm = read_frame(&mut device).await.expect("read input ARM");
            assert_eq!(arm.message_type, keyferry_protocol::message::ARM);
            assert_eq!(arm.sequence, 2);
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::ACK,
                    arm.sequence,
                    vec![keyferry_protocol::message::ARM, 0, 0],
                ),
            )
            .await
            .expect("send input ARM ACK");

            let request = read_frame(&mut device).await.expect("read input command");
            assert_eq!(request.message_type, keyferry_protocol::message::COMMAND);
            assert_eq!(request.sequence, 3);
            assert_eq!(
                request.payload[52],
                keyferry_protocol::command_kind::EXECUTE_INPUT_CHUNK_V1
            );
            let body_len = u16::from_le_bytes([request.payload[53], request.payload[54]]) as usize;
            assert_eq!(body_len, expected_body.len());
            assert_eq!(&request.payload[55..], expected_body.as_slice());
            send_input_evidence(
                &mut device,
                3,
                command_id,
                keyferry_protocol::result_code::ACCEPTED,
                0,
                0,
                0,
            )
            .await;
            send_input_evidence(
                &mut device,
                3,
                command_id,
                keyferry_protocol::result_code::STARTED,
                0,
                INPUT_EFFECT_OCCURRED,
                0,
            )
            .await;
            send_input_evidence(
                &mut device,
                3,
                command_id,
                keyferry_protocol::result_code::EMITTED,
                DUAL_NEUTRAL_MASK,
                INPUT_EFFECT_OCCURRED,
                0,
            )
            .await;
        });
        let progress = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = Arc::clone(&progress);
        let progress_handler: ProgressHandler = Arc::new(move |event| {
            observed.lock().unwrap().push(event);
        });
        let mut next_sequence = 2;
        assert_eq!(
            execute_connection(
                &mut host,
                &mut next_sequence,
                &command,
                Cancellation::new(),
                &progress_handler,
            )
            .await
            .expect("execute mixed input"),
            TransportOutcome::Emitted
        );
        device.await.expect("device task");
        assert_eq!(next_sequence, 4);
        assert_eq!(
            *progress.lock().unwrap(),
            vec![TransportProgress::Accepted, TransportProgress::Started]
        );
    }

    #[tokio::test]
    async fn legacy_result_cannot_satisfy_input_command() {
        let (mut host, mut device) = duplex(4096);
        let command_id = uuid::Uuid::now_v7();
        let device = tokio::spawn(async move {
            let mut payload = command_id.as_bytes().to_vec();
            payload.push(keyferry_protocol::result_code::EMITTED);
            send_frame(
                &mut device,
                Frame::v1(keyferry_protocol::message::COMMAND_RESULT, 9, payload),
            )
            .await
            .expect("send legacy result");
        });
        assert!(matches!(
            read_input_command_result(&mut host, 9, command_id).await,
            Err(TlsTransportError::Protocol(_))
        ));
        device.await.expect("device task");
    }

    #[tokio::test]
    async fn control_error_is_a_device_rejection_without_ack_confusion() {
        let (mut host, mut device) = duplex(4096);
        let device = tokio::spawn(async move {
            let frame = read_frame(&mut device).await.expect("read DISARM");
            assert_eq!(frame.message_type, keyferry_protocol::message::DISARM);
            assert!(frame.payload.is_empty());
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::ERROR,
                    frame.sequence,
                    Vec::new(),
                ),
            )
            .await
            .expect("send ERROR");
        });
        let mut next_sequence = 7;
        assert!(matches!(
            send_control_request(
                &mut host,
                &mut next_sequence,
                keyferry_protocol::message::DISARM,
                &[],
            )
            .await,
            Err(TlsTransportError::DeviceRejected)
        ));
        device.await.expect("device task");
        assert_eq!(next_sequence, 8);
    }

    #[tokio::test]
    async fn control_ack_must_match_sequence_type_and_status() {
        for ack in [
            Frame::v1(
                keyferry_protocol::message::ACK,
                10,
                vec![keyferry_protocol::message::LEASE_RENEW, 0, 0],
            ),
            Frame::v1(
                keyferry_protocol::message::ACK,
                9,
                vec![keyferry_protocol::message::DISARM, 0, 0],
            ),
            Frame::v1(
                keyferry_protocol::message::ACK,
                9,
                vec![keyferry_protocol::message::LEASE_RENEW, 1, 0],
            ),
        ] {
            let (mut host, mut device) = duplex(4096);
            let device = tokio::spawn(async move {
                let _ = read_frame(&mut device).await.expect("read LEASE_RENEW");
                send_frame(&mut device, ack)
                    .await
                    .expect("send malformed ACK");
            });
            let mut next_sequence = 9;
            assert!(matches!(
                send_control_request(
                    &mut host,
                    &mut next_sequence,
                    keyferry_protocol::message::LEASE_RENEW,
                    &1_000_u32.to_le_bytes(),
                )
                .await,
                Err(TlsTransportError::Protocol(_)) | Err(TlsTransportError::DeviceRejected)
            ));
            device.await.expect("device task");
        }
    }

    #[tokio::test]
    async fn endpoint_command_results_are_the_progress_authority() {
        let (mut host, mut device) = duplex(4096);
        let command_id = uuid::Uuid::now_v7();
        let command = super::PlannedCommand {
            command_id,
            chunks: vec![crate::PlannedChunk {
                steps: vec![
                    ReportStep::Report(keyferry_layouts::KeyboardReport::single(0, 4)),
                    ReportStep::Report(keyferry_layouts::KeyboardReport::RELEASED),
                ],
                expected_ms: 10,
            }],
            action_count: 2,
            char_count: 1,
            profile: "windows-us".to_owned(),
            expires_at: std::time::Instant::now() + Duration::from_secs(1),
            arm_before_first: false,
            input: None,
        };
        let device = tokio::spawn(async move {
            let request = read_frame(&mut device).await.expect("read COMMAND");
            assert_eq!(request.message_type, keyferry_protocol::message::COMMAND);
            for result in [
                keyferry_protocol::result_code::ACCEPTED,
                keyferry_protocol::result_code::STARTED,
                keyferry_protocol::result_code::EMITTED,
            ] {
                let mut payload = command_id.as_bytes().to_vec();
                payload.push(result);
                send_frame(
                    &mut device,
                    Frame::v1(
                        keyferry_protocol::message::COMMAND_RESULT,
                        request.sequence,
                        payload,
                    ),
                )
                .await
                .expect("send COMMAND_RESULT");
            }
        });
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed_for_progress = observed.clone();
        let progress: ProgressHandler = Arc::new(move |event| {
            observed_for_progress.lock().unwrap().push(event);
        });
        let mut next_sequence = 2;
        assert_eq!(
            execute_connection(
                &mut host,
                &mut next_sequence,
                &command,
                Cancellation::new(),
                &progress,
            )
            .await
            .expect("execute"),
            TransportOutcome::Emitted
        );
        device.await.expect("device task");
        assert_eq!(
            *observed.lock().unwrap(),
            vec![TransportProgress::Accepted, TransportProgress::Started]
        );
    }

    #[tokio::test]
    async fn command_scoped_execute_places_arm_immediately_before_first_command() {
        let (mut host, mut device) = duplex(4096);
        let command_id = uuid::Uuid::now_v7();
        let command = super::PlannedCommand {
            command_id,
            chunks: vec![crate::PlannedChunk {
                steps: vec![
                    ReportStep::Report(keyferry_layouts::KeyboardReport::single(0x08, 0)),
                    ReportStep::Report(keyferry_layouts::KeyboardReport::RELEASED),
                ],
                expected_ms: 10,
            }],
            action_count: 2,
            char_count: 0,
            profile: "windows-us".to_owned(),
            expires_at: std::time::Instant::now() + Duration::from_secs(1),
            arm_before_first: true,
            input: None,
        };
        let device = tokio::spawn(async move {
            let arm = read_frame(&mut device).await.expect("read atomic ARM");
            assert_eq!(arm.message_type, keyferry_protocol::message::ARM);
            assert_eq!(arm.sequence, 2);
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::ACK,
                    arm.sequence,
                    vec![keyferry_protocol::message::ARM, 0, 0],
                ),
            )
            .await
            .expect("acknowledge ARM");

            let request = read_frame(&mut device).await.expect("read first COMMAND");
            assert_eq!(request.message_type, keyferry_protocol::message::COMMAND);
            assert_eq!(request.sequence, 3);
            for result in [
                keyferry_protocol::result_code::ACCEPTED,
                keyferry_protocol::result_code::STARTED,
                keyferry_protocol::result_code::EMITTED,
            ] {
                let mut payload = command_id.as_bytes().to_vec();
                payload.push(result);
                send_frame(
                    &mut device,
                    Frame::v1(
                        keyferry_protocol::message::COMMAND_RESULT,
                        request.sequence,
                        payload,
                    ),
                )
                .await
                .unwrap();
            }
        });
        let progress: ProgressHandler = Arc::new(|_| {});
        let mut next_sequence = 2;
        assert_eq!(
            execute_connection(
                &mut host,
                &mut next_sequence,
                &command,
                Cancellation::new(),
                &progress,
            )
            .await
            .expect("execute"),
            TransportOutcome::Emitted
        );
        device.await.expect("device task");
        assert_eq!(next_sequence, 4);
    }

    #[tokio::test]
    async fn release_all_waits_for_device_completion() {
        let (mut host, mut device) = duplex(4096);
        let device = tokio::spawn(async move {
            let request = read_frame(&mut device).await.expect("read RELEASE_ALL");
            let command_id = uuid::Uuid::from_slice(&request.payload[..16]).unwrap();
            for result in [
                keyferry_protocol::result_code::ACCEPTED,
                keyferry_protocol::result_code::EMITTED,
            ] {
                let mut payload = command_id.as_bytes().to_vec();
                payload.push(result);
                send_frame(
                    &mut device,
                    Frame::v1(
                        keyferry_protocol::message::COMMAND_RESULT,
                        request.sequence,
                        payload,
                    ),
                )
                .await
                .unwrap();
            }
        });
        let mut next_sequence = 7;
        send_release_all_and_wait(&mut host, &mut next_sequence)
            .await
            .expect("release-all completion");
        device.await.unwrap();
        assert_eq!(next_sequence, 8);
    }

    #[tokio::test]
    async fn release_all_transport_diagnostic_identifies_missing_result_boundary() {
        for (send_accepted, expected) in [
            (false, TransportDiagnostic::CancelReleaseAcceptedTransport),
            (true, TransportDiagnostic::CancelReleaseEmittedTransport),
        ] {
            let (mut host, mut device) = duplex(4096);
            let device = tokio::spawn(async move {
                let request = read_frame(&mut device).await.expect("read RELEASE_ALL");
                if send_accepted {
                    let command_id = uuid::Uuid::from_slice(&request.payload[..16]).unwrap();
                    let mut payload = command_id.as_bytes().to_vec();
                    payload.push(keyferry_protocol::result_code::ACCEPTED);
                    send_frame(
                        &mut device,
                        Frame::v1(
                            keyferry_protocol::message::COMMAND_RESULT,
                            request.sequence,
                            payload,
                        ),
                    )
                    .await
                    .unwrap();
                }
            });
            let mut next_sequence = 7;
            let error = send_release_all_and_wait(&mut host, &mut next_sequence)
                .await
                .unwrap_err();
            assert_eq!(error.diagnostic(), Some(expected));
            device.await.unwrap();
        }
    }

    #[tokio::test]
    async fn multi_chunk_execution_rearms_each_later_chunk() {
        let (mut host, mut device) = duplex(4096);
        let command_id = uuid::Uuid::now_v7();
        let chunk = crate::PlannedChunk {
            steps: vec![
                ReportStep::Report(keyferry_layouts::KeyboardReport::single(0, 4)),
                ReportStep::Report(keyferry_layouts::KeyboardReport::RELEASED),
            ],
            expected_ms: 10,
        };
        let command = super::PlannedCommand {
            command_id,
            chunks: vec![chunk.clone(), chunk],
            action_count: 4,
            char_count: 2,
            profile: "windows-us".to_owned(),
            expires_at: std::time::Instant::now() + Duration::from_secs(1),
            arm_before_first: false,
            input: None,
        };
        let device = tokio::spawn(async move {
            for expected_sequence in [2, 4] {
                let request = read_frame(&mut device).await.expect("read COMMAND");
                assert_eq!(request.sequence, expected_sequence);
                let valid_for_ms = u32::from_le_bytes(request.payload[16..20].try_into().unwrap());
                if expected_sequence == 2 {
                    assert!((1..=1000).contains(&valid_for_ms));
                } else {
                    assert_eq!(valid_for_ms, COMMAND_MAX_MS);
                }
                for result in [
                    keyferry_protocol::result_code::ACCEPTED,
                    keyferry_protocol::result_code::STARTED,
                    keyferry_protocol::result_code::EMITTED,
                ] {
                    let mut payload = command_id.as_bytes().to_vec();
                    payload.push(result);
                    send_frame(
                        &mut device,
                        Frame::v1(
                            keyferry_protocol::message::COMMAND_RESULT,
                            request.sequence,
                            payload,
                        ),
                    )
                    .await
                    .unwrap();
                }
                if expected_sequence == 2 {
                    let arm = read_frame(&mut device).await.expect("read second ARM");
                    assert_eq!(arm.message_type, keyferry_protocol::message::ARM);
                    assert_eq!(arm.sequence, 3);
                    send_frame(
                        &mut device,
                        Frame::v1(
                            keyferry_protocol::message::ACK,
                            arm.sequence,
                            vec![keyferry_protocol::message::ARM, 0, 0],
                        ),
                    )
                    .await
                    .unwrap();
                }
            }
        });
        let progress: ProgressHandler = Arc::new(|_| {});
        let mut next_sequence = 2;
        assert_eq!(
            execute_connection(
                &mut host,
                &mut next_sequence,
                &command,
                Cancellation::new(),
                &progress,
            )
            .await
            .unwrap(),
            TransportOutcome::Emitted
        );
        device.await.unwrap();
        assert_eq!(next_sequence, 5);
    }

    #[tokio::test]
    async fn wait_only_continuation_does_not_require_started() {
        let (mut host, mut device) = duplex(4096);
        let command_id = uuid::Uuid::now_v7();
        let first = crate::PlannedChunk {
            steps: vec![
                ReportStep::Report(keyferry_layouts::KeyboardReport::single(0, 4)),
                ReportStep::Report(keyferry_layouts::KeyboardReport::RELEASED),
            ],
            expected_ms: 10,
        };
        let wait_only = crate::PlannedChunk {
            steps: vec![
                ReportStep::Report(keyferry_layouts::KeyboardReport::RELEASED),
                ReportStep::WaitMs(100),
                ReportStep::Report(keyferry_layouts::KeyboardReport::RELEASED),
            ],
            expected_ms: 100,
        };
        let command = super::PlannedCommand {
            command_id,
            chunks: vec![first, wait_only],
            action_count: 5,
            char_count: 1,
            profile: "windows-us".to_owned(),
            expires_at: std::time::Instant::now() + Duration::from_secs(1),
            arm_before_first: false,
            input: None,
        };
        let device = tokio::spawn(async move {
            for (index, expected_sequence) in [2, 4].into_iter().enumerate() {
                let request = read_frame(&mut device).await.expect("read COMMAND");
                assert_eq!(request.sequence, expected_sequence);
                let results: &[u8] = if index == 0 {
                    &[
                        keyferry_protocol::result_code::ACCEPTED,
                        keyferry_protocol::result_code::STARTED,
                        keyferry_protocol::result_code::EMITTED,
                    ]
                } else {
                    &[
                        keyferry_protocol::result_code::ACCEPTED,
                        keyferry_protocol::result_code::EMITTED,
                    ]
                };
                for result in results {
                    let mut payload = command_id.as_bytes().to_vec();
                    payload.push(*result);
                    send_frame(
                        &mut device,
                        Frame::v1(
                            keyferry_protocol::message::COMMAND_RESULT,
                            request.sequence,
                            payload,
                        ),
                    )
                    .await
                    .unwrap();
                }
                if index == 0 {
                    let arm = read_frame(&mut device).await.expect("read second ARM");
                    assert_eq!(arm.message_type, keyferry_protocol::message::ARM);
                    assert_eq!(arm.sequence, 3);
                    send_frame(
                        &mut device,
                        Frame::v1(
                            keyferry_protocol::message::ACK,
                            arm.sequence,
                            vec![keyferry_protocol::message::ARM, 0, 0],
                        ),
                    )
                    .await
                    .unwrap();
                }
            }
        });
        let progress: ProgressHandler = Arc::new(|_| {});
        let mut next_sequence = 2;
        assert_eq!(
            execute_connection(
                &mut host,
                &mut next_sequence,
                &command,
                Cancellation::new(),
                &progress,
            )
            .await
            .unwrap(),
            TransportOutcome::Emitted
        );
        device.await.unwrap();
        assert_eq!(next_sequence, 5);
    }

    #[tokio::test]
    async fn later_chunk_rejection_cannot_erase_prior_start() {
        let (mut host, mut device) = duplex(4096);
        let command_id = uuid::Uuid::now_v7();
        let chunk = crate::PlannedChunk {
            steps: vec![
                ReportStep::Report(keyferry_layouts::KeyboardReport::single(0, 4)),
                ReportStep::Report(keyferry_layouts::KeyboardReport::RELEASED),
            ],
            expected_ms: 10,
        };
        let command = super::PlannedCommand {
            command_id,
            chunks: vec![chunk.clone(), chunk],
            action_count: 4,
            char_count: 2,
            profile: "windows-us".to_owned(),
            expires_at: std::time::Instant::now() + Duration::from_secs(1),
            arm_before_first: false,
            input: None,
        };
        let device = tokio::spawn(async move {
            let first = read_frame(&mut device).await.expect("read first COMMAND");
            for result in [
                keyferry_protocol::result_code::ACCEPTED,
                keyferry_protocol::result_code::STARTED,
                keyferry_protocol::result_code::EMITTED,
            ] {
                let mut payload = command_id.as_bytes().to_vec();
                payload.push(result);
                send_frame(
                    &mut device,
                    Frame::v1(
                        keyferry_protocol::message::COMMAND_RESULT,
                        first.sequence,
                        payload,
                    ),
                )
                .await
                .unwrap();
            }
            let arm = read_frame(&mut device).await.expect("read second ARM");
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::ACK,
                    arm.sequence,
                    vec![keyferry_protocol::message::ARM, 0, 0],
                ),
            )
            .await
            .unwrap();
            let second = read_frame(&mut device).await.expect("read second COMMAND");
            let mut rejected = command_id.as_bytes().to_vec();
            rejected.push(keyferry_protocol::result_code::REJECTED);
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::COMMAND_RESULT,
                    second.sequence,
                    rejected,
                ),
            )
            .await
            .unwrap();
        });
        let mut next_sequence = 2;
        let progress: ProgressHandler = Arc::new(|_| {});
        assert_eq!(
            execute_connection(
                &mut host,
                &mut next_sequence,
                &command,
                Cancellation::new(),
                &progress,
            )
            .await
            .unwrap(),
            TransportOutcome::Aborted
        );
        device.await.unwrap();
    }

    #[tokio::test]
    async fn rejection_after_start_without_terminal_zero_is_unknown() {
        let (mut host, mut device) = duplex(4096);
        let command_id = uuid::Uuid::now_v7();
        let chunk = crate::PlannedChunk {
            steps: vec![
                ReportStep::Report(keyferry_layouts::KeyboardReport::single(0, 4)),
                ReportStep::Report(keyferry_layouts::KeyboardReport::RELEASED),
            ],
            expected_ms: 10,
        };
        let command = super::PlannedCommand {
            command_id,
            chunks: vec![chunk],
            action_count: 2,
            char_count: 1,
            profile: "windows-us".to_owned(),
            expires_at: std::time::Instant::now() + Duration::from_secs(1),
            arm_before_first: false,
            input: None,
        };
        let device = tokio::spawn(async move {
            let request = read_frame(&mut device).await.expect("read COMMAND");
            for result in [
                keyferry_protocol::result_code::ACCEPTED,
                keyferry_protocol::result_code::STARTED,
                keyferry_protocol::result_code::REJECTED,
            ] {
                let mut payload = command_id.as_bytes().to_vec();
                payload.push(result);
                send_frame(
                    &mut device,
                    Frame::v1(
                        keyferry_protocol::message::COMMAND_RESULT,
                        request.sequence,
                        payload,
                    ),
                )
                .await
                .unwrap();
            }
        });
        let mut next_sequence = 2;
        let progress: ProgressHandler = Arc::new(|_| {});
        assert_eq!(
            execute_connection(
                &mut host,
                &mut next_sequence,
                &command,
                Cancellation::new(),
                &progress,
            )
            .await
            .unwrap(),
            TransportOutcome::Unknown
        );
        device.await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_accepts_endpoint_terminal_zero_without_redundant_release() {
        let (mut host, mut device) = duplex(4096);
        let command = empty_command(2);
        let command_id = command.command_id;
        let device = tokio::spawn(async move {
            let cancel = read_frame(&mut device).await.expect("read CANCEL");
            assert_eq!(cancel.sequence, 3);
            let mut aborted = command_id.as_bytes().to_vec();
            aborted.push(keyferry_protocol::result_code::ABORTED);
            send_frame(
                &mut device,
                Frame::v1(keyferry_protocol::message::COMMAND_RESULT, 2, aborted),
            )
            .await
            .unwrap();
        });
        let mut next_sequence = 3;
        assert_eq!(
            cancel_connection(&mut host, &mut next_sequence, &command, 2, true, true)
                .await
                .unwrap(),
            TransportOutcome::Aborted
        );
        device.await.unwrap();
        assert_eq!(next_sequence, 4);
    }

    #[tokio::test]
    async fn cancellation_at_chunk_completion_drains_rejection_and_aborts_remaining_chunks() {
        let (mut host, mut device) = duplex(4096);
        let command = empty_command(2);
        let command_id = command.command_id;
        let device = tokio::spawn(async move {
            let cancel = read_frame(&mut device).await.expect("read CANCEL");
            assert_eq!(cancel.sequence, 3);
            for (sequence, result) in [
                (2, keyferry_protocol::result_code::EMITTED),
                (3, keyferry_protocol::result_code::REJECTED),
            ] {
                let mut payload = command_id.as_bytes().to_vec();
                payload.push(result);
                send_frame(
                    &mut device,
                    Frame::v1(
                        keyferry_protocol::message::COMMAND_RESULT,
                        sequence,
                        payload,
                    ),
                )
                .await
                .unwrap();
            }
        });
        let mut next_sequence = 3;
        assert_eq!(
            cancel_connection(&mut host, &mut next_sequence, &command, 2, true, true)
                .await
                .unwrap(),
            TransportOutcome::Aborted
        );
        device.await.unwrap();
        assert_eq!(next_sequence, 4);
    }

    #[tokio::test]
    async fn input_cancellation_at_chunk_completion_drains_late_rejection() {
        let (mut host, mut device) = duplex(4096);
        let command = empty_command(2);
        let command_id = command.command_id;
        let device = tokio::spawn(async move {
            let cancel = read_frame(&mut device).await.expect("read input CANCEL");
            assert_eq!(cancel.sequence, 3);
            assert_eq!(
                cancel.payload[52],
                keyferry_protocol::command_kind::CANCEL_INPUT_SEQUENCE_V1
            );
            send_input_evidence(
                &mut device,
                2,
                command_id,
                keyferry_protocol::result_code::EMITTED,
                DUAL_NEUTRAL_MASK,
                INPUT_EFFECT_OCCURRED,
                0,
            )
            .await;
            send_input_evidence(
                &mut device,
                3,
                command_id,
                keyferry_protocol::result_code::REJECTED,
                0,
                0,
                keyferry_protocol::error_code::INVALID_MODE,
            )
            .await;
        });
        let mut next_sequence = 3;
        assert_eq!(
            cancel_input_connection(&mut host, &mut next_sequence, &command, 2, true, true)
                .await
                .unwrap(),
            TransportOutcome::Aborted
        );
        device.await.unwrap();
        assert_eq!(next_sequence, 4);
    }

    #[tokio::test]
    async fn cancellation_active_result_transport_failure_has_stable_diagnostic() {
        let (mut host, mut device) = duplex(4096);
        let command = empty_command(2);
        let device = tokio::spawn(async move {
            let cancel = read_frame(&mut device).await.expect("read CANCEL");
            assert_eq!(cancel.sequence, 3);
        });
        let mut next_sequence = 3;
        let error = cancel_connection(&mut host, &mut next_sequence, &command, 2, true, true)
            .await
            .unwrap_err();
        assert_eq!(
            error.diagnostic(),
            Some(TransportDiagnostic::CancelActiveResultTransport)
        );
        device.await.unwrap();
    }

    #[tokio::test]
    async fn input_cancellation_active_result_transport_failure_has_stable_diagnostic() {
        let (mut host, mut device) = duplex(4096);
        let command = empty_command(2);
        let device = tokio::spawn(async move {
            let cancel = read_frame(&mut device).await.expect("read input CANCEL");
            assert_eq!(cancel.sequence, 3);
            assert_eq!(
                cancel.payload[52],
                keyferry_protocol::command_kind::CANCEL_INPUT_SEQUENCE_V1
            );
        });
        let mut next_sequence = 3;
        let error = cancel_input_connection(&mut host, &mut next_sequence, &command, 2, true, true)
            .await
            .unwrap_err();
        assert_eq!(
            error.diagnostic(),
            Some(TransportDiagnostic::CancelActiveResultTransport)
        );
        device.await.unwrap();
    }

    #[tokio::test]
    async fn input_release_without_dual_neutral_has_stable_protocol_diagnostic() {
        let (mut host, mut device) = duplex(4096);
        let device = tokio::spawn(async move {
            let release = read_frame(&mut device).await.expect("read input release");
            let command_id = uuid::Uuid::from_slice(&release.payload[..16]).unwrap();
            send_input_evidence(
                &mut device,
                release.sequence,
                command_id,
                keyferry_protocol::result_code::ACCEPTED,
                0,
                0,
                0,
            )
            .await;
            send_input_evidence(
                &mut device,
                release.sequence,
                command_id,
                keyferry_protocol::result_code::EMITTED,
                0x01,
                0,
                0,
            )
            .await;
        });
        let mut next_sequence = 3;
        let error = send_input_release_all_and_wait(&mut host, &mut next_sequence)
            .await
            .unwrap_err();
        assert_eq!(
            error.diagnostic(),
            Some(TransportDiagnostic::CancelReleaseEmittedProtocol)
        );
        device.await.unwrap();
    }

    #[test]
    fn cancellation_diagnostic_distinguishes_protocol_failure() {
        let error = cancellation_error(
            TlsTransportError::Protocol("payload must not be exposed".to_owned()),
            TransportDiagnostic::CancelReleaseEmittedTransport,
            TransportDiagnostic::CancelReleaseEmittedProtocol,
        );
        assert_eq!(
            error.diagnostic(),
            Some(TransportDiagnostic::CancelReleaseEmittedProtocol)
        );
        assert!(!error.diagnostic().unwrap().code().contains("payload"));
    }

    #[tokio::test]
    async fn route_proof_request_is_sequence_and_controller_bound() {
        let (mut host, mut device) = duplex(4096);
        let controller_installation_id = [0x31; 16];
        let controller_nonce = [0x42; 32];
        let device_task = tokio::spawn(async move {
            let request = read_frame(&mut device).await.expect("route request");
            assert_eq!(
                request.message_type,
                keyferry_protocol::message::ROUTE_PROOF_REQUEST
            );
            assert_eq!(request.sequence, 2);
            assert_eq!(request.payload[..16], controller_installation_id);
            assert_eq!(request.payload[16..], controller_nonce);
            let input = keyferry_gateway::RouteProofInput {
                owner_id: [0x11; 16],
                device_id: [0x22; 16],
                epoch: 1,
                policy_sequence: 1,
                policy_hash: [0x23; 32],
                gateway_installation_id: [0x24; 16],
                controller_installation_id,
                controller_nonce,
                device_boot_nonce: [0x25; 16],
                endpoint_session_id: [0x26; 16],
                link_path: keyferry_gateway::GatewayLinkPath::Bluetooth,
                usb_ready: true,
            };
            let response = keyferry_gateway::encode_route_proof_response(&input, &[0x27; 32])
                .expect("route response");
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::ROUTE_PROOF_RESPONSE,
                    request.sequence,
                    response.to_vec(),
                ),
            )
            .await
            .unwrap();
        });
        let mut next_sequence = 2;
        let proof = send_route_proof_request(
            &mut host,
            &mut next_sequence,
            controller_installation_id,
            controller_nonce,
        )
        .await
        .unwrap();
        assert_eq!(
            proof.input.controller_installation_id,
            controller_installation_id
        );
        assert_eq!(proof.input.controller_nonce, controller_nonce);
        assert_eq!(proof.tag, [0x27; 32]);
        assert_eq!(next_sequence, 3);
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn file_request_uses_sequence_and_exact_status_shape() {
        use keyferry_protocol::file::{Error, Request, State, Status};
        let (mut host, mut device) = duplex(4096);
        let device_task = tokio::spawn(async move {
            let frame = read_frame(&mut device).await.expect("file request");
            assert_eq!(frame.message_type, keyferry_protocol::message::FILE_REQUEST);
            assert_eq!(frame.sequence, 7);
            assert_eq!(Request::decode(&frame.payload).unwrap(), Request::Status);
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::FILE_STATUS,
                    frame.sequence,
                    Status {
                        state: State::Empty,
                        error: Error::Ok,
                        size: 0,
                        received: 0,
                    }
                    .encode()
                    .to_vec(),
                ),
            )
            .await
            .unwrap();
        });
        let mut next_sequence = 7;
        let status = send_file_request(&mut host, &mut next_sequence, &Request::Status)
            .await
            .unwrap();
        assert_eq!(status.state, State::Empty);
        assert_eq!(next_sequence, 8);
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn gateway_handoff_start_is_exact_and_requires_a_correlated_operation() {
        let (mut host, mut device) = duplex(4096);
        let start = keyferry_protocol::gateway_handoff::Start {
            transaction_id: [0x11; 16],
            target_installation_id: [0x22; 16],
            readiness_nonce: [0x33; 16],
            proof_digest: [0x44; 32],
            target_ipv4: [192, 168, 30, 50],
            target_port: keyferry_protocol::roaming::DEVICE_TLS_PORT,
            target_valid_ms: keyferry_protocol::roaming::GATEWAY_HANDOFF_TARGET_VALID_MS as u32,
            recovery_ms: keyferry_protocol::roaming::GATEWAY_HANDOFF_RECOVERY_MS as u32,
        };
        let expected = start.clone();
        let device_task = tokio::spawn(async move {
            let request = read_frame(&mut device).await.expect("handoff START");
            assert_eq!(
                request.message_type,
                keyferry_protocol::message::GATEWAY_HANDOFF
            );
            assert_eq!(request.sequence, 9);
            assert_eq!(
                keyferry_protocol::gateway_handoff::decode_request(&request.payload).unwrap(),
                keyferry_protocol::gateway_handoff::Request::Start(expected.clone())
            );
            let status = keyferry_protocol::gateway_handoff::Status {
                reply_operation: keyferry_protocol::gateway_handoff_operation::START,
                status: keyferry_protocol::gateway_handoff_status::OK,
                transaction_id: expected.transaction_id,
                phase: keyferry_protocol::gateway_handoff_phase::TARGETING,
                reason: keyferry_protocol::gateway_handoff_reason::NONE,
                remaining_phase_ms: 6000,
                remaining_recovery_ms: 6000,
                target_installation_id: expected.target_installation_id,
                previous_installation_id: [0x55; 16],
                device_boot_nonce: [0x66; 16],
                current_endpoint_session: [0x77; 16],
            };
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::GATEWAY_HANDOFF_STATUS,
                    request.sequence,
                    keyferry_protocol::gateway_handoff::encode_status(&status).to_vec(),
                ),
            )
            .await
            .unwrap();
        });
        let mut next_sequence = 9;
        let status = send_gateway_handoff_request(
            &mut host,
            &mut next_sequence,
            &keyferry_protocol::gateway_handoff::Request::Start(start),
        )
        .await
        .unwrap();
        assert_eq!(
            status.phase,
            keyferry_protocol::gateway_handoff_phase::TARGETING
        );
        assert_eq!(next_sequence, 10);
        device_task.await.unwrap();

        let (mut host, mut device) = duplex(4096);
        let start = keyferry_protocol::gateway_handoff::Start {
            transaction_id: [0x11; 16],
            target_installation_id: [0x22; 16],
            readiness_nonce: [0x33; 16],
            proof_digest: [0x44; 32],
            target_ipv4: [192, 168, 30, 50],
            target_port: keyferry_protocol::roaming::DEVICE_TLS_PORT,
            target_valid_ms: keyferry_protocol::roaming::GATEWAY_HANDOFF_TARGET_VALID_MS as u32,
            recovery_ms: keyferry_protocol::roaming::GATEWAY_HANDOFF_RECOVERY_MS as u32,
        };
        let expected = start.clone();
        let device_task = tokio::spawn(async move {
            let request = read_frame(&mut device).await.unwrap();
            let mismatched = keyferry_protocol::gateway_handoff::Status {
                reply_operation: keyferry_protocol::gateway_handoff_operation::ACCEPT,
                status: keyferry_protocol::gateway_handoff_status::OK,
                transaction_id: expected.transaction_id,
                phase: keyferry_protocol::gateway_handoff_phase::TARGETING,
                reason: keyferry_protocol::gateway_handoff_reason::NONE,
                remaining_phase_ms: 6000,
                remaining_recovery_ms: 6000,
                target_installation_id: expected.target_installation_id,
                previous_installation_id: [0x55; 16],
                device_boot_nonce: [0x66; 16],
                current_endpoint_session: [0x77; 16],
            };
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::GATEWAY_HANDOFF_STATUS,
                    request.sequence,
                    keyferry_protocol::gateway_handoff::encode_status(&mismatched).to_vec(),
                ),
            )
            .await
            .unwrap();
        });
        let mut next_sequence = 3;
        assert!(matches!(
            send_gateway_handoff_request(
                &mut host,
                &mut next_sequence,
                &keyferry_protocol::gateway_handoff::Request::Start(start),
            )
            .await,
            Err(TlsTransportError::Protocol(_))
        ));
        device_task.await.unwrap();
    }

    #[test]
    fn file_secret_store_persists_host_identity_without_secret_debug_output() {
        let root = std::env::temp_dir().join(format!("keyferry-tls-{}", uuid::Uuid::now_v7()));
        let store = FileTlsSecretStore::new(&root);
        let first = store
            .load_or_create_host_identity()
            .expect("create identity");
        let second = store.load_or_create_host_identity().expect("load identity");
        assert_eq!(first, second);
        assert!(format!("{first:?}").contains("secret key elided"));
        fs::remove_dir_all(root).expect("remove test identity");
    }

    fn create_installation_store(root: &Path) -> ([u8; 16], [u8; 16], Vec<u8>) {
        let owner = test_support::TestOwner::new([0x11; 16]);
        let device_id = [0x22; 16];
        let (installation_id, spki) = owner.issue(root, device_id, [0x44; 32]);
        (device_id, installation_id, spki)
    }

    #[test]
    fn installation_secret_store_is_read_only_and_identity_bound() {
        let root = std::env::temp_dir().join(format!("keyferry-install-{}", uuid::Uuid::now_v7()));
        let (device_id, installation_id, _) = create_installation_store(&root);
        let before = fs::read_dir(&root).expect("list before").count();
        let store = InstallationTlsSecretStore::load(&root).expect("load issued installation");
        assert_eq!(store.device_id(), device_id);
        let identity = store.load_or_create_host_identity().expect("load identity");
        assert_eq!(identity.host_id(), installation_id);
        assert_eq!(store.load_link_secret(device_id).unwrap(), [0x33; 32]);
        assert!(store.load_link_secret([0x44; 16]).is_err());
        assert!(TlsTransport::from_secret_store(&store, device_id).is_ok());
        assert_eq!(fs::read_dir(&root).expect("list after").count(), before);
        fs::remove_dir_all(root).expect("remove installation root");
    }

    #[test]
    fn installation_secret_store_rejects_spki_identity_mismatch() {
        let root = std::env::temp_dir().join(format!("keyferry-install-{}", uuid::Uuid::now_v7()));
        let (_, mut installation_id, _) = create_installation_store(&root);
        installation_id[0] ^= 0xff;
        fs::write(root.join("installation-id.bin"), installation_id).expect("alter identity");
        assert!(InstallationTlsSecretStore::load(&root).is_err());
        fs::remove_dir_all(root).expect("remove installation root");
    }

    #[tokio::test]
    async fn installation_device_tls_requires_the_exact_device_sni() {
        let root = std::env::temp_dir().join(format!("keyferry-install-{}", uuid::Uuid::now_v7()));
        let (device_id, _, _) = create_installation_store(&root);
        let store = InstallationTlsSecretStore::load(&root).expect("load issued installation");
        let identity = store.load_or_create_host_identity().expect("identity");
        let credentials = TlsCredentials::new(identity.clone(), device_id, [0x33; 32]);
        let config = server_config_exact_sni(&identity, store.device_server_name())
            .expect("exact-SNI server config");

        let (server, client) = duplex(4096);
        let accept = TlsAcceptor::from(config.clone()).accept(server);
        let connect = pinned_connector(&credentials, identity.certificate_der()).connect(
            ServerName::try_from(store.device_server_name().to_owned()).unwrap(),
            client,
        );
        let (accepted, connected) = tokio::join!(accept, connect);
        assert!(accepted.is_ok());
        assert!(connected.is_ok());

        let (server, client) = duplex(4096);
        let accept = TlsAcceptor::from(config).accept(server);
        let connect = pinned_connector(&credentials, identity.certificate_der()).connect(
            ServerName::try_from("wrong.keyferry.invalid").unwrap(),
            client,
        );
        let (accepted, connected) = tokio::join!(accept, connect);
        assert!(accepted.is_err());
        assert!(connected.is_err());
        fs::remove_dir_all(root).expect("remove installation root");
    }

    fn owner_client_connector(
        trust_store: &InstallationTlsSecretStore,
        client_store: Option<&InstallationTlsSecretStore>,
    ) -> TlsConnector {
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites =
            vec![rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256];
        provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(trust_store.owner_ca_der().to_vec()))
            .expect("owner root");
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS 1.2")
            .with_root_certificates(roots);
        let mut config = if let Some(store) = client_store {
            let identity = store.desktop_client_identity().expect("client identity");
            builder
                .with_client_auth_cert(
                    vec![CertificateDer::from(identity.certificate_der().to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        identity.private_key_der().to_vec(),
                    )),
                )
                .expect("client certificate")
        } else {
            builder.with_no_client_auth()
        };
        config.resumption = rustls::client::Resumption::disabled();
        TlsConnector::from(Arc::new(config))
    }

    #[tokio::test]
    async fn desktop_listener_requires_owner_rooted_client_authentication() {
        let root = std::env::temp_dir().join(format!("keyferry-install-{}", uuid::Uuid::now_v7()));
        create_installation_store(&root);
        let store = InstallationTlsSecretStore::load(&root).expect("installation");
        let server_name = ServerName::try_from(store.desktop_server_name().to_owned()).unwrap();

        let (server, client) = duplex(4096);
        let accept = store.remote_tls_acceptor().unwrap().accept(server);
        let connect = store
            .remote_tls_connector()
            .expect("owner connector")
            .connect(server_name.clone(), client);
        let (accepted, connected) = tokio::join!(accept, connect);
        let accepted = accepted.expect("owner-authenticated server connection");
        connected.expect("owner-authenticated client connection");
        let peer = accepted
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .expect("peer certificate");
        assert_eq!(
            installation_id_from_peer_certificate(peer.as_ref()).unwrap(),
            store.installation_id()
        );

        let (server, client) = duplex(4096);
        let accept = store.remote_tls_acceptor().unwrap().accept(server);
        let connect = owner_client_connector(&store, None).connect(server_name, client);
        let (accepted, connected) = tokio::join!(accept, connect);
        assert!(accepted.is_err());
        assert!(connected.is_err());
        fs::remove_dir_all(root).expect("remove installation root");
    }

    #[tokio::test]
    async fn listener_rejects_unqualified_bind_addresses() {
        let credentials = credentials();
        let transport = TlsTransport::new(credentials).expect("TLS transport");
        assert!(matches!(
            TlsListener::bind("0.0.0.0:0".parse().unwrap(), transport).await,
            Err(TlsTransportError::InvalidConfiguration(_))
        ));
    }

    #[tokio::test]
    async fn transport_authenticates_a_non_tcp_byte_stream() {
        let credentials = credentials();
        let transport = TlsTransport::new(credentials.clone()).expect("TLS transport");
        let (server, client) = duplex(4096);
        let accepting_transport = transport.clone();
        let accept = tokio::spawn(async move {
            accepting_transport
                .accept_stream_on(server, TlsLinkPath::Bluetooth)
                .await
        });
        let link_secret = credentials.link_secret;
        let (mut client, ready) = respond_on(client, &credentials, &link_secret).await;
        accept.await.expect("accept task").expect("accept stream");
        assert!(transport.is_ready());
        assert!(transport.supports_file_set());
        let request_transport = transport.clone();
        let request = tokio::spawn(async move {
            request_transport
                .file_set_request(keyferry_protocol::file_set::Request::Status { index: 255 })
                .await
        });
        let frame = read_frame(&mut client).await.expect("file-set request");
        assert_eq!(
            frame.message_type,
            keyferry_protocol::message::FILE_SET_REQUEST
        );
        assert_eq!(frame.payload, vec![5, 255]);
        send_frame(
            &mut client,
            Frame::v1(
                keyferry_protocol::message::FILE_SET_STATUS,
                frame.sequence,
                vec![0; keyferry_protocol::file_set::STATUS_BYTES],
            ),
        )
        .await
        .expect("file-set status");
        let status = request.await.unwrap().unwrap();
        assert_eq!(status.state, keyferry_protocol::file_set::State::Empty);
        let mut session_id = [0_u8; 16];
        session_id.copy_from_slice(&ready.payload[..16]);
        assert_eq!(
            transport.session_snapshot(),
            Some(TlsSessionSnapshot {
                link_path: TlsLinkPath::Bluetooth,
                protocol_session_id: session_id,
                firmware_identity: Some(
                    keyferry_protocol::firmware_identity::decode_v1(&firmware_identity_payload(),)
                        .expect("fixture identity"),
                ),
            })
        );
        drop(client);
        time::timeout(Duration::from_secs(1), async {
            while transport.is_ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("transport observes stream loss");
        assert_eq!(transport.session_snapshot(), None);
    }

    #[tokio::test]
    async fn file_set_indexed_status_accepts_exact_entry_and_rejects_wrong_or_missing_entry() {
        for entry_index in [Some(0_u8), Some(1), None] {
            let (mut host, mut device) = duplex(4096);
            let device_task = tokio::spawn(async move {
                let request = read_frame(&mut device)
                    .await
                    .expect("file-set status request");
                assert_eq!(
                    request.message_type,
                    keyferry_protocol::message::FILE_SET_REQUEST
                );
                assert_eq!(request.payload, [5, 0]);
                let mut payload = vec![2, 0];
                payload.extend_from_slice(&7u32.to_le_bytes());
                payload.extend_from_slice(&7u32.to_le_bytes());
                payload.push(2);
                if let Some(index) = entry_index {
                    payload.extend_from_slice(&[index, 1, b'A']);
                    payload.extend_from_slice(&0u32.to_le_bytes());
                }
                send_frame(
                    &mut device,
                    Frame::v1(
                        keyferry_protocol::message::FILE_SET_STATUS,
                        request.sequence,
                        payload,
                    ),
                )
                .await
                .expect("file-set status response");
            });
            let mut sequence = 2;
            let result = send_file_set_request(
                &mut host,
                &mut sequence,
                &keyferry_protocol::file_set::Request::Status { index: 0 },
            )
            .await;
            if entry_index == Some(0) {
                assert_eq!(result.unwrap().entry.unwrap().index, 0);
            } else {
                assert!(matches!(result, Err(TlsTransportError::Protocol(_))));
            }
            assert_eq!(sequence, 3);
            device_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn legacy_firmware_gets_exactly_one_pre_command_reconnect() {
        let credentials = credentials();
        let transport = TlsTransport::new(credentials.clone()).expect("TLS transport");
        let listener = Arc::new(
            TlsListener::bind("127.0.0.1:0".parse().unwrap(), transport.clone())
                .await
                .expect("listener"),
        );
        let address = listener.local_addr().expect("listener address");

        let first_listener = Arc::clone(&listener);
        let first_accept = tokio::spawn(async move { first_listener.accept_one().await });
        let first_stream = TcpStream::connect(address).await.expect("first connect");
        let (first_device, first_ready) =
            respond_on_mode(first_stream, &credentials, &credentials.link_secret, false).await;
        let first_capabilities = u32::from_le_bytes(
            first_ready.payload[18..22]
                .try_into()
                .expect("capabilities"),
        );
        assert_ne!(
            first_capabilities & keyferry_protocol::capability::FIRMWARE_IDENTITY_V1,
            0
        );
        assert!(matches!(
            first_accept.await.expect("first accept task"),
            Err(TlsTransportError::FirmwareIdentityUnavailable)
        ));
        drop(first_device);
        assert!(!transport.is_ready());

        let second_listener = Arc::clone(&listener);
        let second_accept = tokio::spawn(async move { second_listener.accept_one().await });
        let second_stream = TcpStream::connect(address).await.expect("second connect");
        let (second_device, second_ready) =
            respond_on_mode(second_stream, &credentials, &credentials.link_secret, false).await;
        assert_eq!(
            u32::from_le_bytes(
                second_ready.payload[18..22]
                    .try_into()
                    .expect("capabilities")
            ),
            keyferry_protocol::capability::KEYBOARD
        );
        second_accept.await.expect("second accept task").unwrap();
        assert!(transport.is_ready());
        assert_eq!(
            transport
                .session_snapshot()
                .expect("legacy session")
                .firmware_identity,
            None
        );
        drop(second_device);
    }

    #[tokio::test]
    async fn idle_tcp_listener_does_not_block_a_non_tcp_candidate() {
        let credentials = credentials();
        let transport = TlsTransport::new(credentials.clone()).expect("TLS transport");
        let listener = Arc::new(
            TlsListener::bind("127.0.0.1:0".parse().unwrap(), transport.clone())
                .await
                .expect("listener"),
        );
        let accept_listener = Arc::clone(&listener);
        let idle_tcp_accept = tokio::spawn(async move { accept_listener.accept_one().await });

        let (server, client) = duplex(4096);
        let candidate_transport = transport.clone();
        let candidate =
            tokio::spawn(async move { candidate_transport.accept_stream(server).await });
        let link_secret = credentials.link_secret;
        let (client, _) = respond_on(client, &credentials, &link_secret).await;
        candidate.await.unwrap().unwrap();
        assert!(transport.is_ready());

        idle_tcp_accept.abort();
        assert!(idle_tcp_accept.await.unwrap_err().is_cancelled());
        drop(client);
    }

    #[tokio::test]
    async fn authentication_timeout_releases_the_candidate_slot() {
        let transport = TlsTransport::new(credentials()).expect("TLS transport");
        let (server, _client) = duplex(4096);

        assert!(matches!(
            transport
                .accept_stream_with_timeout(server, Duration::from_millis(25), TlsLinkPath::Wifi,)
                .await,
            Err(TlsTransportError::AuthenticationTimeout)
        ));
        assert_eq!(
            transport.inner.candidate_slots.available_permits(),
            MAX_AUTHENTICATION_CANDIDATES
        );
    }

    #[tokio::test]
    async fn transport_bounds_pending_authentication_candidates_to_two() {
        let transport = TlsTransport::new(credentials()).expect("TLS transport");
        let (first_server, _first_client) = duplex(4096);
        let (second_server, _second_client) = duplex(4096);
        let first_transport = transport.clone();
        let first = tokio::spawn(async move { first_transport.accept_stream(first_server).await });
        let second_transport = transport.clone();
        let second =
            tokio::spawn(async move { second_transport.accept_stream(second_server).await });

        time::timeout(Duration::from_secs(1), async {
            while transport.inner.candidate_slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("two candidates acquire both slots");

        let (third_server, _third_client) = duplex(4096);
        assert!(matches!(
            transport.accept_stream(third_server).await,
            Err(TlsTransportError::AlreadyAccepted)
        ));

        first.abort();
        second.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert!(second.await.unwrap_err().is_cancelled());
        assert_eq!(
            transport.inner.candidate_slots.available_permits(),
            MAX_AUTHENTICATION_CANDIDATES
        );
    }

    #[tokio::test]
    async fn accepted_socket_enables_host_keepalive() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let client = TcpStream::connect(address).await.expect("connect client");
        let (server, _) = accept_with_keepalive(&listener)
            .await
            .expect("accept with keepalive");

        assert!(SockRef::from(&server).keepalive().expect("read keepalive"));
        drop(client);
    }

    #[tokio::test]
    async fn listener_rejects_a_duplicate_live_session_before_tls() {
        let credentials = credentials();
        let transport = TlsTransport::new(credentials.clone()).expect("TLS transport");
        let listener = Arc::new(
            TlsListener::bind("127.0.0.1:0".parse().unwrap(), transport.clone())
                .await
                .expect("listener"),
        );
        let address = listener.local_addr().unwrap();
        let accept_listener = Arc::clone(&listener);
        let accept = tokio::spawn(async move { accept_listener.accept_one().await });
        let active_stream = connect_authenticated(address, &credentials).await;
        accept.await.unwrap().unwrap();
        assert!(transport.is_ready());

        let accept_listener = Arc::clone(&listener);
        let duplicate_accept = tokio::spawn(async move { accept_listener.accept_one().await });
        let mut duplicate = TcpStream::connect(address)
            .await
            .expect("connect duplicate");
        assert!(matches!(
            duplicate_accept.await.unwrap(),
            Err(TlsTransportError::AlreadyAccepted)
        ));
        let mut byte = [0_u8; 1];
        assert_eq!(
            duplicate.read(&mut byte).await.expect("duplicate closes"),
            0
        );
        assert!(transport.is_ready());
        drop(active_stream);
    }

    #[tokio::test]
    async fn maintenance_waits_for_disarm_zero_and_closes_the_live_session() {
        let credentials = credentials();
        let transport = TlsTransport::new(credentials.clone()).expect("TLS transport");
        let listener = Arc::new(
            TlsListener::bind("127.0.0.1:0".parse().unwrap(), transport.clone())
                .await
                .expect("listener"),
        );
        let address = listener.local_addr().unwrap();
        let accept_listener = Arc::clone(&listener);
        let accept = tokio::spawn(async move { accept_listener.accept_one().await });
        let mut device = connect_authenticated(address, &credentials).await;
        accept.await.unwrap().unwrap();

        let endpoint = tokio::spawn(async move {
            let disarm = read_frame(&mut device).await.expect("read DISARM");
            assert_eq!(disarm.message_type, keyferry_protocol::message::DISARM);
            assert!(disarm.payload.is_empty());
            send_frame(
                &mut device,
                Frame::v1(
                    keyferry_protocol::message::ACK,
                    disarm.sequence,
                    vec![keyferry_protocol::message::DISARM, 0, 0],
                ),
            )
            .await
            .expect("acknowledge DISARM");
        });

        transport
            .begin_maintenance()
            .await
            .expect("enter maintenance");
        endpoint.await.expect("endpoint task");
        assert!(transport.is_in_maintenance());
        assert!(!transport.is_ready());
        assert_eq!(transport.session_snapshot(), None);
        transport.finish_maintenance();
    }

    #[tokio::test]
    async fn session_setup_error_identifies_auth_response_read_stage() {
        let credentials = credentials();
        let transport = TlsTransport::new(credentials.clone()).expect("TLS transport");
        let listener = Arc::new(
            TlsListener::bind("127.0.0.1:0".parse().unwrap(), transport)
                .await
                .expect("listener"),
        );
        let address = listener.local_addr().unwrap();
        let accept_listener = Arc::clone(&listener);
        let accept = tokio::spawn(async move { accept_listener.accept_one().await });
        let connector = pinned_connector(&credentials, credentials.identity().certificate_der());
        let stream = TcpStream::connect(address).await.expect("connect device");
        let mut stream = connector
            .connect(ServerName::try_from("keyferry.local").unwrap(), stream)
            .await
            .expect("complete TLS handshake");
        read_frame(&mut stream).await.expect("read challenge");
        drop(stream);

        let error = accept.await.unwrap().unwrap_err();
        assert!(matches!(
            &error,
            TlsTransportError::SessionSetup {
                stage: "reading authentication response",
                ..
            }
        ));
        assert!(error
            .to_string()
            .contains("during reading authentication response"));
    }

    #[tokio::test]
    async fn listener_accepts_a_new_session_after_transport_disconnect() {
        let credentials = credentials();
        let transport = TlsTransport::new(credentials.clone()).expect("TLS transport");
        let listener = Arc::new(
            TlsListener::bind("127.0.0.1:0".parse().unwrap(), transport.clone())
                .await
                .expect("listener"),
        );
        let address = listener.local_addr().unwrap();
        let accept_listener = Arc::clone(&listener);
        let accept = tokio::spawn(async move { accept_listener.accept_one().await });
        let connector = pinned_connector(&credentials, credentials.identity().certificate_der());
        let stream = TcpStream::connect(address).await.unwrap();
        let mut stream = connector
            .connect(ServerName::try_from("keyferry.local").unwrap(), stream)
            .await
            .unwrap();
        assert_eq!(
            stream.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );
        assert_eq!(
            stream
                .get_ref()
                .1
                .negotiated_cipher_suite()
                .unwrap()
                .suite(),
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        );
        let challenge = read_frame(&mut stream).await.unwrap();
        assert!(!transport.is_ready());
        let (host_id, boot_nonce, challenge_bytes) = parse_challenge(&challenge);
        let device_nonce = [0x44; 32];
        let mut payload = Vec::with_capacity(AUTH_RESPONSE_LEN);
        payload.extend_from_slice(&credentials.device_id());
        payload.extend_from_slice(&device_nonce);
        payload.extend_from_slice(&auth_hmac(
            &[0x33; 32],
            &host_id,
            &credentials.device_id(),
            &boot_nonce,
            &challenge_bytes,
            &device_nonce,
            1,
            0,
        ));
        send_frame(
            &mut stream,
            Frame::v1(keyferry_protocol::message::AUTH_RESPONSE, 0, payload),
        )
        .await
        .unwrap();
        let ready = read_frame(&mut stream).await.unwrap();
        assert_eq!(
            ready.message_type,
            keyferry_protocol::message::SESSION_READY
        );
        send_frame(
            &mut stream,
            Frame::v1(
                keyferry_protocol::message::CAPABILITIES,
                1,
                firmware_identity_payload(),
            ),
        )
        .await
        .unwrap();
        accept.await.unwrap().unwrap();
        assert!(transport.is_ready());
        drop(stream);
        tokio::time::timeout(Duration::from_secs(1), async {
            while transport.is_ready() {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("idle disconnect is observed");

        let accept_listener = Arc::clone(&listener);
        let accept = tokio::spawn(async move { accept_listener.accept_one().await });
        let second_stream = connect_authenticated(address, &credentials).await;
        accept.await.unwrap().unwrap();
        assert!(transport.is_ready());
        drop(second_stream);
    }

    #[tokio::test]
    async fn listener_accepts_a_new_session_after_authentication_failure() {
        let credentials = credentials();
        let transport = TlsTransport::new(credentials.clone()).expect("TLS transport");
        let listener = Arc::new(
            TlsListener::bind("127.0.0.1:0".parse().unwrap(), transport.clone())
                .await
                .expect("listener"),
        );
        let address = listener.local_addr().unwrap();
        let accept_listener = Arc::clone(&listener);
        let accept = tokio::spawn(async move { accept_listener.accept_one().await });
        let connector = pinned_connector(&credentials, credentials.identity().certificate_der());
        let stream = TcpStream::connect(address).await.unwrap();
        let mut stream = connector
            .connect(ServerName::try_from("keyferry.local").unwrap(), stream)
            .await
            .unwrap();
        let challenge = read_frame(&mut stream).await.unwrap();
        let (host_id, boot_nonce, challenge_bytes) = parse_challenge(&challenge);
        let device_nonce = [0x44; 32];
        let mut payload = Vec::with_capacity(AUTH_RESPONSE_LEN);
        payload.extend_from_slice(&credentials.device_id());
        payload.extend_from_slice(&device_nonce);
        payload.extend_from_slice(&auth_hmac(
            &[0x99; 32],
            &host_id,
            &credentials.device_id(),
            &boot_nonce,
            &challenge_bytes,
            &device_nonce,
            1,
            0,
        ));
        send_frame(
            &mut stream,
            Frame::v1(keyferry_protocol::message::AUTH_RESPONSE, 0, payload),
        )
        .await
        .unwrap();
        assert!(read_frame(&mut stream).await.is_err());
        assert!(!transport.is_ready());
        assert!(matches!(
            accept.await.unwrap(),
            Err(TlsTransportError::SessionSetup {
                stage: "verifying authentication response",
                source,
            }) if matches!(*source, TlsTransportError::Authentication)
        ));

        let accept_listener = Arc::clone(&listener);
        let accept = tokio::spawn(async move { accept_listener.accept_one().await });
        let stream = connect_authenticated(address, &credentials).await;
        accept.await.unwrap().unwrap();
        assert!(transport.is_ready());
        drop(stream);
    }

    #[tokio::test]
    async fn different_pinned_key_fails_before_any_application_frame() {
        let credentials = credentials();
        let wrong = HostIdentity::generate().expect("wrong identity");
        let transport = TlsTransport::new(credentials.clone()).expect("TLS transport");
        let listener = TlsListener::bind("127.0.0.1:0".parse().unwrap(), transport.clone())
            .await
            .expect("listener");
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept_one().await });
        let connector = pinned_connector(&credentials, wrong.certificate_der());
        let stream = TcpStream::connect(address).await.unwrap();
        assert!(connector
            .connect(ServerName::try_from("keyferry.local").unwrap(), stream)
            .await
            .is_err());
        assert!(!transport.is_ready());
        assert!(matches!(
            accept.await.unwrap(),
            Err(TlsTransportError::SessionSetup {
                stage: "TLS handshake",
                source,
            }) if matches!(*source, TlsTransportError::Tls(_))
        ));
    }

    #[tokio::test]
    async fn captured_server_records_stay_below_the_512_byte_wire_bound() {
        let credentials = credentials();
        let config = server_config(credentials.identity()).unwrap();
        let acceptor = TlsAcceptor::from(config);
        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (server_io, client_io) = duplex(32 * 1024);
        let server_io = RecordingIo {
            inner: server_io,
            captured: captured.clone(),
        };
        let server_acceptor = acceptor.clone();
        let server_credentials = credentials.clone();
        let server = tokio::spawn(async move {
            authenticate_stream(&server_acceptor, server_io, &server_credentials, false).await
        });
        let connector = pinned_connector(&credentials, credentials.identity().certificate_der());
        let mut client = connector
            .connect(ServerName::try_from("keyferry.local").unwrap(), client_io)
            .await
            .unwrap();
        let challenge = read_frame(&mut client).await.unwrap();
        let (host_id, boot_nonce, challenge_bytes) = parse_challenge(&challenge);
        let device_nonce = [0x44; 32];
        let mut payload = Vec::with_capacity(AUTH_RESPONSE_LEN);
        payload.extend_from_slice(&credentials.device_id());
        payload.extend_from_slice(&device_nonce);
        payload.extend_from_slice(&auth_hmac(
            &[0x33; 32],
            &host_id,
            &credentials.device_id(),
            &boot_nonce,
            &challenge_bytes,
            &device_nonce,
            1,
            0,
        ));
        send_frame(
            &mut client,
            Frame::v1(keyferry_protocol::message::AUTH_RESPONSE, 0, payload),
        )
        .await
        .unwrap();
        let _ = read_frame(&mut client).await.unwrap();
        let (mut server, _, _, _) = server.await.unwrap().unwrap();
        let command = super::PlannedCommand {
            command_id: uuid::Uuid::now_v7(),
            chunks: Vec::new(),
            action_count: 0,
            char_count: 0,
            profile: "windows-us".to_owned(),
            expires_at: std::time::Instant::now() + Duration::from_secs(1),
            arm_before_first: false,
            input: None,
        };
        send_command(
            &mut server,
            2,
            &command,
            COMMAND_KIND_RELEASE_ALL,
            &[],
            COMMAND_MAX_MS,
        )
        .await
        .unwrap();
        let bytes = captured.lock().unwrap().clone();
        assert!(!bytes.is_empty());
        let mut offset = 0;
        while offset < bytes.len() {
            assert!(bytes.len() - offset >= 5, "truncated TLS record");
            let length = usize::from(u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]));
            assert!(length <= TLS_MAX_FRAGMENT_SIZE);
            offset += 5 + length;
        }
        assert_eq!(offset, bytes.len());
    }

    #[tokio::test]
    async fn stale_auth_response_sequence_is_rejected() {
        let credentials = credentials();
        let (server_io, client_io) = duplex(16 * 1024);
        let config = server_config(credentials.identity()).unwrap();
        let acceptor = TlsAcceptor::from(config);
        let server_acceptor = acceptor.clone();
        let server_credentials = credentials.clone();
        let server = tokio::spawn(async move {
            authenticate_stream(&server_acceptor, server_io, &server_credentials, false).await
        });
        let connector = pinned_connector(&credentials, credentials.identity().certificate_der());
        let mut client = connector
            .connect(ServerName::try_from("keyferry.local").unwrap(), client_io)
            .await
            .unwrap();
        let challenge = read_frame(&mut client).await.unwrap();
        let (host_id, boot_nonce, challenge_bytes) = parse_challenge(&challenge);
        let device_nonce = [0x44; 32];
        let mut payload = Vec::with_capacity(AUTH_RESPONSE_LEN);
        payload.extend_from_slice(&credentials.device_id());
        payload.extend_from_slice(&device_nonce);
        payload.extend_from_slice(&auth_hmac(
            &[0x33; 32],
            &host_id,
            &credentials.device_id(),
            &boot_nonce,
            &challenge_bytes,
            &device_nonce,
            1,
            0,
        ));
        send_frame(
            &mut client,
            Frame::v1(keyferry_protocol::message::AUTH_RESPONSE, 1, payload),
        )
        .await
        .unwrap();
        assert!(matches!(
            server.await.unwrap(),
            Err(TlsTransportError::SessionSetup {
                stage: "verifying authentication response",
                source,
            }) if matches!(*source, TlsTransportError::Authentication)
        ));
    }

    fn parse_challenge(frame: &Frame) -> ([u8; 16], [u8; 16], [u8; 32]) {
        assert_eq!(
            frame.message_type,
            keyferry_protocol::message::AUTH_CHALLENGE
        );
        assert_eq!(frame.sequence, 0);
        assert_eq!(frame.payload.len(), AUTH_CHALLENGE_LEN);
        let mut host_id = [0; 16];
        let mut boot_nonce = [0; 16];
        let mut challenge = [0; 32];
        host_id.copy_from_slice(&frame.payload[..16]);
        boot_nonce.copy_from_slice(&frame.payload[16..32]);
        challenge.copy_from_slice(&frame.payload[32..64]);
        assert_eq!(frame.payload[64..], [1, 0]);
        (host_id, boot_nonce, challenge)
    }

    fn pinned_connector(credentials: &TlsCredentials, certificate: &[u8]) -> TlsConnector {
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites =
            vec![rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256];
        provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
        let verifier = PinVerifier {
            certificate: certificate.to_vec(),
            algorithms: provider.signature_verification_algorithms,
        };
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        let _ = credentials;
        TlsConnector::from(Arc::new(config))
    }

    #[derive(Debug)]
    struct PinVerifier {
        certificate: Vec<u8>,
        algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
    }

    impl ServerCertVerifier for PinVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            if intermediates.is_empty() && end_entity.as_ref() == self.certificate {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(Error::General("pinned server certificate mismatch".into()))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.algorithms.supported_schemes()
        }
    }

    struct RecordingIo {
        inner: tokio::io::DuplexStream,
        captured: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl AsyncRead for RecordingIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for RecordingIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.captured.lock().unwrap().extend_from_slice(data);
            Pin::new(&mut self.inner).poll_write(cx, data)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
