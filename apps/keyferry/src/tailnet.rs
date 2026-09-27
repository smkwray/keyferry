//! Bounded, on-demand Tailscale inventory for gateway discovery.
//!
//! Tailnet membership is only a discovery hint. A peer is not a Keyferry gateway and is not
//! trusted until the application-level gateway handshake succeeds.

use serde::Deserialize;
use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fmt, fs,
    io::{self, Read},
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_STATUS_BYTES: usize = 8 * 1024 * 1024;
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailNode {
    pub node_id: Option<String>,
    pub hostname: String,
    pub dns_name: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub online: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailStatus {
    pub backend_state: String,
    pub local: TailNode,
    pub peers: Vec<TailNode>,
}

impl TailStatus {
    pub fn online_peers(&self) -> impl Iterator<Item = &TailNode> {
        self.peers
            .iter()
            .filter(|peer| peer.online && !peer.is_discovery_noise())
    }
}

impl TailNode {
    /// Tailscale advertises service nodes such as `hello` on every tailnet.
    /// They are not Keyferry computers and must not be probed or listed.
    #[must_use]
    pub fn is_discovery_noise(&self) -> bool {
        is_tailscale_hello(&self.hostname, self.dns_name.as_deref())
    }
}

#[must_use]
pub fn is_tailscale_hello(hostname: &str, dns_name: Option<&str>) -> bool {
    let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if host == "hello" {
        return true;
    }
    dns_name
        .map(|dns| dns.trim().trim_end_matches('.').to_ascii_lowercase())
        .is_some_and(|dns| {
            dns == "hello.ipn.dev"
                || dns.starts_with("hello.ipn.dev.")
                || dns.split('.').next() == Some("hello")
        })
}

#[derive(Debug)]
pub enum DiscoveryError {
    BinaryNotFound,
    Launch(io::Error),
    NonZeroExit { code: Option<i32>, stderr: String },
    Timeout,
    OutputTooLarge(usize),
    InvalidJson(serde_json::Error),
    MissingLocal,
    MissingAddress(String),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BinaryNotFound => write!(f, "Tailscale is not installed or could not be found"),
            Self::Launch(error) => write!(f, "could not run Tailscale: {error}"),
            Self::NonZeroExit { code, stderr } => {
                write!(f, "Tailscale status failed ({code:?}): {stderr}")
            }
            Self::Timeout => write!(f, "Tailscale status did not finish within 5 seconds"),
            Self::OutputTooLarge(bytes) => write!(
                f,
                "Tailscale status returned {bytes} bytes; limit is {MAX_STATUS_BYTES}"
            ),
            Self::InvalidJson(error) => {
                write!(f, "Tailscale returned invalid status JSON: {error}")
            }
            Self::MissingLocal => write!(f, "Tailscale status omitted the local node"),
            Self::MissingAddress(node) => {
                write!(f, "Tailscale supplied no valid address for {node}")
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

#[derive(Clone, Debug)]
pub struct TailnetDiscovery {
    binary: PathBuf,
}

impl TailnetDiscovery {
    pub fn discover() -> Result<Self, DiscoveryError> {
        locate_binary()
            .map(|binary| Self { binary })
            .ok_or(DiscoveryError::BinaryNotFound)
    }

    #[must_use]
    pub fn from_binary(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
        }
    }

    pub fn refresh(&self) -> Result<TailStatus, DiscoveryError> {
        let mut command = Command::new(&self.binary);
        hide_console(&mut command);
        command.args(["status", "--json"]);
        let output = output_with_timeout(command, STATUS_TIMEOUT, MAX_STATUS_BYTES)?;
        if !output.status.success() {
            return Err(DiscoveryError::NonZeroExit {
                code: output.status.code(),
                stderr: bounded_lossy(&output.stderr, 4096),
            });
        }
        parse_status_json(&output.stdout)
    }
}

/// Runs `command` with piped output, killing it after `timeout`; stdout beyond `max_stdout` bytes
/// is an error, never truncated silently.
pub(crate) fn output_with_timeout(
    mut command: Command,
    timeout: Duration,
    max_stdout: usize,
) -> Result<Output, DiscoveryError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(DiscoveryError::Launch)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| DiscoveryError::Launch(io::Error::other("stdout was not piped")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| DiscoveryError::Launch(io::Error::other("stderr was not piped")))?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(max_stdout as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.take(4097).read_to_end(&mut bytes).map(|_| bytes)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(DiscoveryError::Timeout);
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(DiscoveryError::Launch(error));
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| DiscoveryError::Launch(io::Error::other("stdout reader panicked")))?
        .map_err(DiscoveryError::Launch)?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| DiscoveryError::Launch(io::Error::other("stderr reader panicked")))?
        .map_err(DiscoveryError::Launch)?;
    if stdout.len() > max_stdout {
        return Err(DiscoveryError::OutputTooLarge(stdout.len()));
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(windows)]
pub(crate) fn hide_console(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0800_0000);
}

#[cfg(not(windows))]
pub(crate) fn hide_console(_command: &mut Command) {}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawStatus {
    #[serde(default)]
    backend_state: String,
    #[serde(rename = "Self")]
    local: Option<RawNode>,
    #[serde(default)]
    peer: BTreeMap<String, RawNode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawNode {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "HostName", default)]
    hostname: String,
    #[serde(rename = "DNSName")]
    dns_name: Option<String>,
    #[serde(rename = "TailscaleIPs", default)]
    addresses: Vec<String>,
    #[serde(default)]
    online: bool,
}

pub fn parse_status_json(bytes: &[u8]) -> Result<TailStatus, DiscoveryError> {
    if bytes.len() > MAX_STATUS_BYTES {
        return Err(DiscoveryError::OutputTooLarge(bytes.len()));
    }
    let raw: RawStatus = serde_json::from_slice(bytes).map_err(DiscoveryError::InvalidJson)?;
    let local = convert_node(raw.local.ok_or(DiscoveryError::MissingLocal)?)?;
    let mut peers = raw
        .peer
        .into_values()
        .map(convert_node)
        .collect::<Result<Vec<_>, _>>()?;
    peers.sort_by_key(|peer| peer.hostname.to_ascii_lowercase());
    Ok(TailStatus {
        backend_state: raw.backend_state,
        local,
        peers,
    })
}

fn convert_node(raw: RawNode) -> Result<TailNode, DiscoveryError> {
    let hostname = if raw.hostname.trim().is_empty() {
        raw.dns_name
            .as_deref()
            .unwrap_or("unknown-tailnet-device")
            .trim_end_matches('.')
            .split('.')
            .next()
            .unwrap_or("unknown-tailnet-device")
            .to_owned()
    } else {
        raw.hostname
    };
    let addresses = raw
        .addresses
        .iter()
        .filter_map(|address| address.parse::<IpAddr>().ok())
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(DiscoveryError::MissingAddress(hostname));
    }
    Ok(TailNode {
        node_id: raw.id,
        hostname,
        dns_name: raw
            .dns_name
            .map(|value| value.trim_end_matches('.').to_owned()),
        addresses,
        online: raw.online,
    })
}

fn locate_binary() -> Option<PathBuf> {
    if let Some(explicit) = env::var_os("KEYFERRY_TAILSCALE_BIN") {
        let path = PathBuf::from(explicit);
        if is_file(&path) {
            return Some(path);
        }
    }
    let executable = if cfg!(windows) {
        OsString::from("tailscale.exe")
    } else {
        OsString::from("tailscale")
    };
    if let Some(path) = env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|directory| directory.join(&executable))
            .find(|candidate| is_file(candidate))
    }) {
        return Some(path);
    }
    known_locations().into_iter().find(|path| is_file(path))
}

fn known_locations() -> Vec<PathBuf> {
    let mut locations = vec![
        PathBuf::from("/Applications/Tailscale.app/Contents/MacOS/Tailscale"),
        PathBuf::from("/usr/bin/tailscale"),
        PathBuf::from("/usr/local/bin/tailscale"),
        PathBuf::from("/opt/homebrew/bin/tailscale"),
    ];
    if let Some(program_files) = env::var_os("ProgramFiles") {
        locations.push(
            PathBuf::from(program_files)
                .join("Tailscale")
                .join("tailscale.exe"),
        );
    }
    locations
}

fn is_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

pub(crate) fn bounded_lossy(bytes: &[u8], maximum: usize) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(maximum)])
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_sorts_online_tailnet_candidates_without_trusting_them() {
        let status = parse_status_json(
            br#"{
                "BackendState":"Running",
                "Self":{"ID":"self","HostName":"controller-a","TailscaleIPs":["100.64.0.1"]},
                "Peer":{
                    "two":{"ID":"node-z","HostName":"zeta","DNSName":"zeta.ts.net.","TailscaleIPs":["100.64.0.3"],"Online":false},
                    "one":{"ID":"node-b","HostName":"controller-b","DNSName":"controller-b.tail.example.","TailscaleIPs":["100.64.0.2","fd7a:115c:a1e0::2"],"Online":true}
                }
            }"#,
        )
        .expect("status");
        assert_eq!(status.backend_state, "Running");
        assert_eq!(status.local.hostname, "controller-a");
        assert_eq!(status.peers[0].hostname, "controller-b");
        assert_eq!(status.online_peers().count(), 1);
        assert_eq!(status.peers[0].node_id.as_deref(), Some("node-b"));
        assert_eq!(
            status.peers[0].dns_name.as_deref(),
            Some("controller-b.tail.example")
        );
    }

    #[test]
    fn tailscale_hello_is_not_a_keyferry_computer() {
        assert!(is_tailscale_hello("hello", Some("hello.ipn.dev")));
        assert!(is_tailscale_hello("HELLO", Some("hello.ipn.dev.")));
        assert!(is_tailscale_hello("ignored", Some("hello.tail123.ts.net")));
        assert!(!is_tailscale_hello(
            "controller-b",
            Some("controller-b.tail.example")
        ));
        assert!(!is_tailscale_hello("helloworld", None));

        let status = parse_status_json(
            br#"{
                "BackendState":"Running",
                "Self":{"ID":"self","HostName":"controller-a","TailscaleIPs":["100.64.0.1"]},
                "Peer":{
                    "hello":{"ID":"hello","HostName":"hello","DNSName":"hello.ipn.dev.","TailscaleIPs":["100.64.0.9"],"Online":true},
                    "one":{"ID":"node-b","HostName":"controller-b","DNSName":"controller-b.tail.example.","TailscaleIPs":["100.64.0.2"],"Online":true}
                }
            }"#,
        )
        .expect("status");
        let online = status
            .online_peers()
            .map(|peer| peer.hostname.as_str())
            .collect::<Vec<_>>();
        assert_eq!(online, ["controller-b"]);
    }

    #[test]
    fn malformed_or_addressless_status_fails_closed() {
        assert!(parse_status_json(b"not json").is_err());
        assert!(parse_status_json(br#"{"BackendState":"Running","Peer":{}}"#).is_err());
        assert!(parse_status_json(
            br#"{"Self":{"HostName":"controller-a","TailscaleIPs":[]},"Peer":{}}"#,
        )
        .is_err());
    }
}
