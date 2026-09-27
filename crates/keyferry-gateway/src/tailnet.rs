//! Bounded parsing of `tailscale status --json` for owner-controller discovery.
//!
//! Tailnet membership is only a discovery hint. A peer is not a Keyferry controller and is not
//! trusted until owner-rooted mutual TLS and a fresh device route proof succeed.

use serde::Deserialize;
use std::{collections::BTreeMap, fmt, net::IpAddr};

pub const MAX_TAILNET_STATUS_BYTES: usize = 8 * 1024 * 1024;

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
pub enum TailnetStatusError {
    OutputTooLarge(usize),
    InvalidJson(serde_json::Error),
    MissingLocal,
    MissingAddress(String),
}

impl fmt::Display for TailnetStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooLarge(bytes) => write!(
                f,
                "Tailscale status returned {bytes} bytes; limit is {MAX_TAILNET_STATUS_BYTES}"
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

impl std::error::Error for TailnetStatusError {}

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

pub fn parse_status_json(bytes: &[u8]) -> Result<TailStatus, TailnetStatusError> {
    if bytes.len() > MAX_TAILNET_STATUS_BYTES {
        return Err(TailnetStatusError::OutputTooLarge(bytes.len()));
    }
    let raw: RawStatus = serde_json::from_slice(bytes).map_err(TailnetStatusError::InvalidJson)?;
    let local = convert_node(raw.local.ok_or(TailnetStatusError::MissingLocal)?)?;
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

fn convert_node(raw: RawNode) -> Result<TailNode, TailnetStatusError> {
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
        return Err(TailnetStatusError::MissingAddress(hostname));
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
    }

    #[test]
    fn malformed_oversized_or_addressless_status_fails_closed() {
        assert!(parse_status_json(b"not json").is_err());
        assert!(parse_status_json(br#"{"BackendState":"Running","Peer":{}}"#).is_err());
        assert!(parse_status_json(
            br#"{"Self":{"HostName":"controller-a","TailscaleIPs":[]},"Peer":{}}"#,
        )
        .is_err());
        assert!(matches!(
            parse_status_json(&vec![b' '; MAX_TAILNET_STATUS_BYTES + 1]),
            Err(TailnetStatusError::OutputTooLarge(_))
        ));
    }
}
