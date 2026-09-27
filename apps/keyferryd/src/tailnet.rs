//! Bounded invocations of the local Tailscale client.
//!
//! Output is only a routing hint: it names this computer's tailnet address and the peers worth
//! probing. It never grants Keyferry authority.

use keyferry_gateway::tailnet::{parse_status_json, TailStatus, MAX_TAILNET_STATUS_BYTES};
use std::{net::IpAddr, path::PathBuf, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command, time};

const TAILSCALE_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TAILSCALE_IP_OUTPUT: usize = 256;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Returns this computer's single canonical Tailscale IPv4 address, if Tailscale reports one.
pub async fn discover_local_tailscale_ipv4() -> Option<IpAddr> {
    run_tailscale(&["ip", "-4"], MAX_TAILSCALE_IP_OUTPUT, parse_tailscale_ipv4).await
}

pub(crate) async fn tailscale_status() -> Option<TailStatus> {
    run_tailscale(&["status", "--json"], MAX_TAILNET_STATUS_BYTES, |bytes| {
        parse_status_json(bytes).ok()
    })
    .await
}

async fn run_tailscale<T>(
    args: &[&str],
    max_output: usize,
    parse: impl Fn(&[u8]) -> Option<T>,
) -> Option<T> {
    for binary in tailscale_candidates() {
        let mut child = Command::new(&binary);
        child
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        child.creation_flags(CREATE_NO_WINDOW);
        let Ok(mut child) = child.spawn() else {
            continue;
        };
        let Some(stdout) = child.stdout.take() else {
            continue;
        };
        let mut bytes = Vec::new();
        let completed = time::timeout(TAILSCALE_COMMAND_TIMEOUT, async {
            stdout
                .take(max_output as u64 + 1)
                .read_to_end(&mut bytes)
                .await
                .ok()?;
            child.wait().await.ok()
        })
        .await
        .ok()
        .flatten();
        if completed.is_some_and(|status| status.success()) && bytes.len() <= max_output {
            if let Some(value) = parse(&bytes) {
                return Some(value);
            }
        }
    }
    None
}

fn tailscale_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = std::env::var_os("KEYFERRY_TAILSCALE_EXE") {
        paths.push(PathBuf::from(path));
    }
    paths.push(PathBuf::from(if cfg!(windows) {
        "tailscale.exe"
    } else {
        "tailscale"
    }));
    if cfg!(windows) {
        if let Some(program_files) = std::env::var_os("ProgramFiles") {
            paths.push(
                PathBuf::from(program_files)
                    .join("Tailscale")
                    .join("tailscale.exe"),
            );
        }
    }
    if cfg!(target_os = "macos") {
        paths.extend([
            PathBuf::from("/Applications/Tailscale.app/Contents/MacOS/Tailscale"),
            PathBuf::from("/usr/local/bin/tailscale"),
            PathBuf::from("/opt/homebrew/bin/tailscale"),
        ]);
    }
    paths
}

fn parse_tailscale_ipv4(bytes: &[u8]) -> Option<IpAddr> {
    if bytes.len() > MAX_TAILSCALE_IP_OUTPUT {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let addresses = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::parse::<IpAddr>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    match addresses.as_slice() {
        [address] if keyferry_gateway::is_tailscale_ip(*address) && address.is_ipv4() => {
            Some(*address)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_tailnet_address_requires_one_canonical_ipv4() {
        assert_eq!(
            parse_tailscale_ipv4(b"100.64.0.7\n"),
            Some("100.64.0.7".parse().unwrap())
        );
        for invalid in [
            b"192.168.1.7\n".as_slice(),
            b"fd7a:115c:a1e0::7\n".as_slice(),
            b"100.64.0.7\n100.64.0.8\n".as_slice(),
            b"not-an-address\n".as_slice(),
            &[b'x'; MAX_TAILSCALE_IP_OUTPUT + 1],
        ] {
            assert_eq!(parse_tailscale_ipv4(invalid), None);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn automatic_tailnet_discovery_checks_packaged_and_homebrew_locations() {
        let candidates = tailscale_candidates();
        for required in [
            "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
            "/usr/local/bin/tailscale",
            "/opt/homebrew/bin/tailscale",
        ] {
            assert!(candidates.contains(&PathBuf::from(required)));
        }
    }

    #[test]
    fn tailscale_client_never_allocates_a_console_window() {
        let source = include_str!("tailnet.rs");
        assert!(source.contains("child.creation_flags(CREATE_NO_WINDOW);"));
    }
}
