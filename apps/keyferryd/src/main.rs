#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Duration,
};

use keyferryd::discover_local_tailscale_ipv4;
use tokio::time;

const FIRST_HIL_CONFIG: &str = "secrets/first-hil/keyferryd/runtime.json";
/// Time allowed for cancelled commands to release and for each endpoint to disarm and close.
const DEVICE_SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
/// Time allowed for remaining tasks after they are dropped at runtime shutdown.
const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// The daemon runs only while the Keyferry app is open (D-20260926-04); the app's service
/// manager stops it with SIGTERM on macOS. A stop request ends device work through
/// [`keyferryd::Daemon::shutdown`], then dropping every task closes the remaining sockets and
/// kills the macOS Bluetooth helper, whose handle is `kill_on_drop`.
fn main() -> Result<(), keyferryd::DaemonError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let started = Arc::new(OnceLock::new());
    let result = runtime.block_on(async {
        let result = tokio::select! {
            result = run(Arc::clone(&started)) => result,
            () = shutdown_signal() => {
                println!("keyferryd stopping");
                Ok(())
            }
        };
        if let Some(daemon) = started.get() {
            daemon.shutdown(DEVICE_SHUTDOWN_GRACE).await;
        }
        result
    });
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_GRACE);
    result
}

/// Resolves when the service manager or a console asks the daemon to stop. On Windows the Task
/// Scheduler's `/End` terminates the process without an event; the endpoint's disconnect path
/// then releases every key.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let (Ok(mut terminate), Ok(mut interrupt)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown};
        let (Ok(mut interrupt), Ok(mut brk), Ok(mut close), Ok(mut logoff), Ok(mut shutdown)) = (
            ctrl_c(),
            ctrl_break(),
            ctrl_close(),
            ctrl_logoff(),
            ctrl_shutdown(),
        ) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = brk.recv() => {}
            _ = close.recv() => {}
            _ = logoff.recv() => {}
            _ = shutdown.recv() => {}
        }
    }
    #[cfg(not(any(unix, windows)))]
    std::future::pending::<()>().await
}

async fn run(started: Arc<OnceLock<keyferryd::Daemon>>) -> Result<(), keyferryd::DaemonError> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "keyferryd service\n  keyferryd [--port PORT]\n  keyferryd --config PATH [--port PORT] [--ble [--ble-single-shot]] [--tailnet-address IP] [--tailnet-port PORT]\n  keyferryd --installation DIRECTORY [--port PORT] [--ble-single-shot] [--lan-interface NAME]... [--tailnet-address IP] [--tailnet-port PROBE_PORT]\n\nAn issued installation enables nearby Bluetooth and follows the local Tailscale IPv4 address automatically unless --tailnet-address is supplied. Each explicit --lan-interface enables owner-authorized device TLS and directed discovery on that interface only."
        );
        return Ok(());
    }
    let options = parse_options(&args)?;
    #[cfg(not(any(windows, target_os = "macos")))]
    if options.ble || options.installation.is_some() {
        return Err(keyferryd::DaemonError::Tls(
            "--ble is supported only on Windows and macOS".to_owned(),
        ));
    }
    let port = options.port.unwrap_or(keyferryd::DEFAULT_PORT);
    let (daemon, ble_transport, ble_multi, remote_installation) = if let Some(path) = options.config
    {
        let config = keyferryd::PairedRuntimeConfig::load(path)?;
        let device_id = config.device_id();
        let secret_store = keyferryd::FileTlsSecretStore::new(config.secret_dir());
        let transport =
            keyferryd::TlsTransport::from_secret_store(&secret_store, *device_id.as_bytes())
                .map_err(|error| keyferryd::DaemonError::Tls(error.to_string()))?;
        let listener = keyferryd::TlsListener::bind(config.bind(), transport.clone())
            .await
            .map_err(|error| keyferryd::DaemonError::Tls(error.to_string()))?;
        if let Some(plan) = config.beacon_plan() {
            let beacon = keyferryd::HostBeacon::bind(plan, transport.host_id()).await?;
            tokio::spawn(beacon.run());
        }
        let ble_transport = options.ble.then(|| transport.clone());
        let daemon = keyferryd::Daemon::with_tls_transport(
            keyferryd::FileTokenStore::default(),
            device_id.to_string(),
            "Paired keyboard".to_owned(),
            transport,
        )?;
        println!("keyferryd TLS listener ready for the paired dongle");
        tokio::spawn(async move {
            loop {
                match listener.accept_one().await {
                    Ok(peer) => println!("TLS dongle session authenticated from {peer}"),
                    Err(error) => eprintln!("TLS dongle connection rejected: {error}"),
                }
            }
        });
        (daemon, ble_transport, None, None)
    } else if let Some(path) = options.installation {
        wait_for_authorization(&path).await;
        let secret_stores = keyferryd::InstallationTlsSecretSet::load(path)?;
        let transports = secret_stores
            .transports()
            .map_err(|error| keyferryd::DaemonError::Tls(error.to_string()))?;
        let remote_installation = secret_stores
            .iter()
            .next()
            .expect("an installation contains at least one device")
            .clone();
        let beacon_host_id = remote_installation.installation_id();
        let devices = secret_stores
            .iter()
            .zip(transports.iter().cloned())
            .map(|(store, transport)| {
                let device_id = uuid::Uuid::from_bytes(store.device_id());
                (
                    device_id.to_string(),
                    format!("Keyferry {}", &device_id.simple().to_string()[..8]),
                    transport,
                )
            })
            .collect();
        let daemon =
            keyferryd::Daemon::with_tls_transports(keyferryd::FileTokenStore::default(), devices)?;
        daemon.enable_tailnet_forwarding(&secret_stores)?;
        println!(
            "keyferryd ready for {} owner-authorized Keyferry device(s)",
            secret_stores.len()
        );
        if !options.lan_interfaces.is_empty() {
            println!(
                "keyferryd enabling owner-authorized Wi-Fi on selected interface(s): {}",
                options
                    .lan_interfaces
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            tokio::spawn(keyferryd::HostBeacon::run_selected_multi(
                beacon_host_id,
                secret_stores.clone(),
                transports.clone(),
                options.lan_interfaces.clone(),
                daemon.gateway_listener_registry(),
            ));
        }
        let ble_multi = if cfg!(target_os = "macos") && secret_stores.len() > 1 {
            eprintln!(
                "multi-device Bluetooth gateway disabled on macOS; Wi-Fi control remains available"
            );
            None
        } else {
            Some((secret_stores, transports))
        };
        (daemon, None, ble_multi, Some(remote_installation))
    } else {
        (
            keyferryd::Daemon::new(keyferryd::FileTokenStore::default())?,
            None,
            None,
            None,
        )
    };
    let _ = started.set(daemon.clone());
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    println!("keyferryd local API listening on http://{address}");
    let mut services = tokio::task::JoinSet::new();
    let local_daemon = daemon.clone();
    services.spawn(async move { keyferryd::serve(local_daemon, address).await });
    let tailnet_port = options
        .tailnet_port
        .unwrap_or(keyferryd::DEFAULT_REMOTE_PORT);
    match (remote_installation, options.tailnet_address) {
        (Some(installation), Some(tailnet_ip)) => {
            let control_port = owner_control_port(tailnet_port)?;
            let probe_address = SocketAddr::new(tailnet_ip, tailnet_port);
            let control_address = SocketAddr::new(tailnet_ip, control_port);
            let installation_id = installation.installation_id();
            println!(
                "keyferryd owner gateway probe on http://{probe_address}; authenticated control on {control_address}"
            );
            services.spawn(async move {
                keyferryd::serve_tailnet_candidate(probe_address, installation_id).await
            });
            services.spawn(async move {
                keyferryd::serve_tailnet_mtls(daemon, control_address, installation).await
            });
        }
        (Some(installation), None) => {
            println!("keyferryd will follow the local Tailscale IPv4 address when available");
            services.spawn(supervise_owner_tailnet(
                daemon.clone(),
                installation,
                tailnet_port,
            ));
        }
        (None, Some(tailnet_ip)) => {
            let remote_address = SocketAddr::new(tailnet_ip, tailnet_port);
            let policy =
                keyferryd::RemoteApiPolicy::new(keyferryd::FileTokenStore::remote_default())?;
            println!("keyferryd legacy tailnet API listening on http://{remote_address}");
            services.spawn(async move {
                keyferryd::serve_tailnet(daemon, remote_address, policy).await
            });
        }
        (None, None) => {}
    }
    let joined_service = async {
        services
            .join_next()
            .await
            .ok_or_else(|| keyferryd::DaemonError::Tls("keyferryd started no services".to_owned()))?
            .map_err(|error| keyferryd::DaemonError::Tls(error.to_string()))?
    };
    let result = if let Some(transport) = ble_transport {
        tokio::select! {
            result = joined_service => result,
            result = keyferryd::run_ble_gateway(transport, options.ble_single_shot) => {
                result.map_err(|error| keyferryd::DaemonError::Tls(error.to_string()))
            }
        }
    } else if let Some((stores, transports)) = ble_multi {
        tokio::select! {
            result = joined_service => result,
            result = keyferryd::run_ble_gateways(stores, transports, options.ble_single_shot) => {
                result.map_err(|error| keyferryd::DaemonError::Tls(error.to_string()))
            }
        }
    } else {
        joined_service.await
    };
    services.abort_all();
    result
}

const TAILSCALE_REFRESH: Duration = Duration::from_secs(5);

/// A program-only install has no credentials until the desktop authorizes this computer. The
/// desktop publishes the directory with one rename, so its existence means it is complete.
async fn wait_for_authorization(path: &std::path::Path) {
    if path.exists() {
        return;
    }
    println!("keyferryd waiting for this computer to be authorized in the Keyferry app");
    while !path.exists() {
        time::sleep(AUTHORIZATION_POLL).await;
    }
}

const AUTHORIZATION_POLL: Duration = Duration::from_secs(2);

async fn supervise_owner_tailnet(
    daemon: keyferryd::Daemon,
    installation: keyferryd::InstallationTlsSecretStore,
    probe_port: u16,
) -> Result<(), keyferryd::DaemonError> {
    let control_port = owner_control_port(probe_port)?;
    loop {
        let Some(ip) = discover_local_tailscale_ipv4().await else {
            time::sleep(TAILSCALE_REFRESH).await;
            continue;
        };
        let probe_address = SocketAddr::new(ip, probe_port);
        let control_address = SocketAddr::new(ip, control_port);
        println!(
            "keyferryd owner gateway probe on http://{probe_address}; authenticated control on {control_address}"
        );
        let probe =
            keyferryd::serve_tailnet_candidate(probe_address, installation.installation_id());
        let control =
            keyferryd::serve_tailnet_mtls(daemon.clone(), control_address, installation.clone());
        tokio::pin!(probe);
        tokio::pin!(control);
        loop {
            tokio::select! {
                result = &mut probe => {
                    if let Err(error) = result {
                        eprintln!("owner gateway probe stopped: {error}");
                    }
                    break;
                }
                result = &mut control => {
                    if let Err(error) = result {
                        eprintln!("owner gateway control stopped: {error}");
                    }
                    break;
                }
                () = time::sleep(TAILSCALE_REFRESH) => {
                    if discover_local_tailscale_ipv4().await != Some(ip) {
                        println!("keyferryd tailnet address changed; rebinding owner gateway listeners");
                        break;
                    }
                }
            }
        }
        time::sleep(Duration::from_secs(1)).await;
    }
}

fn owner_control_port(probe_port: u16) -> Result<u16, keyferryd::DaemonError> {
    probe_port.checked_add(1).ok_or_else(|| {
        keyferryd::DaemonError::Tls("owner gateway probe port leaves no control port".to_owned())
    })
}

struct Options {
    port: Option<u16>,
    config: Option<PathBuf>,
    installation: Option<PathBuf>,
    ble: bool,
    ble_single_shot: bool,
    lan_interfaces: BTreeSet<String>,
    tailnet_address: Option<IpAddr>,
    tailnet_port: Option<u16>,
}

fn parse_options(args: &[String]) -> Result<Options, keyferryd::DaemonError> {
    let mut options = Options {
        port: None,
        config: None,
        installation: None,
        ble: false,
        ble_single_shot: false,
        lan_interfaces: BTreeSet::new(),
        tailnet_address: None,
        tailnet_port: None,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--port" if options.port.is_none() => {
                let value = args.get(index + 1).ok_or_else(|| {
                    keyferryd::DaemonError::Tls("--port requires one value".to_owned())
                })?;
                options.port = Some(
                    value
                        .parse::<u16>()
                        .ok()
                        .filter(|port| *port != 0)
                        .ok_or_else(|| {
                            keyferryd::DaemonError::Tls(
                                "--port must be an integer from 1 through 65535".to_owned(),
                            )
                        })?,
                );
                index += 2;
            }
            "--config" if options.config.is_none() => {
                let value = args.get(index + 1).ok_or_else(|| {
                    keyferryd::DaemonError::Tls("--config requires one path".to_owned())
                })?;
                if value.is_empty() {
                    return Err(keyferryd::DaemonError::Tls(
                        "--config path must not be empty".to_owned(),
                    ));
                }
                options.config = Some(PathBuf::from(value));
                index += 2;
            }
            "--installation" if options.installation.is_none() => {
                let value = args.get(index + 1).ok_or_else(|| {
                    keyferryd::DaemonError::Tls("--installation requires one path".to_owned())
                })?;
                if value.is_empty() {
                    return Err(keyferryd::DaemonError::Tls(
                        "--installation path must not be empty".to_owned(),
                    ));
                }
                options.installation = Some(PathBuf::from(value));
                index += 2;
            }
            "--first-hil" if options.config.is_none() => {
                options.config = Some(PathBuf::from(FIRST_HIL_CONFIG));
                index += 1;
            }
            "--ble" if !options.ble => {
                options.ble = true;
                index += 1;
            }
            "--ble-single-shot" if !options.ble_single_shot => {
                options.ble_single_shot = true;
                index += 1;
            }
            "--lan-interface" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    keyferryd::DaemonError::Tls("--lan-interface requires one name".to_owned())
                })?;
                if value.is_empty() || !options.lan_interfaces.insert(value.clone()) {
                    return Err(keyferryd::DaemonError::Tls(
                        "--lan-interface must be nonempty and unique".to_owned(),
                    ));
                }
                index += 2;
            }
            "--tailnet-address" if options.tailnet_address.is_none() => {
                let value = args.get(index + 1).ok_or_else(|| {
                    keyferryd::DaemonError::Tls("--tailnet-address requires one value".to_owned())
                })?;
                let address = value.parse::<IpAddr>().map_err(|_| {
                    keyferryd::DaemonError::Tls(
                        "--tailnet-address must be an IP address".to_owned(),
                    )
                })?;
                if !keyferryd::is_tailscale_ip(address) {
                    return Err(keyferryd::DaemonError::Tls(
                        "--tailnet-address must be a Tailscale address".to_owned(),
                    ));
                }
                options.tailnet_address = Some(address);
                index += 2;
            }
            "--tailnet-port" if options.tailnet_port.is_none() => {
                let value = args.get(index + 1).ok_or_else(|| {
                    keyferryd::DaemonError::Tls("--tailnet-port requires one value".to_owned())
                })?;
                options.tailnet_port = Some(
                    value
                        .parse::<u16>()
                        .ok()
                        .filter(|port| *port != 0)
                        .ok_or_else(|| {
                            keyferryd::DaemonError::Tls(
                                "--tailnet-port must be an integer from 1 through 65535".to_owned(),
                            )
                        })?,
                );
                index += 2;
            }
            _ => {
                return Err(keyferryd::DaemonError::Tls(
                    "unsupported or duplicate keyferryd option".to_owned(),
                ));
            }
        }
    }
    if options.config.is_some() && options.installation.is_some() {
        return Err(keyferryd::DaemonError::Tls(
            "--config and --installation are mutually exclusive".to_owned(),
        ));
    }
    let has_credentials = options.config.is_some() || options.installation.is_some();
    if options.ble && !has_credentials {
        return Err(keyferryd::DaemonError::Tls(
            "--ble requires --config or --installation".to_owned(),
        ));
    }
    if options.ble_single_shot && !options.ble && options.installation.is_none() {
        return Err(keyferryd::DaemonError::Tls(
            "--ble-single-shot requires --ble or --installation".to_owned(),
        ));
    }
    if options.tailnet_address.is_some() && !has_credentials {
        return Err(keyferryd::DaemonError::Tls(
            "--tailnet-address requires --config or --installation".to_owned(),
        ));
    }
    if !options.lan_interfaces.is_empty() && options.installation.is_none() {
        return Err(keyferryd::DaemonError::Tls(
            "--lan-interface requires --installation".to_owned(),
        ));
    }
    if options.tailnet_port.is_some() && options.tailnet_address.is_none() {
        return Err(keyferryd::DaemonError::Tls(
            "--tailnet-port requires --tailnet-address".to_owned(),
        ));
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_config_path_is_explicit() {
        let options = parse_options(&[
            "--config".to_owned(),
            "private/runtime.json".to_owned(),
            "--port".to_owned(),
            "7444".to_owned(),
        ])
        .expect("parse options");
        assert_eq!(options.config, Some(PathBuf::from("private/runtime.json")));
        assert_eq!(options.port, Some(7444));
        assert!(!options.ble);
        assert!(!options.ble_single_shot);
    }

    #[test]
    fn legacy_first_hil_is_only_a_compatibility_alias() {
        let options = parse_options(&["--first-hil".to_owned()]).expect("parse alias");
        assert_eq!(options.config, Some(PathBuf::from(FIRST_HIL_CONFIG)));
        assert!(parse_options(&[
            "--first-hil".to_owned(),
            "--config".to_owned(),
            "other.json".to_owned()
        ])
        .is_err());
    }

    #[test]
    fn bluetooth_requires_paired_runtime_configuration() {
        assert!(parse_options(&["--ble".to_owned()]).is_err());
        let options = parse_options(&[
            "--config".to_owned(),
            "private/runtime.json".to_owned(),
            "--ble".to_owned(),
        ])
        .expect("parse Bluetooth gateway");
        assert!(options.ble);
        assert!(!options.ble_single_shot);
        let single = parse_options(&[
            "--config".to_owned(),
            "private/runtime.json".to_owned(),
            "--ble".to_owned(),
            "--ble-single-shot".to_owned(),
        ])
        .expect("parse single-shot Bluetooth gateway");
        assert!(single.ble);
        assert!(single.ble_single_shot);
        assert!(parse_options(&[
            "--config".to_owned(),
            "private/runtime.json".to_owned(),
            "--ble-single-shot".to_owned(),
        ])
        .is_err());
    }

    #[test]
    fn issued_installation_is_an_implicit_bluetooth_gateway() {
        let options = parse_options(&[
            "--installation".to_owned(),
            "private/installation".to_owned(),
            "--ble-single-shot".to_owned(),
        ])
        .expect("parse issued installation");
        assert_eq!(
            options.installation,
            Some(PathBuf::from("private/installation"))
        );
        assert!(!options.ble);
        assert!(options.ble_single_shot);
        assert!(options.lan_interfaces.is_empty());
        assert!(parse_options(&[
            "--installation".to_owned(),
            "private/installation".to_owned(),
            "--config".to_owned(),
            "private/runtime.json".to_owned(),
        ])
        .is_err());
    }

    #[test]
    fn installation_lan_interfaces_are_explicit_and_unique() {
        let options = parse_options(&[
            "--installation".to_owned(),
            "private/installation".to_owned(),
            "--lan-interface".to_owned(),
            "en0".to_owned(),
            "--lan-interface".to_owned(),
            "en7".to_owned(),
        ])
        .expect("parse selected LAN interfaces");
        assert_eq!(
            options.lan_interfaces,
            BTreeSet::from(["en0".to_owned(), "en7".to_owned()])
        );
        assert!(parse_options(&[
            "--installation".to_owned(),
            "private/installation".to_owned(),
            "--lan-interface".to_owned(),
            "en0".to_owned(),
            "--lan-interface".to_owned(),
            "en0".to_owned(),
        ])
        .is_err());
        assert!(parse_options(&["--lan-interface".to_owned(), "en0".to_owned()]).is_err());
    }

    #[test]
    fn owner_gateway_control_port_immediately_follows_probe_port() {
        assert_eq!(owner_control_port(18_043).unwrap(), 18_044);
        assert!(owner_control_port(u16::MAX).is_err());
    }

    #[test]
    fn direct_tailnet_surface_requires_config_and_tailscale_address() {
        assert!(
            parse_options(&["--tailnet-address".to_owned(), "100.64.0.5".to_owned(),]).is_err()
        );
        assert!(parse_options(&["--tailnet-port".to_owned(), "18043".to_owned()]).is_err());
        assert!(parse_options(&[
            "--config".to_owned(),
            "private/runtime.json".to_owned(),
            "--tailnet-address".to_owned(),
            "192.168.1.5".to_owned(),
        ])
        .is_err());
        let options = parse_options(&[
            "--installation".to_owned(),
            "private/installation".to_owned(),
            "--tailnet-address".to_owned(),
            "100.64.0.5".to_owned(),
            "--tailnet-port".to_owned(),
            "18043".to_owned(),
        ])
        .expect("parse direct tailnet surface");
        assert_eq!(options.tailnet_address, Some("100.64.0.5".parse().unwrap()));
        assert_eq!(options.tailnet_port, Some(18_043));
    }

    #[test]
    fn windows_daemon_does_not_allocate_a_console_window() {
        let source = include_str!("main.rs");
        assert!(source
            .starts_with("#![cfg_attr(target_os = \"windows\", windows_subsystem = \"windows\")]"));
    }
}
