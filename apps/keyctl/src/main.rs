#![forbid(unsafe_code)]

use keyferry_core::TransportDiagnostic;
use keyferry_layouts::text_stream::{
    TextStreamError, TextStreamReader, UnsupportedTextPolicy, TEXT_STREAM_RECEIPT_SCHEMA_V1,
    TEXT_STREAM_SCHEMA_V1,
};
use keyferry_layouts::{
    compile_input_sequence, compile_sequence, parse_input_sequence_json_with_command_id, KeyClass,
    KeyPortability, KeyboardSequenceV1, SequenceAction, SequenceArmPolicy, TypingTiming,
    KEYBOARD_KEYS, SEQUENCE_SCHEMA_V1,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    env, fs,
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};

const DEFAULT_URL: &str = "http://127.0.0.1:8042";
const MAX_SEQUENCE_BODY: usize = 65_536;
const SEQUENCE_WAIT_TIMEOUT: Duration = Duration::from_secs(125);
const SEQUENCE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const SEQUENCE_CANCEL_RECONCILE: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct ClientError(String);

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ClientError {}

#[derive(Clone, Debug)]
struct Endpoint {
    host: String,
    port: u16,
}

#[derive(Clone, Debug)]
struct Client {
    endpoint: Endpoint,
    token: String,
}

#[derive(Serialize)]
struct ArmRequest<'a> {
    policy: &'a str,
}

#[derive(Serialize)]
struct CancelRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    command_id: Option<String>,
}

#[derive(Serialize)]
struct OutputModeRequest<'a> {
    mode: &'a str,
}

#[derive(Serialize)]
struct DisplayOrientationRequest<'a> {
    orientation: &'a str,
}

#[derive(Serialize)]
struct ScreenPowerRequest<'a> {
    power: &'a str,
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let url = take_named_option(&mut args, "--url").unwrap_or_else(|| DEFAULT_URL.to_owned());
    let token_file = take_named_option(&mut args, "--token-file")
        .map(PathBuf::from)
        .unwrap_or_else(default_token_path);
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h" | "help") {
        println!("{}", help_text());
        return ExitCode::SUCCESS;
    }
    if args.first().is_some_and(|command| {
        matches!(
            command.as_str(),
            "local-status" | "local-recover" | "local-probe"
        )
    }) {
        return ExitCode::from(run_local_helper(&args));
    }
    if args.len() == 1 && args[0] == "keys" {
        println!("{}", key_registry_json());
        return ExitCode::SUCCESS;
    }
    if args.len() == 2 && args[0] == "sequence" && args[1] == "--help" {
        println!("{}", sequence_help_text());
        return ExitCode::SUCCESS;
    }
    if args.len() == 2 && args[0] == "sequence" && args[1] == "--example" {
        println!("{SEQUENCE_EXAMPLE}");
        return ExitCode::SUCCESS;
    }
    if args.len() == 2 && args[0] == "sequence" && args[1] == "--validate" {
        return ExitCode::from(run_sequence_validate());
    }
    if args.len() == 2 && args[0] == "type" && args[1] == "--help" {
        println!("{}", type_help_text());
        return ExitCode::SUCCESS;
    }
    if args.len() == 2 && args[0] == "stream" && args[1] == "--help" {
        println!("{}", stream_help_text());
        return ExitCode::SUCCESS;
    }
    if args.first().is_some_and(|command| command == "stream") {
        let device = args.get(1).map_or("", String::as_str);
        if device.is_empty() || device.starts_with("--") {
            emit_stream_error(device, None, "input.usage", None);
            return ExitCode::from(20);
        }
        let options = match parse_stream_options(&args[2..]) {
            Ok(options) => options,
            Err(code) => {
                emit_stream_error(device, None, code, None);
                return ExitCode::from(20);
            }
        };
        if options.validate {
            return ExitCode::from(run_stream_validate(device, &options));
        }
        let endpoint = match parse_endpoint(&url) {
            Ok(endpoint) => endpoint,
            Err(_) => {
                emit_stream_error(device, None, "input.url", None);
                return ExitCode::from(20);
            }
        };
        let token = match service_token(&endpoint, &token_file) {
            Ok(token) => token,
            Err(_) => {
                emit_stream_error(device, None, "daemon.token_unavailable", None);
                return ExitCode::from(23);
            }
        };
        return ExitCode::from(run_stream(&Client { endpoint, token }, device, &options));
    }
    if args
        .first()
        .is_some_and(|command| command == "input-sequence")
        && args
            .get(1)
            .is_some_and(|argument| argument == "--describe" || argument == "--validate")
    {
        return ExitCode::from(run_input_sequence_local(&args));
    }
    if args
        .first()
        .is_some_and(|command| command == "input-sequence")
    {
        let device = args.get(1).map_or("", String::as_str);
        let endpoint = match parse_endpoint(&url) {
            Ok(endpoint) => endpoint,
            Err(_) => {
                emit_sequence_result(device, None, SequenceOutcome::Rejected, Some("input.url"));
                return ExitCode::from(20);
            }
        };
        let token = match service_token(&endpoint, &token_file) {
            Ok(token) => token,
            Err(_) => {
                emit_sequence_result(
                    device,
                    None,
                    SequenceOutcome::Rejected,
                    Some("daemon.token_unavailable"),
                );
                return ExitCode::from(23);
            }
        };
        return ExitCode::from(run_input_sequence(&Client { endpoint, token }, &args));
    }
    if args.first().is_some_and(|command| command == "sequence") {
        let device = args.get(1).map_or("", String::as_str);
        let endpoint = match parse_endpoint(&url) {
            Ok(endpoint) => endpoint,
            Err(_) => {
                emit_sequence_result(device, None, SequenceOutcome::Rejected, Some("input.url"));
                return ExitCode::from(20);
            }
        };
        let token = match service_token(&endpoint, &token_file) {
            Ok(token) => token,
            Err(_) => {
                emit_sequence_result(
                    device,
                    None,
                    SequenceOutcome::Rejected,
                    Some("daemon.token_unavailable"),
                );
                return ExitCode::from(23);
            }
        };
        return ExitCode::from(run_sequence(&Client { endpoint, token }, &args));
    }
    if args.first().is_some_and(|command| command == "type") {
        let device = args.get(1).map_or("", String::as_str);
        let endpoint = match parse_endpoint(&url) {
            Ok(endpoint) => endpoint,
            Err(_) => {
                emit_sequence_result(device, None, SequenceOutcome::Rejected, Some("input.url"));
                return ExitCode::from(20);
            }
        };
        let token = match service_token(&endpoint, &token_file) {
            Ok(token) => token,
            Err(_) => {
                emit_sequence_result(
                    device,
                    None,
                    SequenceOutcome::Rejected,
                    Some("daemon.token_unavailable"),
                );
                return ExitCode::from(23);
            }
        };
        return ExitCode::from(run_type(&Client { endpoint, token }, &args));
    }
    let result = parse_endpoint(&url)
        .and_then(|endpoint| {
            let token = if needs_service(args.first().map(String::as_str)) {
                service_token(&endpoint, &token_file)
            } else {
                load_token(&token_file)
            }?;
            Ok(Client { endpoint, token })
        })
        .and_then(|client| run_command(&client, args));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// How long keyctl waits for the local service after opening Keyferry.
const SERVICE_START_WAIT: Duration = Duration::from_secs(20);
const SERVICE_POLL: Duration = Duration::from_millis(250);
const SERVICE_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Platform {
    Windows,
    MacOs,
    Other,
}

impl Platform {
    const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Other
        }
    }
}

/// Commands that need the local service. Local-only commands never open the app.
fn needs_service(command: Option<&str>) -> bool {
    matches!(
        command,
        Some(
            "devices"
                | "list"
                | "status"
                | "capabilities"
                | "actions"
                | "output-mode"
                | "display-orientation"
                | "screen-power"
                | "maintenance"
                | "forget-bluetooth"
                | "arm"
                | "disarm"
                | "cancel"
                | "outcome"
                | "events"
                | "follow"
                | "type"
                | "sequence"
                | "input-sequence"
                | "stream"
                | "file"
                | "files"
                | "file-status"
                | "file-clear"
        )
    )
}

/// The program and arguments that open the Keyferry app, which starts the service
/// (D-20260926-04). keyctl never starts keyferryd itself: that daemon would outlive the app.
fn app_launch(
    platform: Platform,
    keyctl: &Path,
    home: Option<&Path>,
    exists: impl Fn(&Path) -> bool,
) -> Option<(PathBuf, Vec<String>)> {
    match platform {
        Platform::Windows => {
            let app = keyctl.parent()?.join("keyferry.exe");
            exists(&app).then_some((app, Vec::new()))
        }
        Platform::MacOs => {
            let bundle = keyctl
                .ancestors()
                .find(|path| path.extension().is_some_and(|extension| extension == "app"))
                .map(Path::to_path_buf)
                .or_else(|| home.map(|home| home.join("Applications").join("Keyferry.app")))
                .filter(|bundle| exists(bundle))?;
            Some((
                PathBuf::from("/usr/bin/open"),
                vec!["-a".to_owned(), bundle.to_string_lossy().into_owned()],
            ))
        }
        Platform::Other => None,
    }
}

/// On Windows, Explorer launches the GUI as a shell broker. Starting it directly from keyctl
/// leaves a PowerShell caller waiting for the GUI descendant even after keyctl exits.
fn app_start_command(
    platform: Platform,
    program: &Path,
    args: &[String],
    system_root: Option<&Path>,
    exists: impl Fn(&Path) -> bool,
) -> Option<Command> {
    match platform {
        Platform::Windows => {
            if !args.is_empty() {
                return None;
            }
            let explorer = system_root?.join("explorer.exe");
            if !exists(&explorer) {
                return None;
            }
            let mut command = Command::new(explorer);
            command.arg(program);
            Some(command)
        }
        Platform::MacOs | Platform::Other => {
            let mut command = Command::new(program);
            command.args(args);
            Some(command)
        }
    }
}

fn loopback_address(endpoint: &Endpoint) -> Option<std::net::SocketAddr> {
    let address = endpoint.host.parse::<std::net::IpAddr>().ok()?;
    address
        .is_loopback()
        .then_some(std::net::SocketAddr::new(address, endpoint.port))
}

fn wait_until(limit: Duration, poll: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if ready() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(poll);
    }
}

/// Set once this process has reached the service or tried to open Keyferry; later failures,
/// such as the app closing mid-command, are reported and never reopen it.
static SERVICE_OPEN_SETTLED: AtomicBool = AtomicBool::new(false);

/// Opens Keyferry because the local service is not running, then waits a bounded time for it
/// to accept connections. Returns whether it did. A failure leaves the ordinary daemon error to
/// the caller's command.
fn open_service(endpoint: &Endpoint) -> bool {
    let Some(address) = loopback_address(endpoint) else {
        return false;
    };
    // Unit tests connect to closed loopback ports on purpose; they must never open a real app.
    if cfg!(test) || SERVICE_OPEN_SETTLED.swap(true, Ordering::AcqRel) {
        return false;
    }
    let Some((program, args)) = env::current_exe().ok().and_then(|keyctl| {
        app_launch(
            Platform::current(),
            &keyctl,
            env::var_os("HOME").map(PathBuf::from).as_deref(),
            Path::exists,
        )
    }) else {
        return false;
    };
    let system_root = env::var_os("SystemRoot").map(PathBuf::from);
    let Some(mut command) = app_start_command(
        Platform::current(),
        &program,
        &args,
        system_root.as_deref(),
        Path::is_file,
    ) else {
        eprintln!("keyctl: could not find the Windows shell; open Keyferry and try again");
        return false;
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if command.spawn().is_err() {
        eprintln!("keyctl: could not open Keyferry; open it and try again");
        return false;
    }
    eprintln!("keyctl: opened Keyferry");
    let started = wait_until(SERVICE_START_WAIT, SERVICE_POLL, || {
        TcpStream::connect_timeout(&address, SERVICE_CONNECT_TIMEOUT).is_ok()
    });
    if !started {
        eprintln!(
            "keyctl: Keyferry did not start its service within {} seconds",
            SERVICE_START_WAIT.as_secs()
        );
    }
    started
}

/// Loads the local bearer, opening Keyferry first when the service has never created it.
fn service_token(endpoint: &Endpoint, token_file: &Path) -> Result<String, ClientError> {
    load_token(token_file).or_else(|error| {
        if open_service(endpoint) {
            load_token(token_file)
        } else {
            Err(error)
        }
    })
}

fn load_token(path: &Path) -> Result<String, ClientError> {
    let token = fs::read_to_string(path)
        .map_err(|error| {
            ClientError(format!(
                "cannot read token file {}: {error}",
                path.display()
            ))
        })?
        .trim()
        .to_owned();
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return Err(ClientError("token file is empty or malformed".to_owned()));
    }
    Ok(token)
}

fn take_named_option(args: &mut Vec<String>, name: &str) -> Option<String> {
    let position = args.iter().position(|arg| arg == name)?;
    if position + 1 >= args.len() {
        return None;
    }
    args.remove(position);
    Some(args.remove(position))
}

/// Explains an offline device. The daemon already uses a stick that another of the owner's
/// controllers holds on Tailscale (`link_path` "tailnet", `via` names that controller), so an
/// offline stick is unreachable from here by any route.
fn offline_hint(devices: &Value) -> Option<&'static str> {
    let offline = devices["devices"]
        .as_array()?
        .iter()
        .any(|device| device["link"] != "authenticated");
    offline.then_some(
        "keyctl: an offline device is unplugged, out of range, or held by a controller this \
         computer cannot reach over Tailscale. A stick held by another of your controllers is \
         used through it automatically and shows link_path \"tailnet\".",
    )
}

fn run_command(client: &Client, args: Vec<String>) -> Result<(), ClientError> {
    match args.first().map(String::as_str) {
        Some("file") => {
            if args.len() != 3 {
                return Err(ClientError("usage: keyctl file DEVICE PATH".to_owned()));
            }
            let device = &args[1];
            let file = fs::File::open(&args[2])
                .map_err(|error| ClientError(format!("cannot read file: {error}")))?;
            let mut bytes = Vec::new();
            file.take((keyferry_protocol::file::MAX_FILE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|error| ClientError(format!("cannot read file: {error}")))?;
            if bytes.len() > keyferry_protocol::file::MAX_FILE_BYTES {
                return Err(ClientError(format!(
                    "file exceeds {} bytes",
                    keyferry_protocol::file::MAX_FILE_BYTES
                )));
            }
            let body = serde_json::json!({"bytes": bytes}).to_string();
            print_json(&client.request(
                "POST",
                &format!("/v1/devices/{device}/file"),
                Some(&body),
            )?)
        }
        Some("files") => {
            if args.len() < 3 || args.len() > 2 + keyferry_protocol::file_set::MAX_FILES {
                return Err(ClientError(
                    "usage: keyctl files DEVICE PATH... (1..16 files)".to_owned(),
                ));
            }
            let device = &args[1];
            let paths = &args[2..];
            let names = paths
                .iter()
                .map(|path| {
                    std::path::Path::new(path)
                        .file_name()
                        .and_then(|value| value.to_str())
                        .ok_or_else(|| ClientError("file path has no valid basename".to_owned()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            keyferry_protocol::file_set::validate_names(&names)
                .map_err(|_| ClientError("invalid file set: names or count".to_owned()))?;
            let mut files = Vec::new();
            let mut total = 0usize;
            for (path, name) in paths.iter().zip(names) {
                if !fs::metadata(path)
                    .map_err(|error| ClientError(format!("cannot inspect file: {error}")))?
                    .is_file()
                {
                    return Err(ClientError("file path is not a regular file".to_owned()));
                }
                let file = fs::File::open(path)
                    .map_err(|error| ClientError(format!("cannot read file: {error}")))?;
                if !file
                    .metadata()
                    .map_err(|error| ClientError(format!("cannot inspect file: {error}")))?
                    .is_file()
                {
                    return Err(ClientError("file path is not a regular file".to_owned()));
                }
                let mut bytes = Vec::new();
                file.take((keyferry_protocol::file_set::MAX_FILE_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|error| ClientError(format!("cannot read file: {error}")))?;
                total = total
                    .checked_add(bytes.len())
                    .ok_or_else(|| ClientError("file set exceeds limit".to_owned()))?;
                if total > keyferry_protocol::file_set::MAX_FILE_BYTES {
                    return Err(ClientError("file set exceeds 262144 bytes".to_owned()));
                }
                files.push(keyferry_protocol::file_set::File {
                    name: name.to_owned(),
                    bytes,
                });
            }
            keyferry_protocol::file_set::encode_bundle(&files).map_err(|_| {
                ClientError("invalid file set: names, count, or total size".to_owned())
            })?;
            let body = serde_json::json!({"files": files.iter().map(|file| serde_json::json!({"name":file.name,"bytes":file.bytes})).collect::<Vec<_>>()}).to_string();
            print_json(&client.request(
                "POST",
                &format!("/v1/devices/{device}/files"),
                Some(&body),
            )?)
        }
        Some("file-status") | Some("file-clear") => {
            if args.len() != 2 {
                return Err(ClientError(
                    "usage: keyctl file-status|file-clear DEVICE".to_owned(),
                ));
            }
            let method = if args[0] == "file-clear" {
                "DELETE"
            } else {
                "GET"
            };
            let device = &args[1];
            let view: serde_json::Value = serde_json::from_str(&client.request(
                "GET",
                &format!("/v1/devices/{device}"),
                None,
            )?)
            .map_err(|_| ClientError("device status response is invalid".to_owned()))?;
            let endpoint = if view["firmware"]["usb_file_set_v2"] == true {
                "files"
            } else {
                "file"
            };
            print_json(&client.request(
                method,
                &format!("/v1/devices/{device}/{endpoint}"),
                None,
            )?)
        }
        Some("capabilities") => {
            if args.len() != 1 {
                return Err(ClientError("usage: keyctl capabilities".to_owned()));
            }
            print_json(&client.request("GET", "/v1/capabilities", None)?)
        }
        Some("status") if args.len() == 2 => {
            print_json(&client.request("GET", &format!("/v1/devices/{}", args[1]), None)?)
        }
        Some("devices") | Some("list") | Some("status") => {
            if args.len() != 1 {
                return Err(ClientError(
                    "usage: keyctl devices | status [DEVICE]".to_owned(),
                ));
            }
            let devices = client.request("GET", "/v1/devices", None)?;
            let parsed = serde_json::from_str(&devices).unwrap_or(Value::Null);
            if let Some(hint) = offline_hint(&parsed) {
                eprintln!("{hint}");
            }
            print_json(&devices)
        }
        Some("actions") => {
            let device = required(&args, 1, "actions DEVICE  (JSON is read from stdin)")?;
            if args.len() > 2 {
                return Err(ClientError(ARGV_PAYLOAD_REFUSED.to_owned()));
            }
            let raw = read_payload_from_stdin()?;
            let value: Value = serde_json::from_str(&raw)
                .map_err(|error| ClientError(format!("invalid actions JSON: {error}")))?;
            let body = if value.is_array() {
                serde_json::json!({ "actions": value })
            } else {
                value
            };
            let body =
                serde_json::to_string(&body).map_err(|error| ClientError(error.to_string()))?;
            print_json(&client.request(
                "POST",
                &format!("/v1/devices/{device}/actions"),
                Some(&body),
            )?)
        }
        Some("output-mode") => {
            let device = required(&args, 1, "output-mode DEVICE [usb-hid|ble-hid]")?;
            if args.len() > 3 {
                return Err(ClientError(
                    "usage: keyctl output-mode DEVICE [usb-hid|ble-hid]".to_owned(),
                ));
            }
            let path = format!("/v1/devices/{device}/output-mode");
            match args.get(2).map(String::as_str) {
                None => print_json(&client.request("GET", &path, None)?),
                Some(mode @ ("usb-hid" | "ble-hid")) => {
                    let body = serde_json::to_string(&OutputModeRequest { mode })
                        .map_err(|error| ClientError(error.to_string()))?;
                    print_json(&client.request("POST", &path, Some(&body))?)
                }
                Some(_) => Err(ClientError(
                    "output mode must be usb-hid or ble-hid".to_owned(),
                )),
            }
        }
        Some("display-orientation") => {
            let device = required(&args, 1, "display-orientation DEVICE [normal|rotated-180]")?;
            if args.len() > 3 {
                return Err(ClientError(
                    "usage: keyctl display-orientation DEVICE [normal|rotated-180]".to_owned(),
                ));
            }
            let path = format!("/v1/devices/{device}/display-orientation");
            match args.get(2).map(String::as_str) {
                None => print_json(&client.request("GET", &path, None)?),
                Some(orientation @ ("normal" | "rotated-180")) => {
                    let body = serde_json::to_string(&DisplayOrientationRequest { orientation })
                        .map_err(|error| ClientError(error.to_string()))?;
                    print_json(&client.request("POST", &path, Some(&body))?)
                }
                Some(_) => Err(ClientError(
                    "display orientation must be normal or rotated-180".to_owned(),
                )),
            }
        }
        Some("screen-power") => {
            let device = required(&args, 1, "screen-power DEVICE [on|off]")?;
            if args.len() > 3 {
                return Err(ClientError(
                    "usage: keyctl screen-power DEVICE [on|off]".to_owned(),
                ));
            }
            let path = format!("/v1/devices/{device}/screen-power");
            match args.get(2).map(String::as_str) {
                None => {
                    let response = client.request("GET", &path, None)?;
                    print_screen_power_response(&response, &device, None)
                }
                Some(power @ ("on" | "off")) => {
                    let body = serde_json::to_string(&ScreenPowerRequest { power })
                        .map_err(|error| ClientError(error.to_string()))?;
                    let response = client.request("POST", &path, Some(&body))?;
                    print_screen_power_response(&response, &device, Some(power))
                }
                Some(_) => Err(ClientError("screen power must be on or off".to_owned())),
            }
        }
        Some("maintenance") => {
            if args.len() != 3 || !matches!(args[2].as_str(), "begin" | "finish") {
                return Err(ClientError(
                    "usage: keyctl maintenance DEVICE begin|finish".to_owned(),
                ));
            }
            let path = format!("/v1/devices/{}/maintenance/{}", args[1], args[2]);
            print_json(&client.request("POST", &path, None)?)
        }
        Some("forget-bluetooth") => {
            let device = required(&args, 1, "forget-bluetooth DEVICE")?;
            if args.len() != 2 {
                return Err(ClientError(
                    "usage: keyctl forget-bluetooth DEVICE".to_owned(),
                ));
            }
            print_json(&client.request(
                "POST",
                &format!("/v1/devices/{device}/ble-hid-bond/reset"),
                None,
            )?)
        }
        Some("arm") => {
            let device = required(&args, 1, "arm DEVICE [POLICY]")?;
            let policy = args.get(2).map(String::as_str).unwrap_or("command-scoped");
            let body = serde_json::to_string(&ArmRequest { policy })
                .map_err(|error| ClientError(error.to_string()))?;
            print_json(&client.request(
                "POST",
                &format!("/v1/devices/{device}/arm"),
                Some(&body),
            )?)
        }
        Some("disarm") => {
            let device = required(&args, 1, "disarm DEVICE")?;
            print_json(&client.request("POST", &format!("/v1/devices/{device}/disarm"), None)?)
        }
        Some("cancel") => {
            let device = required(&args, 1, "cancel DEVICE [COMMAND_ID]")?;
            let body = serde_json::to_string(&CancelRequest {
                command_id: args.get(2).cloned(),
            })
            .map_err(|error| ClientError(error.to_string()))?;
            print_json(&client.request(
                "POST",
                &format!("/v1/devices/{device}/cancel"),
                Some(&body),
            )?)
        }
        Some("outcome") => {
            let device = required(&args, 1, "outcome DEVICE COMMAND_ID")?;
            let command_id = required(&args, 2, "outcome DEVICE COMMAND_ID")?;
            if args.len() != 3 {
                return Err(ClientError(
                    "usage: keyctl outcome DEVICE COMMAND_ID".to_owned(),
                ));
            }
            print_json(&client.request(
                "GET",
                &format!("/v1/devices/{device}/commands/{command_id}"),
                None,
            )?)
        }
        Some("events") | Some("follow") => client.follow_events(),
        Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(command) => Err(ClientError(format!(
            "unknown command: {command}\n{}",
            help_text()
        ))),
    }
}

/// Dictated text and action bodies are listed assets in `SECURITY.md`, which
/// forbids putting them where the process list can expose them. They therefore
/// arrive on stdin, never on argv.
const ARGV_PAYLOAD_REFUSED: &str = "refusing to read the payload from argv: the process list and shell history expose command-line arguments. Pipe it on stdin instead, e.g. `keyctl type DEVICE < message.txt`.";

fn read_payload_from_stdin() -> Result<String, ClientError> {
    use std::io::Read as _;
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|error| ClientError(format!("failed to read stdin: {error}")))?;
    Ok(buffer.trim_end_matches(['\n', '\r']).to_owned())
}

fn required(args: &[String], index: usize, usage: &str) -> Result<String, ClientError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| ClientError(format!("usage: keyctl {usage}")))
}

fn print_json(body: &str) -> Result<(), ClientError> {
    match serde_json::from_str::<Value>(body) {
        Ok(value) => println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(|error| ClientError(error.to_string()))?
        ),
        Err(_) => println!("{body}"),
    }
    Ok(())
}

fn print_screen_power_response(
    body: &str,
    device_id: &str,
    requested: Option<&str>,
) -> Result<(), ClientError> {
    let value: Value = serde_json::from_str(body)
        .map_err(|_| ClientError("invalid screen-power response".to_owned()))?;
    if value.get("schema").and_then(Value::as_str) != Some("keyferry.screen-power.v1")
        || value.get("device_id").and_then(Value::as_str) != Some(device_id)
        || !matches!(
            value.get("active").and_then(Value::as_str),
            Some("on" | "off")
        )
        || !matches!(
            value.get("stored").and_then(Value::as_str),
            Some("on" | "off")
        )
        || value.get("available").and_then(Value::as_bool).is_none()
        || requested.is_some_and(|power| value.get("stored").and_then(Value::as_str) != Some(power))
    {
        return Err(ClientError(
            "screen-power response did not match the selected device or request".to_owned(),
        ));
    }
    print_json(body)
}

impl Client {
    fn connect(&self) -> Result<TcpStream, ClientError> {
        let address = format!("{}:{}", self.endpoint.host, self.endpoint.port)
            .parse()
            .map_err(|error| ClientError(format!("invalid endpoint: {error}")))?;
        // A refused first connection sent nothing, so after opening Keyferry it is tried once more.
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
            .or_else(|error| {
                if open_service(&self.endpoint) {
                    TcpStream::connect_timeout(&address, Duration::from_secs(5))
                } else {
                    Err(error)
                }
            })
            .map_err(|error| ClientError(format!("cannot connect to daemon: {error}")))?;
        SERVICE_OPEN_SETTLED.store(true, Ordering::Release);
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| ClientError(error.to_string()))?;
        Ok(stream)
    }

    fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<String, ClientError> {
        let response = self.request_raw(method, path, body)?;
        if response.status >= 400 {
            return Err(ClientError(format!(
                "daemon returned HTTP {}: {}",
                response.status,
                response.body.trim()
            )));
        }
        Ok(response.body)
    }

    fn request_raw(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<HttpResponse, ClientError> {
        let mut stream = self.connect()?;
        if path.ends_with("/file") || path.ends_with("/files") {
            stream
                .set_read_timeout(Some(Duration::from_secs(150)))
                .map_err(|error| ClientError(error.to_string()))?;
        }
        let body = body.unwrap_or("");
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n{}\r\n{body}",
            self.endpoint.host,
            self.token,
            body.len(),
            if body.is_empty() { "" } else { "Content-Type: application/json\r\n" },
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|error| ClientError(format!("cannot send request: {error}")))?;
        read_response(&mut stream)
    }

    fn sequence_post(&self, path: &str, body: &str) -> Result<HttpResponse, SequencePostError> {
        let mut stream = self.connect().map_err(|_| SequencePostError {
            may_have_sent: false,
        })?;
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{body}",
            self.endpoint.host,
            self.token,
            body.len(),
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|_| SequencePostError {
                may_have_sent: true,
            })?;
        read_response(&mut stream).map_err(|_| SequencePostError {
            may_have_sent: true,
        })
    }

    fn follow_events(&self) -> Result<(), ClientError> {
        let mut stream = self.connect()?;
        stream
            .set_read_timeout(None)
            .map_err(|error| ClientError(error.to_string()))?;
        let request = format!(
            "GET /v1/events HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n\r\n",
            self.endpoint.host, self.token
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|error| ClientError(format!("cannot send request: {error}")))?;
        let response = read_headers(&mut stream)?;
        if response.status >= 400 {
            return Err(ClientError(format!(
                "daemon returned HTTP {}",
                response.status
            )));
        }
        let mut output = io::stdout().lock();
        if response.chunked {
            loop {
                let size = read_chunk_size(&mut stream)?;
                if size == 0 {
                    break;
                }
                let mut chunk = vec![0_u8; size];
                stream
                    .read_exact(&mut chunk)
                    .map_err(|error| ClientError(format!("event stream failed: {error}")))?;
                let mut delimiter = [0_u8; 2];
                stream
                    .read_exact(&mut delimiter)
                    .map_err(|error| ClientError(format!("event stream failed: {error}")))?;
                if delimiter != *b"\r\n" {
                    return Err(ClientError("malformed event stream chunk".to_owned()));
                }
                output
                    .write_all(&chunk)
                    .map_err(|error| ClientError(error.to_string()))?;
                output
                    .flush()
                    .map_err(|error| ClientError(error.to_string()))?;
            }
        } else {
            let mut buffer = [0_u8; 4096];
            loop {
                let count = stream
                    .read(&mut buffer)
                    .map_err(|error| ClientError(format!("event stream failed: {error}")))?;
                if count == 0 {
                    break;
                }
                output
                    .write_all(&buffer[..count])
                    .map_err(|error| ClientError(error.to_string()))?;
                output
                    .flush()
                    .map_err(|error| ClientError(error.to_string()))?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    body: String,
}

fn read_response(stream: &mut TcpStream) -> Result<HttpResponse, ClientError> {
    let headers = read_headers(stream)?;
    let mut body = Vec::new();
    stream
        .read_to_end(&mut body)
        .map_err(|error| ClientError(format!("cannot read response: {error}")))?;
    let body = if headers.chunked {
        decode_chunked(&body)?
    } else {
        body
    };
    let _ = stream.shutdown(Shutdown::Both);
    Ok(HttpResponse {
        status: headers.status,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

struct ResponseHeaders {
    status: u16,
    chunked: bool,
}

fn read_headers(stream: &mut TcpStream) -> Result<ResponseHeaders, ClientError> {
    let mut bytes = Vec::new();
    let mut one = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut one)
            .map_err(|error| ClientError(format!("cannot read HTTP headers: {error}")))?;
        bytes.push(one[0]);
        if bytes.len() > 64 * 1024 {
            return Err(ClientError("HTTP headers exceed 64 KiB".to_owned()));
        }
    }
    let text = String::from_utf8_lossy(&bytes);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| ClientError("malformed HTTP status line".to_owned()))?;
    let chunked = text
        .lines()
        .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked"));
    Ok(ResponseHeaders { status, chunked })
}

fn decode_chunked(input: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut output = Vec::new();
    let mut position = 0;
    loop {
        let line_end = input[position..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| ClientError("malformed chunked response".to_owned()))?
            + position;
        let size = usize::from_str_radix(
            std::str::from_utf8(&input[position..line_end])
                .map_err(|_| ClientError("malformed chunk size".to_owned()))?
                .trim(),
            16,
        )
        .map_err(|_| ClientError("malformed chunk size".to_owned()))?;
        position = line_end + 2;
        if size == 0 {
            break;
        }
        let end = position
            .checked_add(size)
            .ok_or_else(|| ClientError("chunk size overflow".to_owned()))?;
        if end + 2 > input.len() || &input[end..end + 2] != b"\r\n" {
            return Err(ClientError("truncated chunked response".to_owned()));
        }
        output.extend_from_slice(&input[position..end]);
        position = end + 2;
    }
    Ok(output)
}

fn read_chunk_size(stream: &mut TcpStream) -> Result<usize, ClientError> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    while !line.ends_with(b"\r\n") {
        stream
            .read_exact(&mut byte)
            .map_err(|error| ClientError(format!("event stream failed: {error}")))?;
        line.push(byte[0]);
        if line.len() > 64 * 1024 {
            return Err(ClientError(
                "event stream chunk header exceeds 64 KiB".to_owned(),
            ));
        }
    }
    let line = std::str::from_utf8(&line[..line.len() - 2])
        .map_err(|_| ClientError("malformed event stream chunk size".to_owned()))?;
    usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16)
        .map_err(|_| ClientError("malformed event stream chunk size".to_owned()))
}

fn parse_endpoint(value: &str) -> Result<Endpoint, ClientError> {
    let authority = value
        .strip_prefix("http://")
        .ok_or_else(|| ClientError("keyctl accepts only http://127.0.0.1 endpoints".to_owned()))?
        .split('/')
        .next()
        .unwrap_or_default();
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| ClientError("endpoint must include a port".to_owned()))?;
    if host != "127.0.0.1" {
        return Err(ClientError(
            "keyctl refuses non-loopback endpoints".to_owned(),
        ));
    }
    let port = port
        .parse()
        .map_err(|_| ClientError("endpoint port is invalid".to_owned()))?;
    if port == 0 {
        return Err(ClientError("endpoint port must be nonzero".to_owned()));
    }
    Ok(Endpoint {
        host: host.to_owned(),
        port,
    })
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
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("state")
        .join("keyferry")
        .join("token")
}

fn help_text() -> &'static str {
    "keyctl [--url http://127.0.0.1:8042] [--token-file PATH] <command>\n  devices | list | status [DEVICE]  (exact selected-device status when DEVICE is given)\n  capabilities  (read local daemon capabilities)\n  file DEVICE PATH  (publish one read-only MESSAGE.TXT)\n  files DEVICE PATH...  (replace USB drive with 1..16 named files, 256 KiB total; requires v2 firmware)\n  file-status DEVICE  (list files on v2 firmware)\n  file-clear DEVICE  (clear whole USB file set)\n  keys  (local machine-readable canonical key registry)\n  type DEVICE [--key-gap-ms N] [--key-down-ms N] [--send-after-seconds N] [--detach]\n  type --help  (text is read only from stdin)\n  stream DEVICE --input FILE [--validate]  (unbounded file-backed text stream)\n  stream --help\n  actions DEVICE  (JSON is read from stdin)\n  sequence DEVICE [--input json] [--detach]  (JSON is read from stdin)\n  sequence --help | --example | --validate  (local; no device contact)\n  input-sequence DEVICE [--input PATH] [--detach]\n  input-sequence --describe | --validate [--input PATH]  (local; no device contact)\n  local-status --owner-kit PATH [--device UUID]  (direct USB; exact UUID for multi-device kits; password from stdin)\n  local-probe --owner-kit PATH [--device UUID] [--samples N]  (read-only USB probe metadata; passphrase from stdin)\n  local-recover --owner-kit PATH [--device UUID] ACTION  (exact USB stick; password from stdin; restart-network|forget-bluetooth|cancel-enrollment|usb-hid|ble-hid|reboot; some actions restart the stick; UNKNOWN is never retried automatically)\n  output-mode DEVICE [usb-hid|ble-hid]  (read or persist output; a change restarts the stick)\n  display-orientation DEVICE [normal|rotated-180]  (read or persist LCD orientation; a change restarts the stick)\n  screen-power DEVICE [on|off]  (read or persist live LCD power)\n  maintenance DEVICE begin|finish  (pause/resume exact local stick around direct USB policy work)\n  forget-bluetooth DEVICE  (forget Bluetooth keyboard output bond; distinct from USB local-recover forget-bluetooth; restarts into pairing)\n  arm DEVICE [command-scoped|temporary|always-ready]\n  disarm DEVICE\n  cancel DEVICE [COMMAND_ID]\n  outcome DEVICE COMMAND_ID\n  events"
}

fn run_local_helper(args: &[String]) -> u8 {
    if !valid_local_helper_args(args) {
        emit_json_line(&serde_json::json!({
            "schema": "keyferry.local-cli-error.v1",
            "outcome": "REJECTED",
            "error": "input.usage",
        }));
        return 20;
    }
    let helper = match local_helper_path() {
        Ok(path) => path,
        Err(code) => {
            emit_json_line(&serde_json::json!({
                "schema": "keyferry.local-cli-error.v1",
                "outcome": "REJECTED",
                "error": code,
            }));
            return 23;
        }
    };
    match Command::new(helper)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(status) if status.success() => 0,
        Ok(_) => 21,
        Err(_) => {
            emit_json_line(&serde_json::json!({
                "schema": "keyferry.local-cli-error.v1",
                "outcome": "REJECTED",
                "error": "local.helper_unavailable",
            }));
            23
        }
    }
}

fn canonical_device_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|uuid| !uuid.is_nil() && uuid.hyphenated().to_string() == value)
}

fn local_recovery_action(action: &str) -> bool {
    matches!(
        action,
        "restart-network"
            | "forget-bluetooth"
            | "cancel-enrollment"
            | "usb-hid"
            | "ble-hid"
            | "reboot"
    )
}

fn valid_local_helper_args(args: &[String]) -> bool {
    let owner_kit = args.get(1).is_some_and(|value| value == "--owner-kit")
        && args.get(2).is_some_and(|value| !value.is_empty());
    if !owner_kit {
        return false;
    }
    match args.first().map(String::as_str) {
        Some("local-status") => {
            args.len() == 3
                || (args.len() == 5 && args[3] == "--device" && canonical_device_uuid(&args[4]))
        }
        Some("local-recover") => {
            (args.len() == 4 && local_recovery_action(&args[3]))
                || (args.len() == 6
                    && args[3] == "--device"
                    && canonical_device_uuid(&args[4])
                    && local_recovery_action(&args[5]))
        }
        // The helper owns read-only probe option validation before opening USB.
        Some("local-probe") => args.len() >= 3,
        _ => false,
    }
}

fn local_helper_path() -> Result<PathBuf, &'static str> {
    if let Some(path) = env::var_os("KEYFERRY_PAIRING_EXE").map(PathBuf::from) {
        return Ok(path);
    }
    let current = env::current_exe().map_err(|_| "local.helper_unavailable")?;
    let directory = current.parent().ok_or("local.helper_unavailable")?;
    Ok(directory.join(if cfg!(windows) {
        "keyferry-pairing.exe"
    } else {
        "keyferry-pairing"
    }))
}

fn type_help_text() -> &'static str {
    "keyctl type DEVICE [--key-gap-ms N] [--key-down-ms N] [--send-after-seconds N] [--detach]\n  Reads literal text from stdin and submits one command-scoped keyboard sequence.\n  --key-down-ms N         hold each key for 5..100 ms (default 12)\n  --key-gap-ms N          release gap between keys, 5..100 ms (default 40)\n  --send-after-seconds N  wait 0..10 seconds with all keys released before typing\n  --detach                return after the daemon accepts the command\n  Output is one compact keyferry.command-result.v2 JSON object with output transport and release evidence.\n  Text is never accepted on argv and commands are never automatically retried.\n  One command accepts at most 4096 supported windows-us characters and 60 seconds planned time."
}

fn stream_help_text() -> &'static str {
    "keyctl stream DEVICE --input FILE [--key-gap-ms N] [--key-down-ms N] [--send-after-seconds N] [--unsupported reject|replace] [--validate]\n  Streams windows-us text as bounded child commands with no configured total-length limit.\n  The file is preflighted using bounded memory before any device contact.\n  --unsupported reject is the default and emits nothing when any character is unsupported.\n  --unsupported replace explicitly replaces each unsupported character with one visible '?'.\n  --validate performs the preflight only.\n  Each child is submitted once; interruption or uncertain delivery stops the parent and is never retried.\n  Output is compact JSONL metadata and never includes source text.\n  Directly supported plain text is printable ASCII, TAB, LF, and CR."
}

#[derive(Clone, Debug)]
struct StreamOptions {
    input: PathBuf,
    key_down_ms: u16,
    key_gap_ms: u16,
    send_after_seconds: u16,
    unsupported: UnsupportedTextPolicy,
    validate: bool,
}

#[derive(Clone, Copy, Debug)]
struct StreamSummary {
    bytes: u64,
    scalars: u64,
    children: u64,
    gestures: u64,
    replacements: u64,
}

#[derive(Debug, Deserialize)]
struct StreamCapabilities {
    epoch: String,
    text_stream: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StreamCursor {
    bytes: String,
    scalars: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StreamConfirmedPrefix {
    bytes: String,
    scalars: String,
    children: String,
    gestures: String,
}

#[derive(Clone, Debug, Deserialize)]
struct StreamCurrentChild {
    command_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct StreamReceipt {
    schema: String,
    epoch: String,
    job_id: String,
    outcome: Option<SequenceOutcome>,
    terminal: bool,
    confirmed_prefix: StreamConfirmedPrefix,
    not_dispatched_from: StreamCursor,
    next_index: String,
    current_child: Option<StreamCurrentChild>,
    possible_start: bool,
    terminal_zero_confirmed: bool,
}

fn parse_stream_options(args: &[String]) -> Result<StreamOptions, &'static str> {
    let mut input = None;
    let mut key_down_ms = u64::from(TypingTiming::DESKTOP_SAFE.key_down_ms);
    let mut key_gap_ms = u64::from(TypingTiming::DESKTOP_SAFE.release_gap_ms);
    let mut send_after_seconds = 0_u64;
    let mut validate = false;
    let mut unsupported = UnsupportedTextPolicy::Reject;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--input" if input.is_none() && index + 1 < args.len() => {
                input = Some(PathBuf::from(&args[index + 1]));
                index += 1;
            }
            "--key-down-ms" | "--key-gap-ms" | "--send-after-seconds" if index + 1 < args.len() => {
                let value = args[index + 1].parse::<u64>().map_err(|_| "input.timing")?;
                match args[index].as_str() {
                    "--key-down-ms" => key_down_ms = value,
                    "--key-gap-ms" => key_gap_ms = value,
                    _ => send_after_seconds = value,
                }
                index += 1;
            }
            "--unsupported" if index + 1 < args.len() => {
                unsupported = match args[index + 1].as_str() {
                    "reject" => UnsupportedTextPolicy::Reject,
                    "replace" => UnsupportedTextPolicy::Replace,
                    _ => return Err("input.unsupported_policy"),
                };
                index += 1;
            }
            "--validate" if !validate => validate = true,
            _ => return Err("input.usage"),
        }
        index += 1;
    }
    if !(5..=100).contains(&key_down_ms)
        || !(5..=100).contains(&key_gap_ms)
        || send_after_seconds > 10
    {
        return Err("input.timing");
    }
    Ok(StreamOptions {
        input: input.ok_or("input.usage")?,
        key_down_ms: key_down_ms as u16,
        key_gap_ms: key_gap_ms as u16,
        send_after_seconds: send_after_seconds as u16,
        unsupported,
        validate,
    })
}

fn stream_timing(options: &StreamOptions) -> TypingTiming {
    TypingTiming {
        key_down_ms: options.key_down_ms,
        release_gap_ms: options.key_gap_ms,
    }
}

fn preflight_stream(options: &StreamOptions) -> Result<StreamSummary, TextStreamError> {
    let file = fs::File::open(&options.input).map_err(|_| TextStreamError {
        kind: keyferry_layouts::text_stream::TextStreamErrorKind::SourceIo,
        byte_offset: 0,
        scalar_offset: 0,
    })?;
    let mut reader = TextStreamReader::with_unsupported_policy(
        file,
        stream_timing(options),
        options.unsupported,
    )?;
    let mut summary = StreamSummary {
        bytes: 0,
        scalars: 0,
        children: 0,
        gestures: 0,
        replacements: 0,
    };
    while let Some(part) = reader.next_part()? {
        summary.bytes = part.end_bytes;
        summary.scalars = part.end_scalars;
        summary.children = summary.children.saturating_add(1);
        summary.gestures = summary.gestures.saturating_add(u64::from(part.gestures));
        summary.replacements = summary
            .replacements
            .saturating_add(u64::from(part.replacements));
    }
    if summary.children == 0 {
        return Err(TextStreamError {
            kind: keyferry_layouts::text_stream::TextStreamErrorKind::Empty,
            byte_offset: 0,
            scalar_offset: 0,
        });
    }
    Ok(summary)
}

fn run_stream_validate(device: &str, options: &StreamOptions) -> u8 {
    match preflight_stream(options) {
        Ok(summary) => {
            emit_json_line(&serde_json::json!({
                "schema": "keyferry.text-stream-validation.v1",
                "device_id": device,
                "valid": true,
                "source_bytes": summary.bytes.to_string(),
                "source_scalars": summary.scalars.to_string(),
                "children": summary.children.to_string(),
                "gestures": summary.gestures.to_string(),
                "unsupported": options.unsupported,
                "replacements": summary.replacements.to_string(),
                "error": Value::Null,
            }));
            0
        }
        Err(error) => {
            emit_stream_error(
                device,
                None,
                error.code(),
                Some((error.byte_offset, error.scalar_offset)),
            );
            20
        }
    }
}

fn run_stream(client: &Client, device: &str, options: &StreamOptions) -> u8 {
    let summary = match preflight_stream(options) {
        Ok(summary) => summary,
        Err(error) => {
            emit_stream_error(
                device,
                None,
                error.code(),
                Some((error.byte_offset, error.scalar_offset)),
            );
            return 20;
        }
    };
    let source_metadata = match stream_source_metadata(&options.input) {
        Ok(metadata) => metadata,
        Err(code) => {
            emit_stream_error(device, None, code, None);
            return 20;
        }
    };
    let capabilities = match client.request("GET", "/v1/capabilities", None) {
        Ok(body) => match serde_json::from_str::<StreamCapabilities>(&body) {
            Ok(value) if value.text_stream == TEXT_STREAM_SCHEMA_V1 => value,
            _ => {
                emit_stream_error(device, None, "protocol.capability", None);
                return 25;
            }
        },
        Err(_) => {
            emit_stream_error(device, None, "daemon.unavailable", None);
            return 23;
        }
    };
    let job_id = uuid::Uuid::now_v7().to_string();
    let create = serde_json::json!({
        "schema": TEXT_STREAM_SCHEMA_V1,
        "epoch": capabilities.epoch,
        "job_id": job_id,
        "profile": "windows-us",
        "key_down_ms": options.key_down_ms,
        "key_gap_ms": options.key_gap_ms,
        "send_after_seconds": options.send_after_seconds,
        "source_kind": "text",
        "validation": "preflight",
        "unsupported": options.unsupported,
    });
    let create_body = serde_json::to_string(&create).expect("stream create serialization");
    let path = format!("/v1/devices/{device}/text-streams");
    let response = match client.sequence_post(&path, &create_body) {
        Ok(response) if response.status < 400 => response,
        Ok(response) => {
            emit_stream_error(
                device,
                Some(&job_id),
                http_error_code(response.status),
                None,
            );
            return http_exit_code(response.status);
        }
        Err(_) => {
            emit_stream_error(device, Some(&job_id), "stream.create_unknown", None);
            return 12;
        }
    };
    let mut receipt = match parse_stream_receipt(&response.body, &capabilities.epoch, &job_id) {
        Ok(receipt) => receipt,
        Err(code) => {
            emit_stream_error(device, Some(&job_id), code, None);
            return 25;
        }
    };
    emit_json_line(&serde_json::json!({
        "schema": "keyferry.text-stream-event.v1",
        "event": "created",
        "job_id": job_id,
        "device_id": device,
        "source_bytes": summary.bytes.to_string(),
        "source_scalars": summary.scalars.to_string(),
        "children": summary.children.to_string(),
        "gestures": summary.gestures.to_string(),
        "unsupported": options.unsupported,
        "replacements": summary.replacements.to_string(),
    }));

    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupt_handler = Arc::clone(&interrupted);
    if ctrlc::set_handler(move || interrupt_handler.store(true, Ordering::Release)).is_err() {
        emit_stream_error(device, Some(&job_id), "internal.interrupt_handler", None);
        return 25;
    }
    let file = match fs::File::open(&options.input) {
        Ok(file) => file,
        Err(_) => {
            cancel_stream_best_effort(client, device, &job_id, &capabilities.epoch, "source_io");
            emit_stream_error(device, Some(&job_id), "input.source_io", None);
            return 20;
        }
    };
    let mut reader = match TextStreamReader::with_unsupported_policy(
        file,
        stream_timing(options),
        options.unsupported,
    ) {
        Ok(reader) => reader,
        Err(error) => {
            cancel_stream_best_effort(
                client,
                device,
                &job_id,
                &capabilities.epoch,
                "source_invalid",
            );
            emit_stream_error(device, Some(&job_id), error.code(), None);
            return 20;
        }
    };
    let mut index = 0_u64;
    loop {
        if interrupted.load(Ordering::Acquire) {
            cancel_stream_best_effort(client, device, &job_id, &capabilities.epoch, "user_cancel");
            return await_stream_terminal(
                client,
                device,
                &job_id,
                &capabilities.epoch,
                receipt,
                &interrupted,
            );
        }
        if stream_source_metadata(&options.input).as_ref() != Ok(&source_metadata) {
            cancel_stream_best_effort(
                client,
                device,
                &job_id,
                &capabilities.epoch,
                "source_changed",
            );
            return emit_stream_failure(
                device,
                &job_id,
                "input.source_changed",
                None,
                (index > 0).then_some(&receipt),
                20,
            );
        }
        let part = match reader.next_part() {
            Ok(Some(part)) => part,
            Ok(None) => {
                if receipt.terminal {
                    return emit_stream_terminal(device, &receipt);
                }
                let body = serde_json::json!({
                    "epoch": capabilities.epoch,
                    "next_index": index.to_string(),
                    "final_position": {"bytes": summary.bytes.to_string(), "scalars": summary.scalars.to_string()},
                });
                let body = serde_json::to_string(&body).expect("stream finish serialization");
                let path = format!("/v1/devices/{device}/text-streams/{job_id}/finish");
                return match client.request_raw("POST", &path, Some(&body)) {
                    Ok(response) if response.status < 400 => {
                        match parse_stream_receipt(&response.body, &capabilities.epoch, &job_id) {
                            Ok(final_receipt) => emit_stream_terminal(device, &final_receipt),
                            Err(code) => {
                                emit_stream_failure(device, &job_id, code, None, Some(&receipt), 25)
                            }
                        }
                    }
                    Ok(response) => emit_stream_failure(
                        device,
                        &job_id,
                        http_error_code(response.status),
                        None,
                        Some(&receipt),
                        http_exit_code(response.status),
                    ),
                    Err(_) => emit_stream_failure(
                        device,
                        &job_id,
                        "stream.finish_unknown",
                        None,
                        Some(&receipt),
                        12,
                    ),
                };
            }
            Err(error) => {
                cancel_stream_best_effort(
                    client,
                    device,
                    &job_id,
                    &capabilities.epoch,
                    "source_invalid",
                );
                return emit_stream_failure(
                    device,
                    &job_id,
                    error.code(),
                    Some((error.byte_offset, error.scalar_offset)),
                    (index > 0).then_some(&receipt),
                    20,
                );
            }
        };
        let command_id = uuid::Uuid::now_v7().to_string();
        emit_json_line(&serde_json::json!({
            "schema": "keyferry.text-stream-event.v1",
            "event": "attempt",
            "job_id": job_id,
            "child_command_id": command_id,
            "index": index.to_string(),
            "source_start": {"bytes": part.start_bytes.to_string(), "scalars": part.start_scalars.to_string()},
            "source_end": {"bytes": part.end_bytes.to_string(), "scalars": part.end_scalars.to_string()},
            "gestures": part.gestures.to_string(),
        }));
        let body = serde_json::json!({
            "epoch": capabilities.epoch,
            "child_command_id": command_id,
            "source_start": {"bytes": part.start_bytes.to_string(), "scalars": part.start_scalars.to_string()},
            "source_end": {"bytes": part.end_bytes.to_string(), "scalars": part.end_scalars.to_string()},
            "text": part.text,
            "end_of_input": part.end_of_input,
        });
        let body = serde_json::to_string(&body).expect("stream part serialization");
        let path = format!("/v1/devices/{device}/text-streams/{job_id}/parts/{index}");
        receipt = match client.sequence_post(&path, &body) {
            Ok(response) if response.status < 400 => {
                match parse_stream_receipt(&response.body, &capabilities.epoch, &job_id) {
                    Ok(receipt) => receipt,
                    Err(code) => {
                        return emit_stream_failure(
                            device,
                            &job_id,
                            code,
                            None,
                            Some(&receipt),
                            25,
                        );
                    }
                }
            }
            Ok(response) => {
                cancel_stream_best_effort(
                    client,
                    device,
                    &job_id,
                    &capabilities.epoch,
                    "producer_lost",
                );
                return emit_stream_failure(
                    device,
                    &job_id,
                    http_error_code(response.status),
                    None,
                    (index > 0).then_some(&receipt),
                    http_exit_code(response.status),
                );
            }
            Err(_) => match reconcile_stream_after_lost_post(
                client,
                device,
                &job_id,
                &capabilities.epoch,
                &command_id,
                index,
            ) {
                Ok(found) => found,
                Err(code) => {
                    return emit_stream_failure(device, &job_id, code, None, Some(&receipt), 12);
                }
            },
        };
        let result = await_stream_child(
            client,
            device,
            &job_id,
            &capabilities.epoch,
            &command_id,
            index,
            receipt.clone(),
            &interrupted,
        );
        receipt = match result {
            Ok(receipt) => receipt,
            Err((code, exit)) => {
                return emit_stream_failure(device, &job_id, code, None, Some(&receipt), exit);
            }
        };
        emit_stream_progress(device, &receipt);
        if receipt.terminal {
            return emit_stream_terminal(device, &receipt);
        }
        index = index.saturating_add(1);
    }
}

fn stream_source_metadata(path: &Path) -> Result<(u64, Option<SystemTime>), &'static str> {
    let metadata = fs::metadata(path).map_err(|_| "input.source_io")?;
    if !metadata.is_file() {
        return Err("input.source_io");
    }
    Ok((metadata.len(), metadata.modified().ok()))
}

fn parse_stream_receipt(
    body: &str,
    epoch: &str,
    job_id: &str,
) -> Result<StreamReceipt, &'static str> {
    let receipt: StreamReceipt =
        serde_json::from_str(body).map_err(|_| "protocol.invalid_response")?;
    if receipt.schema != TEXT_STREAM_RECEIPT_SCHEMA_V1
        || receipt.epoch != epoch
        || receipt.job_id != job_id
        || parse_counter(&receipt.next_index).is_none()
        || parse_counter(&receipt.confirmed_prefix.bytes).is_none()
        || parse_counter(&receipt.confirmed_prefix.scalars).is_none()
        || parse_counter(&receipt.confirmed_prefix.children).is_none()
        || parse_counter(&receipt.confirmed_prefix.gestures).is_none()
        || parse_counter(&receipt.not_dispatched_from.bytes).is_none()
        || parse_counter(&receipt.not_dispatched_from.scalars).is_none()
    {
        return Err("protocol.invalid_response");
    }
    Ok(receipt)
}

fn parse_counter(value: &str) -> Option<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

fn stream_status(
    client: &Client,
    device: &str,
    job_id: &str,
    epoch: &str,
) -> Result<StreamReceipt, &'static str> {
    let path = format!("/v1/devices/{device}/text-streams/{job_id}");
    let response = client
        .request_raw("GET", &path, None)
        .map_err(|_| "daemon.unavailable")?;
    if response.status >= 400 {
        return Err(http_error_code(response.status));
    }
    parse_stream_receipt(&response.body, epoch, job_id)
}

fn renew_stream_best_effort(client: &Client, device: &str, job_id: &str, epoch: &str) {
    let path = format!("/v1/devices/{device}/text-streams/{job_id}/lease");
    let body = serde_json::to_string(&serde_json::json!({"epoch": epoch}))
        .expect("stream lease serialization");
    let _ = client.request_raw("POST", &path, Some(&body));
}

fn cancel_stream_best_effort(
    client: &Client,
    device: &str,
    job_id: &str,
    epoch: &str,
    reason: &str,
) {
    let path = format!("/v1/devices/{device}/text-streams/{job_id}/cancel");
    let mut value = serde_json::json!({"epoch": epoch, "reason": reason});
    if reason == "source_invalid" {
        value["source_error"] = serde_json::json!({"bytes": "0", "scalars": "0"});
    }
    let body = serde_json::to_string(&value).expect("stream cancel serialization");
    let _ = client.request_raw("POST", &path, Some(&body));
}

fn reconcile_stream_after_lost_post(
    client: &Client,
    device: &str,
    job_id: &str,
    epoch: &str,
    command_id: &str,
    index: u64,
) -> Result<StreamReceipt, &'static str> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if let Ok(receipt) = stream_status(client, device, job_id, epoch) {
            let admitted = receipt
                .current_child
                .as_ref()
                .is_some_and(|child| child.command_id == command_id)
                || parse_counter(&receipt.next_index).is_some_and(|next| next > index)
                || receipt.terminal;
            if admitted {
                return Ok(receipt);
            }
        }
        std::thread::sleep(SEQUENCE_POLL_INTERVAL);
    }
    cancel_stream_best_effort(client, device, job_id, epoch, "producer_lost");
    Err("command.outcome_unknown")
}

// The stream identity and the exact child identity are both intentionally
// explicit here; collapsing them into ambient mutable state makes retries easier to introduce.
#[allow(clippy::too_many_arguments)]
fn await_stream_child(
    client: &Client,
    device: &str,
    job_id: &str,
    epoch: &str,
    command_id: &str,
    index: u64,
    mut receipt: StreamReceipt,
    interrupted: &AtomicBool,
) -> Result<StreamReceipt, (&'static str, u8)> {
    let mut renewed_at = std::time::Instant::now();
    let mut cancelled = false;
    loop {
        if receipt.terminal || parse_counter(&receipt.next_index).is_some_and(|next| next > index) {
            return Ok(receipt);
        }
        if let Some(child) = receipt.current_child.as_ref() {
            if child.command_id != command_id {
                return Err(("protocol.child_identity", 25));
            }
        }
        if interrupted.load(Ordering::Acquire) && !cancelled {
            cancel_stream_best_effort(client, device, job_id, epoch, "user_cancel");
            cancelled = true;
        }
        if renewed_at.elapsed() >= Duration::from_secs(5) {
            renew_stream_best_effort(client, device, job_id, epoch);
            renewed_at = std::time::Instant::now();
        }
        std::thread::sleep(SEQUENCE_POLL_INTERVAL);
        receipt = stream_status(client, device, job_id, epoch)
            .map_err(|code| (code, if code == "daemon.unavailable" { 23 } else { 25 }))?;
    }
}

fn await_stream_terminal(
    client: &Client,
    device: &str,
    job_id: &str,
    epoch: &str,
    mut receipt: StreamReceipt,
    _interrupted: &AtomicBool,
) -> u8 {
    let deadline = std::time::Instant::now() + SEQUENCE_CANCEL_RECONCILE;
    while !receipt.terminal && std::time::Instant::now() < deadline {
        std::thread::sleep(SEQUENCE_POLL_INTERVAL);
        if let Ok(next) = stream_status(client, device, job_id, epoch) {
            receipt = next;
        }
    }
    if receipt.terminal {
        emit_stream_terminal(device, &receipt)
    } else {
        let dispatched = receipt.possible_start
            || receipt.current_child.is_some()
            || parse_counter(&receipt.next_index) != Some(0);
        emit_stream_failure(
            device,
            job_id,
            "stream.cancel_reconciliation_timeout",
            None,
            dispatched.then_some(&receipt),
            12,
        )
    }
}

fn emit_stream_progress(device: &str, receipt: &StreamReceipt) {
    emit_json_line(&serde_json::json!({
        "schema": "keyferry.text-stream-event.v1",
        "event": "progress",
        "job_id": receipt.job_id,
        "device_id": device,
        "confirmed_prefix": receipt.confirmed_prefix,
        "next_index": receipt.next_index,
    }));
}

fn emit_stream_terminal(device: &str, receipt: &StreamReceipt) -> u8 {
    let outcome = receipt.outcome.unwrap_or(SequenceOutcome::Unknown);
    emit_json_line(&serde_json::json!({
        "schema": "keyferry.text-stream-result.v1",
        "job_id": receipt.job_id,
        "device_id": device,
        "outcome": outcome,
        "terminal": receipt.terminal,
        "possible_start": receipt.possible_start,
        "terminal_zero_confirmed": receipt.terminal_zero_confirmed,
        "confirmed_prefix": receipt.confirmed_prefix,
        "not_dispatched_from": receipt.not_dispatched_from,
        "error": Value::Null,
    }));
    outcome_exit_code(outcome)
}

fn emit_stream_error(device: &str, job_id: Option<&str>, code: &str, position: Option<(u64, u64)>) {
    emit_json_line(&serde_json::json!({
        "schema": "keyferry.text-stream-result.v1",
        "job_id": job_id,
        "device_id": device,
        "outcome": "REJECTED",
        "terminal": true,
        "possible_start": false,
        "terminal_zero_confirmed": true,
        "error": {
            "code": code,
            "source_position": position.map(|(bytes, scalars)| serde_json::json!({"bytes": bytes.to_string(), "scalars": scalars.to_string()})),
        },
    }));
}

/// Emits a failure after stream creation and returns its exit code. `dispatched` is the last
/// receipt once any child may have been sent. The daemon keeps no stream record across a
/// restart, so such a failure is reported as UNKNOWN (possibly partially typed), never as
/// REJECTED.
fn emit_stream_failure(
    device: &str,
    job_id: &str,
    code: &str,
    position: Option<(u64, u64)>,
    dispatched: Option<&StreamReceipt>,
    exit: u8,
) -> u8 {
    let Some(receipt) = dispatched else {
        emit_stream_error(device, Some(job_id), code, position);
        return exit;
    };
    emit_json_line(&serde_json::json!({
        "schema": "keyferry.text-stream-result.v1",
        "job_id": job_id,
        "device_id": device,
        "outcome": SequenceOutcome::Unknown,
        "terminal": false,
        "possible_start": true,
        "terminal_zero_confirmed": false,
        "confirmed_prefix": receipt.confirmed_prefix,
        "error": {
            "code": code,
            "source_position": position.map(|(bytes, scalars)| serde_json::json!({"bytes": bytes.to_string(), "scalars": scalars.to_string()})),
        },
    }));
    outcome_exit_code(SequenceOutcome::Unknown)
}

fn emit_json_line(value: &Value) {
    let mut output = io::stdout().lock();
    if serde_json::to_writer(&mut output, value).is_ok() {
        let _ = output.write_all(b"\n");
        let _ = output.flush();
    }
}

fn run_input_sequence_local(args: &[String]) -> u8 {
    if args.len() == 2 && args[1] == "--describe" {
        println!("{}", input_sequence_description_json());
        return 0;
    }
    if args.get(1).map(String::as_str) != Some("--validate") {
        println!("{}", input_sequence_validation_error_json("input.usage"));
        return 20;
    }
    let bytes = match args.len() {
        2 => read_bounded_input(&mut io::stdin()),
        4 if args[2] == "--input" => fs::File::open(&args[3])
            .map_err(|_| ())
            .and_then(|mut file| read_bounded_input(&mut file)),
        _ => Err(()),
    };
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(()) => {
            println!("{}", input_sequence_validation_error_json("input.invalid"));
            return 20;
        }
    };
    let generated = uuid::Uuid::now_v7().to_string();
    let request = match parse_input_sequence_json_with_command_id(&bytes, &generated) {
        Ok(request) => request,
        Err(error) => {
            println!("{}", input_sequence_validation_error_json(error.code()));
            return 20;
        }
    };
    let compiled = match compile_input_sequence(&request) {
        Ok(compiled) => compiled,
        Err(error) => {
            println!("{}", input_sequence_validation_error_json(error.code()));
            return 20;
        }
    };
    println!(
        "{}",
        serde_json::to_string(&InputSequenceValidationSuccess {
            schema: "keyferry.input-sequence-validation.v1",
            valid: true,
            source_action_nodes: compiled.source_nodes,
            text_characters: compiled.text_characters,
            effectful_gestures: compiled.effectful_gestures,
            planned_ms: compiled.planned_ms,
            chunks: compiled.chunks.len(),
            has_keyboard: compiled.has_keyboard,
            has_pointer: compiled.has_pointer,
            error: None,
        })
        .expect("input sequence validation serialization is infallible")
    );
    0
}

fn read_bounded_input(reader: &mut impl Read) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_SEQUENCE_BODY + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > MAX_SEQUENCE_BODY {
        return Err(());
    }
    Ok(bytes)
}

fn input_sequence_description_json() -> String {
    serde_json::to_string(&serde_json::json!({
        "schema": "keyferry.input-sequence-description.v1",
        "canonical_schema": "keyferry.input-sequence.v1",
        "status": "submission-available",
        "submission_available": true,
        "submission": "keyctl input-sequence DEVICE [--input PATH] [--detach]",
        "requires_device_capability": "MOUSE_RELATIVE_V1",
        "retry_policy": "never-resubmit-after-possible-send",
        "validation": "keyctl input-sequence --validate [--input PATH]",
        "payload_source": "stdin-or-file",
        "units": {"move_relative": "counts-not-pixels"},
        "actions": ["move_relative", "click", "text", "tap", "chord", "ordered_chord", "wait", "repeat"],
        "buttons": ["button_1", "button_2"],
        "deferred": ["absolute", "scroll", "double_click", "drag", "button_down", "button_up", "raw_report"],
        "bounds": {
            "axis_counts": [-4096, 4096],
            "click_ms": [10, 100],
            "planned_ms": 60000,
            "non_modifier_chord_keys": 6,
            "repeat_nesting": 0
        }
    }))
    .expect("input sequence description serialization is infallible")
}

fn prepare_input_sequence(bytes: &[u8]) -> Result<PreparedInputSequence, &'static str> {
    let generated = uuid::Uuid::now_v7().to_string();
    let request = parse_input_sequence_json_with_command_id(bytes, &generated)
        .map_err(|error| error.code())?;
    compile_input_sequence(&request).map_err(|error| error.code())?;
    let body = serde_json::to_string(&request).map_err(|_| "internal.serialization")?;
    if body.len() > MAX_SEQUENCE_BODY {
        return Err("input.limit");
    }
    Ok(PreparedInputSequence {
        command_id: request.command_id,
        body,
    })
}

fn run_input_sequence(client: &Client, args: &[String]) -> u8 {
    let Some(device) = args.get(1) else {
        emit_sequence_result("", None, SequenceOutcome::Rejected, Some("input.usage"));
        return 20;
    };
    let mut detach = false;
    let mut input_path = None;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--detach" if !detach => detach = true,
            "--input" if input_path.is_none() && index + 1 < args.len() => {
                input_path = Some(args[index + 1].clone());
                index += 1;
            }
            _ => {
                emit_sequence_result(device, None, SequenceOutcome::Rejected, Some("input.usage"));
                return 20;
            }
        }
        index += 1;
    }
    let bytes = match input_path {
        Some(path) => fs::File::open(path)
            .map_err(|_| ())
            .and_then(|mut file| read_bounded_input(&mut file)),
        None => read_bounded_input(&mut io::stdin()),
    };
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(()) => {
            emit_sequence_result(
                device,
                None,
                SequenceOutcome::Rejected,
                Some("input.invalid"),
            );
            return 20;
        }
    };
    let prepared = match prepare_input_sequence(&bytes) {
        Ok(prepared) => prepared,
        Err(code) => {
            emit_sequence_result(device, None, SequenceOutcome::Rejected, Some(code));
            return if code == "internal.serialization" {
                25
            } else {
                20
            };
        }
    };
    submit_prepared_command(
        client,
        device,
        detach,
        "/input-sequences",
        &prepared.command_id,
        &prepared.body,
    )
}

fn input_sequence_validation_error_json(code: &str) -> String {
    serde_json::to_string(&InputSequenceValidationFailure {
        schema: "keyferry.input-sequence-validation.v1",
        valid: false,
        error: SequenceResultError { code },
    })
    .expect("input sequence validation serialization is infallible")
}

const SEQUENCE_EXAMPLE: &str = r#"{"schema":"keyferry.keyboard-sequence.v1","profile":"windows-us","arm":"command-scoped","start_within_ms":5000,"actions":[{"type":"tap","key":"A"}]}"#;

fn sequence_help_text() -> &'static str {
    "keyctl sequence DEVICE [--input json] [--detach]\n  Reads one keyferry.keyboard-sequence.v1 JSON object from stdin.\n  Run `keyctl sequence --example` for a valid starting document.\n  Run `keyctl sequence --validate` with JSON on stdin for a no-contact compilation check.\n  Run `keyctl keys` for the canonical, case-sensitive physical key names.\n  Actions are strict: text(value), tap(key), chord(keys), ordered_chord(keys), wait(ms), repeat(count, actions).\n  `text` types profile-mapped characters; tap/chord use physical key names.\n  `chord` presses together; `ordered_chord` holds keys in listed order and releases in reverse (2-6 keys).\n  Duplicate or unknown keys reject locally. Raw usages and unrestricted key_down/key_up are not accepted.\n  No command is retried after possible start."
}

fn key_registry_json() -> String {
    let keys = KEYBOARD_KEYS
        .iter()
        .map(|key| {
            serde_json::json!({
                "name": key.name,
                "class": match key.class {
                    KeyClass::Modifier => "modifier",
                    KeyClass::NonModifier => "non-modifier",
                },
                "portability": match key.portability {
                    KeyPortability::BootCommon => "boot-common",
                    KeyPortability::ReportExtended => "report-extended",
                },
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&serde_json::json!({
        "schema": "keyferry.keyboard-key-registry.v1",
        "max_modifiers": 8,
        "max_non_modifiers": 6,
        "keys": keys,
    }))
    .expect("keyboard registry serialization is infallible")
}

fn read_bounded_sequence_stdin() -> Result<String, ClientError> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_SEQUENCE_BODY + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ClientError("failed to read sequence stdin".to_owned()))?;
    if bytes.len() > MAX_SEQUENCE_BODY {
        return Err(ClientError("sequence input exceeds 65536 bytes".to_owned()));
    }
    String::from_utf8(bytes).map_err(|_| ClientError("sequence input is not UTF-8".to_owned()))
}

fn prepare_sequence(raw: &str) -> Result<PreparedSequence, &'static str> {
    let mut value: Value = serde_json::from_str(raw).map_err(|_| "input.invalid_json")?;
    let object = value.as_object_mut().ok_or("input.not_object")?;
    if !object.contains_key("command_id") {
        object.insert(
            "command_id".to_owned(),
            Value::String(uuid::Uuid::now_v7().to_string()),
        );
    }
    let request: KeyboardSequenceV1 = serde_json::from_value(value).map_err(|_| "input.schema")?;
    let command_id = uuid::Uuid::parse_str(&request.command_id).map_err(|_| "input.command_id")?;
    if command_id.get_version_num() != 7 {
        return Err("input.command_id");
    }
    let compiled = compile_sequence(&request).map_err(|error| error.code())?;
    let body = serde_json::to_string(&request).map_err(|_| "internal.serialization")?;
    if body.len() > MAX_SEQUENCE_BODY {
        return Err("input.body_limit");
    }
    Ok(PreparedSequence {
        command_id: command_id.to_string(),
        body,
        source_nodes: compiled.source_nodes,
        text_characters: compiled.text_characters,
        gestures: compiled.gestures,
        planned_ms: compiled.planned_ms,
    })
}

fn run_sequence_validate() -> u8 {
    let raw = match read_bounded_sequence_stdin() {
        Ok(raw) => raw,
        Err(_) => {
            println!("{}", sequence_validation_error_json("input.invalid"));
            return 20;
        }
    };
    match prepare_sequence(&raw) {
        Ok(prepared) => {
            println!("{}", sequence_validation_json(&prepared));
            0
        }
        Err(code) => {
            println!("{}", sequence_validation_error_json(code));
            if code == "internal.serialization" {
                25
            } else {
                20
            }
        }
    }
}

fn sequence_validation_json(prepared: &PreparedSequence) -> String {
    serde_json::to_string(&SequenceValidationSuccess {
        schema: "keyferry.sequence-validation.v1",
        valid: true,
        source_action_nodes: prepared.source_nodes,
        text_characters: prepared.text_characters,
        gestures: prepared.gestures,
        planned_ms: prepared.planned_ms,
        error: None,
    })
    .expect("sequence validation serialization is infallible")
}

fn sequence_validation_error_json(code: &str) -> String {
    serde_json::to_string(&SequenceValidationFailure {
        schema: "keyferry.sequence-validation.v1",
        valid: false,
        error: SequenceResultError { code },
    })
    .expect("sequence validation serialization is infallible")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TypeOptions {
    key_down_ms: u16,
    key_gap_ms: u16,
    send_after_seconds: u16,
    detach: bool,
}

fn parse_type_options(args: &[String]) -> Result<TypeOptions, &'static str> {
    let mut key_down_ms = u64::from(TypingTiming::DESKTOP_SAFE.key_down_ms);
    let mut key_gap_ms = u64::from(TypingTiming::DESKTOP_SAFE.release_gap_ms);
    let mut send_after_seconds = 0_u64;
    let mut detach = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--detach" if !detach => detach = true,
            "--key-down-ms" | "--key-gap-ms" | "--send-after-seconds" if index + 1 < args.len() => {
                let option = args[index].as_str();
                let value = args[index + 1].parse::<u64>().map_err(|_| "input.timing")?;
                match option {
                    "--key-down-ms" => key_down_ms = value,
                    "--key-gap-ms" => key_gap_ms = value,
                    _ => send_after_seconds = value,
                }
                index += 1;
            }
            _ => return Err("input.usage"),
        }
        index += 1;
    }
    if !(5..=100).contains(&key_down_ms)
        || !(5..=100).contains(&key_gap_ms)
        || send_after_seconds > 10
    {
        return Err("input.timing");
    }
    Ok(TypeOptions {
        key_down_ms: key_down_ms as u16,
        key_gap_ms: key_gap_ms as u16,
        send_after_seconds: send_after_seconds as u16,
        detach,
    })
}

fn run_type(client: &Client, args: &[String]) -> u8 {
    let Some(device) = args.get(1) else {
        emit_sequence_result("", None, SequenceOutcome::Rejected, Some("input.usage"));
        return 20;
    };
    let options = match parse_type_options(&args[2..]) {
        Ok(options) => options,
        Err(code) => {
            emit_sequence_result(device, None, SequenceOutcome::Rejected, Some(code));
            return 20;
        }
    };
    let text = match read_bounded_sequence_stdin() {
        Ok(text) if !text.is_empty() => text,
        _ => {
            emit_sequence_result(
                device,
                None,
                SequenceOutcome::Rejected,
                Some("input.invalid"),
            );
            return 20;
        }
    };
    let mut actions = Vec::with_capacity(2);
    if options.send_after_seconds > 0 {
        actions.push(SequenceAction::Wait {
            ms: options.send_after_seconds * 1000,
        });
    }
    actions.push(SequenceAction::Text {
        value: text,
        timing: None,
    });
    let request = KeyboardSequenceV1 {
        schema: SEQUENCE_SCHEMA_V1.to_owned(),
        command_id: uuid::Uuid::now_v7().to_string(),
        profile: "windows-us".to_owned(),
        arm: SequenceArmPolicy::CommandScoped,
        start_within_ms: 5000,
        timing: Some(TypingTiming {
            key_down_ms: options.key_down_ms,
            release_gap_ms: options.key_gap_ms,
        }),
        actions,
    };
    let raw = match serde_json::to_string(&request) {
        Ok(raw) => raw,
        Err(_) => {
            emit_sequence_result(
                device,
                Some(&request.command_id),
                SequenceOutcome::Rejected,
                Some("internal.serialization"),
            );
            return 25;
        }
    };
    let prepared = match prepare_sequence(&raw) {
        Ok(prepared) => prepared,
        Err(code) => {
            emit_sequence_result(
                device,
                Some(&request.command_id),
                SequenceOutcome::Rejected,
                Some(code),
            );
            return if code == "internal.serialization" {
                25
            } else {
                20
            };
        }
    };
    submit_prepared_command(
        client,
        device,
        options.detach,
        "/sequences",
        &prepared.command_id,
        &prepared.body,
    )
}

fn run_sequence(client: &Client, args: &[String]) -> u8 {
    let Some(device) = args.get(1) else {
        emit_sequence_result("", None, SequenceOutcome::Rejected, Some("input.usage"));
        return 20;
    };
    let mut detach = false;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--detach" if !detach => detach = true,
            "--input" if index + 1 < args.len() && args[index + 1] == "json" => index += 1,
            "--input" if index + 1 < args.len() && args[index + 1] == "kfs1" => {
                emit_sequence_result(
                    device,
                    None,
                    SequenceOutcome::Rejected,
                    Some("input.kfs1_not_implemented"),
                );
                return 20;
            }
            _ => {
                emit_sequence_result(device, None, SequenceOutcome::Rejected, Some("input.usage"));
                return 20;
            }
        }
        index += 1;
    }
    let raw = match read_bounded_sequence_stdin() {
        Ok(raw) => raw,
        Err(_) => {
            emit_sequence_result(
                device,
                None,
                SequenceOutcome::Rejected,
                Some("input.invalid"),
            );
            return 20;
        }
    };
    let prepared = match prepare_sequence(&raw) {
        Ok(prepared) => prepared,
        Err(code) => {
            emit_sequence_result(device, None, SequenceOutcome::Rejected, Some(code));
            return if code == "internal.serialization" {
                25
            } else {
                20
            };
        }
    };
    submit_prepared_command(
        client,
        device,
        detach,
        "/sequences",
        &prepared.command_id,
        &prepared.body,
    )
}

fn submit_prepared_command(
    client: &Client,
    device: &str,
    detach: bool,
    endpoint_suffix: &str,
    command_id: &str,
    body: &str,
) -> u8 {
    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupted_handler = Arc::clone(&interrupted);
    if ctrlc::set_handler(move || interrupted_handler.store(true, Ordering::Release)).is_err() {
        emit_sequence_result(
            device,
            Some(command_id),
            SequenceOutcome::Rejected,
            Some("internal.interrupt_handler"),
        );
        return 25;
    }
    let path = format!("/v1/devices/{device}{endpoint_suffix}");
    let (initial, uncertain_post) = match client.sequence_post(&path, body) {
        Ok(response) if response.status < 400 => match parse_daemon_outcome(&response.body) {
            Ok(outcome) => (outcome, false),
            Err(()) => {
                emit_sequence_result(
                    device,
                    Some(command_id),
                    SequenceOutcome::Unknown,
                    Some("protocol.invalid_response"),
                );
                return 25;
            }
        },
        Ok(response) => {
            let code = http_exit_code(response.status);
            emit_sequence_result(
                device,
                Some(command_id),
                http_outcome(response.status),
                Some(http_error_code(response.status)),
            );
            return code;
        }
        Err(error) if !error.may_have_sent => {
            emit_sequence_result(
                device,
                Some(command_id),
                SequenceOutcome::Rejected,
                Some("daemon.unavailable"),
            );
            return 23;
        }
        Err(_) => (
            DaemonCommandResponse {
                outcome: SequenceOutcome::Unknown,
                terminal: true,
                possible_start: true,
                terminal_zero_confirmed: false,
                terminal_release_completed: Some(false),
                output_transport: None,
                diagnostic_code: None,
            },
            true,
        ),
    };
    if detach {
        emit_daemon_sequence_result(device, command_id, &initial);
        return if initial.outcome == SequenceOutcome::Queued {
            0
        } else {
            outcome_exit_code(initial.outcome)
        };
    }
    let started = std::time::Instant::now();
    let mut last = initial;
    let mut cancellation_deadline = None;
    loop {
        if last.terminal && (!uncertain_post || last.outcome != SequenceOutcome::Unknown) {
            emit_daemon_sequence_result(device, command_id, &last);
            return outcome_exit_code(last.outcome);
        }
        if started.elapsed() >= SEQUENCE_WAIT_TIMEOUT {
            let (outcome, error, code) = if last.outcome == SequenceOutcome::Unknown {
                (SequenceOutcome::Unknown, "command.outcome_unknown", 12)
            } else {
                (last.outcome, "command.wait_timeout", 24)
            };
            emit_sequence_result(device, Some(command_id), outcome, Some(error));
            return code;
        }
        if interrupted.load(Ordering::Acquire) && cancellation_deadline.is_none() {
            let body = serde_json::to_string(&CancelRequest {
                command_id: Some(command_id.to_owned()),
            })
            .expect("cancel request serialization is infallible");
            let _ =
                client.request_raw("POST", &format!("/v1/devices/{device}/cancel"), Some(&body));
            cancellation_deadline = Some(std::time::Instant::now() + SEQUENCE_CANCEL_RECONCILE);
        }
        if cancellation_deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            emit_sequence_result(
                device,
                Some(command_id),
                SequenceOutcome::Unknown,
                Some("command.cancel_reconciliation_timeout"),
            );
            return 12;
        }
        std::thread::sleep(SEQUENCE_POLL_INTERVAL);
        let outcome_path = format!("/v1/devices/{device}/commands/{command_id}");
        if let Ok(response) = client.request_raw("GET", &outcome_path, None) {
            if response.status < 400 {
                if let Ok(outcome) = parse_daemon_outcome(&response.body) {
                    last = outcome;
                }
            }
        }
    }
}

fn parse_daemon_outcome(body: &str) -> Result<DaemonCommandResponse, ()> {
    let response: DaemonCommandResponse = serde_json::from_str(body).map_err(|_| ())?;
    if response
        .diagnostic_code
        .as_deref()
        .is_some_and(|code| TransportDiagnostic::from_code(code).is_none())
    {
        return Err(());
    }
    if response
        .output_transport
        .as_deref()
        .is_some_and(|transport| !matches!(transport, "usb-hid" | "ble-hid" | "simulator"))
    {
        return Err(());
    }
    Ok(response)
}

fn emit_daemon_sequence_result(
    device_id: &str,
    command_id: &str,
    response: &DaemonCommandResponse,
) {
    let rendered = sequence_result_json_with_transport(
        device_id,
        Some(command_id),
        response.outcome,
        ResultEvidence {
            terminal: response.terminal,
            possible_start: response.possible_start,
            terminal_zero_confirmed: response.terminal_zero_confirmed,
            terminal_release_completed: response
                .terminal_release_completed
                .unwrap_or(response.terminal_zero_confirmed),
            output_transport: response.output_transport.as_deref(),
        },
        response.diagnostic_code.as_deref(),
    );
    let mut output = io::stdout().lock();
    let _ = output.write_all(rendered.as_bytes());
    let _ = output.write_all(b"\n");
}

fn emit_sequence_result(
    device_id: &str,
    command_id: Option<&str>,
    outcome: SequenceOutcome,
    error: Option<&str>,
) {
    let rendered = sequence_result_json(device_id, command_id, outcome, error);
    let mut output = io::stdout().lock();
    let _ = output.write_all(rendered.as_bytes());
    let _ = output.write_all(b"\n");
}

fn sequence_result_json(
    device_id: &str,
    command_id: Option<&str>,
    outcome: SequenceOutcome,
    error: Option<&str>,
) -> String {
    let possible_start = matches!(
        outcome,
        SequenceOutcome::Started
            | SequenceOutcome::Emitted
            | SequenceOutcome::Aborted
            | SequenceOutcome::Unknown
    );
    let terminal_zero_confirmed = matches!(
        outcome,
        SequenceOutcome::Emitted | SequenceOutcome::Aborted | SequenceOutcome::Rejected
    );
    sequence_result_json_with_evidence(
        device_id,
        command_id,
        outcome,
        outcome.is_terminal(),
        possible_start,
        terminal_zero_confirmed,
        error,
    )
}

fn sequence_result_json_with_evidence(
    device_id: &str,
    command_id: Option<&str>,
    outcome: SequenceOutcome,
    terminal: bool,
    possible_start: bool,
    terminal_zero_confirmed: bool,
    error: Option<&str>,
) -> String {
    sequence_result_json_with_transport(
        device_id,
        command_id,
        outcome,
        ResultEvidence {
            terminal,
            possible_start,
            terminal_zero_confirmed,
            terminal_release_completed: terminal_zero_confirmed,
            output_transport: None,
        },
        error,
    )
}

#[derive(Clone, Copy)]
struct ResultEvidence<'a> {
    terminal: bool,
    possible_start: bool,
    terminal_zero_confirmed: bool,
    terminal_release_completed: bool,
    output_transport: Option<&'a str>,
}

fn sequence_result_json_with_transport(
    device_id: &str,
    command_id: Option<&str>,
    outcome: SequenceOutcome,
    evidence: ResultEvidence<'_>,
    error: Option<&str>,
) -> String {
    let result = SequenceResult {
        schema: "keyferry.command-result.v2",
        command_id,
        device_id,
        outcome,
        terminal: evidence.terminal,
        possible_start: evidence.possible_start,
        terminal_zero_confirmed: evidence.terminal_zero_confirmed,
        terminal_release_completed: evidence.terminal_release_completed,
        output_transport: evidence.output_transport,
        error: error.map(|code| SequenceResultError { code }),
    };
    serde_json::to_string(&result).expect("sequence result serialization is infallible")
}

fn outcome_exit_code(outcome: SequenceOutcome) -> u8 {
    match outcome {
        SequenceOutcome::Emitted | SequenceOutcome::Queued => 0,
        SequenceOutcome::Rejected => 10,
        SequenceOutcome::Aborted => 11,
        SequenceOutcome::Unknown => 12,
        SequenceOutcome::Accepted | SequenceOutcome::Started => 24,
    }
}

/// HTTP 502 is the daemon's statement that a request forwarded to the controller holding the
/// stick may have arrived but its result was lost; that is an unknown outcome, never a rejection.
const HTTP_FORWARD_UNCERTAIN: u16 = 502;

fn http_exit_code(status: u16) -> u8 {
    match status {
        401 | 403 | 422 => 21,
        409 => 22,
        404 | 503 => 23,
        400 | 413 => 20,
        HTTP_FORWARD_UNCERTAIN => outcome_exit_code(SequenceOutcome::Unknown),
        _ => 25,
    }
}

fn http_error_code(status: u16) -> &'static str {
    match status {
        400 | 413 => "input.rejected",
        401 | 403 | 422 => "policy.rejected",
        409 => "command.busy_or_conflict",
        404 | 503 => "daemon.unavailable",
        HTTP_FORWARD_UNCERTAIN => "command.outcome_unknown",
        _ => "protocol.http_error",
    }
}

fn http_outcome(status: u16) -> SequenceOutcome {
    if status == HTTP_FORWARD_UNCERTAIN {
        SequenceOutcome::Unknown
    } else {
        SequenceOutcome::Rejected
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum SequenceOutcome {
    Queued,
    Accepted,
    Started,
    Emitted,
    Aborted,
    Rejected,
    Unknown,
}

impl SequenceOutcome {
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Emitted | Self::Aborted | Self::Rejected | Self::Unknown
        )
    }
}

#[derive(Debug, Deserialize)]
struct DaemonCommandResponse {
    outcome: SequenceOutcome,
    terminal: bool,
    possible_start: bool,
    terminal_zero_confirmed: bool,
    #[serde(default)]
    terminal_release_completed: Option<bool>,
    #[serde(default)]
    output_transport: Option<String>,
    #[serde(default)]
    diagnostic_code: Option<String>,
}

#[derive(Debug, Serialize)]
struct SequenceResult<'a> {
    schema: &'static str,
    command_id: Option<&'a str>,
    device_id: &'a str,
    outcome: SequenceOutcome,
    terminal: bool,
    possible_start: bool,
    terminal_zero_confirmed: bool,
    terminal_release_completed: bool,
    output_transport: Option<&'a str>,
    error: Option<SequenceResultError<'a>>,
}

#[derive(Debug, Serialize)]
struct SequenceResultError<'a> {
    code: &'a str,
}

#[derive(Debug, Serialize)]
struct SequenceValidationSuccess {
    schema: &'static str,
    valid: bool,
    source_action_nodes: usize,
    text_characters: usize,
    gestures: usize,
    planned_ms: u32,
    error: Option<SequenceResultError<'static>>,
}

#[derive(Debug, Serialize)]
struct SequenceValidationFailure<'a> {
    schema: &'static str,
    valid: bool,
    error: SequenceResultError<'a>,
}

#[derive(Debug, Serialize)]
struct InputSequenceValidationSuccess {
    schema: &'static str,
    valid: bool,
    source_action_nodes: usize,
    text_characters: usize,
    effectful_gestures: usize,
    planned_ms: u64,
    chunks: usize,
    has_keyboard: bool,
    has_pointer: bool,
    error: Option<SequenceResultError<'static>>,
}

#[derive(Debug, Serialize)]
struct InputSequenceValidationFailure<'a> {
    schema: &'static str,
    valid: bool,
    error: SequenceResultError<'a>,
}

#[derive(Debug)]
struct PreparedSequence {
    command_id: String,
    body: String,
    source_nodes: usize,
    text_characters: usize,
    gestures: usize,
    planned_ms: u32,
}

#[derive(Debug)]
struct PreparedInputSequence {
    command_id: String,
    body: String,
}

struct SequencePostError {
    may_have_sent: bool,
}

fn print_help() {
    println!("{}", help_text());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn screen_power_cli_rejects_mismatched_response_before_printing() {
        for response in [
            r#"{"schema":"wrong","device_id":"device-1","active":"on","stored":"off","available":true}"#,
            r#"{"schema":"keyferry.screen-power.v1","device_id":"device-2","active":"on","stored":"off","available":true}"#,
            r#"{"schema":"keyferry.screen-power.v1","device_id":"device-1","active":"on","stored":"on","available":true}"#,
        ] {
            assert!(print_screen_power_response(response, "device-1", Some("off")).is_err());
        }
    }

    #[test]
    fn file_one_over_limit_rejects_before_network() {
        let path = std::env::current_dir()
            .unwrap()
            .join(format!("keyferry-file-over-limit-{}", uuid::Uuid::now_v7()));
        std::fs::write(
            &path,
            vec![0xff; keyferry_protocol::file::MAX_FILE_BYTES + 1],
        )
        .unwrap();
        let client = Client {
            endpoint: Endpoint {
                host: "127.0.0.1".to_owned(),
                port: 9,
            },
            token: "unused".to_owned(),
        };
        let result = run_command(
            &client,
            vec![
                "file".to_owned(),
                "device-1".to_owned(),
                path.to_string_lossy().into_owned(),
            ],
        );
        std::fs::remove_file(path).unwrap();
        assert_eq!(
            result.unwrap_err().to_string(),
            format!(
                "file exceeds {} bytes",
                keyferry_protocol::file::MAX_FILE_BYTES
            )
        );
    }

    #[test]
    fn file_set_rejects_bad_names_and_aggregate_limit_before_network() {
        let root =
            std::env::temp_dir().join(format!("keyferry-file-set-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let bad = root.join("bad+name.txt");
        let first = root.join("first.txt");
        let second = root.join("second.bin");
        std::fs::write(&bad, [1]).unwrap();
        std::fs::write(&first, vec![0; 150_000]).unwrap();
        std::fs::write(&second, vec![0; 150_000]).unwrap();
        let client = Client {
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port: 9,
            },
            token: "unused".into(),
        };
        for paths in [vec![bad.clone()], vec![first.clone(), second.clone()]] {
            let mut args = vec!["files".to_owned(), "device-1".to_owned()];
            args.extend(paths.iter().map(|path| path.to_string_lossy().into_owned()));
            let error = run_command(&client, args).unwrap_err().to_string();
            assert!(
                error.contains("invalid file set") || error.contains("exceeds 262144"),
                "{error}"
            );
        }
        let invalid_unreadable = root.join("bad+missing.txt");
        let error = run_command(
            &client,
            vec![
                "files".into(),
                "device-1".into(),
                invalid_unreadable.to_string_lossy().into_owned(),
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("invalid file set"), "{error}");
        let error = run_command(
            &client,
            vec![
                "files".into(),
                "device-1".into(),
                root.to_string_lossy().into_owned(),
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not a regular file"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_set_cli_posts_and_routes_status_clear_by_capability() {
        let root =
            std::env::temp_dir().join(format!("keyferry-file-route-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("note.txt");
        std::fs::write(&path, [1, 2]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            for (expected, response) in [
                ("POST /v1/devices/device-1/files HTTP/1.1", "{}"),
                (
                    "GET /v1/devices/device-1 HTTP/1.1",
                    r#"{"firmware":{"usb_file_set_v2":true}}"#,
                ),
                ("GET /v1/devices/device-1/files HTTP/1.1", "{}"),
                (
                    "GET /v1/devices/device-1 HTTP/1.1",
                    r#"{"firmware":{"usb_file_set_v2":true}}"#,
                ),
                ("DELETE /v1/devices/device-1/files HTTP/1.1", "{}"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = [0_u8; 4096];
                let count = stream.read(&mut bytes).unwrap();
                assert!(std::str::from_utf8(&bytes[..count])
                    .unwrap()
                    .starts_with(expected));
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
            }
        });
        let client = Client {
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port,
            },
            token: "test-token".into(),
        };
        assert!(run_command(
            &client,
            vec![
                "files".into(),
                "device-1".into(),
                path.to_string_lossy().into_owned()
            ]
        )
        .is_ok());
        assert!(run_command(&client, vec!["file-status".into(), "device-1".into()]).is_ok());
        assert!(run_command(&client, vec!["file-clear".into(), "device-1".into()]).is_ok());
        server.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_set_upload_waits_for_a_delayed_daemon_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = [0_u8; 4096];
            let count = stream.read(&mut bytes).unwrap();
            assert!(std::str::from_utf8(&bytes[..count])
                .unwrap()
                .starts_with("POST /v1/devices/device-1/files HTTP/1.1"));
            std::thread::sleep(Duration::from_millis(10_500));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )
            .unwrap();
        });
        let client = Client {
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port,
            },
            token: "test-token".into(),
        };
        let response = client
            .request_raw("POST", "/v1/devices/device-1/files", Some("{}"))
            .unwrap();
        assert_eq!(response.status, 200);
        server.join().unwrap();
    }

    #[test]
    fn old_firmware_file_status_and_clear_keep_single_file_route() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            for (expected, response) in [
                (
                    "GET /v1/devices/device-1 HTTP/1.1",
                    r#"{"firmware":{"usb_file_handoff_v1":true}}"#,
                ),
                ("GET /v1/devices/device-1/file HTTP/1.1", "{}"),
                (
                    "GET /v1/devices/device-1 HTTP/1.1",
                    r#"{"firmware":{"usb_file_handoff_v1":true}}"#,
                ),
                ("DELETE /v1/devices/device-1/file HTTP/1.1", "{}"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = [0_u8; 1024];
                let count = stream.read(&mut bytes).unwrap();
                assert!(std::str::from_utf8(&bytes[..count])
                    .unwrap()
                    .starts_with(expected));
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
            }
        });
        let client = Client {
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port,
            },
            token: "test-token".into(),
        };
        assert!(run_command(&client, vec!["file-status".into(), "device-1".into()]).is_ok());
        assert!(run_command(&client, vec!["file-clear".into(), "device-1".into()]).is_ok());
        server.join().unwrap();
    }

    #[test]
    fn offline_hint_appears_only_when_a_device_is_not_authenticated() {
        let online = serde_json::json!({"devices": [{"link": "authenticated"}]});
        let mixed =
            serde_json::json!({"devices": [{"link": "authenticated"}, {"link": "offline"}]});
        assert!(offline_hint(&online).is_none());
        assert!(offline_hint(&serde_json::json!({"devices": []})).is_none());
        assert!(offline_hint(&mixed).is_some_and(|hint| hint.contains("\"tailnet\"")));
    }

    #[test]
    fn only_local_service_commands_open_keyferry() {
        for command in [
            "devices",
            "status",
            "capabilities",
            "maintenance",
            "screen-power",
            "type",
            "sequence",
            "stream",
            "files",
            "cancel",
            "events",
        ] {
            assert!(needs_service(Some(command)), "{command}");
        }
        for command in [
            None,
            Some("keys"),
            Some("--help"),
            Some("local-status"),
            Some("x"),
        ] {
            assert!(!needs_service(command), "{command:?}");
        }
        let local = Endpoint {
            host: "127.0.0.1".to_owned(),
            port: 8042,
        };
        assert_eq!(
            loopback_address(&local),
            Some("127.0.0.1:8042".parse().unwrap())
        );
        let remote = Endpoint {
            host: "100.64.0.2".to_owned(),
            port: 8042,
        };
        assert_eq!(loopback_address(&remote), None);
    }

    #[test]
    fn keyferry_is_opened_from_its_installed_location_never_as_the_daemon() {
        let windows_keyctl = PathBuf::from("Programs")
            .join("Keyferry")
            .join("keyctl.exe");
        let windows_app = PathBuf::from("Programs")
            .join("Keyferry")
            .join("keyferry.exe");
        assert_eq!(
            app_launch(Platform::Windows, &windows_keyctl, None, |_| true),
            Some((windows_app, Vec::new()))
        );
        assert_eq!(
            app_launch(Platform::Windows, &windows_keyctl, None, |_| false),
            None
        );

        let bundle = PathBuf::from("/Users/owner/Applications/Keyferry.app");
        let bundled_keyctl = bundle.join("Contents").join("MacOS").join("keyctl");
        let open = |bundle: &Path| {
            Some((
                PathBuf::from("/usr/bin/open"),
                vec!["-a".to_owned(), bundle.to_string_lossy().into_owned()],
            ))
        };
        assert_eq!(
            app_launch(Platform::MacOs, &bundled_keyctl, None, |_| true),
            open(&bundle)
        );
        let home = PathBuf::from("/Users/owner");
        let loose_keyctl = PathBuf::from("/usr/local/bin/keyctl");
        assert_eq!(
            app_launch(Platform::MacOs, &loose_keyctl, Some(&home), |_| true),
            open(&home.join("Applications").join("Keyferry.app"))
        );
        assert_eq!(
            app_launch(Platform::MacOs, &loose_keyctl, Some(&home), |_| false),
            None
        );
        assert_eq!(
            app_launch(Platform::Other, &loose_keyctl, Some(&home), |_| true),
            None
        );
        for (program, _) in [
            app_launch(Platform::Windows, &windows_keyctl, None, |_| true),
            app_launch(Platform::MacOs, &bundled_keyctl, None, |_| true),
        ]
        .into_iter()
        .flatten()
        {
            assert!(!program.to_string_lossy().contains("keyferryd"));
        }
    }

    #[test]
    fn windows_shell_broker_receives_one_exact_app_path_with_spaces() {
        let system_root = PathBuf::from(r"C:\Windows");
        let app = PathBuf::from(r"C:\Program Files\Keyferry App\keyferry.exe");
        let explorer = system_root.join("explorer.exe");
        let command = app_start_command(Platform::Windows, &app, &[], Some(&system_root), |path| {
            path == explorer
        })
        .expect("shell broker");
        assert_eq!(command.get_program(), explorer.as_os_str());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![app.as_os_str()]
        );
        assert!(app_start_command(Platform::Windows, &app, &[], None, |_| true).is_none());
        assert!(app_start_command(
            Platform::Windows,
            &app,
            &["unexpected".to_owned()],
            Some(&system_root),
            |_| true,
        )
        .is_none());
    }

    #[test]
    fn service_wait_is_bounded() {
        let mut polls = 0;
        assert!(wait_until(
            Duration::from_secs(5),
            Duration::from_millis(1),
            || {
                polls += 1;
                polls == 3
            }
        ));
        assert_eq!(polls, 3);
        let started = std::time::Instant::now();
        assert!(!wait_until(
            Duration::from_millis(30),
            Duration::from_millis(5),
            || false
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn forwarded_uncertainty_is_unknown_never_rejected() {
        assert_eq!(http_outcome(502), SequenceOutcome::Unknown);
        assert_eq!(http_exit_code(502), 12);
        assert_eq!(http_error_code(502), "command.outcome_unknown");
        assert_eq!(http_outcome(503), SequenceOutcome::Rejected);
        assert_eq!(http_exit_code(503), 23);
    }

    fn minimal_sequence(extra_action: &str) -> String {
        format!(
            r#"{{"schema":"keyferry.keyboard-sequence.v1","profile":"windows-us","arm":"command-scoped","start_within_ms":5000,"actions":[{extra_action}]}}"#
        )
    }

    #[test]
    fn endpoint_parser_remains_loopback_http_only() {
        let endpoint = parse_endpoint("http://127.0.0.1:8042").expect("loopback endpoint");
        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 8042);

        for rejected in [
            "https://127.0.0.1:8042",
            "http://localhost:8042",
            "http://100.90.118.120:8042",
            "http://127.0.0.1:0",
        ] {
            assert!(parse_endpoint(rejected).is_err(), "accepted {rejected}");
        }
    }

    #[test]
    fn sequence_preparation_injects_uuid_v7_and_compiles_before_network() {
        let prepared = prepare_sequence(&minimal_sequence(r#"{"type":"tap","key":"LEFT_GUI"}"#))
            .expect("valid sequence");
        let command_id = uuid::Uuid::parse_str(&prepared.command_id).unwrap();
        assert_eq!(command_id.get_version_num(), 7);
        let body: KeyboardSequenceV1 = serde_json::from_str(&prepared.body).unwrap();
        assert_eq!(body.command_id, prepared.command_id);
        assert!(compile_sequence(&body).is_ok());
        let ordered = prepare_sequence(&minimal_sequence(
            r#"{"type":"ordered_chord","keys":["CAPS_LOCK","SPACE","J"]}"#,
        ))
        .expect("ordered physical chord");
        let body: KeyboardSequenceV1 = serde_json::from_str(&ordered.body).unwrap();
        assert_eq!(compile_sequence(&body).unwrap().planned_ms, 112);
    }

    #[test]
    fn sequence_discovery_is_local_strict_and_machine_readable() {
        assert!(prepare_sequence(SEQUENCE_EXAMPLE).is_ok());
        let registry: Value = serde_json::from_str(&key_registry_json()).unwrap();
        assert_eq!(registry["schema"], "keyferry.keyboard-key-registry.v1");
        assert_eq!(registry["max_modifiers"], 8);
        assert_eq!(registry["max_non_modifiers"], 6);
        assert_eq!(
            registry["keys"].as_array().unwrap().len(),
            KEYBOARD_KEYS.len()
        );
        assert!(registry["keys"].as_array().unwrap().iter().all(|entry| {
            entry.get("name").is_some()
                && entry.get("class").is_some()
                && entry.get("portability").is_some()
                && entry.get("code").is_none()
        }));
        assert!(sequence_help_text().contains("case-sensitive physical key names"));
        assert!(sequence_help_text().contains("Duplicate or unknown keys reject locally"));
        assert!(sequence_help_text().contains("no-contact compilation check"));
        assert!(help_text().contains("output-mode DEVICE [usb-hid|ble-hid]"));
        assert!(help_text().contains("a change restarts the stick"));

        let prepared = prepare_sequence(SEQUENCE_EXAMPLE).unwrap();
        assert_eq!(
            sequence_validation_json(&prepared),
            r#"{"schema":"keyferry.sequence-validation.v1","valid":true,"source_action_nodes":1,"text_characters":0,"gestures":1,"planned_ms":52,"error":null}"#
        );
        let rejected = sequence_validation_error_json("chord.rollover_limit");
        assert_eq!(
            rejected,
            r#"{"schema":"keyferry.sequence-validation.v1","valid":false,"error":{"code":"chord.rollover_limit"}}"#
        );
        assert!(!rejected.contains("keys"));
    }

    #[test]
    fn type_options_are_explicit_bounded_and_agent_readable() {
        let defaults = parse_type_options(&[]).unwrap();
        assert_eq!(defaults.key_down_ms, 12);
        assert_eq!(defaults.key_gap_ms, 40);

        let options = parse_type_options(&[
            "--key-gap-ms".to_owned(),
            "25".to_owned(),
            "--key-down-ms".to_owned(),
            "9".to_owned(),
            "--send-after-seconds".to_owned(),
            "3".to_owned(),
            "--detach".to_owned(),
        ])
        .unwrap();
        assert_eq!(options.key_down_ms, 9);
        assert_eq!(options.key_gap_ms, 25);
        assert_eq!(options.send_after_seconds, 3);
        assert!(options.detach);
        assert_eq!(
            parse_type_options(&["--key-gap-ms".to_owned(), "4".to_owned()]),
            Err("input.timing")
        );
        assert_eq!(
            parse_type_options(&["--send-after-seconds".to_owned(), "11".to_owned()]),
            Err("input.timing")
        );
        assert!(type_help_text().contains("release gap between keys"));
        assert!(type_help_text().contains("5..100 ms (default 40)"));
        assert!(type_help_text().contains("never automatically retried"));
    }

    #[test]
    fn stream_preflight_has_no_total_length_limit_and_reports_numeric_failures() {
        let path =
            std::env::temp_dir().join(format!("keyferry-stream-test-{}.txt", uuid::Uuid::now_v7()));
        fs::write(&path, "abc123\r\n".repeat(10_000)).unwrap();
        let options = parse_stream_options(&[
            "--input".to_owned(),
            path.to_string_lossy().into_owned(),
            "--key-down-ms".to_owned(),
            "5".to_owned(),
            "--key-gap-ms".to_owned(),
            "5".to_owned(),
            "--validate".to_owned(),
        ])
        .unwrap();
        let summary = preflight_stream(&options).unwrap();
        assert_eq!(summary.bytes, 80_000);
        assert_eq!(summary.scalars, 80_000);
        assert_eq!(summary.gestures, 70_000);
        assert_eq!(summary.children, 350);
        assert_eq!(summary.replacements, 0);
        assert!(stream_help_text().contains("no configured total-length limit"));

        let defaults =
            parse_stream_options(&["--input".to_owned(), path.to_string_lossy().into_owned()])
                .unwrap();
        assert_eq!(defaults.key_down_ms, 12);
        assert_eq!(defaults.key_gap_ms, 40);

        fs::write(&path, b"ok\xe2\x80\x94").unwrap();
        let error = preflight_stream(&options).unwrap_err();
        assert_eq!(error.code(), "input.unsupported_text");
        assert_eq!((error.byte_offset, error.scalar_offset), (2, 2));

        let replace_options = parse_stream_options(&[
            "--input".to_owned(),
            path.to_string_lossy().into_owned(),
            "--unsupported".to_owned(),
            "replace".to_owned(),
            "--validate".to_owned(),
        ])
        .unwrap();
        let replaced = preflight_stream(&replace_options).unwrap();
        assert_eq!(replaced.bytes, 5);
        assert_eq!(replaced.scalars, 3);
        assert_eq!(replaced.gestures, 3);
        assert_eq!(replaced.replacements, 1);
        assert!(matches!(
            parse_stream_options(&[
                "--input".to_owned(),
                path.to_string_lossy().into_owned(),
                "--unsupported".to_owned(),
                "drop".to_owned(),
            ]),
            Err("input.unsupported_policy")
        ));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn sequence_preparation_preserves_supplied_uuid_and_exact_error_codes() {
        let command_id = uuid::Uuid::now_v7();
        let mut value: Value = serde_json::from_str(&minimal_sequence(
            r#"{"type":"chord","keys":["A","B","C","D","E","F","G"]}"#,
        ))
        .unwrap();
        value["command_id"] = Value::String(command_id.to_string());
        assert_eq!(
            prepare_sequence(&serde_json::to_string(&value).unwrap()).unwrap_err(),
            "chord.rollover_limit"
        );
        value["actions"] = serde_json::json!([{"type":"tap","key":"ENTER"}]);
        let prepared = prepare_sequence(&serde_json::to_string(&value).unwrap()).unwrap();
        assert_eq!(prepared.command_id, command_id.to_string());

        value["payload"] = Value::String("must-not-cross-the-boundary".to_owned());
        assert_eq!(
            prepare_sequence(&serde_json::to_string(&value).unwrap()).unwrap_err(),
            "input.schema"
        );
    }

    #[test]
    fn sequence_result_is_one_compact_stable_object() {
        let rendered = sequence_result_json(
            "device-1",
            Some("019d1234-5678-7abc-8123-456789abcdef"),
            SequenceOutcome::Emitted,
            None,
        );
        assert_eq!(
            rendered,
            r#"{"schema":"keyferry.command-result.v2","command_id":"019d1234-5678-7abc-8123-456789abcdef","device_id":"device-1","outcome":"EMITTED","terminal":true,"possible_start":true,"terminal_zero_confirmed":true,"terminal_release_completed":true,"output_transport":null,"error":null}"#
        );
        assert!(!rendered.contains('\n'));
        assert_eq!(outcome_exit_code(SequenceOutcome::Emitted), 0);
        assert_eq!(outcome_exit_code(SequenceOutcome::Rejected), 10);
        assert_eq!(outcome_exit_code(SequenceOutcome::Aborted), 11);
        assert_eq!(outcome_exit_code(SequenceOutcome::Unknown), 12);

        let daemon = parse_daemon_outcome(
            r#"{"outcome":"ABORTED","terminal":true,"possible_start":false,"terminal_zero_confirmed":true}"#,
        )
        .unwrap();
        let carried = sequence_result_json_with_evidence(
            "device-1",
            Some("019d1234-5678-7abc-8123-456789abcdef"),
            daemon.outcome,
            daemon.terminal,
            daemon.possible_start,
            daemon.terminal_zero_confirmed,
            daemon.diagnostic_code.as_deref(),
        );
        assert!(carried.contains("\"possible_start\":false"));

        let ble = parse_daemon_outcome(
            r#"{"outcome":"EMITTED","terminal":true,"possible_start":true,"terminal_zero_confirmed":false,"terminal_release_completed":true,"output_transport":"ble-hid"}"#,
        )
        .unwrap();
        let carried = sequence_result_json_with_transport(
            "device-1",
            Some("019d1234-5678-7abc-8123-456789abcdef"),
            ble.outcome,
            ResultEvidence {
                terminal: ble.terminal,
                possible_start: ble.possible_start,
                terminal_zero_confirmed: ble.terminal_zero_confirmed,
                terminal_release_completed: ble.terminal_release_completed.unwrap(),
                output_transport: ble.output_transport.as_deref(),
            },
            None,
        );
        assert!(carried.contains("\"output_transport\":\"ble-hid\""));
        assert!(carried.contains("\"terminal_release_completed\":true"));
        assert!(carried.contains("\"terminal_zero_confirmed\":false"));

        let diagnostic = parse_daemon_outcome(
            r#"{"outcome":"UNKNOWN","terminal":true,"possible_start":true,"terminal_zero_confirmed":false,"diagnostic_code":"cancel.active_result.transport"}"#,
        )
        .unwrap();
        let carried = sequence_result_json_with_evidence(
            "device-1",
            Some("019d1234-5678-7abc-8123-456789abcdef"),
            diagnostic.outcome,
            diagnostic.terminal,
            diagnostic.possible_start,
            diagnostic.terminal_zero_confirmed,
            diagnostic.diagnostic_code.as_deref(),
        );
        assert!(carried.contains("\"code\":\"cancel.active_result.transport\""));
        assert!(parse_daemon_outcome(
            r#"{"outcome":"UNKNOWN","terminal":true,"possible_start":true,"terminal_zero_confirmed":false,"diagnostic_code":"cancel.payload.text"}"#,
        )
        .is_err());
    }

    #[test]
    fn sequence_post_distinguishes_precontact_failure_from_uncertain_send() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = [0_u8; 4096];
            let count = stream.read(&mut bytes).unwrap();
            assert!(std::str::from_utf8(&bytes[..count])
                .unwrap()
                .starts_with("POST /v1/devices/device-1/sequences HTTP/1.1\r\n"));
        });
        let client = Client {
            endpoint: Endpoint {
                host: "127.0.0.1".to_owned(),
                port,
            },
            token: "test-token".to_owned(),
        };
        assert!(
            client
                .sequence_post("/v1/devices/device-1/sequences", "{}")
                .unwrap_err()
                .may_have_sent
        );
        server.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let client = Client {
            endpoint: Endpoint {
                host: "127.0.0.1".to_owned(),
                port,
            },
            token: "test-token".to_owned(),
        };
        assert!(
            !client
                .sequence_post("/v1/devices/device-1/sequences", "{}")
                .unwrap_err()
                .may_have_sent
        );
    }

    #[test]
    fn input_sequence_agent_description_and_validation_are_local_and_payload_free() {
        let description: Value = serde_json::from_str(&input_sequence_description_json()).unwrap();
        assert_eq!(
            description["canonical_schema"],
            "keyferry.input-sequence.v1"
        );
        assert_eq!(description["status"], "submission-available");
        assert_eq!(description["submission_available"], true);
        assert_eq!(
            description["requires_device_capability"],
            "MOUSE_RELATIVE_V1"
        );
        assert_eq!(description["units"]["move_relative"], "counts-not-pixels");

        let raw = br#"{"schema":"keyferry.input-sequence.v1","arm":"command-scoped","start_within_ms":5000,"actions":[{"type":"move_relative","dx_counts":240,"dy_counts":-40},{"type":"click","button":"button_1"}]}"#;
        let generated = uuid::Uuid::now_v7().to_string();
        let request = parse_input_sequence_json_with_command_id(raw, &generated).unwrap();
        let compiled = compile_input_sequence(&request).unwrap();
        assert!(!compiled.has_keyboard);
        assert!(compiled.has_pointer);
        assert_eq!(compiled.effectful_gestures, 2);
        assert_eq!(compiled.chunks.len(), 1);

        let prepared = prepare_input_sequence(raw).expect("prepare input submission");
        assert_eq!(
            uuid::Uuid::parse_str(&prepared.command_id)
                .unwrap()
                .get_version_num(),
            7
        );
        let posted = parse_input_sequence_json_with_command_id(
            prepared.body.as_bytes(),
            &uuid::Uuid::now_v7().to_string(),
        )
        .unwrap();
        assert_eq!(posted.command_id, prepared.command_id);
        assert!(compile_input_sequence(&posted).is_ok());
        assert_eq!(
            prepare_input_sequence(
                br#"{"schema":"keyferry.input-sequence.v1","arm":"command-scoped","start_within_ms":5000,"start_within_ms":4000,"actions":[{"type":"click","button":"button_1"}]}"#
            )
            .unwrap_err(),
            "input.duplicate_field"
        );

        let rejected = input_sequence_validation_error_json("pointer.out_of_scope");
        assert_eq!(
            rejected,
            r#"{"schema":"keyferry.input-sequence-validation.v1","valid":false,"error":{"code":"pointer.out_of_scope"}}"#
        );
        assert!(!rejected.contains("dx_counts"));
        assert!(!rejected.contains("button_1"));
    }

    #[test]
    fn input_sequence_submission_posts_once_with_a_pregenerated_id() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let headers = String::from_utf8(request.clone()).unwrap();
            assert!(headers.starts_with("POST /v1/devices/device-1/input-sequences HTTP/1.1\r\n"));
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Content-Length: ")
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap();
            let mut body = vec![0_u8; content_length];
            stream.read_exact(&mut body).unwrap();
            let posted =
                parse_input_sequence_json_with_command_id(&body, &uuid::Uuid::now_v7().to_string())
                    .unwrap();
            assert_eq!(
                uuid::Uuid::parse_str(&posted.command_id)
                    .unwrap()
                    .get_version_num(),
                7
            );
            let response = format!(
                r#"{{"command_id":"{}","device_id":"device-1","outcome":"EMITTED","terminal":true,"possible_start":true,"terminal_zero_confirmed":true}}"#,
                posted.command_id
            );
            write!(
                stream,
                "HTTP/1.1 202 Accepted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });
        let path =
            std::env::temp_dir().join(format!("keyferry-input-{}.json", uuid::Uuid::now_v7()));
        fs::write(
            &path,
            br#"{"schema":"keyferry.input-sequence.v1","arm":"command-scoped","start_within_ms":5000,"actions":[{"type":"click","button":"button_1"}]}"#,
        )
        .unwrap();
        let client = Client {
            endpoint: Endpoint {
                host: "127.0.0.1".to_owned(),
                port,
            },
            token: "test-token".to_owned(),
        };
        let args = vec![
            "input-sequence".to_owned(),
            "device-1".to_owned(),
            "--input".to_owned(),
            path.to_string_lossy().into_owned(),
        ];
        assert_eq!(run_input_sequence(&client, &args), 0);
        server.join().unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn local_recovery_cli_is_explicit_and_rejects_unknown_actions_before_spawn() {
        assert!(help_text().contains(
            "local-status --owner-kit PATH [--device UUID]  (direct USB; exact UUID for multi-device kits; password from stdin)"
        ));
        assert!(help_text().contains("local-recover --owner-kit PATH [--device UUID] ACTION"));
        assert!(help_text().contains("UNKNOWN is never retried automatically"));
        let selected = "019d1234-5678-7abc-8123-456789abcdef";
        assert!(valid_local_helper_args(&[
            "local-status".into(),
            "--owner-kit".into(),
            "owner-kit.json".into(),
            "--device".into(),
            selected.into(),
        ]));
        assert!(valid_local_helper_args(&[
            "local-recover".into(),
            "--owner-kit".into(),
            "owner-kit.json".into(),
            "--device".into(),
            selected.into(),
            "restart-network".into(),
        ]));
        for invalid in ["", "another-device", "019D1234-5678-7ABC-8123-456789ABCDEF"] {
            assert!(!valid_local_helper_args(&[
                "local-recover".into(),
                "--owner-kit".into(),
                "owner-kit.json".into(),
                "--device".into(),
                invalid.into(),
                "restart-network".into(),
            ]));
        }
        assert_eq!(
            run_local_helper(&[
                "local-recover".to_owned(),
                "--owner-kit".to_owned(),
                "owner-kit.json".to_owned(),
                "type-text".to_owned(),
            ]),
            20
        );
    }

    #[test]
    fn capabilities_and_exact_device_status_use_read_only_routes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            for expected in [
                "GET /v1/capabilities HTTP/1.1",
                "GET /v1/devices/device-1 HTTP/1.1",
                "POST /v1/devices/device-1/maintenance/begin HTTP/1.1",
                "POST /v1/devices/device-1/maintenance/finish HTTP/1.1",
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = [0_u8; 1024];
                let count = stream.read(&mut bytes).unwrap();
                assert!(std::str::from_utf8(&bytes[..count])
                    .unwrap()
                    .starts_with(expected));
                let response = "{}";
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
            }
        });
        let client = Client {
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port,
            },
            token: "test-token".into(),
        };
        assert!(run_command(&client, vec!["capabilities".into()]).is_ok());
        assert!(run_command(&client, vec!["status".into(), "device-1".into()]).is_ok());
        assert!(run_command(
            &client,
            vec!["maintenance".into(), "device-1".into(), "begin".into()]
        )
        .is_ok());
        assert!(run_command(
            &client,
            vec!["maintenance".into(), "device-1".into(), "finish".into()]
        )
        .is_ok());
        assert!(run_command(
            &client,
            vec!["status".into(), "device-1".into(), "extra".into()]
        )
        .is_err());
        assert!(run_command(
            &client,
            vec!["maintenance".into(), "device-1".into(), "restart".into()]
        )
        .is_err());
        server.join().unwrap();
    }
}
