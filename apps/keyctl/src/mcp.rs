//! Newline-delimited JSON-RPC MCP over stdio only. stdout is exclusively protocol.
use super::{
    frames::{self, Frame, FrameSource, Region},
    geometry::{self, Geometry},
    ocr::{self, NativeOcr, Ocr},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

#[path = "daemon_frames.rs"]
mod daemon_frames;
use daemon_frames::{automatic_device, DaemonFrames};

const MAX_MESSAGE: usize = 65_536;
const FRAME_WAIT: Duration = Duration::from_secs(20);
const HELP: &str = "keyctl mcp [--device UUID] [--source NAME_OR_ID]\n  Stdio MCP; screenshots/OCR stay in memory. No listener or automatic app launch.\n  Calibrate each session before pointer tools, or explicitly pass uncalibrated:true.\n  Ordinary ASCII text only; secrets belong to keyctl secure-text's owner dialog.\nkeyctl capture calibrate DEVICE [--source NAME_OR_ID]\n  Moves pointer through daemon once per probe; requires an approved harmless target.";

fn options(args: &[String]) -> Result<(Option<String>, Option<String>), &'static str> {
    if !args.len().is_multiple_of(2) {
        return Err("input.usage");
    }
    let (mut device, mut source) = (None, None);
    for p in args.chunks_exact(2) {
        match p[0].as_str() {
            "--device" if device.is_none() => device = Some(p[1].clone()),
            "--source" if source.is_none() && !p[1].is_empty() => source = Some(p[1].clone()),
            _ => return Err("input.usage"),
        }
    }
    if let Some(device) = &device {
        uuid::Uuid::parse_str(device).map_err(|_| "input.device_uuid")?;
    }
    Ok((device, source))
}

pub(super) fn run(args: &[String], url: &str, token_file: &Path) -> u8 {
    if args == ["--help"] {
        println!("{HELP}");
        return 0;
    }
    let (device, source) = match options(args) {
        Ok(v) => v,
        Err(code) => {
            eprintln!("{code}");
            return 20;
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let cancelling = cancelled.clone();
    if ctrlc::set_handler(move || {
        stopping.store(true, Ordering::Release);
        cancelling.store(true, Ordering::Release);
    })
    .is_err()
    {
        eprintln!("internal.interrupt_handler");
        return 25;
    }
    let mut server = Server::new(
        device.unwrap_or_default(),
        source,
        url,
        token_file,
        super::state_root().join("capture-geometry"),
        |source| DaemonFrames::new(source, url, token_file),
        NativeOcr,
    );
    let active = Arc::new(Mutex::new(None::<Value>));
    let current = active.clone();
    let cancel_reader = cancelled.clone();
    // Bounded requests; cancellation bypasses the queue, never resubmits an action.
    let (tx, rx) = mpsc::sync_channel(8);
    thread::spawn(move || {
        let mut input = io::stdin().lock();
        loop {
            match read_message(&mut input) {
                Ok(Some(v)) if v["method"] == "notifications/cancelled" => {
                    if current.lock().expect("active request").as_ref()
                        == Some(&v["params"]["requestId"])
                    {
                        cancel_reader.store(true, Ordering::Release);
                    }
                }
                Ok(Some(v)) => {
                    if tx.send(Ok(v)).is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = tx.send(Err("stdio.closed"));
                    break;
                }
                Err(code) => {
                    if tx.send(Err(code)).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut output = io::stdout().lock();
    while !stop.load(Ordering::Acquire) {
        let message = match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(Ok(v)) => v,
            Ok(Err("stdio.closed")) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Ok(Err(code)) => {
                if write_message(&mut output, &rpc_error(Value::Null, -32700, code)).is_err() {
                    return 25;
                }
                continue;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
        };
        cancelled.store(false, Ordering::Release);
        *active.lock().expect("active request") = message.get("id").cloned();
        let response = server.dispatch(message, &cancelled);
        *active.lock().expect("active request") = None;
        if let Some(response) = response {
            if write_message(&mut output, &response).is_err() {
                return 25;
            }
        }
    }
    0
}

pub(super) fn calibrate_cli(args: &[String], url: &str, token: &Path) -> u8 {
    let Some(device) = args.first() else {
        eprintln!("{HELP}");
        return 20;
    };
    let mut converted = vec!["--device".into(), device.clone()];
    converted.extend_from_slice(&args[1..]);
    let (device, source) = match options(&converted) {
        Ok(v) => v,
        Err(c) => {
            eprintln!("{c}");
            return 20;
        }
    };
    let interrupted = Arc::new(AtomicBool::new(false));
    let signal = interrupted.clone();
    if ctrlc::set_handler(move || signal.store(true, Ordering::Release)).is_err() {
        return 25;
    }
    let mut server = Server::new(
        device.unwrap_or_default(),
        source,
        url,
        token,
        super::state_root().join("capture-geometry"),
        |source| DaemonFrames::new(source, url, token),
        NativeOcr,
    );
    match server.calibrate(&interrupted) {
        Ok(v) => {
            println!(
                "{}",
                json!({"schema":"keyferry.capture-calibration.v1","result":v})
            );
            0
        }
        Err(e) => {
            println!(
                "{}",
                json!({"schema":"keyferry.capture-error.v1","error":e})
            );
            25
        }
    }
}

fn read_message(reader: &mut impl BufRead) -> Result<Option<Value>, &'static str> {
    let mut bytes = Vec::new();
    let n = Read::by_ref(reader)
        .take((MAX_MESSAGE + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "stdio.read")?;
    if n == 0 {
        return Ok(None);
    }
    if n > MAX_MESSAGE || bytes.last() != Some(&b'\n') {
        if bytes.last() != Some(&b'\n') {
            // Drain without retaining oversized payloads.
            loop {
                let chunk = reader.fill_buf().map_err(|_| "stdio.read")?;
                if chunk.is_empty() {
                    break;
                }
                let end = chunk.iter().position(|v| *v == b'\n');
                let count = end.map_or(chunk.len(), |i| i + 1);
                reader.consume(count);
                if end.is_some() {
                    break;
                }
            }
        }
        return Err("stdio.message_limit_or_incomplete");
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "rpc.invalid_json")
}

fn write_message(output: &mut impl Write, v: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, v)?;
    output.write_all(b"\n")?;
    output.flush()
}

fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn failure(code: &str) -> Value {
    json!({"code":code,"message": match code {
        "device.select_required" => "Select a device using list_devices and select_device; no unambiguous authenticated device is available.",
        "capture.no_source_anywhere" => "No capture source is available on this controller or an authenticated owner peer. Connect a capture card and check list_capture_sources for discovery errors.",
        "capture.source_unavailable" => "The capture source is absent or unavailable. Connect the capture card and request sources again; retries are backed off and no input was sent.",
        "capture.peer_offline" => "The selected capture peer is offline or its fresh device proof failed. Check controller connectivity; no input was sent.",
        "capture.select_required" => "Select a capture source using list_capture_sources and select_capture_source; no unambiguous source is available.",
        "calibration.cursor_not_seen" => "Cursor not seen: capture may show a different machine. Check HDMI main-display mirroring and a static harmless target.",
        "pointer.capability_required" => "Device lacks POINTER_EXTENDED_V1; keyboard tools remain available.",
        "pointer.calibration_required" => "Calibrate this capture/device binding first, or explicitly pass uncalibrated:true for full-frame linear mapping.",
        "pointer.screenshot_required" => "Take a fresh screenshot after capture geometry changes before pointer input.",
        "ocr.unsupported_platform" => "Native find_text is currently supported on Windows only; macOS Vision is not implemented.",
        "ocr.engine_unavailable" => "Windows OCR unavailable; install an OCR-capable language in Windows language settings.",
        "text.unsupported" => "Only supported ASCII is accepted; no normalization. Use the owner-only secure-text dialog for secrets.",
        _ => code,
    }})
}
fn tool_result(value: Value, error: bool) -> Value {
    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":error})
}

// One schema table governs tool listing AND runtime validation.
fn tools() -> Vec<Value> {
    let pixel = json!({"type":"integer","minimum":0,"maximum":frames::MAX_SIDE - 1});
    let boolean = json!({"type":"boolean"});
    let button = json!({"type":"string","enum":["left","right","middle"]});
    let region = json!({"type":"object","additionalProperties":false,"required":["x","y","width","height"],
        "properties":{"x":pixel,"y":pixel,"width":{"type":"integer","minimum":1,"maximum":frames::MAX_SIDE},"height":{"type":"integer","minimum":1,"maximum":frames::MAX_SIDE}}});
    let mut result = Vec::new();
    let mut add = |name: &str,
                   description: &str,
                   properties: Value,
                   required: &[&str],
                   read_only: bool| {
        result.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","additionalProperties":false,"properties":properties,"required":required},
            "annotations":{"readOnlyHint":read_only,"destructiveHint":!read_only,"idempotentHint":read_only,"openWorldHint":false}}));
    };
    add("screenshot","Latest HDMI frame as a bounded PNG image plus pixel/native geometry. Memory only; save_path explicitly saves a new file.",json!({"save_path":{"type":"string","minLength":1,"maxLength":4096}}),&[],true);
    add("move","Move absolute pointer to screenshot pixels; requires calibrated binding or explicit uncalibrated:true.",json!({"x":pixel,"y":pixel,"uncalibrated":boolean}),&["x","y"],false);
    add(
        "click",
        "Move then click once or double; left/right/middle. Never retries a command.",
        json!({"x":pixel,"y":pixel,"button":button,"double":boolean,"uncalibrated":boolean}),
        &["x", "y"],
        false,
    );
    add("drag","Balanced atomic drag from screenshot pixels to screenshot pixels; releases in the same command.",json!({"from_x":pixel,"from_y":pixel,"to_x":pixel,"to_y":pixel,"button":button,"uncalibrated":boolean}),&["from_x","from_y","to_x","to_y"],false);
    add("scroll","Move to screenshot pixels, then scroll detents: dy positive up, dx positive right; target OS may invert.",json!({"x":pixel,"y":pixel,"dx":{"type":"integer","minimum":-127,"maximum":127},"dy":{"type":"integer","minimum":-127,"maximum":127},"uncalibrated":boolean}),&["x","y","dx","dy"],false);
    add("type_text","Type ordinary supported ASCII through daemon input admission. Do not supply secrets; secure text is an owner-only dialog.",json!({"text":{"type":"string","minLength":1,"maxLength":4096}}),&["text"],false);
    add("key","Tap one named key or chord of named keys; uses keyctl keys' canonical registry/alias table (CMD, OPTION, CTRL, etc.).",json!({"keys":{"type":"array","minItems":1,"maxItems":14,"items":{"type":"string","minLength":1,"maxLength":64}}}),&["keys"],false);
    for name in ["wait_for_stable", "wait_for_change"] {
        add(name,"Observe fresh frames, optionally within a screenshot-pixel region. Returns matched or timed_out; never treats a frozen/missing stream as stable.",json!({"timeout_ms":{"type":"integer","minimum":1,"maximum":30000},"region":region}),&["timeout_ms"],true);
    }
    add("find_text","Local OCR line boxes in screenshot pixels, optional case-insensitive substring query. No persistence/logging; Windows only.",json!({"query":{"type":"string","maxLength":256}}),&[],true);
    add("calibrate","Move pointer at safe known positions, prove capture binding, fit geometry and verify an independent probe. Use a static harmless target. Persists only geometry.",json!({}),&[],false);
    add("status","Authenticated device/armed state, pointer capability, capture restart status and current/persisted geometry binding.",json!({}),&[],true);
    add(
        "list_devices",
        "List authorized sticks and authenticated routes.",
        json!({}),
        &[],
        true,
    );
    add(
        "select_device",
        "Choose an exact authenticated stick; clears calibration.",
        json!({"device":{"type":"string","minLength":36,"maxLength":36}}),
        &["device"],
        true,
    );
    add(
        "list_capture_sources",
        "List local and authenticated owner-controller capture sources.",
        json!({}),
        &[],
        true,
    );
    add(
        "select_capture_source",
        "Choose an exact capture source; clears calibration.",
        json!({"source":{"type":"string","minLength":1,"maxLength":1100}}),
        &["source"],
        true,
    );
    result
}

fn validate(value: &Value, schema: &Value) -> bool {
    let typed = match schema["type"].as_str() {
        Some("object") => value.is_object(),
        Some("integer") => value.as_i64().is_some(),
        Some("string") => value.is_string(),
        Some("boolean") => value.is_boolean(),
        Some("array") => value.is_array(),
        _ => false,
    };
    if !typed {
        return false;
    }
    if let Some(choices) = schema["enum"].as_array() {
        if !choices.contains(value) {
            return false;
        }
    }
    if let Some(n) = value.as_i64() {
        if schema["minimum"].as_i64().is_some_and(|min| n < min)
            || schema["maximum"].as_i64().is_some_and(|max| n > max)
        {
            return false;
        }
    }
    if let Some(s) = value.as_str() {
        let n = s.chars().count() as u64;
        if schema["minLength"].as_u64().is_some_and(|min| n < min)
            || schema["maxLength"].as_u64().is_some_and(|max| n > max)
        {
            return false;
        }
    }
    if let Some(a) = value.as_array() {
        let n = a.len() as u64;
        if schema["minItems"].as_u64().is_some_and(|min| n < min)
            || schema["maxItems"].as_u64().is_some_and(|max| n > max)
            || !a.iter().all(|v| validate(v, &schema["items"]))
        {
            return false;
        }
    }
    if let Some(o) = value.as_object() {
        if schema["required"]
            .as_array()
            .is_some_and(|a| a.iter().any(|k| !o.contains_key(k.as_str().unwrap_or(""))))
        {
            return false;
        }
        let Some(properties) = schema["properties"].as_object() else {
            return false;
        };
        if !o
            .iter()
            .all(|(k, v)| properties.get(k).is_some_and(|s| validate(v, s)))
        {
            return false;
        }
    }
    true
}

struct Server<F: FrameSource, O: Ocr> {
    device: String,
    device_choice: &'static str,
    source: Option<String>,
    url: String,
    token: PathBuf,
    root: PathBuf,
    frames: F,
    ocr: O,
    geometry: Option<Geometry>,
    bound_generation: Option<u64>,
    screenshot_geometry: Option<(u32, u32, (u32, u32), u64)>,
    loaded: bool,
    initialized: bool,
    ready: bool,
    seen: HashSet<String>,
}

impl<F: FrameSource, O: Ocr> Server<F, O> {
    fn new(
        device: String,
        source: Option<String>,
        url: &str,
        token: &Path,
        root: PathBuf,
        create: impl FnOnce(Option<String>) -> F,
        ocr: O,
    ) -> Self {
        Self {
            frames: create(source.clone()),
            device_choice: if device.is_empty() {
                "unselected"
            } else {
                "explicit"
            },
            device,
            source,
            url: url.into(),
            token: token.into(),
            root,
            ocr,
            geometry: None,
            bound_generation: None,
            screenshot_geometry: None,
            loaded: false,
            initialized: false,
            ready: false,
            seen: HashSet::new(),
        }
    }
    fn dispatch(&mut self, request: Value, cancelled: &AtomicBool) -> Option<Value> {
        let id = request.get("id").cloned();
        let method = request["method"].as_str();
        if request["jsonrpc"] != "2.0"
            || method.is_none()
            || id
                .as_ref()
                .is_some_and(|id| !id.is_string() && id.as_i64().is_none())
        {
            return Some(rpc_error(Value::Null, -32600, "rpc.invalid_request"));
        }
        let method = method.unwrap_or("");
        if id.is_none() {
            if method == "notifications/initialized" && self.initialized {
                self.ready = true;
            }
            return None;
        }
        let id = id.unwrap_or(Value::Null);
        if self.seen.len() >= 65_536 {
            return Some(rpc_error(id, -32000, "rpc.session_request_limit"));
        }
        if !self.seen.insert(id.to_string()) {
            return Some(rpc_error(id, -32600, "rpc.duplicate_id_no_replay"));
        }
        let result = match method {
            "initialize" if !self.initialized => {
                let version = request["params"]["protocolVersion"].as_str();
                if version.is_none()
                    || !request["params"]["capabilities"].is_object()
                    || !request["params"]["clientInfo"].is_object()
                {
                    return Some(rpc_error(id, -32602, "rpc.initialize_parameters"));
                }
                self.initialized = true;
                let version = match version.unwrap_or("") {
                    v @ ("2024-11-05" | "2025-03-26" | "2025-06-18" | "2025-11-25") => v,
                    _ => "2025-11-25",
                };
                json!({"protocolVersion":version,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"keyferry","version":env!("CARGO_PKG_VERSION")},
                    "instructions":"Screens and OCR may contain secrets. Calibrate a harmless target each session before pointer tools. Never retry UNKNOWN actions; inspect the target and reconcile command_id. Secure text stays in the owner-only dialog."})
            }
            "ping" => json!({}),
            _ if !self.ready => return Some(rpc_error(id, -32000, "rpc.not_initialized")),
            "tools/list" => json!({"tools":tools()}),
            "tools/call" => {
                let Some(name) = request["params"]["name"].as_str() else {
                    return Some(rpc_error(id, -32602, "rpc.tool_name"));
                };
                let schemas = tools();
                let Some(tool) = schemas.iter().find(|t| t["name"] == name) else {
                    return Some(rpc_error(id, -32602, "rpc.unknown_tool"));
                };
                let empty = json!({});
                let args = request["params"].get("arguments").unwrap_or(&empty);
                if !validate(args, &tool["inputSchema"]) {
                    tool_result(json!({"error":failure("input.tool_arguments")}), true)
                } else {
                    match self.call(name, args, cancelled) {
                        Ok(v) => v,
                        Err(e) => tool_result(json!({"error":e}), true),
                    }
                }
            }
            _ => return Some(rpc_error(id, -32601, "rpc.method_not_found")),
        };
        Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
    }
    fn client(&self) -> Result<super::Client, Value> {
        let endpoint = super::parse_endpoint(&self.url).map_err(|_| failure("input.url"))?;
        let token =
            super::load_token(&self.token).map_err(|_| failure("daemon.token_unavailable"))?;
        Ok(super::Client { endpoint, token })
    }
    fn devices(&self) -> Result<Value, Value> {
        let response = self
            .client()?
            .request("GET", "/v1/devices", None)
            .map_err(|_| failure("daemon.unavailable"))?;
        serde_json::from_str(&response).map_err(|_| failure("protocol.invalid_response"))
    }
    fn choose_device(&mut self) -> Result<(), Value> {
        if self.device.is_empty() || self.device_choice.starts_with("automatic") {
            let inventory = self.devices()?;
            let chosen = automatic_device(&inventory)?;
            if self.device.is_empty() {
                if let Some((id, why)) = chosen {
                    self.device = id;
                    self.device_choice = why;
                }
            } else if chosen.as_ref().is_none_or(|(id, _)| id != &self.device) {
                self.device.clear();
                self.device_choice = "unselected";
                self.clear_binding();
                return Err(failure("device.select_required"));
            }
        }
        if self.device.is_empty() {
            return Err(failure("device.select_required"));
        }
        Ok(())
    }
    fn clear_binding(&mut self) {
        self.geometry = None;
        self.bound_generation = None;
        self.screenshot_geometry = None;
        self.loaded = false;
    }
    fn device_status(&self) -> Result<Value, Value> {
        if self.device.is_empty() {
            return Err(failure("device.select_required"));
        }
        let response = self
            .client()?
            .request("GET", &format!("/v1/devices/{}", self.device), None)
            .map_err(|_| failure("daemon.unavailable"))?;
        serde_json::from_str(&response).map_err(|_| failure("protocol.invalid_response"))
    }
    fn require_pointer(&self) -> Result<(), Value> {
        let status = self.device_status()?;
        if status["firmware"]["device_capability_mask"]
            .as_u64()
            .unwrap_or(0)
            & u64::from(keyferry_protocol::capability::POINTER_EXTENDED_V1)
            == 0
        {
            return Err(failure("pointer.capability_required"));
        }
        if status["link"] != "authenticated" {
            return Err(failure("device.not_authenticated"));
        }
        Ok(())
    }
    fn frame(&mut self, cancelled: &AtomicBool) -> Result<Arc<Frame>, Value> {
        let f = self
            .frames
            .latest(None, FRAME_WAIT, cancelled)
            .map_err(failure)?;
        if let Some(source) = self.frames.status()["source"].as_str() {
            self.source = Some(source.into());
        }
        if !self.loaded {
            self.geometry = geometry::load(
                &self.root,
                &self.device,
                self.source.as_deref().unwrap_or("auto"),
            )
            .map_err(failure)?;
            self.loaded = true;
        }
        if self.bound_generation.is_some_and(|g| g != f.generation)
            || self.geometry.as_ref().is_some_and(|g| {
                !g.matches(&self.device, self.source.as_deref().unwrap_or("auto"), &f)
            })
        {
            self.bound_generation = None;
            self.geometry = None;
        }
        Ok(f)
    }
    fn submission(
        &self,
        actions: Vec<Value>,
        pointer: bool,
        cancelled: &AtomicBool,
    ) -> Result<Value, Value> {
        if cancelled.load(Ordering::Acquire) {
            return Err(failure("request.cancelled"));
        }
        let mut request = json!({"schema":if pointer {"keyferry.input-sequence.v2"}else{"keyferry.input-sequence.v1"},"arm":"command-scoped","start_within_ms":5000,"actions":actions});
        if !pointer {
            request["keyboard_profile"] = json!(super::LEGACY_WIRE_MAPPING);
        }
        let raw = request.to_string();
        let prepared = super::prepare_input_sequence(raw.as_bytes()).map_err(failure)?;
        let client = self.client()?;
        let mut result = None;
        let exit = super::submit_prepared_with_interrupt(
            &client,
            &self.device,
            false,
            "/input-sequences",
            &prepared.command_id,
            &prepared.body,
            cancelled,
            |s| result = serde_json::from_str::<Value>(&s).ok(),
        );
        let mut result = result.ok_or_else(|| failure("protocol.invalid_response"))?;
        if result["terminal"] == false && result["possible_start"] == true {
            result["outcome"] = json!("UNKNOWN");
            result["terminal"] = json!(true);
            result["terminal_zero_confirmed"] = json!(false);
            result["terminal_release_completed"] = json!(false);
        }
        if exit != 0 || result["outcome"] != "EMITTED" {
            return Err(
                json!({"code":"command.failed_or_unknown","command":result,"message":"Do not replay; inspect target and reconcile command_id. UNKNOWN may have started."}),
            );
        }
        Ok(result)
    }
    fn point(&self, f: &Frame, x: f64, y: f64, uncalibrated: bool) -> Result<[f64; 2], Value> {
        // Bounds check first, even with calibration; crop coordinates cannot escape a screenshot.
        geometry::linear(f, x, y).map_err(failure)?;
        if uncalibrated {
            return geometry::linear(f, x, y).map_err(failure);
        }
        if self.bound_generation != Some(f.generation) {
            return Err(failure("pointer.calibration_required"));
        }
        self.geometry
            .as_ref()
            .ok_or_else(|| failure("pointer.calibration_required"))?
            .map(x, y)
            .map_err(failure)
    }
    fn call(&mut self, name: &str, args: &Value, cancelled: &AtomicBool) -> Result<Value, Value> {
        match name {
            "list_devices" => return self.devices().map(|v| tool_result(v, false)),
            "select_device" => {
                let inventory = self.devices()?;
                let id = args["device"].as_str().unwrap_or("");
                if !inventory["devices"].as_array().is_some_and(|a| {
                    a.iter()
                        .any(|d| d["id"] == id && d["link"] == "authenticated")
                }) {
                    return Err(failure("device.not_authenticated_or_authorized"));
                }
                self.device = id.into();
                self.device_choice = "selected";
                self.clear_binding();
                return Ok(tool_result(
                    json!({"device":self.device,"selection":self.device_choice}),
                    false,
                ));
            }
            "list_capture_sources" => {
                return self
                    .frames
                    .sources()
                    .map(|v| tool_result(v, false))
                    .map_err(failure)
            }
            "select_capture_source" => {
                let source = args["source"].as_str().unwrap_or("");
                self.frames.select(source).map_err(failure)?;
                self.source = Some(source.into());
                self.clear_binding();
                return Ok(tool_result(self.frames.status(), false));
            }
            _ => {}
        }
        let selection = self.choose_device();
        self.frames.device(&self.device);
        if name == "status" {
            let source_error = self.frames.resolve().err();
            let capture = self.frames.status();
            if !capture["error"].is_null()
                || capture["generation"]
                    .as_u64()
                    .is_some_and(|g| self.bound_generation.is_some_and(|b| b != g))
            {
                self.bound_generation = None;
                self.geometry = None;
            }
            let device = self.device_status();
            return Ok(tool_result(
                json!({"selected_device":if self.device.is_empty(){None}else{Some(&self.device)},"device_selection":self.device_choice,"selection_error":selection.err(),
                "device":device.as_ref().ok(),"device_error":device.as_ref().err(),"capture":self.frames.status(),"capture_selection_error":source_error,
                "binding_verified_this_session":self.bound_generation.is_some(),"geometry":self.geometry,"ocr":self.frames.status().get("ocr").cloned().unwrap_or_else(||json!(if cfg!(windows){"windows-native"}else{"unsupported"}))}),
                false,
            ));
        }
        if [
            "calibrate",
            "move",
            "click",
            "drag",
            "scroll",
            "type_text",
            "key",
        ]
        .contains(&name)
        {
            selection?;
        }
        if name == "calibrate" {
            return self.calibrate(cancelled).map(|v| tool_result(v, false));
        }
        if name == "type_text" {
            let text = args["text"].as_str().unwrap_or("");
            if !text.is_ascii() {
                return Err(failure("text.unsupported"));
            }
            return self
                .submission(vec![json!({"type":"text","value":text})], false, cancelled)
                .map(|v| tool_result(v, false));
        }
        if name == "key" {
            let keys = args["keys"]
                .as_array()
                .ok_or_else(|| failure("input.keys"))?;
            let action = if keys.len() == 1 {
                json!({"type":"tap","key":keys[0]})
            } else {
                json!({"type":"chord","keys":keys})
            };
            return self
                .submission(vec![action], false, cancelled)
                .map(|v| tool_result(v, false));
        }
        self.frames.request_ocr(name == "find_text");
        let frame = self.frame(cancelled)?;
        if name == "screenshot" {
            let png = frame.png().map_err(failure)?;
            if let Some(path) = args["save_path"].as_str() {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|_| failure("capture.output"))?;
                if file.write_all(&png).and_then(|()| file.flush()).is_err() {
                    drop(file);
                    let _ = std::fs::remove_file(path);
                    return Err(failure("capture.output"));
                }
            }
            self.screenshot_geometry =
                Some((frame.width, frame.height, frame.native, frame.generation));
            let (signal, mean_luma) = keyferry_capture::capture::signal(&frame.rgb);
            let metadata = json!({"signal":signal,"mean_luma":mean_luma,"width":frame.width,"height":frame.height,"native_width":frame.native.0,"native_height":frame.native.1,
                "frame_id":frame.serial,"capture_generation":frame.generation,"frame_age_ms":frame.at.elapsed().as_millis(),"calibrated":self.bound_generation==Some(frame.generation),
                "geometry":self.geometry,"active_video_rectangle":self.geometry.as_ref().map(Geometry::active_rectangle),"capture":self.frames.status()});
            let mut result = tool_result(metadata, false);
            result["content"]
                .as_array_mut()
                .expect("tool content")
                .insert(
                    0,
                    json!({"type":"image","mimeType":"image/png","data":STANDARD.encode(png)}),
                );
            return Ok(result);
        }
        if name == "find_text" {
            let boxes = ocr::filter(
                match self.frames.ocr_result() {
                    Some(boxes) => boxes,
                    None => self.ocr.recognize(&frame).map_err(failure)?,
                },
                args["query"].as_str(),
            );
            self.screenshot_geometry =
                Some((frame.width, frame.height, frame.native, frame.generation));
            return Ok(tool_result(
                json!({"boxes":boxes,"width":frame.width,"height":frame.height,"frame_id":frame.serial}),
                false,
            ));
        }
        if name == "wait_for_stable" || name == "wait_for_change" {
            return self
                .wait(name, args, frame, cancelled)
                .map(|v| tool_result(v, false));
        }
        self.require_pointer()?;
        if self.screenshot_geometry
            != Some((frame.width, frame.height, frame.native, frame.generation))
        {
            return Err(failure("pointer.screenshot_required"));
        }
        let uncalibrated = args["uncalibrated"].as_bool().unwrap_or(false);
        let button = match args["button"].as_str().unwrap_or("left") {
            "left" => "button_1",
            "right" => "button_2",
            _ => "button_3",
        };
        let coordinate = |x: &str, y: &str| {
            self.point(
                &frame,
                args[x].as_f64().unwrap_or(-1.0),
                args[y].as_f64().unwrap_or(-1.0),
                uncalibrated,
            )
        };
        let p = if name == "drag" {
            coordinate("from_x", "from_y")?
        } else {
            coordinate("x", "y")?
        };
        let mut actions = vec![json!({"type":"move_absolute","x":p[0],"y":p[1]})];
        match name {
            "move"=>{},
            "click"=>actions.push(json!({"type":if args["double"].as_bool().unwrap_or(false){"double_click"}else{"click"},"button":button})),
            "drag"=>{let to=coordinate("to_x","to_y")?;actions.push(json!({"type":"drag","button":button,"x":to[0],"y":to[1],"hold_ms":40}));},
            "scroll"=>actions.push(json!({"type":"scroll","vertical":args["dy"],"horizontal":args["dx"]})),
            _=>return Err(failure("rpc.unknown_tool")),
        }
        let result = self.submission(actions, true, cancelled)?;
        Ok(tool_result(
            json!({"command":result,"uncalibrated":uncalibrated,"mapping":if uncalibrated{"linear-full-frame"}else{"calibrated"}}),
            false,
        ))
    }
    fn wait(
        &mut self,
        name: &str,
        args: &Value,
        first: Arc<Frame>,
        cancelled: &AtomicBool,
    ) -> Result<Value, Value> {
        let timeout = Duration::from_millis(args["timeout_ms"].as_u64().unwrap_or(1));
        let region = if let Some(value) = args.get("region") {
            Some(
                serde_json::from_value::<Region>(value.clone())
                    .map_err(|_| failure("input.region"))?,
            )
        } else {
            None
        };
        if region.is_some_and(|r| !r.valid(&first)) {
            return Err(failure("input.region"));
        }
        let start = Instant::now();
        let mut stable = Instant::now();
        let mut previous = first.clone();
        let mut samples = 0;
        loop {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Ok(
                    json!({"matched":false,"timed_out":true,"elapsed_ms":start.elapsed().as_millis(),"frames":samples}),
                );
            }
            let next = match self.frames.latest(
                Some(previous.serial),
                remaining.min(Duration::from_secs(2)),
                cancelled,
            ) {
                Ok(f) => f,
                Err("capture.frame_timeout") if start.elapsed() >= timeout => continue,
                Err(e) => return Err(failure(e)),
            };
            let delta = frames::difference(&previous, &next, region).map_err(failure)?;
            let baseline = frames::difference(&first, &next, region).map_err(failure)?;
            samples += 1;
            if delta > 0.002 {
                stable = Instant::now();
            }
            let matched = if name == "wait_for_change" {
                baseline > 0.01
            } else {
                samples >= 3 && stable.elapsed() >= Duration::from_millis(300)
            };
            if matched {
                return Ok(
                    json!({"matched":true,"timed_out":false,"elapsed_ms":start.elapsed().as_millis(),"frames":samples,"difference":if name=="wait_for_change"{baseline}else{delta},"frame_id":next.serial}),
                );
            }
            previous = next;
        }
    }
    fn probe(&mut self, p: [f64; 2], cancelled: &AtomicBool) -> Result<(Arc<Frame>, Value), Value> {
        let before = self.frame(cancelled)?;
        let receipt = self.submission(
            vec![json!({"type":"move_absolute","x":p[0],"y":p[1]})],
            true,
            cancelled,
        )?;
        // Ignore frames captured while the command was still running.
        let complete = Instant::now();
        let deadline = complete + Duration::from_secs(3);
        let mut serial = before.serial;
        loop {
            let f = self
                .frames
                .latest(
                    Some(serial),
                    deadline.saturating_duration_since(Instant::now()),
                    cancelled,
                )
                .map_err(failure)?;
            serial = f.serial;
            if (f.width, f.height, f.native, f.generation)
                != (
                    before.width,
                    before.height,
                    before.native,
                    before.generation,
                )
            {
                return Err(failure("capture.geometry_changed"));
            }
            if f.at >= complete + Duration::from_millis(120) {
                return Ok((f, receipt));
            }
            if Instant::now() >= deadline {
                return Err(failure("calibration.frame_timeout"));
            }
        }
    }
    fn calibrate(&mut self, cancelled: &AtomicBool) -> Result<Value, Value> {
        self.choose_device()?;
        self.frames.device(&self.device);
        self.bound_generation = None;
        self.geometry = None;
        self.loaded = true;
        self.require_pointer()?;
        let positions = [
            [0.12, 0.15],
            [0.80, 0.20],
            [0.25, 0.78],
            [0.73, 0.72],
            [0.45, 0.42],
            [0.60, 0.60],
        ];
        let mut captured = Vec::new();
        let mut receipts = Vec::new();
        // Only three frames retained while streaming probes; snapshots never hit disk.
        let mut samples = Vec::new();
        for (i, p) in positions.iter().enumerate() {
            let (f, receipt) = self.probe(*p, cancelled)?;
            receipts.push(json!({"position":p,"frame_id":f.serial,"command":receipt}));
            captured.push(f);
            if captured.len() == 3 {
                let point =
                    geometry::cursor(&captured[0], &captured[1], &captured[2]).map_err(failure)?;
                samples.push((positions[i - 1], point));
                captured.remove(0);
            }
        }
        let last = captured
            .last()
            .ok_or_else(|| failure("calibration.insufficient_samples"))?;
        let source = self.source.as_deref().unwrap_or("auto");
        let fitted = geometry::fit(&self.device, source, last, &samples).map_err(failure)?;
        let before = last.clone();
        let check = [0.35, 0.55];
        let (middle, receipt) = self.probe(check, cancelled)?;
        receipts.push(json!({"position":check,"frame_id":middle.serial,"command":receipt}));
        let (after, receipt) = self.probe(positions[0], cancelled)?;
        receipts.push(json!({"position":positions[0],"frame_id":after.serial,"command":receipt}));
        let observed = geometry::cursor(&before, &middle, &after).map_err(failure)?;
        if (0..2)
            .any(|a| (observed[a] - fitted.origin[a] - fitted.extent[a] * check[a]).abs() > 5.0)
        {
            return Err(failure("calibration.verification_failed"));
        }
        geometry::save(&self.root, &fitted).map_err(failure)?;
        self.bound_generation = Some(after.generation);
        self.geometry = Some(fitted.clone());
        Ok(
            json!({"bound":true,"geometry":fitted,"active_video_rectangle":fitted.active_rectangle(),"probes":receipts,"verification_error_px":[observed[0]-fitted.origin[0]-fitted.extent[0]*check[0],observed[1]-fitted.origin[1]-fitted.extent[1]*check[1]],"pointer_moved":true}),
        )
    }
}

#[cfg(test)]
#[path = "mcp_tests.rs"]
mod tests;
