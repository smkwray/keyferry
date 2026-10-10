//! Newline-delimited JSON-RPC MCP over stdio only. stdout is exclusively protocol.
use super::{
    frames::{self, Frame, FrameSource, Region},
    geometry::{self, Geometry},
    ocr::{self, NativeOcr, Ocr},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use keyferry_layouts::recipe::{
    self as recipes,
    routines::{self, Step},
    RecipeV1,
};
use keyferry_protocol::MAX_SCREENSHOT_SIDE;
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
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
const ACTION_WAIT: Duration = Duration::from_secs(3);
const SETTLE: Duration = Duration::from_millis(350);
const ANIMATION_SAMPLE: Duration = Duration::from_millis(1100);
// Live MCP comparison: JPEG was 32x smaller and returned 27% faster than fast PNG.
const DEFAULT_IMAGE_FORMAT: &str = "jpeg";
const GLIDE_HELP: &str = " The pointer always glides (~120-240 ms, eased) from its last position; buttons press after arrival.";
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

fn routine_steps(recipe: &RecipeV1, args: &Value) -> Result<Vec<Step>, Value> {
    if !recipe.is_routine() {
        return Err(failure("recipe.routine_required"));
    }
    recipes::validate(recipe).map_err(|e| failure(e.code()))?;
    if let Some(os) = args["target_os"].as_str() {
        let declared =
            serde_json::to_value(recipe.target_os).map_err(|_| failure("recipe.schema"))?;
        if declared != "any" && declared != os {
            return Err(failure("recipe.target_os_mismatch"));
        }
    }
    let params = recipes::parse_params(
        args.get("params")
            .unwrap_or(&json!({}))
            .to_string()
            .as_bytes(),
    )
    .map_err(|e| failure(e.code()))?;
    routines::resolve(recipe, &params, false).map_err(|e| failure(e.code()))
}

pub(super) fn routine_cli(args: &[String], url: &str, token: &Path) -> u8 {
    let execute = || -> Result<Value, Value> {
        let device = args.first().ok_or_else(|| failure("input.usage"))?;
        uuid::Uuid::parse_str(device).map_err(|_| failure("input.device_uuid"))?;
        let name = args.get(1).ok_or_else(|| failure("input.usage"))?;
        let mut source = None;
        let mut calibrate = false;
        let mut arguments = json!({"name":name});
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--calibrate" if !calibrate => calibrate = true,
                "--source" if source.is_none() => {
                    i += 1;
                    source = Some(args.get(i).ok_or_else(|| failure("input.usage"))?.clone());
                }
                "--target-os" if arguments.get("target_os").is_none() => {
                    i += 1;
                    arguments["target_os"] =
                        json!(args.get(i).ok_or_else(|| failure("input.usage"))?);
                }
                _ => return Err(failure("input.argv_payload_refused")),
            }
            i += 1;
        }
        let library = super::recipe::Library::current();
        let recipe = library.load(name).map_err(|e| e.json())?;
        recipes::validate(&recipe).map_err(|e| failure(e.code()))?;
        if recipe
            .parameters()
            .iter()
            .any(|p| p.kind != recipes::ParameterKind::Secure)
        {
            let bytes = super::recipe::read_capped(io::stdin().lock())
                .map_err(|_| failure("params.json"))?;
            // Strict parser runs again in run_routine; keep source/values out of errors.
            recipes::parse_params(&bytes).map_err(|e| failure(e.code()))?;
            arguments["params"] =
                serde_json::from_slice(&bytes).map_err(|_| failure("params.json"))?;
        }
        if arguments["target_os"]
            .as_str()
            .is_some_and(|os| !["macos", "windows", "linux", "any"].contains(&os))
        {
            return Err(failure("input.tool_arguments"));
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = cancelled.clone();
        ctrlc::set_handler(move || signal.store(true, Ordering::Release))
            .map_err(|_| failure("internal.interrupt_handler"))?;
        let mut server = Server::new(
            device.clone(),
            source,
            url,
            token,
            super::state_root().join("capture-geometry"),
            |source| DaemonFrames::new(source, url, token),
            NativeOcr,
        );
        routine_steps(&recipe, &arguments)?;
        if calibrate {
            server.calibrate(&cancelled)?;
            server.call("screenshot", &json!({}), &cancelled)?;
        }
        server.run_routine(&recipe, &arguments, false, false, &cancelled)
    };
    match execute() {
        Ok(result) => {
            super::emit_json_line(&result);
            if result["isError"] == true {
                25
            } else {
                0
            }
        }
        Err(error) => {
            super::emit_json_line(&json!({"error":error}));
            20
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
    let pixel = json!({"type":"integer","minimum":0,"maximum":MAX_SCREENSHOT_SIDE - 1});
    let boolean = json!({"type":"boolean"});
    let button = json!({"type":"string","enum":["left","right","middle"]});
    let region = json!({"type":"object","additionalProperties":false,"required":["x","y","width","height"],
        "properties":{"x":pixel,"y":pixel,"width":{"type":"integer","minimum":1,"maximum":MAX_SCREENSHOT_SIDE},"height":{"type":"integer","minimum":1,"maximum":MAX_SCREENSHOT_SIDE}}});
    let mut result = Vec::new();
    let mut add = |name: &str,
                   description: &str,
                   properties: Value,
                   required: &[&str],
                   read_only: bool| {
        let action = ["move", "click", "drag", "scroll", "key", "type_text"].contains(&name);
        let pointer = ["move", "click", "drag", "scroll"].contains(&name);
        let mut properties = properties;
        if action {
            properties["return_screenshot"] = json!({"type":"boolean","default":true});
            properties["format"] =
                json!({"type":"string","enum":["png","jpeg"],"default":DEFAULT_IMAGE_FORMAT});
        }
        let mut description = if action {
            format!("{description} Returns the observed post-action image by default (return_screenshot:false opts out), settled, latency_ms from EMITTED to visible change, and frame_id. Moves return when a compact cursor change is seen near the target; other actions require adaptive quiet on fresh frames within 3 s. settled:false never authorizes replay.")
        } else {
            description.to_owned()
        };
        if pointer {
            description.push_str(GLIDE_HELP);
        }
        result.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","additionalProperties":false,"properties":properties,"required":required},
            "annotations":{"readOnlyHint":read_only,"destructiveHint":!read_only,"idempotentHint":read_only,"openWorldHint":false}}));
    };
    add("screenshot","Latest HDMI frame as a bounded image (JPEG by default; format:png is lossless) plus pixel/native geometry. Memory only; save_path explicitly saves a new file.",json!({"format":{"type":"string","enum":["png","jpeg"],"default":DEFAULT_IMAGE_FORMAT},"save_path":{"type":"string","minLength":1,"maxLength":4096}}),&[],true);
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
    add("calibrate","Move pointer at safe known positions, prove capture binding, fit geometry and verify an independent probe. Masks small animations learned while stationary; waits up to 3 s per probe and reports measured latency_ms. Persists only geometry. Use an approved harmless target.",json!({}),&[],false);
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
    add("routines", "Discover saved recipes before improvising. Searches the shared skill library and local overrides. Example: {\"os\":\"macos\",\"query\":\"settings\"}. Invalid entries are counted explicitly.",
        json!({"query":{"type":"string","maxLength":256},"os":{"type":"string","enum":["macos","windows","linux","any"]},"tag":{"type":"string","maxLength":32}}),&[],true);
    add("routine_run", "Run a named keyferry.recipe.v1 routine once. Example: {\"name\":\"clear-stacked-dialogs\",\"params\":{\"count\":10,\"delay_ms\":800}}. Merges input stretches, stops at a failed check/non-EMITTED result, returns per-step receipts and a final image. target_os optionally asserts the target OS (never inferred from controller OS). Passwords only via secure_text's owner dialog; REQUESTED is not input proof.",
        json!({"name":{"type":"string","minLength":1,"maxLength":63},"params":{"type":"object","additionalProperties":true},"target_os":{"type":"string","enum":["macos","windows","linux","any"]},"format":{"type":"string","enum":["png","jpeg"]}}),&["name"],false);
    add(
        "routine_save",
        r#"Validate and save after a manual flow succeeds. Example: {"definition":{"schema":"keyferry.recipe.v1","name":"copy-all","target_os":"windows","verified":false,"steps":[{"type":"key","keys":["CTRL","A"]},{"type":"key","keys":["CTRL","C"]}]}}. Exclusive create; replace:true deliberately replaces. Generalize parameters and add checkpoints; never save secrets."#,
        json!({"definition":{"type":"object","additionalProperties":true},"replace":{"type":"boolean"}}),
        &["definition"],
        false,
    );
    let actions: Vec<Value> = result.iter().filter(|t| ["move", "click", "drag", "scroll", "key", "type_text"].contains(&t["name"].as_str().unwrap_or("")))
        .map(|t| json!({"type":"object","additionalProperties":false,"required":["tool","arguments"],"properties":{"tool":{"type":"string","enum":[t["name"]]},"arguments":t["inputSchema"],"repeat":{"type":"integer","minimum":1,"maximum":1000},"delay_ms":{"type":"integer","minimum":0,"maximum":10000},"settle":{"type":"boolean"}}})).collect();
    result.push(json!({"name":"batch","description":r#"Ad-hoc input through the routine executor: contiguous actions merge into one bounded command. Example: {"actions":[{"tool":"key","arguments":{"keys":["ESCAPE"]},"repeat":10,"delay_ms":800}],"settle":false}. Per-action settle:true inserts a stable checkpoint; settle defaults true after the last stretch. Stops on non-EMITTED/failed check; never retries. One final image by default. Pointer glides can split a long stretch into consecutive commands."#,
        "inputSchema":{"type":"object","additionalProperties":false,"required":["actions"],"properties":{"actions":{"type":"array","minItems":1,"maxItems":32,"items":{"anyOf":actions}},"repeat":{"type":"integer","minimum":1,"maximum":1000},"delay_ms":{"type":"integer","minimum":0,"maximum":10000},"settle":{"type":"boolean","default":true},"return_screenshot":{"type":"boolean","default":true},"format":{"type":"string","enum":["png","jpeg"],"default":DEFAULT_IMAGE_FORMAT}}},
        "annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":false}}));
    result
}

fn validate(value: &Value, schema: &Value) -> bool {
    if let Some(choices) = schema["anyOf"].as_array() {
        return choices.iter().any(|choice| validate(value, choice));
    }
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
        if schema["additionalProperties"] == true && schema.get("properties").is_none() {
            return true;
        }
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
    library: super::recipe::Library,
    secure_prompt: fn(&str, &str, &Path) -> Result<Value, &'static str>,
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
    animation: Option<(Arc<Frame>, frames::MotionMask, Instant)>,
    observed_latency: Duration,
    last_observed: Option<Arc<Frame>>,
    lease: Option<(String, std::fs::File)>,
}

/// One agent per stick on this controller: an OS file lock the system releases on exit or crash.
fn device_lease(root: &Path, device: &str) -> Result<std::fs::File, Value> {
    if device.is_empty()
        || !device
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(failure("device.select_required"));
    }
    let directory = root.join("device-leases");
    std::fs::create_dir_all(&directory).map_err(|_| failure("device.lease_unavailable"))?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(directory.join(format!("{device}.lock")))
        .map_err(|_| failure("device.lease_unavailable"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(failure("device.in_use_by_other_agent")),
        Err(_) => Err(failure("device.lease_unavailable")),
    }
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
            library: super::recipe::Library::current(),
            secure_prompt: super::secure_text_request,
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
            animation: None,
            observed_latency: SETTLE,
            last_observed: None,
            lease: None,
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
                    "instructions":"Screens and OCR may contain secrets. Calibrate a harmless target each session before pointer tools. Never retry UNKNOWN actions; inspect the target and reconcile command_id. Secure text stays in the owner-only dialog. Check routines before improvising; save successful generalized flows with routine_save."})
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
    /// `daemon.unavailable` only when the local daemon cannot be reached; its own refusal keeps
    /// the daemon's code.
    fn get_json(&self, path: &str) -> Result<Value, Value> {
        let response = self
            .client()?
            .request_raw("GET", path, None)
            .map_err(|_| failure("daemon.unavailable"))?;
        if response.status >= 400 {
            return Err(failure(&super::http_error_code(&response)));
        }
        serde_json::from_str(&response.body).map_err(|_| failure("protocol.invalid_response"))
    }
    fn devices(&self) -> Result<Value, Value> {
        self.get_json("/v1/devices")
    }
    fn choose_device(&mut self) -> Result<(), Value> {
        // A lost automatic choice never re-arms: the only remaining stick may be another agent's.
        if self.device_choice == "lost" {
            return Err(failure("device.select_required"));
        }
        if self.device.is_empty() || self.device_choice.starts_with("automatic") {
            let inventory = self.devices()?;
            let chosen = automatic_device(&inventory)?;
            if self.device.is_empty() {
                if let Some((id, why)) = chosen {
                    self.lease(&id)?;
                    self.device = id;
                    self.device_choice = why;
                }
            } else if chosen.as_ref().is_none_or(|(id, _)| id != &self.device) {
                self.device.clear();
                self.device_choice = "lost";
                self.lease = None;
                self.clear_binding();
                return Err(failure("device.select_required"));
            }
        }
        if self.device.is_empty() {
            return Err(failure("device.select_required"));
        }
        self.lease(&self.device.clone())
    }
    fn lease(&mut self, device: &str) -> Result<(), Value> {
        if self.lease.as_ref().is_none_or(|(held, _)| held != device) {
            self.lease = Some((device.to_owned(), device_lease(&self.root, device)?));
        }
        Ok(())
    }
    fn clear_binding(&mut self) {
        self.animation = None;
        self.last_observed = None;
        self.geometry = None;
        self.bound_generation = None;
        self.screenshot_geometry = None;
        self.loaded = false;
    }
    fn device_status(&self) -> Result<Value, Value> {
        if self.device.is_empty() {
            return Err(failure("device.select_required"));
        }
        self.get_json(&format!("/v1/devices/{}", self.device))
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
        self.submission_config(actions, pointer, None, 5000, cancelled)
    }
    fn submission_config(
        &self,
        actions: Vec<Value>,
        pointer: bool,
        timing: Option<keyferry_layouts::InputKeyboardTiming>,
        start_within_ms: u64,
        cancelled: &AtomicBool,
    ) -> Result<Value, Value> {
        if cancelled.load(Ordering::Acquire) {
            return Err(failure("request.cancelled"));
        }
        let keyboard = actions.iter().any(routines::has_keyboard);
        let mut request = json!({"schema":if pointer {"keyferry.input-sequence.v2"}else{"keyferry.input-sequence.v1"},"arm":"command-scoped","start_within_ms":start_within_ms,"actions":actions});
        if keyboard {
            request["keyboard_profile"] = json!(super::LEGACY_WIRE_MAPPING);
            if let Some(timing) = timing {
                request["keyboard_timing"] = json!(timing);
            }
        }
        let raw = request.to_string();
        let prepared = super::prepare_input_sequence(raw.as_bytes()).map_err(failure)?;
        let client = self.client()?;
        let mut result = None;
        let started = Instant::now();
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
        result["submission_ms"] = json!(started.elapsed().as_millis());
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
    /// Presumed pointer position (normalized HID) for the device, shared by every session on
    /// this controller. Absent or malformed means unknown: the next glide starts at
    /// `routines::GLIDE.origin`.
    fn pointer_path(&self) -> PathBuf {
        self.root.join(format!("{}.pointer.json", self.device))
    }
    fn presumed(&self) -> Option<[f64; 2]> {
        let at: [f64; 2] = serde_json::from_slice(&fs::read(self.pointer_path()).ok()?).ok()?;
        at.iter().all(|v| (0.0..=1.0).contains(v)).then_some(at)
    }
    /// Best effort: a lost write only costs one origin report on the next glide.
    fn presume(&self, at: [f64; 2]) {
        let tmp = self
            .root
            .join(format!(".pointer-{}.tmp", uuid::Uuid::now_v7()));
        let written = fs::create_dir_all(&self.root)
            .and_then(|()| fs::write(&tmp, json!(at).to_string()))
            .and_then(|()| fs::rename(&tmp, self.pointer_path()));
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
            let _ = fs::remove_file(self.pointer_path());
        }
    }
    /// Submit input ending with the pointer at `end`. A command that may have started presumes
    /// `end` (an interrupted glide stops on the segment toward it); one that cannot have
    /// started leaves the presumed position unchanged.
    fn submit_tracked(
        &mut self,
        actions: Vec<Value>,
        pointer: bool,
        end: Option<[f64; 2]>,
        timing: Option<keyferry_layouts::InputKeyboardTiming>,
        start_within_ms: u64,
        cancelled: &AtomicBool,
    ) -> Result<Value, Value> {
        let result = self.submission_config(actions, pointer, timing, start_within_ms, cancelled);
        let started = match &result {
            Ok(_) => true,
            Err(error) => error["command"]["possible_start"] == true,
        };
        if let Some(end) = end.filter(|_| pointer && started) {
            self.presume(end);
        }
        result
    }
    /// Compile input steps through this session's mapping from the presumed pointer position
    /// into one or more consecutive commands; sends nothing.
    fn stretch(
        &self,
        frame: &Frame,
        steps: &[Step],
        recipe: Option<&RecipeV1>,
        uncalibrated: bool,
    ) -> Result<Vec<routines::Stretch>, Value> {
        let mut mapping_error = None;
        routines::compile_stretch(
            steps,
            recipe.and_then(routines::timing),
            recipe.map_or(5000, routines::start_within),
            &mut |x, y| {
                self.point(frame, f64::from(x), f64::from(y), uncalibrated)
                    .map_err(|e| {
                        mapping_error = Some(e);
                        routines::mapping_error()
                    })
            },
            self.presumed(),
        )
        .map_err(|e| mapping_error.unwrap_or_else(|| failure(e.code())))
    }
    fn submit_stretch(
        &mut self,
        stretch: routines::Stretch,
        recipe: Option<&RecipeV1>,
        cancelled: &AtomicBool,
    ) -> Result<Value, Value> {
        self.submit_tracked(
            stretch.actions,
            stretch.pointer,
            stretch.cursor,
            recipe.and_then(routines::timing),
            recipe.map_or(5000, routines::start_within),
            cancelled,
        )
    }
    /// Glide to `p`, then the optional button action, as one command.
    fn glide_command(
        &mut self,
        p: [f64; 2],
        then: Option<Value>,
        cancelled: &AtomicBool,
    ) -> Result<Value, Value> {
        let mut at = self.presumed();
        let mut actions = routines::glide_to(&mut at, p);
        actions.extend(then);
        self.submit_tracked(actions, true, at, None, 5000, cancelled)
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
        if name == "batch" {
            return self.batch(args, cancelled);
        }
        if name == "routines" {
            return self
                .library
                .list(args, true)
                .map(|v| tool_result(v, false))
                .map_err(|e| e.json());
        }
        if name == "routine_save" {
            return self
                .library
                .save(
                    args["definition"].to_string().as_bytes(),
                    args["replace"] == true,
                )
                .map(|v| tool_result(v, false))
                .map_err(|e| e.json());
        }
        if name == "routine_run" {
            let recipe = self
                .library
                .load(args["name"].as_str().unwrap_or(""))
                .map_err(|e| e.json())?;
            return self.run_routine(&recipe, args, false, false, cancelled);
        }
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
                self.lease(id)?;
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
            let (before, mask) = self.stationary(cancelled)?;
            let mut result =
                self.submission(vec![json!({"type":"text","value":text})], false, cancelled)?;
            return self.finish_action(&before, &mask, &mut result, args, None, cancelled);
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
            let (before, mask) = self.stationary(cancelled)?;
            let mut result = self.submission(vec![action], false, cancelled)?;
            return self.finish_action(&before, &mask, &mut result, args, None, cancelled);
        }
        self.frames.request_ocr(name == "find_text");
        let frame = self.frame(cancelled)?;
        if name == "screenshot" {
            if let Some(path) = args["save_path"].as_str() {
                let (image, _) = frame
                    .image(args["format"].as_str().unwrap_or(DEFAULT_IMAGE_FORMAT))
                    .map_err(failure)?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|_| failure("capture.output"))?;
                if file.write_all(&image).and_then(|()| file.flush()).is_err() {
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
            return self.image_result(&frame, args, metadata);
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
        // The tool arguments are the routine step vocabulary; one compiler serves both.
        let mut step = args.clone();
        let object = step
            .as_object_mut()
            .ok_or_else(|| failure("input.tool_arguments"))?;
        for key in ["uncalibrated", "return_screenshot", "format"] {
            object.remove(key);
        }
        object.insert("type".into(), json!(name));
        let step: Step = serde_json::from_value(step).map_err(|_| failure("rpc.unknown_tool"))?;
        let (before, mask) = self.stationary(cancelled)?;
        // A reconnect during animation sampling invalidates the already compiled mapping.
        mask.changed(&frame, &before).map_err(failure)?;
        // One step never splits; the glide starts from the position presumed just before sending.
        let mut parts = self.stretch(&frame, std::slice::from_ref(&step), None, uncalibrated)?;
        let command = self.submit_stretch(parts.remove(0), None, cancelled)?;
        let mut result = json!({"command":command,"uncalibrated":uncalibrated,"mapping":if uncalibrated{"linear-full-frame"}else{"calibrated"}});
        let target = (name == "move").then(|| {
            [
                args["x"].as_f64().unwrap_or(-1.0),
                args["y"].as_f64().unwrap_or(-1.0),
            ]
        });
        self.finish_action(&before, &mask, &mut result, args, target, cancelled)
    }

    fn stationary(
        &mut self,
        cancelled: &AtomicBool,
    ) -> Result<(Arc<Frame>, frames::MotionMask), Value> {
        self.frames.request_ocr(false);
        let first = self.frame(cancelled)?;
        if let Some((prior, mut mask, at)) = self.animation.take() {
            if at.elapsed() < Duration::from_secs(30)
                && mask.learn(&prior, &first).is_ok()
                && mask.small()
            {
                self.animation = Some((first.clone(), mask.clone(), at));
                return Ok((first, mask));
            }
        }
        let mut mask = frames::MotionMask::new(&first);
        let start = Instant::now();
        let mut previous = first;
        while start.elapsed() < ANIMATION_SAMPLE {
            let remaining = ANIMATION_SAMPLE.saturating_sub(start.elapsed());
            match self
                .frames
                .latest(Some(previous.serial), remaining, cancelled)
            {
                Ok(next) => {
                    if next.serial <= previous.serial || next.at <= previous.at {
                        return Err(failure("capture.stale_frame"));
                    }
                    mask.learn(&previous, &next).map_err(failure)?;
                    previous = next;
                }
                Err("capture.frame_timeout") => break,
                Err(code) => return Err(failure(code)),
            }
        }
        self.animation = Some((previous.clone(), mask.clone(), Instant::now()));
        Ok((previous, mask))
    }

    /// A quiet old frame is not completion. First observe significant change, then require
    /// a continuous quiet interval on fresh frames. Screens and masks remain in memory.
    fn observe_action(
        &mut self,
        before: &Arc<Frame>,
        mask: &frames::MotionMask,
        cancelled: &AtomicBool,
    ) -> Result<(Arc<Frame>, Value), Value> {
        self.observe_target(before, mask, None, None, cancelled)
    }

    fn observe_target(
        &mut self,
        before: &Arc<Frame>,
        mask: &frames::MotionMask,
        target: Option<[f64; 2]>,
        region: Option<Region>,
        cancelled: &AtomicBool,
    ) -> Result<(Arc<Frame>, Value), Value> {
        let start = Instant::now();
        let mut previous = before.clone();
        let mut anchor = before.clone();
        let mut stable_since = start;
        let mut latency = None;
        // Large animations are not masked; they must settle normally.
        let unmasked = frames::MotionMask::new(before);
        let mask = if mask.small() { mask } else { &unmasked };
        loop {
            let remaining = ACTION_WAIT.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Ok((
                    previous.clone(),
                    json!({"settled":false,"latency_ms":latency.unwrap_or(start.elapsed().as_millis()),"frame_id":previous.serial}),
                ));
            }
            let next = match self
                .frames
                .latest(Some(previous.serial), remaining, cancelled)
            {
                Ok(next) => next,
                Err("capture.frame_timeout") => continue,
                Err(code) => return Err(failure(code)),
            };
            if next.serial <= previous.serial || next.at <= previous.at {
                return Err(failure("capture.stale_frame"));
            }
            if let Some(target) = target {
                if next.at >= start {
                    if let Ok(cursor) =
                        geometry::cursor_near(before, &next, before, mask, Some(target))
                    {
                        let elapsed = start.elapsed();
                        self.observed_latency = elapsed;
                        return Ok((
                            next.clone(),
                            json!({"settled":true,"latency_ms":elapsed.as_millis(),"frame_id":next.serial,"cursor_px":cursor,"settle_method":"cursor-at-target","stability_window_ms":0}),
                        ));
                    }
                }
                previous = next;
                continue;
            }
            let changed = mask
                .changed_region(before, &next, region)
                .map_err(failure)?
                >= 6;
            if next.at >= start && changed && latency.is_none() {
                latency = Some(start.elapsed().as_millis());
                self.observed_latency = start.elapsed();
                stable_since = Instant::now();
                anchor = next.clone();
            }
            if mask
                .changed_region(&anchor, &next, region)
                .map_err(failure)?
                >= 6
            {
                stable_since = Instant::now();
                anchor = next.clone();
            }
            let quiet = self
                .observed_latency
                .mul_f64(0.15)
                .clamp(Duration::from_millis(100), SETTLE);
            if next.at >= start && latency.is_some() && stable_since.elapsed() >= quiet {
                return Ok((
                    next.clone(),
                    json!({"settled":true,"latency_ms":latency,"frame_id":next.serial,"settle_method":"adaptive-quiet","stability_window_ms":quiet.as_millis(),"settle_region":region}),
                ));
            }
            previous = next;
        }
    }

    fn finish_action(
        &mut self,
        before: &Arc<Frame>,
        mask: &frames::MotionMask,
        result: &mut Value,
        args: &Value,
        target: Option<[f64; 2]>,
        cancelled: &AtomicBool,
    ) -> Result<Value, Value> {
        let start = Instant::now();
        let region = if target.is_none() {
            let point = args
                .get("to_x")
                .zip(args.get("to_y"))
                .or_else(|| args.get("x").zip(args.get("y")));
            point.map(|(x, y)| {
                let width = 256.min(before.width);
                let height = 192.min(before.height);
                Region {
                    x: (x.as_u64().unwrap_or(0) as u32)
                        .saturating_sub(width / 2)
                        .min(before.width - width),
                    y: (y.as_u64().unwrap_or(0) as u32)
                        .saturating_sub(height / 2)
                        .min(before.height - height),
                    width,
                    height,
                }
            })
        } else {
            None
        };
        let (frame, observation) = match self
            .observe_target(before, mask, target, region, cancelled)
        {
            Ok((frame, observation)) => (Some(frame), observation),
            // Input has already completed: preserve its receipt and never suggest replay.
            Err(error) => (
                None,
                json!({"settled":false,"latency_ms":start.elapsed().as_millis(),"frame_id":null,"settle_error":error}),
            ),
        };
        result
            .as_object_mut()
            .expect("action result")
            .extend(observation.as_object().expect("observation").clone());
        if let Some(frame) = frame {
            self.last_observed = Some(frame.clone());
            if let Some((prior, _, _)) = self.animation.as_mut() {
                *prior = frame.clone();
            }
            if result["settled"] != true {
                self.animation = None;
            }
            if args["return_screenshot"] != false {
                // Encoding/observation failure cannot erase an EMITTED receipt.
                return match self.image_result(&frame, args, result.clone()) {
                    Ok(value) => Ok(value),
                    Err(error) => {
                        result["screenshot_error"] = error;
                        Ok(tool_result(result.clone(), false))
                    }
                };
            }
        } else {
            self.animation = None;
        }
        Ok(tool_result(result.clone(), false))
    }

    fn image_result(
        &mut self,
        frame: &Frame,
        args: &Value,
        mut metadata: Value,
    ) -> Result<Value, Value> {
        let started = Instant::now();
        let (bytes, mime) = frame
            .image(args["format"].as_str().unwrap_or(DEFAULT_IMAGE_FORMAT))
            .map_err(failure)?;
        metadata["image_bytes"] = json!(bytes.len());
        metadata["mime_type"] = json!(mime);
        metadata["image_encode_ms"] = json!(started.elapsed().as_millis());
        metadata["width"] = json!(frame.width);
        metadata["height"] = json!(frame.height);
        metadata["native_width"] = json!(frame.native.0);
        metadata["native_height"] = json!(frame.native.1);
        metadata["frame_id"] = json!(frame.serial);
        metadata["capture_generation"] = json!(frame.generation);
        metadata["frame_age_ms"] = json!(frame.at.elapsed().as_millis());
        self.screenshot_geometry =
            Some((frame.width, frame.height, frame.native, frame.generation));
        let mut result = tool_result(metadata, false);
        result["content"]
            .as_array_mut()
            .expect("tool content")
            .insert(
                0,
                json!({"type":"image","mimeType":mime,"data":STANDARD.encode(bytes)}),
            );
        Ok(result)
    }

    fn batch(&mut self, args: &Value, cancelled: &AtomicBool) -> Result<Value, Value> {
        let mut steps = Vec::new();
        let mut uncalibrated = None;
        for action in args["actions"]
            .as_array()
            .ok_or_else(|| failure("input.tool_arguments"))?
        {
            let tool = action["tool"].as_str().unwrap_or("");
            let mut step = action["arguments"].clone();
            let object = step
                .as_object_mut()
                .ok_or_else(|| failure("input.tool_arguments"))?;
            object.remove("return_screenshot");
            object.remove("format");
            let bypass = object.remove("uncalibrated").is_some_and(|v| v == true);
            if ["move", "click", "scroll", "drag"].contains(&tool) {
                if uncalibrated.is_some_and(|prior| prior != bypass) {
                    return Err(failure("pointer.mixed_calibration_policy"));
                }
                uncalibrated = Some(bypass);
            }
            object.insert("type".into(), json!(tool));
            let count = action["repeat"].as_u64().unwrap_or(1);
            let delay = action["delay_ms"].as_u64().unwrap_or(0);
            if count > 1 {
                step = json!({"type":"repeat","count":count,"delay_ms":delay,"steps":[step]});
            } else if delay != 0 {
                return Err(failure("repeat.delay_without_repeat"));
            }
            steps.push(step);
            if action["settle"] == true {
                steps.push(json!({"type":"wait_for_stable","timeout_ms":3000}));
            }
        }
        let count = args["repeat"].as_u64().unwrap_or(1);
        let delay = args["delay_ms"].as_u64().unwrap_or(0);
        if count > 1 {
            steps = vec![json!({"type":"repeat","count":count,"delay_ms":delay,"steps":steps})];
        } else if delay != 0 {
            return Err(failure("repeat.delay_without_repeat"));
        }
        let recipe=recipes::parse(json!({"schema":"keyferry.recipe.v1","name":"ad-hoc-batch","target_os":"any","steps":steps}).to_string().as_bytes()).map_err(|e|failure(e.code()))?;
        self.run_routine(
            &recipe,
            args,
            uncalibrated.unwrap_or(false),
            args["settle"] != false,
            cancelled,
        )
    }

    fn run_routine(
        &mut self,
        recipe: &RecipeV1,
        args: &Value,
        uncalibrated: bool,
        settle: bool,
        cancelled: &AtomicBool,
    ) -> Result<Value, Value> {
        if !recipe.is_routine() {
            return Err(failure("recipe.routine_required"));
        }
        let steps = routine_steps(recipe, args)?;
        self.choose_device()?;
        self.frames.device(&self.device);
        self.execute_routine(recipe, &steps, args, uncalibrated, settle, cancelled)
    }

    fn execute_routine(
        &mut self,
        recipe: &RecipeV1,
        steps: &[Step],
        args: &Value,
        uncalibrated: bool,
        settle: bool,
        cancelled: &AtomicBool,
    ) -> Result<Value, Value> {
        let mut receipts = Vec::new();
        let mut stopped = None;
        let mut completed = 0;
        let mut awaiting_owner = false;
        let mut i = 0;
        let mut commands = 0;
        // Capture the pre-input baseline so wait_for_change cannot miss a fast UI transition.
        self.frames.request_ocr(false);
        let mut baseline = self.frame(cancelled)?;
        self.screenshot_geometry = Some((
            baseline.width,
            baseline.height,
            baseline.native,
            baseline.generation,
        ));
        while i < steps.len() {
            if cancelled.load(Ordering::Acquire) {
                stopped = Some(i);
                receipts.push(json!({"step":i,"error":failure("request.cancelled")}));
                break;
            }
            if steps[i].input_only() {
                if awaiting_owner {
                    stopped = Some(i);
                    receipts.push(
                        json!({"step":i,"error":failure("recipe.owner_completion_required")}),
                    );
                    break;
                }
                let begin = i;
                while i < steps.len() && steps[i].input_only() {
                    i += 1;
                }
                let stretch = &steps[begin..i];
                let compiled = (|| {
                    self.frames.request_ocr(false);
                    let frame = self.frame(cancelled)?;
                    baseline = frame.clone();
                    if stretch.iter().any(Step::pointer) {
                        self.require_pointer()?;
                        if self.screenshot_geometry
                            != Some((frame.width, frame.height, frame.native, frame.generation))
                        {
                            return Err(failure("pointer.screenshot_required"));
                        }
                    }
                    self.stretch(&frame, stretch, Some(recipe), uncalibrated)
                })();
                // Compile the entire stretch, including all repeats/delays, before sending any of
                // it; glides may split it into consecutive commands that stop at the first failure.
                let mut outcomes = Vec::new();
                match compiled {
                    Ok(parts) => {
                        for part in parts {
                            commands += 1;
                            let range = part.steps.clone();
                            let result = self.submit_stretch(part, Some(recipe), cancelled);
                            let failed = result.is_err();
                            outcomes.push((range, result));
                            if failed {
                                break;
                            }
                        }
                    }
                    Err(error) => outcomes.push((0..stretch.len(), Err(error))),
                }
                for (range, result) in outcomes {
                    match result {
                        Ok(command) => {
                            for offset in range {
                                receipts.push(json!({"step":begin+offset,"type":stretch[offset].kind(),"command":command}));
                                completed += 1;
                            }
                        }
                        Err(error) => {
                            // Every step in this one command is uncertain together. No per-step
                            // emission claim can be made after a partial or possibly-started
                            // command.
                            for offset in range.clone() {
                                receipts.push(json!({"step":begin+offset,"type":stretch[offset].kind(),"error":error}));
                            }
                            stopped = Some(begin + range.start);
                        }
                    }
                }
                if stopped.is_none() {
                    self.animation = None;
                    if settle && i == steps.len() {
                        let mask = frames::MotionMask::new(&baseline);
                        let observed = self.observe_target(&baseline, &mask, None, None, cancelled);
                        let receipt = receipts.last_mut().expect("stretch receipt");
                        match observed {
                            Ok((frame, observation)) => {
                                self.last_observed = Some(frame);
                                receipt["observation"] = observation.clone();
                                if observation["settled"] != true {
                                    stopped = Some(begin);
                                    completed -= stretch.len();
                                }
                            }
                            Err(error) => {
                                receipt["observation_error"] = error;
                                stopped = Some(begin);
                                completed -= stretch.len();
                            }
                        }
                    }
                }
            } else {
                let result = (|| match &steps[i] {
                    Step::WaitForChange {
                        timeout_ms, region, ..
                    }
                    | Step::WaitForStable {
                        timeout_ms, region, ..
                    } => {
                        let mut check = json!({"timeout_ms":timeout_ms});
                        if let Some(region) = region {
                            check["region"] = json!(region);
                        }
                        let first = if matches!(steps[i], Step::WaitForChange { .. }) {
                            baseline.clone()
                        } else {
                            self.frame(cancelled)?
                        };
                        let value = self.wait(steps[i].kind(), &check, first, cancelled)?;
                        if value["matched"] == true {
                            Ok(value)
                        } else {
                            Err(json!({"code":"recipe.checkpoint_failed","check":value}))
                        }
                    }
                    Step::ExpectText {
                        query,
                        timeout_ms,
                        region,
                        optional,
                        ..
                    } => {
                        if *optional && query.is_empty() {
                            Ok(json!({"skipped":true}))
                        } else {
                            self.text_checkpoint(query, *timeout_ms, *region, false, cancelled)
                                .map(|(v, _)| v)
                        }
                    }
                    Step::ClickText {
                        query,
                        timeout_ms,
                        region,
                        button,
                        double,
                        ..
                    } => {
                        let (check, point) =
                            self.text_checkpoint(query, *timeout_ms, *region, true, cancelled)?;
                        let (x, y) = point.ok_or_else(|| failure("recipe.text_not_unique"))?;
                        let frame = self.frame(cancelled)?;
                        self.require_pointer()?;
                        let p = self.point(&frame, x, y, false)?;
                        baseline = frame;
                        commands += 1;
                        let command = self.glide_command(p, Some(json!({"type":if *double {"double_click"} else {"click"},"button":button.wire()})), cancelled)?;
                        Ok(json!({"check":check,"command":command}))
                    }
                    Step::SecureText { .. } => {
                        (self.secure_prompt)(&self.device, &self.url, &self.token)
                            .map_err(failure)
                            .inspect(|_| {
                                awaiting_owner = true;
                            })
                    }
                    _ => unreachable!(),
                })();
                match result {
                    Ok(receipt) => {
                        receipts.push(json!({"step":i,"type":steps[i].kind(),"receipt":receipt}));
                        completed += 1;
                        if !matches!(steps[i], Step::SecureText { .. })
                            && receipts
                                .last()
                                .is_some_and(|r| r["receipt"]["skipped"] != true)
                        {
                            awaiting_owner = false;
                        }
                    }
                    Err(error) => {
                        receipts.push(json!({"step":i,"type":steps[i].kind(),"error":error}));
                        stopped = Some(i);
                    }
                }
                i += 1;
            }
            if stopped.is_some() {
                break;
            }
        }
        let mut metadata = json!({"name":recipe.name(),"target_os":recipe.target_os,"actions":receipts,"completed":completed,"step_count":steps.len(),"command_count":commands,
            "stopped_at":stopped,"awaiting_owner":awaiting_owner,"never_retried":true,"execution_complete":stopped.is_none()&&!awaiting_owner,"settled":stopped.is_none()&&!awaiting_owner&&(settle || matches!(steps.last(),Some(Step::WaitForStable{..})))});
        // Exactly one final image; observation/encoding failures preserve all prior receipts.
        let mut result = if args["return_screenshot"] != false {
            self.frames.request_ocr(false);
            match self
                .frames
                .latest(None, ACTION_WAIT, cancelled)
                .map_err(failure)
                .and_then(|frame| self.image_result(&frame, args, metadata.clone()))
            {
                Ok(value) => value,
                Err(error) => {
                    metadata["screenshot_error"] = error;
                    tool_result(metadata, false)
                }
            }
        } else {
            tool_result(metadata, false)
        };
        result["isError"] = json!(
            stopped.is_some()
                || result["structuredContent"]
                    .get("screenshot_error")
                    .is_some()
        );
        Ok(result)
    }

    fn text_checkpoint(
        &mut self,
        query: &str,
        timeout_ms: u64,
        region: Option<routines::Region>,
        unique: bool,
        cancelled: &AtomicBool,
    ) -> Result<(Value, Option<(f64, f64)>), Value> {
        let start = Instant::now();
        let timeout = Duration::from_millis(timeout_ms);
        let mut after = None;
        loop {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(failure("recipe.checkpoint_failed"));
            }
            // Every polled frame uses capture-controller OCR; a request flag lasts one frame.
            self.frames.request_ocr(true);
            let frame = self
                .frames
                .latest(after, remaining, cancelled)
                .map_err(failure)?;
            if after.is_some_and(|serial| frame.serial <= serial) {
                return Err(failure("capture.stale_frame"));
            }
            after = Some(frame.serial);
            let region = region.map(|r| Region {
                x: r.x,
                y: r.y,
                width: r.width,
                height: r.height,
            });
            if region.is_some_and(|r| !r.valid(&frame)) {
                return Err(failure("input.region"));
            }
            let boxes = ocr::filter(
                match self.frames.ocr_result() {
                    Some(v) => v,
                    None => self.ocr.recognize(&frame).map_err(failure)?,
                },
                Some(query),
            );
            let matches: Vec<_> = boxes
                .iter()
                .filter(|b| {
                    region.is_none_or(|r| {
                        b.x >= f64::from(r.x)
                            && b.y >= f64::from(r.y)
                            && b.x + b.width <= f64::from(r.x + r.width)
                            && b.y + b.height <= f64::from(r.y + r.height)
                    })
                })
                .collect();
            if unique && matches.len() > 1 {
                return Err(failure("recipe.text_not_unique"));
            }
            if !matches.is_empty() {
                let point = unique.then(|| {
                    (
                        matches[0].x + matches[0].width / 2.0,
                        matches[0].y + matches[0].height / 2.0,
                    )
                });
                self.last_observed = Some(frame.clone());
                self.screenshot_geometry =
                    Some((frame.width, frame.height, frame.native, frame.generation));
                return Ok((
                    json!({"matched":true,"match_count":matches.len(),"frame_id":frame.serial,"elapsed_ms":start.elapsed().as_millis()}),
                    point,
                ));
            }
        }
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
        // A cursor or small dialog never moves the frame mean past the noise margin. With a
        // fresh animation mask from the last action, use the action observer's pixel test too.
        let mask = self
            .animation
            .as_ref()
            .filter(|(_, mask, at)| {
                at.elapsed() < Duration::from_secs(30)
                    && mask.small()
                    && mask.changed(&first, &first).is_ok()
            })
            .map(|(_, mask, _)| mask.clone());
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
            if next.serial <= previous.serial || next.at <= previous.at {
                return Err(failure("capture.stale_frame"));
            }
            let delta = frames::difference(&previous, &next, region).map_err(failure)?;
            let baseline = frames::difference(&first, &next, region).map_err(failure)?;
            samples += 1;
            if delta > 0.002 {
                stable = Instant::now();
            }
            let matched = if name == "wait_for_change" {
                baseline > 0.01
                    || match &mask {
                        Some(mask) => {
                            mask.changed_region(&first, &next, region)
                                .map_err(failure)?
                                >= 6
                        }
                        None => false,
                    }
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
    fn probe(
        &mut self,
        p: [f64; 2],
        mask: &frames::MotionMask,
        cancelled: &AtomicBool,
    ) -> Result<(Arc<Frame>, Value), Value> {
        // A probe onto the presumed cursor changes no pixels, and calibration ends on its first
        // probe point: step aside first so a repeated calibration still sees the cursor move.
        if self
            .presumed()
            .is_some_and(|at| (at[0] - p[0]).abs().max((at[1] - p[1]).abs()) < 0.05)
        {
            let aside = p.map(|v| v + (0.5 - v).signum() * 0.1);
            let before = self.frame(cancelled)?;
            self.glide_command(aside, None, cancelled)?;
            self.observe_action(&before, mask, cancelled)?;
        }
        let before = self.frame(cancelled)?;
        // The probe glides like every agent motion; EMITTED arrives after the final report, and
        // observation then requires the moved cursor to hold still on fresh frames.
        let mut receipt = self.glide_command(p, None, cancelled)?;
        let (frame, observation) = self.observe_action(&before, mask, cancelled)?;
        if observation["settled"] != true {
            return Err(failure("calibration.cursor_not_seen"));
        }
        receipt["latency_ms"] = observation["latency_ms"].clone();
        Ok((frame, receipt))
    }
    fn calibrate(&mut self, cancelled: &AtomicBool) -> Result<Value, Value> {
        self.choose_device()?;
        self.frames.device(&self.device);
        self.bound_generation = None;
        self.geometry = None;
        self.animation = None;
        self.loaded = true;
        self.require_pointer()?;
        // Cursor evidence and the fit use native pixels; the binding is then expressed in
        // the bounded agent view shared by screenshots, OCR boxes and pointer tools.
        self.frames.request_native(true);
        let fitted = self.calibrate_native(cancelled);
        self.frames.request_native(false);
        let (fitted, mask, mut result) = fitted?;
        let view = self.frame(cancelled)?;
        // Also rejects a capture restart between the native probes and this view.
        let mask = mask.scaled(&view).map_err(failure)?;
        let fitted = fitted.scaled(view.width, view.height);
        geometry::save(&self.root, &fitted).map_err(failure)?;
        self.bound_generation = Some(view.generation);
        self.geometry = Some(fitted.clone());
        self.animation = Some((view, mask, Instant::now()));
        result["geometry"] = json!(fitted);
        result["active_video_rectangle"] = json!(fitted.active_rectangle());
        Ok(result)
    }
    fn calibrate_native(
        &mut self,
        cancelled: &AtomicBool,
    ) -> Result<(Geometry, frames::MotionMask, Value), Value> {
        let (_, mask) = self.stationary(cancelled)?;
        if !mask.small() {
            return Err(failure("calibration.animated_or_ambiguous"));
        }
        let positions = [
            [0.12, 0.15],
            [0.80, 0.20],
            [0.25, 0.78],
            [0.73, 0.72],
            [0.45, 0.42],
            [0.60, 0.60],
            [0.18, 0.62],
            [0.68, 0.35],
        ];
        let mut captured = Vec::new();
        let mut receipts = Vec::new();
        // Only three frames retained while streaming probes; snapshots never hit disk.
        let mut samples = Vec::new();
        for (i, p) in positions.iter().enumerate() {
            let (f, receipt) = self.probe(*p, &mask, cancelled)?;
            receipts.push(json!({"position":p,"frame_id":f.serial,"command":receipt}));
            captured.push(f);
            if captured.len() == 3 {
                let middle = &captured[1];
                let approximate = [
                    positions[i - 1][0] * f64::from(middle.width - 1),
                    positions[i - 1][1] * f64::from(middle.height - 1),
                ];
                let point =
                    geometry::cursor(&captured[0], middle, &captured[2], &mask).or_else(|_| {
                        geometry::cursor_near(
                            &captured[0],
                            middle,
                            &captured[2],
                            &mask,
                            Some(approximate),
                        )
                    });
                match point {
                    Ok(point) => samples.push((positions[i - 1], point)),
                    Err("calibration.cursor_not_seen" | "calibration.animated_or_ambiguous") => {}
                    Err(code) => return Err(failure(code)),
                }
                captured.remove(0);
            }
        }
        let last = captured
            .last()
            .ok_or_else(|| failure("calibration.insufficient_samples"))?;
        let source = self.source.as_deref().unwrap_or("auto");
        let (fitted, inliers, rms) =
            geometry::robust_fit(&self.device, source, last, &samples).map_err(failure)?;
        let before = last.clone();
        let check = [0.35, 0.55];
        let (middle, receipt) = self.probe(check, &mask, cancelled)?;
        receipts.push(json!({"position":check,"frame_id":middle.serial,"command":receipt}));
        let (after, receipt) = self.probe(positions[0], &mask, cancelled)?;
        receipts.push(json!({"position":positions[0],"frame_id":after.serial,"command":receipt}));
        let expected = [
            fitted.origin[0] + fitted.extent[0] * check[0],
            fitted.origin[1] + fitted.extent[1] * check[1],
        ];
        let observed = geometry::cursor_near(&before, &middle, &after, &mask, Some(expected))
            .map_err(failure)?;
        if (0..2)
            .any(|a| (observed[a] - fitted.origin[a] - fitted.extent[a] * check[a]).abs() > 5.0)
        {
            return Err(failure("calibration.verification_failed"));
        }
        let latency_ms = receipts
            .iter()
            .filter_map(|r| r["command"]["latency_ms"].as_u64())
            .max();
        let result = json!({"bound":true,"probes":receipts,"latency_ms":latency_ms,"calibration_frame":[after.width,after.height],"residual_rms_px":rms,"inlier_samples":inliers,"rejected_samples":positions.len()-2-inliers,"verification_error_px":[observed[0]-fitted.origin[0]-fitted.extent[0]*check[0],observed[1]-fitted.origin[1]-fitted.extent[1]*check[1]],"pointer_moved":true});
        Ok((fitted, mask, result))
    }
}

#[cfg(all(test, not(keyferry_daemon_tests)))]
#[path = "mcp_tests.rs"]
mod tests;

#[cfg(all(test, keyferry_daemon_tests))]
#[path = "../../../tools/keyferry-integration-tests/tests/mcp_tests.rs"]
mod integration_tests;
