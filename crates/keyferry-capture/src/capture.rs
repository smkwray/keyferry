//! Local, one-shot capture. No daemon, temporary frames, or inherited FFmpeg reports.
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::{self, Cursor, Read, Write},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PIXELS: usize = 4096 * 4096;
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_LIST_BYTES: usize = 256 * 1024;

pub const HELP: &str = "keyctl capture calibrate DEVICE [--source NAME_OR_ID] (moves pointer through daemon; see keyctl mcp --help)\nkeyctl capture list\nkeyctl capture frame --out PATH [--source NAME_OR_ID] [--size WxH] [--scale WxH]\n  list/frame: local USB HDMI/UVC video capture using ffmpeg on PATH; never contacts a stick or daemon.\n  Default source: the single recognized capture device; otherwise supply --source from list.\n  --size selects the input mode; --scale resizes the output (each at most 4096x4096 pixels).\n  Writes one PNG only to --out; refuses an existing path. Screens may contain secrets: keep and delete it privately.\n  Each ffmpeg process has a 15-second deadline; no retries or temporary frames.\n  signal=no-signal is a near-uniform black/blue heuristic, not proof of HDMI signal loss.\n  On macOS grant Camera permission to the terminal/app in System Settings > Privacy & Security.\n  Exit: 0 success (including no-signal), 20 arguments/source selection, 23 ffmpeg missing,\n        24 timeout (child killed), 25 capture/list/decode/output failure. Output/errors are compact JSON.";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Backend {
    Dshow,
    Avfoundation,
    V4l2,
}

impl Backend {
    fn current() -> Self {
        if cfg!(windows) {
            Self::Dshow
        } else if cfg!(target_os = "macos") {
            Self::Avfoundation
        } else {
            Self::V4l2
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Dshow => "dshow",
            Self::Avfoundation => "avfoundation",
            Self::V4l2 => "v4l2",
        }
    }

    fn install_hint(self) -> &'static str {
        match self {
            Self::Dshow => "Install FFmpeg (for example: choco install ffmpeg) and put it on PATH.",
            Self::Avfoundation => {
                "Install FFmpeg (for example: brew install ffmpeg) and put it on PATH."
            }
            Self::V4l2 => "Install your distribution's ffmpeg package and put it on PATH.",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Device {
    pub name: String,
    pub id: String,
}

#[derive(Debug)]
pub struct Error {
    pub code: &'static str,
    message: &'static str,
    candidates: Vec<Device>,
}

impl Error {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            candidates: vec![],
        }
    }

    fn exit(&self) -> u8 {
        match self.code {
            "capture.arguments" | "capture.source_required" | "capture.source_not_found" => 20,
            "capture.ffmpeg_missing" => 23,
            "capture.timeout" => 24,
            _ => 25,
        }
    }
}

#[derive(Debug, PartialEq)]
struct FrameOptions {
    out: PathBuf,
    source: Option<String>,
    size: Option<(u32, u32)>,
    scale: Option<(u32, u32)>,
}

#[derive(Debug, PartialEq)]
enum Request {
    Help,
    List,
    Frame(FrameOptions),
}

fn dimensions(value: &str) -> Result<(u32, u32), Error> {
    let invalid = || {
        Error::new(
            "capture.arguments",
            "Expected WxH with each dimension in 1..4096.",
        )
    };
    let (w, h) = value.split_once('x').ok_or_else(invalid)?;
    let w: u32 = w.parse().map_err(|_| invalid())?;
    let h: u32 = h.parse().map_err(|_| invalid())?;
    if !(1..=4096).contains(&w) || !(1..=4096).contains(&h) {
        return Err(invalid());
    }
    Ok((w, h))
}

fn parse(args: &[String]) -> Result<Request, Error> {
    let invalid = || {
        Error::new(
            "capture.arguments",
            "Use keyctl capture --help for arguments.",
        )
    };
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h" | "help") {
        return Ok(Request::Help);
    }
    if args.len() == 1 && args[0] == "list" {
        return Ok(Request::List);
    }
    if args.first().map(String::as_str) != Some("frame") || !(args.len() - 1).is_multiple_of(2) {
        return Err(invalid());
    }
    let (mut out, mut source, mut size, mut scale) = (None, None, None, None);
    for pair in args[1..].chunks_exact(2) {
        if pair[1].is_empty() || pair[1].starts_with("--") {
            return Err(invalid());
        }
        match pair[0].as_str() {
            "--out" if out.is_none() => out = Some(PathBuf::from(&pair[1])),
            "--source" if source.is_none() => source = Some(pair[1].clone()),
            "--size" if size.is_none() => size = Some(dimensions(&pair[1])?),
            "--scale" if scale.is_none() => scale = Some(dimensions(&pair[1])?),
            _ => return Err(invalid()),
        }
    }
    Ok(Request::Frame(FrameOptions {
        out: out.ok_or_else(invalid)?,
        source,
        size,
        scale,
    }))
}

pub fn run(args: &[String]) -> u8 {
    let backend = Backend::current();
    // Program injection belongs only to tests; production always resolves ffmpeg on PATH.
    match execute(args, backend, || Command::new("ffmpeg"), TIMEOUT) {
        Ok(Some(value)) => {
            println!("{value}");
            0
        }
        Ok(None) => {
            println!("{HELP}");
            0
        }
        Err(error) => {
            println!(
                "{}",
                json!({"schema": "keyferry.capture-error.v1",
                "error": {"code": error.code, "message": error.message},
                "candidates": error.candidates})
            );
            error.exit()
        }
    }
}

fn execute(
    args: &[String],
    backend: Backend,
    command: impl Fn() -> Command,
    timeout: Duration,
) -> Result<Option<Value>, Error> {
    let request = parse(args)?;
    if request == Request::Help {
        return Ok(None);
    }
    let devices = list(backend, &command, timeout)?;
    match request {
        Request::List => Ok(Some(json!({"schema": "keyferry.capture-devices.v1",
            "backend": backend.name(), "devices": devices}))),
        Request::Frame(options) => {
            let device = select_source(&devices, options.source.as_deref())?;
            let mut child = command();
            child.args(frame_args(backend, device, &options));
            let output = bounded_output(child, timeout, MAX_FRAME_BYTES, backend)?;
            if !output.status.success() {
                return Err(Error::new("capture.frame_failed", "Cannot capture a frame; check source, mode, device permissions and macOS Camera permission."));
            }
            let (width, height, rgb) = decode(&output.stdout)?;
            if options
                .scale
                .or(options.size)
                .is_some_and(|size| size != (width, height))
            {
                return Err(Error::new(
                    "capture.size_mismatch",
                    "Capture did not produce the requested dimensions.",
                ));
            }
            let (signal, mean_luma) = signal(&rgb);
            let captured_at = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|_| {
                    Error::new("capture.clock", "Cannot format the host UTC timestamp.")
                })?;
            // Exclusive creation protects existing files and symlinks. No disk bytes until
            // the process and complete PNG have both passed validation; no temp path exists.
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&options.out)
                .map_err(|_| {
                    Error::new(
                        "capture.output",
                        "Cannot create --out; choose a new path in an existing writable directory.",
                    )
                })?;
            if file
                .write_all(&output.stdout)
                .and_then(|()| file.flush())
                .is_err()
            {
                drop(file);
                std::fs::remove_file(&options.out)
                    .map_err(|_| Error::new("capture.output_cleanup", "Output write failed and the incomplete --out could not be removed; delete it privately."))?;
                return Err(Error::new(
                    "capture.output",
                    "Cannot write --out; incomplete output was removed.",
                ));
            }
            Ok(Some(
                json!({"schema": "keyferry.capture-frame.v1", "path": options.out,
                "source": device.name, "width": width, "height": height,
                "captured_at": captured_at, "signal": signal, "mean_luma": mean_luma}),
            ))
        }
        Request::Help => unreachable!(),
    }
}

struct Output {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn read_bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new("capture.process_io", "Cannot read ffmpeg output."))?;
    if bytes.len() > limit {
        return Err(Error::new(
            "capture.output_limit",
            "ffmpeg output exceeded the capture limit.",
        ));
    }
    Ok(bytes)
}

fn bounded_output(
    mut command: Command,
    timeout: Duration,
    limit: usize,
    backend: Backend,
) -> Result<Output, Error> {
    let mut child = command
        .env_remove("FFREPORT")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                Error::new("capture.ffmpeg_missing", backend.install_hint())
            } else {
                Error::new("capture.process_start", "Cannot start ffmpeg from PATH.")
            }
        })?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    // Drain both pipes concurrently so a full pipe cannot block capture or timeout handling.
    let out = thread::spawn(move || read_bounded(stdout, limit));
    let err = thread::spawn(move || read_bounded(stderr, MAX_LIST_BYTES));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if start.elapsed() < timeout => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                break Err(Error::new(
                    "capture.timeout",
                    "ffmpeg timed out; its child was killed and no frame was written.",
                ))
            }
            Err(_) => {
                break Err(Error::new(
                    "capture.process_wait",
                    "Cannot wait for ffmpeg.",
                ))
            }
        }
    };
    if status.is_err() {
        stop_child(&mut child);
    }
    let stdout = out
        .join()
        .map_err(|_| Error::new("capture.process_io", "Capture reader failed."));
    let stderr = err
        .join()
        .map_err(|_| Error::new("capture.process_io", "Capture reader failed."));
    Ok(Output {
        status: status?,
        stdout: stdout??,
        stderr: stderr??,
    })
}

/// Windows PATH launchers may spawn the real encoder as a grandchild holding both pipes.
/// Stop this owned child's entire tree before joining readers; never use a process name.
pub fn stop_child(child: &mut Child) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn list(
    backend: Backend,
    command: &impl Fn() -> Command,
    timeout: Duration,
) -> Result<Vec<Device>, Error> {
    let mut child = command();
    child.args(["-hide_banner", "-nostdin"]);
    match backend {
        Backend::Dshow => {
            child.args(["-list_devices", "true", "-f", "dshow", "-i", "dummy"]);
        }
        Backend::Avfoundation => {
            child.args(["-list_devices", "true", "-f", "avfoundation", "-i", ""]);
        }
        Backend::V4l2 => {
            child.args(["-sources", "v4l2"]);
        }
    }
    let output = bounded_output(child, timeout, MAX_LIST_BYTES, backend)?;
    if backend == Backend::V4l2 && !output.status.success() {
        return Err(list_error());
    }
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // dshow/avfoundation intentionally exit nonzero after listing. Require recognizable
    // listing syntax instead of treating every failed invocation as an empty device list.
    parse_devices(backend, &text)
}

fn parse_devices(backend: Backend, text: &str) -> Result<Vec<Device>, Error> {
    let mut devices: Vec<Device> = vec![];
    let mut recognized = false;
    let mut video = false;
    for line in text.lines() {
        match backend {
            Backend::Dshow => {
                recognized |= line.contains("DirectShow video devices");
                if line.ends_with("(video)") {
                    let name = line
                        .split_once('"')
                        .and_then(|(_, rest)| rest.rsplit_once('"').map(|(name, _)| name));
                    let name = name
                        .filter(|name| !name.is_empty())
                        .ok_or_else(list_error)?;
                    devices.push(Device {
                        name: name.to_owned(),
                        id: name.to_owned(),
                    });
                    video = true;
                    recognized = true;
                } else if line.contains("Alternative name") && video {
                    if let Some((_, rest)) = line.split_once("Alternative name \"") {
                        devices.last_mut().expect("video device").id =
                            rest.trim_end_matches('"').to_owned();
                    } else {
                        return Err(list_error());
                    }
                    video = false;
                } else if line.contains("(audio)") || line.contains("(none)") {
                    video = false;
                }
            }
            Backend::Avfoundation => {
                if line.contains("AVFoundation video devices:") {
                    video = true;
                    recognized = true;
                } else if line.contains("AVFoundation audio devices:") {
                    video = false;
                } else if video {
                    // Strip the FFmpeg log prefix, then parse the numeric device index.
                    let entry = if line.starts_with("[AVFoundation") {
                        line.split_once("] ")
                            .map(|(_, rest)| rest.trim())
                            .ok_or_else(list_error)?
                    } else {
                        line.trim()
                    };
                    if let Some(entry) = entry.strip_prefix('[') {
                        let (id, name) = entry.split_once("] ").ok_or_else(list_error)?;
                        if id.parse::<u32>().is_err() || name.is_empty() {
                            return Err(list_error());
                        }
                        // Screen grabbing is not an HDMI/UVC device.
                        if !name.starts_with("Capture screen ") {
                            devices.push(Device {
                                name: name.to_owned(),
                                id: id.to_owned(),
                            });
                        }
                    }
                }
            }
            Backend::V4l2 => {
                recognized |= line.contains("Auto-detected sources for");
                let entry = line.trim().trim_start_matches('*').trim();
                if entry.starts_with("/dev/video") {
                    let (id, rest) = entry.split_once(" [").ok_or_else(list_error)?;
                    let name = rest
                        .split_once(']')
                        .map(|(name, _)| name)
                        .ok_or_else(list_error)?;
                    if name.is_empty() {
                        return Err(list_error());
                    }
                    devices.push(Device {
                        name: name.to_owned(),
                        id: id.to_owned(),
                    });
                }
            }
        }
    }
    if !recognized {
        return Err(list_error());
    }
    Ok(devices)
}

fn list_error() -> Error {
    Error::new("capture.list_failed", "Cannot enumerate video devices; check ffmpeg's platform backend and device/Camera permissions.")
}

pub fn select_source<'a>(devices: &'a [Device], source: Option<&str>) -> Result<&'a Device, Error> {
    let matches: Vec<_> = devices
        .iter()
        .filter(|device| {
            if let Some(source) = source {
                device.name == source || device.id == source
            } else {
                let name = device.name.to_ascii_lowercase();
                !["webcam", "camera", "facetime", "virtual"]
                    .iter()
                    .any(|s| name.contains(s))
                    && ["capture", "hdmi", "hagibis", "ms2130", "elgato"]
                        .iter()
                        .any(|s| name.contains(s))
            }
        })
        .collect();
    if matches.len() == 1 {
        return Ok(matches[0]);
    }
    Err(Error {
        code: if source.is_some() && matches.is_empty() {
            "capture.source_not_found"
        } else {
            "capture.source_required"
        },
        message: "Select exactly one video device with --source NAME_OR_ID from candidates.",
        candidates: devices.to_vec(),
    })
}

fn frame_args(backend: Backend, device: &Device, options: &FrameOptions) -> Vec<String> {
    let mut args = [
        "-hide_banner",
        "-nostdin",
        "-loglevel",
        "error",
        "-threads",
        "1",
        "-f",
        backend.name(),
    ]
    .map(str::to_owned)
    .to_vec();
    if backend == Backend::Dshow {
        args.extend(["-rtbufsize".into(), "256M".into()]);
    }
    if backend == Backend::Avfoundation {
        args.extend(["-framerate".into(), "30".into()]);
    }
    if let Some((w, h)) = options.size {
        args.extend(["-video_size".into(), format!("{w}x{h}")]);
    }
    let input = match backend {
        Backend::Dshow => format!("video={}", device.id),
        Backend::Avfoundation => format!("{}:none", device.id),
        Backend::V4l2 => device.id.clone(),
    };
    args.extend([
        "-i".into(),
        input,
        "-map".into(),
        "0:v:0".into(),
        "-frames:v".into(),
        "1".into(),
    ]);
    if let Some((w, h)) = options.scale {
        args.extend(["-vf".into(), format!("scale={w}:{h}")]);
    }
    args.extend(
        [
            "-an",
            "-sn",
            "-dn",
            "-threads",
            "1",
            "-filter_threads",
            "1",
            "-c:v",
            "png",
            "-pix_fmt",
            "rgb24",
            "-f",
            "image2pipe",
            "pipe:1",
        ]
        .map(str::to_owned),
    );
    args
}

fn decode(bytes: &[u8]) -> Result<(u32, u32, Vec<u8>), Error> {
    let invalid = || {
        Error::new(
            "capture.invalid_frame",
            "ffmpeg did not return a complete bounded RGB PNG.",
        )
    };
    let decoder = png::Decoder::new_with_limits(
        Cursor::new(bytes),
        png::Limits {
            bytes: MAX_FRAME_BYTES,
        },
    );
    let mut reader = decoder.read_info().map_err(|_| invalid())?;
    let info = reader.info();
    if !(1..=4096).contains(&info.width)
        || !(1..=4096).contains(&info.height)
        || u64::from(info.width) * u64::from(info.height) > MAX_PIXELS as u64
        || info.color_type != png::ColorType::Rgb
        || info.bit_depth != png::BitDepth::Eight
        || info.is_animated()
    {
        return Err(invalid());
    }
    let (width, height) = (info.width, info.height);
    let size = reader
        .output_buffer_size()
        .filter(|size| *size <= MAX_FRAME_BYTES)
        .ok_or_else(invalid)?;
    let mut rgb = vec![0; size];
    let output = reader.next_frame(&mut rgb).map_err(|_| invalid())?;
    reader.finish().map_err(|_| invalid())?;
    rgb.truncate(output.buffer_size());
    Ok((width, height, rgb))
}

fn signal(rgb: &[u8]) -> (&'static str, f64) {
    let count = (rgb.len() / 3) as f64;
    let mut sums = [0.0; 3];
    let mut squares = [0.0; 3];
    for pixel in rgb.chunks_exact(3) {
        for channel in 0..3 {
            let value = f64::from(pixel[channel]);
            sums[channel] += value;
            squares[channel] += value * value;
        }
    }
    let means = sums.map(|sum| sum / count);
    let uniform = (0..3).all(|c| squares[c] / count - means[c] * means[c] <= 16.0);
    let black = means.iter().all(|mean| *mean <= 20.0);
    let blue = means[2] >= 60.0 && means[2] >= means[0] + 40.0 && means[2] >= means[1] + 20.0;
    let luma = 0.2126 * means[0] + 0.7152 * means[1] + 0.0722 * means[2];
    (
        if uniform && (black || blue) {
            "no-signal"
        } else {
            "present"
        },
        (luma * 100.0).round() / 100.0,
    )
}

/// Enumerate and probe in memory, then return arguments for one continuous raw RGB pipe.
/// The probe bounds the native geometry; showinfo detects a later input-mode change.
pub fn stream_setup(source: Option<&str>) -> Result<(String, u32, u32, Vec<String>), &'static str> {
    let backend = Backend::current();
    let devices = list(backend, &|| Command::new("ffmpeg"), TIMEOUT).map_err(|e| e.code)?;
    let device = select_source(&devices, source).map_err(|e| e.code)?;
    let options = FrameOptions {
        out: PathBuf::new(),
        source: None,
        size: None,
        scale: None,
    };
    let mut command = Command::new("ffmpeg");
    command.args(frame_args(backend, device, &options));
    let output = bounded_output(command, TIMEOUT, MAX_FRAME_BYTES, backend).map_err(|e| e.code)?;
    if !output.status.success() {
        return Err("capture.frame_failed");
    }
    let (w, h, _) = decode(&output.stdout).map_err(|e| e.code)?;
    let mut args = frame_args(backend, device, &options);
    let end = args
        .iter()
        .position(|s| s == "-frames:v")
        .ok_or("capture.arguments")?;
    args.truncate(end);
    // Keep aspect ratio; bound both dimensions, preserving screenshot pixel coordinates.
    let (sw, sh) = super::frames::scaled_size((w, h));
    let level = args
        .iter()
        .position(|s| s == "-loglevel")
        .ok_or("capture.arguments")?;
    args[level + 1] = "info".into();
    if let Some(buffer) = args.iter().position(|s| s == "-rtbufsize") {
        args[buffer + 1] = "16M".into();
    }
    args.extend([
        "-vf".into(),
        format!("showinfo,scale={sw}:{sh}"),
        "-an".into(),
        "-sn".into(),
        "-dn".into(),
        "-threads".into(),
        "1".into(),
        "-filter_threads".into(),
        "1".into(),
        "-pix_fmt".into(),
        "rgb24".into(),
        "-f".into(),
        "rawvideo".into(),
        "pipe:1".into(),
    ]);
    Ok((device.id.clone(), w, h, args))
}

#[cfg(test)]
#[path = "capture_tests.rs"]
mod tests;

/// Local inventory; only recognized HDMI capture devices auto-select.
pub fn devices() -> Result<Vec<Device>, &'static str> {
    list(Backend::current(), &|| Command::new("ffmpeg"), TIMEOUT).map_err(|e| e.code)
}
pub fn recognized(device: &Device) -> bool {
    select_source(std::slice::from_ref(device), None).is_ok()
}
