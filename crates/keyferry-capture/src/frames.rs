//! Latest-frame capture only. No disk, frame queue, FFmpeg report, or frame logging.
use serde::{Deserialize, Serialize};
pub const MAX_SIDE: u32 = 1280;

pub fn scaled_size(native: (u32, u32)) -> (u32, u32) {
    let ratio = (f64::from(MAX_SIDE) / f64::from(native.0))
        .min(f64::from(MAX_SIDE) / f64::from(native.1))
        .min(1.0);
    (
        (f64::from(native.0) * ratio).round().max(2.0) as u32,
        (f64::from(native.1) * ratio).round().max(2.0) as u32,
    )
}

use std::{
    io::{BufRead, BufReader, Read},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub native: (u32, u32),
    pub rgb: Vec<u8>,
    pub serial: u64,
    pub generation: u64,
    pub at: Instant,
}

impl Frame {
    pub fn png(&self) -> Result<Vec<u8>, &'static str> {
        let mut bytes = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut bytes, self.width, self.height);
            encoder.set_color(png::ColorType::Rgb);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().map_err(|_| "capture.encode")?;
            writer
                .write_image_data(&self.rgb)
                .map_err(|_| "capture.encode")?;
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Region {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Region {
    pub fn valid(self, frame: &Frame) -> bool {
        self.width > 0
            && self.height > 0
            && self
                .x
                .checked_add(self.width)
                .is_some_and(|x| x <= frame.width)
            && self
                .y
                .checked_add(self.height)
                .is_some_and(|y| y <= frame.height)
    }
}

pub fn difference(a: &Frame, b: &Frame, region: Option<Region>) -> Result<f64, &'static str> {
    if (a.width, a.height, a.native, a.generation) != (b.width, b.height, b.native, b.generation) {
        return Err("capture.geometry_changed");
    }
    let r = region.unwrap_or(Region {
        x: 0,
        y: 0,
        width: a.width,
        height: a.height,
    });
    if !r.valid(a) {
        return Err("input.region");
    }
    let mut total = 0_u64;
    for y in r.y..r.y + r.height {
        let start = ((y * a.width + r.x) * 3) as usize;
        let end = start + r.width as usize * 3;
        total += a.rgb[start..end]
            .iter()
            .zip(&b.rgb[start..end])
            .map(|(a, b)| u64::from(a.abs_diff(*b)))
            .sum::<u64>();
    }
    Ok(total as f64 / (f64::from(r.width) * f64::from(r.height) * 3.0 * 255.0))
}

/// Transient animation mask learned only while input is stationary. Whole 16-pixel tiles
/// cover changing clock glyphs/carets and their compression edges, not just lit pixels.
pub struct MotionMask {
    geometry: (u32, u32, (u32, u32), u64),
    tiles: Vec<bool>,
}

impl MotionMask {
    pub fn new(frame: &Frame) -> Self {
        Self {
            geometry: (frame.width, frame.height, frame.native, frame.generation),
            tiles: vec![false; (frame.width.div_ceil(16) * frame.height.div_ceil(16)) as usize],
        }
    }

    fn check(&self, frame: &Frame) -> Result<(), &'static str> {
        if self.geometry != (frame.width, frame.height, frame.native, frame.generation) {
            return Err("capture.geometry_changed");
        }
        Ok(())
    }

    pub fn ignored(&self, pixel: usize) -> bool {
        let width = self.geometry.0 as usize;
        self.tiles[(pixel / width / 16) * width.div_ceil(16) + pixel % width / 16]
    }

    pub fn small(&self) -> bool {
        self.tiles.iter().filter(|tile| **tile).count() * 20 <= self.tiles.len()
    }

    pub fn learn(&mut self, a: &Frame, b: &Frame) -> Result<(), &'static str> {
        self.check(a)?;
        self.check(b)?;
        let columns = a.width.div_ceil(16) as usize;
        for (pixel, (a, b)) in a.rgb.chunks_exact(3).zip(b.rgb.chunks_exact(3)).enumerate() {
            if pixel_changed(a, b) {
                let width = self.geometry.0 as usize;
                self.tiles[(pixel / width / 16) * columns + pixel % width / 16] = true;
            }
        }
        Ok(())
    }

    /// Count significant changed pixels, so a small cursor on a large frame is visible.
    pub fn changed(&self, a: &Frame, b: &Frame) -> Result<usize, &'static str> {
        self.check(a)?;
        self.check(b)?;
        Ok(a.rgb
            .chunks_exact(3)
            .zip(b.rgb.chunks_exact(3))
            .enumerate()
            .filter(|(pixel, (a, b))| !self.ignored(*pixel) && pixel_changed(a, b))
            .count())
    }
}

pub fn pixel_changed(a: &[u8], b: &[u8]) -> bool {
    a.iter().zip(b).any(|(a, b)| a.abs_diff(*b) >= 35)
}

pub trait FrameSource {
    fn device(&mut self, _: &str) {}
    fn sources(&mut self) -> Result<serde_json::Value, &'static str> {
        Ok(self.status())
    }
    fn select(&mut self, _: &str) -> Result<(), &'static str> {
        Err("capture.select_unsupported")
    }
    fn resolve(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
    fn request_ocr(&mut self, _: bool) {}
    fn ocr_result(&mut self) -> Option<Vec<super::ocr::TextBox>> {
        None
    }

    fn latest(
        &mut self,
        after: Option<u64>,
        timeout: Duration,
        cancelled: &AtomicBool,
    ) -> Result<Arc<Frame>, &'static str>;
    fn status(&self) -> serde_json::Value;
}

#[derive(Default)]
struct State {
    source: Option<String>,
    requested_at: Option<Instant>,
    retry: Retry,
    latest: Option<Arc<Frame>>,
    ready: bool,
    last_frame_at: Option<Instant>,
    error: Option<&'static str>,
    last_failure: Option<&'static str>,
    restarts: u64,
    generation: u64,
    serial: u64,
}

/// Demand-driven retry policy; the clock and attempted work are injectable on the live path.
#[derive(Default)]
pub struct Retry {
    failures: u32,
    next: Option<Instant>,
}

impl Retry {
    pub fn attempt<T>(
        &mut self,
        now: Instant,
        work: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        if self.next.is_some_and(|next| now < next) {
            return Err("capture.source_unavailable");
        }
        match work() {
            Ok(value) => {
                self.failures = 0;
                self.next = None;
                Ok(value)
            }
            Err(code) => {
                self.failed(now);
                Err(code)
            }
        }
    }
    fn failed(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        let seconds = (2_u64.saturating_pow(self.failures.min(6))).min(60);
        self.next = Some(now + Duration::from_secs(seconds));
    }
}

/// Hold the HDMI sink across pauses between clients; change this one policy constant.
pub const IDLE: Duration = Duration::from_secs(30 * 60);
pub const WARMUP: Duration = Duration::from_secs(6);
pub const FRAME_WAIT: Duration = Duration::from_secs(15);

pub struct Capture {
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    source: Option<String>,
}

impl Capture {
    /// Construction is inert. Only latest() can request a discovery/probe/stream.
    pub fn start(source: Option<String>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            stop: Arc::new(AtomicBool::new(false)),
            worker: None,
            source,
        }
    }

    fn request_at(
        &mut self,
        now: Instant,
        spawn: impl FnOnce(Option<String>, Arc<Mutex<State>>, Arc<AtomicBool>) -> JoinHandle<()>,
    ) -> Result<(), &'static str> {
        let mut state = self.state.lock().expect("capture state");
        state.requested_at = Some(now);
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            return Ok(());
        }
        if state.retry.next.is_some_and(|next| now < next) {
            return Err("capture.source_unavailable");
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        state.error = None;
        state.latest = None;
        state.ready = false;
        state.last_frame_at = None;
        drop(state);
        self.worker = Some(spawn(
            self.source.clone(),
            self.state.clone(),
            self.stop.clone(),
        ));
        Ok(())
    }
}

fn spawn_worker(
    source: Option<String>,
    shared: Arc<Mutex<State>>,
    stopping: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        // One attempt per explicit request; never an automatic restart/discovery loop.
        let result = super::capture::stream_setup(source.as_deref()).and_then(|(id, args)| {
            let generation = {
                let mut s = shared.lock().expect("capture state");
                s.source = Some(id);
                s.generation += 1;
                s.generation
            };
            // A request that expired during discovery/probing must not start a stream.
            if idle(&shared, Instant::now()) || stopping.load(Ordering::Acquire) {
                return Ok(());
            }
            let mut command = keyferry_core::process::command("ffmpeg");
            command.args(args);
            stream(command, generation, &shared, &stopping, true)
        });
        finish_attempt(&shared, result, Instant::now());
    })
}

fn finish_attempt(state: &Arc<Mutex<State>>, result: Result<(), &'static str>, now: Instant) {
    let mut s = state.lock().expect("capture state");
    s.latest = None;
    if let Err(code) = result {
        s.last_failure = Some(code);
        s.error = Some(code);
        s.retry.failed(now);
        s.restarts += 1;
    }
}

fn idle(state: &Arc<Mutex<State>>, now: Instant) -> bool {
    state
        .lock()
        .expect("capture state")
        .requested_at
        .is_none_or(|at| now.saturating_duration_since(at) >= IDLE)
}

impl FrameSource for Capture {
    fn latest(
        &mut self,
        after: Option<u64>,
        timeout: Duration,
        cancelled: &AtomicBool,
    ) -> Result<Arc<Frame>, &'static str> {
        if cancelled.load(Ordering::Acquire) {
            return Err("request.cancelled");
        }
        self.request_at(Instant::now(), spawn_worker)?;
        wait_latest(&self.state, after, timeout, cancelled)
    }
    fn status(&self) -> serde_json::Value {
        let s = self.state.lock().expect("capture state");
        serde_json::json!({"source":s.source,"error":s.error,"last_failure":s.last_failure,"restarts":s.restarts,"generation":s.generation,
            "frame_age_ms":s.latest.as_ref().map(|f|f.at.elapsed().as_millis())})
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn kill(child: &Arc<Mutex<Child>>) {
    let mut child = child.lock().expect("capture child");
    super::capture::stop_child(&mut child);
}

/// The one-shot CLI and daemon use the same reader, warm-up and failure handling.
pub fn one_shot(command: Command, timeout: Duration) -> Result<Arc<Frame>, &'static str> {
    let state = Arc::new(Mutex::new(State {
        requested_at: Some(Instant::now()),
        ..State::default()
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let shared = state.clone();
    let stopping = stop.clone();
    let worker = thread::spawn(move || {
        let result = stream(command, 1, &shared, &stopping, false);
        finish_attempt(&shared, result, Instant::now());
    });
    let result = wait_latest(&state, None, timeout, &AtomicBool::new(false));
    stop.store(true, Ordering::Release);
    let _ = worker.join();
    result.map_err(|code| {
        if code == "capture.frame_timeout" {
            "capture.timeout"
        } else {
            code
        }
    })
}

fn wait_latest(
    state: &Arc<Mutex<State>>,
    after: Option<u64>,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<Arc<Frame>, &'static str> {
    let start = Instant::now();
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err("request.cancelled");
        }
        let mut s = state.lock().expect("capture state");
        if s.ready {
            if let Some(frame) = &s.latest {
                if after.is_none_or(|n| frame.serial > n)
                    && frame.at.elapsed() < Duration::from_secs(2)
                {
                    let frame = frame.clone();
                    s.retry = Retry::default();
                    return Ok(frame);
                }
            }
        }
        if let Some(code) = s.error {
            return Err(code);
        }
        if start.elapsed() >= timeout {
            return Err("capture.frame_timeout");
        }
        drop(s);
        thread::sleep(Duration::from_millis(10));
    }
}

// PNG chunk framing bounds memory before decoding and carries geometry in the same stream.
// There is no separate geometry probe that would close/reopen the HDMI sink.
fn read_png(reader: &mut impl Read) -> Result<Vec<u8>, &'static str> {
    const LIMIT: usize = 64 * 1024 * 1024;
    let mut signature = [0; 8];
    reader
        .read_exact(&mut signature)
        .map_err(|_| "capture.frame_failed")?;
    if &signature != b"\x89PNG\r\n\x1a\n" {
        return Err("capture.invalid_frame");
    }
    let mut bytes = signature.to_vec();
    loop {
        let mut header = [0; 8];
        reader
            .read_exact(&mut header)
            .map_err(|_| "capture.invalid_frame")?;
        let length = u32::from_be_bytes(header[..4].try_into().expect("length")) as usize;
        let next = bytes
            .len()
            .checked_add(length)
            .and_then(|n| n.checked_add(12))
            .filter(|n| *n <= LIMIT)
            .ok_or("capture.output_limit")?;
        let end = &header[4..] == b"IEND";
        bytes.extend_from_slice(&header);
        bytes.resize(next, 0);
        reader
            .read_exact(&mut bytes[next - length - 4..])
            .map_err(|_| "capture.invalid_frame")?;
        if end {
            return Ok(bytes);
        }
    }
}

fn read_frame(reader: &mut impl Read, generation: u64, at: Instant) -> Result<Frame, &'static str> {
    let bytes = read_png(reader)?;
    let (width, height, rgb) = super::capture::decode(&bytes).map_err(|e| e.code)?;
    Ok(Frame {
        width,
        height,
        native: (width, height),
        rgb,
        serial: 0,
        generation,
        at,
    })
}

fn publish(
    state: &Arc<Mutex<State>>,
    mut frame: Frame,
    opened: Instant,
    bounded: bool,
) -> Result<(), &'static str> {
    let valid = super::capture::signal(&frame.rgb).0 == "present";
    let mut s = state.lock().expect("capture state");
    if s.latest.as_ref().is_some_and(|f| f.native != frame.native) {
        return Err("capture.resolution_changed");
    }
    s.last_frame_at = Some(frame.at);
    s.ready |= valid || frame.at.saturating_duration_since(opened) >= WARMUP;
    if bounded {
        let (width, height) = scaled_size(frame.native);
        if (width, height) != frame.native {
            let mut rgb = Vec::with_capacity((width * height * 3) as usize);
            for y in 0..height {
                for x in 0..width {
                    let i = (((y * frame.height / height) * frame.width + x * frame.width / width)
                        * 3) as usize;
                    rgb.extend_from_slice(&frame.rgb[i..i + 3]);
                }
            }
            frame.rgb = rgb;
            frame.width = width;
            frame.height = height;
        }
    }
    s.serial += 1;
    frame.serial = s.serial;
    s.latest = Some(Arc::new(frame));
    Ok(())
}

fn stream(
    mut command: Command,
    generation: u64,
    state: &Arc<Mutex<State>>,
    stop: &Arc<AtomicBool>,
    bounded: bool,
) -> Result<(), &'static str> {
    let mut child = command
        .env_remove("FFREPORT")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "capture.ffmpeg_missing"
            } else {
                "capture.process_start"
            }
        })?;
    let mut stdout = child.stdout.take().ok_or("capture.pipe")?;
    let stderr = child.stderr.take().ok_or("capture.pipe")?;
    let child = Arc::new(Mutex::new(child));
    let busy = Arc::new(AtomicBool::new(false));
    let busy_reader = busy.clone();
    let diagnostic = thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        // Discard bounded lines immediately; never retain or return device/FFmpeg text.
        loop {
            let mut line = Vec::new();
            if reader
                .by_ref()
                .take(4096)
                .read_until(b'\n', &mut line)
                .unwrap_or(0)
                == 0
            {
                break;
            }
            if source_busy(&String::from_utf8_lossy(&line)) {
                busy_reader.store(true, Ordering::Release);
            }
        }
    });
    let opened = Instant::now();
    let reading_state = state.clone();
    let reader = thread::spawn(move || -> Result<(), &'static str> {
        loop {
            let mut frame = read_frame(&mut stdout, generation, Instant::now())?;
            frame.at = Instant::now();
            publish(&reading_state, frame, opened, bounded)?;
        }
    });
    let result = loop {
        if stop.load(Ordering::Acquire) || idle(state, Instant::now()) {
            break Ok(());
        }
        if reader.is_finished() {
            break Err("capture.frame_failed");
        }
        let stale = state
            .lock()
            .expect("capture state")
            .last_frame_at
            .map_or(opened.elapsed(), |at| at.elapsed());
        if stale > FRAME_WAIT {
            break Err("capture.frame_timeout");
        }
        thread::sleep(Duration::from_millis(20));
    };
    kill(&child);
    let reader_result = reader.join().unwrap_or(Err("capture.process_io"));
    let _ = diagnostic.join();
    if result.is_err() && busy.load(Ordering::Acquire) {
        Err("capture.source_busy")
    } else if result == Err("capture.frame_failed") {
        reader_result
    } else {
        result
    }
}

fn source_busy(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    [
        "device or resource busy",
        "already in use",
        "being used by another",
        "0x80070020",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_frame(value: u8, at: Instant) -> Frame {
        let frame = Frame {
            width: 2,
            height: 2,
            native: (2, 2),
            rgb: vec![value; 12],
            serial: 0,
            generation: 1,
            at,
        };
        // Fake sources supply bytes through the production framing/decoding path.
        read_frame(&mut std::io::Cursor::new(frame.png().unwrap()), 1, at).unwrap()
    }

    #[test]
    fn warmup_black_then_picture_and_permanent_black_no_signal() {
        let opened = Instant::now();
        let state = Arc::new(Mutex::new(State::default()));
        publish(&state, fake_frame(0, opened), opened, true).unwrap();
        assert!(!state.lock().unwrap().ready);
        publish(
            &state,
            fake_frame(0, opened + WARMUP - Duration::from_millis(1)),
            opened,
            true,
        )
        .unwrap();
        assert!(!state.lock().unwrap().ready);
        publish(&state, fake_frame(118, opened), opened, true).unwrap();
        let frame = wait_latest(&state, None, Duration::ZERO, &AtomicBool::new(false)).unwrap();
        assert_eq!(super::super::capture::signal(&frame.rgb).0, "present");

        let state = Arc::new(Mutex::new(State::default()));
        publish(&state, fake_frame(0, opened + WARMUP), opened, true).unwrap();
        let frame = wait_latest(&state, None, Duration::ZERO, &AtomicBool::new(false)).unwrap();
        assert_eq!(super::super::capture::signal(&frame.rgb).0, "no-signal");
    }

    #[test]
    fn requests_reuse_the_live_owner_and_warm_up_each_reopen() {
        let mut capture = Capture::start(None);
        let now = Instant::now();
        capture
            .request_at(now, |_, state, stop| {
                thread::spawn(move || {
                    publish(&state, fake_frame(118, Instant::now()), now, true).unwrap();
                    while !stop.load(Ordering::Acquire) {
                        thread::sleep(Duration::from_millis(1));
                    }
                })
            })
            .unwrap();
        let frame = capture
            .latest(None, Duration::from_secs(1), &AtomicBool::new(false))
            .unwrap();
        capture
            .request_at(now + Duration::from_secs(10), |_, _, _| {
                panic!("per-frame reopen")
            })
            .unwrap();
        assert_eq!(
            capture
                .latest(None, Duration::from_secs(1), &AtomicBool::new(false))
                .unwrap()
                .serial,
            frame.serial
        );
        assert!(!idle(&capture.state, now + Duration::from_secs(29 * 60)));
        assert!(idle(&capture.state, now + Duration::from_secs(10) + IDLE));
    }

    #[test]
    fn busy_diagnostics_are_fixed_codes_and_png_input_is_bounded() {
        assert!(source_busy("Device or resource busy"));
        assert!(source_busy(
            "Could not run graph (device already in use by other application)"
        ));
        assert!(!source_busy("private screen and device text"));
        let mut malformed = b"\x89PNG\r\n\x1a\n".to_vec();
        malformed.extend_from_slice(&u32::MAX.to_be_bytes());
        malformed.extend_from_slice(b"IDAT");
        assert_eq!(
            read_png(&mut std::io::Cursor::new(malformed)).unwrap_err(),
            "capture.output_limit"
        );
    }

    #[test]
    fn zero_requests_never_discover_or_spawn() {
        let capture = Capture::start(Some("absent".into()));
        assert!(capture.worker.is_none());
        assert!(capture.state.lock().unwrap().requested_at.is_none());
        assert_eq!(capture.status()["generation"], 0);
        assert_eq!(capture.status()["restarts"], 0);
    }

    #[test]
    fn missing_source_attempts_require_demand_and_back_off_to_sixty_seconds() {
        let mut capture = Capture::start(Some("absent".into()));
        let start = Instant::now();
        let mut attempts = Vec::new();
        for second in 0..=240 {
            let now = start + Duration::from_secs(second);
            let _ = capture.request_at(now, |_, state, _| {
                attempts.push(second);
                // Fake discovery/spawner uses the same admission and failure policy as production.
                finish_attempt(&state, Err("capture.source_unavailable"), now);
                thread::spawn(|| {})
            });
            if let Some(worker) = capture.worker.take() {
                worker.join().unwrap();
            }
        }
        assert_eq!(attempts, [0, 2, 6, 14, 30, 62, 122, 182]);
        // Passing time without requests cannot invoke the spawner, including after backoff.
        assert!(capture.worker.is_none());
        assert_eq!(capture.state.lock().unwrap().generation, 0);
    }

    #[test]
    fn idle_deadline_is_measured_from_last_frame_request() {
        let capture = Capture::start(None);
        let now = Instant::now();
        assert!(idle(&capture.state, now));
        capture.state.lock().unwrap().requested_at = Some(now);
        assert!(!idle(&capture.state, now + Duration::from_secs(29 * 60)));
        assert!(!idle(&capture.state, now + IDLE - Duration::from_millis(1)));
        assert!(idle(&capture.state, now + IDLE));
    }

    #[test]
    #[ignore = "requires ffmpeg on PATH; local raw-pipe and idle process-tree shutdown smoke"]
    fn continuous_raw_pipe_stops_owned_process_tree_after_idle() {
        let state = Arc::new(Mutex::new(State {
            requested_at: Some(Instant::now()),
            ..State::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let args = [
            "-hide_banner",
            "-nostdin",
            "-loglevel",
            "info",
            "-f",
            "lavfi",
            "-i",
            "testsrc=size=320x240:rate=15",
            "-threads",
            "1",
            "-filter_threads",
            "1",
            "-pix_fmt",
            "rgb24",
            "-c:v",
            "png",
            "-f",
            "image2pipe",
            "pipe:1",
        ]
        .map(str::to_owned);
        let reader_state = state.clone();
        let stopping = stop.clone();
        let worker = thread::spawn(move || {
            let mut command = keyferry_core::process::command("ffmpeg");
            command.args(args);
            stream(command, 1, &reader_state, &stopping, true)
        });
        let start = Instant::now();
        while state.lock().unwrap().latest.is_none() && start.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(10));
        }
        let observed = state
            .lock()
            .unwrap()
            .latest
            .as_ref()
            .map(|f| (f.width, f.height, f.rgb.len()));
        state.lock().unwrap().requested_at = Some(Instant::now() - IDLE);
        assert!(worker.join().unwrap().is_ok());
        assert_eq!(observed, Some((320, 240, 320 * 240 * 3)));
        assert!(start.elapsed() < Duration::from_secs(6));
    }
}
