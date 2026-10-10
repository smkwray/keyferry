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
    process::{Child, Stdio},
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
    latest: Option<Arc<Frame>>,
    error: Option<&'static str>,
    last_failure: Option<&'static str>,
    restarts: u64,
    generation: u64,
    serial: u64,
}

pub struct Capture {
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Capture {
    pub fn start(source: Option<String>) -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let shared = state.clone();
        let stopping = stop.clone();
        let worker = thread::spawn(move || {
            let mut selected = source;
            while !stopping.load(Ordering::Acquire) {
                match super::capture::stream_setup(selected.as_deref()) {
                    Ok((id, w, h, args)) => {
                        selected = Some(id);
                        let generation = {
                            let mut s = shared.lock().expect("capture state");
                            s.source = selected.clone();
                            s.generation += 1;
                            s.generation
                        };
                        let result = stream(&args, (w, h), generation, &shared, &stopping);
                        if !stopping.load(Ordering::Acquire) {
                            let mut s = shared.lock().expect("capture state");
                            s.latest = None;
                            s.error = Some(result.err().unwrap_or("capture.process_ended"));
                            s.last_failure = s.error;
                        }
                    }
                    Err(code) => {
                        let mut s = shared.lock().expect("capture state");
                        s.error = Some(code);
                        s.last_failure = Some(code);
                    }
                }
                if stopping.load(Ordering::Acquire) {
                    break;
                }
                // Bounded backoff. Capture restarts never replay input commands.
                for _ in 0..20 {
                    if stopping.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                shared.lock().expect("capture state").restarts += 1;
            }
        });
        Self {
            state,
            stop,
            worker: Some(worker),
        }
    }
}

impl FrameSource for Capture {
    fn latest(
        &mut self,
        after: Option<u64>,
        timeout: Duration,
        cancelled: &AtomicBool,
    ) -> Result<Arc<Frame>, &'static str> {
        let start = Instant::now();
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err("request.cancelled");
            }
            let s = self.state.lock().expect("capture state");
            if let Some(frame) = &s.latest {
                if after.is_none_or(|n| frame.serial > n)
                    && frame.at.elapsed() < Duration::from_secs(2)
                {
                    return Ok(frame.clone());
                }
            }
            if start.elapsed() >= timeout {
                return Err(s.error.unwrap_or("capture.frame_timeout"));
            }
            drop(s);
            thread::sleep(Duration::from_millis(10));
        }
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

fn stream(
    args: &[String],
    native: (u32, u32),
    generation: u64,
    state: &Arc<Mutex<State>>,
    stop: &Arc<AtomicBool>,
) -> Result<(), &'static str> {
    let mut child = keyferry_core::process::command("ffmpeg")
        .args(args)
        .env_remove("FFREPORT")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "capture.process_start")?;
    let mut stdout = child.stdout.take().ok_or("capture.pipe")?;
    let stderr = child.stderr.take().ok_or("capture.pipe")?;
    let child = Arc::new(Mutex::new(child));
    let changed = Arc::new(AtomicBool::new(false));
    let changed_reader = changed.clone();
    let diagnostic = thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        // Read one bounded line at a time; never retain, print, or return FFmpeg messages.
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
            let text = String::from_utf8_lossy(&line);
            if text.contains("showinfo") {
                if let Some(size) = text
                    .split(" s:")
                    .nth(1)
                    .and_then(|s| s.split_whitespace().next())
                {
                    if size != format!("{}x{}", native.0, native.1) {
                        changed_reader.store(true, Ordering::Release);
                    }
                }
            }
        }
    });
    let (width, height) = scaled_size(native);
    let reading_state = state.clone();
    let reader = thread::spawn(move || loop {
        let mut rgb = vec![0; width as usize * height as usize * 3];
        if stdout.read_exact(&mut rgb).is_err() {
            break;
        }
        let mut s = reading_state.lock().expect("capture state");
        s.serial += 1;
        s.error = None;
        s.latest = Some(Arc::new(Frame {
            width,
            height,
            native,
            rgb,
            serial: s.serial,
            generation,
            at: Instant::now(),
        }));
    });
    let start = Instant::now();
    let result = loop {
        if stop.load(Ordering::Acquire) {
            break Ok(());
        }
        if changed.load(Ordering::Acquire) {
            break Err("capture.resolution_changed");
        }
        if reader.is_finished() {
            break Err("capture.process_ended");
        }
        let stale = state
            .lock()
            .expect("capture state")
            .latest
            .as_ref()
            .filter(|f| f.generation == generation)
            .map_or(start.elapsed(), |f| f.at.elapsed());
        if stale > Duration::from_secs(5) {
            break Err("capture.frame_timeout");
        }
        thread::sleep(Duration::from_millis(20));
    };
    kill(&child);
    let _ = reader.join();
    let _ = diagnostic.join();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires ffmpeg on PATH; local raw-pipe and process-tree shutdown smoke"]
    fn continuous_raw_pipe_stops_owned_process_tree() {
        let state = Arc::new(Mutex::new(State::default()));
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
            "-vf",
            "showinfo",
            "-threads",
            "1",
            "-filter_threads",
            "1",
            "-pix_fmt",
            "rgb24",
            "-f",
            "rawvideo",
            "pipe:1",
        ]
        .map(str::to_owned);
        let reader_state = state.clone();
        let stopping = stop.clone();
        let worker = thread::spawn(move || stream(&args, (320, 240), 1, &reader_state, &stopping));
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
        stop.store(true, Ordering::Release);
        assert!(worker.join().unwrap().is_ok());
        assert_eq!(observed, Some((320, 240, 320 * 240 * 3)));
        assert!(start.elapsed() < Duration::from_secs(6));
    }
}
