use super::super::ocr::TextBox;
use super::*;
use std::{collections::VecDeque, fs};

fn frame(w: u32, h: u32, serial: u64) -> Frame {
    Frame {
        width: w,
        height: h,
        native: (w * 2, h * 2),
        rgb: vec![60; w as usize * h as usize * 3],
        serial,
        generation: 1,
        at: Instant::now(),
    }
}
/// Where the fake target shows normalized pointer positions: origin x, y and extent w, h.
const FAKE_AREA: [f64; 4] = [20.0, 30.0, 280.0, 180.0];
/// The cursor tip's screenshot pixel for pointer position `p`.
fn tip(area: [f64; 4], p: [f64; 2]) -> (u32, u32) {
    (
        (area[0] + p[0] * area[2]).round() as u32,
        (area[1] + p[1] * area[3]).round() as u32,
    )
}
fn cursor_frame(area: [f64; 4], p: [f64; 2], serial: u64) -> Frame {
    let mut f = frame(320, 240, serial);
    let (x, y) = tip(area, p);
    for dy in 0..9 {
        for dx in 0..=dy / 2 {
            if x + dx < f.width && y + dy < f.height {
                let i = ((y + dy) * f.width + x + dx) as usize * 3;
                f.rgb[i..i + 3].fill(255);
            }
        }
    }
    f
}

struct FakeFrames {
    next: u64,
    scripted: VecDeque<Frame>,
    change_after: Option<u64>,
    pointer: Option<Arc<Mutex<Visual>>>,
    area: [f64; 4],
    visible: Visual,
    delay: Duration,
    animate: bool,
    busy: bool,
    never_change: bool,
    started: Instant,
    ocr: bool,
    ocr_polls: u32,
    native: bool,
    native_polls: u32,
}
/// Like the controller, native requests serve the frame's native pixels (here 2x).
fn native_view(f: Frame) -> Frame {
    let (w, h) = f.native;
    let mut rgb = Vec::with_capacity(w as usize * h as usize * 3);
    for y in 0..h {
        for x in 0..w {
            let i = ((y * f.height / h) * f.width + x * f.width / w) as usize * 3;
            rgb.extend_from_slice(&f.rgb[i..i + 3]);
        }
    }
    Frame {
        width: w,
        height: h,
        rgb,
        ..f
    }
}
#[derive(Clone)]
struct Visual {
    pointer: [f64; 2],
    revision: u8,
    at: Instant,
    /// Every absolute report requested, in order; read by the daemon-backed MCP tests.
    #[allow(dead_code)]
    path: Vec<[f64; 2]>,
}
impl FakeFrames {
    fn new() -> Self {
        Self {
            next: 0,
            scripted: VecDeque::new(),
            change_after: None,
            pointer: None,
            area: FAKE_AREA,
            visible: Visual {
                pointer: [0.5, 0.5],
                revision: 0,
                at: Instant::now(),
                path: Vec::new(),
            },
            delay: Duration::ZERO,
            animate: false,
            busy: false,
            never_change: false,
            started: Instant::now(),
            ocr: false,
            ocr_polls: 0,
            native: false,
            native_polls: 0,
        }
    }
}
impl FrameSource for FakeFrames {
    fn request_ocr(&mut self, ocr: bool) {
        self.ocr = ocr;
    }
    fn request_native(&mut self, native: bool) {
        self.native = native;
    }
    fn latest(
        &mut self,
        after: Option<u64>,
        timeout: Duration,
        cancelled: &AtomicBool,
    ) -> Result<Arc<Frame>, &'static str> {
        let frame = self.agent_view(after, timeout, cancelled)?;
        if !self.native {
            return Ok(frame);
        }
        self.native_polls += 1;
        Ok(Arc::new(native_view(Arc::unwrap_or_clone(frame))))
    }
    fn status(&self) -> Value {
        json!({"source":"fake-hdmi","generation":1,"restarts":0})
    }
}
impl FakeFrames {
    fn agent_view(
        &mut self,
        after: Option<u64>,
        timeout: Duration,
        cancelled: &AtomicBool,
    ) -> Result<Arc<Frame>, &'static str> {
        // Like the daemon client, an OCR request covers exactly one frame.
        if std::mem::take(&mut self.ocr) {
            self.ocr_polls += 1;
        }
        if cancelled.load(Ordering::Acquire) {
            return Err("request.cancelled");
        }
        if let Some(mut f) = self.scripted.pop_front() {
            self.next = self.next.max(after.unwrap_or(0)) + 1;
            f.serial = self.next;
            f.at = Instant::now();
            return Ok(Arc::new(f));
        }
        if timeout < Duration::from_millis(50) {
            thread::sleep(timeout);
            return Err("capture.frame_timeout");
        }
        if after.is_some() {
            thread::sleep(Duration::from_millis(50));
        }
        self.next = self.next.max(after.unwrap_or(0)) + 1;
        if let Some(pointer) = &self.pointer {
            let desired = pointer.lock().unwrap();
            if !self.never_change && desired.at.elapsed() >= self.delay {
                self.visible = desired.clone();
            }
        }
        let mut f = if self.pointer.is_some() {
            cursor_frame(self.area, self.visible.pointer, self.next)
        } else {
            frame(320, 240, self.next)
        };
        if self.visible.revision != 0 {
            for y in 208..214 {
                for x in 20..28 {
                    let i = (y * f.width + x) as usize * 3;
                    f.rgb[i..i + 3].fill(if self.visible.revision % 2 == 1 {
                        200
                    } else {
                        100
                    });
                }
            }
        }
        if self.animate {
            let elapsed = self.started.elapsed().as_millis();
            // Blink every 200 ms and advance a clock glyph every second, away from probes.
            for (x, width, value) in [
                (
                    280,
                    3,
                    if (elapsed / 200).is_multiple_of(2) {
                        255
                    } else {
                        60
                    },
                ),
                (288, 8, 100 + (elapsed / 1000 % 4) as u8 * 40),
            ] {
                for y in 8..20 {
                    for x in x..x + width {
                        let i = (y * f.width + x) as usize * 3;
                        f.rgb[i..i + 3].fill(value);
                    }
                }
            }
        }
        if self.busy {
            // Notification panel plus a late-changing unlearned glyph, away from probe targets.
            let value = if (self.started.elapsed().as_millis() / 200).is_multiple_of(2) {
                200
            } else {
                60
            };
            for y in 25..85 {
                for x in 270..310 {
                    let i = (y * f.width + x) as usize * 3;
                    f.rgb[i..i + 3].fill(value);
                }
            }
        }
        if self.change_after.is_some_and(|n| self.next >= n) {
            f.rgb.fill(255);
        }
        Ok(Arc::new(f))
    }
}
struct FakeOcr;
impl Ocr for FakeOcr {
    fn recognize(&mut self, f: &Frame) -> Result<Vec<TextBox>, &'static str> {
        assert_eq!((f.width, f.height), (320, 240));
        Ok(vec![
            TextBox {
                text: "Safe test target".into(),
                x: 32.0,
                y: 24.0,
                width: 128.0,
                height: 20.0,
            },
            TextBox {
                text: "Another label".into(),
                x: 2.0,
                y: 2.0,
                width: 80.0,
                height: 15.0,
            },
        ])
    }
}
fn server() -> Server<FakeFrames, FakeOcr> {
    Server::new(
        "simulator-1".into(),
        Some("fake-hdmi".into()),
        "http://127.0.0.1:9",
        Path::new("missing-token"),
        std::env::temp_dir().join(format!("kf-mcp-{}", uuid::Uuid::now_v7())),
        |_| FakeFrames::new(),
        FakeOcr,
    )
}
fn init(s: &mut Server<FakeFrames, FakeOcr>) {
    let c = AtomicBool::new(false);
    assert_eq!(s.dispatch(json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"test","version":"1"},"capabilities":{}}}),&c).unwrap()["result"]["serverInfo"]["name"],"keyferry");
    assert!(s
        .dispatch(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            &c
        )
        .is_none());
}
