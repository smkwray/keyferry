use super::super::ocr::TextBox;
use super::*;
use keyferryd::{
    Daemon, MemoryTokenStore, SimulationFault, SimulatorTransport, SIMULATOR_DEVICE_ID,
};
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
fn cursor_frame(p: [f64; 2], serial: u64) -> Frame {
    let mut f = frame(320, 240, serial);
    let x = (20.0 + p[0] * 280.0).round() as u32;
    let y = (30.0 + p[1] * 180.0).round() as u32;
    for dy in 0..9 {
        for dx in 0..=dy / 2 {
            let i = ((y + dy) * f.width + x + dx) as usize * 3;
            f.rgb[i..i + 3].fill(255);
        }
    }
    f
}

struct FakeFrames {
    next: u64,
    scripted: VecDeque<Frame>,
    change_after: Option<u64>,
    pointer: Option<Arc<Mutex<Visual>>>,
    visible: Visual,
    delay: Duration,
    animate: bool,
    busy: bool,
    never_change: bool,
    started: Instant,
    ocr: bool,
    ocr_polls: u32,
}
#[derive(Clone)]
struct Visual {
    pointer: [f64; 2],
    revision: u8,
    at: Instant,
}
impl FakeFrames {
    fn new() -> Self {
        Self {
            next: 0,
            scripted: VecDeque::new(),
            change_after: None,
            pointer: None,
            visible: Visual {
                pointer: [0.5, 0.5],
                revision: 0,
                at: Instant::now(),
            },
            delay: Duration::ZERO,
            animate: false,
            busy: false,
            never_change: false,
            started: Instant::now(),
            ocr: false,
            ocr_polls: 0,
        }
    }
}
impl FrameSource for FakeFrames {
    fn request_ocr(&mut self, ocr: bool) {
        self.ocr = ocr;
    }
    fn latest(
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
            cursor_frame(self.visible.pointer, self.next)
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
    fn status(&self) -> Value {
        json!({"source":"fake-hdmi","generation":1,"restarts":0})
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
        SIMULATOR_DEVICE_ID.into(),
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

#[test]
fn framing_is_newline_bounded_and_sanitized() {
    let mut input =
        io::Cursor::new(b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}\n{\"id\":2}\n");
    assert_eq!(read_message(&mut input).unwrap().unwrap()["id"], 1);
    assert_eq!(read_message(&mut input).unwrap().unwrap()["id"], 2);
    assert!(read_message(&mut input).unwrap().is_none());
    let mut long = vec![b'x'; MAX_MESSAGE + 500];
    long.extend_from_slice(b"\n{\"id\":3}\n");
    let mut input = io::Cursor::new(long);
    assert_eq!(
        read_message(&mut input).unwrap_err(),
        "stdio.message_limit_or_incomplete"
    );
    assert_eq!(read_message(&mut input).unwrap().unwrap()["id"], 3);
    assert_eq!(
        read_message(&mut io::Cursor::new(b"{\"secret\":\"do-not-echo\"}")).unwrap_err(),
        "stdio.message_limit_or_incomplete"
    );
    let mut output = Vec::new();
    write_message(&mut output, &json!({"text":"line\nbreak"})).unwrap();
    assert_eq!(output.iter().filter(|v| **v == b'\n').count(), 1);
}

#[test]
fn dispatch_lifecycle_schema_and_duplicate_id_no_replay() {
    let mut s = server();
    let c = AtomicBool::new(false);
    assert_eq!(
        s.dispatch(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}), &c)
            .unwrap()["error"]["message"],
        "rpc.not_initialized"
    );
    init(&mut s);
    let list = s
        .dispatch(
            json!({"jsonrpc":"2.0","id":"list","method":"tools/list"}),
            &c,
        )
        .unwrap();
    assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 20);
    for tool in tools() {
        assert!(
            validate(&json!({}), &tool["inputSchema"])
                || !tool["inputSchema"]["required"]
                    .as_array()
                    .unwrap()
                    .is_empty()
        );
    }
    for (name, args) in [
        ("click", json!({"x":1,"y":2,"extra":"do-not-echo"})),
        ("scroll", json!({"x":1,"y":2,"dx":128,"dy":0})),
        ("move", json!({"x":-1,"y":2})),
        ("key", json!({"keys":[]})),
        ("screenshot", json!({"save_path":null})),
    ] {
        let result=s.dispatch(json!({"jsonrpc":"2.0","id":name,"method":"tools/call","params":{"name":name,"arguments":args}}),&c).unwrap();
        assert_eq!(result["result"]["isError"], true);
        assert!(!result.to_string().contains("do-not-echo"));
    }
    let result=s.dispatch(json!({"jsonrpc":"2.0","id":"click","method":"tools/call","params":{"name":"click","arguments":{"x":1,"y":2}}}),&c).unwrap();
    assert_eq!(result["error"]["message"], "rpc.duplicate_id_no_replay");
    assert!(s.dispatch(json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"click","arguments":{"x":1,"y":2}}}),&c).is_none());
    assert_eq!(
        s.dispatch(json!({"jsonrpc":"2.0","id":null,"method":"ping"}), &c)
            .unwrap()["error"]["code"],
        -32600
    );
}

#[test]
fn mapping_letterbox_scale_and_overscan() {
    let f = frame(320, 240, 1);
    let samples = vec![
        ([0.1, 0.2], [48.0, 66.0]),
        ([0.8, 0.2], [244.0, 66.0]),
        ([0.2, 0.8], [76.0, 174.0]),
        ([0.8, 0.7], [244.0, 156.0]),
    ];
    let g = geometry::fit("d", "s", &f, &samples).unwrap();
    let p = g.map(160.0, 120.0).unwrap();
    assert!((p[0] - 0.5).abs() < 1e-9 && (p[1] - 0.5).abs() < 1e-9);
    assert_eq!(
        g.map(0.0, 120.0).unwrap_err(),
        "pointer.outside_active_video"
    );
    let mut other = f.clone();
    other.native = (1920, 1080);
    assert!(!g.matches("d", "s", &other));
    assert!(!g.matches("d", "other", &f));
    assert_eq!(geometry::linear(&f, 319.0, 239.0).unwrap(), [1.0, 1.0]);
    assert!(geometry::linear(&f, 320.0, 239.0).is_err());
    let mut scaled = g.clone();
    scaled.origin = [-10.0, -10.0];
    scaled.extent = [340.0, 260.0];
    assert!(scaled.map(0.0, 0.0).unwrap().iter().all(|n| *n > 0.0));
    let changed = vec![
        ([0.1, 0.2], [48.0, 66.0]),
        ([0.8, 0.2], [244.0, 66.0]),
        ([0.2, 0.8], [76.0, 174.0]),
        ([0.8, 0.7], [150.0, 156.0]),
    ];
    assert!(geometry::fit("d", "s", &f, &changed).is_err());
}

#[test]
fn cursor_differencing_synthetic_and_ambiguity() {
    let a = cursor_frame([0.1, 0.1], 1);
    let b = cursor_frame([0.7, 0.2], 2);
    let c = cursor_frame([0.3, 0.8], 3);
    let mask = frames::MotionMask::new(&a);
    assert_eq!(geometry::cursor(&a, &b, &c, &mask).unwrap(), [216.0, 66.0]);
    assert_eq!(
        geometry::cursor(&a, &a, &a, &mask).unwrap_err(),
        "calibration.cursor_not_seen"
    );
    let mut b2 = b.clone();
    for y in 10..15 {
        for x in 10..15 {
            let i = (y * b.width + x) as usize * 3;
            b2.rgb[i..i + 3].fill(255);
        }
    }
    assert_eq!(
        geometry::cursor(&a, &b2, &c, &mask).unwrap_err(),
        "calibration.animated_or_ambiguous"
    );
    let mut c2 = c.clone();
    c2.generation = 2;
    assert!(geometry::cursor(&a, &b, &c2, &mask).is_err());
}

#[test]
fn robust_fit_rejects_two_outliers_and_reports_pixel_residuals() {
    let f = frame(320, 240, 1);
    let mut samples: Vec<_> = [
        [0.12, 0.15],
        [0.80, 0.20],
        [0.25, 0.78],
        [0.73, 0.72],
        [0.45, 0.42],
        [0.60, 0.60],
    ]
    .into_iter()
    .map(|p| (p, [20.0 + 280.0 * p[0], 30.0 + 180.0 * p[1]]))
    .collect();
    samples[0].1 = [280.0, 200.0];
    samples[5].1 = [5.0, 5.0];
    let (g, inliers, rms) = geometry::robust_fit("d", "s", &f, &samples).unwrap();
    assert_eq!(inliers, 4);
    assert!(rms < 0.001);
    assert!((g.extent[0] - 280.0).abs() < 0.001);
    samples[1].1 = [5.0, 5.0];
    assert!(geometry::robust_fit("d", "s", &f, &samples).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_desktop_calibration_and_moves_use_the_production_path() {
    let (mut s, transport, _, task) = harness(vec![], true).await;
    let root = s.root.clone();
    s.frames.busy = true;
    s.frames.animate = true;
    s.frames.delay = Duration::from_millis(250);
    tokio::task::spawn_blocking(move || {
        init(&mut s);
        let c=AtomicBool::new(false);
        let calibration=s.dispatch(json!({"jsonrpc":"2.0","id":"busy-calibration","method":"tools/call","params":{"name":"calibrate","arguments":{}}}),&c).unwrap();
        assert_eq!(calibration["result"]["isError"],false,"{calibration}");
        assert!(calibration["result"]["structuredContent"]["residual_rms_px"].as_f64().unwrap()<1.0);
        s.call("screenshot",&json!({}),&c).unwrap();
        for (i,(x,y)) in [(100,130),(200,160)].into_iter().enumerate() {
            let start=Instant::now();
            let response=s.dispatch(json!({"jsonrpc":"2.0","id":format!("move-{i}"),"method":"tools/call","params":{"name":"move","arguments":{"x":x,"y":y,"format":"jpeg"}}}),&c).unwrap();
            assert_eq!(response["result"]["isError"],false,"{response}");
            let result=&response["result"]["structuredContent"];
            assert_eq!(result["settled"],true,"{result}");
            assert_eq!(result["settle_method"],"cursor-at-target");
            assert!(start.elapsed()<Duration::from_millis(1000));
            // Delay begins at admission; latency_ms begins after the EMITTED receipt.
            assert!(start.elapsed()>=Duration::from_millis(250));
            assert!(result["latency_ms"].as_u64().unwrap()>0);
            assert_eq!(response["result"]["content"][0]["mimeType"],"image/jpeg");
            let id=uuid::Uuid::parse_str(result["command"]["command_id"].as_str().unwrap()).unwrap();
            assert_eq!(transport.execution_count(id),1);
        }
        // A newly appearing panel outside the action ROI cannot prolong a settled click.
        s.animation.as_mut().unwrap().1 = frames::MotionMask::new(s.last_observed.as_ref().unwrap());
        let clicked = s.call("click", &json!({"x":100,"y":150,"format":"png"}), &c).unwrap();
        assert_eq!(clicked["structuredContent"]["settled"],true);
        assert_eq!(clicked["structuredContent"]["settle_region"]["width"],256);
        assert_eq!(clicked["content"][0]["mimeType"],"image/png");
    }).await.unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_dispatch_returns_one_image_and_stops_on_unknown_or_unsettled() {
    for fault in [false, true] {
        let faults = if fault {
            vec![SimulationFault::LostAfterStart]
        } else {
            vec![]
        };
        let (mut s, transport, _, task) = harness(faults, true).await;
        let root = s.root.clone();
        tokio::task::spawn_blocking(move || {
            init(&mut s);
            let c=AtomicBool::new(false);
            s.call("screenshot",&json!({}),&c).unwrap();
            let response=s.dispatch(json!({"jsonrpc":"2.0","id":"batch","method":"tools/call","params":{"name":"batch","arguments":{"actions":[{"tool":"move","arguments":{"x":100,"y":130,"uncalibrated":true}},{"tool":"move","arguments":{"x":200,"y":160,"uncalibrated":true}}]}}}),&c).unwrap();
            let result=&response["result"]["structuredContent"];
            assert_eq!(response["result"]["isError"],fault,"{response}");
            assert_eq!(result["actions"].as_array().unwrap().len(),2);
            assert_eq!(response["result"]["content"].as_array().unwrap().iter().filter(|c|c["type"]=="image").count(),1);
            for action in result["actions"].as_array().unwrap() {
                let command=if fault {&action["error"]["command"]} else {&action["command"]};
                let id=uuid::Uuid::parse_str(command["command_id"].as_str().unwrap()).unwrap();
                assert_eq!(transport.execution_count(id),1);
            }
            let prior=transport.control_request_counts();
            let malformed=s.dispatch(json!({"jsonrpc":"2.0","id":"invalid-batch","method":"tools/call","params":{"name":"batch","arguments":{"actions":[{"tool":"move","arguments":{"x":100,"y":130,"uncalibrated":true}},{"tool":"calibrate","arguments":{}}]}}}),&c).unwrap();
            assert_eq!(malformed["result"]["isError"],true);
            assert_eq!(transport.control_request_counts(),prior);
            s.frames.never_change=true;
            let response=s.dispatch(json!({"jsonrpc":"2.0","id":"unsettled-batch","method":"tools/call","params":{"name":"batch","arguments":{"return_screenshot":false,"actions":[{"tool":"move","arguments":{"x":130,"y":150,"uncalibrated":true}},{"tool":"move","arguments":{"x":220,"y":100,"uncalibrated":true}}]}}}),&c).unwrap();
            assert_eq!(response["result"]["structuredContent"]["actions"].as_array().unwrap().len(),2);
            assert_eq!(response["result"]["structuredContent"]["stopped_at"],0);
            assert_eq!(response["result"]["content"].as_array().unwrap().len(),1);
        }).await.unwrap();
        task.abort();
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn stability_change_region_ocr_and_no_persistence() {
    let mut s = server();
    let c = AtomicBool::new(false);
    let f = s.frame(&c).unwrap();
    let v = s
        .wait("wait_for_stable", &json!({"timeout_ms":1000}), f, &c)
        .unwrap();
    assert_eq!(v["matched"], true);
    let f = s.frame(&c).unwrap();
    let v = s
        .wait("wait_for_change", &json!({"timeout_ms":120}), f, &c)
        .unwrap();
    assert_eq!(v["timed_out"], true);
    s.frames.change_after = Some(s.frames.next + 3);
    let f = s.frame(&c).unwrap();
    assert_eq!(
        s.wait("wait_for_change", &json!({"timeout_ms":1000}), f, &c)
            .unwrap()["matched"],
        true
    );
    let result = s
        .call("find_text", &json!({"query":"SAFE TEST"}), &c)
        .unwrap();
    assert_eq!(
        result["structuredContent"]["boxes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(result["structuredContent"]["boxes"][0]["x"], 32.0);
    let before = s.call("screenshot", &json!({}), &c).unwrap();
    let data = before["content"][0]["data"].as_str().unwrap();
    let bytes = STANDARD.decode(data).unwrap();
    assert_eq!(before["content"][0]["mimeType"], "image/jpeg");
    assert_eq!(&bytes[..2], b"\xff\xd8");
    let png = s.call("screenshot", &json!({"format":"png"}), &c).unwrap();
    assert_eq!(png["content"][0]["mimeType"], "image/png");
    let bytes = STANDARD
        .decode(png["content"][0]["data"].as_str().unwrap())
        .unwrap();
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
    assert!(!s.root.exists());
    let mut changed = frame(320, 240, 1);
    changed.generation = 2;
    assert!(frames::difference(&frame(320, 240, 1), &changed, None).is_err());
    assert!(frames::difference(
        &changed,
        &changed,
        Some(Region {
            x: 319,
            y: 239,
            width: 2,
            height: 2
        })
    )
    .is_err());
    assert_eq!(
        s.call("type_text", &json!({"text":"\u{1f512}"}), &c)
            .unwrap_err()["code"],
        "text.unsupported"
    );
    c.store(true, Ordering::Release);
    assert_eq!(s.frame(&c).unwrap_err()["code"], "request.cancelled");
}

#[test]
fn saved_geometry_is_nonsecret_and_requires_session_binding() {
    let mut s = server();
    let f = frame(320, 240, 1);
    let g = geometry::fit(
        &s.device,
        "fake-hdmi",
        &f,
        &[
            ([0.1, 0.1], [48.0, 48.0]),
            ([0.8, 0.2], [244.0, 66.0]),
            ([0.2, 0.8], [76.0, 174.0]),
            ([0.8, 0.7], [244.0, 156.0]),
        ],
    )
    .unwrap();
    geometry::save(&s.root, &g).unwrap();
    geometry::save(&s.root, &g).unwrap();
    let c = AtomicBool::new(false);
    let f = s.frame(&c).unwrap();
    assert!(s.geometry.is_some());
    assert_eq!(
        s.point(&f, 160.0, 120.0, false).unwrap_err()["code"],
        "pointer.calibration_required"
    );
    assert!(s.point(&f, 160.0, 120.0, true).is_ok());
    s.bound_generation = Some(1);
    assert!(s.point(&f, 160.0, 120.0, false).is_ok());
    s.frames.scripted.push_back({
        let mut f = frame(320, 240, 2);
        f.generation = 2;
        f
    });
    s.frame(&c).unwrap();
    assert!(s.bound_generation.is_none());
    assert!(s.geometry.is_none());
    fs::remove_dir_all(&s.root).unwrap();
}

/// GET status supplies simulator-only capability metadata, because SimulatorTransport has no
/// physical firmware identity. POST/GET command routes are the actual daemon router unchanged.
async fn harness(
    faults: Vec<SimulationFault>,
    extended: bool,
) -> (
    Server<FakeFrames, FakeOcr>,
    Arc<SimulatorTransport>,
    Daemon,
    tokio::task::JoinHandle<()>,
) {
    let transport = Arc::new(if extended {
        SimulatorTransport::new(faults).with_extended_pointer()
    } else {
        SimulatorTransport::new(faults).with_input_sequence()
    });
    let daemon = Daemon::with_transport(
        MemoryTokenStore::new("test-token-123456"),
        transport.clone(),
    )
    .unwrap();
    let mask = if extended {
        keyferry_protocol::capability::POINTER_EXTENDED_V1
    } else {
        0
    };
    let pointer = Arc::new(Mutex::new(Visual {
        pointer: [0.5, 0.5],
        revision: 0,
        at: Instant::now(),
    }));
    let observed = pointer.clone();
    let app = daemon.router().layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let observed = observed.clone();
            async move {
                let status = request.method() == axum::http::Method::GET
                    && request.uri().path() == format!("/v1/devices/{SIMULATOR_DEVICE_ID}");
                let request = if request.method() == axum::http::Method::POST
                    && request.uri().path().ends_with("/input-sequences")
                {
                    let (parts, body) = request.into_parts();
                    let bytes = axum::body::to_bytes(body, MAX_MESSAGE).await.unwrap();
                    let value: Value = serde_json::from_slice(&bytes).unwrap();
                    for action in value["actions"].as_array().unwrap() {
                        if action["type"] == "move_absolute" || action["type"] == "drag" {
                            observed.lock().unwrap().pointer =
                                [action["x"].as_f64().unwrap(), action["y"].as_f64().unwrap()];
                        } else {
                            observed.lock().unwrap().revision += 1;
                        }
                    }
                    observed.lock().unwrap().at = Instant::now();
                    axum::extract::Request::from_parts(parts, axum::body::Body::from(bytes))
                } else {
                    request
                };
                let response = next.run(request).await;
                if !status {
                    return response;
                }
                let (parts, body) = response.into_parts();
                let bytes = axum::body::to_bytes(body, 8192).await.unwrap();
                let mut v: Value = serde_json::from_slice(&bytes).unwrap();
                v["firmware"] = json!({"device_capability_mask":mask});
                axum::response::Response::from_parts(parts, axum::body::Body::from(v.to_string()))
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut s = server();
    s.frames.pointer = Some(pointer);
    s.url = format!("http://127.0.0.1:{port}");
    fs::create_dir_all(&s.root).unwrap();
    s.token = s.root.join("token");
    fs::write(&s.token, "test-token-123456").unwrap();
    (s, transport, daemon, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simulator_screenshot_click_wait_find_text_end_to_end() {
    let (mut s, t, _d, task) = harness(vec![], true).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move||{
        init(&mut s);let c=AtomicBool::new(false);
        for (i,name,args) in [(1,"screenshot",json!({})),(2,"click",json!({"x":160,"y":120,"uncalibrated":true})),(3,"wait_for_stable",json!({"timeout_ms":1000})),(4,"find_text",json!({"query":"safe"}))]{
            let response=s.dispatch(json!({"jsonrpc":"2.0","id":i,"method":"tools/call","params":{"name":name,"arguments":args}}),&c).unwrap();
            assert_eq!(response["result"]["isError"],false,"{response}");
            if name=="click"{let result=&response["result"]["structuredContent"];assert_eq!(result["uncalibrated"],true);assert_eq!(result["command"]["outcome"],"EMITTED");
                assert_eq!(t.execution_count(uuid::Uuid::parse_str(result["command"]["command_id"].as_str().unwrap()).unwrap()),1);assert!(!t.is_remotely_armed());}
        }
        assert!(s.call("click",&json!({"x":1,"y":2}),&c).unwrap_err()["code"]=="pointer.calibration_required");
    }).await.unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capability_refuses_before_arm_and_unknown_never_replays() {
    let (mut s, t, _, task) = harness(vec![], false).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move || {
        let c = AtomicBool::new(false);
        s.call("screenshot", &json!({}), &c).unwrap();
        assert_eq!(
            s.call("click", &json!({"x":1,"y":2,"uncalibrated":true}), &c)
                .unwrap_err()["code"],
            "pointer.capability_required"
        );
        assert_eq!(t.control_request_counts(), (0, 0, 0));
        assert_eq!(
            s.call("key", &json!({"keys":["CMD","A"]}), &c).unwrap()["structuredContent"]
                ["outcome"],
            "EMITTED"
        );
    })
    .await
    .unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
    let (mut s, t, _, task) = harness(vec![SimulationFault::LostAfterStart], true).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move || {
        let c = AtomicBool::new(false);
        s.call("screenshot", &json!({}), &c).unwrap();
        let e = s
            .call("click", &json!({"x":1,"y":2,"uncalibrated":true}), &c)
            .unwrap_err();
        assert_eq!(e["command"]["outcome"], "UNKNOWN");
        let id = uuid::Uuid::parse_str(e["command"]["command_id"].as_str().unwrap()).unwrap();
        assert_eq!(t.execution_count(id), 1);
    })
    .await
    .unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn calibrated_simulator_binding_and_all_actions() {
    let (mut s, transport, _, task) = harness(vec![], true).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move || {
        let c = AtomicBool::new(false);
        let result = s.calibrate(&c).unwrap();
        assert_eq!(result["bound"], true);
        let probes = result["probes"].as_array().unwrap();
        assert_eq!(probes.len(), 10);
        for probe in probes {
            let id =
                uuid::Uuid::parse_str(probe["command"]["command_id"].as_str().unwrap()).unwrap();
            assert_eq!(transport.execution_count(id), 1);
        }
        let g = s.geometry.as_ref().unwrap();
        assert!((g.origin[0] - 20.0).abs() < 1.0);
        assert!((g.extent[1] - 180.0).abs() < 1.0);
        assert!(geometry::load(&s.root, SIMULATOR_DEVICE_ID, "fake-hdmi")
            .unwrap()
            .is_some());
        s.call("screenshot", &json!({}), &c).unwrap();
        for (name, args) in [
            ("move", json!({"x":160,"y":120})),
            (
                "click",
                json!({"x":160,"y":120,"button":"middle","double":true}),
            ),
            (
                "drag",
                json!({"from_x":100,"from_y":80,"to_x":200,"to_y":170}),
            ),
            ("scroll", json!({"x":160,"y":120,"dx":3,"dy":-3})),
            ("type_text", json!({"text":"ordinary ascii\n"})),
            ("key", json!({"keys":["OPTION","A"]})),
        ] {
            let result = s.call(name, &args, &c).unwrap();
            assert_eq!(result["isError"], false);
            assert!(!transport.is_remotely_armed());
        }
        assert_eq!(
            s.call("move", &json!({"x":0,"y":0}), &c).unwrap_err()["code"],
            "pointer.outside_active_video"
        );
        assert!(s
            .call("key", &json!({"keys":["UNSUPPORTED_KEY"]}), &c)
            .is_err());
    })
    .await
    .unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_animated_capture_calibrates_and_settles_every_mcp_action() {
    let (mut s, transport, _, task) = harness(vec![], true).await;
    let root = s.root.clone();
    s.frames.delay = Duration::from_millis(1500);
    s.frames.animate = true;
    tokio::task::spawn_blocking(move || {
        init(&mut s);
        let c = AtomicBool::new(false);
        let calibration = s.dispatch(json!({"jsonrpc":"2.0","id":"calibration","method":"tools/call","params":{"name":"calibrate","arguments":{}}}), &c).unwrap();
        assert_eq!(calibration["result"]["isError"], false, "{calibration}");
        let calibrated = &calibration["result"]["structuredContent"];
        assert_eq!(calibrated["bound"], true);
        assert!(calibrated["latency_ms"].as_u64().unwrap() >= 1400);
        assert!((s.geometry.as_ref().unwrap().origin[0] - 20.0).abs() < 1.0);
        assert!((s.geometry.as_ref().unwrap().extent[1] - 180.0).abs() < 1.0);
        let persisted = geometry::load(&s.root, SIMULATOR_DEVICE_ID, "fake-hdmi").unwrap().unwrap();
        let record = serde_json::to_value(persisted).unwrap();
        assert_eq!(record.as_object().unwrap().len(), 7);
        assert!(record.get("latency_ms").is_none());
        s.call("screenshot", &json!({}), &c).unwrap();
        for (name, arguments) in [
            ("move", json!({"x":150,"y":110})),
            ("click", json!({"x":180,"y":130})),
            ("drag", json!({"from_x":100,"from_y":80,"to_x":220,"to_y":170})),
            ("scroll", json!({"x":160,"y":120,"dx":1,"dy":-1})),
            ("key", json!({"keys":["OPTION","A"]})),
            ("type_text", json!({"text":"ordinary ascii"})),
        ] {
            let start = Instant::now();
            let response = s.dispatch(json!({"jsonrpc":"2.0","id":name,"method":"tools/call","params":{"name":name,"arguments":arguments}}), &c).unwrap();
            assert_eq!(response["result"]["isError"], false, "{response}");
            let result = &response["result"]["structuredContent"];
            assert_eq!(result["settled"], true, "{name}: {result}");
            let latency = result["latency_ms"].as_u64().unwrap();
            assert!((1400..=2600).contains(&latency), "{name}: {latency}");
            assert!(start.elapsed() >= Duration::from_millis(1400));
            assert_eq!(response["result"]["content"][0]["type"], "image");
            let command = if result.get("command").is_some() { &result["command"] } else { result };
            assert_eq!(command["outcome"], "EMITTED");
            let id = uuid::Uuid::parse_str(command["command_id"].as_str().unwrap()).unwrap();
            assert_eq!(transport.execution_count(id), 1);
            assert!(!transport.is_remotely_armed());
            let shot = s.call("screenshot", &json!({}), &c).unwrap();
            assert!(shot["structuredContent"]["frame_id"].as_u64().unwrap() >= result["frame_id"].as_u64().unwrap());
            let visible = &s.frames.visible;
            let requested = s.frames.pointer.as_ref().unwrap().lock().unwrap();
            assert_eq!(visible.pointer, requested.pointer);
            assert_eq!(visible.revision, requested.revision);
        }
    }).await.unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn animated_capture_without_cursor_response_times_out_without_binding_or_replay() {
    let (mut s, transport, _, task) = harness(vec![], true).await;
    let root = s.root.clone();
    s.frames.never_change = true;
    s.frames.animate = true;
    tokio::task::spawn_blocking(move || {
        init(&mut s);
        let c = AtomicBool::new(false);
        s.call("screenshot", &json!({}), &c).unwrap();
        let start = Instant::now();
        let response = s.dispatch(json!({"jsonrpc":"2.0","id":"move","method":"tools/call","params":{"name":"move","arguments":{"x":100,"y":150,"uncalibrated":true}}}), &c).unwrap();
        assert_eq!(response["result"]["isError"], false, "{response}");
        let result = &response["result"]["structuredContent"];
        assert_eq!(result["settled"], false);
        assert!(result["latency_ms"].as_u64().unwrap() >= 2900);
        assert!(result["frame_id"].as_u64().is_some());
        assert!(start.elapsed() < Duration::from_secs(6));
        let id = uuid::Uuid::parse_str(result["command"]["command_id"].as_str().unwrap()).unwrap();
        assert_eq!(transport.execution_count(id), 1);
        let start = Instant::now();
        let response = s.dispatch(json!({"jsonrpc":"2.0","id":"calibration","method":"tools/call","params":{"name":"calibrate","arguments":{}}}), &c).unwrap();
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(response["result"]["structuredContent"]["error"]["code"], "calibration.cursor_not_seen");
        assert!(start.elapsed() >= Duration::from_secs(3));
        assert!(start.elapsed() < Duration::from_secs(6));
        assert!(s.geometry.is_none() && s.bound_generation.is_none());
        assert!(geometry::load(&s.root, SIMULATOR_DEVICE_ID, "fake-hdmi").unwrap().is_none());
        assert!(!transport.is_remotely_armed());
    }).await.unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
#[ignore = "local Windows OCR language-pack smoke; uses explicit synthetic image path"]
fn windows_native_ocr_synthetic_smoke() {
    let path = std::env::var("KEYFERRY_OCR_SMOKE_PNG").unwrap();
    let decoder = png::Decoder::new(io::BufReader::new(fs::File::open(path).unwrap()));
    let mut reader = decoder.read_info().unwrap();
    let mut rgb = vec![0; reader.output_buffer_size().unwrap()];
    let output = reader.next_frame(&mut rgb).unwrap();
    assert_eq!(output.color_type, png::ColorType::Rgb);
    rgb.truncate(output.buffer_size());
    let f = Frame {
        width: output.width,
        height: output.height,
        native: (output.width, output.height),
        rgb,
        serial: 1,
        generation: 1,
        at: Instant::now(),
    };
    let result = NativeOcr.recognize(&f).unwrap();
    assert!(result
        .iter()
        .any(|b| b.text.to_lowercase().contains("keyferry test")));
}

#[test]
fn no_argument_options_and_unselected_action_errors_are_clear() {
    assert_eq!(options(&[]).unwrap(), (None, None));
    assert_eq!(
        options(&["--source".into(), "HDMI".into()]).unwrap(),
        (None, Some("HDMI".into()))
    );
    assert!(options(&["--device".into(), "invalid".into()]).is_err());
    let mut s = server();
    s.device.clear();
    init(&mut s);
    // Absent daemon/token is visible; it never becomes permission to pick a device.
    let status = s
        .call("status", &json!({}), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(status["structuredContent"]["selected_device"], Value::Null);
    for name in ["type_text", "key", "click", "calibrate"] {
        let e = s
            .call(
                name,
                &json!({"text":"PRIVATE","keys":["A"],"x":1,"y":2}),
                &AtomicBool::new(false),
            )
            .unwrap_err();
        assert!(!e.to_string().contains("PRIVATE"));
    }
    let listed = tools();
    for name in [
        "list_devices",
        "select_device",
        "list_capture_sources",
        "select_capture_source",
    ] {
        assert!(listed.iter().any(|t| t["name"] == name));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_status_and_selection_use_the_production_device_inventory() {
    let (mut server, _, _, task) = harness(vec![], true).await;
    tokio::task::spawn_blocking(move || {
        server.device.clear();
        server.device_choice = "unselected";
        let c = AtomicBool::new(false);
        let status = server.call("status", &json!({}), &c).unwrap();
        assert_eq!(
            status["structuredContent"]["selected_device"],
            SIMULATOR_DEVICE_ID
        );
        assert_eq!(
            status["structuredContent"]["device_selection"],
            "automatic-single"
        );
        let listed = server.call("list_devices", &json!({}), &c).unwrap();
        assert_eq!(
            listed["structuredContent"]["devices"][0]["id"],
            SIMULATOR_DEVICE_ID
        );
        let selected = server
            .call("select_device", &json!({"device":SIMULATOR_DEVICE_ID}), &c)
            .unwrap();
        assert_eq!(selected["structuredContent"]["selection"], "selected");
        assert!(server
            .call(
                "select_device",
                &json!({"device":"00000000-0000-0000-0000-000000000000"}),
                &c
            )
            .is_err());
        std::fs::remove_dir_all(&server.root).unwrap();
    })
    .await
    .unwrap();
    task.abort();
}

fn routine_definition(steps: Value) -> Value {
    json!({"schema":"keyferry.recipe.v1","name":"test-flow","target_os":"any","verified":false,"steps":steps})
}
fn bind_fake(s: &mut Server<FakeFrames, FakeOcr>) {
    let f = frame(320, 240, 1);
    s.geometry = Some(
        geometry::fit(
            &s.device,
            "fake-hdmi",
            &f,
            &[
                ([0.1, 0.1], [48.0, 48.0]),
                ([0.8, 0.2], [244.0, 66.0]),
                ([0.2, 0.8], [76.0, 174.0]),
                ([0.8, 0.7], [244.0, 156.0]),
            ],
        )
        .unwrap(),
    );
    s.loaded = true;
    s.bound_generation = Some(1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routine_checkpoints_split_stretches_and_stop_without_replay() {
    for failed in [false, true] {
        let (mut s, transport, _, task) = harness(vec![], false).await;
        let root = s.root.clone();
        tokio::task::spawn_blocking(move|| {
            s.library=super::super::recipe::Library{local:s.root.join("local"),shared:Some(s.root.join("shared"))};
            init(&mut s);let cancelled=AtomicBool::new(false);
            let definition=routine_definition(json!([
                {"type":"key","keys":["ESCAPE"]},
                {"type":"type_text","text":"ordinary-canary-text"},
                {"type":"expect_text","query":if failed {"absent"} else {"Safe test target"},"timeout_ms":120},
                {"type":"key","keys":["TAB"]},
                {"type":"key","keys":["ENTER"]}
            ]));
            let saved=s.call("routine_save",&json!({"definition":definition}),&cancelled).unwrap();
            assert_eq!(saved["isError"],false);
            let result=s.dispatch(json!({"jsonrpc":"2.0","id":"run-flow","method":"tools/call","params":{"name":"routine_run","arguments":{"name":"test-flow"}}}),&cancelled).unwrap();
            let result=&result["result"];let content=&result["structuredContent"];
            assert_eq!(result["isError"],failed,"{content}");
            assert_eq!(content["command_count"],if failed {1} else {2});
            assert_eq!(content["actions"].as_array().unwrap().len(),if failed {3} else {5});
            assert_eq!(content["actions"][0]["command"]["command_id"],content["actions"][1]["command"]["command_id"]);
            if failed {assert_eq!(content["stopped_at"],2);} else {
                assert_ne!(content["actions"][1]["command"]["command_id"],content["actions"][3]["command"]["command_id"]);
                assert_eq!(content["actions"][3]["command"]["command_id"],content["actions"][4]["command"]["command_id"]);
            }
            for action in content["actions"].as_array().unwrap() {
                if let Some(id)=action["command"]["command_id"].as_str() {assert_eq!(transport.execution_count(uuid::Uuid::parse_str(id).unwrap()),1);}
            }
            assert!(!content.to_string().contains("ordinary-canary-text"));
            assert_eq!(result["content"].as_array().unwrap().iter().filter(|c|c["type"]=="image").count(),1);
            let files=fs::read_dir(s.library.shared.unwrap()).unwrap().count();assert_eq!(files,1,"run writes no state");
        }).await.unwrap();
        task.abort();
        fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routine_ocr_click_maps_center_and_requires_unique_match() {
    let (mut s, transport, _, task) = harness(vec![], true).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move||{
        let cancelled=AtomicBool::new(false);bind_fake(&mut s);
        let definition=routine_definition(json!([
            {"type":"click_text","query":"Safe test target","timeout_ms":100},
            {"type":"expect_text","query":"Safe test target","timeout_ms":100,"region":{"x":20,"y":20,"width":150,"height":40}}
        ]));
        let recipe=recipes::parse(definition.to_string().as_bytes()).unwrap();
        let result=s.run_routine(&recipe,&json!({}),false,false,&cancelled).unwrap();
        assert_eq!(result["isError"],false);let result=&result["structuredContent"];
        assert_eq!(result["actions"][0]["receipt"]["check"]["match_count"],1);
        let visual=s.frames.pointer.as_ref().unwrap().lock().unwrap();
        assert!((visual.pointer[0]-(96.0-20.0)/280.0).abs()<0.001);
        assert!((visual.pointer[1]-(34.0-30.0)/180.0).abs()<0.001);
        drop(visual);
        let id=uuid::Uuid::parse_str(result["actions"][0]["receipt"]["command"]["command_id"].as_str().unwrap()).unwrap();
        assert_eq!(transport.execution_count(id),1);
        let before=transport.control_request_counts();
        let ambiguous=routine_definition(json!([{ "type":"click_text","query":"a","timeout_ms":100}]));
        let recipe=recipes::parse(ambiguous.to_string().as_bytes()).unwrap();
        let result=s.run_routine(&recipe,&json!({}),false,false,&cancelled).unwrap();
        assert_eq!(result["isError"],true);
        assert_eq!(result["structuredContent"]["actions"][0]["error"]["code"],"recipe.text_not_unique");
        assert_eq!(transport.control_request_counts(),before);
    }).await.unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_repeat_uses_one_command_and_rejects_bounds_before_input() {
    let (mut s, transport, _, task) = harness(vec![], false).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move||{
        init(&mut s);let c=AtomicBool::new(false);
        let response=s.dispatch(json!({"jsonrpc":"2.0","id":"repeat","method":"tools/call","params":{"name":"batch","arguments":{"actions":[{"tool":"key","arguments":{"keys":["ESCAPE"]},"repeat":10,"delay_ms":5}],"settle":false}}}),&c).unwrap();
        let result=&response["result"]["structuredContent"];assert_eq!(response["result"]["isError"],false,"{result}");
        assert_eq!(result["command_count"],1);assert_eq!(result["actions"].as_array().unwrap().len(),1);
        let id=uuid::Uuid::parse_str(result["actions"][0]["command"]["command_id"].as_str().unwrap()).unwrap();assert_eq!(transport.execution_count(id),1);
        let before=transport.control_request_counts();
        for (i,args) in [
            json!({"actions":[{"tool":"key","arguments":{"keys":["ESCAPE"]},"repeat":1001}],"settle":false}),
            json!({"actions":[{"tool":"key","arguments":{"keys":["ESCAPE"]},"repeat":1000,"delay_ms":800}],"settle":false})
        ].into_iter().enumerate() {
            let response=s.dispatch(json!({"jsonrpc":"2.0","id":format!("bad-{i}"),"method":"tools/call","params":{"name":"batch","arguments":args}}),&c).unwrap();
            assert_eq!(response["result"]["isError"],true);
        }
        assert_eq!(transport.control_request_counts(),before);
    }).await.unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn secure_request_requires_owner_completion_and_never_exposes_values() {
    let mut s = server();
    s.secure_prompt = |_, _, _| Ok(json!({"outcome":"REQUESTED","input_sent":false}));
    let definition = routine_definition(json!([
        {"type":"secure_text"},
        {"type":"expect_text","query":"{marker}","optional":true,"timeout_ms":100},
        {"type":"key","keys":["ENTER"]}
    ]));
    let mut definition = definition;
    definition["parameters"] =
        json!([{"name":"marker","type":"text","max_chars":100,"optional":true}]);
    let recipe = recipes::parse(definition.to_string().as_bytes()).unwrap();
    let result = s
        .run_routine(&recipe, &json!({}), false, false, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(
        result["structuredContent"]["actions"][0]["receipt"]["outcome"],
        "REQUESTED"
    );
    assert_eq!(result["structuredContent"]["awaiting_owner"], true);
    assert_eq!(result["structuredContent"]["stopped_at"], 2);
    assert_eq!(result["structuredContent"]["command_count"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routine_change_uses_pre_input_baseline_and_stable_requires_fresh_frames() {
    let (mut s, _, _, task) = harness(vec![], false).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move || {
        s.frames.change_after = Some(3);
        let definition = routine_definition(json!([
            {"type":"key","keys":["ESCAPE"]},
            {"type":"wait_for_change","timeout_ms":500},
            {"type":"wait_for_stable","timeout_ms":600},
            {"type":"key","keys":["TAB"]}
        ]));
        let recipe = recipes::parse(definition.to_string().as_bytes()).unwrap();
        let result = s
            .run_routine(&recipe, &json!({}), false, false, &AtomicBool::new(false))
            .unwrap();
        let content = &result["structuredContent"];
        assert_eq!(result["isError"], false, "{content}");
        assert_eq!(content["actions"][1]["receipt"]["matched"], true);
        assert_eq!(content["actions"][2]["receipt"]["matched"], true);
        assert_eq!(content["command_count"], 2);
    })
    .await
    .unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn text_checkpoint_requests_capture_ocr_on_every_poll() {
    let (mut s, _, _, task) = harness(vec![], true).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move || {
        let cancelled = AtomicBool::new(false);
        bind_fake(&mut s);
        let definition = routine_definition(json!([
            {"type":"expect_text","query":"appears later","timeout_ms":300}
        ]));
        let recipe = recipes::parse(definition.to_string().as_bytes()).unwrap();
        let result = s
            .run_routine(&recipe, &json!({}), false, false, &cancelled)
            .unwrap();
        assert_eq!(result["isError"], true);
        assert!(s.frames.ocr_polls >= 2, "polls {}", s.frames.ocr_polls);
    })
    .await
    .unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}
