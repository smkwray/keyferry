include!("../../../apps/keyctl/src/mcp_test_support.rs");
use keyferryd::{
    Daemon, MemoryTokenStore, SimulationFault, SimulatorTransport, SIMULATOR_DEVICE_ID,
};
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
            let response=s.dispatch(json!({"jsonrpc":"2.0","id":format!("move-{i}"),"method":"tools/call","params":{"name":"move","arguments":{"x":x,"y":y,"return_screenshot":true,"format":"jpeg"}}}),&c).unwrap();
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
        let clicked = s.call("click", &json!({"x":100,"y":150,"return_screenshot":true,"format":"png"}), &c).unwrap();
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
            let response=s.dispatch(json!({"jsonrpc":"2.0","id":"batch","method":"tools/call","params":{"name":"batch","arguments":{"return_screenshot":true,"actions":[{"tool":"move","arguments":{"x":100,"y":130,"uncalibrated":true}},{"tool":"move","arguments":{"x":200,"y":160,"uncalibrated":true}}]}}}),&c).unwrap();
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

/// The simulated target cursor's starting position, deliberately off the screen centre.
const START: [f64; 2] = [0.3, 0.65];
/// A fake target whose pointer spans the whole frame, as absolute reports span the target
/// display: the motion-free video-area mapping then locates an observed cursor tip exactly.
const FULL_AREA: [f64; 4] = [0.0, 0.0, 319.0, 239.0];

/// The agent's production seed: a fresh screenshot, then calibrate with the cursor tip it shows.
fn seed(s: &mut Server<FakeFrames, FakeOcr>, mode: &str, c: &AtomicBool) -> Result<Value, Value> {
    s.call("screenshot", &json!({}), c)?;
    let (x, y) = tip(s.frames.area, s.frames.visible.pointer);
    s.call(
        "calibrate",
        &json!({"mode":mode,"cursor_x":x,"cursor_y":y}),
        c,
    )
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
        pointer: START,
        revision: 0,
        at: Instant::now(),
        path: Vec::new(),
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
                            let at = [action["x"].as_f64().unwrap(), action["y"].as_f64().unwrap()];
                            let mut visual = observed.lock().unwrap();
                            visual.pointer = at;
                            visual.path.push(at);
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
    s.frames.visible.pointer = START;
    s.url = format!("http://127.0.0.1:{port}");
    fs::create_dir_all(&s.root).unwrap();
    s.token = s.root.join("token");
    fs::write(&s.token, "test-token-123456").unwrap();
    // This agent has already seen the starting cursor on its leased stick; the production seed
    // (calibrate with cursor_x/cursor_y) is exercised by the fresh-session and switch tests.
    s.lease(SIMULATOR_DEVICE_ID).unwrap();
    s.pointer = Some(START);
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
        let error = s.call("key", &json!({"keys":["enter"]}), &c).unwrap_err();
        assert_eq!(error["code"], "key.unknown");
        assert!(error["message"].as_str().unwrap().contains("keyctl keys"));
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
        let result = s.calibrate(&json!({}), &c).unwrap();
        assert_eq!(result["bound"], true);
        let probes = result["probes"].as_array().unwrap();
        assert_eq!(probes.len(), 10);
        for probe in probes {
            let id =
                uuid::Uuid::parse_str(probe["command"]["command_id"].as_str().unwrap()).unwrap();
            assert_eq!(transport.execution_count(id), 1);
        }
        // Cursor evidence is fitted on native 2x frames, then bound to the agent view.
        assert_eq!(result["calibration_frame"], json!([640, 480]));
        assert!(s.frames.native_polls >= 10 && !s.frames.native);
        let g = s.geometry.as_ref().unwrap();
        assert_eq!((g.screenshot, g.native), ((320, 240), (640, 480)));
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
            assert_eq!(response["result"]["content"][0]["type"], "text");
            assert_eq!(response["result"]["content"].as_array().unwrap().len(), 1);
            assert!(result.get("image_bytes").is_none());
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
async fn routine_and_batch_images_require_explicit_opt_in() {
    let (mut s, transport, _, task) = harness(vec![], false).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move || {
        s.library = super::super::recipe::Library {
            local: s.root.join("local"),
            shared: Some(s.root.join("shared")),
        };
        init(&mut s);
        let cancelled = AtomicBool::new(false);
        let definition = routine_definition(json!([{"type":"key","keys":["ESCAPE"]}]));
        assert_eq!(
            s.call("routine_save", &json!({"definition":definition}), &cancelled)
                .unwrap()["isError"],
            false
        );
        for (i, setting) in [None, Some(false), Some(true)].into_iter().enumerate() {
            for name in ["routine_run", "batch"] {
                let mut args = if name == "routine_run" {
                    json!({"name":"test-flow"})
                } else {
                    json!({"actions":[{"tool":"key","arguments":{"keys":["ESCAPE"]}}],"settle":false})
                };
                if let Some(setting) = setting {
                    args["return_screenshot"] = json!(setting);
                }
                let response = s
                    .dispatch(
                        json!({"jsonrpc":"2.0","id":format!("{name}-{i}"),"method":"tools/call","params":{"name":name,"arguments":args}}),
                        &cancelled,
                    )
                    .unwrap();
                let result = &response["result"];
                let metadata = &result["structuredContent"];
                assert_eq!(result["isError"], false, "{name}: {metadata}");
                assert_eq!(metadata["execution_complete"], true);
                assert_eq!(metadata["command_count"], 1);
                let images = result["content"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|content| content["type"] == "image")
                    .count();
                assert_eq!(images, usize::from(setting == Some(true)), "{name}");
                if setting == Some(true) {
                    assert_eq!(result["content"][0]["mimeType"], "image/jpeg");
                    assert!(metadata["image_bytes"].as_u64().unwrap() > 0);
                } else {
                    assert!(metadata.get("image_bytes").is_none());
                    assert_eq!(result["content"].as_array().unwrap().len(), 1);
                }
                let command = &metadata["actions"][0]["command"];
                assert_eq!(command["outcome"], "EMITTED");
                let id = uuid::Uuid::parse_str(command["command_id"].as_str().unwrap()).unwrap();
                assert_eq!(transport.execution_count(id), 1);
            }
        }
    })
    .await
    .unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
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
            assert_eq!(result["content"].as_array().unwrap().iter().filter(|c|c["type"]=="image").count(),0);
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

/// Largest distance between consecutive requested reports, from the session's start position.
fn largest_jump(path: &[[f64; 2]]) -> f64 {
    path.windows(2)
        .map(|w| (w[1][0] - w[0][0]).hypot(w[1][1] - w[0][1]))
        .fold(0.0, f64::max)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_agent_pointer_motion_glides_including_calibration_and_split_batches() {
    let (mut s, transport, _, task) = harness(vec![], true).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move || {
        init(&mut s);
        let c = AtomicBool::new(false);
        let calibration = s.call("calibrate", &json!({}), &c).unwrap();
        assert_eq!(calibration["structuredContent"]["bound"], true);
        let probes = s.frames.pointer.as_ref().unwrap().lock().unwrap().path.len();
        assert!(probes > 10 * 12, "every probe glides: {probes} reports");
        s.call("screenshot", &json!({}), &c).unwrap();
        for (name, args) in [
            ("move", json!({"x":150,"y":110})),
            ("click", json!({"x":280,"y":200,"button":"right"})),
            ("click", json!({"x":60,"y":200,"double":true})),
            ("drag", json!({"from_x":280,"from_y":60,"to_x":60,"to_y":200})),
            ("scroll", json!({"x":280,"y":200,"dx":0,"dy":-2})),
        ] {
            let result = s.call(name, &args, &c).unwrap();
            assert_eq!(result["isError"], false, "{name}: {result}");
            assert_eq!(result["structuredContent"]["settled"], true, "{name}");
        }
        // Far-apart clicks overflow one input sequence; they split, still gliding throughout.
        let actions: Vec<Value> = (0..16)
            .map(|i| json!({"tool":"click","arguments":{"x":if i % 2 == 0 {40} else {290},"y":40 + 10 * i}}))
            .collect();
        let response = s
            .call("batch", &json!({"actions":actions,"settle":false,"return_screenshot":false}), &c)
            .unwrap();
        let result = &response["structuredContent"];
        assert_eq!(response["isError"], false, "{result}");
        assert!(result["command_count"].as_u64().unwrap() > 1, "{result}");
        let receipts = result["actions"].as_array().unwrap();
        assert_eq!(receipts.len(), 16);
        for receipt in receipts {
            assert_eq!(receipt["command"]["outcome"], "EMITTED");
            let id = uuid::Uuid::parse_str(receipt["command"]["command_id"].as_str().unwrap())
                .unwrap();
            assert_eq!(transport.execution_count(id), 1);
        }
        let visual = s.frames.pointer.as_ref().unwrap().lock().unwrap();
        // The session's first report continues from where the target cursor started.
        let jump = largest_jump(&[&[START][..], &visual.path[..]].concat());
        assert!(jump < 0.12, "largest step {jump}");
        assert!(s.pointer.unwrap().into_iter().zip(*visual.path.last().unwrap()).all(|(a,b)| (a-b).abs() < 1e-12));
        assert!(!transport.is_remotely_armed());
    })
    .await
    .unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

/// Calibration ends on its first probe point; the next calibration must still see the cursor move.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn back_to_back_calibrations_bind_and_still_glide() {
    let (mut s, _, _, task) = harness(vec![], true).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move || {
        init(&mut s);
        let c = AtomicBool::new(false);
        for round in 0..2 {
            let calibration = s.call("calibrate", &json!({}), &c);
            assert!(calibration.is_ok(), "round {round}: {calibration:?}");
            assert_eq!(calibration.unwrap()["structuredContent"]["bound"], true);
        }
        let visual = s.frames.pointer.as_ref().unwrap().lock().unwrap();
        let jump = largest_jump(&visual.path);
        assert!(jump < 0.12, "largest step {jump}");
    })
    .await
    .unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn faulted_glides_never_replay_and_track_only_possible_starts() {
    for fault in [
        SimulationFault::LostAfterStart,
        SimulationFault::BeforeAccept,
    ] {
        let (mut s, transport, _, task) = harness(vec![fault], true).await;
        let root = s.root.clone();
        tokio::task::spawn_blocking(move || {
            let c = AtomicBool::new(false);
            s.call("screenshot", &json!({}), &c).unwrap();
            let error = s
                .call(
                    "drag",
                    &json!({"from_x":40,"from_y":40,"to_x":290,"to_y":200,"uncalibrated":true}),
                    &c,
                )
                .unwrap_err();
            assert_eq!(error["code"], "command.failed_or_unknown", "{error}");
            if let Some(id) = error["command"]["command_id"].as_str() {
                assert!(transport.execution_count(uuid::Uuid::parse_str(id).unwrap()) <= 1);
            }
            assert!(!transport.is_remotely_armed());
            let path = s
                .frames
                .pointer
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .path
                .clone();
            if fault == SimulationFault::LostAfterStart {
                // An interrupted glide stops on the segment toward its end; presume the end.
                assert_eq!(error["command"]["outcome"], "UNKNOWN");
                assert!(s
                    .pointer
                    .unwrap()
                    .into_iter()
                    .zip(*path.last().unwrap())
                    .all(|(a, b)| (a - b).abs() < 1e-12));
            } else {
                assert_eq!(
                    s.pointer,
                    Some(START),
                    "a command that never started moves nothing"
                );
            }
        })
        .await
        .unwrap();
        task.abort();
        fs::remove_dir_all(root).unwrap();
    }
}

/// The presumed pointer lives only in session memory: same-session glides stay continuous, no
/// file holds a coordinate, and a new session knows nothing of the previous one's position.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pointer_presumption_is_session_memory_only() {
    let (mut s, transport, _, task) = harness(vec![], true).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move || {
        let root = s.root.clone();
        init(&mut s);
        let c = AtomicBool::new(false);
        let calibration = s.call("calibrate", &json!({}), &c).unwrap();
        assert_eq!(calibration["structuredContent"]["bound"], true);
        s.call("screenshot", &json!({}), &c).unwrap();
        for (x, y) in [(60, 60), (280, 200), (60, 200)] {
            let moved = s.call("move", &json!({"x":x,"y":y}), &c).unwrap();
            assert_eq!(moved["isError"], false, "{moved}");
        }
        let visual = s.frames.pointer.clone().unwrap();
        let path = visual.lock().unwrap().path.clone();
        let jump = largest_jump(&[&[START][..], &path[..]].concat());
        assert!(jump < 0.12, "largest step {jump}");
        let last = path.last().copied();
        assert!(s.pointer.unwrap().into_iter().zip(last.unwrap()).all(|(a,b)| (a-b).abs() < 1e-12));
        // Leases, token and the coordinate-free geometry record only; no pointer state.
        let coordinates = json!(last.unwrap()).to_string();
        let mut dirs = vec![root.clone()];
        while let Some(dir) = dirs.pop() {
            for entry in fs::read_dir(dir).unwrap() {
                let file = entry.unwrap().path();
                if file.is_dir() {
                    dirs.push(file);
                    continue;
                }
                let name = file.file_name().unwrap().to_string_lossy().into_owned();
                assert!(!name.contains("pointer"), "{name}");
                let content = fs::read_to_string(&file).unwrap_or_default();
                assert!(!content.contains(&coordinates), "{name}");
            }
        }
        // A new session on the same controller and stick starts with no presumed position.
        let mut next = server();
        (next.root, next.url, next.token) = (root.clone(), s.url.clone(), s.token.clone());
        next.frames.pointer = Some(visual.clone());
        next.frames.area = FULL_AREA;
        drop(s);
        init(&mut next);
        assert_eq!(next.pointer, None);
        let status = next.call("status", &json!({}), &c).unwrap();
        assert_eq!(status["structuredContent"]["pointer_position_known"], false);
        let input = || {
            let v = visual.lock().unwrap();
            (v.path.len(), v.revision, transport.control_request_counts())
        };
        let sent = input();
        let saved = serde_json::to_value(geometry::load(&root, SIMULATOR_DEVICE_ID, "fake-hdmi").unwrap()).unwrap();
        let refuse = |next: &mut Server<FakeFrames, FakeOcr>, name: &str, args: Value, code: &str| {
            let error = next.call(name, &args, &c).unwrap_err();
            assert_eq!(error["code"], code, "{name} {args}");
            assert_eq!(next.pointer, None, "{name} {args}");
            assert_eq!(input(), sent, "{name} {args} sent input");
        };
        // Nothing moves, not even a calibration probe, before a valid observed seed.
        let (x, y) = tip(FULL_AREA, visual.lock().unwrap().pointer);
        refuse(&mut next, "calibrate", json!({"mode":"screen","cursor_x":x,"cursor_y":y}), "pointer.screenshot_required");
        next.call("screenshot", &json!({}), &c).unwrap();
        refuse(&mut next, "move", json!({"x":100,"y":120,"uncalibrated":true}), "pointer.position_required");
        refuse(&mut next, "calibrate", json!({}), "pointer.position_required");
        refuse(
            &mut next,
            "batch",
            json!({"actions":[{"tool":"key","arguments":{"keys":["SHIFT"]}},{"tool":"click","arguments":{"x":100,"y":120,"uncalibrated":true}}]}),
            "pointer.position_required",
        );
        refuse(&mut next, "calibrate", json!({"cursor_x":x}), "pointer.cursor_pair_required");
        refuse(&mut next, "calibrate", json!({"mode":"screen","cursor_x":400,"cursor_y":y}), "pointer.outside_active_video");
        let unchanged = serde_json::to_value(geometry::load(&root, SIMULATOR_DEVICE_ID, "fake-hdmi").unwrap()).unwrap();
        assert_eq!(unchanged, saved, "a refused seed persists nothing");
        // Screen-only binding moves nothing and leaves the position unknown.
        let bound = next.call("calibrate", &json!({"mode":"screen"}), &c).unwrap();
        assert_eq!(bound["structuredContent"]["bound"], true, "{bound}");
        assert_eq!(bound["structuredContent"]["pointer_position_known"], false);
        refuse(&mut next, "move", json!({"x":100,"y":120}), "pointer.position_required");
        // Seeded from the observed tip, probes and the next move glide on from the real cursor.
        let start = visual.lock().unwrap().pointer;
        assert!((start[0] - 0.5).hypot(start[1] - 0.5) > 0.2, "off-centre start {start:?}");
        let seeded = seed(&mut next, "probe", &c).unwrap();
        assert_eq!(seeded["structuredContent"]["bound"], true, "{seeded}");
        let status = next.call("status", &json!({}), &c).unwrap();
        assert_eq!(status["structuredContent"]["pointer_position_known"], true);
        next.call("screenshot", &json!({}), &c).unwrap();
        let moved = next
            .call("move", &json!({"x":100,"y":120,"uncalibrated":true}), &c)
            .unwrap();
        assert_eq!(moved["isError"], false, "{moved}");
        let path = visual.lock().unwrap().path.clone();
        assert!(path.len() > sent.0 + 10 * 12, "every probe glides");
        let jump = largest_jump(&[&[start][..], &path[sent.0..]].concat());
        assert!(jump < 0.12, "largest step {jump}");
        assert!(next.pointer.unwrap().into_iter().zip(*path.last().unwrap()).all(|(a,b)| (a-b).abs() < 1e-12));
    })
    .await
    .unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

/// Capture restarts invalidate cursor state even without a verified binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unbound_capture_restart_forgets_the_observed_cursor_before_input() {
    let (mut s, transport, _, task) = harness(vec![], true).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move || {
        init(&mut s);
        let c = AtomicBool::new(false);
        seed(&mut s, "screen", &c).unwrap();
        assert!(s.pointer.is_some());
        // A failed probe may leave an observed position but no verified binding.
        s.bound_generation = None;
        s.geometry = None;
        let mut restarted = frame(320, 240, s.frames.next + 1);
        restarted.generation = 2;
        s.frames.scripted.push_back(restarted.clone());
        s.frames.scripted.push_back(restarted);
        let sent = transport.control_request_counts();
        s.call("screenshot", &json!({}), &c).unwrap();
        assert!(s.pointer.is_none());
        let refused = s
            .call("move", &json!({"x":100,"y":120,"uncalibrated":true}), &c)
            .unwrap_err();
        assert_eq!(refused["code"], "pointer.position_required");
        assert_eq!(transport.control_request_counts(), sent);
    })
    .await
    .unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

/// Switching sticks in one session never glides from another stick's presumed position.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_switch_never_reuses_another_sticks_pointer() {
    let ids = ["sim-stick-a", "sim-stick-b"];
    let transports = ids.map(|_| Arc::new(SimulatorTransport::new(vec![]).with_extended_pointer()));
    let daemon = Daemon::with_device_transports(
        MemoryTokenStore::new("test-token-123456"),
        ids.iter()
            .zip(&transports)
            .map(|(id, t)| {
                (
                    id.to_string(),
                    id.to_string(),
                    t.clone() as Arc<dyn keyferryd::DeviceTransport>,
                )
            })
            .collect(),
    )
    .unwrap();
    let visual = Arc::new(Mutex::new(Visual {
        pointer: [0.7, 0.25],
        revision: 0,
        at: Instant::now(),
        path: Vec::new(),
    }));
    let sent: Arc<Mutex<Vec<(String, [f64; 2])>>> = Arc::default();
    let (observed, log) = (visual.clone(), sent.clone());
    let app = daemon.router().layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let (observed, log) = (observed.clone(), log.clone());
            async move {
                let path = request.uri().path().to_owned();
                let device = path.strip_prefix("/v1/devices/").and_then(|p| p.split('/').next()).unwrap_or("").to_owned();
                let status = request.method() == axum::http::Method::GET && ids.contains(&device.as_str()) && path.ends_with(&device);
                let request = if request.method() == axum::http::Method::POST && path.ends_with("/input-sequences") {
                    let (parts, body) = request.into_parts();
                    let bytes = axum::body::to_bytes(body, MAX_MESSAGE).await.unwrap();
                    let value: Value = serde_json::from_slice(&bytes).unwrap();
                    let mut visual = observed.lock().unwrap();
                    for action in value["actions"].as_array().unwrap() {
                        if action["type"] == "move_absolute" {
                            let at = [action["x"].as_f64().unwrap(), action["y"].as_f64().unwrap()];
                            visual.pointer = at;
                            log.lock().unwrap().push((device.clone(), at));
                        } else {
                            visual.revision += 1;
                        }
                    }
                    visual.at = Instant::now();
                    drop(visual);
                    axum::extract::Request::from_parts(parts, axum::body::Body::from(bytes))
                } else {
                    request
                };
                let response = next.run(request).await;
                if !status {
                    return response;
                }
                let (parts, body) = response.into_parts();
                let mut v: Value = serde_json::from_slice(&axum::body::to_bytes(body, 8192).await.unwrap()).unwrap();
                v["firmware"] = json!({"device_capability_mask":keyferry_protocol::capability::POINTER_EXTENDED_V1});
                axum::response::Response::from_parts(parts, axum::body::Body::from(v.to_string()))
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut s = server();
    let root = s.root.clone();
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("token"), "test-token-123456").unwrap();
    (s.url, s.token) = (url, root.join("token"));
    s.frames.pointer = Some(visual.clone());
    s.frames.area = FULL_AREA;
    tokio::task::spawn_blocking(move || {
        init(&mut s);
        let c = AtomicBool::new(false);
        for (id, (x, y)) in [
            (ids[0], (60, 60)),
            (ids[0], (280, 200)),
            (ids[1], (280, 60)),
            (ids[0], (60, 200)),
        ] {
            if s.device != id {
                let selected = s.call("select_device", &json!({"device":id}), &c).unwrap();
                assert_eq!(selected["structuredContent"]["selection"], "selected");
                assert_eq!(s.pointer, None, "a newly leased stick's cursor is unknown");
                s.call("screenshot", &json!({}), &c).unwrap();
                let before = sent.lock().unwrap().len();
                let refused = s
                    .call("move", &json!({"x":x,"y":y,"uncalibrated":true}), &c)
                    .unwrap_err();
                assert_eq!(refused["code"], "pointer.position_required");
                assert_eq!(
                    sent.lock().unwrap().len(),
                    before,
                    "no input before the seed"
                );
                let seeded = seed(&mut s, "screen", &c).unwrap();
                assert_eq!(seeded["structuredContent"]["pointer_moved"], false);
                assert_eq!(seeded["structuredContent"]["pointer_position_known"], true);
            }
            // Where the target cursor really is: off centre at first, then wherever the
            // other stick left it.
            let from = visual.lock().unwrap().pointer;
            let start = sent.lock().unwrap().len();
            let moved = s
                .call("move", &json!({"x":x,"y":y,"uncalibrated":true}), &c)
                .unwrap();
            assert_eq!(moved["isError"], false, "{moved}");
            let sent = sent.lock().unwrap();
            assert!(sent[start..].iter().all(|(d, _)| d == id), "{id}");
            let path: Vec<[f64; 2]> = std::iter::once(from)
                .chain(sent[start..].iter().map(|(_, at)| *at))
                .collect();
            assert!(largest_jump(&path) < 0.12, "{id}: {path:?}");
            assert!(s
                .pointer
                .unwrap()
                .into_iter()
                .zip(sent.last().unwrap().1)
                .all(|(a, b)| (a - b).abs() < 1e-12));
        }
        assert!(transports.iter().all(|t| !t.is_remotely_armed()));
    })
    .await
    .unwrap();
    task.abort();
    drop(daemon);
    fs::remove_dir_all(root).unwrap();
}

/// Two agents on one controller: separate MCP servers, sticks and screens, one real daemon.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_agents_drive_two_sticks_concurrently_without_cross_talk() {
    use std::collections::HashMap;
    const DELAY: Duration = Duration::from_millis(400);
    let ids = ["sim-agent-a", "sim-agent-b"];
    // Agent B's first command is lost after it may have started; agent A must not notice.
    let transports = [
        Arc::new(
            SimulatorTransport::new(vec![])
                .with_extended_pointer()
                .with_accept_delay(DELAY),
        ),
        Arc::new(
            SimulatorTransport::new(vec![SimulationFault::LostAfterStart])
                .with_extended_pointer()
                .with_accept_delay(DELAY),
        ),
    ];
    let daemon = Daemon::with_device_transports(
        MemoryTokenStore::new("test-token-123456"),
        ids.iter()
            .zip(&transports)
            .map(|(id, t)| {
                (
                    id.to_string(),
                    id.to_string(),
                    t.clone() as Arc<dyn keyferryd::DeviceTransport>,
                )
            })
            .collect(),
    )
    .unwrap();
    let visuals: HashMap<String, Arc<Mutex<Visual>>> = ids
        .iter()
        .map(|id| {
            (
                id.to_string(),
                Arc::new(Mutex::new(Visual {
                    pointer: START,
                    revision: 0,
                    at: Instant::now(),
                    path: Vec::new(),
                })),
            )
        })
        .collect();
    let posted: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let (observed, log) = (visuals.clone(), posted.clone());
    let app = daemon.router().layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let (observed, log) = (observed.clone(), log.clone());
            async move {
                let path = request.uri().path().to_owned();
                let device = path.strip_prefix("/v1/devices/").and_then(|p| p.split('/').next()).unwrap_or("").to_owned();
                let status = request.method() == axum::http::Method::GET && observed.contains_key(&device) && path.ends_with(&device);
                let request = if request.method() == axum::http::Method::POST && path.ends_with("/input-sequences") {
                    let (parts, body) = request.into_parts();
                    let bytes = axum::body::to_bytes(body, MAX_MESSAGE).await.unwrap();
                    let value: Value = serde_json::from_slice(&bytes).unwrap();
                    log.lock().unwrap().push((device.clone(), value["command_id"].as_str().unwrap().to_owned()));
                    let mut visual = observed[&device].lock().unwrap();
                    for action in value["actions"].as_array().unwrap() {
                        if action["type"] == "move_absolute" || action["type"] == "drag" {
                            visual.pointer = [action["x"].as_f64().unwrap(), action["y"].as_f64().unwrap()];
                        } else {
                            visual.revision += 1;
                        }
                    }
                    visual.at = Instant::now();
                    drop(visual);
                    axum::extract::Request::from_parts(parts, axum::body::Body::from(bytes))
                } else {
                    request
                };
                let response = next.run(request).await;
                if !status {
                    return response;
                }
                let (parts, body) = response.into_parts();
                let mut v: Value = serde_json::from_slice(&axum::body::to_bytes(body, 8192).await.unwrap()).unwrap();
                v["firmware"] = json!({"device_capability_mask":keyferry_protocol::capability::POINTER_EXTENDED_V1});
                axum::response::Response::from_parts(parts, axum::body::Body::from(v.to_string()))
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // Production state root is shared per user; leases and geometry are keyed per stick.
    let root = server().root;
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("token"), "test-token-123456").unwrap();
    let agents = ids.map(|id| {
        let mut s = server();
        s.device = id.into();
        s.root = root.clone();
        s.url = url.clone();
        s.token = root.join("token");
        s.frames.pointer = Some(visuals[id].clone());
        s.frames.area = FULL_AREA;
        s
    });
    fn script(s: &mut Server<FakeFrames, FakeOcr>, lost_first: bool) -> Vec<String> {
        let c = AtomicBool::new(false);
        let mut commands = Vec::new();
        if lost_first {
            let lost = s.call("key", &json!({"keys":["SHIFT"]}), &c).unwrap_err();
            assert_eq!(lost["command"]["outcome"], "UNKNOWN", "{lost}");
            commands.push(lost["command"]["command_id"].as_str().unwrap().to_owned());
        }
        // A fresh session seeds its probes from the cursor it sees; a known one needs no seed.
        let calibration = if s.pointer.is_none() {
            seed(s, "probe", &c)
        } else {
            s.call("calibrate", &json!({}), &c)
        }
        .unwrap();
        assert_eq!(
            calibration["structuredContent"]["bound"], true,
            "{calibration}"
        );
        for probe in calibration["structuredContent"]["probes"]
            .as_array()
            .unwrap()
        {
            commands.push(probe["command"]["command_id"].as_str().unwrap().to_owned());
        }
        s.call("screenshot", &json!({}), &c).unwrap();
        let found = s
            .call("find_text", &json!({"query":"safe test"}), &c)
            .unwrap();
        assert_eq!(
            found["structuredContent"]["boxes"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        for (name, args) in [
            ("click", json!({"x":160,"y":120})),
            ("type_text", json!({"text":"agent text"})),
            ("key", json!({"keys":["SHIFT"]})),
        ] {
            let result = s.call(name, &args, &c).unwrap();
            assert_eq!(result["isError"], false, "{name}: {result}");
            let receipt = &result["structuredContent"];
            let command = if receipt.get("command").is_some() {
                &receipt["command"]
            } else {
                receipt
            };
            assert_eq!(command["outcome"], "EMITTED");
            commands.push(command["command_id"].as_str().unwrap().to_owned());
        }
        commands
    }
    let run = |mut s: Server<FakeFrames, FakeOcr>, lost_first: bool| {
        tokio::task::spawn_blocking(move || {
            if !s.initialized {
                init(&mut s);
            }
            let started = Instant::now();
            let commands = script(&mut s, lost_first);
            (s, commands, started.elapsed())
        })
    };
    let [a, b] = agents;
    // Agent A alone sets the baseline; then both agents run at once.
    let (a, mut a_commands, solo) = run(a, false).await.unwrap();
    let started = Instant::now();
    let (concurrent_a, concurrent_b) = tokio::join!(run(a, false), run(b, true));
    let wall = started.elapsed();
    let (a, more, a_elapsed) = concurrent_a.unwrap();
    let (b, b_commands, _) = concurrent_b.unwrap();
    a_commands.extend(more);
    let posted = posted.lock().unwrap().clone();
    let results = [
        (a.device.clone(), a_commands),
        (b.device.clone(), b_commands),
    ];
    for (i, (device, commands)) in results.iter().enumerate() {
        let other = 1 - i;
        for id in commands {
            let id_uuid = uuid::Uuid::parse_str(id).unwrap();
            // Every command ran exactly once, on its own stick only; UNKNOWN was never replayed.
            assert_eq!(transports[i].execution_count(id_uuid), 1, "{device} {id}");
            assert_eq!(
                transports[other].execution_count(id_uuid),
                0,
                "{device} {id}"
            );
            assert!(posted.contains(&(device.clone(), id.clone())));
        }
        assert_eq!(
            posted.iter().filter(|(d, _)| d == device).count(),
            commands.len()
        );
        assert!(!transports[i].is_remotely_armed());
        assert!(geometry::load(&root, device, "fake-hdmi")
            .unwrap()
            .is_some());
    }
    // Serializing the sticks would add agent B's device time to agent A's own run.
    let b_device_time = DELAY * results[1].1.len() as u32;
    let bound = solo + b_device_time.mul_f64(0.6);
    assert!(
        a_elapsed < bound && wall < bound,
        "solo {solo:?}, A {a_elapsed:?}, wall {wall:?}, B device {b_device_time:?}"
    );
    println!("two agents: solo {solo:?}, A concurrent {a_elapsed:?}, wall {wall:?}, B device {b_device_time:?}");
    drop((a, b));
    task.abort();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn screen_calibration_binds_without_any_pointer_input() {
    let (mut s, transport, _, task) = harness(vec![], true).await;
    let root = s.root.clone();
    tokio::task::spawn_blocking(move || {
        init(&mut s);
        let c = AtomicBool::new(false);
        let before = s.frames.pointer.as_ref().unwrap().lock().unwrap().pointer;
        let counts = transport.control_request_counts();
        let r = s.dispatch(json!({"jsonrpc":"2.0","id":"screen-cal","method":"tools/call","params":{"name":"calibrate","arguments":{"mode":"screen"}}}), &c).unwrap();
        assert_eq!(r["result"]["isError"], false, "{r}");
        let result = &r["result"]["structuredContent"];
        assert_eq!(result["pointer_moved"], false);
        assert_eq!(result["pointer_position_known"], true);
        assert_eq!(result["basis"], "video-area");
        assert_eq!(transport.control_request_counts(), counts, "no stick traffic");
        assert_eq!(s.frames.pointer.as_ref().unwrap().lock().unwrap().pointer, before);
        s.call("screenshot", &json!({}), &c).unwrap();
        let moved = s.dispatch(json!({"jsonrpc":"2.0","id":"after","method":"tools/call","params":{"name":"move","arguments":{"x":100,"y":120}}}), &c).unwrap();
        assert_eq!(moved["result"]["isError"], false, "{moved}");
    })
    .await
    .unwrap();
    task.abort();
    fs::remove_dir_all(root).unwrap();
}
