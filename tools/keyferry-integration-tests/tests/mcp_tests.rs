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
            assert_eq!(result["actions"].as_array().unwrap().len(),if fault {1} else {2});
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
            assert_eq!(response["result"]["structuredContent"]["actions"].as_array().unwrap().len(),1);
            assert_eq!(response["result"]["structuredContent"]["stopped_at"],0);
            assert_eq!(response["result"]["content"].as_array().unwrap().len(),1);
        }).await.unwrap();
        task.abort();
        fs::remove_dir_all(root).unwrap();
    }
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
