include!("mcp_test_support.rs");

#[test]
fn secure_prompt_blocks_ocr_click_and_stability_does_not_resume_input() {
    for (following, stopped_at) in [
        (
            json!([{ "type":"click_text","query":"safe","timeout_ms":100 }]),
            1,
        ),
        (
            json!([
                {"type":"wait_for_stable","timeout_ms":1000},
                {"type":"key","keys":["ENTER"]}
            ]),
            2,
        ),
    ] {
        let mut s = server();
        s.pointer = Some([0.5, 0.5]);
        s.secure_prompt = |_, _, _| Ok(json!({"outcome":"REQUESTED","input_sent":false}));
        let mut steps = vec![json!({"type":"secure_text"})];
        steps.extend(following.as_array().unwrap().iter().cloned());
        let definition = json!({
            "schema":"keyferry.recipe.v1", "name":"test-owner-wait",
            "target_os":"any", "verified":false, "steps":steps
        });
        let recipe = recipes::parse(definition.to_string().as_bytes()).unwrap();
        let args = json!({});
        let steps = routine_steps(&recipe, &args).unwrap();
        let result = s
            .execute_routine(
                &recipe,
                &steps,
                &args,
                false,
                false,
                &AtomicBool::new(false),
            )
            .unwrap();
        let metadata = &result["structuredContent"];
        assert_eq!(metadata["actions"][0]["receipt"]["outcome"], "REQUESTED");
        assert_eq!(metadata["stopped_at"], stopped_at);
        assert_eq!(metadata["awaiting_owner"], true);
        assert_eq!(metadata["command_count"], 0);
        assert_eq!(metadata["execution_complete"], false);
        assert_eq!(
            metadata["actions"][stopped_at as usize]["error"]["code"],
            "recipe.owner_completion_required"
        );
        if stopped_at == 2 {
            assert_eq!(
                metadata["actions"][1]["receipt"]["matched"], true,
                "the unchanged stable screen must pass its check without releasing the owner latch"
            );
        }
        assert!(
            !s.root.exists(),
            "the isolated executor must persist nothing"
        );
    }
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
fn images_are_opt_in_and_save_path_is_rejected_before_capture() {
    let listed = tools();
    for name in [
        "move",
        "click",
        "drag",
        "scroll",
        "key",
        "type_text",
        "batch",
        "routine_run",
    ] {
        let schema = &listed.iter().find(|t| t["name"] == name).unwrap()["inputSchema"];
        assert_eq!(schema["properties"]["return_screenshot"]["default"], false);
    }
    let mut s = server();
    init(&mut s);
    let c = AtomicBool::new(false);
    let output = s.root.join("must-not-save.png");
    let result = s
        .dispatch(
            json!({"jsonrpc":"2.0","id":"save-frame","method":"tools/call","params":{"name":"screenshot","arguments":{"save_path":output}}}),
            &c,
        )
        .unwrap();
    assert_eq!(result["result"]["isError"], true);
    assert_eq!(
        result["result"]["structuredContent"]["error"]["code"],
        "input.tool_arguments"
    );
    assert_eq!(
        s.frames.next, 0,
        "invalid persistence request must not capture"
    );
    assert!(!output.exists());
    assert!(
        !s.root.exists(),
        "invalid persistence request must not create state"
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
fn native_fit_binds_the_agent_view_at_matching_pixel_centres() {
    // Fitted on a native 1920x1080 frame, used on the 1280x720 agent view.
    let mut native = frame(1920, 1080, 1);
    native.native = (1920, 1080);
    let samples: Vec<_> = [[0.1, 0.2], [0.8, 0.2], [0.2, 0.8], [0.8, 0.7]]
        .into_iter()
        .map(|p| (p, [60.0 + 1800.0 * p[0], 30.0 + 1020.0 * p[1]]))
        .collect();
    let g = geometry::fit("d", "s", &native, &samples).unwrap();
    let view = g.scaled(1280, 720);
    let mut agent = frame(1280, 720, 2);
    agent.native = (1920, 1080);
    assert!(view.matches("d", "s", &agent) && !g.matches("d", "s", &agent));
    for (x, y) in [(61.0, 31.0), (960.5, 540.5), (1858.0, 1048.0)] {
        let expected = g.map(x, y).unwrap();
        let p = view.map((x + 0.5) * 2.0 / 3.0 - 0.5, (y + 0.5) * 2.0 / 3.0 - 0.5);
        assert!((0..2).all(|a| (p.unwrap()[a] - expected[a]).abs() < 1e-9));
    }
}

#[test]
fn cursor_differencing_synthetic_and_ambiguity() {
    let a = cursor_frame(FAKE_AREA, [0.1, 0.1], 1);
    let b = cursor_frame(FAKE_AREA, [0.7, 0.2], 2);
    let c = cursor_frame(FAKE_AREA, [0.3, 0.8], 3);
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

/// A small Windows arrow on a white (Notepad) background after 2:1 nearest-neighbour
/// downscaling: only every other pixel of its one-pixel black outline survives.
fn outline_frame(tip: (u32, u32), serial: u64) -> Frame {
    let mut f = frame(320, 240, serial);
    f.rgb.fill(255);
    let (x, y) = tip;
    for (dx, dy) in (0..=14)
        .step_by(2)
        .map(|k| (0, k))
        .chain((0..=10).step_by(2).map(|k| (k, k)))
    {
        let i = ((y + dy) * f.width + x + dx) as usize * 3;
        f.rgb[i..i + 3].fill(0);
    }
    f
}

#[test]
fn decimated_thin_arrow_outline_is_one_cursor() {
    let a = outline_frame((40, 40), 1);
    let b = outline_frame((200, 100), 2);
    let c = outline_frame((100, 180), 3);
    let mask = frames::MotionMask::new(&a);
    assert_eq!(geometry::cursor(&a, &b, &c, &mask).unwrap(), [200.0, 100.0]);
    assert_eq!(
        geometry::cursor_near(&a, &b, &c, &mask, Some([202.0, 98.0])).unwrap(),
        [200.0, 100.0]
    );
}

#[test]
fn probe_prediction_excludes_pillar_bars_and_prefers_agreeing_probes() {
    let mut f = frame(320, 240, 1);
    for y in 0..240 {
        for x in (0..40).chain(280..320) {
            let i = (y * f.width + x) as usize * 3;
            f.rgb[i..i + 3].fill(0);
        }
    }
    assert_eq!(geometry::active_video(&f), [40.0, 0.0, 240.0, 240.0]);
    assert_eq!(geometry::expected(&f, &[], [0.5, 0.25]), [159.5, 59.75]);
    let mut dark = f.clone();
    dark.rgb.fill(0);
    assert_eq!(geometry::active_video(&dark), [0.0, 0.0, 320.0, 240.0]);
    let mut samples = vec![
        ([0.1, 0.1], [50.0, 40.0]),
        ([0.9, 0.2], [250.0, 60.0]),
        ([0.5, 0.9], [150.0, 200.0]),
    ];
    let p = geometry::expected(&f, &samples, [0.5, 0.5]);
    assert!((p[0] - 150.0).abs() < 1e-9 && (p[1] - 120.0).abs() < 1e-9);
    samples[2].1 = [10.0, 10.0];
    assert_eq!(
        geometry::expected(&f, &samples, [0.5, 0.25]),
        [159.5, 59.75]
    );
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
    // A small edit far below the 1% mean margin matches only through the action's
    // animation mask; the masked blink and clock alone never match.
    s.frames.change_after = None;
    s.frames.animate = true;
    let f = s.frame(&c).unwrap();
    assert_eq!(
        s.wait("wait_for_change", &json!({"timeout_ms":300}), f, &c)
            .unwrap()["timed_out"],
        true
    );
    s.stationary(&c).unwrap();
    let f = s.frame(&c).unwrap();
    assert_eq!(
        s.wait("wait_for_change", &json!({"timeout_ms":400}), f, &c)
            .unwrap()["timed_out"],
        true
    );
    let f = s.frame(&c).unwrap();
    s.frames.visible.revision = 1;
    let v = s
        .wait("wait_for_change", &json!({"timeout_ms":1000}), f, &c)
        .unwrap();
    assert_eq!(v["matched"], true);
    assert!(v["difference"].as_f64().unwrap() < 0.001, "{v}");
    s.frames.animate = false;
    s.frames.visible.revision = 0;
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
    // Only the stick lease exists; frames and OCR are never persisted.
    let persisted = fs::read_dir(&s.root)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(persisted, ["device-leases"]);
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
    s.lease = None;
    fs::remove_dir_all(&s.root).unwrap();
}

#[test]
fn one_agent_per_stick_and_a_lost_automatic_choice_never_rearms() {
    let mut a = server();
    let mut b = server();
    b.root = a.root.clone();
    let c = AtomicBool::new(false);
    // Any device-scoped call claims the stick; eyes alone stay available to the other agent.
    a.call("screenshot", &json!({}), &c).unwrap();
    assert!(a.lease.is_some());
    b.call("screenshot", &json!({}), &c).unwrap();
    for name in ["key", "status"] {
        let result = b.call(name, &json!({"keys":["SHIFT"]}), &c);
        let error = match name {
            "status" => result.unwrap()["structuredContent"]["selection_error"].clone(),
            _ => result.unwrap_err(),
        };
        assert_eq!(error["code"], "device.in_use_by_other_agent", "{name}");
    }
    // Releasing (exit or crash closes the handle) frees the stick for the other agent.
    a.lease = None;
    b.call("screenshot", &json!({}), &c).unwrap();
    assert!(b.lease.is_some());
    // An automatic choice that stops matching stays unselected instead of re-arming.
    b.device_choice = "lost";
    b.device.clear();
    b.lease = None;
    assert_eq!(
        b.call("key", &json!({"keys":["SHIFT"]}), &c).unwrap_err()["code"],
        "device.select_required"
    );
    assert!(b.lease.is_none());
    for id in ["../escape", "a b", ""] {
        assert!(device_lease(&a.root, id).is_err());
    }
    let root = a.root.clone();
    drop((a, b));
    fs::remove_dir_all(root).unwrap();
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

#[test]
fn screen_area_preserves_dark_wallpaper_and_recognizes_letterbox() {
    let mut f = frame(1280, 720, 1);
    // The reported dark-desktop regression: asymmetric top/bottom and slightly uneven pillars.
    for y in 0..720 {
        for x in 0..1280 {
            if !(66..1215).contains(&x) || !(5..718).contains(&y) {
                let i = (y * 1280 + x) as usize * 3;
                f.rgb[i..i + 3].fill(0);
            }
        }
    }
    assert_eq!(geometry::active_video(&f), [64.0, 0.0, 1152.0, 720.0]);
    let mut dark = frame(1280, 720, 1);
    dark.rgb.fill(0);
    for y in 680..720 {
        for x in 0..1280 {
            let i = (y * 1280 + x) as usize * 3;
            dark.rgb[i..i + 3].fill(60);
        }
    }
    assert_eq!(geometry::active_video(&dark), [0.0, 0.0, 1280.0, 720.0]);
    let mut letter = frame(640, 480, 1);
    for y in (0..60).chain(420..480) {
        let i = (y * 640) as usize * 3;
        letter.rgb[i..i + 640 * 3].fill(0);
    }
    assert_eq!(geometry::active_video(&letter), [0.0, 60.0, 640.0, 360.0]);
    // A few symmetric dark rows on a source already at 16:9 are real desktop pixels.
    let mut wide = frame(1280, 720, 1);
    for y in (0..2).chain(718..720) {
        let i = (y * 1280) as usize * 3;
        wide.rgb[i..i + 1280 * 3].fill(0);
    }
    assert_eq!(geometry::active_video(&wide), [0.0, 0.0, 1280.0, 720.0]);
    // Symmetry alone is insufficient for arbitrary dark margins.
    letter.rgb.fill(60);
    for y in (0..5).chain(475..480) {
        let i = (y * 640) as usize * 3;
        letter.rgb[i..i + 640 * 3].fill(0);
    }
    assert_eq!(geometry::active_video(&letter), [0.0, 0.0, 640.0, 480.0]);
}

#[test]
fn input_rejections_and_unknown_keys_have_actionable_messages() {
    for code in ["input.capability_required", "input.invalid_mode"] {
        let error = failure(code);
        assert_eq!(error["code"], code);
        assert!(error["message"].as_str().unwrap().contains("absolute"));
        let result: Value = serde_json::from_str(&super::super::sequence_result_json(
            "test-device",
            None,
            super::super::SequenceOutcome::Rejected,
            Some(code),
        ))
        .unwrap();
        assert_eq!(result["error"], error);
    }
    let raw = br#"{"schema":"keyferry.input-sequence.v1","keyboard_profile":"windows-us","arm":"command-scoped","start_within_ms":5000,"actions":[{"type":"tap","key":"enter"}]}"#;
    assert_eq!(
        super::super::prepare_input_sequence(raw).unwrap_err(),
        "key.unknown"
    );
    assert!(failure("key.unknown")["message"]
        .as_str()
        .unwrap()
        .contains("keyctl keys"));
}

#[test]
fn cursor_seed_is_paired_and_unknown_position_is_actionable() {
    assert_eq!(observed_cursor(&json!({})).unwrap(), None);
    assert_eq!(
        observed_cursor(&json!({"cursor_x":10,"cursor_y":20})).unwrap(),
        Some([10.0, 20.0])
    );
    for args in [json!({"cursor_x":10}), json!({"cursor_y":20})] {
        assert_eq!(
            observed_cursor(&args).unwrap_err()["code"],
            "pointer.cursor_pair_required"
        );
    }
    let message = failure("pointer.position_required")["message"].clone();
    let message = message.as_str().unwrap();
    assert!(message.contains("fresh screenshot") && message.contains("cursor_x/cursor_y"));
    let listed = tools();
    let schema = &listed.iter().find(|t| t["name"] == "calibrate").unwrap()["inputSchema"];
    assert!(validate(
        &json!({"mode":"screen","cursor_x":10,"cursor_y":20}),
        schema
    ));
    assert!(!validate(&json!({"cursor_x":-1,"cursor_y":20}), schema));
}
