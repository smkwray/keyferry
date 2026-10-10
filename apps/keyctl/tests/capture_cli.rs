//! Fake ffmpeg is this test executable placed on a private PATH. This exercises
//! the production CLI/program selection, with no production test override.
use serde_json::Value;
use std::{
    env, fs,
    io::{self, Write},
    path::Path,
    process::{self, Command, Output},
    thread,
    time::{Duration, Instant},
};

fn main() {
    if let Ok(mode) = env::var("KEYCTL_FAKE_FFMPEG") {
        fake_ffmpeg(&mode);
        return;
    }
    one_shot_warmup();
    if cfg!(windows) {
        run_native_windows_tests();
    } else {
        run_tests();
    }
}

fn fake_ffmpeg(mode: &str) {
    assert!(
        env::var_os("FFREPORT").is_none(),
        "capture must disable inherited ffmpeg reports"
    );
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args
        .iter()
        .any(|arg| arg == "-list_devices" || arg == "-sources")
    {
        if mode == "bad-list" {
            eprintln!("Unknown input format");
            process::exit(1);
        }
        if args.iter().any(|arg| arg == "avfoundation") {
            eprint!("{}", include_str!("fixtures/avfoundation-devices.txt"));
            process::exit(1);
        } else if args.iter().any(|arg| arg == "v4l2") {
            print!("{}", include_str!("fixtures/v4l2-devices.txt"));
        } else {
            eprint!("{}", include_str!("fixtures/dshow-devices.txt"));
            if mode == "ambiguous" {
                eprintln!("[in#0 @ 0] \"HDMI Capture\" (video)");
            }
            process::exit(1);
        }
        return;
    }
    assert_eq!(args.last().unwrap(), "pipe:1");
    if mode == "timeout" {
        let path = env::var_os("KEYCTL_FAKE_HEARTBEAT").unwrap();
        for n in 0..400 {
            fs::write(&path, n.to_string()).unwrap();
            thread::sleep(Duration::from_millis(100));
        }
    }
    if mode == "fail" {
        eprintln!("private-target-content-and-path-must-not-be-reflected");
        process::exit(1);
    }
    if mode == "malformed" {
        print!("not-a-png");
        return;
    }
    if mode == "flood" {
        let mut out = io::stdout().lock();
        let bytes = [0; 65536];
        for _ in 0..1100 {
            if out.write_all(&bytes).is_err() {
                process::exit(1);
            }
        }
        return;
    }
    let mut width = 2;
    let mut height = 1;
    for pair in args.windows(2) {
        if pair[0] == "-video_size" || (pair[0] == "-vf" && pair[1].contains("scale=")) {
            let size = pair[1].trim_start_matches("fps=5,scale=");
            let (w, h) = size
                .split_once(if pair[0] == "-vf" { ':' } else { 'x' })
                .unwrap();
            width = w.parse().unwrap();
            height = h.parse().unwrap();
        }
    }
    let mut out = io::stdout().lock();
    for n in 0..400 {
        let value = if mode == "warmup" && n >= 3 {
            118
        } else if mode == "ok" {
            0
        } else {
            118
        };
        let pixels = [value; 3].repeat(width as usize * height as usize);
        let mut bytes = Vec::new();
        let mut encoder = png::Encoder::new(&mut bytes, width, height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&pixels)
            .unwrap();
        if out.write_all(&bytes).and_then(|()| out.flush()).is_err() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn one_shot_warmup() {
    let mut command = keyferry_core::process::command(env::current_exe().unwrap());
    command
        .args(["-f", "image2pipe", "pipe:1"])
        .env("KEYCTL_FAKE_FFMPEG", "warmup");
    let start = Instant::now();
    let frame = keyferry_capture::frames::one_shot(command, Duration::from_secs(10)).unwrap();
    assert_eq!(keyferry_capture::capture::signal(&frame.rgb).0, "present");
    assert!(start.elapsed() >= Duration::from_millis(150));
    let mut command = keyferry_core::process::command(env::current_exe().unwrap());
    command
        .args(["-f", "image2pipe", "pipe:1"])
        .env("KEYCTL_FAKE_FFMPEG", "ok");
    let start = Instant::now();
    let frame = keyferry_capture::frames::one_shot(command, Duration::from_secs(10)).unwrap();
    assert_eq!(keyferry_capture::capture::signal(&frame.rgb).0, "no-signal");
    assert!(start.elapsed() >= keyferry_capture::frames::WARMUP);
    assert!(start.elapsed() < Duration::from_secs(9));
}

fn invoke(directory: &Path, mode: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_keyctl"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--token-file",
            "missing-token",
            "capture",
        ])
        .args(args)
        .env("PATH", directory)
        .env("KEYCTL_FAKE_FFMPEG", mode)
        .env("KEYCTL_FAKE_HEARTBEAT", directory.join("heartbeat"))
        .env("FFREPORT", "file=must-not-write-a-report.log")
        .output()
        .unwrap()
}

fn value(output: &Output, exit: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(exit),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(text.lines().count(), 1);
    assert!(!text.contains("private-target-content"));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn run_native_windows_tests() {
    // A hostile fake ffmpeg on PATH cannot affect Windows native discovery.
    let directory = env::temp_dir().join(format!("keyctl-native-capture-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&directory).unwrap();
    let fake = directory.join("ffmpeg.exe");
    fs::copy(env::current_exe().unwrap(), &fake).unwrap();
    let list = value(&invoke(&directory, "bad-list", &["list"]), 0);
    assert_eq!(list["backend"], "dshow");
    assert!(list["devices"].is_array());
    let out = directory.join("frame.png");
    let missing = value(
        &invoke(
            &directory,
            "timeout",
            &[
                "frame",
                "--out",
                out.to_str().unwrap(),
                "--source",
                "keyferry-absent-test-source",
            ],
        ),
        20,
    );
    assert_eq!(missing["error"]["code"], "capture.source_not_found");
    assert!(!directory.join("heartbeat").exists());
    assert!(!out.exists());
    fs::remove_file(fake).unwrap();
    // Inventory still works with no ffmpeg executable at all.
    let without_ffmpeg = value(&invoke(&directory, "ok", &["list"]), 0);
    assert_eq!(without_ffmpeg["devices"], list["devices"]);
    assert_eq!(
        value(&invoke(&directory, "ok", &["frame"]), 20)["error"]["code"],
        "capture.arguments"
    );
    fs::remove_dir_all(directory).unwrap();
    println!(
        "capture_cli: passed native Windows discovery without ffmpeg and absent-source no-spawn"
    );
}

fn run_tests() {
    let directory = env::temp_dir().join(format!("keyctl-capture-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&directory).unwrap();
    let fake = directory.join(if cfg!(windows) {
        "ffmpeg.exe"
    } else {
        "ffmpeg"
    });
    fs::copy(env::current_exe().unwrap(), &fake).unwrap();
    let frame = directory.join("frame.png");
    let out = frame.to_str().unwrap();
    let list = value(&invoke(&directory, "ok", &["list"]), 0);
    assert_eq!(list["schema"], "keyferry.capture-devices.v1");
    assert_eq!(list["devices"].as_array().unwrap().len(), 2);
    let captured = value(
        &invoke(
            &directory,
            "ok",
            &["frame", "--out", out, "--size", "4x2", "--scale", "2x1"],
        ),
        0,
    );
    assert_eq!(captured["schema"], "keyferry.capture-frame.v1");
    assert_eq!(captured["signal"], "no-signal");
    assert_eq!(captured["width"], 2);
    assert_eq!(captured["height"], 1);
    assert_eq!(captured["path"], out);
    assert_eq!(captured["mean_luma"], 0.0);
    assert!(captured["captured_at"].as_str().unwrap().ends_with('Z'));
    assert!(fs::read(&frame).unwrap().starts_with(b"\x89PNG\r\n\x1a\n"));
    let saved = fs::read(&frame).unwrap();
    assert_eq!(
        value(&invoke(&directory, "ok", &["frame", "--out", out]), 25)["error"]["code"],
        "capture.output"
    );
    assert_eq!(
        fs::read(&frame).unwrap(),
        saved,
        "existing output must be untouched"
    );
    fs::remove_file(&frame).unwrap();
    if cfg!(windows) {
        let ambiguous = value(
            &invoke(&directory, "ambiguous", &["frame", "--out", out]),
            20,
        );
        assert_eq!(ambiguous["error"]["code"], "capture.source_required");
        assert_eq!(ambiguous["candidates"].as_array().unwrap().len(), 3);
    }
    let not_found = value(
        &invoke(
            &directory,
            "ok",
            &["frame", "--out", out, "--source", "absent"],
        ),
        20,
    );
    assert_eq!(not_found["error"]["code"], "capture.source_not_found");
    for (mode, code) in [
        ("bad-list", "capture.list_failed"),
        ("fail", "capture.frame_failed"),
        ("malformed", "capture.invalid_frame"),
        ("flood", "capture.output_limit"),
    ] {
        assert_eq!(
            value(&invoke(&directory, mode, &["frame", "--out", out]), 25)["error"]["code"],
            code
        );
        assert!(!frame.exists());
    }
    let start = Instant::now();
    assert_eq!(
        value(&invoke(&directory, "timeout", &["frame", "--out", out]), 24)["error"]["code"],
        "capture.timeout"
    );
    assert!(start.elapsed() < Duration::from_secs(20));
    let heartbeat = fs::read(directory.join("heartbeat")).unwrap();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        fs::read(directory.join("heartbeat")).unwrap(),
        heartbeat,
        "timed-out child must stop"
    );
    assert!(!frame.exists());
    mcp_daemon_smoke(&directory);
    fs::remove_file(fake).unwrap();
    assert_eq!(
        value(&invoke(&directory, "ok", &["list"]), 23)["error"]["code"],
        "capture.ffmpeg_missing"
    );
    assert_eq!(
        value(&invoke(&directory, "ok", &["frame"]), 20)["error"]["code"],
        "capture.arguments"
    );
    let help = invoke(&directory, "ok", &["--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Camera permission"));
    fs::remove_dir_all(directory).unwrap();
    println!(
        "capture_cli: passed (real CLI, fake ffmpeg PATH, timeout kill, output/privacy/errors)"
    );
}

fn mcp_daemon_smoke(directory: &Path) {
    use keyferryd::{Daemon, MemoryTokenStore, SIMULATOR_DEVICE_ID};
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let original_path = env::var_os("PATH").unwrap();
    let mut paths = vec![directory.to_owned()];
    paths.extend(env::split_paths(&original_path));
    env::set_var("PATH", env::join_paths(paths).unwrap());
    env::set_var("KEYCTL_FAKE_FFMPEG", "ok");
    env::set_var("FFREPORT", "file=must-not-write-a-report.log");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (daemon, port, task) = runtime.block_on(async {
        let daemon = Daemon::new(MemoryTokenStore::new("test-token-123456")).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = daemon.router();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (daemon, port, task)
    });
    let token = directory.join("mcp-token");
    fs::write(&token, "test-token-123456").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_keyctl"))
        .args([
            "--url",
            &format!("http://127.0.0.1:{port}"),
            "--token-file",
            token.to_str().unwrap(),
            "mcp",
        ])
        .env("LOCALAPPDATA", directory)
        .env("XDG_STATE_HOME", directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let request = |input: &mut std::process::ChildStdin,
                   output: &mut BufReader<std::process::ChildStdout>,
                   id,
                   name,
                   args| {
        writeln!(input,"{}",serde_json::json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}})).unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        serde_json::from_str::<Value>(&line).unwrap()["result"].clone()
    };
    writeln!(input,"{}",serde_json::json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"test","version":"1"},"capabilities":{}}})).unwrap();
    input.flush().unwrap();
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&line).unwrap()["result"]["serverInfo"]["name"],
        "keyferry"
    );
    writeln!(
        input,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )
    .unwrap();
    let status = request(&mut input, &mut output, 1, "status", serde_json::json!({}));
    assert_eq!(
        status["structuredContent"]["selected_device"],
        SIMULATOR_DEVICE_ID
    );
    assert_eq!(
        status["structuredContent"]["device_selection"],
        "automatic-single"
    );
    assert_eq!(
        status["structuredContent"]["capture"]["selection"],
        "automatic-local"
    );
    let inventory = request(
        &mut input,
        &mut output,
        2,
        "list_capture_sources",
        serde_json::json!({}),
    );
    let source = inventory["structuredContent"]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["recognized"] == true)
        .unwrap()["id"]
        .clone();
    let selected = request(
        &mut input,
        &mut output,
        3,
        "select_capture_source",
        serde_json::json!({"source":source}),
    );
    assert_eq!(selected["structuredContent"]["selection"], "selected");
    let frame = request(
        &mut input,
        &mut output,
        4,
        "screenshot",
        serde_json::json!({}),
    );
    assert_eq!(frame["isError"], false, "{frame}");
    assert_eq!(frame["content"][0]["type"], "image");
    assert_eq!(frame["structuredContent"]["capture"]["owner"], "keyferryd");
    drop(input);
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    runtime.block_on(daemon.shutdown(Duration::from_secs(3)));
    task.abort();
    drop(daemon);
    runtime.shutdown_timeout(Duration::from_secs(3));
    env::set_var("PATH", original_path);
    env::remove_var("KEYCTL_FAKE_FFMPEG");
    env::remove_var("FFREPORT");
    assert!(!directory.join("must-not-write-a-report.log").exists());
}
