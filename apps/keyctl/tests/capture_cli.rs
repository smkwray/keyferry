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
    run_tests();
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
    assert!(args.windows(2).any(|pair| pair == ["-frames:v", "1"]));
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
        if pair[0] == "-video_size" || pair[0] == "-vf" {
            let size = pair[1].trim_start_matches("scale=");
            let (w, h) = size
                .split_once(if pair[0] == "-vf" { ':' } else { 'x' })
                .unwrap();
            width = w.parse().unwrap();
            height = h.parse().unwrap();
        }
    }
    let pixels = [0, 0, 0].repeat(width as usize * height as usize);
    let mut encoder = png::Encoder::new(io::stdout().lock(), width, height);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .unwrap()
        .write_image_data(&pixels)
        .unwrap();
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
