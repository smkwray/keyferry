use super::*;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn arguments_are_strict_and_bounded() {
    assert_eq!(parse(&args(&["list"])).unwrap(), Request::List);
    assert_eq!(parse(&args(&["--help"])).unwrap(), Request::Help);
    let Request::Frame(options) = parse(&args(&[
        "frame",
        "--out",
        "screen.png",
        "--source",
        "Hagibis",
        "--size",
        "1920x1080",
        "--scale",
        "960x540",
    ]))
    .unwrap() else {
        panic!()
    };
    assert_eq!(options.size, Some((1920, 1080)));
    assert_eq!(options.scale, Some((960, 540)));
    for values in [
        vec![],
        vec!["list", "extra"],
        vec!["frame"],
        vec!["frame", "--out"],
        vec!["frame", "--out", "a", "--out", "b"],
        vec!["frame", "--out", ""],
        vec!["frame", "--out", "a", "--size", "0x100"],
        vec!["frame", "--out", "a", "--scale", "4097x1"],
        vec!["frame", "--out", "a", "--size", "1920x1080x2"],
        vec!["frame", "--out", "a", "--wat", "1"],
    ] {
        assert_eq!(parse(&args(&values)).unwrap_err().exit(), 20, "{values:?}");
    }
}

#[test]
fn real_listing_shapes_exclude_audio_and_desktop_sources() {
    let devices = parse_devices(
        Backend::Dshow,
        include_str!("../../../apps/keyctl/tests/fixtures/dshow-devices.txt"),
    )
    .unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[1].name, "Hagibis");
    assert!(devices[1].id.starts_with("@device_pnp_"));
    let devices = parse_devices(
        Backend::Avfoundation,
        include_str!("../../../apps/keyctl/tests/fixtures/avfoundation-devices.txt"),
    )
    .unwrap();
    assert_eq!(
        devices,
        vec![
            Device {
                name: "FaceTime HD Camera".into(),
                id: "0".into()
            },
            Device {
                name: "USB Capture HDMI".into(),
                id: "1".into()
            }
        ]
    );
    let devices = parse_devices(
        Backend::V4l2,
        include_str!("../../../apps/keyctl/tests/fixtures/v4l2-devices.txt"),
    )
    .unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(
        devices[1],
        Device {
            name: "USB Video Capture".into(),
            id: "/dev/video2".into()
        }
    );
    for backend in [Backend::Dshow, Backend::Avfoundation, Backend::V4l2] {
        assert_eq!(
            parse_devices(backend, "Unknown input format")
                .unwrap_err()
                .code,
            "capture.list_failed"
        );
    }
    assert!(parse_devices(
        Backend::V4l2,
        "Auto-detected sources for video4linux2,v4l2:\n/dev/video0 broken"
    )
    .is_err());
    assert!(parse_devices(
        Backend::Avfoundation,
        "AVFoundation video devices:\n[not-an-index] X"
    )
    .is_err());
}

#[test]
fn default_selection_needs_one_recognized_non_webcam() {
    let mut devices = parse_devices(
        Backend::Dshow,
        include_str!("../../../apps/keyctl/tests/fixtures/dshow-devices.txt"),
    )
    .unwrap();
    assert_eq!(select_source(&devices, None).unwrap().name, "Hagibis");
    assert!(recognized(&Device {
        name: "Cam Link 4K".into(),
        id: "cam".into(),
    }));
    assert_eq!(
        select_source(&devices, Some(&devices[0].id)).unwrap().name,
        "Logitech Webcam C925e"
    );
    assert_eq!(
        select_source(&devices, Some("missing")).unwrap_err().code,
        "capture.source_not_found"
    );
    devices.push(Device {
        name: "HDMI Capture".into(),
        id: "another".into(),
    });
    assert_eq!(
        select_source(&devices, None).unwrap_err().candidates.len(),
        3
    );
    assert!(select_source(&devices[..1], None).is_err());
    assert!(select_source(&[], None).is_err());
    let duplicates = vec![
        devices[1].clone(),
        Device {
            name: "Hagibis".into(),
            id: "unique".into(),
        },
    ];
    assert!(select_source(&duplicates, Some("Hagibis")).is_err());
    assert_eq!(
        select_source(&duplicates, Some("unique")).unwrap().id,
        "unique"
    );
}

#[test]
fn frame_arguments_select_backend_and_only_pipe_output() {
    let options = FrameOptions {
        out: "private.png".into(),
        source: None,
        size: Some((1920, 1080)),
        scale: Some((960, 540)),
        mode: None,
        bound: None,
    };
    let device = Device {
        name: "capture".into(),
        id: "3".into(),
    };
    let rate = "select='isnan(prev_selected_t)+gte(t-prev_selected_t,0.06)'";
    for (backend, input) in [
        (Backend::Dshow, "video=3"),
        (Backend::Avfoundation, "3:none"),
        (Backend::V4l2, "3"),
    ] {
        let values = frame_args(backend, &device, &options);
        assert!(values.windows(2).any(|pair| pair == ["-i", input]));
        assert!(!values.iter().any(|arg| arg == "-frames:v"));
        assert!(values.windows(2).any(|pair| pair
            == [
                "-vf".to_owned(),
                format!("{rate},scale=960:540:flags=fast_bilinear")
            ]));
        // Rate limiting only drops; no filter or muxer duplicates frames into a backlog.
        assert!(!values.iter().any(|value| value.contains("fps=")));
        assert!(values
            .windows(2)
            .any(|pair| pair == ["-fps_mode", "passthrough"]));
        let bounded = FrameOptions {
            out: "private.png".into(),
            source: None,
            size: None,
            scale: None,
            mode: None,
            bound: Some(1280),
        };
        assert!(frame_args(backend, &device, &bounded).windows(2).any(|pair| pair
            == [
                "-vf".to_owned(),
                format!("{rate},scale=w='min(iw,1280)':h='min(ih,1280)':force_original_aspect_ratio=decrease:flags=area")
            ]));
        assert_eq!(values.last().unwrap(), "pipe:1");
        assert!(values.windows(2).any(|pair| pair == ["-pred", "none"]));
        assert!(!values.iter().any(|value| value.contains("private.png")));
        if backend == Backend::Dshow {
            assert!(values.windows(2).any(|pair| pair == ["-rtbufsize", "4M"]));
        }
    }
}

#[test]
fn ms2130_streams_its_native_lossless_1080p_mode_and_others_negotiate() {
    // Instance segments are synthetic; VID/PID and category remain public constants.
    let card = Device {
        name: "Hagibis".into(),
        id: r"@device_pnp_\\?\usb#vid_345f&pid_2130&mi_00#synthetic-ms2130-instance#{65e8773d-8f56-11d0-a3b9-00a0c9223196}\global".into(),
    };
    let mode = input_mode(Backend::Dshow, &card).expect("pinned mode");
    assert_eq!(mode.size, (super::super::frames::MAX_SIDE, 1080));
    let options = FrameOptions {
        out: PathBuf::new(),
        source: None,
        size: None,
        scale: None,
        mode: Some(mode),
        bound: None,
    };
    let values = frame_args(Backend::Dshow, &card, &options);
    let input = values.iter().position(|v| v == "-i").unwrap();
    for pair in [
        ["-video_size", "1920x1080"],
        ["-pixel_format", "yuyv422"],
        ["-framerate", "30"],
    ] {
        let at = values.windows(2).position(|w| w == pair).expect("mode");
        assert!(at < input, "input options precede -i");
    }
    // No output scaling: frames stay native for OCR, calibration and pointer mapping.
    let vf = values.windows(2).find(|w| w[0] == "-vf").expect("filter");
    assert!(vf[1].starts_with("select=") && !vf[1].contains("scale"));
    assert!(input_mode(Backend::Avfoundation, &card).is_none());
    let other = Device {
        name: "Cam Link 4K".into(),
        id: r"@device_pnp_\\?\usb#vid_0fd9&pid_0066&mi_00#synthetic-other-instance#{x}\global"
            .into(),
    };
    assert!(input_mode(Backend::Dshow, &other).is_none());
    let options = FrameOptions {
        mode: None,
        ..options
    };
    let values = frame_args(Backend::Dshow, &other, &options);
    assert!(!values
        .iter()
        .any(|v| v == "-video_size" || v == "-pixel_format"));
}

#[test]
fn signal_detects_near_uniform_black_blue_but_keeps_other_screens() {
    for pixel in [[0, 0, 0], [16, 16, 16], [0, 0, 255], [10, 25, 180]] {
        assert_eq!(signal(&pixel.repeat(100)).0, "no-signal");
    }
    let noisy_black = [[0, 0, 0], [8, 8, 8]].concat().repeat(100);
    assert_eq!(signal(&noisy_black), ("no-signal", 4.0));
    for pixel in [[255, 255, 255], [255, 0, 0], [60, 60, 60], [0, 255, 0]] {
        assert_eq!(signal(&pixel.repeat(100)).0, "present");
    }
    assert_eq!(signal(&[[0, 0, 0], [255, 255, 255]].concat()).0, "present");
    assert_eq!(signal(&[255, 255, 255]).1, 255.0);
}

#[test]
fn decode_rejects_truncated_or_unbounded_images() {
    assert_eq!(
        decode(b"not a PNG").unwrap_err().code,
        "capture.invalid_frame"
    );
    let mut bytes = Vec::new();
    let mut encoder = png::Encoder::new(&mut bytes, 2, 1);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .unwrap()
        .write_image_data(&[0; 6])
        .unwrap();
    let (w, h, rgb) = decode(&bytes).unwrap();
    assert_eq!((w, h, rgb.len()), (2, 1, 6));
    assert!(decode(&bytes[..bytes.len() / 2]).is_err());
    assert!(read_bounded(Cursor::new([0; 10]), 9).is_err());
    assert_eq!(read_bounded(Cursor::new([0; 10]), 10).unwrap().len(), 10);
    let mut oversized = Vec::new();
    let mut encoder = png::Encoder::new(&mut oversized, 4097, 1);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .unwrap()
        .write_image_data(&vec![0; 4097 * 3])
        .unwrap();
    assert!(decode(&oversized).is_err());
}

#[test]
fn fake_ffmpeg_wait() {
    if std::env::var_os("KEYCTL_UNIT_FFMPEG_SLEEP").is_some() {
        thread::sleep(Duration::from_secs(5));
    }
}

#[test]
fn process_deadline_kills_a_fake_ffmpeg() {
    let mut command = keyferry_core::process::command(std::env::current_exe().unwrap());
    command
        .args(["--exact", "capture::tests::fake_ffmpeg_wait", "--nocapture"])
        .env("KEYCTL_UNIT_FFMPEG_SLEEP", "1");
    let start = Instant::now();
    let error = bounded_output(
        command,
        Duration::from_millis(150),
        MAX_LIST_BYTES,
        Backend::current(),
    )
    .err()
    .expect("sleeping fake must time out");
    assert_eq!(error.code, "capture.timeout");
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn error_exit_codes_are_explicit() {
    for (code, exit) in [
        ("capture.arguments", 20),
        ("capture.source_required", 20),
        ("capture.source_not_found", 20),
        ("capture.ffmpeg_missing", 23),
        ("capture.timeout", 24),
        ("capture.output", 25),
        ("capture.frame_failed", 25),
    ] {
        assert_eq!(Error::new(code, "test").exit(), exit);
    }
}

#[cfg(windows)]
#[test]
fn background_capture_child_has_no_console() {
    let mut command = keyferry_core::process::command("pwsh");
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        r#"Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class CaptureConsole { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); }'; if ([CaptureConsole]::GetConsoleWindow() -ne [IntPtr]::Zero) { exit 1 }; Write-Output 'no-console'"#,
    ]);
    let output = bounded_output(command, TIMEOUT, MAX_LIST_BYTES, Backend::current()).unwrap();
    assert!(output.status.success(), "capture child acquired a console");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "no-console"
    );
}
