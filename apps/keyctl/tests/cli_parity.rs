use std::{
    env, fs,
    io::{Read, Write},
    path::Path,
    process::{self, Command, Stdio},
};

const DEVICE: &str = "019d1234-5678-7abc-8123-456789abcdef";
const PASSWORD: &str = "test-only-password\n";

fn main() {
    if let Ok(capture) = env::var("KEYCTL_TEST_CAPTURE") {
        let args = env::args().skip(1).collect::<Vec<_>>();
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let record = serde_json::json!({ "args": args, "stdin_ok": input == PASSWORD });
        let mut capture = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(capture)
            .unwrap();
        writeln!(capture, "{record}").unwrap();
        if args.first().is_some_and(|arg| arg == "local-recover") {
            println!(
                "{{\"schema\":\"keyferry.local-recovery-result.v1\",\"outcome\":\"UNKNOWN\"}}"
            );
            process::exit(2);
        }
        println!("{{\"schema\":\"keyferry.local-status.v1\"}}");
        return;
    }
    run_tests();
}

fn run_tests() {
    let keyctl = Path::new(env!("CARGO_BIN_EXE_keyctl"));
    let directory = env::temp_dir().join(format!("keyctl-cli-parity-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&directory).unwrap();
    let missing_token = directory.join("missing-token");
    for arguments in [Vec::<&str>::new(), vec!["--help"], vec!["help"]] {
        let output = Command::new(keyctl)
            .args([
                "--token-file",
                missing_token.to_str().unwrap(),
                "--url",
                "http://127.0.0.1:9",
            ])
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "offline help must not need a token or service"
        );
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("local-recover"));
    }
    for (name, arguments, expected_success) in [
        (
            "status",
            vec![
                "local-status",
                "--owner-kit",
                "test-kit",
                "--device",
                DEVICE,
            ],
            true,
        ),
        (
            "recover",
            vec![
                "local-recover",
                "--owner-kit",
                "test-kit",
                "--device",
                DEVICE,
                "restart-network",
            ],
            false,
        ),
    ] {
        let capture = directory.join(format!("{name}.json"));
        let mut child = Command::new(keyctl)
            .args(&arguments)
            .env("KEYFERRY_PAIRING_EXE", env::current_exe().unwrap())
            .env("KEYCTL_TEST_CAPTURE", &capture)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(PASSWORD.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.success(), expected_success);
        let records = fs::read_to_string(&capture).unwrap();
        assert_eq!(
            records.lines().count(),
            1,
            "the helper must be invoked once"
        );
        let record: serde_json::Value = serde_json::from_str(records.trim()).unwrap();
        assert_eq!(record["args"], serde_json::json!(arguments));
        assert_eq!(record["stdin_ok"], true);
        if name == "recover" {
            assert!(String::from_utf8(output.stdout)
                .unwrap()
                .contains("UNKNOWN"));
        }
        fs::remove_file(capture).unwrap();
    }
    let rejected_capture = directory.join("invalid-device.json");
    let rejected = Command::new(keyctl)
        .args([
            "local-recover",
            "--owner-kit",
            "test-kit",
            "--device",
            "019D1234-5678-7ABC-8123-456789ABCDEF",
            "restart-network",
        ])
        .env("KEYFERRY_PAIRING_EXE", env::current_exe().unwrap())
        .env("KEYCTL_TEST_CAPTURE", &rejected_capture)
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(20));
    assert!(
        !rejected_capture.exists(),
        "invalid selection must not launch the helper"
    );
    fs::remove_dir(directory).unwrap();
}
