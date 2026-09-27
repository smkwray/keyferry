use std::{
    env, fs,
    io::{self, Read, Write},
    net::TcpListener,
    path::Path,
    process::{self, Command, Stdio},
    thread,
    time::{Duration, Instant},
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
    recipe_library_is_local_and_import_is_the_only_writer();
    recipe_run_posts_once_to_the_expanded_route();
}

const SECRET: &str = "Hunter2-recipe-secret";

fn keyboard_recipe(revision: u32) -> String {
    serde_json::json!({
        "schema": "keyferry.recipe.v1", "name": "open-terminal", "revision": revision,
        "description": "Open a URL",
        "parameters": [{"name": "url", "type": "text", "max_chars": 64}],
        "actions": [
            {"type": "chord", "keys": ["COMMAND", "SPACE"]},
            {"type": "text", "value": SECRET},
            {"type": "text", "param": "url"},
            {"type": "tap", "key": "RETURN"}
        ]
    })
    .to_string()
}

fn keyctl_recipe(
    library: &Path,
    token: &Path,
    url: &str,
    arguments: &[&str],
    stdin: Option<&str>,
) -> process::Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_keyctl"))
        .arg("--token-file")
        .arg(token)
        .args(["--url", url, "recipe"])
        .args(arguments)
        .env("KEYFERRY_RECIPE_DIR", library)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = stdin {
        // A refused run may exit before reading; the write result is irrelevant then.
        let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    }
    child
}

/// Exit status and the single JSON stdout line; no output may carry recipe or parameter text.
fn finish(child: process::Child) -> (Option<i32>, serde_json::Value, String) {
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    for stream in [&stdout, &stderr] {
        assert!(!stream.contains(SECRET), "{stream}");
        assert!(!stream.contains("COMMAND"), "{stream}");
    }
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    (
        output.status.code(),
        serde_json::from_str(stdout.trim()).unwrap(),
        stderr,
    )
}

fn recipe_library_is_local_and_import_is_the_only_writer() {
    let root = env::temp_dir().join(format!("keyctl-recipes-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    let library = root.join("library");
    let missing_token = root.join("missing-token");
    let offline = |arguments: &[&str]| {
        finish(keyctl_recipe(
            &library,
            &missing_token,
            "http://127.0.0.1:9",
            arguments,
            None,
        ))
    };

    let (code, listed, _) = offline(&["list"]);
    assert_eq!(code, Some(0), "list needs no token, service, or library");
    assert_eq!(listed["schema"], "keyferry.recipe-list.v1");
    assert_eq!(listed["library"], library.to_str().unwrap());
    assert_eq!(listed["recipes"], serde_json::json!([]));
    assert!(!library.exists(), "listing never creates the library");

    let draft = root.join("draft.json");
    fs::write(&draft, keyboard_recipe(1)).unwrap();
    let draft_path = draft.to_str().unwrap();
    let (code, validated, _) = offline(&["validate", "--input", draft_path]);
    assert_eq!(code, Some(0));
    assert_eq!(validated["schema"], "keyferry.recipe-validation.v1");
    assert_eq!(validated["name"], "open-terminal");
    assert_eq!(validated["valid"], true);
    assert_eq!(validated["route"], "sequences");
    // chord + 21 literal characters + 64 at the parameter maximum + tap, 52 ms each.
    assert_eq!(validated["planned_ms"], 87 * 52);

    let invalid = root.join("invalid.json");
    fs::write(
        &invalid,
        keyboard_recipe(1).replace("RETURN", "SECRET_KEY_Hunter2-recipe-secret"),
    )
    .unwrap();
    let (code, rejected, _) = offline(&["validate", "--input", invalid.to_str().unwrap()]);
    assert_eq!(code, Some(20));
    assert_eq!(rejected["valid"], false);
    assert_eq!(rejected["error"]["code"], "key.unknown");
    let (code, rejected, _) = offline(&["import", invalid.to_str().unwrap()]);
    assert_eq!(code, Some(20));
    assert_eq!(rejected["imported"], false);
    assert!(!library.exists(), "an invalid recipe is never written");

    let target = library.join("open-terminal.json");
    let (code, imported, _) = offline(&["import", draft_path]);
    assert_eq!(code, Some(0));
    assert_eq!(imported["schema"], "keyferry.recipe-import.v1");
    assert_eq!(imported["name"], "open-terminal");
    assert_eq!(imported["replaced"], false);
    assert_eq!(fs::read_to_string(&target).unwrap(), keyboard_recipe(1));

    fs::write(&draft, keyboard_recipe(2)).unwrap();
    let (code, refused, _) = offline(&["import", draft_path]);
    assert_eq!(code, Some(20));
    assert_eq!(refused["error"]["code"], "recipe.exists");
    assert_eq!(fs::read_to_string(&target).unwrap(), keyboard_recipe(1));
    let (code, replaced, _) = offline(&["import", draft_path, "--replace"]);
    assert_eq!(code, Some(0));
    assert_eq!(replaced["replaced"], true);
    assert_eq!(fs::read_to_string(&target).unwrap(), keyboard_recipe(2));
    let entries: Vec<_> = fs::read_dir(&library)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, ["open-terminal.json"], "no temporary file remains");

    fs::write(library.join("broken.json"), format!("{{\"{SECRET}\"")).unwrap();
    fs::write(
        library.join("other.json"),
        keyboard_recipe(1).replace("\"open-terminal\"", "\"renamed\""),
    )
    .unwrap();
    fs::write(library.join("notes.txt"), SECRET).unwrap();
    let (code, listed, _) = offline(&["list"]);
    assert_eq!(code, Some(0));
    let recipes = listed["recipes"].as_array().unwrap();
    let summary: Vec<_> = recipes
        .iter()
        .map(|entry| {
            (
                entry["name"].as_str().unwrap(),
                entry["valid"].as_bool().unwrap(),
                entry["error"]["code"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("broken", false, Some("recipe.json")),
            ("open-terminal", true, None),
            ("other", false, Some("recipe.name_mismatch")),
        ]
    );
    assert_eq!(recipes[1]["revision"], 2);
    assert_eq!(recipes[1]["description"], "Open a URL");
    assert_eq!(
        recipes[1]["parameters"],
        serde_json::json!([{"name": "url", "type": "text", "max_chars": 64}])
    );

    let (code, inspected, _) = offline(&["inspect", "open-terminal"]);
    assert_eq!(code, Some(0));
    assert_eq!(inspected["schema"], "keyferry.recipe-inspection.v1");
    assert_eq!(inspected["revision"], 2);
    assert_eq!(inspected["route"], "sequences");
    assert_eq!(inspected["chunks"], serde_json::Value::Null);
    assert!(inspected.get("actions").is_none());
    for (arguments, expected) in [
        (vec!["inspect", "../token"], "recipe.name"),
        (vec!["inspect", "missing"], "recipe.not_found"),
        (vec!["validate", "other"], "recipe.name_mismatch"),
        (vec!["frobnicate"], "input.usage"),
    ] {
        let (code, failed, _) = offline(&arguments);
        assert_eq!(code, Some(20), "{arguments:?}");
        assert_eq!(failed["error"]["code"], expected, "{arguments:?}");
    }
    let (code, _, _) = offline(&["validate", "open-terminal"]);
    assert_eq!(code, Some(0));

    // A payload on argv is refused before any token, service, or stdin is read.
    let (code, refused, _) = offline(&["run", "device-1", "open-terminal", SECRET]);
    assert_eq!(code, Some(20));
    assert_eq!(refused["schema"], "keyferry.command-result.v2");
    assert_eq!(refused["error"]["code"], "input.argv_payload_refused");
    fs::remove_dir_all(root).unwrap();
}

/// Accepts one request within a bounded wait and answers it as a terminal emission.
fn serve_once(listener: &TcpListener) -> (String, Vec<u8>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "keyctl never posted");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("{error}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        headers.push(byte[0]);
    }
    let headers = String::from_utf8(headers).unwrap();
    let length = headers
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap();
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).unwrap();
    let posted: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let response = serde_json::json!({
        "command_id": posted["command_id"], "device_id": "device-1", "outcome": "EMITTED",
        "terminal": true, "possible_start": true, "terminal_zero_confirmed": true
    })
    .to_string();
    write!(
        stream,
        "HTTP/1.1 202 Accepted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
        response.len()
    )
    .unwrap();
    (headers.lines().next().unwrap().to_owned(), body)
}

fn assert_no_further_contact(listener: &TcpListener) {
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
        "keyctl contacted the daemon more than once"
    );
}

fn recipe_run_posts_once_to_the_expanded_route() {
    let root = env::temp_dir().join(format!("keyctl-recipe-run-{}", uuid::Uuid::now_v7()));
    let library = root.join("library");
    fs::create_dir_all(&library).unwrap();
    fs::write(library.join("open-terminal.json"), keyboard_recipe(1)).unwrap();
    fs::write(
        library.join("open-file.json"),
        serde_json::json!({
            "schema": "keyferry.recipe.v1", "name": "open-file",
            "actions": [
                {"type": "move_relative", "dx_counts": 40, "dy_counts": -8},
                {"type": "double_click", "button": "button_1"},
                {"type": "tap", "key": "ESC"}
            ]
        })
        .to_string(),
    )
    .unwrap();
    let token = root.join("token");
    fs::write(&token, "test-token\n").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let run = |arguments: &[&str], stdin: Option<&str>| {
        keyctl_recipe(&library, &token, &url, arguments, stdin)
    };

    // Rejected before contact: parameters only from stdin, and strict by default.
    for (arguments, stdin, expected) in [
        (
            vec!["run", "device-1", "open-terminal", "--url-param", SECRET],
            Some("{}"),
            "input.argv_payload_refused",
        ),
        (
            vec!["run", "device-1", "open-terminal"],
            Some(""),
            "params.json",
        ),
        (
            vec!["run", "device-1", "open-terminal"],
            Some(r#"{"url":"café"}"#),
            "text.unsupported_character",
        ),
        (
            vec!["run", "device-1", "open-terminal", "--unsupported", "drop"],
            Some("{}"),
            "input.unsupported_policy",
        ),
    ] {
        let (code, rejected, _) = finish(run(&arguments, stdin));
        assert_eq!(code, Some(20), "{arguments:?}");
        assert_eq!(rejected["outcome"], "REJECTED");
        assert_eq!(rejected["error"]["code"], expected, "{arguments:?}");
        assert_no_further_contact(&listener);
    }

    let child = run(
        &[
            "run",
            "device-1",
            "open-terminal",
            "--unsupported",
            "replace",
        ],
        Some(r#"{"url":"example.test/café"}"#),
    );
    let (line, body) = serve_once(&listener);
    let (code, result, stderr) = finish(child);
    assert_no_further_contact(&listener);
    assert_eq!(line, "POST /v1/devices/device-1/sequences HTTP/1.1");
    let posted: keyferry_layouts::KeyboardSequenceV1 = serde_json::from_slice(&body).unwrap();
    assert!(keyferry_layouts::compile_sequence(&posted).is_ok());
    assert_eq!(
        uuid::Uuid::parse_str(&posted.command_id)
            .unwrap()
            .get_version_num(),
        7
    );
    assert_eq!(posted.profile, "windows-us");
    assert_eq!(
        serde_json::to_value(&posted.actions).unwrap(),
        serde_json::json!([
            {"type": "chord", "keys": ["LEFT_GUI", "SPACE"]},
            {"type": "text", "value": SECRET},
            {"type": "text", "value": "example.test/caf?"},
            {"type": "tap", "key": "ENTER"}
        ])
    );
    assert_eq!(code, Some(0));
    assert_eq!(result["schema"], "keyferry.command-result.v2");
    assert_eq!(result["command_id"], posted.command_id.as_str());
    assert_eq!(result["outcome"], "EMITTED");
    assert_eq!(
        stderr.trim(),
        r#"{"replacements":1,"schema":"keyferry.recipe-replacements.v1"}"#
    );

    let child = run(&["run", "device-1", "open-file", "--detach"], None);
    let (line, body) = serve_once(&listener);
    let (code, result, _) = finish(child);
    assert_no_further_contact(&listener);
    assert_eq!(line, "POST /v1/devices/device-1/input-sequences HTTP/1.1");
    let posted = keyferry_layouts::parse_input_sequence_json(&body).unwrap();
    let compiled = keyferry_layouts::compile_input_sequence(&posted).unwrap();
    assert!(compiled.has_pointer && compiled.has_keyboard);
    assert_eq!(
        serde_json::to_value(&posted.actions[2]).unwrap(),
        serde_json::json!({"type": "tap", "key": "ESCAPE"})
    );
    assert!(compiled
        .gestures
        .iter()
        .any(|gesture| matches!(gesture, keyferry_layouts::InputGesture::DoubleClick { .. })));
    assert_eq!(code, Some(0));
    assert_eq!(result["command_id"], posted.command_id.as_str());
    fs::remove_dir_all(root).unwrap();
}
