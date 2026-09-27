#![cfg(windows)]

use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::windows::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const CTRL_BREAK_EVENT: u32 = 1;

#[link(name = "Kernel32")]
unsafe extern "system" {
    fn GenerateConsoleCtrlEvent(ctrl_event: u32, process_group_id: u32) -> i32;
}

#[test]
#[ignore = "requires an attached Windows console for a focused native signal gate"]
fn ctrl_break_cancels_once_and_reconciles_without_resubmission() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake daemon");
    let port = listener.local_addr().expect("fake daemon address").port();
    let (submitted_tx, submitted_rx) = mpsc::channel();
    let server = thread::spawn(move || serve_until_reconciled(listener, submitted_tx));

    let token_path = temporary_token_path();
    fs::write(&token_path, "test-token\n").expect("write disposable token");
    let mut child = Command::new(env!("CARGO_BIN_EXE_keyctl"))
        .args(["--url", &format!("http://127.0.0.1:{port}"), "--token-file"])
        .arg(&token_path)
        .args(["sequence", "device-1"])
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn isolated keyctl process group");
    let input = r#"{"schema":"keyferry.keyboard-sequence.v1","profile":"windows-us","arm":"command-scoped","start_within_ms":5000,"actions":[{"type":"tap","key":"ENTER"}]}"#;
    child
        .stdin
        .take()
        .expect("keyctl stdin")
        .write_all(input.as_bytes())
        .expect("write sequence stdin");

    submitted_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("keyctl submitted before signal");
    thread::sleep(Duration::from_millis(50));
    // SAFETY: the child was created as a distinct process group whose ID is its
    // process ID. CTRL_BREAK_EVENT is scoped to that group, so this does not
    // signal the test runner or an unrelated console process.
    assert_ne!(
        unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id()) },
        0,
        "send Ctrl+Break to isolated keyctl group"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll keyctl") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("keyctl did not finish bounded cancellation reconciliation");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .expect("keyctl stdout")
        .read_to_string(&mut stdout)
        .expect("read keyctl stdout");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("keyctl stderr")
        .read_to_string(&mut stderr)
        .expect("read keyctl stderr");
    let counts = server.join().expect("fake daemon joins");
    let _ = fs::remove_file(&token_path);

    assert_eq!(status.code(), Some(11), "stderr: {stderr}");
    assert_eq!(stdout.lines().count(), 1, "stdout must be one JSON line");
    let result: Value = serde_json::from_str(stdout.trim()).expect("compact result JSON");
    assert_eq!(result["outcome"], "ABORTED");
    assert_eq!(result["terminal_zero_confirmed"], true);
    assert!(stderr.is_empty(), "stderr must remain sanitized and empty");
    assert_eq!(counts, (1, 1), "one submit and one cancellation only");
}

#[test]
#[ignore = "requires an attached Windows console for a focused native signal gate"]
fn stream_ctrl_break_cancels_parent_once_without_resubmitting_the_child() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake daemon");
    let port = listener.local_addr().expect("fake daemon address").port();
    let (submitted_tx, submitted_rx) = mpsc::channel();
    let server = thread::spawn(move || serve_stream_until_reconciled(listener, submitted_tx));

    let token_path = temporary_token_path();
    let source_path = temporary_source_path();
    fs::write(&token_path, "test-token\n").expect("write disposable token");
    fs::write(&source_path, "three harmless characters").expect("write disposable source");
    let mut child = Command::new(env!("CARGO_BIN_EXE_keyctl"))
        .args(["--url", &format!("http://127.0.0.1:{port}"), "--token-file"])
        .arg(&token_path)
        .args(["stream", "device-1", "--input"])
        .arg(&source_path)
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn isolated keyctl stream process group");

    submitted_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stream child submitted before signal");
    thread::sleep(Duration::from_millis(50));
    // SAFETY: the child owns a distinct process group, as in the sequence
    // test above. The event cannot target the test runner's process group.
    assert_ne!(
        unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id()) },
        0,
        "send Ctrl+Break to isolated keyctl stream group"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll keyctl stream") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("keyctl stream did not finish bounded cancellation reconciliation");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .expect("keyctl stream stdout")
        .read_to_string(&mut stdout)
        .expect("read keyctl stream stdout");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("keyctl stream stderr")
        .read_to_string(&mut stderr)
        .expect("read keyctl stream stderr");
    let counts = server.join().expect("fake stream daemon joins");
    let _ = fs::remove_file(&token_path);
    let _ = fs::remove_file(&source_path);

    assert_eq!(status.code(), Some(11), "stderr: {stderr}");
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(
        lines.len(),
        4,
        "created, attempt, final progress, and terminal JSONL only"
    );
    let result: Value = serde_json::from_str(lines[3]).expect("compact terminal result JSON");
    assert_eq!(result["schema"], "keyferry.text-stream-result.v1");
    assert_eq!(result["outcome"], "ABORTED");
    assert_eq!(result["terminal_zero_confirmed"], true);
    assert_eq!(result["confirmed_prefix"]["bytes"], "0");
    assert!(stderr.is_empty(), "stderr must remain sanitized and empty");
    assert_eq!(
        counts,
        (1, 1, 1),
        "one create, child, and cancellation only"
    );
}

fn serve_until_reconciled(listener: TcpListener, submitted: mpsc::Sender<()>) -> (usize, usize) {
    let mut sequence_posts = 0;
    let mut cancel_posts = 0;
    loop {
        let (mut stream, _) = listener.accept().expect("accept keyctl request");
        let request = read_request(&mut stream);
        if request.starts_with("POST /v1/devices/device-1/sequences HTTP/1.1\r\n") {
            sequence_posts += 1;
            submitted.send(()).expect("announce submission");
            respond(
                &mut stream,
                202,
                r#"{"outcome":"QUEUED","terminal":false,"possible_start":false,"terminal_zero_confirmed":false}"#,
            );
        } else if request.starts_with("POST /v1/devices/device-1/cancel HTTP/1.1\r\n") {
            cancel_posts += 1;
            respond(&mut stream, 200, "{}");
        } else if request.starts_with("GET /v1/devices/device-1/commands/") {
            if cancel_posts == 0 {
                respond(
                    &mut stream,
                    200,
                    r#"{"outcome":"QUEUED","terminal":false,"possible_start":false,"terminal_zero_confirmed":false}"#,
                );
            } else {
                respond(
                    &mut stream,
                    200,
                    r#"{"outcome":"ABORTED","terminal":true,"possible_start":true,"terminal_zero_confirmed":true}"#,
                );
                break;
            }
        } else {
            respond(&mut stream, 404, "{}");
        }
    }
    (sequence_posts, cancel_posts)
}

fn serve_stream_until_reconciled(
    listener: TcpListener,
    submitted: mpsc::Sender<()>,
) -> (usize, usize, usize) {
    const EPOCH: &str = "019a0000-0000-7000-8000-000000000001";
    let mut creates = 0;
    let mut parts = 0;
    let mut cancels = 0;
    let mut job_id = String::new();
    let mut child_id = String::new();
    loop {
        let (mut stream, _) = listener.accept().expect("accept keyctl stream request");
        let request = read_request(&mut stream);
        if request.starts_with("GET /v1/capabilities HTTP/1.1\r\n") {
            respond(
                &mut stream,
                200,
                &format!(r#"{{"epoch":"{EPOCH}","text_stream":"keyferry.text-stream.v1"}}"#),
            );
        } else if request.starts_with("POST /v1/devices/device-1/text-streams HTTP/1.1\r\n") {
            creates += 1;
            let value: Value = serde_json::from_str(request_body(&request)).expect("create JSON");
            job_id = value["job_id"].as_str().expect("job ID").to_owned();
            respond(
                &mut stream,
                201,
                &stream_receipt(EPOCH, &job_id, None, false, None),
            );
        } else if request.starts_with(&format!(
            "POST /v1/devices/device-1/text-streams/{job_id}/parts/0 HTTP/1.1\r\n"
        )) {
            parts += 1;
            let value: Value = serde_json::from_str(request_body(&request)).expect("part JSON");
            child_id = value["child_command_id"]
                .as_str()
                .expect("child command ID")
                .to_owned();
            submitted.send(()).expect("announce stream submission");
            respond(
                &mut stream,
                202,
                &stream_receipt(EPOCH, &job_id, None, false, Some(&child_id)),
            );
        } else if request.starts_with(&format!(
            "POST /v1/devices/device-1/text-streams/{job_id}/cancel HTTP/1.1\r\n"
        )) {
            cancels += 1;
            respond(
                &mut stream,
                200,
                &stream_receipt(EPOCH, &job_id, Some("ABORTED"), true, None),
            );
        } else if request.starts_with(&format!(
            "GET /v1/devices/device-1/text-streams/{job_id} HTTP/1.1\r\n"
        )) {
            let body = if cancels == 0 {
                stream_receipt(EPOCH, &job_id, None, false, Some(&child_id))
            } else {
                stream_receipt(EPOCH, &job_id, Some("ABORTED"), true, None)
            };
            respond(&mut stream, 200, &body);
            if cancels != 0 {
                break;
            }
        } else {
            respond(&mut stream, 404, "{}");
        }
    }
    (creates, parts, cancels)
}

fn stream_receipt(
    epoch: &str,
    job_id: &str,
    outcome: Option<&str>,
    terminal: bool,
    child_id: Option<&str>,
) -> String {
    serde_json::json!({
        "schema": "keyferry.text-stream-receipt.v1",
        "epoch": epoch,
        "job_id": job_id,
        "outcome": outcome,
        "terminal": terminal,
        "confirmed_prefix": {"bytes":"0","scalars":"0","children":"0","gestures":"0"},
        "not_dispatched_from": {"bytes":"0","scalars":"0"},
        "next_index": "0",
        "current_child": child_id.map(|command_id| serde_json::json!({"command_id":command_id})),
        "possible_start": terminal,
        "terminal_zero_confirmed": terminal,
    })
    .to_string()
}

fn request_body(request: &str) -> &str {
    request.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

fn read_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set request timeout");
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let count = stream.read(&mut buffer).expect("read request");
        assert_ne!(count, 0, "request ended before headers");
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("Content-Length: ")
                .and_then(|value| value.parse::<usize>().ok())
        })
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let count = stream.read(&mut buffer).expect("read request body");
        assert_ne!(count, 0, "request ended before body");
        bytes.extend_from_slice(&buffer[..count]);
    }
    String::from_utf8(bytes).expect("keyctl request is UTF-8")
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = if status == 202 { "Accepted" } else { "OK" };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write fake response");
}

fn temporary_token_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "keyferry-keyctl-{}-{unique}.token",
        std::process::id()
    ))
}

fn temporary_source_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "keyferry-keyctl-{}-{unique}.txt",
        std::process::id()
    ))
}
