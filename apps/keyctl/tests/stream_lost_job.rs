use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    thread,
};

const RECEIPT_SCHEMA: &str = "keyferry.text-stream-receipt.v1";

fn receipt(job_id: &str) -> String {
    serde_json::json!({
        "schema": RECEIPT_SCHEMA,
        "epoch": "epoch-1",
        "job_id": job_id,
        "outcome": null,
        "terminal": false,
        "confirmed_prefix": {"bytes": "0", "scalars": "0", "children": "0", "gestures": "0"},
        "not_dispatched_from": {"bytes": "0", "scalars": "0"},
        "next_index": "0",
        "current_child": null,
        "possible_start": false,
        "terminal_zero_confirmed": true,
    })
    .to_string()
}

/// Admits the stream and its first child, then answers every status poll the way a restarted
/// daemon does: it no longer knows the job.
fn serve_then_forget(listener: TcpListener) {
    let mut job_id = String::new();
    loop {
        let (mut stream, _) = listener.accept().expect("accept keyctl request");
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).expect("read request headers");
            request.push(byte[0]);
        }
        let headers = String::from_utf8(request).expect("ASCII headers");
        let length = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0_u8; length];
        stream.read_exact(&mut body).expect("read request body");
        let line = headers.lines().next().unwrap_or_default().to_owned();
        let (status, response) = if line.starts_with("GET /v1/capabilities ") {
            (
                "200 OK",
                r#"{"epoch":"epoch-1","text_stream":"keyferry.text-stream.v1"}"#.to_owned(),
            )
        } else if line.starts_with("POST /v1/devices/device-1/text-streams ") {
            let create: Value = serde_json::from_slice(&body).expect("create body");
            job_id = create["job_id"].as_str().expect("job id").to_owned();
            ("201 Created", receipt(&job_id))
        } else if line.contains("/parts/0 ") {
            ("202 Accepted", receipt(&job_id))
        } else {
            assert!(line.starts_with("GET /v1/devices/device-1/text-streams/"));
            (
                "404 Not Found",
                r#"{"error":"text_stream.not_found","outcome":"REJECTED","command_id":null}"#
                    .to_owned(),
            )
        };
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len()
        )
        .expect("write response");
        if status.starts_with("404") {
            return;
        }
    }
}

#[test]
fn stream_forgotten_after_dispatch_is_unknown_not_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake daemon");
    let port = listener.local_addr().expect("fake daemon address").port();
    let server = thread::spawn(move || serve_then_forget(listener));
    let unique = uuid::Uuid::now_v7();
    let token_path = std::env::temp_dir().join(format!("keyferry-keyctl-{unique}.token"));
    let source_path = std::env::temp_dir().join(format!("keyferry-keyctl-{unique}.txt"));
    fs::write(&token_path, "test-token\n").expect("write disposable token");
    fs::write(&source_path, "abc").expect("write source");

    let output = Command::new(env!("CARGO_BIN_EXE_keyctl"))
        .args(["--url", &format!("http://127.0.0.1:{port}"), "--token-file"])
        .arg(&token_path)
        .args(["stream", "device-1", "--input"])
        .arg(&source_path)
        .output()
        .expect("run keyctl stream");
    server.join().expect("fake daemon");
    let _ = fs::remove_file(&token_path);
    let _ = fs::remove_file(&source_path);

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let result: Value = serde_json::from_str(stdout.lines().last().expect("result line"))
        .expect("JSON result line");
    assert_eq!(output.status.code(), Some(12), "{stdout}");
    assert_eq!(result["schema"], "keyferry.text-stream-result.v1");
    assert_eq!(result["outcome"], "UNKNOWN");
    assert_eq!(result["possible_start"], true);
    assert_eq!(result["terminal_zero_confirmed"], false);
    assert!(!stdout.contains("abc"));
}
