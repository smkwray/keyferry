use super::*;
pub(super) fn mcp_daemon_smoke(directory: &Path) {
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
    let mut child = Command::new(cli_executable())
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
