//! Exercise the production entry point, including ownership before authorization and crash recovery.
#![cfg(any(windows, target_os = "macos"))]

use std::{
    fs, io,
    path::Path,
    process::{Child, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(root: &Path) -> Process {
    Process(
        keyferry_core::process::command(env!("CARGO_BIN_EXE_keyferryd"))
            .arg("--installation")
            .arg(root.join("not-authorized"))
            .env("KEYFERRY_TOKEN_FILE", root.join("token"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn wait_for_lock(root: &Path, process: &mut Process) {
    let store = keyferryd::FileTokenStore::new(root.join("token"));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(process.0.try_wait().unwrap().is_none(), "daemon exited");
        if store
            .lock_instance()
            .is_err_and(|error| error.kind() == io::ErrorKind::AlreadyExists)
        {
            return;
        }
        assert!(Instant::now() < deadline, "daemon never acquired its lock");
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn unauthorized_daemon_excludes_a_second_process_and_recovers_after_crash() {
    let root = std::env::temp_dir().join(format!("keyferry-instance-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    let mut first = start(&root);
    wait_for_lock(&root, &mut first);
    let mut duplicate = start(&root);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = duplicate.0.try_wait().unwrap() {
            assert!(!status.success(), "duplicate daemon was admitted");
            break;
        }
        assert!(Instant::now() < deadline, "duplicate daemon stayed running");
        thread::sleep(Duration::from_millis(25));
    }
    assert!(first.0.try_wait().unwrap().is_none());
    assert!(
        !root.join("token").exists(),
        "authorization wait created a bearer"
    );
    drop(duplicate);
    drop(first); // Force termination: ownership must recover without deleting the lock file.
    let mut recovered = start(&root);
    wait_for_lock(&root, &mut recovered);
    drop(recovered);
    fs::remove_dir_all(root).unwrap();
}
