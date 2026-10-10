fn main() {
    println!("cargo::rustc-check-cfg=cfg(keyferry_daemon_tests)");
    println!("cargo::rustc-cfg=keyferry_daemon_tests");
}
