#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("doctor") => doctor(),
        Some("check") => run_check(),
        Some("gen-protocol") => generate_protocol(),
        Some("package") => {
            eprintln!("release packaging is deliberately disabled until the Phase 7 gate");
            ExitCode::from(2)
        }
        Some("--help") | Some("-h") | None => {
            help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown xtask command: {other}");
            help();
            ExitCode::from(2)
        }
    }
}

fn help() {
    println!("cargo run -p xtask -- doctor");
    println!("cargo run -p xtask -- check");
    println!("cargo run -p xtask -- gen-protocol");
    println!("cargo run -p xtask -- package   # intentionally blocked until Phase 7");
}

fn doctor() -> ExitCode {
    let required = ["cargo"];
    let optional = ["python3", "python", "pio", "g++", "avrdude", "esptool.py"];
    let mut missing_required = false;

    println!("Keyferry toolchain doctor");
    for tool in required {
        let ok = command_exists(tool);
        println!("  {:<14} {}", tool, if ok { "ok" } else { "MISSING" });
        missing_required |= !ok;
    }
    for tool in optional {
        println!(
            "  {:<14} {}",
            tool,
            if command_exists(tool) {
                "ok"
            } else {
                "not found"
            }
        );
    }
    println!("  repository     {}", repository_root().display());

    if missing_required {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run_check() -> ExitCode {
    let root = repository_root();
    let python = if command_exists("python3") {
        "python3"
    } else if command_exists("python") {
        "python"
    } else {
        eprintln!("Python is required for scripts/check.py");
        return ExitCode::from(1);
    };

    let status = Command::new(python)
        .arg(root.join("scripts/check.py"))
        .arg("--strict")
        .current_dir(&root)
        .status();
    exit_from_status(status)
}

fn generate_protocol() -> ExitCode {
    let root = repository_root();
    let python = if command_exists("python3") {
        "python3"
    } else if command_exists("python") {
        "python"
    } else {
        eprintln!("Python is required to generate protocol artifacts");
        return ExitCode::from(1);
    };

    let generated = Command::new(python)
        .arg(root.join("scripts/gen_protocol.py"))
        .arg("--write")
        .current_dir(&root)
        .status();
    match generated {
        Ok(status) if status.success() => {}
        other => return exit_from_status(other),
    }

    let checked = Command::new(python)
        .arg(root.join("scripts/check_seed.py"))
        .current_dir(&root)
        .status();
    exit_from_status(checked)
}

fn command_exists(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live under repository root")
        .to_path_buf()
}

fn exit_from_status(status: std::io::Result<std::process::ExitStatus>) -> ExitCode {
    match status {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(error) => {
            eprintln!("failed to launch check: {error}");
            ExitCode::from(1)
        }
    }
}
