//! All background subprocesses inherit the same platform policy.
use std::{ffi::OsStr, process::Command};

/// Build a command that never allocates a console on Windows.
pub fn command(program: impl AsRef<OsStr>) -> Command {
    let command = Command::new(program);
    #[cfg(windows)]
    let command = {
        use std::os::windows::process::CommandExt;
        let mut command = command;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        command
    };
    command
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn child_has_no_console_even_when_parent_has_one() {
        let output = super::command("pwsh")
            .args([
                "-NoProfile", "-NonInteractive", "-Command",
                r#"Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class ChildConsole { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); }'; if ([ChildConsole]::GetConsoleWindow() -ne [IntPtr]::Zero) { exit 1 }; Write-Output 'no-console'"#,
            ])
            .output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            "no-console"
        );
    }
}
