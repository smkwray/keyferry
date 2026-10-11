//! All background subprocesses inherit the same platform policy.
use std::{ffi::OsStr, process::Command};

/// Nonsecret, editable preselection for the separately launched owner prompt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum SecureTextWake {
    None = 0,
    Mouse = 1,
    MacLogin = 2,
}

impl SecureTextWake {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "mouse" => Some(Self::Mouse),
            "mac-login" => Some(Self::MacLogin),
            _ => None,
        }
    }

    pub fn argument(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Mouse => "mouse",
            Self::MacLogin => "mac-login",
        }
    }
}

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
