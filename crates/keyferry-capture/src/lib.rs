#![forbid(unsafe_code)]
pub mod capture;
pub mod frames;
pub mod ocr;

// Piped background children must not create a Windows console (including PATH shims).
pub(crate) fn hide_console(command: &mut std::process::Command) -> &mut std::process::Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    command
}
