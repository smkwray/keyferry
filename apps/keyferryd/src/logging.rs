use std::{fmt, io::Write};

/// Metadata-only daemon diagnostics, shared by every platform and listener.
pub fn log(arguments: fmt::Arguments<'_>) {
    let now = ::time::OffsetDateTime::now_utc();
    let _ = writeln!(
        std::io::stderr().lock(),
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z pid={} {arguments}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
        std::process::id(),
    );
}

#[macro_export]
macro_rules! daemon_log {
    ($($argument:tt)*) => {
        $crate::logging::log(format_args!($($argument)*))
    };
}
