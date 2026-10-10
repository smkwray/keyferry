use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::Mutex,
};

/// A persisted log is rotated at this size, keeping one previous file beside it.
const MAX_LOG_BYTES: u64 = 1024 * 1024;

static FILE: Mutex<Option<LogFile>> = Mutex::new(None);

/// Metadata-only daemon diagnostics, shared by every platform and listener.
pub fn log(arguments: fmt::Arguments<'_>) {
    let now = ::time::OffsetDateTime::now_utc();
    let line = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z pid={} {arguments}\n",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
        std::process::id(),
    );
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
    if let Some(file) = FILE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_mut()
    {
        let _ = file.append(line.as_bytes());
    }
}

/// Also appends every later line to `path`, for a service whose stderr is discarded.
pub fn persist_to(path: PathBuf) -> io::Result<()> {
    let file = LogFile::open(path, MAX_LOG_BYTES)?;
    *FILE.lock().unwrap_or_else(|error| error.into_inner()) = Some(file);
    Ok(())
}

/// `%LOCALAPPDATA%\keyferry\logs\keyferryd.log`: the Windows service runs without a console.
#[cfg(windows)]
pub fn default_file() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|root| {
        PathBuf::from(root)
            .join("keyferry")
            .join("logs")
            .join("keyferryd.log")
    })
}

struct LogFile {
    path: PathBuf,
    file: File,
    len: u64,
    limit: u64,
}

impl LogFile {
    fn open(path: PathBuf, limit: u64) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            path,
            file,
            len,
            limit,
        })
    }

    fn append(&mut self, line: &[u8]) -> io::Result<()> {
        if self.len > 0 && self.len + line.len() as u64 > self.limit {
            let mut previous = self.path.clone().into_os_string();
            previous.push(".1");
            fs::rename(&self.path, previous)?;
            *self = Self::open(self.path.clone(), self.limit)?;
        }
        self.file.write_all(line)?;
        self.len += line.len() as u64;
        Ok(())
    }
}

#[macro_export]
macro_rules! daemon_log {
    ($($argument:tt)*) => {
        $crate::logging::log(format_args!($($argument)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_log_rotates_to_one_bounded_previous_file() {
        let root = std::env::temp_dir().join(format!("keyferry-log-{}", uuid::Uuid::now_v7()));
        let path = root.join("logs").join("keyferryd.log");
        let mut file = LogFile::open(path.clone(), 64).unwrap();
        for index in 0..10 {
            file.append(format!("line {index:02} metadata only........\n").as_bytes())
                .unwrap();
        }
        let current = fs::read_to_string(&path).unwrap();
        let previous = fs::read_to_string(root.join("logs").join("keyferryd.log.1")).unwrap();
        assert!(current.len() <= 64 && previous.len() <= 64);
        assert!(current.ends_with("line 09 metadata only........\n"));
        assert!(previous.ends_with("line 07 metadata only........\n"));
        drop(file);
        let reopened = LogFile::open(path, 64).unwrap();
        assert_eq!(reopened.len, current.len() as u64);
        fs::remove_dir_all(root).unwrap();
    }
}
