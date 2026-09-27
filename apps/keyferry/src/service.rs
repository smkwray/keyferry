//! Keyferry's background service runs only while the desktop app is open (D-20260926-04).
//!
//! The installers define the service in exactly one verified place, a Task Scheduler task on
//! Windows or a launchd agent on macOS, with no automatic start. The app starts it on launch and
//! stops it on exit. Where no service is defined, as in a development run, both steps report
//! [`ServiceOutcome::NotInstalled`] and change nothing.

use crate::tailnet::{bounded_lossy, hide_console, output_with_timeout, DiscoveryError};
use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

/// Must equal `$taskName` in `scripts/install_windows_controller.ps1`.
pub const WINDOWS_TASK_NAME: &str = "Keyferry Desktop";
/// Must equal `launch_label` in `scripts/install_unix_controller.sh`.
pub const MACOS_LAUNCH_LABEL: &str = "io.github.smkwray.keyferryd";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_COMMAND_OUTPUT: usize = 256 * 1024;
const MAX_DETAIL: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    pub program: PathBuf,
    pub args: Vec<OsString>,
}

impl Invocation {
    fn new<I, S>(program: &Path, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            program: program.to_path_buf(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Completion {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Runs one service-manager command; `Err` means the command itself could not run.
pub type Runner<'a> = dyn FnMut(&Invocation) -> Result<Completion, String> + 'a;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceOutcome {
    /// The service manager accepted the start; an already running service is left as it is.
    Started,
    Stopped,
    NotRunning,
    NotInstalled,
    Unsupported,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceManager {
    TaskScheduler {
        schtasks: PathBuf,
    },
    Launchd {
        launchctl: PathBuf,
        domain: String,
        /// The installed agent definition, when it exists on disk.
        agent: Option<PathBuf>,
    },
    Unsupported,
}

impl ServiceManager {
    /// The service manager for this computer and user.
    pub fn for_this_computer(run: &mut Runner<'_>) -> Result<Self, String> {
        if cfg!(windows) {
            let root = env::var_os("SystemRoot").ok_or("SystemRoot is not set")?;
            Ok(Self::task_scheduler(Path::new(&root)))
        } else if cfg!(target_os = "macos") {
            let home = env::var_os("HOME").ok_or("HOME is not set")?;
            let id = run(&Invocation::new(Path::new("/usr/bin/id"), ["-u"]))?;
            let uid = id
                .success
                .then(|| id.stdout.trim().parse::<u32>().ok())
                .flatten()
                .ok_or("could not read this user's ID")?;
            Ok(Self::launchd(uid, Path::new(&home)))
        } else {
            Ok(Self::Unsupported)
        }
    }

    #[must_use]
    pub fn task_scheduler(system_root: &Path) -> Self {
        Self::TaskScheduler {
            schtasks: system_root.join("System32").join("schtasks.exe"),
        }
    }

    #[must_use]
    pub fn launchd(uid: u32, home: &Path) -> Self {
        let agent = home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{MACOS_LAUNCH_LABEL}.plist"));
        Self::Launchd {
            launchctl: PathBuf::from("/bin/launchctl"),
            domain: format!("gui/{uid}"),
            agent: agent.is_file().then_some(agent),
        }
    }

    /// Starts the service unless it is already running.
    pub fn start(&self, run: &mut Runner<'_>) -> ServiceOutcome {
        let result = match self {
            Self::TaskScheduler { schtasks } => start_task(schtasks, run),
            Self::Launchd {
                launchctl,
                domain,
                agent,
            } => start_agent(launchctl, domain, agent.as_deref(), run),
            Self::Unsupported => Ok(ServiceOutcome::Unsupported),
        };
        result.unwrap_or_else(ServiceOutcome::Failed)
    }

    /// Stops the service and leaves its definition in place for the next launch.
    pub fn stop(&self, run: &mut Runner<'_>) -> ServiceOutcome {
        let result = match self {
            Self::TaskScheduler { schtasks } => stop_task(schtasks, run),
            Self::Launchd {
                launchctl, domain, ..
            } => stop_agent(launchctl, domain, run),
            Self::Unsupported => Ok(ServiceOutcome::Unsupported),
        };
        result.unwrap_or_else(ServiceOutcome::Failed)
    }
}

fn task_command(schtasks: &Path, verb: &str) -> Invocation {
    Invocation::new(schtasks, [verb, "/TN", WINDOWS_TASK_NAME])
}

// The installer registers the task with MultipleInstances=IgnoreNew, so /Run leaves a running
// daemon alone.
fn start_task(schtasks: &Path, run: &mut Runner<'_>) -> Result<ServiceOutcome, String> {
    if !run(&task_command(schtasks, "/Query"))?.success {
        return Ok(ServiceOutcome::NotInstalled);
    }
    require(
        run(&task_command(schtasks, "/Run"))?,
        "Task Scheduler did not start the service",
    )?;
    Ok(ServiceOutcome::Started)
}

fn stop_task(schtasks: &Path, run: &mut Runner<'_>) -> Result<ServiceOutcome, String> {
    if !run(&task_command(schtasks, "/Query"))?.success {
        return Ok(ServiceOutcome::NotInstalled);
    }
    require(
        run(&task_command(schtasks, "/End"))?,
        "Task Scheduler did not stop the service",
    )?;
    Ok(ServiceOutcome::Stopped)
}

// `kickstart` without `-k` leaves a running daemon alone. An agent that exists on disk but is not
// loaded is loaded first; it has RunAtLoad=false, so loading alone starts nothing.
fn start_agent(
    launchctl: &Path,
    domain: &str,
    agent: Option<&Path>,
    run: &mut Runner<'_>,
) -> Result<ServiceOutcome, String> {
    let target = format!("{domain}/{MACOS_LAUNCH_LABEL}");
    if !run(&Invocation::new(launchctl, ["print", target.as_str()]))?.success {
        let Some(agent) = agent else {
            return Ok(ServiceOutcome::NotInstalled);
        };
        let bootstrap = Invocation::new(
            launchctl,
            [
                OsString::from("bootstrap"),
                OsString::from(domain),
                agent.as_os_str().to_owned(),
            ],
        );
        require(run(&bootstrap)?, "launchd did not load the service")?;
    }
    require(
        run(&Invocation::new(launchctl, ["kickstart", target.as_str()]))?,
        "launchd did not start the service",
    )?;
    Ok(ServiceOutcome::Started)
}

// SIGTERM ends the daemon; with KeepAlive=false launchd does not restart it, and the agent stays
// loaded for the next launch.
fn stop_agent(
    launchctl: &Path,
    domain: &str,
    run: &mut Runner<'_>,
) -> Result<ServiceOutcome, String> {
    let target = format!("{domain}/{MACOS_LAUNCH_LABEL}");
    let printed = run(&Invocation::new(launchctl, ["print", target.as_str()]))?;
    if !printed.success {
        return Ok(ServiceOutcome::NotInstalled);
    }
    if launchd_pid(&printed.stdout).is_none() {
        return Ok(ServiceOutcome::NotRunning);
    }
    require(
        run(&Invocation::new(
            launchctl,
            ["kill", "TERM", target.as_str()],
        ))?,
        "launchd did not stop the service",
    )?;
    Ok(ServiceOutcome::Stopped)
}

/// The running process ID from `launchctl print`, which omits `pid` while the job is idle.
fn launchd_pid(printed: &str) -> Option<u32> {
    printed.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        match (words.next(), words.next(), words.next(), words.next()) {
            (Some("pid"), Some("="), Some(pid), None) => pid.parse().ok(),
            _ => None,
        }
    })
}

fn require(completion: Completion, action: &str) -> Result<(), String> {
    if completion.success {
        return Ok(());
    }
    let detail = if completion.stderr.trim().is_empty() {
        completion.stdout.trim()
    } else {
        completion.stderr.trim()
    };
    Err(if detail.is_empty() {
        format!("{action}.")
    } else {
        format!("{action}: {detail}")
    })
}

/// Runs a service-manager command without a console window, bounded in time and output.
pub fn run_command(invocation: &Invocation) -> Result<Completion, String> {
    let mut command = Command::new(&invocation.program);
    command.args(&invocation.args).stdin(Stdio::null());
    hide_console(&mut command);
    let output =
        output_with_timeout(command, COMMAND_TIMEOUT, MAX_COMMAND_OUTPUT).map_err(|error| {
            match error {
                DiscoveryError::Timeout => format!(
                    "{} did not finish within {} seconds",
                    invocation.program.display(),
                    COMMAND_TIMEOUT.as_secs()
                ),
                DiscoveryError::Launch(error) => {
                    format!("could not run {}: {error}", invocation.program.display())
                }
                DiscoveryError::OutputTooLarge(bytes) => format!(
                    "{} returned {bytes} bytes of output",
                    invocation.program.display()
                ),
                other => other.to_string(),
            }
        })?;
    Ok(Completion {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: bounded_lossy(&output.stderr, MAX_DETAIL),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Script {
        seen: Vec<Invocation>,
        replies: VecDeque<Result<Completion, String>>,
    }

    impl Script {
        fn new(replies: impl IntoIterator<Item = Result<Completion, String>>) -> Self {
            Self {
                seen: Vec::new(),
                replies: replies.into_iter().collect(),
            }
        }

        fn run(&mut self, invocation: &Invocation) -> Result<Completion, String> {
            self.seen.push(invocation.clone());
            self.replies.pop_front().expect("unexpected extra command")
        }

        fn commands(&self) -> Vec<String> {
            self.seen
                .iter()
                .map(|invocation| {
                    std::iter::once(invocation.program.to_string_lossy().into_owned())
                        .chain(
                            invocation
                                .args
                                .iter()
                                .map(|arg| arg.to_string_lossy().into_owned()),
                        )
                        .collect::<Vec<_>>()
                        .join(" | ")
                })
                .collect()
        }
    }

    fn ok(stdout: &str) -> Result<Completion, String> {
        Ok(Completion {
            success: true,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        })
    }

    fn failed(stderr: &str) -> Result<Completion, String> {
        Ok(Completion {
            success: false,
            stdout: String::new(),
            stderr: stderr.to_owned(),
        })
    }

    fn windows() -> ServiceManager {
        ServiceManager::task_scheduler(Path::new(r"C:\Windows"))
    }

    fn schtasks(verb: &str) -> String {
        let program = Path::new(r"C:\Windows")
            .join("System32")
            .join("schtasks.exe");
        format!("{} | {verb} | /TN | Keyferry Desktop", program.display())
    }

    fn macos(agent: Option<&str>) -> ServiceManager {
        ServiceManager::Launchd {
            launchctl: PathBuf::from("/bin/launchctl"),
            domain: "gui/501".to_owned(),
            agent: agent.map(PathBuf::from),
        }
    }

    const PLIST: &str = "/Users/owner/Library/LaunchAgents/io.github.smkwray.keyferryd.plist";

    #[test]
    fn windows_start_runs_the_registered_task() {
        let mut script = Script::new([ok(""), ok("")]);
        let outcome = windows().start(&mut |invocation| script.run(invocation));
        assert_eq!(outcome, ServiceOutcome::Started);
        assert_eq!(script.commands(), [schtasks("/Query"), schtasks("/Run")]);
    }

    #[test]
    fn windows_stop_ends_the_registered_task() {
        let mut script = Script::new([ok(""), ok("")]);
        let outcome = windows().stop(&mut |invocation| script.run(invocation));
        assert_eq!(outcome, ServiceOutcome::Stopped);
        assert_eq!(script.commands(), [schtasks("/Query"), schtasks("/End")]);
    }

    #[test]
    fn windows_without_a_registered_task_changes_nothing() {
        for stop in [false, true] {
            let mut script = Script::new([failed("ERROR: The system cannot find the file")]);
            let mut run = |invocation: &Invocation| script.run(invocation);
            let outcome = if stop {
                windows().stop(&mut run)
            } else {
                windows().start(&mut run)
            };
            assert_eq!(outcome, ServiceOutcome::NotInstalled);
            assert_eq!(script.commands(), [schtasks("/Query")]);
        }
    }

    #[test]
    fn windows_start_failure_is_reported_with_its_reason() {
        let mut script = Script::new([ok(""), failed("ERROR: Access is denied.")]);
        let outcome = windows().start(&mut |invocation| script.run(invocation));
        assert_eq!(
            outcome,
            ServiceOutcome::Failed(
                "Task Scheduler did not start the service: ERROR: Access is denied.".to_owned()
            )
        );
    }

    #[test]
    fn command_that_cannot_run_is_a_failure_not_a_missing_service() {
        let mut script = Script::new([Err("could not run schtasks.exe".to_owned())]);
        let outcome = windows().start(&mut |invocation| script.run(invocation));
        assert_eq!(
            outcome,
            ServiceOutcome::Failed("could not run schtasks.exe".to_owned())
        );
    }

    #[test]
    fn macos_start_kickstarts_the_loaded_agent_without_restarting_it() {
        let mut script = Script::new([ok("state = not running\n"), ok("")]);
        let outcome = macos(Some(PLIST)).start(&mut |invocation| script.run(invocation));
        assert_eq!(outcome, ServiceOutcome::Started);
        assert_eq!(
            script.commands(),
            [
                "/bin/launchctl | print | gui/501/io.github.smkwray.keyferryd",
                "/bin/launchctl | kickstart | gui/501/io.github.smkwray.keyferryd",
            ]
        );
    }

    #[test]
    fn macos_start_loads_an_unloaded_agent_first() {
        let mut script = Script::new([failed("Could not find service"), ok(""), ok("")]);
        let outcome = macos(Some(PLIST)).start(&mut |invocation| script.run(invocation));
        assert_eq!(outcome, ServiceOutcome::Started);
        assert_eq!(
            script.commands()[1],
            format!("/bin/launchctl | bootstrap | gui/501 | {PLIST}")
        );
        assert_eq!(
            script.commands()[2],
            "/bin/launchctl | kickstart | gui/501/io.github.smkwray.keyferryd"
        );
    }

    #[test]
    fn macos_without_an_agent_changes_nothing() {
        let mut script = Script::new([failed("Could not find service")]);
        let outcome = macos(None).start(&mut |invocation| script.run(invocation));
        assert_eq!(outcome, ServiceOutcome::NotInstalled);
        assert_eq!(script.seen.len(), 1);

        let mut script = Script::new([failed("Could not find service")]);
        let outcome = macos(Some(PLIST)).stop(&mut |invocation| script.run(invocation));
        assert_eq!(outcome, ServiceOutcome::NotInstalled);
        assert_eq!(script.seen.len(), 1);
    }

    #[test]
    fn macos_stop_signals_only_a_running_daemon_and_keeps_the_agent_loaded() {
        let running =
            "gui/501/io.github.smkwray.keyferryd = {\n\tstate = running\n\tpid = 4242\n}\n";
        let mut script = Script::new([ok(running), ok("")]);
        let outcome = macos(Some(PLIST)).stop(&mut |invocation| script.run(invocation));
        assert_eq!(outcome, ServiceOutcome::Stopped);
        assert_eq!(
            script.commands()[1],
            "/bin/launchctl | kill | TERM | gui/501/io.github.smkwray.keyferryd"
        );
        assert!(script
            .commands()
            .iter()
            .all(|command| !command.contains("bootout")));

        let mut script = Script::new([ok("state = not running\n")]);
        let outcome = macos(Some(PLIST)).stop(&mut |invocation| script.run(invocation));
        assert_eq!(outcome, ServiceOutcome::NotRunning);
        assert_eq!(script.seen.len(), 1);
    }

    #[test]
    fn launchd_pid_reads_only_an_exact_pid_line() {
        assert_eq!(launchd_pid("\tpid = 77\n"), Some(77));
        assert_eq!(launchd_pid("\tlast exit code = 0\n"), None);
        assert_eq!(launchd_pid("\tpid = 77 extra\n"), None);
        assert_eq!(launchd_pid("\tpid = none\n"), None);
    }

    #[test]
    fn other_platforms_have_no_service_to_manage() {
        let mut run = |_: &Invocation| -> Result<Completion, String> {
            panic!("no command may run without a service manager")
        };
        assert_eq!(
            ServiceManager::Unsupported.start(&mut run),
            ServiceOutcome::Unsupported
        );
        assert_eq!(
            ServiceManager::Unsupported.stop(&mut run),
            ServiceOutcome::Unsupported
        );
    }

    #[test]
    fn installers_define_the_service_the_app_manages() {
        let windows = include_str!("../../../scripts/install_windows_controller.ps1");
        let macos = include_str!("../../../scripts/install_unix_controller.sh");
        assert!(windows.contains(&format!("$taskName = '{WINDOWS_TASK_NAME}'")));
        assert!(windows.contains("-MultipleInstances IgnoreNew"));
        assert!(macos.contains(&format!("launch_label={MACOS_LAUNCH_LABEL}\n")));
        assert!(macos.contains("plutil -insert RunAtLoad -bool false"));
        assert!(macos.contains("plutil -insert KeepAlive -bool false"));
    }
}
