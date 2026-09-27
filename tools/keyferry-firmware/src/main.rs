#![forbid(unsafe_code)]

use keyferry_firmware::{
    apply_clone_split, apply_exact_update, build_clone_split_plan, build_exact_update_plan,
    exact_observation_from_probe, generate_update_manifest, prepare_update_package,
    ApplicationWrite, ApplyOutcome, BackendFailure, CloneSplitBackend, CloneSplitBindingV1,
    CloneSplitLiveObservation, CloneSplitMigrationPlanV1, CloneSplitOutcome, CloneSplitRegion,
    ExactUnitObservation, FirmwareUpdateBackend, ManifestMetadata, PlanError,
    PreparedUpdatePackage, RomProbeRequirements, WriteSafety, APPLICATION_OFFSET,
    APPLICATION_PARTITION_SIZE, CLONE_SPLIT_PROTECTED_SUFFIX_BYTES,
    CLONE_SPLIT_PROTECTED_SUFFIX_OFFSET, MAX_METADATA_BYTES,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    ops::{Deref, DerefMut},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const MAX_IMAGE_BYTES: usize = 1024 * 1024;
const MAX_ELF_BYTES: usize = 32 * 1024 * 1024;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const ROM_PROBE_TIMEOUT: Duration = Duration::from_secs(60);
const APPLY_TIMEOUT: Duration = Duration::from_secs(300);
// Two complete flash passes have unmeasured duration on USB Serial/JTAG.
const BACKUP_TIMEOUT: Duration = Duration::from_secs(7200);

struct ReapChild(Child);
impl Deref for ReapChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl DerefMut for ReapChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for ReapChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn main() -> ExitCode {
    match run_with_backends(
        env::args().skip(1).collect(),
        &ProductionRomProbe,
        &ProductionApplyRunner,
        &ProductionCloneSplitRunner,
        &ProductionBackupRunner,
    ) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!(
                "{}",
                json!({
                    "schema": "keyferry.firmware-update-result.v1",
                    "ready": false,
                    "error": {"code": error},
                })
            );
            ExitCode::from(
                if matches!(
                    error,
                    "firmware.apply_unknown_write" | "firmware.clone_split_interrupted"
                ) {
                    25
                } else {
                    20
                },
            )
        }
    }
}

#[cfg(test)]
fn run(args: Vec<String>) -> Result<String, &'static str> {
    run_with_backends(
        args,
        &ProductionRomProbe,
        &RefuseApplyRunner,
        &RefuseCloneSplitRunner,
        &RefuseBackupRunner,
    )
}

trait RomProbeRunner {
    fn probe(
        &self,
        port: &str,
        requirements: RomProbeRequirements,
    ) -> Result<Vec<u8>, &'static str>;
}

struct ProductionRomProbe;

trait BackupRunner {
    fn backup(
        &self,
        package: &PreparedUpdatePackage,
        unit_record: &[u8],
        port: &str,
        output: &Path,
    ) -> Result<serde_json::Value, &'static str>;
}

struct ProductionBackupRunner;
#[cfg(test)]
struct RefuseBackupRunner;
#[cfg(test)]
impl BackupRunner for RefuseBackupRunner {
    fn backup(
        &self,
        _: &PreparedUpdatePackage,
        _: &[u8],
        _: &str,
        _: &Path,
    ) -> Result<serde_json::Value, &'static str> {
        Err("firmware.backend_unavailable")
    }
}

trait ApplyRunner {
    fn apply(
        &self,
        plan: &[u8],
        authorize: &str,
        package: &PreparedUpdatePackage,
        unit_record: &[u8],
    ) -> ApplyOutcome;
}

struct ProductionApplyRunner;

trait CloneSplitRunner {
    fn observe(
        &self,
        package: &PreparedUpdatePackage,
        binding: &CloneSplitBindingV1,
        port: &str,
    ) -> Result<CloneSplitLiveObservation, &'static str>;

    fn apply(
        &self,
        plan: &[u8],
        authorize: &str,
        package: &PreparedUpdatePackage,
    ) -> CloneSplitOutcome;
}

struct ProductionCloneSplitRunner;

#[cfg(test)]
struct RefuseApplyRunner;

#[cfg(test)]
struct RefuseCloneSplitRunner;

#[cfg(test)]
impl ApplyRunner for RefuseApplyRunner {
    fn apply(
        &self,
        _plan: &[u8],
        _authorize: &str,
        _package: &PreparedUpdatePackage,
        _unit_record: &[u8],
    ) -> ApplyOutcome {
        ApplyOutcome::Rejected(keyferry_firmware::ApplyError::BackendUnavailable)
    }
}

#[cfg(test)]
impl CloneSplitRunner for RefuseCloneSplitRunner {
    fn observe(
        &self,
        _package: &PreparedUpdatePackage,
        _binding: &CloneSplitBindingV1,
        _port: &str,
    ) -> Result<CloneSplitLiveObservation, &'static str> {
        Err("firmware.backend_unavailable")
    }

    fn apply(
        &self,
        _plan: &[u8],
        _authorize: &str,
        _package: &PreparedUpdatePackage,
    ) -> CloneSplitOutcome {
        CloneSplitOutcome::Rejected(keyferry_firmware::ApplyError::BackendUnavailable)
    }
}

impl RomProbeRunner for ProductionRomProbe {
    fn probe(
        &self,
        port: &str,
        requirements: RomProbeRequirements,
    ) -> Result<Vec<u8>, &'static str> {
        let (python, helper) = backend_paths()?;

        let mut command = Command::new(python);
        command
            .arg("-I")
            .arg(helper)
            .arg("probe")
            .arg("--port")
            .arg(port)
            .arg("--bootloader-offset")
            .arg(requirements.bootloader_offset.to_string())
            .arg("--bootloader-size")
            .arg(requirements.bootloader_size_bytes.to_string())
            .arg("--partition-table-offset")
            .arg(requirements.partition_table_offset.to_string())
            .arg("--partition-table-size")
            .arg(requirements.partition_table_size_bytes.to_string())
            .stdin(Stdio::null());
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|_| "firmware.backend_unavailable")?;
        let deadline = Instant::now() + ROM_PROBE_TIMEOUT;
        loop {
            if child
                .try_wait()
                .map_err(|_| "firmware.backend_unavailable")?
                .is_some()
            {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("firmware.rom_probe_timeout");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let output = child
            .wait_with_output()
            .map_err(|_| "firmware.backend_unavailable")?;
        if output.stdout.len() > MAX_METADATA_BYTES {
            return Err("firmware.rom_probe_failed");
        }
        if !output.status.success() {
            let value: serde_json::Value =
                serde_json::from_slice(&output.stdout).map_err(|_| "firmware.rom_probe_failed")?;
            return Err(
                match value
                    .get("error")
                    .and_then(|error| error.get("code"))
                    .and_then(serde_json::Value::as_str)
                {
                    Some("firmware.rom_probe_tool") => "firmware.rom_probe_tool",
                    Some("firmware.rom_probe_range") => "firmware.rom_probe_range",
                    Some("firmware.rom_probe_connect") => "firmware.rom_probe_connect",
                    Some("firmware.rom_probe_mode") => "firmware.rom_probe_mode",
                    Some("firmware.rom_probe_flash_attach") => "firmware.rom_probe_flash_attach",
                    Some("firmware.rom_probe_identity") => "firmware.rom_probe_identity",
                    Some("firmware.rom_probe_efuse") => "firmware.rom_probe_efuse",
                    Some("firmware.rom_probe_preserved_read") => {
                        "firmware.rom_probe_preserved_read"
                    }
                    _ => "firmware.rom_probe_failed",
                },
            );
        }
        Ok(output.stdout)
    }
}

fn backend_paths() -> Result<(std::path::PathBuf, std::path::PathBuf), &'static str> {
    let project_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let helper = project_root
        .join("tools")
        .join("keyferry-firmware")
        .join("esptool_backend.py");
    #[cfg(windows)]
    let python = project_root
        .join(".tools")
        .join("idf-tools-v6.0.3")
        .join("python_env")
        .join("idf6.0_py3.14_env")
        .join("Scripts")
        .join("python.exe");
    #[cfg(not(windows))]
    let python = project_root
        .join(".tools")
        .join("idf-tools-v6.0.3")
        .join("python_env")
        .join("idf6.0_py3.14_env")
        .join("bin")
        .join("python3");
    for path in [&python, &helper] {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| "firmware.backend_missing")?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("firmware.backend_missing");
        }
    }
    Ok((python, helper))
}

fn create_private_backup_dir(path: &Path) -> Result<(), &'static str> {
    let parent = path.parent().ok_or("input.output")?;
    let parent_type = fs::symlink_metadata(parent).map_err(|_| "input.output")?;
    if !parent_type.is_dir() || parent_type.file_type().is_symlink() {
        return Err("input.output");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path).map_err(|_| "input.output")?;
    }
    #[cfg(windows)]
    {
        fs::create_dir(path).map_err(|_| "input.output")?;
        let sid = current_windows_sid()?;
        let grant = format!("*{sid}:(OI)(CI)F");
        let status = Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", &grant, "/q"])
            .output()
            .map_err(|_| "input.output_acl")?;
        if !status.status.success() {
            return Err("input.output_acl");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn current_windows_sid() -> Result<String, &'static str> {
    let output = Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .map_err(|_| "input.output_acl")?;
    if !output.status.success() {
        return Err("input.output_acl");
    }
    let identity = String::from_utf8(output.stdout).map_err(|_| "input.output_acl")?;
    identity
        .split(&['"', ','][..])
        .map(str::trim)
        .find(|field| field.starts_with("S-1-"))
        .map(str::to_owned)
        .ok_or("input.output_acl")
}

fn snapshot_digest_and_app(
    path: &Path,
    flash_size: u64,
    image: &[u8],
) -> Result<String, &'static str> {
    let mut file = File::open(path).map_err(|_| "firmware.backup_snapshot")?;
    if file
        .metadata()
        .map_err(|_| "firmware.backup_snapshot")?
        .len()
        != flash_size
    {
        return Err("firmware.backup_snapshot");
    }
    file.seek(SeekFrom::Start(APPLICATION_OFFSET))
        .map_err(|_| "firmware.backup_snapshot")?;
    let mut current_image = vec![0; image.len()];
    file.read_exact(&mut current_image)
        .map_err(|_| "firmware.backup_snapshot")?;
    if current_image != image {
        return Err("firmware.backup_app_mismatch");
    }
    file.rewind().map_err(|_| "firmware.backup_snapshot")?;
    let mut sha = Sha256::new();
    let mut chunk = [0_u8; 65_536];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|_| "firmware.backup_snapshot")?;
        if read == 0 {
            break;
        }
        sha.update(&chunk[..read]);
    }
    Ok(format!("{:x}", sha.finalize()))
}

impl ProductionBackupRunner {
    fn backup_with_paths(
        &self,
        package: &PreparedUpdatePackage,
        unit_record: &[u8],
        port: &str,
        output: &Path,
        python: &Path,
        helper: &Path,
    ) -> Result<serde_json::Value, &'static str> {
        let requirements = package.rom_probe_requirements().map_err(PlanError::code)?;
        let mut command = Command::new(python);
        command
            .arg("-I")
            .arg(helper)
            .arg("backup-session")
            .arg("--port")
            .arg(port)
            .arg("--bootloader-offset")
            .arg(requirements.bootloader_offset.to_string())
            .arg("--bootloader-size")
            .arg(requirements.bootloader_size_bytes.to_string())
            .arg("--partition-table-offset")
            .arg(requirements.partition_table_offset.to_string())
            .arg("--partition-table-size")
            .arg(requirements.partition_table_size_bytes.to_string())
            .arg("--output")
            .arg(output)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);
        let mut child = ReapChild(
            command
                .spawn()
                .map_err(|_| "firmware.backend_unavailable")?,
        );
        let mut stdin = child.stdin.take().ok_or("firmware.backend_unavailable")?;
        let stdout = child.stdout.take().ok_or("firmware.backend_unavailable")?;
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = Vec::new();
            let result = reader
                .by_ref()
                .take((MAX_METADATA_BYTES + 1) as u64)
                .read_until(b'\n', &mut line)
                .map(|_| line);
            let _ = sender.send((result, reader.into_inner()));
        });
        let (line, stdout) = match receiver.recv_timeout(ROM_PROBE_TIMEOUT) {
            Ok((Ok(line), stdout)) if !line.is_empty() && line.len() <= MAX_METADATA_BYTES => {
                (line, stdout)
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("firmware.backup_probe");
            }
        };
        let observed = match exact_observation_from_probe(package, unit_record, port, &line)
            .and_then(|observation| build_exact_update_plan(package, observation))
        {
            Ok(plan) => plan,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.code());
            }
        };
        let flash_size = observed.target.flash_size_bytes;
        if flash_size != 16 * 1024 * 1024 {
            let _ = child.kill();
            let _ = child.wait();
            return Err("firmware.backup_size");
        }
        let mut request = serde_json::to_vec(&json!({
            "schema": "keyferry.backup-request.v1", "action": "read_full_flash", "flash_size_bytes": flash_size,
        })).map_err(|_| "firmware.serialization")?;
        request.push(b'\n');
        if stdin
            .write_all(&request)
            .and_then(|()| stdin.flush())
            .is_err()
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err("firmware.backup_protocol");
        }
        drop(stdin);
        let deadline = Instant::now() + BACKUP_TIMEOUT;
        loop {
            if child
                .try_wait()
                .map_err(|_| "firmware.backup_read")?
                .is_some()
            {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("firmware.backup_timeout");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let status = child.wait().map_err(|_| "firmware.backup_read")?;
        let mut result_bytes = Vec::new();
        stdout
            .take((MAX_METADATA_BYTES + 1) as u64)
            .read_to_end(&mut result_bytes)
            .map_err(|_| "firmware.backup_read")?;
        if !status.success() || result_bytes.len() > MAX_METADATA_BYTES {
            return Err("firmware.backup_read");
        }
        let result: serde_json::Value =
            serde_json::from_slice(&result_bytes).map_err(|_| "firmware.backup_read")?;
        if result["schema"] != "keyferry.backup-session-result.v1"
            || result["size_bytes"].as_u64() != Some(flash_size)
            || result["second_pass_equal"] != true
        {
            return Err("firmware.backup_read");
        }
        let after = serde_json::to_vec(&result["after"]).map_err(|_| "firmware.backup_read")?;
        exact_observation_from_probe(package, unit_record, port, &after)
            .map_err(PlanError::code)?;
        let digest = snapshot_digest_and_app(
            &output.join("full-flash.partial"),
            flash_size,
            package.image(),
        )?;
        if result["sha256"].as_str() != Some(digest.as_str()) {
            return Err("firmware.backup_difference");
        }
        fs::rename(
            output.join("full-flash.partial"),
            output.join("full-flash.bin"),
        )
        .map_err(|_| "firmware.backup_snapshot")?;
        Ok(json!({
            "schema": "keyferry.firmware-backup-result.v1", "outcome": "READ_VERIFIED",
            "snapshot": {"file": "full-flash.bin", "size_bytes": flash_size, "sha256": digest, "passes_equal": true},
            "installed_application": {"offset": APPLICATION_OFFSET, "size_bytes": package.image().len(), "sha256": package.plan_only().firmware.image_sha256},
            "unit_binding_sha256": observed.target.unit_binding_sha256,
            "unit_record_sha256": format!("{:x}", Sha256::digest(unit_record)),
            "package_manifest_sha256": observed.raw_manifest_sha256,
            "port": port,
            "bootloader_sha256": observed.target.bootloader_sha256,
            "partition_table_sha256": observed.target.partition_table_sha256,
            "efuse_sha256": observed.target.efuse_sha256,
        }))
    }
}

impl BackupRunner for ProductionBackupRunner {
    fn backup(
        &self,
        package: &PreparedUpdatePackage,
        unit_record: &[u8],
        port: &str,
        output: &Path,
    ) -> Result<serde_json::Value, &'static str> {
        let (python, helper) = backend_paths()?;
        self.backup_with_paths(package, unit_record, port, output, &python, &helper)
    }
}

struct ApplySession {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
}

struct ProductionFirmwareBackend<'a> {
    package: &'a PreparedUpdatePackage,
    unit_record: &'a [u8],
    session: Option<ApplySession>,
    verified: bool,
}

impl Drop for ProductionFirmwareBackend<'_> {
    fn drop(&mut self) {
        if let Some(session) = &mut self.session {
            if session.child.try_wait().ok().flatten().is_none() {
                let _ = session.child.kill();
                let _ = session.child.wait();
            }
        }
    }
}

impl FirmwareUpdateBackend for ProductionFirmwareBackend<'_> {
    fn observe(
        &mut self,
        port: &str,
    ) -> Result<keyferry_firmware::ExactUnitObservation, BackendFailure> {
        if self.session.is_some() || !valid_local_port(port) {
            return Err(BackendFailure::Unavailable);
        }
        let requirements = self
            .package
            .rom_probe_requirements()
            .map_err(|_| BackendFailure::Unavailable)?;
        let (python, helper) = backend_paths().map_err(|_| BackendFailure::Unavailable)?;
        let mut command = Command::new(python);
        command
            .arg("-I")
            .arg(helper)
            .arg("apply-session")
            .arg("--port")
            .arg(port)
            .arg("--bootloader-offset")
            .arg(requirements.bootloader_offset.to_string())
            .arg("--bootloader-size")
            .arg(requirements.bootloader_size_bytes.to_string())
            .arg("--partition-table-offset")
            .arg(requirements.partition_table_offset.to_string())
            .arg("--partition-table-size")
            .arg(requirements.partition_table_size_bytes.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);
        let mut child = command.spawn().map_err(|_| BackendFailure::Unavailable)?;
        let stdin = child.stdin.take().ok_or(BackendFailure::Unavailable)?;
        let stdout = child.stdout.take().ok_or(BackendFailure::Unavailable)?;
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = Vec::new();
            let result = reader.read_until(b'\n', &mut line).map(|_| line);
            let _ = sender.send((result, reader.into_inner()));
        });
        let (line, stdout) = match receiver.recv_timeout(ROM_PROBE_TIMEOUT) {
            Ok((Ok(line), stdout)) if !line.is_empty() && line.len() <= MAX_METADATA_BYTES => {
                (line, stdout)
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BackendFailure::Timeout);
            }
        };
        if child
            .try_wait()
            .map_err(|_| BackendFailure::Unavailable)?
            .is_some()
        {
            return Err(BackendFailure::Unavailable);
        }
        let observation = exact_observation_from_probe(self.package, self.unit_record, port, &line)
            .map_err(|_| BackendFailure::Mismatch)?;
        self.session = Some(ApplySession {
            child,
            stdin: Some(stdin),
            stdout: Some(stdout),
        });
        Ok(observation)
    }

    fn write_application(&mut self, write: ApplicationWrite<'_>) -> Result<(), BackendFailure> {
        if write.offset != APPLICATION_OFFSET
            || write.bytes != self.package.image()
            || write.safety != WriteSafety::LOCKED
        {
            return Err(BackendFailure::Unavailable);
        }
        let session = self.session.as_mut().ok_or(BackendFailure::Unavailable)?;
        let mut stdin = session.stdin.take().ok_or(BackendFailure::Unavailable)?;
        let request = json!({
            "schema": "keyferry.apply-request.v1",
            "action": "write_application",
            "offset": APPLICATION_OFFSET,
            "size": write.bytes.len(),
            "sha256": self.package.plan_only().firmware.image_sha256,
        });
        let mut request = serde_json::to_vec(&request).map_err(|_| BackendFailure::Unavailable)?;
        request.push(b'\n');
        stdin
            .write_all(&request)
            .and_then(|()| stdin.write_all(write.bytes))
            .and_then(|()| stdin.flush())
            .map_err(|_| BackendFailure::Disconnected)?;
        drop(stdin);

        let deadline = Instant::now() + APPLY_TIMEOUT;
        loop {
            if session
                .child
                .try_wait()
                .map_err(|_| BackendFailure::Disconnected)?
                .is_some()
            {
                break;
            }
            if Instant::now() >= deadline {
                let _ = session.child.kill();
                let _ = session.child.wait();
                return Err(BackendFailure::Timeout);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let status = session
            .child
            .wait()
            .map_err(|_| BackendFailure::Disconnected)?;
        let mut output = Vec::new();
        session
            .stdout
            .take()
            .ok_or(BackendFailure::Disconnected)?
            .take((MAX_METADATA_BYTES + 1) as u64)
            .read_to_end(&mut output)
            .map_err(|_| BackendFailure::Disconnected)?;
        if output.len() > MAX_METADATA_BYTES || !status.success() {
            return Err(BackendFailure::Disconnected);
        }
        let result: serde_json::Value =
            serde_json::from_slice(&output).map_err(|_| BackendFailure::Disconnected)?;
        let exact_shape = result.as_object().is_some_and(|object| {
            object.len() == 2
                && result["schema"] == "keyferry.apply-result.v1"
                && result["outcome"] == "WRITE_VERIFIED"
        });
        if !exact_shape {
            return Err(BackendFailure::Disconnected);
        }
        self.verified = true;
        Ok(())
    }

    fn verify_application(&mut self, offset: u64, expected: &[u8]) -> Result<bool, BackendFailure> {
        Ok(self.verified && offset == APPLICATION_OFFSET && expected == self.package.image())
    }
}

impl ApplyRunner for ProductionApplyRunner {
    fn apply(
        &self,
        plan: &[u8],
        authorize: &str,
        package: &PreparedUpdatePackage,
        unit_record: &[u8],
    ) -> ApplyOutcome {
        let mut backend = ProductionFirmwareBackend {
            package,
            unit_record,
            session: None,
            verified: false,
        };
        apply_exact_update(plan, authorize, package, &mut backend)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCloneSplitObservation {
    schema: String,
    port: String,
    rom_mac: String,
    chip: String,
    soc_revision: String,
    flash_manufacturer_id: String,
    flash_device_id: String,
    flash_size_bytes: u64,
    secure_boot: bool,
    flash_encryption: bool,
    secure_download_mode: bool,
    efuse_sha256: String,
    bootloader_sha256: String,
    partition_table_sha256: String,
    application_sha256: String,
    state_sha256: String,
    protected_prefix_sha256: String,
    protected_suffix_sha256: String,
    esptool_version: String,
}

fn clone_observation(
    package: &PreparedUpdatePackage,
    binding: &CloneSplitBindingV1,
    port: &str,
    bytes: &[u8],
) -> Result<CloneSplitLiveObservation, &'static str> {
    let raw: RawCloneSplitObservation =
        serde_json::from_slice(bytes).map_err(|_| "firmware.clone_split_observation")?;
    if raw.schema != "keyferry.clone-split-observation.v1"
        || raw.port != port
        || raw.rom_mac != binding.rom_mac
        || raw.esptool_version != "5.4.0"
    {
        return Err("firmware.clone_split_observation");
    }
    Ok(CloneSplitLiveObservation {
        exact_unit: ExactUnitObservation {
            port: raw.port,
            unit_binding_sha256: binding.unit_binding_sha256.clone(),
            chip: raw.chip,
            soc_revision: raw.soc_revision,
            flash_manufacturer_id: raw.flash_manufacturer_id,
            flash_device_id: raw.flash_device_id,
            flash_size_bytes: raw.flash_size_bytes,
            secure_boot: raw.secure_boot,
            flash_encryption: raw.flash_encryption,
            secure_download_mode: raw.secure_download_mode,
            efuse_sha256: raw.efuse_sha256,
            bootloader_sha256: raw.bootloader_sha256,
            partition_table_sha256: raw.partition_table_sha256,
            partition_map_sha256: package.plan_only().partition_map_sha256.clone(),
        },
        rom_mac: raw.rom_mac,
        application_sha256: raw.application_sha256,
        state_sha256: raw.state_sha256,
        protected_prefix_sha256: raw.protected_prefix_sha256,
        protected_suffix_sha256: raw.protected_suffix_sha256,
    })
}

fn clone_command(
    operation: &str,
    port: &str,
    requirements: RomProbeRequirements,
) -> Result<Command, &'static str> {
    let (python, helper) = backend_paths()?;
    let mut command = Command::new(python);
    command
        .arg("-I")
        .arg(helper)
        .arg(operation)
        .arg("--port")
        .arg(port)
        .arg("--bootloader-offset")
        .arg(requirements.bootloader_offset.to_string())
        .arg("--bootloader-size")
        .arg(requirements.bootloader_size_bytes.to_string())
        .arg("--partition-table-offset")
        .arg(requirements.partition_table_offset.to_string())
        .arg("--partition-table-size")
        .arg(requirements.partition_table_size_bytes.to_string());
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    Ok(command)
}

fn wait_child(child: &mut Child, timeout: Duration) -> Result<(), BackendFailure> {
    let deadline = Instant::now() + timeout;
    loop {
        if child
            .try_wait()
            .map_err(|_| BackendFailure::Disconnected)?
            .is_some()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(BackendFailure::Timeout);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn read_session_line(
    stdout: ChildStdout,
    timeout: Duration,
) -> Result<(Vec<u8>, ChildStdout), BackendFailure> {
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = Vec::new();
        let result = reader.read_until(b'\n', &mut line).map(|_| line);
        let _ = sender.send((result, reader.into_inner()));
    });
    match receiver.recv_timeout(timeout) {
        Ok((Ok(line), stdout))
            if !line.is_empty() && line.len() <= MAX_METADATA_BYTES && line.ends_with(b"\n") =>
        {
            Ok((line, stdout))
        }
        _ => Err(BackendFailure::Timeout),
    }
}

impl CloneSplitRunner for ProductionCloneSplitRunner {
    fn observe(
        &self,
        package: &PreparedUpdatePackage,
        binding: &CloneSplitBindingV1,
        port: &str,
    ) -> Result<CloneSplitLiveObservation, &'static str> {
        if !valid_local_port(port) {
            return Err("input.port");
        }
        let requirements = package.rom_probe_requirements().map_err(PlanError::code)?;
        let mut command = clone_command("clone-split-probe", port, requirements)?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|_| "firmware.backend_unavailable")?;
        wait_child(&mut child, APPLY_TIMEOUT).map_err(|_| "firmware.clone_split_observation")?;
        let output = child
            .wait_with_output()
            .map_err(|_| "firmware.clone_split_observation")?;
        if !output.status.success() || output.stdout.len() > MAX_METADATA_BYTES {
            return Err("firmware.clone_split_observation");
        }
        clone_observation(package, binding, port, &output.stdout)
    }

    fn apply(
        &self,
        plan: &[u8],
        authorize: &str,
        package: &PreparedUpdatePackage,
    ) -> CloneSplitOutcome {
        let parsed: CloneSplitMigrationPlanV1 = match serde_json::from_slice(plan) {
            Ok(parsed) => parsed,
            Err(_) => {
                return CloneSplitOutcome::Rejected(keyferry_firmware::ApplyError::PlanInvalid);
            }
        };
        let mut backend = ProductionCloneSplitBackend {
            package,
            binding: &parsed.binding,
            session: None,
            completed: false,
        };
        apply_clone_split(plan, authorize, package, &mut backend)
    }
}

struct CloneApplySession {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
}

struct ProductionCloneSplitBackend<'a> {
    package: &'a PreparedUpdatePackage,
    binding: &'a CloneSplitBindingV1,
    session: Option<CloneApplySession>,
    completed: bool,
}

impl Drop for ProductionCloneSplitBackend<'_> {
    fn drop(&mut self) {
        if let Some(session) = &mut self.session {
            if session.child.try_wait().ok().flatten().is_none() {
                let _ = session.child.kill();
                let _ = session.child.wait();
            }
        }
    }
}

impl ProductionCloneSplitBackend<'_> {
    fn exchange(
        &mut self,
        request: serde_json::Value,
        body: &[u8],
    ) -> Result<bool, BackendFailure> {
        let session = self.session.as_mut().ok_or(BackendFailure::Unavailable)?;
        let stdin = session.stdin.as_mut().ok_or(BackendFailure::Unavailable)?;
        let mut bytes = serde_json::to_vec(&request).map_err(|_| BackendFailure::Unavailable)?;
        bytes.push(b'\n');
        stdin
            .write_all(&bytes)
            .and_then(|()| stdin.write_all(body))
            .and_then(|()| stdin.flush())
            .map_err(|_| BackendFailure::Disconnected)?;
        let stdout = session.stdout.take().ok_or(BackendFailure::Unavailable)?;
        let (line, stdout) = read_session_line(stdout, APPLY_TIMEOUT)?;
        session.stdout = Some(stdout);
        let value: serde_json::Value =
            serde_json::from_slice(&line).map_err(|_| BackendFailure::Disconnected)?;
        let exact = value.as_object().is_some_and(|object| {
            object.len() == 2
                && value["schema"] == "keyferry.clone-split-result.v1"
                && value["ok"].is_boolean()
        });
        if !exact {
            return Err(BackendFailure::Disconnected);
        }
        value["ok"].as_bool().ok_or(BackendFailure::Disconnected)
    }

    fn finish(&mut self) -> Result<(), BackendFailure> {
        let session = self.session.as_mut().ok_or(BackendFailure::Unavailable)?;
        session.stdin.take();
        wait_child(&mut session.child, APPLY_TIMEOUT)?;
        let status = session
            .child
            .wait()
            .map_err(|_| BackendFailure::Disconnected)?;
        let stdout = session.stdout.take().ok_or(BackendFailure::Disconnected)?;
        let (line, _stdout) = read_session_line(stdout, Duration::from_secs(1))?;
        let value: serde_json::Value =
            serde_json::from_slice(&line).map_err(|_| BackendFailure::Disconnected)?;
        let exact = status.success()
            && value.as_object().is_some_and(|object| {
                object.len() == 2
                    && value["schema"] == "keyferry.clone-split-session.v1"
                    && value["outcome"] == "COMPLETE"
            });
        if !exact {
            return Err(BackendFailure::Disconnected);
        }
        self.completed = true;
        Ok(())
    }
}

impl CloneSplitBackend for ProductionCloneSplitBackend<'_> {
    fn observe(&mut self, port: &str) -> Result<CloneSplitLiveObservation, BackendFailure> {
        if self.session.is_some() || !valid_local_port(port) {
            return Err(BackendFailure::Unavailable);
        }
        let requirements = self
            .package
            .rom_probe_requirements()
            .map_err(|_| BackendFailure::Unavailable)?;
        let mut command = clone_command("clone-split-session", port, requirements)
            .map_err(|_| BackendFailure::Unavailable)?;
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|_| BackendFailure::Unavailable)?;
        let stdin = child.stdin.take().ok_or(BackendFailure::Unavailable)?;
        let stdout = child.stdout.take().ok_or(BackendFailure::Unavailable)?;
        let (line, stdout) = read_session_line(stdout, APPLY_TIMEOUT)?;
        let observed = clone_observation(self.package, self.binding, port, &line)
            .map_err(|_| BackendFailure::Mismatch)?;
        self.session = Some(CloneApplySession {
            child,
            stdin: Some(stdin),
            stdout: Some(stdout),
        });
        Ok(observed)
    }

    fn erase_region(&mut self, region: &CloneSplitRegion) -> Result<(), BackendFailure> {
        self.exchange(
            json!({
                "schema": "keyferry.clone-split-request.v1",
                "action": "erase",
                "offset": region.offset,
                "length": region.length,
            }),
            &[],
        )?
        .then_some(())
        .ok_or(BackendFailure::Mismatch)
    }

    fn verify_erased(&mut self, region: &CloneSplitRegion) -> Result<bool, BackendFailure> {
        self.exchange(
            json!({
                "schema": "keyferry.clone-split-request.v1",
                "action": "verify_erased",
                "offset": region.offset,
                "length": region.length,
            }),
            &[],
        )
    }

    fn write_application(&mut self, write: ApplicationWrite<'_>) -> Result<(), BackendFailure> {
        if write.offset != APPLICATION_OFFSET
            || write.bytes != self.package.image()
            || write.safety != WriteSafety::LOCKED
        {
            return Err(BackendFailure::Unavailable);
        }
        self.exchange(
            json!({
                "schema": "keyferry.clone-split-request.v1",
                "action": "write_application",
                "offset": APPLICATION_OFFSET,
                "size": write.bytes.len(),
                "sha256": self.package.plan_only().firmware.image_sha256,
            }),
            write.bytes,
        )?
        .then_some(())
        .ok_or(BackendFailure::Mismatch)
    }

    fn verify_application_partition(
        &mut self,
        image: &[u8],
        partition_size: u64,
    ) -> Result<bool, BackendFailure> {
        if image != self.package.image() || partition_size != APPLICATION_PARTITION_SIZE {
            return Err(BackendFailure::Unavailable);
        }
        self.exchange(
            json!({
                "schema": "keyferry.clone-split-request.v1",
                "action": "verify_application",
                "image_size": image.len(),
                "image_sha256": self.package.plan_only().firmware.image_sha256,
                "partition_size": partition_size,
            }),
            &[],
        )
    }

    fn verify_protected(
        &mut self,
        prefix: &CloneSplitRegion,
        prefix_sha256: &str,
        suffix: &CloneSplitRegion,
        suffix_sha256: &str,
    ) -> Result<bool, BackendFailure> {
        if prefix.offset != 0
            || prefix.length != APPLICATION_OFFSET
            || suffix.offset != CLONE_SPLIT_PROTECTED_SUFFIX_OFFSET
            || suffix.length != CLONE_SPLIT_PROTECTED_SUFFIX_BYTES
        {
            return Err(BackendFailure::Unavailable);
        }
        let verified = self.exchange(
            json!({
                "schema": "keyferry.clone-split-request.v1",
                "action": "verify_protected",
                "prefix_sha256": prefix_sha256,
                "suffix_sha256": suffix_sha256,
            }),
            &[],
        )?;
        if verified {
            self.finish()?;
        }
        Ok(verified && self.completed)
    }
}

fn run_with_backends<R: RomProbeRunner, A: ApplyRunner, C: CloneSplitRunner, B: BackupRunner>(
    args: Vec<String>,
    probe_runner: &R,
    apply_runner: &A,
    clone_runner: &C,
    backup_runner: &B,
) -> Result<String, &'static str> {
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        return Ok(json!({
            "schema": "keyferry.firmware-update-help.v1",
            "commands": ["manifest", "plan", "apply", "clone-split-plan", "clone-split-apply", "backup"],
            "usage": {
                "manifest": "keyferry-fw manifest --source-revision HEX40 --esptool-version SEMVER --board-manifest PATH --partitions PATH --image PATH --elf PATH --bootloader PATH --partition-table PATH",
                "plan": [
                    "keyferry-fw plan --manifest PATH --board-manifest PATH --partitions PATH --image PATH --elf PATH --bootloader PATH --partition-table PATH",
                    "keyferry-fw plan --package DIR --port EXACT_PORT --unit-record PATH"
                ],
                "apply": "keyferry-fw apply --plan PATH --authorize SHA256 --package DIR --unit-record PATH",
                "clone-split-plan": "keyferry-fw clone-split-plan --package DIR --port EXACT_PORT --binding PATH",
                "clone-split-apply": "keyferry-fw clone-split-apply --plan PATH --authorize SHA256 --package DIR",
                "backup": "keyferry-fw backup --package DIR --port EXACT_PORT --unit-record PATH --output NEW_DIR"
            },
            "apply_available": true,
        }).to_string());
    }
    match args.first().map(String::as_str) {
        Some("backup") if args.len() == 9 => {
            let package = read_package(Path::new(argument(&args, "--package")?))?;
            let port = argument(&args, "--port")?;
            if !valid_local_port(port) {
                return Err("input.port");
            }
            let record = read_bounded(
                Path::new(argument(&args, "--unit-record")?),
                MAX_METADATA_BYTES,
            )?;
            let output = Path::new(argument(&args, "--output")?);
            create_private_backup_dir(output)?;
            let receipt = backup_runner.backup(&package, &record, port, output)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output.join("receipt.partial"))
                .map_err(|_| "firmware.backup_receipt")?;
            let bytes = serde_json::to_vec(&receipt).map_err(|_| "firmware.serialization")?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| "firmware.backup_receipt")?;
            fs::rename(output.join("receipt.partial"), output.join("receipt.json"))
                .map_err(|_| "firmware.backup_receipt")?;
            Ok(receipt.to_string())
        }
        Some("manifest") if args.len() == 17 => {
            let board = read_bounded(
                Path::new(argument(&args, "--board-manifest")?),
                MAX_METADATA_BYTES,
            )?;
            let partitions = read_bounded(
                Path::new(argument(&args, "--partitions")?),
                MAX_METADATA_BYTES,
            )?;
            let image = read_bounded(Path::new(argument(&args, "--image")?), MAX_IMAGE_BYTES)?;
            let elf = read_bounded(Path::new(argument(&args, "--elf")?), MAX_ELF_BYTES)?;
            let bootloader = read_bounded(
                Path::new(argument(&args, "--bootloader")?),
                MAX_METADATA_BYTES,
            )?;
            let partition_table = read_bounded(
                Path::new(argument(&args, "--partition-table")?),
                MAX_METADATA_BYTES,
            )?;
            let manifest = generate_update_manifest(
                ManifestMetadata {
                    source_revision: argument(&args, "--source-revision")?,
                    esptool_version: argument(&args, "--esptool-version")?,
                },
                &board,
                &partitions,
                &image,
                &elf,
                &bootloader,
                &partition_table,
            )
            .map_err(PlanError::code)?;
            serde_json::to_string(&manifest).map_err(|_| "firmware.serialization")
        }
        Some("plan") if args.len() == 15 => {
            let manifest = read_bounded(
                Path::new(argument(&args, "--manifest")?),
                MAX_METADATA_BYTES,
            )?;
            let board = read_bounded(
                Path::new(argument(&args, "--board-manifest")?),
                MAX_METADATA_BYTES,
            )?;
            let partitions = read_bounded(
                Path::new(argument(&args, "--partitions")?),
                MAX_METADATA_BYTES,
            )?;
            let image = read_bounded(Path::new(argument(&args, "--image")?), MAX_IMAGE_BYTES)?;
            let elf = read_bounded(Path::new(argument(&args, "--elf")?), MAX_ELF_BYTES)?;
            let bootloader = read_bounded(
                Path::new(argument(&args, "--bootloader")?),
                MAX_METADATA_BYTES,
            )?;
            let partition_table = read_bounded(
                Path::new(argument(&args, "--partition-table")?),
                MAX_METADATA_BYTES,
            )?;
            let package = prepare_update_package(
                &manifest,
                &board,
                &partitions,
                &image,
                &elf,
                &bootloader,
                &partition_table,
            )
            .map_err(PlanError::code)?;
            serde_json::to_string(package.plan_only()).map_err(|_| "firmware.serialization")
        }
        Some("plan") if args.len() == 7 => {
            let package_root = Path::new(argument(&args, "--package")?);
            let package = read_package(package_root)?;
            let port = argument(&args, "--port")?;
            if !valid_local_port(port) {
                return Err("input.port");
            }
            let unit_record = read_bounded(
                Path::new(argument(&args, "--unit-record")?),
                MAX_METADATA_BYTES,
            )?;
            let requirements = package.rom_probe_requirements().map_err(PlanError::code)?;
            let probe = probe_runner.probe(port, requirements)?;
            let observation = exact_observation_from_probe(&package, &unit_record, port, &probe)
                .map_err(PlanError::code)?;
            let plan = build_exact_update_plan(&package, observation).map_err(PlanError::code)?;
            serde_json::to_string(&plan).map_err(|_| "firmware.serialization")
        }
        Some("apply") if args.len() == 9 => {
            let plan = read_bounded(Path::new(argument(&args, "--plan")?), MAX_METADATA_BYTES)?;
            let authorize = argument(&args, "--authorize")?;
            let package = read_package(Path::new(argument(&args, "--package")?))?;
            let unit_record = read_bounded(
                Path::new(argument(&args, "--unit-record")?),
                MAX_METADATA_BYTES,
            )?;
            match apply_runner.apply(&plan, authorize, &package, &unit_record) {
                ApplyOutcome::WriteVerified => serde_json::to_string(&json!({
                    "schema": "keyferry.firmware-update-result.v1",
                    "outcome": "WRITE_VERIFIED",
                    "write": {
                        "offset": package.plan_only().write.offset,
                        "length": package.plan_only().write.length,
                        "sha256": package.plan_only().firmware.image_sha256,
                    }
                }))
                .map_err(|_| "firmware.serialization"),
                ApplyOutcome::Rejected(error) => Err(error.code()),
                ApplyOutcome::UnknownWrite => Err("firmware.apply_unknown_write"),
            }
        }
        Some("clone-split-plan") if args.len() == 7 => {
            let package = read_package(Path::new(argument(&args, "--package")?))?;
            let port = argument(&args, "--port")?;
            if !valid_local_port(port) {
                return Err("input.port");
            }
            let binding_bytes =
                read_bounded(Path::new(argument(&args, "--binding")?), MAX_METADATA_BYTES)?;
            let binding: CloneSplitBindingV1 = serde_json::from_slice(&binding_bytes)
                .map_err(|_| "firmware.clone_split_binding")?;
            let observation = clone_runner.observe(&package, &binding, port)?;
            let plan =
                build_clone_split_plan(&package, binding, observation).map_err(PlanError::code)?;
            serde_json::to_string(&plan).map_err(|_| "firmware.serialization")
        }
        Some("clone-split-apply") if args.len() == 7 => {
            let plan = read_bounded(Path::new(argument(&args, "--plan")?), MAX_METADATA_BYTES)?;
            let authorize = argument(&args, "--authorize")?;
            let package = read_package(Path::new(argument(&args, "--package")?))?;
            match clone_runner.apply(&plan, authorize, &package) {
                CloneSplitOutcome::Complete => serde_json::to_string(&json!({
                    "schema": "keyferry.clone-split-result.v1",
                    "outcome": "COMPLETE",
                    "write": {
                        "offset": APPLICATION_OFFSET,
                        "partition_length": APPLICATION_PARTITION_SIZE,
                        "image_length": package.image().len(),
                        "sha256": package.plan_only().firmware.image_sha256,
                    },
                    "erased_state": {
                        "offset": keyferry_firmware::CLONE_SPLIT_STATE_OFFSET,
                        "length": keyferry_firmware::CLONE_SPLIT_STATE_BYTES,
                    }
                }))
                .map_err(|_| "firmware.serialization"),
                CloneSplitOutcome::Rejected(error) => Err(error.code()),
                CloneSplitOutcome::Interrupted(_) => Err("firmware.clone_split_interrupted"),
            }
        }
        _ => Err("input.usage"),
    }
}

#[cfg(windows)]
fn valid_local_port(port: &str) -> bool {
    let Some(number) = port.strip_prefix("COM") else {
        return false;
    };
    (1..=3).contains(&number.len())
        && number.bytes().all(|byte| byte.is_ascii_digit())
        && !number.starts_with('0')
}

#[cfg(not(windows))]
fn valid_local_port(port: &str) -> bool {
    port.len() <= 128
        && !port.contains("..")
        && (port.starts_with("/dev/tty") || port.starts_with("/dev/cu."))
        && port.bytes().all(|byte| byte.is_ascii_graphic())
}

const PACKAGE_FILES: [&str; 7] = [
    "manifest.json",
    "board-manifest.toml",
    "partitions.csv",
    "keyferry_hil_endpoint.bin",
    "keyferry_hil_endpoint.elf",
    "bootloader.bin",
    "partition-table.bin",
];

fn read_package(root: &Path) -> Result<PreparedUpdatePackage, &'static str> {
    let metadata = std::fs::symlink_metadata(root).map_err(|_| "input.read")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("input.file_type");
    }
    let actual = std::fs::read_dir(root)
        .map_err(|_| "input.read")?
        .map(|entry| {
            entry
                .map_err(|_| "input.read")?
                .file_name()
                .into_string()
                .map_err(|_| "input.package_shape")
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = PACKAGE_FILES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("input.package_shape");
    }
    let file = |name: &str, limit| read_bounded(&root.join(name), limit);
    let manifest = file("manifest.json", MAX_METADATA_BYTES)?;
    let board = file("board-manifest.toml", MAX_METADATA_BYTES)?;
    let partitions = file("partitions.csv", MAX_METADATA_BYTES)?;
    let image = file("keyferry_hil_endpoint.bin", MAX_IMAGE_BYTES)?;
    let elf = file("keyferry_hil_endpoint.elf", MAX_ELF_BYTES)?;
    let bootloader = file("bootloader.bin", MAX_METADATA_BYTES)?;
    let partition_table = file("partition-table.bin", MAX_METADATA_BYTES)?;
    prepare_update_package(
        &manifest,
        &board,
        &partitions,
        &image,
        &elf,
        &bootloader,
        &partition_table,
    )
    .map_err(PlanError::code)
}

fn argument<'a>(args: &'a [String], flag: &str) -> Result<&'a str, &'static str> {
    let mut result = None;
    for pair in args[1..].chunks_exact(2) {
        if pair[0] == flag {
            if result.is_some() {
                return Err("input.usage");
            }
            result = Some(pair[1].as_str());
        }
    }
    result.ok_or("input.usage")
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "input.read")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("input.file_type");
    }
    let file = File::open(path).map_err(|_| "input.read")?;
    let mut bytes = Vec::with_capacity(limit.min(4096));
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "input.read")?;
    if bytes.len() > limit {
        return Err("input.size_limit");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn incomplete_apply_and_ambiguous_arguments_are_not_commands() {
        for args in [
            vec!["apply".to_owned()],
            vec!["plan".to_owned()],
            vec![
                "plan".to_owned(),
                "--manifest".to_owned(),
                "one".to_owned(),
                "--manifest".to_owned(),
                "two".to_owned(),
                "--partitions".to_owned(),
                "three".to_owned(),
                "--image".to_owned(),
                "four".to_owned(),
            ],
        ] {
            assert_eq!(run(args), Err("input.usage"));
        }
    }

    #[test]
    fn help_is_machine_readable_and_exposes_only_the_bounded_apply() {
        let help: serde_json::Value =
            serde_json::from_str(&run(vec!["--help".to_owned()]).unwrap()).unwrap();
        assert_eq!(
            help["commands"],
            json!([
                "manifest",
                "plan",
                "apply",
                "clone-split-plan",
                "clone-split-apply",
                "backup"
            ])
        );
        assert_eq!(help["apply_available"], true);
        assert!(help["usage"]["backup"]
            .as_str()
            .unwrap()
            .contains("--output NEW_DIR"));
        assert!(help["usage"]["plan"].is_array());
        assert_eq!(
            help["usage"]["apply"]
                .as_str()
                .unwrap()
                .matches("--")
                .count(),
            4
        );
    }

    #[test]
    fn python_backend_has_one_locked_application_write_and_requires_manual_rom_entry() {
        let source = include_str!("../esptool_backend.py");
        assert!(source.contains("connect_mode=\"no-reset\""));
        assert!(source.contains("if esp.IS_STUB"));
        assert!(source.contains("cmds.attach_flash("));
        assert_eq!(source.matches("cmds.write_flash(").count(), 1);
        for required in [
            "offset != APPLICATION_OFFSET",
            "flash_freq=\"keep\"",
            "flash_mode=\"keep\"",
            "flash_size=\"keep\"",
            "erase_all=False",
            "encrypt=False",
            "compress=False",
            "no_compress=True",
            "force=False",
            "ignore_flash_enc_efuse=False",
            "[(offset, image)]",
            "readback != image",
        ] {
            assert!(source.contains(required), "missing {required}");
        }
        assert!(!source.contains("io.BytesIO"));
        assert_eq!(source.matches("cmds.erase_region(").count(), 1);
        for required in [
            "CLONE_STATE_OFFSET = 0x110000",
            "CLONE_STATE_BYTES = 0xB000",
            "CLONE_SUFFIX_OFFSET = 0x11B000",
            "(APPLICATION_OFFSET, 0x1000)",
            "force=False",
            "data == b\"\\xff\" * request[\"length\"]",
            "data[size:] == b\"\\xff\" * (MAX_APPLICATION_BYTES - size)",
            "_sha256(prefix) == request[\"prefix_sha256\"]",
            "_sha256(suffix) == request[\"suffix_sha256\"]",
            "_strict_json(line, \"firmware.clone_split_protocol\")",
        ] {
            assert!(source.contains(required), "missing {required}");
        }
        for forbidden in [
            "cmds.erase_flash(",
            "cmds.run_stub(",
            ".hard_reset(",
            ".soft_reset(",
        ] {
            assert!(!source.contains(forbidden), "found {forbidden}");
        }
    }

    #[test]
    fn production_plan_path_reads_exact_files_and_returns_compact_json() {
        const BOARD: &[u8] =
            include_bytes!("../../../tests/fixtures/qualified-board-manifest.toml");
        const PARTITIONS: &[u8] =
            include_bytes!("../../../firmware/esp32s3/hil_endpoint/partitions.csv");
        const ELF: &[u8] = b"test-elf";
        const BOOTLOADER: &[u8] = b"test-bootloader";
        const PARTITION_TABLE: &[u8] = b"test-partition-table";
        const ELF_DIGEST: [u8; 32] = [
            0x2d, 0x2b, 0xe9, 0xf3, 0x73, 0xe0, 0x10, 0x6b, 0x06, 0x7c, 0x74, 0xbc, 0xaf, 0xc8,
            0x17, 0x33, 0xe4, 0x57, 0x32, 0x09, 0x82, 0xc2, 0x69, 0xb7, 0xd8, 0xde, 0x8f, 0x4e,
            0x21, 0x3d, 0x40, 0xa8,
        ];
        let mut image_bytes = vec![0xA5; 4096];
        let descriptor = 128;
        image_bytes[descriptor..descriptor + 256].fill(0);
        image_bytes[descriptor..descriptor + 4].copy_from_slice(&0xABCD_5432_u32.to_le_bytes());
        image_bytes[descriptor + 16..descriptor + 21].copy_from_slice(b"0.1.0");
        image_bytes[descriptor + 48..descriptor + 69].copy_from_slice(b"keyferry_hil_endpoint");
        image_bytes[descriptor + 112..descriptor + 118].copy_from_slice(b"v6.0.3");
        image_bytes[descriptor + 144..descriptor + 176].copy_from_slice(&ELF_DIGEST);
        let generated = generate_update_manifest(
            ManifestMetadata {
                source_revision: "0123456789abcdef0123456789abcdef01234567",
                esptool_version: "5.4.0",
            },
            BOARD,
            PARTITIONS,
            &image_bytes,
            ELF,
            BOOTLOADER,
            PARTITION_TABLE,
        )
        .unwrap();
        let manifest_bytes = serde_json::to_vec(&generated).unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "keyferry-firmware-test-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let manifest = root.join("manifest.json");
        let board = root.join("board.toml");
        let partitions = root.join("partitions.csv");
        let image = root.join("image.bin");
        let elf = root.join("image.elf");
        let bootloader = root.join("bootloader.bin");
        let partition_table = root.join("partition-table.bin");
        std::fs::write(&manifest, &manifest_bytes).unwrap();
        std::fs::write(&board, BOARD).unwrap();
        std::fs::write(&partitions, PARTITIONS).unwrap();
        std::fs::write(&image, &image_bytes).unwrap();
        std::fs::write(&elf, ELF).unwrap();
        std::fs::write(&bootloader, BOOTLOADER).unwrap();
        std::fs::write(&partition_table, PARTITION_TABLE).unwrap();

        let output = run(vec![
            "plan".to_owned(),
            "--manifest".to_owned(),
            manifest.to_string_lossy().into_owned(),
            "--board-manifest".to_owned(),
            board.to_string_lossy().into_owned(),
            "--partitions".to_owned(),
            partitions.to_string_lossy().into_owned(),
            "--image".to_owned(),
            image.to_string_lossy().into_owned(),
            "--elf".to_owned(),
            elf.to_string_lossy().into_owned(),
            "--bootloader".to_owned(),
            bootloader.to_string_lossy().into_owned(),
            "--partition-table".to_owned(),
            partition_table.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let plan: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(plan["mode"], "PLAN_ONLY");
        assert_eq!(plan["apply_available"], false);
        assert_eq!(plan["write"]["offset"], 65_536);
        assert!(!output.contains(root.to_string_lossy().as_ref()));

        let package = root.join("package");
        std::fs::create_dir(&package).unwrap();
        for (name, bytes) in [
            ("manifest.json", manifest_bytes.as_slice()),
            ("board-manifest.toml", BOARD),
            ("partitions.csv", PARTITIONS),
            ("keyferry_hil_endpoint.bin", image_bytes.as_slice()),
            ("keyferry_hil_endpoint.elf", ELF),
            ("bootloader.bin", BOOTLOADER),
            ("partition-table.bin", PARTITION_TABLE),
        ] {
            std::fs::write(package.join(name), bytes).unwrap();
        }
        let prepared_package = read_package(&package).unwrap();
        let clone_binding = CloneSplitBindingV1 {
            schema: keyferry_firmware::CLONE_SPLIT_BINDING_SCHEMA.to_owned(),
            rom_mac: "02:00:00:00:00:02".to_owned(),
            board_compatibility_id: 2,
            old_device_id: "01234567-89ab-4cde-8fab-0123456789ab".to_owned(),
            new_device_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            owner_transaction_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            unit_binding_sha256: "7".repeat(64),
            source_application_sha256: "1".repeat(64),
            source_state_sha256: "2".repeat(64),
            protected_prefix_sha256: "3".repeat(64),
            protected_suffix_sha256: "4".repeat(64),
            private_input_sha256: "5".repeat(64),
            fallback_fingerprint_sha256: "6".repeat(64),
        };
        let raw_clone_observation = json!({
            "schema": "keyferry.clone-split-observation.v1",
            "port": "COM16",
            "rom_mac": clone_binding.rom_mac.clone(),
            "chip": "esp32s3",
            "soc_revision": "v0.2",
            "flash_manufacturer_id": "0x20",
            "flash_device_id": "0x4018",
            "flash_size_bytes": 16777216,
            "secure_boot": false,
            "flash_encryption": false,
            "secure_download_mode": false,
            "efuse_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bootloader_sha256": generated.preserved.bootloader_sha256.clone(),
            "partition_table_sha256": generated.preserved.partition_table_sha256.clone(),
            "application_sha256": clone_binding.source_application_sha256.clone(),
            "state_sha256": clone_binding.source_state_sha256.clone(),
            "protected_prefix_sha256": clone_binding.protected_prefix_sha256.clone(),
            "protected_suffix_sha256": clone_binding.protected_suffix_sha256.clone(),
            "esptool_version": "5.4.0"
        });
        let observed = clone_observation(
            &prepared_package,
            &clone_binding,
            "COM16",
            &serde_json::to_vec(&raw_clone_observation).unwrap(),
        )
        .unwrap();
        assert_eq!(observed.exact_unit.port, "COM16");
        let mut unknown = raw_clone_observation;
        unknown["unexpected"] = json!(true);
        assert_eq!(
            clone_observation(
                &prepared_package,
                &clone_binding,
                "COM16",
                &serde_json::to_vec(&unknown).unwrap(),
            ),
            Err("firmware.clone_split_observation")
        );
        let unit_record = root.join("unit-record.json");
        std::fs::write(
            &unit_record,
            serde_json::to_vec(&json!({
                "schema": "keyferry.exact-unit-record.v1",
                "device_label": "synthetic-test-unit",
                "rom_mac": "02:00:00:00:00:01",
                "chip": "esp32s3",
                "soc_revision": "v0.2",
                "flash_manufacturer_id": "0x20",
                "flash_device_id": "0x4018",
                "flash_size_bytes": 16777216,
                "secure_boot": false,
                "flash_encryption": false,
                "secure_download_mode": false,
                "board_manifest_sha256": generated.target.board_manifest_sha256,
                "partition_map_sha256": generated.target.partition_map_sha256,
                "efuse_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "qualified_recovery_cycles": 2
            }))
            .unwrap(),
        )
        .unwrap();
        struct FakeProbe(Vec<u8>);
        impl RomProbeRunner for FakeProbe {
            fn probe(
                &self,
                port: &str,
                requirements: RomProbeRequirements,
            ) -> Result<Vec<u8>, &'static str> {
                assert_eq!(port, "COM7");
                assert_eq!(requirements.bootloader_size_bytes, BOOTLOADER.len() as u64);
                assert_eq!(
                    requirements.partition_table_size_bytes,
                    PARTITION_TABLE.len() as u64
                );
                Ok(self.0.clone())
            }
        }
        let probe = FakeProbe(
            serde_json::to_vec(&json!({
                "schema": "keyferry.rom-probe-result.v1",
                "mode": "READ_ONLY_PLAN",
                "port": "COM7",
                "rom_mac": "02:00:00:00:00:01",
                "chip": "esp32s3",
                "soc_revision": "v0.2",
                "flash_manufacturer_id": "0x20",
                "flash_device_id": "0x4018",
                "flash_size_bytes": 16777216,
                "secure_boot": false,
                "flash_encryption": false,
                "secure_download_mode": false,
                "efuse_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bootloader_sha256": generated.preserved.bootloader_sha256,
                "partition_table_sha256": generated.preserved.partition_table_sha256,
                "esptool_version": "5.4.0"
            }))
            .unwrap(),
        );
        let exact_output = run_with_backends(
            vec![
                "plan".to_owned(),
                "--package".to_owned(),
                package.to_string_lossy().into_owned(),
                "--port".to_owned(),
                "COM7".to_owned(),
                "--unit-record".to_owned(),
                unit_record.to_string_lossy().into_owned(),
            ],
            &probe,
            &RefuseApplyRunner,
            &RefuseCloneSplitRunner,
            &RefuseBackupRunner,
        )
        .unwrap();
        let exact: serde_json::Value = serde_json::from_str(&exact_output).unwrap();
        assert_eq!(exact["mode"], "EXACT_UNIT_PLAN");
        assert_eq!(exact["target"]["port"], "COM7");
        assert_eq!(exact["authorization_sha256"].as_str().unwrap().len(), 64);
        assert!(!exact_output.contains("02:00:00:00:00:01"));
        struct FakeBackup;
        impl BackupRunner for FakeBackup {
            fn backup(
                &self,
                package: &PreparedUpdatePackage,
                record: &[u8],
                port: &str,
                output: &Path,
            ) -> Result<serde_json::Value, &'static str> {
                assert_eq!(package.image().len(), 4096);
                assert!(!record.is_empty());
                assert_eq!(port, "COM7");
                assert!(output.is_dir());
                Ok(json!({"schema":"keyferry.firmware-backup-result.v1","outcome":"READ_VERIFIED"}))
            }
        }
        let backup_dir = root.join("backup-new");
        let backup_args = vec![
            "backup".to_owned(),
            "--package".to_owned(),
            package.to_string_lossy().into_owned(),
            "--port".to_owned(),
            "COM7".to_owned(),
            "--unit-record".to_owned(),
            unit_record.to_string_lossy().into_owned(),
            "--output".to_owned(),
            backup_dir.to_string_lossy().into_owned(),
        ];
        let backup = run_with_backends(
            backup_args.clone(),
            &probe,
            &RefuseApplyRunner,
            &RefuseCloneSplitRunner,
            &FakeBackup,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&backup).unwrap()["outcome"],
            "READ_VERIFIED"
        );
        assert!(backup_dir.join("receipt.json").is_file());
        assert_eq!(
            run_with_backends(
                backup_args,
                &probe,
                &RefuseApplyRunner,
                &RefuseCloneSplitRunner,
                &FakeBackup
            ),
            Err("input.output")
        );
        // The actual production coordinator must withhold the bulk-read grant
        // until its first ROM observation matches the qualified unit.
        let python = backend_paths().map(|paths| paths.0).unwrap_or_else(|_| {
            Path::new(if cfg!(windows) { "python" } else { "python3" }).to_path_buf()
        });
        let initial_probe = String::from_utf8(probe.0.clone()).unwrap();
        let script_for = |scenario: &str| {
            format!(
                r#"import hashlib,json,pathlib,sys
first=json.loads({initial:?})
scenario={scenario:?}
if scenario=='wrong_initial': first['rom_mac']='02:00:00:00:00:02'
print(json.dumps(first),flush=True)
request=sys.stdin.readline()
if not request: sys.exit(3)
root=pathlib.Path(sys.argv[-1])
(root/'grant').write_text('read authorized')
snapshot=root/'full-flash.partial'
with snapshot.open('wb') as out:
    out.truncate(16777216)
    out.seek(65536)
    out.write(pathlib.Path({image:?}).read_bytes())
digest=hashlib.sha256(snapshot.read_bytes()).hexdigest()
after=first.copy()
if scenario=='wrong_final': after['rom_mac']='02:00:00:00:00:02'
if scenario=='wrong_digest': digest='0'*64
print(json.dumps({{'schema':'keyferry.backup-session-result.v1','size_bytes':16777216,'sha256':digest,'second_pass_equal':True,'after':after}}),flush=True)
"#,
                initial = initial_probe,
                scenario = scenario,
                image = image.to_string_lossy()
            )
        };
        for scenario in ["wrong_initial", "wrong_final", "wrong_digest"] {
            let helper = root.join(format!("fake-backup-{scenario}.py"));
            fs::write(&helper, script_for(scenario)).unwrap();
            let destination = root.join(format!("snapshot-{scenario}"));
            fs::create_dir(&destination).unwrap();
            let result = ProductionBackupRunner.backup_with_paths(
                &prepared_package,
                &fs::read(&unit_record).unwrap(),
                "COM7",
                &destination,
                &python,
                &helper,
            );
            assert!(result.is_err(), "{scenario} unexpectedly promoted");
            assert!(!destination.join("full-flash.bin").exists());
            assert!(!destination.join("receipt.json").exists());
            assert_eq!(
                destination.join("grant").exists(),
                scenario != "wrong_initial"
            );
        }
        assert_eq!(
            run_with_backends(
                vec![
                    "plan".to_owned(),
                    "--package".to_owned(),
                    package.to_string_lossy().into_owned(),
                    "--port".to_owned(),
                    "rfc2217:example.invalid:1234".to_owned(),
                    "--unit-record".to_owned(),
                    unit_record.to_string_lossy().into_owned(),
                ],
                &probe,
                &RefuseApplyRunner,
                &RefuseCloneSplitRunner,
                &RefuseBackupRunner,
            ),
            Err("input.port")
        );

        #[derive(Clone, Copy)]
        struct FakeApply(ApplyOutcome);
        impl ApplyRunner for FakeApply {
            fn apply(
                &self,
                plan: &[u8],
                authorize: &str,
                package: &PreparedUpdatePackage,
                unit_record: &[u8],
            ) -> ApplyOutcome {
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(plan).unwrap()
                        ["authorization_sha256"],
                    authorize
                );
                assert_eq!(package.image().len(), 4096);
                assert!(!unit_record.is_empty());
                self.0
            }
        }
        let exact_plan = root.join("exact-plan.json");
        std::fs::write(&exact_plan, &exact_output).unwrap();
        let authorize = exact["authorization_sha256"].as_str().unwrap().to_owned();
        let apply_args = vec![
            "apply".to_owned(),
            "--plan".to_owned(),
            exact_plan.to_string_lossy().into_owned(),
            "--authorize".to_owned(),
            authorize,
            "--package".to_owned(),
            package.to_string_lossy().into_owned(),
            "--unit-record".to_owned(),
            unit_record.to_string_lossy().into_owned(),
        ];
        let applied = run_with_backends(
            apply_args.clone(),
            &probe,
            &FakeApply(ApplyOutcome::WriteVerified),
            &RefuseCloneSplitRunner,
            &RefuseBackupRunner,
        )
        .unwrap();
        let applied: serde_json::Value = serde_json::from_str(&applied).unwrap();
        assert_eq!(applied["outcome"], "WRITE_VERIFIED");
        assert_eq!(applied["write"]["offset"], 65_536);
        assert_eq!(
            run_with_backends(
                apply_args,
                &probe,
                &FakeApply(ApplyOutcome::UnknownWrite),
                &RefuseCloneSplitRunner,
                &RefuseBackupRunner,
            ),
            Err("firmware.apply_unknown_write")
        );

        std::fs::write(package.join("unexpected.txt"), b"not allowed").unwrap();
        assert_eq!(read_package(&package), Err("input.package_shape"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_reader_rejects_non_files_without_echoing_paths() {
        let error = read_bounded(&env::temp_dir(), 16).unwrap_err();
        assert_eq!(error, "input.file_type");
        assert!(!error.contains(env::temp_dir().to_string_lossy().as_ref()));
    }

    #[test]
    fn snapshot_validation_checks_exact_installed_app_and_length() {
        let root =
            env::temp_dir().join(format!("keyferry-backup-validation-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let path = root.join("full-flash.partial");
        let image = vec![0x5a; 1024];
        let mut bytes = vec![0xff; 0x20000];
        bytes[0x10000..0x10400].copy_from_slice(&image);
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            snapshot_digest_and_app(&path, bytes.len() as u64, &image).unwrap(),
            format!("{:x}", Sha256::digest(&bytes))
        );
        assert_eq!(
            snapshot_digest_and_app(&path, bytes.len() as u64, b"wrong"),
            Err("firmware.backup_app_mismatch")
        );
        assert_eq!(
            snapshot_digest_and_app(&path, bytes.len() as u64 + 1, &image),
            Err("firmware.backup_snapshot")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
