use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const PAIRING_EXE_ENV: &str = "KEYFERRY_PAIRING_EXE";
const PAIRING_BUNDLE_ENV: &str = "KEYFERRY_PAIRING_BUNDLE";
const OWNER_KIT_ENV: &str = "KEYFERRY_OWNER_KIT";
const MAX_STATUS_BYTES: usize = 4096;
const MAX_POLICY_BYTES: u64 = 32 * 1024;
pub const MAX_WIFI_PROFILES: usize = 8;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WifiPolicy {
    pub schema_version: u8,
    pub wifi_profiles: Vec<WifiProfile>,
    pub revoked_installation_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WifiProfile {
    pub ssid: String,
    pub password: String,
    pub priority: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalStatusDocument {
    schema: String,
    device_id: String,
    device: LocalDeviceStatus,
    safety: LocalSafetyStatus,
    network: LocalNetworkStatus,
    ble_hid: LocalBleStatus,
    policy: LocalPolicyStatus,
    last_receipt: Option<LocalReceiptStatus>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalDeviceStatus {
    active_output_mode: u8,
    stored_output_mode: u8,
    board_compatibility_id: u8,
    release: String,
    capabilities: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalSafetyStatus {
    maintenance_active: bool,
    command_active: bool,
    armed: bool,
    usb_mounted: bool,
    keyboard_neutral: bool,
    mouse_neutral: bool,
    restart_pending: bool,
    receipt_storage_healthy: bool,
    usb_attachment_generation: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalNetworkStatus {
    wifi_stage: u8,
    active_path: u8,
    running: bool,
    wifi_available: bool,
    ble_available: bool,
    endpoint_authenticated: bool,
    configuration_valid: bool,
    wifi_profile_count: u8,
    paired_host_count: u8,
    policy_state: u8,
    wifi_error: i32,
    nvs_error: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalBleStatus {
    bond_state: u8,
    peripheral_stage: u8,
    advertising: bool,
    connected: bool,
    authenticated: bool,
    subscribed: bool,
    ready: bool,
    enrollment_active: bool,
    error: i32,
    generation: u32,
    enrollment_remaining_ms: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalPolicyStatus {
    state: u8,
    sequence: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalReceiptStatus {
    state: u8,
    operation: u8,
    result: u8,
    flags: u8,
    argument: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalRecoveryAttempt {
    schema: String,
    device_id: String,
    action: String,
    maintenance_open_id: String,
    action_id: String,
    maintenance_close_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalRecoveryResult {
    schema: String,
    action: String,
    outcome: String,
    #[serde(default)]
    status: Option<u8>,
    #[serde(default)]
    stage: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    operation_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerDeviceAdded {
    schema: String,
    device_id: String,
    authority_epoch: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerDevices {
    schema: String,
    device_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceBootstrapMaterialized {
    schema: String,
    device_id: String,
    installation_id: String,
    authority_epoch: u64,
    private_input_sha256: String,
}

impl Drop for WifiProfile {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl WifiPolicy {
    pub fn normalize_priorities(&mut self) {
        for (index, profile) in self.wifi_profiles.iter_mut().enumerate() {
            profile.priority = u8::MAX - index as u8;
        }
    }
}

pub fn default_bundle_path() -> String {
    env::var_os(PAIRING_BUNDLE_ENV)
        .map(PathBuf::from)
        .or_else(read_bundle_pointer)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub fn default_owner_kit_path(bundle: &Path) -> String {
    env::var_os(OWNER_KIT_ENV)
        .map(PathBuf::from)
        .or_else(|| owner_kit_path_from_bundle(bundle))
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub fn default_wifi_policy_path(owner_kit: &Path) -> String {
    owner_kit
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.join("roaming-policy.json"))
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub fn status(bundle: &Path) -> Result<String, String> {
    validate_bundle(bundle)?;
    run_helper(bundle, &["status"], None)
}

pub fn local_status(owner_kit: &Path, passphrase: &str, device_id: &str) -> Result<String, String> {
    validate_local_secret(owner_kit, passphrase)?;
    let owner_kit_text = owner_kit.to_string_lossy();
    let args = local_status_args(owner_kit_text.as_ref(), device_id)?;
    let input = secret_line(passphrase);
    let output = run_helper_inner(None, &args, Some(input.as_slice()))?;
    let status: LocalStatusDocument = serde_json::from_str(&output)
        .map_err(|_| "The local status response was invalid.".to_owned())?;
    verify_local_status_device(&status, device_id)?;
    format_local_status(status)
}

fn verify_local_status_device(status: &LocalStatusDocument, device_id: &str) -> Result<(), String> {
    if status.device_id != device_id.replace('-', "") {
        return Err("The local status response named another Keyferry.".to_owned());
    }
    Ok(())
}

fn format_local_status(status: LocalStatusDocument) -> Result<String, String> {
    if status.schema != "keyferry.local-status.v1"
        || status.device_id.len() != 32
        || !is_lower_hex(&status.device_id)
        || status.device.release.is_empty()
        || status.device.release.len() > 8
        || !status
            .device
            .release
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
    {
        return Err("The local status response was invalid.".to_owned());
    }
    let bond = match status.ble_hid.bond_state {
        keyferry_protocol::local_management_bond_state::NONE => "none",
        keyferry_protocol::local_management_bond_state::SINGLE => "one paired computer",
        keyferry_protocol::local_management_bond_state::MULTIPLE_INVALID => {
            "invalid multiple bonds"
        }
        keyferry_protocol::local_management_bond_state::STORE_ERROR => "storage error",
        _ => return Err("The local status response was invalid.".to_owned()),
    };
    let active_output = output_mode_label(status.device.active_output_mode)?;
    let stored_output = output_mode_label(status.device.stored_output_mode)?;
    let receipt = status
        .last_receipt
        .as_ref()
        .map(|value| {
            format!(
                "state {} / operation {} / result {} / flags {} / argument {}",
                value.state, value.operation, value.result, value.flags, value.argument
            )
        })
        .unwrap_or_else(|| "none".to_owned());
    Ok(format!(
        "Connected directly to {}. Firmware {} · board {} · output {} (stored {}).\nSafety: maintenance {} · command {} · armed {} · USB {} · keyboard {} · mouse {} · restart {} · receipts {} · attachment {}.\nNetwork: runtime {} · Wi-Fi {} · control BLE {} · endpoint auth {} · config {} · profiles {} · hosts {} · stage {} · path {} · policy state {} · Wi-Fi error {} · NVS error {}.\nBluetooth keyboard: bond {} · ready {} · connected {} · authenticated {} · subscribed {} · advertising {} · enrollment {} ({} ms) · stage {} · error {} · generation {}.\nPolicy: state {} · sequence {} · last receipt {} · capabilities 0x{:08x}.",
        status.device_id,
        status.device.release,
        status.device.board_compatibility_id,
        active_output,
        stored_output,
        yes_no(status.safety.maintenance_active),
        yes_no(status.safety.command_active),
        yes_no(status.safety.armed),
        if status.safety.usb_mounted { "mounted" } else { "not mounted" },
        neutral_label(status.safety.keyboard_neutral),
        neutral_label(status.safety.mouse_neutral),
        yes_no(status.safety.restart_pending),
        if status.safety.receipt_storage_healthy { "healthy" } else { "unhealthy" },
        status.safety.usb_attachment_generation,
        yes_no(status.network.running),
        available_label(status.network.wifi_available),
        available_label(status.network.ble_available),
        yes_no(status.network.endpoint_authenticated),
        if status.network.configuration_valid { "valid" } else { "invalid" },
        status.network.wifi_profile_count,
        status.network.paired_host_count,
        status.network.wifi_stage,
        status.network.active_path,
        status.network.policy_state,
        status.network.wifi_error,
        status.network.nvs_error,
        bond,
        yes_no(status.ble_hid.ready),
        yes_no(status.ble_hid.connected),
        yes_no(status.ble_hid.authenticated),
        yes_no(status.ble_hid.subscribed),
        yes_no(status.ble_hid.advertising),
        if status.ble_hid.enrollment_active { "open" } else { "closed" },
        status.ble_hid.enrollment_remaining_ms,
        status.ble_hid.peripheral_stage,
        status.ble_hid.error,
        status.ble_hid.generation,
        status.policy.state,
        status.policy.sequence,
        receipt,
        status.device.capabilities,
    ))
}

pub fn local_recover(
    owner_kit: &Path,
    passphrase: &str,
    device_id: &str,
    action: &str,
) -> Result<String, String> {
    validate_local_secret(owner_kit, passphrase)?;
    if !matches!(
        action,
        "restart-network"
            | "forget-bluetooth"
            | "cancel-enrollment"
            | "usb-hid"
            | "ble-hid"
            | "reboot"
    ) {
        return Err("The local recovery action is unsupported.".to_owned());
    }
    let owner_kit_text = owner_kit.to_string_lossy();
    let args = local_recover_args(owner_kit_text.as_ref(), device_id, action)?;
    let input = secret_line(passphrase);
    let output = run_helper_capture(None, &args, Some(input.as_slice()))?;
    interpret_local_recovery_output(
        output.status.success(),
        device_id,
        action,
        &output.stdout,
        &output.stderr,
    )
}

fn local_status_args<'a>(owner_kit: &'a str, device_id: &'a str) -> Result<[&'a str; 5], String> {
    if !canonical_uuid(device_id) {
        return Err("Select the exact Keyferry before using local USB status.".to_owned());
    }
    Ok([
        "local-status",
        "--owner-kit",
        owner_kit,
        "--device",
        device_id,
    ])
}

fn local_recover_args<'a>(
    owner_kit: &'a str,
    device_id: &'a str,
    action: &'a str,
) -> Result<[&'a str; 6], String> {
    if !canonical_uuid(device_id) {
        return Err("Select the exact Keyferry before using local USB recovery.".to_owned());
    }
    Ok([
        "local-recover",
        "--owner-kit",
        owner_kit,
        "--device",
        device_id,
        action,
    ])
}

fn interpret_local_recovery_output(
    helper_succeeded: bool,
    device_id: &str,
    action: &str,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<String, String> {
    if stdout.is_empty() {
        if !helper_succeeded {
            let error = String::from_utf8_lossy(stderr);
            match error.trim() {
                "keyferry helper error: owner-kit file is absent or invalid" => {
                    return Err("The owner-kit file is absent or invalid.".to_owned())
                }
                "keyferry helper error: owner-kit authentication, selection, or authority validation failed" => {
                    return Err("The owner-kit password or selected Keyferry is invalid.".to_owned())
                }
                "keyferry helper error: exactly one matching local Keyferry USB interface is required" => {
                    return Err("Connect the selected Keyferry directly by USB.".to_owned())
                }
                "keyferry helper error: local Keyferry authentication failed" => {
                    return Err("Local USB authentication failed for the selected Keyferry.".to_owned())
                }
                _ => {}
            }
        }
        return Err(missing_local_recovery_receipt(action));
    }
    match interpret_local_recovery(helper_succeeded, device_id, action, stdout) {
        Err(error)
            if error == "The local recovery response was missing."
                || error == "The local recovery response was invalid." =>
        {
            Err(missing_local_recovery_receipt(action))
        }
        result => result,
    }
}

fn missing_local_recovery_receipt(action: &str) -> String {
    format!(
        "Local {} outcome is unknown because no valid receipt was returned. Check the selected Keyferry before trying again; do not repeat it automatically.",
        action_label(action)
    )
}

pub struct PreparedSecondDevice {
    pub device_id: String,
    pub expanded_installation: PathBuf,
    pub bootstrap: PathBuf,
    pub private_input_sha256: String,
}

/// Returns the canonical device UUIDs the encrypted owner kit can authorize.
pub fn list_owner_devices(owner_kit: &Path, passphrase: &str) -> Result<Vec<String>, String> {
    validate_local_secret(owner_kit, passphrase)?;
    let owner_kit_text = owner_kit.to_string_lossy();
    let input = secret_line(passphrase);
    let devices_text = run_helper_inner(
        None,
        &["list-owner-devices", "--owner-kit", owner_kit_text.as_ref()],
        Some(input.as_slice()),
    )?;
    let devices: OwnerDevices = serde_json::from_str(&devices_text)
        .map_err(|_| "The owner-device listing response was invalid.".to_owned())?;
    if devices.schema != "keyferry.owner-devices.v1"
        || devices.device_ids.is_empty()
        || devices
            .device_ids
            .iter()
            .any(|device_id| !canonical_uuid(device_id))
    {
        return Err("The owner-device listing response was invalid.".to_owned());
    }
    Ok(devices.device_ids)
}

/// True once this computer holds its own owner-issued credentials.
pub fn this_computer_is_authorized() -> bool {
    keyferry::api::default_installation_path().is_dir()
}

/// Issues this computer's own credential for exactly one device into the path the daemon
/// reads. The helper publishes the directory with one rename, and a waiting daemon starts from
/// it, so authorization needs no restart and never copies another computer's identity.
pub fn authorize_this_computer(
    owner_kit: &Path,
    passphrase: &str,
    device_id: &str,
) -> Result<(), String> {
    validate_local_secret(owner_kit, passphrase)?;
    if !canonical_uuid(device_id) {
        return Err("Choose the Keyferry this computer should control.".to_owned());
    }
    let installation = keyferry::api::default_installation_path();
    if installation.exists() {
        return Err("This computer is already authorized.".to_owned());
    }
    let owner_kit_text = owner_kit.to_string_lossy();
    let installation_text = installation.to_string_lossy();
    let input = secret_line(passphrase);
    run_helper_inner(
        None,
        &[
            "issue-installation",
            "--owner-kit",
            owner_kit_text.as_ref(),
            "--device",
            device_id,
            "--output",
            installation_text.as_ref(),
        ],
        Some(input.as_slice()),
    )?;
    Ok(())
}

pub fn prepare_second_device(
    owner_kit: &Path,
    passphrase: &str,
    existing_installation: &Path,
    network_bundle: &Path,
) -> Result<PreparedSecondDevice, String> {
    validate_local_secret(owner_kit, passphrase)?;
    if !existing_installation.is_dir() {
        return Err("The current installation credentials are unavailable.".to_owned());
    }
    if !network_bundle.is_dir() {
        return Err("The private network bootstrap bundle is unavailable.".to_owned());
    }
    let private_root = owner_kit
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| "The owner-kit directory is unavailable.".to_owned())?;
    let host = env::var("COMPUTERNAME")
        .ok()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 63
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .ok_or_else(|| "The local computer name is unavailable.".to_owned())?;
    let expanded_installation = private_root
        .join("installations")
        .join(format!("{host}-multi"));
    let bootstrap = private_root.join("lilygo-bootstrap");
    if expanded_installation.exists() || bootstrap.exists() {
        return Err(
            "Second-device preparation output already exists; inspect it instead of repeating issuance."
                .to_owned(),
        );
    }

    let owner_kit_text = owner_kit.to_string_lossy();
    let device_ids = list_owner_devices(owner_kit, passphrase)?;
    let installed = keyferry_gateway::InstallationCredentials::load(existing_installation)
        .map_err(|_| "The current installation credentials are invalid.".to_owned())?;
    let installed_device_id = format_uuid_bytes(&installed.device_id());
    if !device_ids
        .iter()
        .any(|device_id| device_id == &installed_device_id)
    {
        return Err(
            "The owner kit does not match this computer's installed Keyferry identity.".to_owned(),
        );
    }
    let candidates = device_ids
        .iter()
        .filter(|device_id| device_id.as_str() != installed_device_id.as_str())
        .cloned()
        .collect::<Vec<_>>();
    let added: OwnerDeviceAdded = match candidates.as_slice() {
        [] => {
            let input = secret_line(passphrase);
            let added_text = run_helper_inner(
                None,
                &["add-owner-device", "--owner-kit", owner_kit_text.as_ref()],
                Some(input.as_slice()),
            )?;
            serde_json::from_str(&added_text)
                .map_err(|_| "The device issuance response was invalid.".to_owned())?
        }
        [device_id] => OwnerDeviceAdded {
            schema: "keyferry.owner-device-added.v1".to_owned(),
            device_id: device_id.clone(),
            authority_epoch: 1,
        },
        _ => return Err(
            "The owner kit has multiple unassigned devices; preparation cannot choose one safely."
                .to_owned(),
        ),
    };
    if added.schema != "keyferry.owner-device-added.v1"
        || added.authority_epoch != 1
        || !canonical_uuid(&added.device_id)
    {
        return Err("The device issuance response was invalid.".to_owned());
    }

    let installation_text = existing_installation.to_string_lossy();
    let expanded_text = expanded_installation.to_string_lossy();
    let input = secret_line(passphrase);
    let grant = run_helper_inner(
        None,
        &[
            "grant-device-to-installation",
            "--owner-kit",
            owner_kit_text.as_ref(),
            "--device",
            &added.device_id,
            "--installation",
            installation_text.as_ref(),
            "--output",
            expanded_text.as_ref(),
        ],
        Some(input.as_slice()),
    )
    .map_err(|error| {
        format!(
            "Device {} was issued, but its installation grant failed: {error}. Do not add another device.",
            added.device_id
        )
    })?;
    if grant.trim() != "device grant added to existing installation identity" {
        return Err(format!(
            "Device {} was issued, but its installation grant response was invalid. Do not add another device.",
            added.device_id
        ));
    }

    let network_text = network_bundle.to_string_lossy();
    let bootstrap_text = bootstrap.to_string_lossy();
    let input = secret_line(passphrase);
    let materialized_text = run_helper_inner(
        None,
        &[
            "materialize-device-bootstrap",
            "--owner-kit",
            owner_kit_text.as_ref(),
            "--device",
            &added.device_id,
            "--installation",
            expanded_text.as_ref(),
            "--network-bundle",
            network_text.as_ref(),
            "--output",
            bootstrap_text.as_ref(),
        ],
        Some(input.as_slice()),
    )
    .map_err(|error| {
        format!(
            "Device {} and its installation grant were created, but firmware preparation failed: {error}. Do not add another device.",
            added.device_id
        )
    })?;
    let materialized: DeviceBootstrapMaterialized = serde_json::from_str(&materialized_text)
        .map_err(|_| "The firmware preparation response was invalid.".to_owned())?;
    if materialized.schema != "keyferry.device-bootstrap-materialized.v1"
        || materialized.device_id != added.device_id
        || materialized.authority_epoch != added.authority_epoch
        || materialized.installation_id.len() != 32
        || !is_lower_hex(&materialized.installation_id)
        || materialized.private_input_sha256.len() != 64
        || !is_lower_hex(&materialized.private_input_sha256)
    {
        return Err("The firmware preparation response was invalid.".to_owned());
    }
    Ok(PreparedSecondDevice {
        device_id: added.device_id,
        expanded_installation,
        bootstrap,
        private_input_sha256: materialized.private_input_sha256,
    })
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
        && value.bytes().any(|byte| byte != b'0' && byte != b'-')
}

fn format_uuid_bytes(bytes: &[u8; 16]) -> String {
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn interpret_local_recovery(
    helper_succeeded: bool,
    device_id: &str,
    action: &str,
    stdout: &[u8],
) -> Result<String, String> {
    let invalid = || "The local recovery response was invalid.".to_owned();
    let text = std::str::from_utf8(stdout).map_err(|_| invalid())?;
    let mut lines = text.lines();
    let attempt: LocalRecoveryAttempt =
        serde_json::from_str(lines.next().ok_or_else(invalid)?).map_err(|_| invalid())?;
    let result: LocalRecoveryResult = serde_json::from_str(lines.next().ok_or_else(invalid)?)
        .map_err(|_| "The local recovery response was invalid.".to_owned())?;
    if lines.next().is_some()
        || attempt.schema != "keyferry.local-recovery-attempt.v1"
        || attempt.device_id != device_id.replace('-', "")
        || attempt.action != action
        || [
            &attempt.maintenance_open_id,
            &attempt.action_id,
            &attempt.maintenance_close_id,
        ]
        .iter()
        .any(|value| value.len() != 32 || !is_lower_hex(value))
        || result.schema != "keyferry.local-recovery-result.v1"
        || result.action != action
        || result
            .operation_id
            .as_deref()
            .is_some_and(|value| value.len() != 32 || !is_lower_hex(value))
    {
        return Err(invalid());
    }
    let expected_operation = match result.stage.as_deref() {
        None | Some("action") => &attempt.action_id,
        Some("open-maintenance") => &attempt.maintenance_open_id,
        Some("close-maintenance") => &attempt.maintenance_close_id,
        _ => return Err(invalid()),
    };
    if result
        .operation_id
        .as_ref()
        .is_some_and(|id| id != expected_operation)
    {
        return Err(invalid());
    }
    let operation = result.operation_id.as_deref().unwrap_or("not reported");
    match result.outcome.as_str() {
        "COMPLETED" if helper_succeeded && result.status == Some(0)
            && result.stage.is_none() && result.operation_id.as_ref() == Some(&attempt.action_id) => Ok(format!(
            "Local {} completed. Operation {}.",
            action_label(action),
            operation
        )),
        "REJECTED" if !helper_succeeded && result.status.is_some_and(|status| status != 0)
            && result.stage.is_none() && result.operation_id.as_ref() == Some(&attempt.action_id) => Err(format!(
            "Local {} was rejected (status {}). Operation {}.",
            action_label(action),
            result.status.unwrap_or(u8::MAX),
            operation
        )),
        "UNKNOWN" => Err(format!(
            "Local {} has an unknown outcome at {} ({}). Operation {}. Do not repeat it automatically.",
            action_label(action),
            result.stage.as_deref().unwrap_or("unknown-stage"),
            result.error.as_deref().unwrap_or("local.unknown"),
            operation
        )),
        _ => Err("The local recovery response was invalid.".to_owned()),
    }
}

fn validate_local_secret(owner_kit: &Path, passphrase: &str) -> Result<(), String> {
    if owner_kit.as_os_str().is_empty() {
        return Err("Choose the encrypted owner-kit file first.".to_owned());
    }
    if passphrase.is_empty() || passphrase.len() > 1024 || passphrase.contains(['\r', '\n', '\0']) {
        return Err("Enter a valid owner-kit password.".to_owned());
    }
    Ok(())
}

fn secret_line(passphrase: &str) -> Zeroizing<Vec<u8>> {
    let mut input = Zeroizing::new(Vec::with_capacity(passphrase.len() + 1));
    input.extend_from_slice(passphrase.as_bytes());
    input.push(b'\n');
    input
}

fn output_mode_label(mode: u8) -> Result<&'static str, String> {
    match mode {
        keyferry_protocol::output_mode::USB_HID => Ok("USB keyboard"),
        keyferry_protocol::output_mode::BLE_HID => Ok("Bluetooth keyboard"),
        _ => Err("The local status response was invalid.".to_owned()),
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn neutral_label(value: bool) -> &'static str {
    if value {
        "released"
    } else {
        "not confirmed released"
    }
}

fn available_label(value: bool) -> &'static str {
    if value {
        "available"
    } else {
        "unavailable"
    }
}

fn action_label(action: &str) -> &'static str {
    match action {
        "restart-network" => "network restart",
        "forget-bluetooth" => "Bluetooth bond reset",
        "cancel-enrollment" => "enrollment cancellation",
        "usb-hid" => "USB keyboard switch",
        "ble-hid" => "Bluetooth keyboard switch",
        "reboot" => "reboot",
        _ => "recovery action",
    }
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn load_wifi_policy(path: &Path) -> Result<WifiPolicy, String> {
    if path.as_os_str().is_empty() {
        return Err("Choose the complete private roaming-policy file first.".to_owned());
    }
    let file =
        File::open(path).map_err(|_| "The roaming-policy file is unavailable.".to_owned())?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Could not read the roaming-policy file.".to_owned())?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err("The roaming-policy file exceeds 32 KiB.".to_owned());
    }
    let policy: WifiPolicy = serde_json::from_slice(bytes.as_slice())
        .map_err(|_| "The roaming-policy file is not strict policy JSON.".to_owned())?;
    validate_wifi_policy(&policy)?;
    Ok(policy)
}

pub fn validate_wifi_policy(policy: &WifiPolicy) -> Result<(), String> {
    if policy.schema_version != 1 {
        return Err("The roaming-policy schema version is unsupported.".to_owned());
    }
    if policy.wifi_profiles.len() > MAX_WIFI_PROFILES {
        return Err("The roaming policy cannot contain more than eight Wi-Fi profiles.".to_owned());
    }
    for profile in &policy.wifi_profiles {
        validate_wifi_profile(&profile.ssid, &profile.password)?;
    }
    if policy.revoked_installation_ids.len() > 64 {
        return Err("The roaming policy contains too many revoked installations.".to_owned());
    }
    let mut previous = None;
    let mut revoked = policy.revoked_installation_ids.iter().collect::<Vec<_>>();
    revoked.sort_unstable();
    for identity in revoked {
        if identity.len() != 32
            || !identity
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("The roaming policy contains an invalid revoked installation.".to_owned());
        }
        if previous == Some(identity.as_str()) {
            return Err("The roaming policy contains a duplicate revocation.".to_owned());
        }
        previous = Some(identity);
    }
    Ok(())
}

pub fn validate_wifi_profile(ssid: &str, password: &str) -> Result<(), String> {
    if !(1..=32).contains(&ssid.len()) || ssid.contains('\0') {
        return Err("Wi-Fi network names must contain 1 through 32 UTF-8 bytes.".to_owned());
    }
    if !(8..=63).contains(&password.len()) || password.contains('\0') {
        return Err("Wi-Fi passwords must contain 8 through 63 UTF-8 bytes.".to_owned());
    }
    Ok(())
}

fn selected_local_usb_id(device_id: &str, known_device_ids: &[String]) -> Result<[u8; 16], String> {
    if !canonical_uuid(device_id) || !known_device_ids.iter().any(|known| known == device_id) {
        return Err("Select an owner-authorized Keyferry before using USB controls.".to_owned());
    }
    uuid::Uuid::parse_str(device_id)
        .map(|parsed| *parsed.as_bytes())
        .map_err(|_| "The selected device identifier is invalid.".to_owned())
}

pub fn connected_local_device_id(
    device_id: &str,
    known_device_ids: &[String],
) -> Result<String, String> {
    let selected = selected_local_usb_id(device_id, known_device_ids)?;
    let device_id =
        keyferry_local_management::hid::unique_present_device_id(&[selected]).map_err(|_| {
            "Connect the selected Keyferry directly by USB before continuing.".to_owned()
        })?;
    Ok(format_uuid_bytes(&device_id))
}

pub fn save_and_update_wifi_policy(
    device_id: &str,
    owner_kit: &Path,
    policy_path: &Path,
    passphrase: &str,
    policy: &WifiPolicy,
) -> Result<String, String> {
    if owner_kit.as_os_str().is_empty() || policy_path.as_os_str().is_empty() {
        return Err("Choose the owner kit and complete roaming-policy file first.".to_owned());
    }
    if passphrase.is_empty() || passphrase.len() > 1024 || passphrase.contains(['\r', '\n', '\0']) {
        return Err("Enter a valid owner-kit password.".to_owned());
    }
    validate_wifi_policy(policy)?;
    let mut policy_json = Zeroizing::new(
        serde_json::to_vec(policy)
            .map_err(|_| "Could not encode the roaming policy.".to_owned())?,
    );
    policy_json.push(b'\n');
    let policy_path_text = policy_path.to_string_lossy();
    run_helper_inner(
        None,
        &[
            "save-roaming-policy",
            "--output",
            policy_path_text.as_ref(),
            "--replace",
        ],
        Some(policy_json.as_slice()),
    )?;

    let owner_kit_text = owner_kit.to_string_lossy();
    let mut password_input = Zeroizing::new(Vec::with_capacity(passphrase.len() + 1));
    password_input.extend_from_slice(passphrase.as_bytes());
    password_input.push(b'\n');
    run_helper_inner(
        None,
        &[
            "update-roaming",
            "--owner-kit",
            owner_kit_text.as_ref(),
            "--device",
            device_id,
            "--policy",
            policy_path_text.as_ref(),
        ],
        Some(password_input.as_slice()),
    )
}

pub fn recover_initial_wifi_policy(
    device_id: &str,
    bundle: &Path,
    owner_kit: &Path,
    policy_path: &Path,
    passphrase: &str,
) -> Result<WifiPolicy, String> {
    validate_bundle(bundle)?;
    if owner_kit.as_os_str().is_empty() || policy_path.as_os_str().is_empty() {
        return Err("Choose the owner kit and private roaming-policy path first.".to_owned());
    }
    if passphrase.is_empty() || passphrase.len() > 1024 || passphrase.contains(['\r', '\n', '\0']) {
        return Err("Enter a valid owner-kit password.".to_owned());
    }
    let owner_kit_text = owner_kit.to_string_lossy();
    let policy_path_text = policy_path.to_string_lossy();
    let mut password_input = Zeroizing::new(Vec::with_capacity(passphrase.len() + 1));
    password_input.extend_from_slice(passphrase.as_bytes());
    password_input.push(b'\n');
    run_helper(
        bundle,
        &[
            "recover-initial-roaming-policy",
            "--owner-kit",
            owner_kit_text.as_ref(),
            "--device",
            device_id,
            "--output",
            policy_path_text.as_ref(),
        ],
        Some(password_input.as_slice()),
    )?;
    load_wifi_policy(policy_path)
}

pub fn change_owner_passphrase(
    owner_kit: &Path,
    current: &str,
    new: &str,
    confirmation: &str,
) -> Result<String, String> {
    validate_owner_passphrase_inputs(owner_kit, current, new, confirmation)?;
    let owner_kit = owner_kit.to_string_lossy();
    let args = [
        "change-owner-kit-passphrase",
        "--owner-kit",
        owner_kit.as_ref(),
    ];
    let mut input = Zeroizing::new(Vec::with_capacity(
        current.len() + new.len() + confirmation.len() + 3,
    ));
    input.extend_from_slice(current.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(new.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(confirmation.as_bytes());
    input.push(b'\n');
    run_helper_inner(None, &args, Some(input.as_slice()))
}

pub fn validate_owner_passphrase_inputs(
    owner_kit: &Path,
    current: &str,
    new: &str,
    confirmation: &str,
) -> Result<(), String> {
    if owner_kit.as_os_str().is_empty() {
        return Err("Choose the encrypted owner-kit file first.".to_owned());
    }
    if current.is_empty() || new.is_empty() {
        return Err("Current and new owner-kit passwords cannot be empty.".to_owned());
    }
    if new != confirmation {
        return Err("New owner-kit password confirmation does not match.".to_owned());
    }
    if [current, new, confirmation]
        .iter()
        .any(|value| value.contains(['\r', '\n', '\0']))
    {
        return Err("Owner-kit passwords cannot contain line breaks.".to_owned());
    }
    if [current, new, confirmation]
        .iter()
        .any(|value| value.len() > 1024)
    {
        return Err("Owner-kit passwords cannot exceed 1,024 UTF-8 bytes.".to_owned());
    }
    Ok(())
}

fn validate_bundle(bundle: &Path) -> Result<(), String> {
    if bundle.as_os_str().is_empty() {
        Err("Choose the private pairing bundle folder first.".to_owned())
    } else {
        Ok(())
    }
}

fn run_helper(bundle: &Path, args: &[&str], stdin: Option<&[u8]>) -> Result<String, String> {
    run_helper_inner(Some(bundle), args, stdin)
}

fn run_helper_inner(
    bundle: Option<&Path>,
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<String, String> {
    let output = run_helper_capture(bundle, args, stdin)?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if message.is_empty() {
            "The provisioner rejected the operation.".to_owned()
        } else {
            message
        });
    }
    let message = String::from_utf8(output.stdout)
        .map_err(|_| "The provisioner returned invalid text.".to_owned())?;
    Ok(message.trim().to_owned())
}

fn run_helper_capture(
    bundle: Option<&Path>,
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<Output, String> {
    let executable = helper_path()?;
    let mut command = Command::new(&executable);
    if let Some(bundle) = bundle {
        command.arg("--bundle").arg(bundle);
    }
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| format!("Could not start {}.", executable.display()))?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| "Could not open the provisioner input.".to_owned())?
            .write_all(input)
            .map_err(|_| "Could not send private input to the provisioner.".to_owned())?;
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "The provisioner did not finish cleanly.".to_owned())?;
    if output.stdout.len() > MAX_STATUS_BYTES || output.stderr.len() > MAX_STATUS_BYTES {
        return Err("The provisioner returned an oversized status message.".to_owned());
    }
    Ok(output)
}

fn helper_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os(PAIRING_EXE_ENV).map(PathBuf::from) {
        return Ok(path);
    }
    let current =
        env::current_exe().map_err(|_| "Cannot locate the Keyferry program.".to_owned())?;
    let directory = current
        .parent()
        .ok_or_else(|| "Cannot locate the Keyferry program directory.".to_owned())?;
    Ok(directory.join(if cfg!(windows) {
        "keyferry-pairing.exe"
    } else {
        "keyferry-pairing"
    }))
}

fn read_bundle_pointer() -> Option<PathBuf> {
    let pointer = bundle_pointer_path_for(
        if cfg!(windows) {
            "windows"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else {
            "unix"
        },
        env::var_os("LOCALAPPDATA").as_deref(),
        env::var_os("HOME").as_deref(),
        env::var_os("XDG_STATE_HOME").as_deref(),
    )?;
    let value = std::fs::read_to_string(pointer).ok()?;
    let path = value.trim();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

fn bundle_pointer_path_for(
    platform: &str,
    local_app_data: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
    xdg_state_home: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    let state_root = match platform {
        "windows" => PathBuf::from(local_app_data?),
        "macos" => PathBuf::from(home?)
            .join("Library")
            .join("Application Support"),
        _ => xdg_state_home
            .map(PathBuf::from)
            .or_else(|| home.map(|value| PathBuf::from(value).join(".local").join("state")))?,
    };
    Some(state_root.join("keyferry").join("pairing-bundle.txt"))
}

fn owner_kit_path_from_bundle(bundle: &Path) -> Option<PathBuf> {
    (!bundle.as_os_str().is_empty())
        .then(|| bundle.parent().map(|parent| parent.join("owner-kit.json")))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_device_identity_parser_is_canonical_and_nonzero() {
        assert!(canonical_uuid("11111111-1111-4111-8111-111111111111"));
        assert!(!canonical_uuid("11111111-1111-4111-8111-11111111111G"));
        assert!(!canonical_uuid("00000000-0000-0000-0000-000000000000"));
        assert!(!canonical_uuid("11111111111141118111111111111111"));
        assert_eq!(
            format_uuid_bytes(&[0x11; 16]),
            "11111111-1111-1111-1111-111111111111"
        );
    }

    #[test]
    fn wifi_policy_secrets_are_not_part_of_process_arguments() {
        let policy = WifiPolicy {
            schema_version: 1,
            wifi_profiles: vec![WifiProfile {
                ssid: "ssid-sentinel".to_owned(),
                password: "password-sentinel".to_owned(),
                priority: 255,
            }],
            revoked_installation_ids: vec!["41".repeat(16)],
        };
        validate_wifi_policy(&policy).unwrap();
        let value = serde_json::to_value(&policy).unwrap();
        assert_eq!(value["wifi_profiles"][0]["ssid"], "ssid-sentinel");
        let save_arguments = ["save-roaming-policy", "--output", "POLICY", "--replace"];
        let update_arguments = [
            "update-roaming",
            "--owner-kit",
            "OWNER-KIT",
            "--device",
            "DEVICE-ID",
            "--policy",
            "POLICY",
        ];
        let recovery_arguments = [
            "recover-initial-roaming-policy",
            "--owner-kit",
            "OWNER-KIT",
            "--device",
            "DEVICE-ID",
            "--output",
            "POLICY",
        ];
        for secret in ["ssid-sentinel", "password-sentinel"] {
            assert!(!save_arguments.join(" ").contains(secret));
            assert!(!update_arguments.join(" ").contains(secret));
            assert!(!recovery_arguments.join(" ").contains(secret));
        }
    }

    #[test]
    fn wifi_policy_bounds_revocations_and_priority_order_are_deterministic() {
        let mut policy = WifiPolicy {
            schema_version: 1,
            wifi_profiles: (0..MAX_WIFI_PROFILES)
                .map(|index| WifiProfile {
                    ssid: format!("network-{index}"),
                    password: "password-sentinel".to_owned(),
                    priority: 0,
                })
                .collect(),
            revoked_installation_ids: vec!["41".repeat(16), "42".repeat(16)],
        };
        policy.normalize_priorities();
        assert_eq!(policy.wifi_profiles[0].priority, 255);
        assert_eq!(policy.wifi_profiles[7].priority, 248);
        validate_wifi_policy(&policy).expect("bounded policy");

        policy.wifi_profiles.push(WifiProfile {
            ssid: "too-many".to_owned(),
            password: "password-sentinel".to_owned(),
            priority: 1,
        });
        assert!(validate_wifi_policy(&policy)
            .unwrap_err()
            .contains("more than eight"));
        policy.wifi_profiles.pop();
        policy
            .revoked_installation_ids
            .push(policy.revoked_installation_ids[0].clone());
        assert!(validate_wifi_policy(&policy)
            .unwrap_err()
            .contains("duplicate revocation"));
    }

    #[test]
    fn wifi_policy_load_rejects_unknown_fields() {
        let path = std::env::temp_dir().join(format!(
            "keyferry-ui-policy-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::write(
            &path,
            br#"{"schema_version":1,"wifi_profiles":[],"revoked_installation_ids":[],"extra":true}"#,
        )
        .expect("temporary policy");
        let result = load_wifi_policy(&path);
        let _ = std::fs::remove_file(&path);
        assert!(result.unwrap_err().contains("strict policy JSON"));
    }

    #[test]
    fn incomplete_provisioning_inputs_fail_before_the_helper_runs() {
        assert!(status(Path::new(""))
            .unwrap_err()
            .contains("pairing bundle"));
        assert!(validate_wifi_profile("", "password")
            .unwrap_err()
            .contains("network name"));
        assert!(validate_wifi_profile("network", "")
            .unwrap_err()
            .contains("passwords"));
        assert!(validate_owner_passphrase_inputs(
            Path::new("owner-kit.json"),
            "current",
            "new",
            "different"
        )
        .unwrap_err()
        .contains("does not match"));
        let device = "0123abcd-0000-4000-8000-00000000abcd";
        assert!(authorize_this_computer(Path::new(""), "password", device)
            .unwrap_err()
            .contains("owner-kit file"));
        assert!(
            authorize_this_computer(Path::new("owner-kit.json"), "", device)
                .unwrap_err()
                .contains("password")
        );
        assert!(
            authorize_this_computer(Path::new("owner-kit.json"), "password", "not-a-device")
                .unwrap_err()
                .contains("Choose the Keyferry")
        );
        assert!(list_owner_devices(Path::new(""), "password")
            .unwrap_err()
            .contains("owner-kit file"));
    }

    #[test]
    fn local_status_and_recovery_results_are_strict_payload_free_metadata() {
        let document: LocalStatusDocument = serde_json::from_value(serde_json::json!({
            "schema": "keyferry.local-status.v1",
            "device_id": "11".repeat(16),
            "device": {"active_output_mode": 1, "stored_output_mode": 2,
                "board_compatibility_id": 1, "release": "ABC12345", "capabilities": 65536},
            "safety": {"maintenance_active": false, "command_active": false, "armed": false,
                "usb_mounted": true, "keyboard_neutral": true, "mouse_neutral": true,
                "restart_pending": false, "receipt_storage_healthy": true,
                "usb_attachment_generation": 7},
            "network": {"wifi_stage": 3, "active_path": 1, "running": true,
                "wifi_available": true, "ble_available": true, "endpoint_authenticated": true,
                "configuration_valid": true, "wifi_profile_count": 2, "paired_host_count": 1,
                "policy_state": 1, "wifi_error": 0, "nvs_error": 0},
            "ble_hid": {"bond_state": 1, "peripheral_stage": 4, "advertising": false,
                "connected": true, "authenticated": true, "subscribed": true, "ready": true,
                "enrollment_active": false, "error": 0, "generation": 5,
                "enrollment_remaining_ms": 0},
            "policy": {"state": 1, "sequence": 9},
            "last_receipt": null
        }))
        .expect("strict local status");
        assert!(
            verify_local_status_device(&document, "11111111-1111-1111-1111-111111111111").is_ok()
        );
        assert!(
            verify_local_status_device(&document, "22222222-2222-2222-2222-222222222222")
                .unwrap_err()
                .contains("another Keyferry")
        );
        let rendered = format_local_status(document).expect("formatted local status");
        assert!(rendered.contains("output USB keyboard (stored Bluetooth keyboard)"));
        assert!(rendered.contains("keyboard released · mouse released"));
        assert!(!rendered.contains("password"));

        let device = "11111111-1111-1111-1111-111111111111";
        let completed = recovery_receipt(
            device,
            "restart-network",
            serde_json::json!({
                "schema":"keyferry.local-recovery-result.v1", "action":"restart-network",
                "outcome":"COMPLETED", "status":0,
                "operation_id":"22222222222222222222222222222222", "error":null
            }),
        );
        assert!(
            interpret_local_recovery(true, device, "restart-network", completed.as_bytes())
                .expect("completed result")
                .contains("22222222222222222222222222222222")
        );
        let unknown = recovery_receipt(
            device,
            "reboot",
            serde_json::json!({
                "schema":"keyferry.local-recovery-result.v1", "action":"reboot", "outcome":"UNKNOWN",
                "stage":"close-maintenance", "error":"local.mutation_uncertain",
                "operation_id":"33333333333333333333333333333333"
            }),
        );
        let message = interpret_local_recovery(false, device, "reboot", unknown.as_bytes())
            .expect_err("unknown must not become success");
        assert!(message.contains("Do not repeat it automatically"));
        assert!(message.contains("33333333333333333333333333333333"));
    }

    fn recovery_receipt(device: &str, action: &str, result: serde_json::Value) -> String {
        let attempt = serde_json::json!({
            "schema":"keyferry.local-recovery-attempt.v1", "device_id":device.replace('-', ""),
            "action":action, "maintenance_open_id":"11111111111111111111111111111111",
            "action_id":"22222222222222222222222222222222",
            "maintenance_close_id":"33333333333333333333333333333333"
        });
        format!("{attempt}\n{result}\n")
    }

    #[test]
    fn completion_requires_matching_device_action_and_operation_receipts() {
        let device = "11111111-1111-1111-1111-111111111111";
        let terminal = serde_json::json!({
            "schema":"keyferry.local-recovery-result.v1", "action":"restart-network",
            "outcome":"COMPLETED", "status":0, "operation_id":"22222222222222222222222222222222"
        });
        let valid = recovery_receipt(device, "restart-network", terminal.clone());
        assert!(interpret_local_recovery_output(
            true,
            device,
            "restart-network",
            valid.as_bytes(),
            b""
        )
        .is_ok());
        let mut wrong_operation = terminal.clone();
        wrong_operation["operation_id"] = "44444444444444444444444444444444".into();
        let mut wrong_action = terminal.clone();
        wrong_action["action"] = "reboot".into();
        for receipt in [
            terminal.to_string(),
            format!("{{}}\n{terminal}"),
            recovery_receipt(
                "55555555-5555-5555-5555-555555555555",
                "restart-network",
                terminal.clone(),
            ),
            recovery_receipt(device, "reboot", terminal.clone()),
            recovery_receipt(device, "restart-network", wrong_action),
            recovery_receipt(device, "restart-network", wrong_operation),
            format!("{valid}{terminal}\n"),
        ] {
            let error = interpret_local_recovery_output(
                true,
                device,
                "restart-network",
                receipt.as_bytes(),
                b"",
            )
            .unwrap_err();
            assert!(error.contains("outcome is unknown"));
        }
    }

    #[test]
    fn local_usb_status_and_recovery_require_the_selected_exact_device() {
        let device = "0123abcd-0000-4000-8000-00000000abcd";
        assert_eq!(
            local_status_args("owner-kit.json", device).unwrap(),
            [
                "local-status",
                "--owner-kit",
                "owner-kit.json",
                "--device",
                device
            ]
        );
        assert_eq!(
            local_recover_args("owner-kit.json", device, "restart-network").unwrap(),
            [
                "local-recover",
                "--owner-kit",
                "owner-kit.json",
                "--device",
                device,
                "restart-network"
            ]
        );
        for invalid in ["", "another device", "0123abcd-0000-4000-8000-00000000abcD"] {
            assert!(local_status_args("owner-kit.json", invalid).is_err());
            assert!(local_recover_args("owner-kit.json", invalid, "restart-network").is_err());
            assert!(local_recover(
                Path::new("owner-kit.json"),
                "owner password",
                invalid,
                "restart-network"
            )
            .is_err());
        }
    }

    #[test]
    fn wifi_usb_discovery_is_restricted_to_the_selected_authorized_stick() {
        let first = "11111111-1111-1111-1111-111111111111";
        let second = "22222222-2222-2222-2222-222222222222";
        let authorized = vec![first.to_owned(), second.to_owned()];
        assert_eq!(
            selected_local_usb_id(first, &authorized).unwrap(),
            [0x11; 16]
        );
        assert_eq!(
            selected_local_usb_id(second, &authorized).unwrap(),
            [0x22; 16]
        );
        for invalid in ["", "not-a-device", "33333333-3333-3333-3333-333333333333"] {
            assert!(selected_local_usb_id(invalid, &authorized).is_err());
        }
        assert!(selected_local_usb_id(first, &[]).is_err());
    }

    #[test]
    fn local_recovery_distinguishes_known_pre_dispatch_errors_from_missing_receipts() {
        let pre_dispatch = interpret_local_recovery_output(
            false,
            "11111111-1111-1111-1111-111111111111",
            "restart-network",
            b"",
            b"keyferry helper error: owner-kit authentication, selection, or authority validation failed\n",
        )
        .unwrap_err();
        assert!(pre_dispatch.contains("password or selected Keyferry"));
        assert!(!pre_dispatch.contains("outcome is unknown"));

        for (stdout, stderr) in [
            (b"".as_slice(), b"unexpected helper failure".as_slice()),
            (
                br#"{"schema":"keyferry.local-recovery-attempt.v1"}"#.as_slice(),
                b"unexpected helper failure".as_slice(),
            ),
        ] {
            let error = interpret_local_recovery_output(
                false,
                "11111111-1111-1111-1111-111111111111",
                "restart-network",
                stdout,
                stderr,
            )
            .unwrap_err();
            assert!(error.contains("outcome is unknown"));
            assert!(error.contains("do not repeat it automatically"));
        }
    }

    #[test]
    fn owner_passwords_are_stdin_only() {
        let fixed_arguments = ["change-owner-kit-passphrase", "--owner-kit", "OWNER-KIT"];
        for secret in ["current-sentinel", "new-sentinel", "confirmation-sentinel"] {
            assert!(!fixed_arguments.join(" ").contains(secret));
        }
    }

    #[test]
    fn owner_kit_path_follows_bundle_parent() {
        assert_eq!(
            owner_kit_path_from_bundle(Path::new("private/first-hil")),
            Some(PathBuf::from("private/owner-kit.json"))
        );
        assert_eq!(owner_kit_path_from_bundle(Path::new("")), None);
        assert_eq!(
            PathBuf::from(default_wifi_policy_path(Path::new(
                "private/owner-kit.json"
            ))),
            PathBuf::from("private/roaming-policy.json")
        );
    }

    #[test]
    fn macos_bundle_colocates_the_required_helpers() {
        let packager = include_str!("../../../scripts/package_macos_app.sh");

        assert!(packager.contains("CONTROLLER DAEMON PAIRING_HELPER CLI OUTPUT.app"));
        assert!(
            packager.contains("install -m 755 \"$daemon\" \"$bundle/Contents/MacOS/keyferryd\"")
        );
        assert!(packager.contains(
            "install -m 755 \"$pairing_helper\" \"$bundle/Contents/MacOS/keyferry-pairing\""
        ));
        assert!(packager.contains("install -m 755 \"$cli\" \"$bundle/Contents/MacOS/keyctl\""));
        assert!(packager.contains("KeyferryBleBridge.swift"));
        assert!(packager.contains("NSBluetoothAlwaysUsageDescription"));
    }

    #[test]
    fn bundle_pointer_uses_platform_state_directory() {
        use std::ffi::OsStr;

        assert_eq!(
            bundle_pointer_path_for("windows", Some(OsStr::new("C:/state")), None, None),
            Some(PathBuf::from("C:/state/keyferry/pairing-bundle.txt"))
        );
        assert_eq!(
            bundle_pointer_path_for("macos", None, Some(OsStr::new("/Users/owner")), None),
            Some(PathBuf::from(
                "/Users/owner/Library/Application Support/keyferry/pairing-bundle.txt"
            ))
        );
        assert_eq!(
            bundle_pointer_path_for(
                "unix",
                None,
                Some(OsStr::new("/home/owner")),
                Some(OsStr::new("/state"))
            ),
            Some(PathBuf::from("/state/keyferry/pairing-bundle.txt"))
        );
    }
}
