#![deny(unsafe_code)]

mod owner_kit;
mod provisioning_host;

use keyferry_gateway::{gateway_id_for_spki, InstallationCredentialSet, InstallationManifestV3};
use keyferry_local_management::{
    generate_operation_id, hid::HidTransport, Client as LocalClient, Error as LocalError,
};
use keyferry_protocol::{
    local_management::{ReceiptStatus, StatusPage},
    local_management_operation as local_operation, local_management_status as local_status,
    local_management_status_page as local_status_page, output_mode,
};
use rcgen::{CertificateParams, KeyPair, PublicKeyData, PKCS_ECDSA_P256_SHA256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::process::Command;
use std::{
    env, fs,
    fs::OpenOptions,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use x509_parser::parse_x509_certificate;
use zeroize::{Zeroize, Zeroizing};

const SCHEMA_VERSION: u8 = 1;
const GATEWAY_CREDENTIAL_SCHEMA_VERSION: u8 = 2;
const PRIVATE_BUNDLE: &str = "secrets/first-hil";
const DEVICE_CONFIG: &str = "firmware/device.json";
const WIFI_CONFIG: &str = "firmware/wifi.json";
const FIRMWARE_CERT: &str = "firmware/host-cert.der";
const FIRMWARE_SPKI: &str = "firmware/host-spki.der";
const DAEMON_CONFIG: &str = "keyferryd/runtime.json";
const DAEMON_SECRETS: &str = "keyferryd/secrets";
const RECOVERY_DIR: &str = "recovery";
const RECOVERY_SECRET: &str = "recovery/secret.bin";
const MAX_WIFI_INPUT: u64 = 1024;
const MAX_ROAMING_POLICY_INPUT: u64 = 32 * 1024;
const MAX_PRIVATE_HEADER_INPUT: u64 = 64 * 1024;
const MAX_CERTIFICATE_BYTES: u64 = 1024;
const MAX_REMOTE_TOKEN_BYTES: u64 = 66;
const MAX_GATEWAY_CREDENTIAL_BYTES: usize = 4096;
const MATERIALIZE_OUTPUT_ENV: &str = "KEYFERRY_PAIRING_OUTPUT_DIR";
const PAIRING_BUNDLE_ENV: &str = "KEYFERRY_PAIRING_BUNDLE";
const GENERATED_HEADER: &str = "keyferry_hil_private.h";
const OWNER_KIT_MAX_BYTES: u64 = 16 * 1024;
const SECRET_LINE_MAX_BYTES: u64 = 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceConfig {
    schema_version: u8,
    device_id: String,
    link_secret_hex: String,
    host_address: String,
    host_port: u16,
    host_certificate_der: String,
    host_spki_der: String,
    host_spki_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WifiConfig {
    schema_version: u8,
    ssid: String,
    password: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DaemonConfig {
    schema_version: u8,
    tls_bind: String,
    tls_device_id: String,
    tls_secret_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    discovery_netmask: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GatewayCredential {
    schema_version: u8,
    port: u16,
    gateway_spki_der: String,
    remote_bearer: String,
}

struct ExportGatewayArgs {
    bundle: PathBuf,
    port: u16,
    remote_token_file: PathBuf,
    output: PathBuf,
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let default_bundle = env::var_os(PAIRING_BUNDLE_ENV)
        .map(PathBuf::from)
        // Relative to the working directory: a release binary must not carry its build path.
        .unwrap_or_else(|| PathBuf::from(PRIVATE_BUNDLE));
    let result = resolve_bundle(&args, &default_bundle)
        .and_then(|(bundle, command)| run(command, &bundle, &mut stdin, &mut stdout));
    if let Err(message) = result {
        eprintln!("keyferry helper error: {message}");
        std::process::exit(2);
    }
}

fn resolve_bundle<'a>(
    args: &'a [String],
    default_bundle: &Path,
) -> Result<(PathBuf, &'a [String]), &'static str> {
    if args.first().is_some_and(|value| value == "--bundle") {
        let path = args.get(1).ok_or("--bundle requires a directory path")?;
        if path.is_empty() {
            return Err("--bundle requires a directory path");
        }
        return Ok((PathBuf::from(path), &args[2..]));
    }
    Ok((default_bundle.to_owned(), args))
}

fn run(
    args: &[String],
    bundle: &Path,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    match args.first().map(String::as_str) {
        Some("create") => {
            let (address, port) = parse_create_args(&args[1..])?;
            create_bundle(bundle, address, port)?;
            writeln!(output, "pairing bundle created; Wi-Fi credentials still required")
                .map_err(|_| "could not write status")
        }
        Some("set-wifi") if args.len() == 1 => {
            set_wifi(bundle, input, false)?;
            writeln!(output, "Wi-Fi credentials stored")
                .map_err(|_| "could not write status")
        }
        Some("set-wifi") if args.len() == 2 && args[1] == "--replace" => {
            set_wifi(bundle, input, true)?;
            writeln!(output, "Wi-Fi credentials updated")
                .map_err(|_| "could not write status")
        }
        Some("initialize-recovery") if args.len() == 1 => {
            initialize_recovery(bundle)?;
            writeln!(output, "administrative recovery secret created in private bundle")
                .map_err(|_| "could not write status")
        }
        Some("validate") if args.len() == 1 => {
            validate_bundle(bundle)?;
            writeln!(output, "pairing bundle valid")
                .map_err(|_| "could not write status")
        }
        Some("materialize") if args.len() == 1 => {
            let destination = env::var_os(MATERIALIZE_OUTPUT_ENV)
                .map(PathBuf::from)
                .ok_or("private firmware output directory is absent")?;
            materialize_firmware(bundle, &destination)?;
            writeln!(output, "private firmware configuration materialized")
                .map_err(|_| "could not write status")
        }
        Some("status") if args.len() == 1 => provisioning_host::status(bundle, output),
        Some("provision") if args.len() == 1 => provisioning_host::provision(bundle, output),
        Some("migrate-roaming")
            if args.len() == 3 && args[1] == "--owner-kit" =>
        {
            let passphrases = read_secret_lines(input, 1)?;
            provisioning_host::migrate_roaming(
                bundle,
                Path::new(&args[2]),
                passphrases[0].as_slice(),
                output,
            )
        }
        Some("update-roaming")
            if args.len() == 5 && args[1] == "--owner-kit" && args[3] == "--policy" =>
        {
            let passphrases = read_secret_lines(input, 1)?;
            provisioning_host::update_roaming(
                Path::new(&args[2]),
                Path::new(&args[4]),
                passphrases[0].as_slice(),
                output,
            )
        }
        Some("update-roaming")
            if args.len() == 7
                && args[1] == "--owner-kit"
                && args[3] == "--device"
                && args[5] == "--policy" =>
        {
            let device_id = parse_uuid(&args[4])?;
            let passphrases = read_secret_lines(input, 1)?;
            provisioning_host::update_roaming_for_device(
                Path::new(&args[2]),
                Path::new(&args[6]),
                passphrases[0].as_slice(),
                device_id,
                output,
            )
        }
        Some("recover-initial-roaming-policy")
            if args.len() == 5 && args[1] == "--owner-kit" && args[3] == "--output" =>
        {
            let output_path = Path::new(&args[4]);
            if output_path.as_os_str().is_empty() {
                return Err("--output requires a private policy path");
            }
            let passphrases = read_secret_lines(input, 1)?;
            let policy = Zeroizing::new(provisioning_host::recover_initial_roaming_policy(
                bundle,
                Path::new(&args[2]),
                passphrases[0].as_slice(),
            )?);
            write_new_owner_only(output_path, policy.as_slice())?;
            writeln!(output, "initial roaming policy recovered")
                .map_err(|_| "could not write status")
        }
        Some("recover-initial-roaming-policy")
            if args.len() == 7
                && args[1] == "--owner-kit"
                && args[3] == "--device"
                && args[5] == "--output" =>
        {
            let device_id = parse_uuid(&args[4])?;
            let output_path = Path::new(&args[6]);
            if output_path.as_os_str().is_empty() {
                return Err("--output requires a private policy path");
            }
            let passphrases = read_secret_lines(input, 1)?;
            let policy = Zeroizing::new(
                provisioning_host::recover_initial_roaming_policy_for_device(
                    bundle,
                    Path::new(&args[2]),
                    passphrases[0].as_slice(),
                    device_id,
                )?,
            );
            write_new_owner_only(output_path, policy.as_slice())?;
            writeln!(output, "initial roaming policy recovered")
                .map_err(|_| "could not write status")
        }
        Some("save-roaming-policy")
            if (args.len() == 3 || (args.len() == 4 && args[3] == "--replace"))
                && args[1] == "--output" =>
        {
            let output_path = Path::new(&args[2]);
            if output_path.as_os_str().is_empty() {
                return Err("--output requires a private policy path");
            }
            let mut input_bytes = Zeroizing::new(Vec::new());
            input
                .take(MAX_ROAMING_POLICY_INPUT + 1)
                .read_to_end(&mut input_bytes)
                .map_err(|_| "could not read roaming policy input")?;
            if input_bytes.len() as u64 > MAX_ROAMING_POLICY_INPUT {
                return Err("roaming policy input exceeds 32 KiB");
            }
            let normalized = Zeroizing::new(provisioning_host::normalize_roaming_policy(
                input_bytes.as_slice(),
            )?);
            if args.len() == 4 {
                replace_private_durable(output_path, normalized.as_slice())?;
            } else {
                write_new_owner_only(output_path, normalized.as_slice())?;
            }
            writeln!(output, "roaming policy stored")
                .map_err(|_| "could not write status")
        }
        Some("export-gateway-credential") => {
            let options = parse_export_gateway_args(&args[1..])?;
            export_gateway_credential(&options)?;
            writeln!(output, "gateway credential created")
                .map_err(|_| "could not write status")
        }
        Some("install-gateway-credential") if args.len() == 3 && args[1] == "--input" => {
            install_gateway_credential(Path::new(&args[2]), &default_gateway_credential_path())?;
            writeln!(output, "gateway credential installed")
                .map_err(|_| "could not write status")
        }
        Some("validate-gateway-credential") if args.len() == 3 && args[1] == "--input" => {
            canonical_gateway_credential(Path::new(&args[2]))?;
            writeln!(output, "gateway credential valid")
                .map_err(|_| "could not write status")
        }
        Some("local-status")
            if args.len() == 3 && args[1] == "--owner-kit" =>
        {
            local_status(Path::new(&args[2]), None, input, output)
        }
        Some("local-status")
            if args.len() == 5 && args[1] == "--owner-kit" && args[3] == "--device" =>
        {
            local_status(
                Path::new(&args[2]),
                Some(parse_uuid(&args[4])?),
                input,
                output,
            )
        }
        Some("local-status-bootstrap")
            if args.len() == 3 && args[1] == "--private-header" =>
        {
            let authority = load_private_header_authority(Path::new(&args[2]))?;
            local_status_with(
                authority.device_id,
                &authority.recovery_secret,
                output,
            )
        }
        Some("local-probe") => {
            let options = parse_local_probe_args(&args[1..])?;
            local_probe(&options, input, output)
        }
        Some("bootstrap-status")
            if args.len() == 3 && args[1] == "--private-header" =>
        {
            let authority = load_private_header_authority(Path::new(&args[2]))?;
            provisioning_host::status_for_device(authority.device_id, output)
        }
        Some("local-recover")
            if args.len() == 4 && args[1] == "--owner-kit" =>
        {
            local_recover(Path::new(&args[2]), None, &args[3], input, output)
        }
        Some("local-recover")
            if args.len() == 6 && args[1] == "--owner-kit" && args[3] == "--device" =>
        {
            local_recover(
                Path::new(&args[2]),
                Some(parse_uuid(&args[4])?),
                &args[5],
                input,
                output,
            )
        }
        Some("local-recover-bootstrap")
            if args.len() == 4 && args[1] == "--private-header" =>
        {
            let authority = load_private_header_authority(Path::new(&args[2]))?;
            local_recover_with(
                authority.device_id,
                &authority.recovery_secret,
                &args[3],
                output,
            )
        }
        Some("bootstrap-roaming")
            if args.len() == 9
                && args[1] == "--private-header"
                && args[3] == "--installation"
                && args[5] == "--network-bundle"
                && args[7] == "--journal-dir" =>
        {
            let bootstrap = load_private_header_authority(Path::new(&args[2]))?;
            let installation_root = Path::new(&args[4]);
            let installation = InstallationCredentialSet::load(installation_root)
                .map_err(|_| "installation credential directory is invalid")?;
            let credential = installation
                .get(bootstrap.device_id)
                .ok_or("installation has no grant for the bootstrap device")?;
            let manifest: InstallationManifestV3 =
                read_json_private(&installation_root.join("installation-v3.json"))?;
            let device_id_hex = hex(&bootstrap.device_id);
            let epoch = manifest
                .devices
                .iter()
                .find(|device| device.device_id_hex == device_id_hex)
                .map(|device| device.authority_epoch)
                .ok_or("installation manifest has no bootstrap device")?;
            let wifi: WifiConfig =
                read_json_private(&Path::new(&args[6]).join(WIFI_CONFIG))?;
            validate_wifi(&wifi)?;
            let authority = owner_kit::DeviceOwnerAuthority {
                owner_id: credential.owner_id(),
                device_id: bootstrap.device_id,
                owner_ca_der: credential.owner_ca_der().to_vec(),
                device_recovery_secret: *bootstrap.recovery_secret,
                authority_epoch: epoch,
            };
            provisioning_host::migrate_roaming_from_private_authority(
                Path::new(&args[8]),
                &authority,
                &wifi,
                output,
            )
        }
        Some("create-owner-kit") if args.len() == 3 && args[1] == "--output" => {
            create_owner_kit(bundle, Path::new(&args[2]), input)?;
            writeln!(output, "encrypted owner kit created")
                .map_err(|_| "could not write status")
        }
        Some("add-owner-device") if args.len() == 3 && args[1] == "--owner-kit" => {
            let device_id = add_owner_device(Path::new(&args[2]), input)?;
            write_json_line(
                output,
                &serde_json::json!({
                    "schema": "keyferry.owner-device-added.v1",
                    "device_id": format_uuid(&device_id),
                    "authority_epoch": 1,
                }),
            )
        }
        Some("list-owner-devices") if args.len() == 3 && args[1] == "--owner-kit" => {
            list_owner_devices(Path::new(&args[2]), input, output)
        }
        Some("issue-installation")
            if args.len() == 5 && args[1] == "--owner-kit" && args[3] == "--output" =>
        {
            issue_installation(Path::new(&args[2]), Path::new(&args[4]), input)?;
            writeln!(output, "installation credentials issued")
                .map_err(|_| "could not write status")
        }
        Some("grant-device-to-installation")
            if args.len() == 9
                && args[1] == "--owner-kit"
                && args[3] == "--device"
                && args[5] == "--installation"
                && args[7] == "--output" =>
        {
            grant_device_to_installation(
                Path::new(&args[2]),
                parse_uuid(&args[4])?,
                Path::new(&args[6]),
                Path::new(&args[8]),
                input,
            )?;
            writeln!(output, "device grant added to existing installation identity")
                .map_err(|_| "could not write status")
        }
        Some("materialize-device-bootstrap")
            if args.len() == 11
                && args[1] == "--owner-kit"
                && args[3] == "--device"
                && args[5] == "--installation"
                && args[7] == "--network-bundle"
                && args[9] == "--output" =>
        {
            materialize_device_bootstrap(
                Path::new(&args[2]),
                parse_uuid(&args[4])?,
                Path::new(&args[6]),
                Path::new(&args[8]),
                Path::new(&args[10]),
                input,
                output,
            )
        }
        Some("issue-installation")
            if args.len() == 7
                && args[1] == "--owner-kit"
                && args[3] == "--device"
                && args[5] == "--output" =>
        {
            issue_installation_for_device(
                Path::new(&args[2]),
                parse_uuid(&args[4])?,
                Path::new(&args[6]),
                input,
            )?;
            writeln!(output, "installation credentials issued")
                .map_err(|_| "could not write status")
        }
        Some("change-owner-kit-passphrase")
            if args.len() == 3 && args[1] == "--owner-kit" =>
        {
            change_owner_kit_passphrase(Path::new(&args[2]), input)?;
            writeln!(output, "owner-kit passphrase changed")
                .map_err(|_| "could not write status")
        }
        Some("validate-installation") if args.len() == 3 && args[1] == "--input" => {
            validate_installation_directory(Path::new(&args[2]))?;
            writeln!(output, "installation credentials valid")
                .map_err(|_| "could not write status")
        }
        Some("validate-installation-upgrade")
            if args.len() == 5 && args[1] == "--existing" && args[3] == "--candidate" =>
        {
            validate_installation_upgrade(Path::new(&args[2]), Path::new(&args[4]))?;
            writeln!(output, "installation credential expansion valid")
                .map_err(|_| "could not write status")
        }
        Some("--help" | "-h" | "help") => writeln!(
            output,
            "keyferry-pairing [--bundle PATH] COMMAND\n  create --host-address IP --host-port PORT\n  set-wifi [--replace]  (reads one JSON object from stdin)\n  initialize-recovery\n  validate\n  materialize  (output directory from KEYFERRY_PAIRING_OUTPUT_DIR)\n  status\n  provision\n  migrate-roaming --owner-kit PATH  (reads a passphrase on stdin)\n  update-roaming --owner-kit PATH [--device UUID] --policy PATH  (reads a passphrase on stdin)\n  recover-initial-roaming-policy --owner-kit PATH [--device UUID] --output PATH  (reads a passphrase on stdin)\n  save-roaming-policy --output PATH [--replace]  (reads complete policy JSON)\n  create-owner-kit --output PATH  (reads and confirms a passphrase on stdin)\n  add-owner-device --owner-kit PATH  (reads a passphrase; adds one generated authority)\n  list-owner-devices --owner-kit PATH  (reads a passphrase; returns device identifiers only)\n  issue-installation --owner-kit PATH [--device UUID] --output DIRECTORY  (reads a passphrase on stdin)\n  grant-device-to-installation --owner-kit PATH --device UUID --installation DIR --output DIR\n  materialize-device-bootstrap --owner-kit PATH --device UUID --installation DIR --network-bundle DIR --output DIR\n  change-owner-kit-passphrase --owner-kit PATH  (reads current, new, confirmation)\n  validate-installation --input DIRECTORY\n  validate-installation-upgrade --existing DIR --candidate DIR\n  export-gateway-credential --bundle PATH --port PORT --remote-token-file PATH --output PATH\n  validate-gateway-credential --input PATH\n  install-gateway-credential --input PATH\n  local-status --owner-kit PATH  (reads one passphrase; daemon/network independent)\n  local-status --owner-kit PATH --device UUID  (required for multi-device kits)\n  local-probe --owner-kit PATH [--device UUID] [--samples N]  (read-only USB probe metadata; passphrase from stdin)\n  local-recover --owner-kit PATH ACTION  (restart-network|forget-bluetooth|cancel-enrollment|usb-hid|ble-hid|reboot)\n  local-recover --owner-kit PATH --device UUID ACTION  (required for multi-device kits)\n  bootstrap-status --private-header PATH  (read-only exact-device policy status)\n  bootstrap-roaming --private-header PATH --installation DIR --network-bundle DIR --journal-dir DIR\n  local-status-bootstrap --private-header PATH\n  local-recover-bootstrap --private-header PATH ACTION"
        )
        .map_err(|_| "could not write help"),
        _ => Err("use --help for the supported commands"),
    }
}

fn validate_installation_directory(input: &Path) -> Result<(), &'static str> {
    keyferry_gateway::InstallationCredentialSet::load(input)
        .map(|_| ())
        .map_err(|_| "installation credential directory is invalid")
}

fn validate_installation_upgrade(existing: &Path, candidate: &Path) -> Result<(), &'static str> {
    let existing = InstallationCredentialSet::load(existing)
        .map_err(|_| "existing installation credential directory is invalid")?;
    let candidate = InstallationCredentialSet::load(candidate)
        .map_err(|_| "candidate installation credential directory is invalid")?;
    if candidate.len() < existing.len() {
        return Err("candidate installation removes a device grant");
    }
    for before in existing.iter() {
        let after = candidate
            .get(before.device_id())
            .ok_or("candidate installation removes a device grant")?;
        if after.owner_id() != before.owner_id()
            || after.installation_id() != before.installation_id()
            || after.owner_ca_der() != before.owner_ca_der()
            || after.installation_spki_der() != before.installation_spki_der()
            || after.installation_key_der() != before.installation_key_der()
            || after.device_server_certificate_der() != before.device_server_certificate_der()
            || after.desktop_server_certificate_der() != before.desktop_server_certificate_der()
            || after.desktop_client_certificate_der() != before.desktop_client_certificate_der()
            || after.device_link_secret() != before.device_link_secret()
            || after.route_proof_secret() != before.route_proof_secret()
        {
            return Err("candidate installation changes existing authority material");
        }
    }
    let Some(reference) = existing.iter().next() else {
        return Err("existing installation credential directory is invalid");
    };
    if candidate.iter().any(|credential| {
        credential.owner_id() != reference.owner_id()
            || credential.installation_id() != reference.installation_id()
            || credential.owner_ca_der() != reference.owner_ca_der()
            || credential.installation_spki_der() != reference.installation_spki_der()
            || credential.installation_key_der() != reference.installation_key_der()
            || credential.desktop_server_certificate_der()
                != reference.desktop_server_certificate_der()
            || credential.desktop_client_certificate_der()
                != reference.desktop_client_certificate_der()
    }) {
        return Err("candidate installation changes computer identity");
    }
    Ok(())
}

struct PrivateHeaderAuthority {
    device_id: [u8; 16],
    recovery_secret: Zeroizing<[u8; 32]>,
}

fn load_private_header_authority(path: &Path) -> Result<PrivateHeaderAuthority, &'static str> {
    let bytes = read_bounded(path, MAX_PRIVATE_HEADER_INPUT)
        .map_err(|_| "private firmware header is absent or invalid")?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| "private firmware header is absent or invalid")?;
    let device_id = parse_private_header_array::<16>(text, "kDeviceId")?;
    let recovery_secret =
        Zeroizing::new(parse_private_header_array::<32>(text, "kProvisioningKey")?);
    if device_id.iter().all(|byte| *byte == 0) || recovery_secret.iter().all(|byte| *byte == 0) {
        return Err("private firmware header authority is invalid");
    }
    Ok(PrivateHeaderAuthority {
        device_id,
        recovery_secret,
    })
}

fn parse_private_header_array<const N: usize>(
    text: &str,
    name: &str,
) -> Result<[u8; N], &'static str> {
    let marker = format!("{name}{{");
    if text.matches(&marker).count() != 1 {
        return Err("private firmware header authority is invalid");
    }
    let body = text
        .split_once(&marker)
        .and_then(|(_, suffix)| suffix.split_once("};").map(|(body, _)| body))
        .ok_or("private firmware header authority is invalid")?;
    let values = body
        .split(',')
        .map(|token| {
            let hex = token
                .trim()
                .strip_prefix("0x")
                .ok_or("private firmware header authority is invalid")?;
            if hex.len() != 2 {
                return Err("private firmware header authority is invalid");
            }
            u8::from_str_radix(hex, 16).map_err(|_| "private firmware header authority is invalid")
        })
        .collect::<Result<Vec<_>, _>>()?;
    values
        .try_into()
        .map_err(|_| "private firmware header authority is invalid")
}

fn local_status(
    owner_kit_path: &Path,
    device_id: Option<[u8; 16]>,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let authority = read_local_authority(owner_kit_path, device_id, input)?;
    local_status_with(
        authority.device_id,
        &authority.device_recovery_secret,
        output,
    )
}

fn read_local_authority(
    owner_kit_path: &Path,
    device_id: Option<[u8; 16]>,
    input: &mut dyn Read,
) -> Result<owner_kit::DeviceOwnerAuthority, &'static str> {
    let passphrases = read_secret_lines(input, 1)?;
    let kit = read_bounded(owner_kit_path, OWNER_KIT_MAX_BYTES)
        .map_err(|_| "owner-kit file is absent or invalid")?;
    match device_id {
        Some(device_id) => owner_kit::unlock_device_authority_for_device(
            &kit,
            passphrases[0].as_slice(),
            device_id,
        ),
        None => owner_kit::unlock_device_authority(&kit, passphrases[0].as_slice()),
    }
    .map_err(|_| "owner-kit authentication, selection, or authority validation failed")
}

#[derive(Debug, PartialEq)]
struct LocalProbeOptions {
    owner_kit: PathBuf,
    device_id: Option<[u8; 16]>,
    samples: u32,
}

fn parse_local_probe_args(args: &[String]) -> Result<LocalProbeOptions, &'static str> {
    let mut owner_kit = None;
    let mut device_id = None;
    let mut samples = None;
    let mut pairs = args.chunks_exact(2);
    for pair in &mut pairs {
        match pair[0].as_str() {
            "--owner-kit" if owner_kit.is_none() && !pair[1].is_empty() => {
                owner_kit = Some(PathBuf::from(&pair[1]));
            }
            "--device" if device_id.is_none() => device_id = Some(parse_uuid(&pair[1])?),
            "--samples" if samples.is_none() => {
                let count = pair[1]
                    .parse::<u32>()
                    .map_err(|_| "invalid probe sample count")?;
                if !(1..=86401).contains(&count) {
                    return Err("probe sample count must be 1 through 86401");
                }
                samples = Some(count);
            }
            _ => return Err("invalid local-probe arguments"),
        }
    }
    if !pairs.remainder().is_empty() {
        return Err("invalid local-probe arguments");
    }
    Ok(LocalProbeOptions {
        owner_kit: owner_kit.ok_or("local-probe requires --owner-kit PATH")?,
        device_id,
        samples: samples.unwrap_or(1),
    })
}

fn local_probe(
    options: &LocalProbeOptions,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    use std::time::{Duration, Instant};
    let authority = read_local_authority(&options.owner_kit, options.device_id, input)?;
    let mut client = None;
    let mut connected_at = Instant::now();
    for sample_index in 1..=options.samples {
        // Start a fresh authenticated read session before its five-minute hard
        // expiry. A failed exchange exits; it is never silently retried.
        if client.is_none() || connected_at.elapsed() >= Duration::from_secs(240) {
            drop(client.take());
            let transport = HidTransport::open(&authority.device_id)
                .map_err(|_| "exactly one matching local Keyferry USB interface is required")?;
            client = Some(
                LocalClient::connect(
                    transport,
                    authority.device_id,
                    &authority.device_recovery_secret,
                )
                .map_err(|_| "local Keyferry authentication failed")?,
            );
            connected_at = Instant::now();
        }
        let snapshot = client
            .as_mut()
            .ok_or("local probe session absent")?
            .probe_snapshot()
            .map_err(LocalError::code)?;
        let document = local_probe_value(sample_index, &snapshot);
        serde_json::to_writer(&mut *output, &document)
            .map_err(|_| "could not write local probe status")?;
        output
            .write_all(b"\n")
            .and_then(|()| output.flush())
            .map_err(|_| "could not write local probe status")?;
        if sample_index < options.samples {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}

fn local_probe_value(
    sample_index: u32,
    snapshot: &keyferry_local_management::ProbeSnapshot,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "keyferry.local-probe.v1",
        "sample_index": sample_index,
        "sample_sequence": snapshot.run.sample_sequence,
        "uptime_seconds": snapshot.run.uptime_seconds,
        "phase": snapshot.run.phase,
        "held_flags": snapshot.run.held_flags,
        "first_outcome": snapshot.run.first_outcome,
        "second_outcome": snapshot.run.second_outcome,
        "transport_running": snapshot.run.transport_running,
        "link_path": snapshot.run.link_path,
        "output_mode": snapshot.run.output_mode,
        "free_bytes": snapshot.heap.free_bytes,
        "largest_bytes": snapshot.heap.largest_bytes,
        "minimum_bytes": snapshot.heap.minimum_bytes,
        "main_stack_free_bytes": snapshot.stack.main_bytes,
        "transport_stack_free_bytes": snapshot.stack.transport_bytes,
        "probe_stack_free_bytes": snapshot.stack.probe_bytes,
    })
}

fn local_status_with(
    device_id: [u8; 16],
    recovery_secret: &[u8; 32],
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let transport = HidTransport::open(&device_id)
        .map_err(|_| "exactly one matching local Keyferry USB interface is required")?;
    let mut client = LocalClient::connect(transport, device_id, recovery_secret)
        .map_err(|_| "local Keyferry authentication failed")?;
    let device = client
        .status(local_status_page::DEVICE)
        .map_err(|_| "local device status failed")?;
    let safety = client
        .status(local_status_page::SAFETY)
        .map_err(|_| "local safety status failed")?;
    let network = client
        .status(local_status_page::NETWORK)
        .map_err(|_| "local network status failed")?;
    let ble_hid = client
        .status(local_status_page::BLE_HID)
        .map_err(|_| "local Bluetooth status failed")?;
    let policy = client
        .status(local_status_page::POLICY)
        .map_err(|_| "local policy status failed")?;
    let receipt = client
        .status(local_status_page::LAST_RECEIPT)
        .map_err(|_| "local receipt status failed")?;
    let document = serde_json::json!({
        "schema": "keyferry.local-status.v1",
        "device_id": hex(&device_id),
        "device": local_status_value(device)?,
        "safety": local_status_value(safety)?,
        "network": local_status_value(network)?,
        "ble_hid": local_status_value(ble_hid)?,
        "policy": local_status_value(policy)?,
        "last_receipt": local_status_value(receipt)?,
    });
    serde_json::to_writer(&mut *output, &document).map_err(|_| "could not write local status")?;
    output
        .write_all(b"\n")
        .map_err(|_| "could not write local status")
}

fn local_status_value(page: StatusPage) -> Result<serde_json::Value, &'static str> {
    match page {
        StatusPage::Device(value) => Ok(serde_json::json!({
            "active_output_mode": value.active_output_mode,
            "stored_output_mode": value.stored_output_mode,
            "board_compatibility_id": value.board_compatibility_id,
            "release": String::from_utf8_lossy(&value.release).trim_end_matches('\0'),
            "capabilities": value.capabilities,
        })),
        StatusPage::Safety(value) => Ok(serde_json::json!({
            "maintenance_active": value.maintenance_active,
            "command_active": value.command_active,
            "armed": value.armed,
            "usb_mounted": value.usb_mounted,
            "keyboard_neutral": value.keyboard_neutral,
            "mouse_neutral": value.mouse_neutral,
            "restart_pending": value.restart_pending,
            "receipt_storage_healthy": value.receipt_storage_healthy,
            "usb_attachment_generation": value.usb_attachment_generation,
        })),
        StatusPage::Network(value) => Ok(serde_json::json!({
            "wifi_stage": value.wifi_stage,
            "active_path": value.active_path,
            "running": value.running,
            "wifi_available": value.wifi_available,
            "ble_available": value.ble_available,
            "endpoint_authenticated": value.endpoint_authenticated,
            "configuration_valid": value.configuration_valid,
            "wifi_profile_count": value.wifi_profile_count,
            "paired_host_count": value.paired_host_count,
            "policy_state": value.policy_state,
            "wifi_error": value.wifi_error,
            "nvs_error": value.nvs_error,
        })),
        StatusPage::BleHid(value) => Ok(serde_json::json!({
            "bond_state": value.bond_state,
            "peripheral_stage": value.peripheral_stage,
            "advertising": value.advertising,
            "connected": value.connected,
            "authenticated": value.authenticated,
            "subscribed": value.subscribed,
            "ready": value.ready,
            "enrollment_active": value.enrollment_active,
            "error": value.error,
            "generation": value.generation,
            "enrollment_remaining_ms": value.enrollment_remaining_ms,
        })),
        StatusPage::Policy(value) => Ok(serde_json::json!({
            "state": value.state,
            "sequence": value.sequence,
        })),
        StatusPage::LastReceipt(value) => Ok(match value {
            Some(receipt) => local_receipt_value(&receipt),
            None => serde_json::Value::Null,
        }),
        StatusPage::ProbeRun(_) | StatusPage::ProbeHeap(_) | StatusPage::ProbeStack(_) => {
            Err("probe status requires local-probe")
        }
    }
}

fn local_receipt_value(receipt: &ReceiptStatus) -> serde_json::Value {
    serde_json::json!({
        "state": receipt.state,
        "operation": receipt.operation,
        "result": receipt.result,
        "flags": receipt.flags,
        "argument": receipt.argument,
    })
}

#[derive(Clone, Copy)]
struct LocalRecoveryAction {
    name: &'static str,
    operation: u8,
    argument: Option<u8>,
    restarts_device: bool,
}

fn parse_local_recovery_action(value: &str) -> Result<LocalRecoveryAction, &'static str> {
    let action = match value {
        "restart-network" => LocalRecoveryAction {
            name: "restart-network",
            operation: local_operation::RESTART_NETWORK,
            argument: None,
            restarts_device: false,
        },
        "forget-bluetooth" => LocalRecoveryAction {
            name: "forget-bluetooth",
            operation: local_operation::CLEAR_BLE_BOND_AND_ENROLL,
            argument: None,
            restarts_device: false,
        },
        "cancel-enrollment" => LocalRecoveryAction {
            name: "cancel-enrollment",
            operation: local_operation::CANCEL_ENROLLMENT,
            argument: None,
            restarts_device: false,
        },
        "usb-hid" => LocalRecoveryAction {
            name: "usb-hid",
            operation: local_operation::SET_OUTPUT_MODE,
            argument: Some(output_mode::USB_HID),
            restarts_device: true,
        },
        "ble-hid" => LocalRecoveryAction {
            name: "ble-hid",
            operation: local_operation::SET_OUTPUT_MODE,
            argument: Some(output_mode::BLE_HID),
            restarts_device: true,
        },
        "reboot" => LocalRecoveryAction {
            name: "reboot",
            operation: local_operation::REBOOT,
            argument: None,
            restarts_device: true,
        },
        _ => return Err("local recovery action is unsupported"),
    };
    Ok(action)
}

fn local_recover(
    owner_kit_path: &Path,
    device_id: Option<[u8; 16]>,
    action_name: &str,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let passphrases = read_secret_lines(input, 1)?;
    let kit = read_bounded(owner_kit_path, OWNER_KIT_MAX_BYTES)
        .map_err(|_| "owner-kit file is absent or invalid")?;
    let authority = match device_id {
        Some(device_id) => owner_kit::unlock_device_authority_for_device(
            &kit,
            passphrases[0].as_slice(),
            device_id,
        ),
        None => owner_kit::unlock_device_authority(&kit, passphrases[0].as_slice()),
    }
    .map_err(|_| "owner-kit authentication, selection, or authority validation failed")?;
    local_recover_with(
        authority.device_id,
        &authority.device_recovery_secret,
        action_name,
        output,
    )
}

fn local_recover_with(
    device_id: [u8; 16],
    recovery_secret: &[u8; 32],
    action_name: &str,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let action = parse_local_recovery_action(action_name)?;
    let transport = HidTransport::open(&device_id)
        .map_err(|_| "exactly one matching local Keyferry USB interface is required")?;
    let mut client = LocalClient::connect(transport, device_id, recovery_secret)
        .map_err(|_| "local Keyferry authentication failed")?;

    let open_id = generate_operation_id().map_err(|_| "operation identity generation failed")?;
    let action_id = generate_operation_id().map_err(|_| "operation identity generation failed")?;
    let close_id = generate_operation_id().map_err(|_| "operation identity generation failed")?;
    write_recovery_line(
        output,
        &serde_json::json!({
            "schema": "keyferry.local-recovery-attempt.v1",
            "device_id": hex(&device_id),
            "action": action.name,
            "maintenance_open_id": hex(&open_id),
            "action_id": hex(&action_id),
            "maintenance_close_id": hex(&close_id),
        }),
    )?;

    let opened =
        match client.mutate_and_reconcile_with_id(local_operation::OPEN_MAINTENANCE, None, open_id)
        {
            Ok(result) => result,
            Err(error) => return local_recovery_error(output, action, "open-maintenance", error),
        };
    if opened.status != local_status::OK {
        write_local_terminal(output, action, action_id, "REJECTED", opened.status, None)?;
        return Err("local maintenance could not be opened");
    }

    let acted =
        match client.mutate_and_reconcile_with_id(action.operation, action.argument, action_id) {
            Ok(result) => result,
            Err(error) => return local_recovery_error(output, action, "action", error),
        };
    let action_succeeded = acted.status == local_status::OK;
    let must_close = !action.restarts_device || !action_succeeded;
    if must_close {
        match client.mutate_and_reconcile_with_id(
            local_operation::CLOSE_MAINTENANCE,
            None,
            close_id,
        ) {
            Ok(result) if result.status == local_status::OK => {}
            Ok(result) => {
                write_local_terminal(
                    output,
                    action,
                    action_id,
                    "UNKNOWN",
                    result.status,
                    Some("close-maintenance-rejected"),
                )?;
                return Err("local maintenance close was not confirmed");
            }
            Err(error) => {
                return local_recovery_error(output, action, "close-maintenance", error);
            }
        }
    }

    let outcome = if action_succeeded {
        "COMPLETED"
    } else {
        "REJECTED"
    };
    write_local_terminal(output, action, action_id, outcome, acted.status, None)?;
    if action_succeeded {
        Ok(())
    } else {
        Err("local recovery action was rejected")
    }
}

fn local_recovery_error(
    output: &mut dyn Write,
    action: LocalRecoveryAction,
    stage: &'static str,
    error: LocalError,
) -> Result<(), &'static str> {
    let operation_id = match error {
        LocalError::UncertainMutation { operation_id, .. } => {
            Some(serde_json::Value::String(hex(&operation_id)))
        }
        _ => None,
    };
    write_recovery_line(
        output,
        &serde_json::json!({
            "schema": "keyferry.local-recovery-result.v1",
            "action": action.name,
            "outcome": "UNKNOWN",
            "stage": stage,
            "error": error.code(),
            "operation_id": operation_id,
        }),
    )?;
    Err("local recovery outcome is not confirmed")
}

fn write_local_terminal(
    output: &mut dyn Write,
    action: LocalRecoveryAction,
    operation_id: [u8; 16],
    outcome: &'static str,
    status: u8,
    error: Option<&'static str>,
) -> Result<(), &'static str> {
    write_recovery_line(
        output,
        &serde_json::json!({
            "schema": "keyferry.local-recovery-result.v1",
            "action": action.name,
            "outcome": outcome,
            "status": status,
            "operation_id": hex(&operation_id),
            "error": error,
        }),
    )
}

fn write_json_line(output: &mut dyn Write, value: &serde_json::Value) -> Result<(), &'static str> {
    serde_json::to_writer(&mut *output, value).map_err(|_| "could not write local result")?;
    output
        .write_all(b"\n")
        .map_err(|_| "could not write local result")
}

fn write_recovery_line(
    output: &mut dyn Write,
    value: &serde_json::Value,
) -> Result<(), &'static str> {
    write_json_line(output, value)?;
    output.flush().map_err(|_| "could not write local result")
}

fn create_owner_kit(
    bundle: &Path,
    output: &Path,
    input: &mut dyn Read,
) -> Result<(), &'static str> {
    require_bundle(bundle)?;
    let device: DeviceConfig = read_json_private(&bundle.join(DEVICE_CONFIG))?;
    let device_id = parse_uuid(&device.device_id)?;
    let recovery = read_bounded(&bundle.join(RECOVERY_SECRET), 32)
        .map_err(|_| "administrative recovery secret is absent or invalid")?;
    let recovery: [u8; 32] = recovery
        .try_into()
        .map_err(|_| "administrative recovery secret is absent or invalid")?;
    if recovery.iter().all(|byte| *byte == 0) {
        return Err("administrative recovery secret is absent or invalid");
    }
    let passphrases = read_secret_lines(input, 2)?;
    if passphrases[0].as_slice() != passphrases[1].as_slice() {
        return Err("owner-kit passphrase confirmation does not match");
    }
    let mut owner_id = random_array::<16>()?;
    while owner_id.iter().all(|byte| *byte == 0) {
        owner_id = random_array::<16>()?;
    }
    let bytes = owner_kit::create(
        device_id,
        recovery,
        passphrases[0].as_slice(),
        random_array::<16>()?,
        random_array::<12>()?,
        owner_id,
    )
    .map_err(|_| "could not create encrypted owner kit")?;
    write_new_owner_only(output, &bytes)
}

fn add_owner_device(owner_kit_path: &Path, input: &mut dyn Read) -> Result<[u8; 16], &'static str> {
    let metadata =
        fs::symlink_metadata(owner_kit_path).map_err(|_| "owner-kit file is absent or invalid")?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("owner-kit file must be a regular unlinked file");
    }
    let passphrases = read_secret_lines(input, 1)?;
    let mut device_id = random_array::<16>()?;
    while device_id.iter().all(|byte| *byte == 0) {
        device_id = random_array::<16>()?;
    }
    let mut recovery_secret = random_array::<32>()?;
    while recovery_secret.iter().all(|byte| *byte == 0) {
        recovery_secret = random_array::<32>()?;
    }
    let lock = owner_kit_path.with_extension("add-device.lock");
    write_new_owner_only(&lock, b"locked\n")
        .map_err(|_| "another owner-kit update is active or needs recovery")?;
    let update_result = (|| {
        let original = read_bounded(owner_kit_path, OWNER_KIT_MAX_BYTES)
            .map_err(|_| "owner-kit file is absent or invalid")?;
        let changed = owner_kit::add_device(
            &original,
            passphrases[0].as_slice(),
            device_id,
            recovery_secret,
            random_array::<16>()?,
            random_array::<12>()?,
        )
        .map_err(|_| "owner-kit authentication or device addition failed")?;
        replace_private_durable(owner_kit_path, &changed)
    })();
    recovery_secret.zeroize();
    let unlock_result = remove_private_durable(&lock);
    match (update_result, unlock_result) {
        (Ok(()), Ok(())) => Ok(device_id),
        (Ok(()), Err(_)) => Err("owner device added but its update lock could not be removed"),
        (Err(error), _) => Err(error),
    }
}

fn list_owner_devices(
    owner_kit_path: &Path,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let passphrases = read_secret_lines(input, 1)?;
    let kit = read_bounded(owner_kit_path, OWNER_KIT_MAX_BYTES)
        .map_err(|_| "owner-kit file is absent or invalid")?;
    let device_ids = owner_kit::device_ids(&kit, passphrases[0].as_slice())
        .map_err(|_| "owner-kit authentication or device listing failed")?;
    write_json_line(
        output,
        &serde_json::json!({
            "schema": "keyferry.owner-devices.v1",
            "device_ids": device_ids.iter().map(format_uuid).collect::<Vec<_>>(),
        }),
    )
}

fn issue_installation(
    owner_kit_path: &Path,
    output: &Path,
    input: &mut dyn Read,
) -> Result<(), &'static str> {
    let passphrases = read_secret_lines(input, 1)?;
    let kit = read_bounded(owner_kit_path, OWNER_KIT_MAX_BYTES)
        .map_err(|_| "owner-kit file is absent or invalid")?;
    let issued = owner_kit::issue_installation(&kit, passphrases[0].as_slice())
        .map_err(|_| "owner-kit authentication or issuance failed")?;
    publish_issued_installation(output, &issued)
}

fn issue_installation_for_device(
    owner_kit_path: &Path,
    device_id: [u8; 16],
    output: &Path,
    input: &mut dyn Read,
) -> Result<(), &'static str> {
    let passphrases = read_secret_lines(input, 1)?;
    let kit = read_bounded(owner_kit_path, OWNER_KIT_MAX_BYTES)
        .map_err(|_| "owner-kit file is absent or invalid")?;
    let issued =
        owner_kit::issue_installation_for_device(&kit, passphrases[0].as_slice(), device_id)
            .map_err(|_| "owner-kit authentication, device selection, or issuance failed")?;
    publish_issued_installation(output, &issued)
}

fn publish_issued_installation(
    output: &Path,
    issued: &owner_kit::IssuedInstallation,
) -> Result<(), &'static str> {
    if output.exists() {
        return Err("installation credential directory already exists");
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|_| "could not create installation output directory")?;
    let temporary = parent.join(format!(
        ".keyferry-installation-{}",
        hex(&random_array::<8>()?)
    ));
    if temporary.exists() {
        return Err("could not allocate installation credential directory");
    }
    create_private_dir(&temporary)?;
    let result = write_issued_installation(&temporary, issued).and_then(|()| {
        fs::rename(&temporary, output)
            .map_err(|_| "could not publish installation credential directory")
    });
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn grant_device_to_installation(
    owner_kit_path: &Path,
    device_id: [u8; 16],
    existing_path: &Path,
    output: &Path,
    input: &mut dyn Read,
) -> Result<(), &'static str> {
    let passphrases = read_secret_lines(input, 1)?;
    let kit = read_bounded(owner_kit_path, OWNER_KIT_MAX_BYTES)
        .map_err(|_| "owner-kit file is absent or invalid")?;
    let existing = keyferry_gateway::InstallationCredentials::load(existing_path)
        .map_err(|_| "existing singleton installation is invalid")?;
    let expanded = owner_kit::expand_installation_with_device(
        &kit,
        passphrases[0].as_slice(),
        &existing,
        device_id,
    )
    .map_err(|_| "owner-kit authentication, device grant, or installation match failed")?;
    if output.exists() {
        return Err("expanded installation output already exists");
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|_| "could not create installation output directory")?;
    let temporary = parent.join(format!(
        ".keyferry-installation-v3-{}",
        hex(&random_array::<8>()?)
    ));
    if temporary.exists() {
        return Err("could not allocate expanded installation directory");
    }
    create_private_dir(&temporary)?;
    let result = write_expanded_installation(&temporary, &expanded).and_then(|()| {
        keyferry_gateway::InstallationCredentialSet::load(&temporary)
            .map_err(|_| "expanded installation failed validation")?;
        fs::rename(&temporary, output)
            .map_err(|_| "could not publish expanded installation directory")
    });
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn change_owner_kit_passphrase(
    owner_kit_path: &Path,
    input: &mut dyn Read,
) -> Result<(), &'static str> {
    let metadata =
        fs::symlink_metadata(owner_kit_path).map_err(|_| "owner-kit file is absent or invalid")?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("owner-kit file must be a regular unlinked file");
    }
    let passphrases = read_secret_lines(input, 3)?;
    if passphrases[1].as_slice() != passphrases[2].as_slice() {
        return Err("new owner-kit passphrase confirmation does not match");
    }
    let lock = owner_kit_path.with_extension("rekey.lock");
    write_new_owner_only(&lock, b"locked\n")
        .map_err(|_| "another owner-kit passphrase change is active or needs recovery")?;
    let change_result = (|| {
        let original = read_bounded(owner_kit_path, 16 * 1024)
            .map_err(|_| "owner-kit file is absent or invalid")?;
        let changed = owner_kit::change_passphrase(
            &original,
            passphrases[0].as_slice(),
            passphrases[1].as_slice(),
            random_array::<16>()?,
            random_array::<12>()?,
        )
        .map_err(|_| "owner-kit authentication or passphrase change failed")?;
        replace_private_durable(owner_kit_path, &changed)
    })();
    let unlock_result = remove_private_durable(&lock);
    match (change_result, unlock_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(_)) => Err("owner-kit changed but its rekey lock could not be removed"),
        (Err(error), _) => Err(error),
    }
}

fn write_issued_installation(
    directory: &Path,
    issued: &owner_kit::IssuedInstallation,
) -> Result<(), &'static str> {
    write_json_private(&directory.join("installation.json"), &issued.manifest)?;
    for (name, bytes) in [
        ("owner-id.bin", issued.owner_id.as_slice()),
        ("device-id.bin", issued.device_id.as_slice()),
        ("installation-id.bin", issued.installation_id.as_slice()),
        ("owner-ca.der", issued.owner_ca_der.as_slice()),
        (
            "installation-spki.der",
            issued.installation_spki_der.as_slice(),
        ),
        (
            "installation-key.der",
            issued.installation_key_der.as_slice(),
        ),
        (
            "device-server-cert.der",
            issued.device_server_certificate_der.as_slice(),
        ),
        (
            "desktop-server-cert.der",
            issued.desktop_server_certificate_der.as_slice(),
        ),
        (
            "desktop-client-cert.der",
            issued.desktop_client_certificate_der.as_slice(),
        ),
        (
            "device-link-secret.bin",
            issued.device_link_secret.as_slice(),
        ),
        (
            "route-proof-secret.bin",
            issued.route_proof_secret.as_slice(),
        ),
    ] {
        write_new_private(&directory.join(name), bytes)?;
    }
    Ok(())
}

fn write_expanded_installation(
    directory: &Path,
    issued: &owner_kit::ExpandedInstallationV3,
) -> Result<(), &'static str> {
    write_json_private(&directory.join("installation-v3.json"), &issued.manifest)?;
    for (name, bytes) in [
        ("owner-id.bin", issued.owner_id.as_slice()),
        ("installation-id.bin", issued.installation_id.as_slice()),
        ("owner-ca.der", issued.owner_ca_der.as_slice()),
        (
            "installation-spki.der",
            issued.installation_spki_der.as_slice(),
        ),
        (
            "installation-key.der",
            issued.installation_key_der.as_slice(),
        ),
        (
            "desktop-server-cert.der",
            issued.desktop_server_certificate_der.as_slice(),
        ),
        (
            "desktop-client-cert.der",
            issued.desktop_client_certificate_der.as_slice(),
        ),
    ] {
        write_new_private(&directory.join(name), bytes)?;
    }
    let devices = directory.join("devices");
    create_private_dir(&devices)?;
    for device in &issued.devices {
        let root = devices.join(hex(&device.device_id));
        create_private_dir(&root)?;
        write_new_private(&root.join("device-id.bin"), &device.device_id)?;
        write_new_private(
            &root.join("device-server-cert.der"),
            &device.device_server_certificate_der,
        )?;
        write_new_private(
            &root.join("device-link-secret.bin"),
            &device.device_link_secret,
        )?;
        write_new_private(
            &root.join("route-proof-secret.bin"),
            &device.route_proof_secret,
        )?;
        write_json_private(&root.join("grant.json"), &device.grant)?;
    }
    Ok(())
}

fn read_secret_lines(
    input: &mut dyn Read,
    expected: usize,
) -> Result<Vec<Zeroizing<Vec<u8>>>, &'static str> {
    let maximum = SECRET_LINE_MAX_BYTES
        .checked_add(1)
        .and_then(|line| line.checked_mul(expected as u64))
        .ok_or("secret input bound is invalid")?;
    let mut bytes = Zeroizing::new(Vec::new());
    input
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read secret input")?;
    if bytes.len() as u64 > maximum || bytes.contains(&0) {
        return Err("secret input is invalid or exceeds its bound");
    }
    let mut lines = bytes
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .collect::<Vec<_>>();
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    if lines.len() != expected
        || lines
            .iter()
            .any(|line| line.is_empty() || line.len() as u64 > SECRET_LINE_MAX_BYTES)
    {
        return Err("secret input has the wrong number of lines");
    }
    Ok(lines
        .into_iter()
        .map(|line| Zeroizing::new(line.to_vec()))
        .collect())
}

fn parse_export_gateway_args(args: &[String]) -> Result<ExportGatewayArgs, &'static str> {
    if args.len() != 8 {
        return Err(
            "export-gateway-credential requires bundle, port, remote token file, and output paths",
        );
    }
    let mut bundle = None;
    let mut port = None;
    let mut remote_token_file = None;
    let mut output = None;
    for pair in args.chunks_exact(2) {
        let slot = match pair[0].as_str() {
            "--bundle" => &mut bundle,
            "--port" => {
                if port.is_some() {
                    return Err("export-gateway-credential received a duplicate option");
                }
                port = Some(
                    pair[1]
                        .parse::<u16>()
                        .ok()
                        .filter(|value| *value != 0)
                        .ok_or("gateway tailnet port must be an integer from 1 through 65535")?,
                );
                continue;
            }
            "--remote-token-file" => &mut remote_token_file,
            "--output" => &mut output,
            _ => return Err("export-gateway-credential received an unsupported option"),
        };
        if slot.is_some() || pair[1].is_empty() {
            return Err("export-gateway-credential received a duplicate or empty option");
        }
        *slot = Some(pair[1].clone());
    }
    Ok(ExportGatewayArgs {
        bundle: PathBuf::from(bundle.ok_or("gateway bundle path is required")?),
        port: port.ok_or("gateway tailnet port is required")?,
        remote_token_file: PathBuf::from(
            remote_token_file.ok_or("remote token file path is required")?,
        ),
        output: PathBuf::from(output.ok_or("gateway credential output path is required")?),
    })
}

fn export_gateway_credential(options: &ExportGatewayArgs) -> Result<(), &'static str> {
    validate_bundle(&options.bundle)?;
    let spki_der = read_bounded(&options.bundle.join(FIRMWARE_SPKI), 2048)?;
    let private_key = read_bounded(
        &options.bundle.join(DAEMON_SECRETS).join("host-key.der"),
        8192,
    )?;
    let parsed_key =
        KeyPair::try_from(private_key.as_slice()).map_err(|_| "host key is invalid")?;
    if parsed_key.algorithm() != &PKCS_ECDSA_P256_SHA256
        || parsed_key.subject_public_key_info() != spki_der
    {
        return Err("gateway identity is not the required P-256 key");
    }
    let remote_bearer = read_remote_bearer(&options.remote_token_file)?;
    let credential = GatewayCredential {
        schema_version: GATEWAY_CREDENTIAL_SCHEMA_VERSION,
        port: options.port,
        gateway_spki_der: hex(&spki_der),
        remote_bearer,
    };
    let mut bytes = serde_json::to_vec_pretty(&credential)
        .map_err(|_| "could not encode gateway credential")?;
    bytes.push(b'\n');
    if bytes.len() > MAX_GATEWAY_CREDENTIAL_BYTES {
        return Err("gateway credential exceeds its bounded size");
    }
    write_new_owner_only(&options.output, &bytes)
}

fn install_gateway_credential(input: &Path, output: &Path) -> Result<(), &'static str> {
    let canonical = canonical_gateway_credential(input)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|_| "could not create gateway credential directory")?;
    }
    write_new_owner_only(output, &canonical)
}

fn canonical_gateway_credential(input: &Path) -> Result<Vec<u8>, &'static str> {
    let bytes = read_bounded(input, 4096).map_err(|_| "gateway credential input is invalid")?;
    let credential: GatewayCredential =
        serde_json::from_slice(&bytes).map_err(|_| "gateway credential input is invalid")?;
    if credential.schema_version != GATEWAY_CREDENTIAL_SCHEMA_VERSION
        || credential.port == 0
        || credential.remote_bearer.len() != 64
        || !credential
            .remote_bearer
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || credential.gateway_spki_der.len() != 182
        || !credential
            .gateway_spki_der
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("gateway credential input is invalid");
    }
    let spki = parse_hex::<91>(
        &credential.gateway_spki_der,
        "gateway credential input is invalid",
    )?;
    gateway_id_for_spki(&spki).map_err(|_| "gateway credential input is invalid")?;
    let mut canonical = serde_json::to_vec_pretty(&credential)
        .map_err(|_| "gateway credential input is invalid")?;
    canonical.push(b'\n');
    if canonical.len() > 4096 {
        return Err("gateway credential input is invalid");
    }
    Ok(canonical)
}

fn default_gateway_credential_path() -> PathBuf {
    if let Some(path) = env::var_os("KEYFERRY_GATEWAY_CREDENTIAL") {
        return PathBuf::from(path);
    }
    #[cfg(windows)]
    if let Some(root) = env::var_os("LOCALAPPDATA") {
        return PathBuf::from(root).join("keyferry").join("gateway.json");
    }
    #[cfg(target_os = "macos")]
    if let Some(root) = env::var_os("HOME") {
        return PathBuf::from(root)
            .join("Library")
            .join("Application Support")
            .join("keyferry")
            .join("gateway.json");
    }
    if let Some(root) = env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(root).join("keyferry").join("gateway.json");
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("state")
        .join("keyferry")
        .join("gateway.json")
}

fn read_remote_bearer(path: &Path) -> Result<String, &'static str> {
    let bytes = read_bounded(path, MAX_REMOTE_TOKEN_BYTES)
        .map_err(|_| "remote bearer token file is absent or invalid")?;
    let token = match bytes.as_slice() {
        [token @ .., b'\n'] => token.strip_suffix(b"\r").unwrap_or(token),
        token => token,
    };
    if token.len() != 64
        || !token
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err("remote bearer token file is absent or invalid");
    }
    String::from_utf8(token.to_vec()).map_err(|_| "remote bearer token file is absent or invalid")
}

fn parse_create_args(args: &[String]) -> Result<(IpAddr, u16), &'static str> {
    if args.len() != 4 {
        return Err("create requires one explicit host address and port");
    }
    let mut address = None;
    let mut port = None;
    for pair in args.chunks_exact(2) {
        match pair[0].as_str() {
            "--host-address" => {
                address = Some(
                    pair[1]
                        .parse::<IpAddr>()
                        .map_err(|_| "host address must be an explicit IP address")?,
                );
            }
            "--host-port" => {
                port = Some(
                    pair[1]
                        .parse::<u16>()
                        .map_err(|_| "host port must be an integer from 1 through 65535")?,
                );
            }
            _ => return Err("create received an unsupported option"),
        }
    }
    let address = address.ok_or("host address is required")?;
    let port = port
        .filter(|value| *value != 0)
        .ok_or("host port must be nonzero")?;
    if address.is_unspecified() || address.is_multicast() {
        return Err("host address must identify one selected interface");
    }
    Ok((address, port))
}

fn create_bundle(bundle: &Path, address: IpAddr, port: u16) -> Result<(), &'static str> {
    if bundle.exists() {
        return Err("private pairing bundle already exists; refusing to overwrite it");
    }
    let parent = bundle.parent().ok_or("private bundle path has no parent")?;
    fs::create_dir_all(parent).map_err(|_| "could not create pairing bundle parent directory")?;
    let suffix = hex(&random_array::<8>()?);
    let temporary = parent.join(format!(".first-hil.tmp-{suffix}"));
    if temporary.exists() {
        return Err("could not allocate private temporary bundle");
    }
    create_private_dir(&temporary)?;

    let result = create_bundle_in(&temporary, address, port).and_then(|()| {
        fs::rename(&temporary, bundle).map_err(|_| "could not publish private bundle")
    });
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn create_bundle_in(bundle: &Path, address: IpAddr, port: u16) -> Result<(), &'static str> {
    for relative in [
        "firmware",
        "keyferryd",
        DAEMON_SECRETS,
        "keyferryd/secrets/pairings",
        RECOVERY_DIR,
    ] {
        create_private_dir(&bundle.join(relative))?;
    }

    let device_id = uuid_v4(random_array::<16>()?);
    let device_id_text = format_uuid(&device_id);
    let link_secret = random_array::<32>()?;
    let mut recovery_secret = random_array::<32>()?;
    while recovery_secret == link_secret {
        recovery_secret = random_array::<32>()?;
    }
    let host_id = random_array::<16>()?;
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|_| "could not generate host signing key")?;
    let parameters = CertificateParams::new(vec!["keyferry.local".to_owned()])
        .map_err(|_| "could not configure host certificate")?;
    let certificate = parameters
        .self_signed(&key_pair)
        .map_err(|_| "could not generate host certificate")?;
    let certificate_der = certificate.der();
    let spki_der = key_pair.subject_public_key_info();

    write_new_private(&bundle.join(FIRMWARE_CERT), certificate_der)?;
    write_new_private(&bundle.join(FIRMWARE_SPKI), &spki_der)?;
    write_new_private(&bundle.join(RECOVERY_SECRET), &recovery_secret)?;
    write_json_private(
        &bundle.join(DEVICE_CONFIG),
        &DeviceConfig {
            schema_version: SCHEMA_VERSION,
            device_id: device_id_text.clone(),
            link_secret_hex: hex(&link_secret),
            host_address: address.to_string(),
            host_port: port,
            host_certificate_der: "host-cert.der".to_owned(),
            host_spki_der: "host-spki.der".to_owned(),
            host_spki_sha256: hex(&Sha256::digest(&spki_der)),
        },
    )?;

    let secret_root = bundle.join(DAEMON_SECRETS);
    write_new_private(&secret_root.join("host-id"), &host_id)?;
    write_new_private(&secret_root.join("host-key.der"), &key_pair.serialize_der())?;
    write_new_private(&secret_root.join("host-cert.der"), certificate_der)?;
    write_new_private(
        &secret_root
            .join("pairings")
            .join(format!("{}.link", hex(&device_id))),
        &link_secret,
    )?;
    write_json_private(
        &bundle.join(DAEMON_CONFIG),
        &DaemonConfig {
            schema_version: SCHEMA_VERSION,
            tls_bind: SocketAddr::new(address, port).to_string(),
            tls_device_id: device_id_text,
            tls_secret_dir: "secrets".to_owned(),
            discovery_netmask: None,
        },
    )
}

fn initialize_recovery(bundle: &Path) -> Result<(), &'static str> {
    require_bundle(bundle)?;
    let secret_path = bundle.join(RECOVERY_SECRET);
    if secret_path.exists() {
        return Err("administrative recovery secret already exists; refusing to overwrite it");
    }
    let device: DeviceConfig = read_json_private(&bundle.join(DEVICE_CONFIG))?;
    let link_secret = parse_hex::<32>(&device.link_secret_hex, "link secret is invalid")?;
    let mut recovery_secret = random_array::<32>()?;
    while recovery_secret == link_secret {
        recovery_secret = random_array::<32>()?;
    }
    create_private_dir(&bundle.join(RECOVERY_DIR))?;
    write_new_private(&secret_path, &recovery_secret)
}

fn set_wifi(bundle: &Path, input: &mut dyn Read, replace: bool) -> Result<(), &'static str> {
    require_bundle(bundle)?;
    let path = bundle.join(WIFI_CONFIG);
    if path.exists() && !replace {
        return Err("Wi-Fi credentials already exist; refusing to overwrite them");
    }
    let mut bytes = Vec::new();
    input
        .take(MAX_WIFI_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read Wi-Fi input")?;
    if bytes.len() as u64 > MAX_WIFI_INPUT {
        return Err("Wi-Fi input exceeds the bounded size");
    }
    let wifi: WifiConfig = serde_json::from_slice(&bytes)
        .map_err(|_| "Wi-Fi input is not the required JSON object")?;
    validate_wifi(&wifi)?;
    if replace {
        write_json_replace_private(&path, &wifi)
    } else {
        write_json_private(&path, &wifi)
    }
}

fn validate_bundle(bundle: &Path) -> Result<(), &'static str> {
    require_bundle(bundle)?;
    let device: DeviceConfig = read_json_private(&bundle.join(DEVICE_CONFIG))?;
    let daemon: DaemonConfig = read_json_private(&bundle.join(DAEMON_CONFIG))?;
    let wifi: WifiConfig = read_json_private(&bundle.join(WIFI_CONFIG))
        .map_err(|_| "private pairing bundle is incomplete: Wi-Fi input is absent or invalid")?;
    validate_wifi(&wifi)?;
    let recovery_secret = read_bounded(&bundle.join(RECOVERY_SECRET), 32)
        .map_err(|_| "administrative recovery secret is absent or invalid")?;
    if recovery_secret.len() != 32 || recovery_secret.iter().all(|byte| *byte == 0) {
        return Err("administrative recovery secret is absent or invalid");
    }

    if device.schema_version != SCHEMA_VERSION || daemon.schema_version != SCHEMA_VERSION {
        return Err("private pairing bundle has an unsupported schema version");
    }
    let device_id = parse_uuid(&device.device_id)?;
    let link_secret = parse_hex::<32>(&device.link_secret_hex, "link secret is invalid")?;
    if recovery_secret.as_slice() == link_secret {
        return Err("administrative recovery secret must differ from the link secret");
    }
    let address = device
        .host_address
        .parse::<IpAddr>()
        .map_err(|_| "host address is invalid")?;
    if address.is_unspecified() || address.is_multicast() || device.host_port == 0 {
        return Err("host endpoint is invalid");
    }
    if daemon.tls_bind != SocketAddr::new(address, device.host_port).to_string()
        || daemon.tls_device_id != device.device_id
        || daemon.tls_secret_dir != "secrets"
    {
        return Err("firmware and keyferryd configuration do not match");
    }
    if let Some(netmask) = &daemon.discovery_netmask {
        let address = match address {
            IpAddr::V4(value) => u32::from(value),
            IpAddr::V6(_) => return Err("discovery requires an IPv4 host address"),
        };
        let mask = u32::from(
            netmask
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| "discovery netmask is invalid")?,
        );
        let inverted = !mask;
        if mask == 0
            || mask == u32::MAX
            || inverted <= 1
            || (inverted & (inverted + 1)) != 0
            || address == (address & mask)
            || address == ((address & mask) | inverted)
        {
            return Err("discovery netmask is invalid for the selected host address");
        }
    }
    if device.host_certificate_der != "host-cert.der" || device.host_spki_der != "host-spki.der" {
        return Err("firmware certificate references are invalid");
    }

    let firmware_cert = read_bounded(&bundle.join(FIRMWARE_CERT), MAX_CERTIFICATE_BYTES)?;
    let firmware_spki = read_bounded(&bundle.join(FIRMWARE_SPKI), 2048)?;
    let daemon_root = bundle.join(DAEMON_SECRETS);
    if fs::read(daemon_root.join("host-id"))
        .map_err(|_| "host identity is absent")?
        .len()
        != 16
    {
        return Err("host identity is invalid");
    }
    let private_key = read_bounded(&daemon_root.join("host-key.der"), 8192)?;
    let parsed_key =
        KeyPair::try_from(private_key.as_slice()).map_err(|_| "host key is invalid")?;
    if parsed_key.subject_public_key_info() != firmware_spki {
        return Err("host key and firmware SPKI do not match");
    }
    let daemon_cert = read_bounded(&daemon_root.join("host-cert.der"), MAX_CERTIFICATE_BYTES)?;
    if daemon_cert != firmware_cert {
        return Err("host certificate copies do not match");
    }
    let (remainder, certificate) =
        parse_x509_certificate(&firmware_cert).map_err(|_| "host certificate is invalid")?;
    if !remainder.is_empty() || certificate.tbs_certificate.subject_pki.raw != firmware_spki {
        return Err("host certificate and firmware SPKI do not match");
    }
    if hex(&Sha256::digest(&firmware_spki)) != device.host_spki_sha256 {
        return Err("host SPKI pin does not match the host key");
    }
    let pairing = fs::read(
        daemon_root
            .join("pairings")
            .join(format!("{}.link", hex(&device_id))),
    )
    .map_err(|_| "keyferryd link secret is absent")?;
    if pairing != link_secret {
        return Err("firmware and keyferryd link secrets do not match");
    }
    Ok(())
}

fn validate_wifi(wifi: &WifiConfig) -> Result<(), &'static str> {
    if wifi.schema_version != SCHEMA_VERSION {
        return Err("Wi-Fi input has an unsupported schema version");
    }
    let ssid_len = wifi.ssid.len();
    let password_len = wifi.password.len();
    if !(1..=32).contains(&ssid_len) || wifi.ssid.contains('\0') {
        return Err("Wi-Fi SSID must contain 1 through 32 bytes and no NUL");
    }
    if !(8..=63).contains(&password_len) || wifi.password.contains('\0') {
        return Err("Wi-Fi password must contain 8 through 63 bytes and no NUL");
    }
    Ok(())
}

fn materialize_device_bootstrap(
    owner_kit_path: &Path,
    device_id: [u8; 16],
    installation_path: &Path,
    network_bundle: &Path,
    destination: &Path,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let passphrases = read_secret_lines(input, 1)?;
    let kit = read_bounded(owner_kit_path, OWNER_KIT_MAX_BYTES)
        .map_err(|_| "owner-kit file is absent or invalid")?;
    let authority =
        owner_kit::unlock_device_authority_for_device(&kit, passphrases[0].as_slice(), device_id)
            .map_err(|_| "owner-kit authorization failed")?;
    let installations = InstallationCredentialSet::load(installation_path)
        .map_err(|_| "installation credential directory is invalid")?;
    let credential = installations
        .get(device_id)
        .ok_or("installation has no grant for the selected device")?;
    if credential.owner_id() != authority.owner_id
        || credential.device_id() != authority.device_id
        || credential.owner_ca_der() != authority.owner_ca_der
    {
        return Err("owner kit and installation authority do not match");
    }

    let wifi: WifiConfig = read_json_private(&network_bundle.join(WIFI_CONFIG))
        .map_err(|_| "network bootstrap Wi-Fi input is absent or invalid")?;
    validate_wifi(&wifi)?;
    let network_device: DeviceConfig = read_json_private(&network_bundle.join(DEVICE_CONFIG))
        .map_err(|_| "network bootstrap endpoint is absent or invalid")?;
    let host_ipv4 = network_device
        .host_address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "network bootstrap endpoint must be IPv4")?;
    if host_ipv4.is_unspecified() || host_ipv4.is_multicast() || network_device.host_port == 0 {
        return Err("network bootstrap endpoint is invalid");
    }
    let host_id = credential.installation_id();
    let link_secret = credential.device_link_secret();
    let spki_hash: [u8; 32] = Sha256::digest(credential.installation_spki_der()).into();
    let header = render_private_header(
        &device_id,
        &host_id,
        &link_secret,
        &authority.device_recovery_secret,
        &spki_hash,
        credential.device_server_certificate_der(),
        wifi.ssid.as_bytes(),
        wifi.password.as_bytes(),
        &host_ipv4.to_string(),
        credential.device_server_name(),
        network_device.host_port,
    );
    create_private_dir(destination)?;
    write_replace_private(&destination.join(GENERATED_HEADER), header.as_bytes())?;
    write_json_line(
        output,
        &serde_json::json!({
            "schema": "keyferry.device-bootstrap-materialized.v1",
            "device_id": format_uuid(&device_id),
            "installation_id": hex(&host_id),
            "authority_epoch": authority.authority_epoch,
            "private_input_sha256": hex(&Sha256::digest(header.as_bytes())),
        }),
    )
}

fn materialize_firmware(bundle: &Path, destination: &Path) -> Result<(), &'static str> {
    validate_bundle(bundle)?;
    let device: DeviceConfig = read_json_private(&bundle.join(DEVICE_CONFIG))?;
    let wifi: WifiConfig = read_json_private(&bundle.join(WIFI_CONFIG))?;
    let device_id = parse_uuid(&device.device_id)?;
    let link_secret = parse_hex::<32>(&device.link_secret_hex, "link secret is invalid")?;
    let recovery_secret = read_bounded(&bundle.join(RECOVERY_SECRET), 32)
        .map_err(|_| "administrative recovery secret is absent or invalid")?;
    let spki_hash = parse_hex::<32>(&device.host_spki_sha256, "host SPKI pin is invalid")?;
    let certificate = read_bounded(&bundle.join(FIRMWARE_CERT), MAX_CERTIFICATE_BYTES)?;
    let host_id = read_bounded(&bundle.join(DAEMON_SECRETS).join("host-id"), 16)?;
    if host_id.len() != 16 {
        return Err("host identity is invalid");
    }
    let host_address = device
        .host_address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "first-HIL firmware requires an IPv4 host address")?;

    let header = render_private_header(
        &device_id,
        host_id
            .as_slice()
            .try_into()
            .map_err(|_| "host identity is invalid")?,
        &link_secret,
        recovery_secret
            .as_slice()
            .try_into()
            .map_err(|_| "administrative recovery secret is absent or invalid")?,
        &spki_hash,
        &certificate,
        wifi.ssid.as_bytes(),
        wifi.password.as_bytes(),
        &host_address.to_string(),
        "keyferry.local",
        device.host_port,
    );

    create_private_dir(destination)?;
    write_replace_private(&destination.join(GENERATED_HEADER), header.as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn render_private_header(
    device_id: &[u8; 16],
    host_id: &[u8; 16],
    link_secret: &[u8; 32],
    provisioning_key: &[u8; 32],
    spki_hash: &[u8; 32],
    certificate: &[u8],
    wifi_ssid: &[u8],
    wifi_password: &[u8],
    host_ipv4: &str,
    tls_server_name: &str,
    host_port: u16,
) -> String {
    let mut header = String::from(
        "// Generated private build input. Never copy into source control.\n\
#pragma once\n\
#include <array>\n\
#include <cstddef>\n\
#include <cstdint>\n\n\
namespace keyferry::hil_private {\n\
inline constexpr bool kEnabled = true;\n",
    );
    append_cpp_array(&mut header, "kDeviceId", device_id);
    append_cpp_array(&mut header, "kHostId", host_id);
    append_cpp_array(&mut header, "kLinkSecret", link_secret);
    append_cpp_array(&mut header, "kProvisioningKey", provisioning_key);
    append_cpp_array(&mut header, "kSpkiSha256", spki_hash);
    append_cpp_array(&mut header, "kCaCertificateDer", certificate);
    append_cpp_array(&mut header, "kWifiSsid", wifi_ssid);
    append_cpp_array(&mut header, "kWifiPassword", wifi_password);
    header.push_str(&format!(
        "inline constexpr char kHostIpv4[] = \"{host_ipv4}\";\n\
inline constexpr char kTlsServerName[] = \"{tls_server_name}\";\n\
inline constexpr std::uint16_t kHostPort = {};\n\
}}  // namespace keyferry::hil_private\n",
        host_port,
    ));
    header
}

fn append_cpp_array(output: &mut String, name: &str, bytes: &[u8]) {
    output.push_str(&format!(
        "inline constexpr std::array<std::uint8_t, {}> {name}{{",
        bytes.len()
    ));
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str(&format!("0x{byte:02x}"));
    }
    output.push_str("};\n");
}

fn require_bundle(bundle: &Path) -> Result<(), &'static str> {
    if bundle.is_dir() {
        Ok(())
    } else {
        Err("private pairing bundle is absent")
    }
}

fn read_json_private<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, &'static str> {
    let bytes = read_bounded(path, 16 * 1024)?;
    serde_json::from_slice(&bytes).map_err(|_| "private pairing file is invalid")
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, &'static str> {
    let file = fs::File::open(path).map_err(|_| "required private pairing file is absent")?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read private pairing file")?;
    if bytes.len() as u64 > maximum {
        return Err("private pairing file exceeds its bounded size");
    }
    Ok(bytes)
}

fn write_json_private<T: Serialize>(path: &Path, value: &T) -> Result<(), &'static str> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|_| "could not encode private JSON")?;
    bytes.push(b'\n');
    write_new_private(path, &bytes)
}

fn publish_json_owner_only<T: Serialize>(path: &Path, value: &T) -> Result<(), &'static str> {
    if path.exists() {
        return Err("private journal already exists");
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|_| "could not create private journal directory")?;
    let temporary = parent.join(format!(
        ".keyferry-journal-{}.tmp",
        hex(&random_array::<8>()?)
    ));
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|_| "could not encode private JSON")?;
    bytes.push(b'\n');
    write_new_owner_only(&temporary, &bytes)?;
    if rename_private_durable(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err("could not atomically publish private journal");
    }
    Ok(())
}

fn remove_private_durable(path: &Path) -> Result<(), &'static str> {
    #[cfg(unix)]
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::remove_file(path).map_err(|_| "could not remove completed private journal")?;
    #[cfg(unix)]
    sync_private_directory(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_private_directory(path: &Path) -> Result<(), &'static str> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "could not durably synchronize private directory")
}

#[cfg(unix)]
fn rename_private_durable(source: &Path, destination: &Path) -> Result<(), &'static str> {
    fs::rename(source, destination).map_err(|_| "could not rename private journal")?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    sync_private_directory(parent)
}

#[cfg(windows)]
fn rename_private_durable(source: &Path, destination: &Path) -> Result<(), &'static str> {
    durable_windows::rename_write_through(source, destination)
        .map_err(|_| "could not durably rename private journal")
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod durable_windows {
    use std::{ffi::OsStr, io, os::windows::ffi::OsStrExt, path::Path};
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MOVE_FILE_FLAGS,
    };

    pub(super) fn rename_write_through(source: &Path, destination: &Path) -> io::Result<()> {
        let source = wide(source.as_os_str());
        let destination = wide(destination.as_os_str());
        // SAFETY: both buffers are owned, NUL-terminated UTF-16 paths and remain
        // alive for the duration of the synchronous Win32 call. The destination
        // does not exist, so replacement semantics are intentionally unnecessary.
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_WRITE_THROUGH as MOVE_FILE_FLAGS,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn replace_write_through(source: &Path, destination: &Path) -> io::Result<()> {
        let source = wide(source.as_os_str());
        let destination = wide(destination.as_os_str());
        // SAFETY: both buffers are owned, NUL-terminated UTF-16 paths and remain
        // alive for the duration of the synchronous Win32 call.
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                (MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) as MOVE_FILE_FLAGS,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }
}

fn write_json_replace_private<T: Serialize>(path: &Path, value: &T) -> Result<(), &'static str> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|_| "could not encode private JSON")?;
    bytes.push(b'\n');
    write_replace_private(path, &bytes)
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "could not create private pairing file")?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "could not persist private pairing file")
}

fn write_new_owner_only(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err("gateway credential output directory is absent");
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "could not create gateway credential without overwriting a file")?;
    #[cfg(windows)]
    if restrict_windows_file_acl(path).is_err() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err("could not restrict gateway credential to the current Windows user");
    }
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "could not persist gateway credential");
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

fn write_replace_private(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    if fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    let temporary = path.with_extension("tmp");
    let backup = path.with_extension("bak");
    if temporary.exists() || backup.exists() {
        return Err("private replacement recovery file already exists; inspect it before retrying");
    }
    write_new_private(&temporary, bytes)?;
    if path.exists() {
        fs::rename(path, &backup).map_err(|_| "could not preserve the previous private file")?;
    }
    if fs::rename(&temporary, path).is_err() {
        if backup.exists() {
            let _ = fs::rename(&backup, path);
        }
        return Err("could not publish private generated file");
    }
    if backup.exists() {
        fs::remove_file(backup).map_err(|_| "could not remove replaced private-file backup")?;
    }
    Ok(())
}

fn replace_private_durable(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(
        ".keyferry-owner-kit-{}.tmp",
        hex(&random_array::<8>()?)
    ));
    write_new_owner_only(&temporary, bytes).and_then(|()| {
        if replace_private_file_durable(&temporary, path).is_err() {
            let _ = fs::remove_file(&temporary);
            return Err("could not atomically replace the encrypted owner kit");
        }
        Ok(())
    })
}

#[cfg(unix)]
fn replace_private_file_durable(source: &Path, destination: &Path) -> Result<(), &'static str> {
    fs::rename(source, destination).map_err(|_| "could not replace private file")?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    sync_private_directory(parent)
}

#[cfg(windows)]
fn replace_private_file_durable(source: &Path, destination: &Path) -> Result<(), &'static str> {
    durable_windows::replace_write_through(source, destination)
        .map_err(|_| "could not durably replace private file")
}

fn create_private_dir(path: &Path) -> Result<(), &'static str> {
    fs::create_dir_all(path).map_err(|_| "could not create private pairing directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "could not restrict private pairing directory")?;
    }
    #[cfg(windows)]
    restrict_windows_acl(path)?;
    Ok(())
}

#[cfg(windows)]
fn restrict_windows_acl(path: &Path) -> Result<(), &'static str> {
    let sid = current_windows_sid()?;
    let grant = format!("*{sid}:(OI)(CI)F");
    let status = Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant, "/q"])
        .output()
        .map_err(|_| "could not restrict the private Windows directory")?;
    if !status.status.success() {
        return Err("could not restrict the private Windows directory");
    }
    Ok(())
}

#[cfg(windows)]
fn restrict_windows_file_acl(path: &Path) -> Result<(), &'static str> {
    let sid = current_windows_sid()?;
    let grant = format!("*{sid}:F");
    let status = Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant, "/q"])
        .output()
        .map_err(|_| "could not restrict the private Windows file")?;
    if !status.status.success() {
        return Err("could not restrict the private Windows file");
    }
    Ok(())
}

#[cfg(windows)]
fn current_windows_sid() -> Result<String, &'static str> {
    let identity = Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .map_err(|_| "could not query the current Windows identity")?;
    if !identity.status.success() {
        return Err("could not query the current Windows identity");
    }
    let identity =
        String::from_utf8(identity.stdout).map_err(|_| "current Windows identity was not UTF-8")?;
    let sid = identity
        .split(&['"', ','][..])
        .map(str::trim)
        .find(|field| field.starts_with("S-1-"))
        .ok_or("current Windows SID was not reported")?;
    Ok(sid.to_owned())
}

fn random_array<const N: usize>() -> Result<[u8; N], &'static str> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| "secure random generation failed")?;
    Ok(bytes)
}

fn uuid_v4(mut bytes: [u8; 16]) -> [u8; 16] {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    let raw = hex(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &raw[..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..]
    )
}

fn parse_uuid(value: &str) -> Result<[u8; 16], &'static str> {
    if value.len() != 36
        || value.as_bytes().get(8) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b'-')
        || value.as_bytes().get(18) != Some(&b'-')
        || value.as_bytes().get(23) != Some(&b'-')
    {
        return Err("device identifier is invalid");
    }
    let compact = value.replace('-', "");
    let bytes = parse_hex::<16>(&compact, "device identifier is invalid")?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err("device identifier is invalid");
    }
    Ok(bytes)
}

fn parse_hex<const N: usize>(value: &str, error: &'static str) -> Result<[u8; N], &'static str> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(error);
    }
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| error)?;
    }
    Ok(output)
}

fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let suffix = hex(&random_array::<8>().expect("random test suffix"));
            let path = env::temp_dir().join(format!("keyferry-pairing-{suffix}"));
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn private_header_authority_parser_is_exact_and_bounded() {
        let device = (0_u8..16)
            .map(|value| format!("0x{value:02x}"))
            .collect::<Vec<_>>()
            .join(", ");
        let recovery = (32_u8..64)
            .map(|value| format!("0x{value:02x}"))
            .collect::<Vec<_>>()
            .join(", ");
        let header = format!(
            "inline constexpr std::array<std::uint8_t, 16> kDeviceId{{{device}}};\n\
             inline constexpr std::array<std::uint8_t, 32> kProvisioningKey{{{recovery}}};\n"
        );
        assert_eq!(
            parse_private_header_array::<16>(&header, "kDeviceId").unwrap(),
            core::array::from_fn(|index| index as u8)
        );
        assert_eq!(
            parse_private_header_array::<32>(&header, "kProvisioningKey").unwrap(),
            core::array::from_fn(|index| (index + 32) as u8)
        );
        assert!(parse_private_header_array::<32>(&header, "kDeviceId").is_err());
        assert!(
            parse_private_header_array::<16>(&format!("{header}{header}"), "kDeviceId").is_err()
        );

        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test root");
        let zero_header = root.0.join("zero-authority.h");
        fs::write(
            &zero_header,
            format!(
                "inline constexpr std::array<std::uint8_t, 16> kDeviceId{{{}}};\n\
                 inline constexpr std::array<std::uint8_t, 32> kProvisioningKey{{{}}};\n",
                vec!["0x00"; 16].join(", "),
                vec!["0x00"; 32].join(", ")
            ),
        )
        .expect("zero authority header");
        assert_eq!(
            load_private_header_authority(&zero_header)
                .err()
                .expect("zero authority must reject"),
            "private firmware header authority is invalid"
        );
    }

    fn complete_bundle(path: &Path) {
        create_bundle(path, "192.0.2.20".parse().unwrap(), 7443).expect("create bundle");
        set_wifi(
            path,
            &mut Cursor::new(
                b"{\"schema_version\":1,\"ssid\":\"private-ssid-sentinel\",\"password\":\"private-password-sentinel\"}",
            ),
            false,
        )
        .expect("set Wi-Fi");
        validate_bundle(path).expect("valid complete bundle");
    }

    #[test]
    fn opaque_random_device_identifier_round_trips_without_uuid_bit_requirements() {
        let text = "89abcdef-0123-4567-89ab-cdef01234567";
        let parsed = parse_uuid(text).expect("opaque random device identifier");
        assert_eq!(format_uuid(&parsed), text);
        assert_eq!(
            parse_uuid("00000000-0000-0000-0000-000000000000"),
            Err("device identifier is invalid")
        );
    }

    #[cfg(unix)]
    #[test]
    fn bundle_creation_leaves_an_existing_parent_permission_unchanged() {
        use std::os::unix::fs::PermissionsExt;

        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test parent");
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755))
            .expect("test parent permissions");
        let bundle = root.0.join("bundle");

        create_bundle(&bundle, "192.0.2.21".parse().unwrap(), 7443).expect("create bundle");

        assert_eq!(
            fs::metadata(&root.0).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(bundle).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    fn export_args(bundle: &Path, token: &Path, output: &Path) -> Vec<String> {
        vec![
            "export-gateway-credential".to_owned(),
            "--bundle".to_owned(),
            bundle.to_string_lossy().into_owned(),
            "--port".to_owned(),
            "18043".to_owned(),
            "--remote-token-file".to_owned(),
            token.to_string_lossy().into_owned(),
            "--output".to_owned(),
            output.to_string_lossy().into_owned(),
        ]
    }

    #[test]
    fn leading_bundle_option_selects_the_private_bundle_without_touching_commands() {
        let default = Path::new("default");
        let args = vec![
            "--bundle".to_owned(),
            "selected".to_owned(),
            "status".to_owned(),
        ];
        let (bundle, command) = resolve_bundle(&args, default).expect("bundle option");
        assert_eq!(bundle, Path::new("selected"));
        assert_eq!(command, &["status"]);
        let default_args = ["validate".to_owned()];
        let (bundle, command) = resolve_bundle(&default_args, default).expect("default bundle");
        assert_eq!(bundle, default);
        assert_eq!(command, &["validate"]);
    }

    #[test]
    fn wifi_replace_is_explicit_and_preserves_secret_free_status() {
        let root = TestRoot::new();
        create_bundle(&root.0, "192.0.2.30".parse().unwrap(), 7443).expect("create bundle");
        set_wifi(
            &root.0,
            &mut Cursor::new(
                b"{\"schema_version\":1,\"ssid\":\"old-sentinel\",\"password\":\"old-password\"}",
            ),
            false,
        )
        .expect("initial Wi-Fi");
        let replacement =
            b"{\"schema_version\":1,\"ssid\":\"new-sentinel\",\"password\":\"new-password\"}";
        let mut output = Vec::new();
        run(
            &["set-wifi".to_owned(), "--replace".to_owned()],
            &root.0,
            &mut Cursor::new(replacement),
            &mut output,
        )
        .expect("replace Wi-Fi");
        let wifi: WifiConfig = read_json_private(&root.0.join(WIFI_CONFIG)).expect("Wi-Fi file");
        assert_eq!(wifi.ssid, "new-sentinel");
        assert_eq!(wifi.password, "new-password");
        let visible = String::from_utf8(output).expect("status UTF-8");
        assert!(!visible.contains("new-sentinel"));
        assert!(!visible.contains("new-password"));
    }

    #[test]
    fn roaming_policy_save_is_strict_private_and_payload_free() {
        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test root");
        let policy_path = root.0.join("roaming-policy.json");
        let policy = br#"{
            "schema_version": 1,
            "wifi_profiles": [
                {"ssid":"travel-sentinel","password":"private-password-sentinel","priority":9}
            ],
            "revoked_installation_ids": ["41414141414141414141414141414141"]
        }"#;
        let args = [
            "save-roaming-policy".to_owned(),
            "--output".to_owned(),
            policy_path.to_string_lossy().into_owned(),
        ];
        let mut output = Vec::new();
        run(&args, &root.0, &mut Cursor::new(policy), &mut output).expect("save policy");
        let stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&policy_path).expect("stored policy"))
                .expect("strict JSON");
        assert_eq!(stored["wifi_profiles"][0]["priority"], 9);
        let visible = String::from_utf8(output).expect("status UTF-8");
        assert_eq!(visible, "roaming policy stored\n");
        assert!(!visible.contains("travel-sentinel"));
        assert!(!visible.contains("private-password-sentinel"));

        let replacement = String::from_utf8(policy.to_vec())
            .unwrap()
            .replace("travel-sentinel", "second--sentinel")
            .into_bytes();
        let replace_args = [
            "save-roaming-policy".to_owned(),
            "--output".to_owned(),
            policy_path.to_string_lossy().into_owned(),
            "--replace".to_owned(),
        ];
        run(
            &replace_args,
            &root.0,
            &mut Cursor::new(replacement),
            &mut Vec::new(),
        )
        .expect("replace policy");
        assert!(String::from_utf8(fs::read(&policy_path).unwrap())
            .unwrap()
            .contains("second--sentinel"));

        let invalid = br#"{"schema_version":1,"wifi_profiles":[],"revoked_installation_ids":[],"extra":true}"#;
        assert_eq!(
            run(
                &replace_args,
                &root.0,
                &mut Cursor::new(invalid),
                &mut Vec::new(),
            ),
            Err("roaming policy input is invalid")
        );
    }

    #[test]
    fn creates_matching_private_state_without_secret_output() {
        let root = TestRoot::new();
        let mut output = Vec::new();
        let create_args = [
            "create".to_owned(),
            "--host-address".to_owned(),
            "192.0.2.10".to_owned(),
            "--host-port".to_owned(),
            "7443".to_owned(),
        ];
        run(&create_args, &root.0, &mut Cursor::new([]), &mut output).expect("create bundle");
        assert!(
            validate_bundle(&root.0).is_err(),
            "Wi-Fi must be present before HIL use"
        );

        let device: DeviceConfig =
            read_json_private(&root.0.join(DEVICE_CONFIG)).expect("device config");
        let recovery_secret = fs::read(root.0.join(RECOVERY_SECRET)).expect("recovery secret");
        assert!(!String::from_utf8_lossy(&output).contains(&device.link_secret_hex));
        assert!(!String::from_utf8_lossy(&output).contains(&hex(&recovery_secret)));
        assert!(!String::from_utf8_lossy(&output).contains(&device.device_id));

        let ssid = "test-ssid-sentinel";
        let password = "test-password-sentinel";
        let wifi =
            format!("{{\"schema_version\":1,\"ssid\":\"{ssid}\",\"password\":\"{password}\"}}");
        run(
            &["set-wifi".to_owned()],
            &root.0,
            &mut Cursor::new(wifi),
            &mut output,
        )
        .expect("set Wi-Fi");
        run(
            &["validate".to_owned()],
            &root.0,
            &mut Cursor::new([]),
            &mut output,
        )
        .expect("validate bundle");
        let visible = String::from_utf8(output).expect("status is UTF-8");
        assert!(!visible.contains(ssid));
        assert!(!visible.contains(password));
        assert!(!visible.contains(&device.link_secret_hex));
        assert!(!visible.contains(&device.device_id));
    }

    #[test]
    fn rejects_absent_bundle_and_mismatched_secret() {
        let root = TestRoot::new();
        assert_eq!(
            validate_bundle(&root.0),
            Err("private pairing bundle is absent")
        );
        create_bundle(&root.0, "192.0.2.11".parse().unwrap(), 7443).expect("create bundle");
        let wifi = b"{\"schema_version\":1,\"ssid\":\"test\",\"password\":\"password\"}";
        set_wifi(&root.0, &mut Cursor::new(wifi), false).expect("set Wi-Fi");
        let device: DeviceConfig =
            read_json_private(&root.0.join(DEVICE_CONFIG)).expect("device config");
        let device_id = parse_uuid(&device.device_id).expect("device ID");
        fs::write(
            root.0
                .join(DAEMON_SECRETS)
                .join("pairings")
                .join(format!("{}.link", hex(&device_id))),
            [0_u8; 32],
        )
        .expect("tamper test secret");
        assert_eq!(
            validate_bundle(&root.0),
            Err("firmware and keyferryd link secrets do not match")
        );
    }

    #[test]
    fn rejects_secret_bearing_arguments_and_unbounded_wifi() {
        let root = TestRoot::new();
        let mut output = Vec::new();
        assert!(run(
            &["set-wifi".to_owned(), "secret".to_owned()],
            &root.0,
            &mut Cursor::new([]),
            &mut output
        )
        .is_err());
        create_bundle(&root.0, "192.0.2.12".parse().unwrap(), 7443).expect("create bundle");
        assert_eq!(
            set_wifi(&root.0, &mut Cursor::new(vec![b'x'; 1025]), false),
            Err("Wi-Fi input exceeds the bounded size")
        );
    }

    #[test]
    fn rejects_shared_authority_keys_and_unprovisionable_certificates() {
        let root = TestRoot::new();
        create_bundle(&root.0, "192.0.2.15".parse().unwrap(), 7443).expect("create bundle");
        set_wifi(
            &root.0,
            &mut Cursor::new(b"{\"schema_version\":1,\"ssid\":\"test\",\"password\":\"password\"}"),
            false,
        )
        .expect("set Wi-Fi");
        let device: DeviceConfig =
            read_json_private(&root.0.join(DEVICE_CONFIG)).expect("device config");
        let link_secret =
            parse_hex::<32>(&device.link_secret_hex, "link secret is invalid").unwrap();
        fs::write(root.0.join(RECOVERY_SECRET), link_secret).expect("share test secrets");
        assert_eq!(
            validate_bundle(&root.0),
            Err("administrative recovery secret must differ from the link secret")
        );

        let mut distinct_recovery = link_secret;
        distinct_recovery[0] ^= 1;
        fs::write(root.0.join(RECOVERY_SECRET), distinct_recovery)
            .expect("restore distinct recovery secret");
        fs::write(
            root.0.join(FIRMWARE_CERT),
            vec![0x30_u8; MAX_CERTIFICATE_BYTES as usize + 1],
        )
        .expect("oversize test certificate");
        assert_eq!(
            validate_bundle(&root.0),
            Err("private pairing file exceeds its bounded size")
        );
    }

    #[test]
    fn firmware_materialization_is_deterministic_and_fails_on_mismatch() {
        let root = TestRoot::new();
        let bundle = root.0.join("bundle");
        let output = root.0.join("generated");
        create_bundle(&bundle, "192.0.2.13".parse().unwrap(), 7443).expect("create bundle");
        set_wifi(
            &bundle,
            &mut Cursor::new(
                b"{\"schema_version\":1,\"ssid\":\"sentinel-ssid\",\"password\":\"sentinel-password\"}",
            ),
            false,
        )
        .expect("set Wi-Fi");

        materialize_firmware(&bundle, &output).expect("first materialization");
        let first = fs::read(output.join(GENERATED_HEADER)).expect("generated header");
        materialize_firmware(&bundle, &output).expect("second materialization");
        let second = fs::read(output.join(GENERATED_HEADER)).expect("generated header");
        assert_eq!(first, second);
        assert!(first.windows(11).any(|part| part == b"kLinkSecret"));
        assert!(first.windows(16).any(|part| part == b"kProvisioningKey"));
        assert!(first.windows(9).any(|part| part == b"kWifiSsid"));

        let device: DeviceConfig = read_json_private(&bundle.join(DEVICE_CONFIG)).unwrap();
        let device_id = parse_uuid(&device.device_id).unwrap();
        fs::write(
            bundle
                .join(DAEMON_SECRETS)
                .join("pairings")
                .join(format!("{}.link", hex(&device_id))),
            [0_u8; 32],
        )
        .expect("tamper secret");
        assert_eq!(
            materialize_firmware(&bundle, &output),
            Err("firmware and keyferryd link secrets do not match")
        );
    }

    #[test]
    fn upgrades_a_legacy_bundle_once_without_exposing_the_secret() {
        let root = TestRoot::new();
        create_bundle(&root.0, "192.0.2.14".parse().unwrap(), 7443).expect("create bundle");
        fs::remove_file(root.0.join(RECOVERY_SECRET)).expect("remove generated secret");
        let mut output = Vec::new();
        run(
            &["initialize-recovery".to_owned()],
            &root.0,
            &mut Cursor::new([]),
            &mut output,
        )
        .expect("initialize recovery");
        let secret = fs::read(root.0.join(RECOVERY_SECRET)).expect("recovery secret");
        assert_eq!(secret.len(), 32);
        assert!(secret.iter().any(|byte| *byte != 0));
        assert!(!String::from_utf8_lossy(&output).contains(&hex(&secret)));
        assert_eq!(
            initialize_recovery(&root.0),
            Err("administrative recovery secret already exists; refusing to overwrite it")
        );
    }

    #[test]
    fn owner_kit_issues_one_private_installation_without_exposing_authority() {
        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test root");
        let bundle = root.0.join("bundle");
        complete_bundle(&bundle);
        let kit_path = root.0.join("owner-kit.json");
        let passphrase = "owner passphrase sentinel value";
        let mut output = Vec::new();
        run(
            &[
                "create-owner-kit".to_owned(),
                "--output".to_owned(),
                kit_path.to_string_lossy().into_owned(),
            ],
            &bundle,
            &mut Cursor::new(format!("{passphrase}\n{passphrase}\n")),
            &mut output,
        )
        .expect("create encrypted owner kit");
        let kit = fs::read(&kit_path).expect("owner kit");
        let recovery = fs::read(bundle.join(RECOVERY_SECRET)).expect("recovery secret");
        assert!(!String::from_utf8_lossy(&kit).contains(passphrase));
        assert!(!String::from_utf8_lossy(&kit).contains(&hex(&recovery)));

        let installation = root.0.join("installation");
        run(
            &[
                "issue-installation".to_owned(),
                "--owner-kit".to_owned(),
                kit_path.to_string_lossy().into_owned(),
                "--output".to_owned(),
                installation.to_string_lossy().into_owned(),
            ],
            &bundle,
            &mut Cursor::new(format!("{passphrase}\n")),
            &mut output,
        )
        .expect("issue installation");
        let manifest: owner_kit::InstallationManifest =
            read_json_private(&installation.join("installation.json"))
                .expect("installation manifest");
        let runtime_credentials = keyferry_gateway::InstallationCredentials::load(&installation)
            .expect("runtime consumes the issued installation");
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(
            hex(&runtime_credentials.installation_id()),
            manifest.installation_id_hex
        );
        assert_eq!(
            fs::read(installation.join("owner-id.bin")).unwrap().len(),
            16
        );
        assert_eq!(
            fs::read(installation.join("device-id.bin")).unwrap().len(),
            16
        );
        assert_eq!(
            fs::read(installation.join("installation-id.bin"))
                .unwrap()
                .len(),
            16
        );
        assert_eq!(
            fs::read(installation.join("installation-spki.der"))
                .unwrap()
                .len(),
            91
        );
        assert_eq!(
            fs::read(installation.join("device-link-secret.bin"))
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            fs::read(installation.join("route-proof-secret.bin"))
                .unwrap()
                .len(),
            32
        );
        run(
            &[
                "validate-installation".to_owned(),
                "--input".to_owned(),
                installation.to_string_lossy().into_owned(),
            ],
            &bundle,
            &mut Cursor::new([]),
            &mut output,
        )
        .expect("validate issued installation");
        let visible = String::from_utf8(output).expect("status UTF-8");
        assert!(visible.contains("installation credentials valid"));
        assert!(!visible.contains(passphrase));
        assert!(!visible.contains(&hex(&recovery)));
        assert!(!visible.contains(&manifest.installation_id_hex));
    }

    #[test]
    fn multi_device_grant_expands_existing_installation_without_changing_computer_identity() {
        let root = TestRoot::new();
        fs::create_dir_all(&root.0).unwrap();
        let bundle = root.0.join("bundle");
        complete_bundle(&bundle);
        let kit_path = root.0.join("owner-kit.json");
        let passphrase = "two device test passphrase";
        create_owner_kit(
            &bundle,
            &kit_path,
            &mut Cursor::new(format!("{passphrase}\n{passphrase}\n")),
        )
        .unwrap();
        let singleton = root.0.join("singleton");
        issue_installation(
            &kit_path,
            &singleton,
            &mut Cursor::new(format!("{passphrase}\n")),
        )
        .unwrap();
        let before = keyferry_gateway::InstallationCredentials::load(&singleton).unwrap();

        let new_device_id =
            add_owner_device(&kit_path, &mut Cursor::new(format!("{passphrase}\n"))).unwrap();
        let mut listed = Vec::new();
        list_owner_devices(
            &kit_path,
            &mut Cursor::new(format!("{passphrase}\n")),
            &mut listed,
        )
        .unwrap();
        let listed: serde_json::Value = serde_json::from_slice(&listed).unwrap();
        assert_eq!(listed["schema"], "keyferry.owner-devices.v1");
        assert_eq!(listed["device_ids"].as_array().unwrap().len(), 2);
        assert!(listed["device_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == &format_uuid(&new_device_id)));
        let expanded = root.0.join("expanded");
        grant_device_to_installation(
            &kit_path,
            new_device_id,
            &singleton,
            &expanded,
            &mut Cursor::new(format!("{passphrase}\n")),
        )
        .unwrap();

        let set = keyferry_gateway::InstallationCredentialSet::load(&expanded).unwrap();
        validate_installation_upgrade(&singleton, &expanded).unwrap();
        assert_eq!(
            validate_installation_upgrade(&expanded, &singleton),
            Err("candidate installation removes a device grant")
        );
        assert_eq!(set.len(), 2);
        let old = set.get(before.device_id()).unwrap();
        let new = set.get(new_device_id).unwrap();
        assert_eq!(old.owner_id(), before.owner_id());
        assert_eq!(old.installation_id(), before.installation_id());
        assert_eq!(old.installation_spki_der(), before.installation_spki_der());
        assert_eq!(old.installation_key_der(), before.installation_key_der());
        assert_eq!(old.owner_ca_der(), before.owner_ca_der());
        assert_eq!(
            old.device_server_certificate_der(),
            before.device_server_certificate_der()
        );
        assert_eq!(old.device_link_secret(), before.device_link_secret());
        assert_eq!(old.route_proof_secret(), before.route_proof_secret());
        assert_eq!(new.owner_id(), before.owner_id());
        assert_eq!(new.installation_id(), before.installation_id());
        assert_eq!(new.installation_spki_der(), before.installation_spki_der());
        assert_ne!(new.device_link_secret(), before.device_link_secret());
        assert_ne!(new.route_proof_secret(), before.route_proof_secret());
        assert!(!expanded.join("device-id.bin").exists());
        assert!(!expanded.join("device-link-secret.bin").exists());

        let bootstrap = root.0.join("new-device-bootstrap");
        let mut receipt = Vec::new();
        materialize_device_bootstrap(
            &kit_path,
            new_device_id,
            &expanded,
            &bundle,
            &bootstrap,
            &mut Cursor::new(format!("{passphrase}\n")),
            &mut receipt,
        )
        .unwrap();
        let header = fs::read_to_string(bootstrap.join(GENERATED_HEADER)).unwrap();
        assert!(header.contains("kDeviceId"));
        assert!(header.contains("kProvisioningKey"));
        assert!(header.contains(new.device_server_name()));
        assert!(!header.contains("keyferry.local\""));
        let receipt = String::from_utf8(receipt).unwrap();
        assert!(receipt.contains("keyferry.device-bootstrap-materialized.v1"));
        assert!(receipt.contains(&format_uuid(&new_device_id)));
        assert!(!receipt.contains(passphrase));
        let authority = owner_kit::unlock_device_authority_for_device(
            &fs::read(&kit_path).unwrap(),
            passphrase.as_bytes(),
            new_device_id,
        )
        .unwrap();
        assert!(!receipt.contains(&hex(&authority.device_recovery_secret)));
    }

    #[test]
    fn owner_kit_confirmation_and_authentication_fail_without_partial_output() {
        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test root");
        let bundle = root.0.join("bundle");
        complete_bundle(&bundle);
        let kit_path = root.0.join("owner-kit.json");
        assert_eq!(
            create_owner_kit(
                &bundle,
                &kit_path,
                &mut Cursor::new(b"first long passphrase\nsecond long passphrase\n"),
            ),
            Err("owner-kit passphrase confirmation does not match")
        );
        assert!(!kit_path.exists());

        create_owner_kit(
            &bundle,
            &kit_path,
            &mut Cursor::new(b"correct long passphrase\ncorrect long passphrase\n"),
        )
        .expect("owner kit");
        let installation = root.0.join("installation");
        assert_eq!(
            issue_installation(
                &kit_path,
                &installation,
                &mut Cursor::new(b"wrong long passphrase\n"),
            ),
            Err("owner-kit authentication or issuance failed")
        );
        assert!(!installation.exists());
    }

    #[test]
    fn owner_kit_passphrase_change_is_atomic_and_preserves_authority() {
        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test root");
        let bundle = root.0.join("bundle");
        complete_bundle(&bundle);
        let kit_path = root.0.join("owner-kit.json");
        create_owner_kit(&bundle, &kit_path, &mut Cursor::new(b"old\nold\n")).expect("owner kit");
        let original = fs::read(&kit_path).expect("original owner kit");
        let first = root.0.join("first-installation");
        issue_installation(&kit_path, &first, &mut Cursor::new(b"old\n"))
            .expect("original installation");
        let first_manifest: owner_kit::InstallationManifest =
            read_json_private(&first.join("installation.json")).expect("first manifest");

        let mut output = Vec::new();
        run(
            &[
                "change-owner-kit-passphrase".to_owned(),
                "--owner-kit".to_owned(),
                kit_path.to_string_lossy().into_owned(),
            ],
            &bundle,
            &mut Cursor::new(b"old\nnew\nnew\n"),
            &mut output,
        )
        .expect("passphrase change");
        assert_eq!(output, b"owner-kit passphrase changed\n");
        assert!(!String::from_utf8_lossy(&output).contains("old"));
        assert!(!String::from_utf8_lossy(&output).contains("new"));
        assert_ne!(fs::read(&kit_path).expect("changed owner kit"), original);
        assert_eq!(
            issue_installation(
                &kit_path,
                &root.0.join("old-password-installation"),
                &mut Cursor::new(b"old\n"),
            ),
            Err("owner-kit authentication or issuance failed")
        );
        let second = root.0.join("second-installation");
        issue_installation(&kit_path, &second, &mut Cursor::new(b"new\n"))
            .expect("new password installation");
        let second_manifest: owner_kit::InstallationManifest =
            read_json_private(&second.join("installation.json")).expect("second manifest");
        assert_eq!(second_manifest.owner_id_hex, first_manifest.owner_id_hex);
        assert_eq!(second_manifest.device_id_hex, first_manifest.device_id_hex);
        assert_eq!(second_manifest.owner_ca_der, first_manifest.owner_ca_der);
        assert_eq!(
            second_manifest.authority_epoch,
            first_manifest.authority_epoch
        );
        assert_ne!(
            second_manifest.installation_id_hex,
            first_manifest.installation_id_hex
        );
        assert!(!kit_path.with_extension("rekey.lock").exists());
        assert!(fs::read_dir(&root.0)
            .expect("test root entries")
            .all(|entry| !entry
                .expect("test entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".keyferry-owner-kit-")));
    }

    #[test]
    fn owner_kit_passphrase_change_failures_preserve_the_file() {
        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test root");
        let bundle = root.0.join("bundle");
        complete_bundle(&bundle);
        let kit_path = root.0.join("owner-kit.json");
        create_owner_kit(&bundle, &kit_path, &mut Cursor::new(b"old\nold\n")).expect("owner kit");
        let original = fs::read(&kit_path).expect("original owner kit");

        assert_eq!(
            change_owner_kit_passphrase(&kit_path, &mut Cursor::new(b"wrong\nnew\nnew\n"),),
            Err("owner-kit authentication or passphrase change failed")
        );
        assert_eq!(fs::read(&kit_path).unwrap(), original);
        assert!(!kit_path.with_extension("rekey.lock").exists());
        assert_eq!(
            change_owner_kit_passphrase(&kit_path, &mut Cursor::new(b"old\nnew\ndifferent\n"),),
            Err("new owner-kit passphrase confirmation does not match")
        );
        assert_eq!(fs::read(&kit_path).unwrap(), original);

        write_new_owner_only(&kit_path.with_extension("rekey.lock"), b"locked\n")
            .expect("preexisting lock");
        assert_eq!(
            change_owner_kit_passphrase(&kit_path, &mut Cursor::new(b"old\nnew\nnew\n")),
            Err("another owner-kit passphrase change is active or needs recovery")
        );
        assert_eq!(fs::read(&kit_path).unwrap(), original);
    }

    #[test]
    fn exports_only_the_minimal_gateway_credential_without_secret_output() {
        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test root");
        let bundle = root.0.join("bundle");
        complete_bundle(&bundle);
        let remote_token = "ab".repeat(32);
        let token_path = root.0.join("remote-token");
        fs::write(&token_path, format!("{remote_token}\n")).expect("remote token fixture");
        let output_path = root.0.join("gateway.json");
        let mut status = Vec::new();

        run(
            &export_args(&bundle, &token_path, &output_path),
            &root.0.join("unused-default-bundle"),
            &mut Cursor::new([]),
            &mut status,
        )
        .expect("export gateway credential");

        assert_eq!(status, b"gateway credential created\n");
        assert!(!String::from_utf8_lossy(&status).contains(&remote_token));
        let bytes = fs::read(&output_path).expect("gateway credential");
        let wire: GatewayCredential = serde_json::from_slice(&bytes).expect("credential JSON");
        assert_eq!(wire.schema_version, 2);
        assert_eq!(wire.port, 18043);
        assert_eq!(wire.remote_bearer, remote_token);
        assert_eq!(
            wire.gateway_spki_der,
            hex(&fs::read(bundle.join(FIRMWARE_SPKI)).expect("public SPKI"))
        );

        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let object = value.as_object().expect("credential object");
        assert_eq!(object.len(), 4);
        for key in [
            "schema_version",
            "port",
            "gateway_spki_der",
            "remote_bearer",
        ] {
            assert!(object.contains_key(key), "missing {key}");
        }
        let device: DeviceConfig = read_json_private(&bundle.join(DEVICE_CONFIG)).unwrap();
        let recovery = hex(&fs::read(bundle.join(RECOVERY_SECRET)).unwrap());
        let host_key = hex(&fs::read(bundle.join(DAEMON_SECRETS).join("host-key.der")).unwrap());
        let visible = String::from_utf8(bytes).unwrap();
        for private in [
            device.link_secret_hex.as_str(),
            recovery.as_str(),
            host_key.as_str(),
            "private-ssid-sentinel",
            "private-password-sentinel",
        ] {
            assert!(!visible.contains(private));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(output_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn gateway_credential_export_is_create_new_and_preserves_existing_output() {
        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test root");
        let bundle = root.0.join("bundle");
        complete_bundle(&bundle);
        let token_path = root.0.join("remote-token");
        fs::write(&token_path, format!("{}\r\n", "cd".repeat(32))).expect("remote token");
        let output_path = root.0.join("gateway.json");
        fs::write(&output_path, b"owner data").expect("existing output");
        let options =
            parse_export_gateway_args(&export_args(&bundle, &token_path, &output_path)[1..])
                .expect("export options");

        assert_eq!(
            export_gateway_credential(&options),
            Err("could not create gateway credential without overwriting a file")
        );
        assert_eq!(fs::read(output_path).unwrap(), b"owner data");
    }

    #[test]
    fn gateway_credential_export_rejects_bad_arguments_and_tokens_before_output() {
        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test root");
        let bundle = root.0.join("bundle");
        complete_bundle(&bundle);
        let token_path = root.0.join("remote-token");
        let output_path = root.0.join("gateway.json");

        for invalid in [
            "ab".repeat(31),
            "AB".repeat(32),
            format!("{} \n", "ab".repeat(32)),
            format!("{}\nextra", "ab".repeat(32)),
        ] {
            fs::write(&token_path, invalid).expect("invalid token fixture");
            let options =
                parse_export_gateway_args(&export_args(&bundle, &token_path, &output_path)[1..])
                    .expect("export options");
            assert_eq!(
                export_gateway_credential(&options),
                Err("remote bearer token file is absent or invalid")
            );
            assert!(!output_path.exists());
        }

        let mut unsupported = export_args(&bundle, &token_path, &output_path);
        unsupported[5] = "--remote-token".to_owned();
        assert_eq!(
            parse_export_gateway_args(&unsupported[1..]).err(),
            Some("export-gateway-credential received an unsupported option")
        );
        let mut bad_port = export_args(&bundle, &token_path, &output_path);
        bad_port[4] = "0".to_owned();
        assert_eq!(
            parse_export_gateway_args(&bad_port[1..]).err(),
            Some("gateway tailnet port must be an integer from 1 through 65535")
        );
        assert!(!output_path.exists());
    }

    #[test]
    fn installs_a_canonical_gateway_credential_without_overwrite() {
        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test root");
        let bundle = root.0.join("bundle");
        complete_bundle(&bundle);
        let token_path = root.0.join("remote-token");
        fs::write(&token_path, format!("{}\n", "ef".repeat(32))).expect("remote token");
        let transfer = root.0.join("transfer.json");
        let options = parse_export_gateway_args(&export_args(&bundle, &token_path, &transfer)[1..])
            .expect("export options");
        export_gateway_credential(&options).expect("export credential");
        let installed = root.0.join("installed").join("gateway.json");

        install_gateway_credential(&transfer, &installed).expect("install credential");
        let wire: GatewayCredential =
            serde_json::from_slice(&fs::read(&installed).unwrap()).unwrap();
        assert_eq!(wire.port, 18043);
        assert_eq!(wire.remote_bearer, "ef".repeat(32));
        assert_eq!(
            install_gateway_credential(&transfer, &installed),
            Err("could not create gateway credential without overwriting a file")
        );
    }

    #[test]
    fn gateway_credential_install_rejects_noncanonical_or_oversized_input() {
        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test root");
        let input = root.0.join("input.json");
        let output = root.0.join("gateway.json");
        for invalid in [
            br#"{"schema_version":1}"#.to_vec(),
            vec![b'x'; 4097],
            br#"{"schema_version":2,"port":18043,"gateway_spki_der":"00","remote_bearer":"abababababababababababababababababababababababababababababababab"}"#.to_vec(),
        ] {
            fs::write(&input, invalid).expect("invalid credential input");
            assert_eq!(
                install_gateway_credential(&input, &output),
                Err("gateway credential input is invalid")
            );
            assert!(!output.exists());
        }
    }

    #[test]
    fn validates_gateway_credential_without_creating_installed_state() {
        let root = TestRoot::new();
        fs::create_dir_all(&root.0).expect("test root");
        let bundle = root.0.join("bundle");
        complete_bundle(&bundle);
        let token_path = root.0.join("remote-token");
        fs::write(&token_path, format!("{}\n", "cd".repeat(32))).expect("remote token");
        let transfer = root.0.join("transfer.json");
        let options = parse_export_gateway_args(&export_args(&bundle, &token_path, &transfer)[1..])
            .expect("export options");
        export_gateway_credential(&options).expect("export credential");

        let before = fs::read(&transfer).expect("credential before validation");
        let canonical = canonical_gateway_credential(&transfer).expect("validate credential");
        assert_eq!(canonical, before);
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 3);
    }

    #[test]
    fn local_status_is_machine_readable_and_help_marks_it_daemon_independent() {
        let page = StatusPage::LastReceipt(Some(ReceiptStatus {
            state: 2,
            operation: 0x15,
            result: 0,
            flags: 0,
            argument: 0,
        }));
        assert_eq!(
            local_status_value(page).expect("status value"),
            serde_json::json!({
                "state": 2,
                "operation": 0x15,
                "result": 0,
                "flags": 0,
                "argument": 0,
            })
        );

        let root = TestRoot::new();
        let mut output = Vec::new();
        run(
            &["--help".to_owned()],
            &root.0,
            &mut io::empty(),
            &mut output,
        )
        .expect("help");
        let help = String::from_utf8(output).expect("UTF-8 help");
        assert!(help.contains("local-status --owner-kit PATH"));
        assert!(help.contains("daemon/network independent"));
        assert!(help.contains("local-recover --owner-kit PATH ACTION"));
        assert_eq!(
            parse_local_recovery_action("forget-bluetooth")
                .expect("recovery action")
                .operation,
            local_operation::CLEAR_BLE_BOND_AND_ENROLL
        );
        assert!(parse_local_recovery_action("type-text").is_err());
    }

    #[test]
    fn local_result_line_is_flushed_and_failed_flush_is_reported() {
        #[derive(Default)]
        struct BufferedWriter {
            pending: Vec<u8>,
            visible: Vec<u8>,
            flushes: usize,
            fail_flush: bool,
        }

        impl Write for BufferedWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.pending.extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                if self.fail_flush {
                    return Err(io::Error::other("flush failed"));
                }
                self.visible.append(&mut self.pending);
                Ok(())
            }
        }

        let mut output = BufferedWriter::default();
        let attempt = serde_json::json!({"schema": "keyferry.local-recovery-attempt.v1"});
        write_recovery_line(&mut output, &attempt).expect("attempt flushed before mutation");
        assert_eq!(output.flushes, 1);
        assert_eq!(
            output.visible,
            b"{\"schema\":\"keyferry.local-recovery-attempt.v1\"}\n"
        );
        assert!(output.pending.is_empty());

        write_local_terminal(
            &mut output,
            parse_local_recovery_action("restart-network").unwrap(),
            [7; 16],
            "REJECTED",
            2,
            None,
        )
        .expect("terminal result flushed before nonzero exit");
        assert_eq!(output.flushes, 2);
        assert!(String::from_utf8_lossy(&output.visible).contains("\"outcome\":\"REJECTED\""));

        output.fail_flush = true;
        assert_eq!(
            write_recovery_line(&mut output, &attempt),
            Err("could not write local result")
        );
        assert_eq!(output.flushes, 3);
    }

    #[test]
    fn local_probe_arguments_are_bounded_and_reject_unknown_or_duplicate_options() {
        let parse = |args: &[&str]| {
            parse_local_probe_args(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(parse(&["--owner-kit", "kit"]).unwrap().samples, 1);
        assert_eq!(
            parse(&["--owner-kit", "kit", "--samples", "86401"])
                .unwrap()
                .samples,
            86401
        );
        for args in [
            vec!["--owner-kit", ""],
            vec!["--owner-kit"],
            vec!["--owner-kit", "kit", "--samples", "0"],
            vec!["--owner-kit", "kit", "--samples", "86402"],
            vec!["--owner-kit", "kit", "--samples", "2", "--samples", "3"],
            vec!["--owner-kit", "kit", "--owner-kit", "other"],
            vec!["--owner-kit", "kit", "--device", "not-an-id"],
            vec!["--owner-kit", "kit", "--reboot", "1"],
        ] {
            assert!(parse(&args).is_err(), "accepted {args:?}");
        }
    }

    #[test]
    fn local_probe_output_is_exact_numeric_metadata() {
        use keyferry_protocol::local_management::{
            ProbeHeapStatus, ProbeRunStatus, ProbeStackStatus,
        };
        let snapshot = keyferry_local_management::ProbeSnapshot {
            run: ProbeRunStatus {
                sample_sequence: 17,
                phase: keyferry_protocol::local_management_probe_phase::RELEASED,
                uptime_seconds: 65,
                held_flags: 0,
                first_outcome: 1,
                second_outcome: 2,
                transport_running: true,
                link_path: 1,
                output_mode: 1,
            },
            heap: ProbeHeapStatus {
                sample_sequence: 17,
                free_bytes: 81_123,
                largest_bytes: 72_345,
                minimum_bytes: 33_009,
            },
            stack: ProbeStackStatus {
                sample_sequence: 17,
                main_bytes: 1023,
                transport_bytes: 2047,
                probe_bytes: 3071,
            },
        };
        assert_eq!(
            local_probe_value(2, &snapshot),
            serde_json::json!({
                "schema": "keyferry.local-probe.v1", "sample_index": 2,
                "sample_sequence": 17, "uptime_seconds": 65, "phase": keyferry_protocol::local_management_probe_phase::RELEASED,
                "held_flags": 0, "first_outcome": 1, "second_outcome": 2,
                "transport_running": true, "link_path": 1, "output_mode": 1,
                "free_bytes": 81_123, "largest_bytes": 72_345, "minimum_bytes": 33_009,
                "main_stack_free_bytes": 1023, "transport_stack_free_bytes": 2047,
                "probe_stack_free_bytes": 3071,
            })
        );
    }
}
