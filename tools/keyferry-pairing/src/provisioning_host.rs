use hmac::{Hmac, Mac};
use keyferry_gateway::{
    authenticated_roaming_policy_payload, derive_policy_auth_secret,
    verify_roaming_policy_auth_tag, RoamingPolicyFields, MAX_CA_CERTIFICATE_LEN,
    MAX_REVOKED_INSTALLATIONS, MAX_WIFI_PROFILES, POLICY_HASH_DOMAIN, ROAMING_POLICY_PAYLOAD_LEN,
    WIFI_RECORD_LEN,
};
use keyferry_local_management::{
    generate_operation_id, hid::HidTransport, Client as LocalClient,
    ReportTransport as LocalReportTransport, TransportError as LocalTransportError,
};
use keyferry_protocol::{
    configuration, local_management_operation as local_operation,
    local_management_status as local_status, provisioning, provisioning_operation,
    provisioning_status,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Write, net::Ipv4Addr, path::Path, time::Duration};
use zeroize::{Zeroize, Zeroizing};

use super::{
    hex, owner_kit, parse_hex, parse_uuid, publish_json_owner_only, random_array, read_bounded,
    read_json_private, remove_private_durable, validate_bundle, DeviceConfig, WifiConfig,
    DAEMON_SECRETS, DEVICE_CONFIG, FIRMWARE_CERT, OWNER_KIT_MAX_BYTES, RECOVERY_DIR,
    RECOVERY_SECRET, WIFI_CONFIG,
};

const REPORT_TIMEOUT_MS: i32 = 5_000;
const COMMIT_REPORT_TIMEOUT_MS: i32 = 30_000;
const RECONCILE_ATTEMPTS: usize = 40;
const RECONCILE_DELAY_MS: u64 = 250;
const RESPONSE_BIT: u8 = 0x80;
const WPA2_PERSONAL: u8 = 1;
const FIRST_PROFILE_PRIORITY: u8 = 1;
const TLS_SERVER_NAME: &[u8] = b"keyferry.local";
const MIGRATION_JOURNAL: &str = "roaming-migration.json";
const MIGRATION_JOURNAL_SCHEMA_VERSION: u8 = 1;
const MIGRATION_JOURNAL_MAX_BYTES: u64 = 16 * 1024;
const MIGRATION_PHASE_PENDING_COMMIT: &str = "pending-commit";
const POLICY_EPOCH_OFFSET: usize = 64;
const POLICY_SEQUENCE_OFFSET: usize = 72;
const POLICY_HASH_OFFSET: usize = 88;
const POLICY_AUTH_TAG_OFFSET: usize = 152;

type HmacSha256 = Hmac<Sha256>;
type Report = [u8; provisioning::REPORT_SIZE];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportError {
    BeforeWrite,
    AfterWrite,
}

trait ReportTransport {
    fn exchange(&mut self, request: &Report) -> Result<Report, TransportError>;
}

struct BundleMaterial {
    device_id: [u8; 16],
    provisioning_key: [u8; 32],
    payload: Box<[u8; configuration::PAYLOAD_BYTES]>,
}

struct RoamingMaterial {
    device_id: [u8; 16],
    recovery_secret: [u8; 32],
    payload: Box<[u8; ROAMING_POLICY_PAYLOAD_LEN]>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MigrationJournal {
    schema_version: u8,
    phase: String,
    device_id_hex: String,
    target_policy_epoch: u64,
    target_policy_sequence: u64,
    target_policy_hash_hex: String,
    transaction_id_hex: String,
    payload_hex: String,
}

struct JournaledMigration {
    material: RoamingMaterial,
    transaction_id: [u8; provisioning::TRANSACTION_ID_SIZE],
    target: PolicyIdentity,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DesiredRoamingPolicy {
    schema_version: u8,
    wifi_profiles: Vec<DesiredWifiProfile>,
    revoked_installation_ids: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DesiredWifiProfile {
    ssid: String,
    password: String,
    priority: u8,
}

impl Drop for DesiredWifiProfile {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub(super) fn normalize_roaming_policy(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let desired: DesiredRoamingPolicy =
        serde_json::from_slice(input).map_err(|_| "roaming policy input is invalid")?;
    validate_desired_policy(&desired)?;
    let mut output =
        serde_json::to_vec_pretty(&desired).map_err(|_| "could not encode roaming policy")?;
    output.push(b'\n');
    Ok(output)
}

struct Challenge {
    version: u8,
    payload_length: usize,
    device_id: [u8; 16],
    nonce: [u8; provisioning::CHALLENGE_SIZE],
    generation: u64,
}

struct CommitReceipt {
    slot: u8,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PolicyIdentity {
    state: u8,
    epoch: u64,
    sequence: u64,
    hash: [u8; 32],
}

struct PreparedRoamingUpdate {
    challenge: Challenge,
    material: RoamingMaterial,
    predecessor: PolicyIdentity,
    expected: PolicyIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitError {
    Definite(&'static str),
    Unknown,
}

fn selected_owner_authority(
    owner_kit_bytes: &[u8],
    passphrase: &[u8],
    device_id: Option<[u8; 16]>,
) -> Result<owner_kit::DeviceOwnerAuthority, &'static str> {
    let result = match device_id {
        Some(device_id) => {
            owner_kit::unlock_device_authority_for_device(owner_kit_bytes, passphrase, device_id)
        }
        None => owner_kit::unlock_device_authority(owner_kit_bytes, passphrase),
    };
    result.map_err(|error| match error {
        owner_kit::OwnerKitError::AuthenticationFailed => "owner-kit password is incorrect",
        owner_kit::OwnerKitError::InvalidPassphrase => "owner-kit password is invalid",
        owner_kit::OwnerKitError::InvalidEnvelope => "owner-kit file is invalid",
        owner_kit::OwnerKitError::InvalidAuthority => {
            "selected device is absent from the owner kit or its authority is invalid"
        }
        owner_kit::OwnerKitError::CryptoFailed | owner_kit::OwnerKitError::EncodingFailed => {
            "owner-kit cryptographic validation failed"
        }
    })
}

pub(super) fn status(bundle: &Path, output: &mut dyn Write) -> Result<(), &'static str> {
    validate_bundle(bundle)?;
    let device: DeviceConfig = read_json_private(&bundle.join(DEVICE_CONFIG))?;
    let expected_device_id = parse_uuid(&device.device_id)?;
    let mut transport = open_device(&expected_device_id)?;
    status_with(&mut transport, expected_device_id, output)
}

pub(super) fn status_for_device(
    device_id: [u8; 16],
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let mut transport = open_device(&device_id)?;
    status_with(&mut transport, device_id, output)
}

pub(super) fn provision(bundle: &Path, output: &mut dyn Write) -> Result<(), &'static str> {
    let material = load_material(bundle)?;
    let mut transport = open_device(&material.device_id)?;
    provision_with(&mut transport, &material, output)
}

pub(super) fn migrate_roaming(
    bundle: &Path,
    owner_kit_path: &Path,
    passphrase: &[u8],
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let candidate = load_roaming_material(bundle, owner_kit_path, passphrase)?;
    let journal_path = bundle.join(RECOVERY_DIR).join(MIGRATION_JOURNAL);
    let migration = if journal_path.exists() {
        load_migration_journal(&journal_path, &candidate)?
    } else {
        create_migration_journal(&journal_path, candidate)?
    };
    migrate_roaming_journaled(&journal_path, &migration, output)
}

pub(super) fn migrate_roaming_from_private_authority(
    journal_root: &Path,
    authority: &owner_kit::DeviceOwnerAuthority,
    wifi: &WifiConfig,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let candidate = build_initial_roaming_material(authority, wifi)?;
    let journal_path = journal_root.join(MIGRATION_JOURNAL);
    let migration = if journal_path.exists() {
        load_migration_journal(&journal_path, &candidate)?
    } else {
        create_migration_journal(&journal_path, candidate)?
    };
    migrate_roaming_journaled(&journal_path, &migration, output)
}

pub(super) fn update_roaming(
    owner_kit_path: &Path,
    policy_path: &Path,
    passphrase: &[u8],
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    update_roaming_selected(owner_kit_path, policy_path, passphrase, None, output)
}

pub(super) fn update_roaming_for_device(
    owner_kit_path: &Path,
    policy_path: &Path,
    passphrase: &[u8],
    device_id: [u8; 16],
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    update_roaming_selected(
        owner_kit_path,
        policy_path,
        passphrase,
        Some(device_id),
        output,
    )
}

fn update_roaming_selected(
    owner_kit_path: &Path,
    policy_path: &Path,
    passphrase: &[u8],
    device_id: Option<[u8; 16]>,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let kit = read_bounded(owner_kit_path, OWNER_KIT_MAX_BYTES)
        .map_err(|_| "owner-kit file is absent or invalid")?;
    let authority = selected_owner_authority(&kit, passphrase, device_id)?;
    let desired: DesiredRoamingPolicy = read_json_private(policy_path)?;
    let mut transport = open_device(&authority.device_id)?;
    let current = query_policy_identity(&mut transport, authority.device_id)?;
    let (material, expected) = prepare_roaming_successor(&authority, &desired, current)?;
    let mut local = LocalClient::connect(
        transport,
        authority.device_id,
        &authority.device_recovery_secret,
    )
    .map_err(|_| "authenticated local maintenance could not start")?;
    let open_id = generate_operation_id().map_err(|_| "operation identity generation failed")?;
    let opened = local
        .mutate_and_reconcile_with_id(local_operation::OPEN_MAINTENANCE, None, open_id)
        .map_err(|_| "authenticated local maintenance outcome is unknown")?;
    if opened.status != local_status::OK {
        return Err("authenticated local maintenance was rejected");
    }
    let challenge = match request_roaming_challenge(local.transport_mut(), authority.device_id) {
        Ok(challenge) if challenge.generation == current.sequence => challenge,
        Ok(_) => {
            cleanup_local_policy_session(&mut local)?;
            return Err("device policy changed while local maintenance began");
        }
        Err(error) => {
            cleanup_local_policy_session(&mut local)?;
            return Err(error);
        }
    };
    let prepared = PreparedRoamingUpdate {
        challenge,
        material,
        predecessor: current,
        expected,
    };
    match commit_roaming_update(local.transport_mut(), &prepared, output) {
        Ok(()) => Ok(()),
        Err(CommitError::Definite(error)) => {
            cleanup_local_policy_session(&mut local)?;
            Err(error)
        }
        Err(CommitError::Unknown) => {
            drop(local);
            reconcile_roaming_update(&authority.device_id, &prepared, output)
        }
    }
}

fn cleanup_local_policy_session(local: &mut LocalClient<HidTransport>) -> Result<(), &'static str> {
    abort_provisioning_if_active(local.transport_mut())?;
    close_local_maintenance(local)
}

fn abort_provisioning_if_active(transport: &mut dyn ReportTransport) -> Result<(), &'static str> {
    let mut abort = [0_u8; provisioning::REPORT_SIZE];
    abort[provisioning::REQUEST_OPERATION_OFFSET] = provisioning_operation::ABORT;
    let response = transport
        .exchange(&abort)
        .map_err(|_| "local policy staging cleanup was not confirmed")?;
    validate_abort_cleanup_response(&response)
}

fn validate_abort_cleanup_response(response: &Report) -> Result<(), &'static str> {
    if response[provisioning::RESPONSE_OPERATION_OFFSET]
        != provisioning_operation::ABORT | RESPONSE_BIT
        || !matches!(
            response[provisioning::RESPONSE_STATUS_OFFSET],
            provisioning_status::OK | provisioning_status::BAD_STATE
        )
        || response[2..].iter().any(|byte| *byte != 0)
    {
        return Err("local policy staging cleanup was not confirmed");
    }
    Ok(())
}

fn close_local_maintenance(local: &mut LocalClient<HidTransport>) -> Result<(), &'static str> {
    let close_id = generate_operation_id().map_err(|_| "operation identity generation failed")?;
    let closed = local
        .mutate_and_reconcile_with_id(local_operation::CLOSE_MAINTENANCE, None, close_id)
        .map_err(|_| "local maintenance cleanup outcome is unknown")?;
    if closed.status != local_status::OK {
        return Err("local maintenance cleanup was rejected");
    }
    Ok(())
}

pub(super) fn recover_initial_roaming_policy(
    bundle: &Path,
    owner_kit_path: &Path,
    passphrase: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let material = load_roaming_material(bundle, owner_kit_path, passphrase)?;
    let wifi: WifiConfig = read_json_private(&bundle.join(WIFI_CONFIG))?;
    let mut transport = open_device(&material.device_id)?;
    recover_initial_roaming_policy_with(&mut transport, &material, &wifi)
}

pub(super) fn recover_initial_roaming_policy_for_device(
    bundle: &Path,
    owner_kit_path: &Path,
    passphrase: &[u8],
    device_id: [u8; 16],
) -> Result<Vec<u8>, &'static str> {
    let material =
        load_roaming_material_selected(bundle, owner_kit_path, passphrase, Some(device_id))?;
    let wifi: WifiConfig = read_json_private(&bundle.join(WIFI_CONFIG))?;
    let mut transport = open_device(&material.device_id)?;
    recover_initial_roaming_policy_with(&mut transport, &material, &wifi)
}

fn recover_initial_roaming_policy_with(
    transport: &mut dyn ReportTransport,
    material: &RoamingMaterial,
    wifi: &WifiConfig,
) -> Result<Vec<u8>, &'static str> {
    let (_, observed) = begin_policy_session(transport, material.device_id)?;
    if observed != migration_journal_target(material) {
        return Err("active policy does not exactly match the recoverable initial policy");
    }
    let encoded = Zeroizing::new(
        serde_json::to_vec(&DesiredRoamingPolicy {
            schema_version: 1,
            wifi_profiles: vec![DesiredWifiProfile {
                ssid: wifi.ssid.clone(),
                password: wifi.password.clone(),
                priority: FIRST_PROFILE_PRIORITY,
            }],
            revoked_installation_ids: Vec::new(),
        })
        .map_err(|_| "could not encode the recoverable initial policy")?,
    );
    normalize_roaming_policy(encoded.as_slice())
}

fn status_with(
    transport: &mut dyn ReportTransport,
    expected_device_id: [u8; 16],
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    // The HID interface was opened by its exact private device identity.
    // POLICY_STATUS is the only side-effect-free status operation: CHALLENGE
    // deliberately opens maintenance and aborts the network session.
    let policy = request_policy_status(transport)?;
    let readiness = match policy.state {
        keyferry_protocol::provisioning_policy_state::LEGACY
        | keyferry_protocol::provisioning_policy_state::ACTIVE => "ready",
        _ => "locked",
    };
    write_policy_status(output, expected_device_id, policy, readiness)
}

fn write_policy_status(
    output: &mut dyn Write,
    device_id: [u8; 16],
    policy: PolicyIdentity,
    readiness: &'static str,
) -> Result<(), &'static str> {
    writeln!(
        output,
        "device={} format={} policy_state={} epoch={} policy={} policy_hash={} status={}",
        format_device_id(&device_id),
        keyferry_protocol::roaming::VERSION,
        policy_state_name(policy.state)?,
        policy.epoch,
        policy.sequence,
        hex(&policy.hash),
        readiness,
    )
    .map_err(|_| "could not write status")
}

fn request_policy_status(
    transport: &mut dyn ReportTransport,
) -> Result<PolicyIdentity, &'static str> {
    let mut request = [0_u8; provisioning::REPORT_SIZE];
    request[provisioning::REQUEST_OPERATION_OFFSET] = provisioning_operation::POLICY_STATUS;
    let response = exchange_ok(
        transport,
        &request,
        provisioning_operation::POLICY_STATUS,
        provisioning::POLICY_STATUS_HASH_OFFSET + 32,
    )?;
    let state = response[provisioning::POLICY_STATUS_STATE_OFFSET];
    policy_state_name(state)?;
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(
        &response
            [provisioning::POLICY_STATUS_HASH_OFFSET..provisioning::POLICY_STATUS_HASH_OFFSET + 32],
    );
    let epoch = get_u64(&response[provisioning::POLICY_STATUS_EPOCH_OFFSET..]);
    let sequence = get_u64(&response[provisioning::POLICY_STATUS_SEQUENCE_OFFSET..]);
    if state == keyferry_protocol::provisioning_policy_state::ACTIVE
        || state == keyferry_protocol::provisioning_policy_state::MIGRATION_PENDING
    {
        if epoch == 0 || sequence == 0 || hash.iter().all(|byte| *byte == 0) {
            return Err("device returned an invalid roaming policy identity");
        }
    } else if epoch != 0 || sequence != 0 || hash.iter().any(|byte| *byte != 0) {
        return Err("device returned an inconsistent roaming policy identity");
    }
    Ok(PolicyIdentity {
        state,
        epoch,
        sequence,
        hash,
    })
}

fn policy_state_name(state: u8) -> Result<&'static str, &'static str> {
    match state {
        keyferry_protocol::provisioning_policy_state::LEGACY => Ok("legacy"),
        keyferry_protocol::provisioning_policy_state::ABSENT => Ok("absent"),
        keyferry_protocol::provisioning_policy_state::MALFORMED => Ok("malformed"),
        keyferry_protocol::provisioning_policy_state::MIGRATION_PENDING => Ok("pending"),
        keyferry_protocol::provisioning_policy_state::ACTIVE => Ok("active"),
        keyferry_protocol::provisioning_policy_state::STORAGE_ERROR => Ok("storage-error"),
        _ => Err("device returned an unknown roaming policy state"),
    }
}

fn provision_with(
    transport: &mut dyn ReportTransport,
    material: &BundleMaterial,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let challenge = request_challenge(transport)?;
    if challenge.device_id != material.device_id {
        return Err("connected device identity does not match the private bundle");
    }
    require_challenge(
        &challenge,
        provisioning::VERSION,
        configuration::PAYLOAD_BYTES,
    )?;
    let next_generation = challenge
        .generation
        .checked_add(1)
        .ok_or("device configuration generation is exhausted")?;

    let receipt = send_authenticated_payload(
        transport,
        &challenge,
        provisioning::VERSION,
        provisioning::AUTHENTICATION_DOMAIN,
        &material.provisioning_key,
        material.payload.as_ref(),
    )
    .map_err(|error| {
        commit_error_message(
            error,
            "configuration commit outcome is unknown; do not retry, reconnect and run status",
        )
    })?;
    if !(1..=2).contains(&receipt.slot) {
        return Err("device returned an invalid configuration slot");
    }
    if receipt.generation != next_generation {
        return Err("device returned an unexpected configuration generation");
    }
    writeln!(
        output,
        "device={} generation={} slot={} status=committed",
        format_device_id(&material.device_id),
        receipt.generation,
        if receipt.slot == 1 { "A" } else { "B" }
    )
    .map_err(|_| "could not write status")
}

fn migrate_roaming_journaled(
    journal_path: &Path,
    migration: &JournaledMigration,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let mut transport = open_device(&migration.material.device_id)?;
    match attempt_journaled_migration(&mut transport, migration)? {
        MigrationAttempt::Active => {
            remove_private_durable(journal_path)?;
            return write_migration_status(
                output,
                &migration.material.device_id,
                "migrated-reconciled",
            );
        }
        MigrationAttempt::Reconnect => {}
    }
    drop(transport);
    reconcile_journaled_migration(journal_path, migration, output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MigrationAttempt {
    Active,
    Reconnect,
}

fn attempt_journaled_migration(
    transport: &mut dyn ReportTransport,
    migration: &JournaledMigration,
) -> Result<MigrationAttempt, &'static str> {
    let (_, observed) = begin_policy_session(transport, migration.material.device_id)?;
    if observed == migration.target {
        return Ok(MigrationAttempt::Active);
    }
    if observed.state != keyferry_protocol::provisioning_policy_state::LEGACY
        && observed != pending_identity(migration.target)
    {
        return Err("device policy conflicts with the durable migration journal");
    }
    // POLICY_STATUS deliberately clears the firmware's challenge. Start a
    // fresh challenge before BEGIN while the application-level maintenance
    // gate remains held.
    let challenge = request_roaming_challenge(transport, migration.material.device_id)?;
    let commit = send_authenticated_payload_with_transaction(
        transport,
        &challenge,
        keyferry_protocol::roaming::VERSION,
        keyferry_protocol::roaming::MAINTENANCE_AUTHENTICATION_DOMAIN,
        &migration.material.recovery_secret,
        migration.material.payload.as_ref(),
        &migration.transaction_id,
    );
    match commit {
        Ok(receipt) if receipt.slot == 0 && receipt.generation == migration.target.sequence => {
            Ok(MigrationAttempt::Reconnect)
        }
        Ok(_) => Err("device returned an invalid roaming migration receipt"),
        Err(CommitError::Definite(error)) => Err(error),
        Err(CommitError::Unknown) => Ok(MigrationAttempt::Reconnect),
    }
}

fn reconcile_journaled_migration(
    journal_path: &Path,
    migration: &JournaledMigration,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    for attempt in 0..RECONCILE_ATTEMPTS {
        if attempt != 0 {
            std::thread::sleep(std::time::Duration::from_millis(RECONCILE_DELAY_MS));
        }
        let Ok(mut transport) = open_device(&migration.material.device_id) else {
            continue;
        };
        let Ok((_, observed)) = begin_policy_session(&mut transport, migration.material.device_id)
        else {
            continue;
        };
        if observed == migration.target {
            remove_private_durable(journal_path)?;
            return write_migration_status(
                output,
                &migration.material.device_id,
                "migrated-reconciled",
            );
        }
        if observed == pending_identity(migration.target)
            || observed.state == keyferry_protocol::provisioning_policy_state::LEGACY
        {
            return Err(
                "roaming migration remains incomplete; rerun migrate-roaming to resume the durable transaction",
            );
        }
        return Err("device policy conflicts with the durable migration journal");
    }
    Err("roaming migration outcome remains unknown; rerun migrate-roaming to resume the durable transaction")
}

fn write_migration_status(
    output: &mut dyn Write,
    device_id: &[u8; 16],
    status: &str,
) -> Result<(), &'static str> {
    writeln!(
        output,
        "device={} policy=1 status={status}",
        format_device_id(device_id)
    )
    .map_err(|_| "could not write status")
}

fn pending_identity(mut target: PolicyIdentity) -> PolicyIdentity {
    target.state = keyferry_protocol::provisioning_policy_state::MIGRATION_PENDING;
    target
}

#[cfg(test)]
fn update_roaming_with(
    transport: &mut dyn ReportTransport,
    authority: &owner_kit::DeviceOwnerAuthority,
    desired: &DesiredRoamingPolicy,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    let prepared = prepare_roaming_update(transport, authority, desired)?;
    commit_roaming_update(transport, &prepared, output).map_err(|error| match error {
        CommitError::Definite(error) => error,
        CommitError::Unknown => {
            "roaming policy update outcome is unknown; no update was retried, reconnect and run status"
        }
    })
}

#[cfg(test)]
fn prepare_roaming_update(
    transport: &mut dyn ReportTransport,
    authority: &owner_kit::DeviceOwnerAuthority,
    desired: &DesiredRoamingPolicy,
) -> Result<PreparedRoamingUpdate, &'static str> {
    let current = query_policy_identity(transport, authority.device_id)?;
    let (material, expected) = prepare_roaming_successor(authority, desired, current)?;
    let challenge = request_roaming_challenge(transport, authority.device_id)?;
    if current.sequence != challenge.generation {
        return Err("device policy changed while maintenance began");
    }
    Ok(PreparedRoamingUpdate {
        challenge,
        material,
        predecessor: current,
        expected,
    })
}

fn prepare_roaming_successor(
    authority: &owner_kit::DeviceOwnerAuthority,
    desired: &DesiredRoamingPolicy,
    current: PolicyIdentity,
) -> Result<(RoamingMaterial, PolicyIdentity), &'static str> {
    if current.state != keyferry_protocol::provisioning_policy_state::ACTIVE {
        return Err("device does not have an active roaming policy");
    }
    if current.epoch != authority.authority_epoch {
        return Err("owner kit authority epoch does not match the device");
    }
    let material = build_successor_material(authority, desired, current)?;
    let sequence = current
        .sequence
        .checked_add(1)
        .ok_or("device policy sequence is exhausted")?;
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&material.payload[88..120]);
    Ok((
        material,
        PolicyIdentity {
            state: keyferry_protocol::provisioning_policy_state::ACTIVE,
            epoch: authority.authority_epoch,
            sequence,
            hash,
        },
    ))
}

fn commit_roaming_update(
    transport: &mut dyn ReportTransport,
    prepared: &PreparedRoamingUpdate,
    output: &mut dyn Write,
) -> Result<(), CommitError> {
    let receipt = send_authenticated_payload(
        transport,
        &prepared.challenge,
        keyferry_protocol::roaming::VERSION,
        keyferry_protocol::roaming::MAINTENANCE_AUTHENTICATION_DOMAIN,
        &prepared.material.recovery_secret,
        prepared.material.payload.as_ref(),
    )?;
    if receipt.slot != 0 || receipt.generation != prepared.expected.sequence {
        return Err(CommitError::Unknown);
    }
    writeln!(
        output,
        "device={} policy={} policy_hash={} status=updated",
        format_device_id(&prepared.material.device_id),
        receipt.generation,
        hex(&prepared.expected.hash),
    )
    .map_err(|_| CommitError::Definite("could not write status"))
}

fn reconcile_roaming_update(
    device_id: &[u8; 16],
    prepared: &PreparedRoamingUpdate,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    for attempt in 0..RECONCILE_ATTEMPTS {
        if attempt != 0 {
            std::thread::sleep(std::time::Duration::from_millis(RECONCILE_DELAY_MS));
        }
        let Ok(mut transport) = open_device(device_id) else {
            continue;
        };
        let Ok(observed) = query_policy_identity(&mut transport, *device_id) else {
            continue;
        };
        return reconcile_roaming_observation(device_id, prepared, observed, output);
    }
    Err("roaming policy update outcome remains unknown; no update was retried, run status")
}

fn reconcile_roaming_observation(
    device_id: &[u8; 16],
    prepared: &PreparedRoamingUpdate,
    observed: PolicyIdentity,
    output: &mut dyn Write,
) -> Result<(), &'static str> {
    if observed == prepared.expected {
        return writeln!(
            output,
            "device={} policy={} policy_hash={} status=updated-reconciled",
            format_device_id(device_id),
            observed.sequence,
            hex(&observed.hash),
        )
        .map_err(|_| "could not write status");
    }
    if observed == prepared.predecessor {
        return Err("roaming policy update did not commit; no update was retried");
    }
    Err("roaming policy changed after an unknown commit outcome; no update was retried")
}

fn query_policy_identity(
    transport: &mut dyn ReportTransport,
    _expected_device_id: [u8; 16],
) -> Result<PolicyIdentity, &'static str> {
    request_policy_status(transport)
}

fn begin_policy_session(
    transport: &mut dyn ReportTransport,
    expected_device_id: [u8; 16],
) -> Result<(Challenge, PolicyIdentity), &'static str> {
    let challenge = request_roaming_challenge(transport, expected_device_id)?;
    let policy = request_policy_status(transport)?;
    if matches!(
        policy.state,
        keyferry_protocol::provisioning_policy_state::MIGRATION_PENDING
            | keyferry_protocol::provisioning_policy_state::ACTIVE
    ) && challenge.generation != policy.sequence
    {
        return Err("device policy changed while status was queried");
    }
    Ok((challenge, policy))
}

fn request_roaming_challenge(
    transport: &mut dyn ReportTransport,
    expected_device_id: [u8; 16],
) -> Result<Challenge, &'static str> {
    let challenge = request_challenge(transport)?;
    if challenge.device_id != expected_device_id {
        return Err("connected device identity does not match the owner kit");
    }
    require_challenge(
        &challenge,
        keyferry_protocol::roaming::VERSION,
        ROAMING_POLICY_PAYLOAD_LEN,
    )?;
    Ok(challenge)
}

fn commit_error_message(error: CommitError, unknown: &'static str) -> &'static str {
    match error {
        CommitError::Definite(error) => error,
        CommitError::Unknown => unknown,
    }
}

fn request_challenge(transport: &mut dyn ReportTransport) -> Result<Challenge, &'static str> {
    let mut request = [0_u8; provisioning::REPORT_SIZE];
    request[provisioning::REQUEST_OPERATION_OFFSET] = provisioning_operation::CHALLENGE;
    let response = exchange_ok(
        transport,
        &request,
        provisioning_operation::CHALLENGE,
        provisioning::CHALLENGE_GENERATION_OFFSET + 8,
    )?;
    let version = response[provisioning::CHALLENGE_VERSION_OFFSET];
    let payload_length =
        get_u16(&response[provisioning::CHALLENGE_PAYLOAD_LENGTH_OFFSET..]) as usize;
    let mut device_id = [0_u8; 16];
    device_id.copy_from_slice(
        &response[provisioning::CHALLENGE_DEVICE_ID_OFFSET
            ..provisioning::CHALLENGE_DEVICE_ID_OFFSET + 16],
    );
    let mut nonce = [0_u8; provisioning::CHALLENGE_SIZE];
    nonce.copy_from_slice(
        &response[provisioning::CHALLENGE_NONCE_OFFSET
            ..provisioning::CHALLENGE_NONCE_OFFSET + provisioning::CHALLENGE_SIZE],
    );
    if device_id.iter().all(|byte| *byte == 0) || nonce.iter().all(|byte| *byte == 0) {
        return Err("device returned an invalid provisioning challenge");
    }
    Ok(Challenge {
        version,
        payload_length,
        device_id,
        nonce,
        generation: get_u64(&response[provisioning::CHALLENGE_GENERATION_OFFSET..]),
    })
}

fn require_challenge(
    challenge: &Challenge,
    version: u8,
    payload_length: usize,
) -> Result<(), &'static str> {
    if challenge.version == version && challenge.payload_length == payload_length {
        Ok(())
    } else {
        Err("device provisioning version or payload size is incompatible")
    }
}

fn send_authenticated_payload(
    transport: &mut dyn ReportTransport,
    challenge: &Challenge,
    version: u8,
    authentication_domain: &[u8],
    key: &[u8; 32],
    payload: &[u8],
) -> Result<CommitReceipt, CommitError> {
    if payload.len() > u16::MAX as usize {
        return Err(CommitError::Definite(
            "provisioning payload exceeds the wire bound",
        ));
    }
    let mut transaction_id =
        random_array::<{ provisioning::TRANSACTION_ID_SIZE }>().map_err(CommitError::Definite)?;
    if transaction_id.iter().all(|byte| *byte == 0) {
        transaction_id[0] = 1;
    }
    send_authenticated_payload_with_transaction(
        transport,
        challenge,
        version,
        authentication_domain,
        key,
        payload,
        &transaction_id,
    )
}

fn send_authenticated_payload_with_transaction(
    transport: &mut dyn ReportTransport,
    challenge: &Challenge,
    version: u8,
    authentication_domain: &[u8],
    key: &[u8; 32],
    payload: &[u8],
    transaction_id: &[u8; provisioning::TRANSACTION_ID_SIZE],
) -> Result<CommitReceipt, CommitError> {
    if payload.len() > u16::MAX as usize {
        return Err(CommitError::Definite(
            "provisioning payload exceeds the wire bound",
        ));
    }
    if transaction_id.iter().all(|byte| *byte == 0) {
        return Err(CommitError::Definite(
            "provisioning transaction identifier is invalid",
        ));
    }
    let mut begin = [0_u8; provisioning::REPORT_SIZE];
    begin[provisioning::REQUEST_OPERATION_OFFSET] = provisioning_operation::BEGIN;
    begin[provisioning::BEGIN_VERSION_OFFSET] = version;
    put_u16(
        &mut begin[provisioning::BEGIN_PAYLOAD_LENGTH_OFFSET..],
        payload.len() as u16,
    );
    begin[provisioning::BEGIN_TRANSACTION_ID_OFFSET
        ..provisioning::BEGIN_TRANSACTION_ID_OFFSET + transaction_id.len()]
        .copy_from_slice(transaction_id);
    exchange_ok(transport, &begin, provisioning_operation::BEGIN, 2)
        .map_err(CommitError::Definite)?;

    for (index, chunk) in payload
        .chunks(provisioning::DATA_BYTES_PER_REPORT)
        .enumerate()
    {
        let byte_offset = index * provisioning::DATA_BYTES_PER_REPORT;
        let mut data = [0_u8; provisioning::REPORT_SIZE];
        data[provisioning::REQUEST_OPERATION_OFFSET] = provisioning_operation::DATA;
        data[provisioning::DATA_TRANSACTION_ID_OFFSET
            ..provisioning::DATA_TRANSACTION_ID_OFFSET + transaction_id.len()]
            .copy_from_slice(transaction_id);
        put_u16(
            &mut data[provisioning::DATA_OFFSET_OFFSET..],
            byte_offset as u16,
        );
        data[provisioning::DATA_LENGTH_OFFSET] = chunk.len() as u8;
        data[provisioning::DATA_BYTES_OFFSET..provisioning::DATA_BYTES_OFFSET + chunk.len()]
            .copy_from_slice(chunk);
        exchange_ok(transport, &data, provisioning_operation::DATA, 2)
            .map_err(CommitError::Definite)?;
    }

    let tag = authentication_tag(
        key,
        authentication_domain,
        challenge,
        transaction_id,
        payload,
    )
    .map_err(CommitError::Definite)?;
    let mut commit = [0_u8; provisioning::REPORT_SIZE];
    commit[provisioning::REQUEST_OPERATION_OFFSET] = provisioning_operation::COMMIT;
    commit[provisioning::COMMIT_TRANSACTION_ID_OFFSET
        ..provisioning::COMMIT_TRANSACTION_ID_OFFSET + transaction_id.len()]
        .copy_from_slice(transaction_id);
    commit[provisioning::COMMIT_TAG_OFFSET
        ..provisioning::COMMIT_TAG_OFFSET + provisioning::AUTHENTICATION_TAG_SIZE]
        .copy_from_slice(&tag);
    let response = transport
        .exchange(&commit)
        .map_err(|_| CommitError::Unknown)?;
    validate_commit_response(&response)?;
    Ok(CommitReceipt {
        slot: response[provisioning::COMMIT_SLOT_OFFSET],
        generation: get_u64(&response[provisioning::COMMIT_GENERATION_OFFSET..]),
    })
}

fn migration_journal_target(material: &RoamingMaterial) -> PolicyIdentity {
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&material.payload[POLICY_HASH_OFFSET..POLICY_HASH_OFFSET + 32]);
    PolicyIdentity {
        state: keyferry_protocol::provisioning_policy_state::ACTIVE,
        epoch: u64::from_be_bytes(
            material.payload[POLICY_EPOCH_OFFSET..POLICY_EPOCH_OFFSET + 8]
                .try_into()
                .expect("fixed policy epoch field"),
        ),
        sequence: u64::from_be_bytes(
            material.payload[POLICY_SEQUENCE_OFFSET..POLICY_SEQUENCE_OFFSET + 8]
                .try_into()
                .expect("fixed policy sequence field"),
        ),
        hash,
    }
}

fn create_migration_journal(
    path: &Path,
    material: RoamingMaterial,
) -> Result<JournaledMigration, &'static str> {
    let mut transaction_id = random_array::<{ provisioning::TRANSACTION_ID_SIZE }>()?;
    if transaction_id.iter().all(|byte| *byte == 0) {
        transaction_id[0] = 1;
    }
    let target = migration_journal_target(&material);
    let journal = MigrationJournal {
        schema_version: MIGRATION_JOURNAL_SCHEMA_VERSION,
        phase: MIGRATION_PHASE_PENDING_COMMIT.to_owned(),
        device_id_hex: hex(&material.device_id),
        target_policy_epoch: target.epoch,
        target_policy_sequence: target.sequence,
        target_policy_hash_hex: hex(&target.hash),
        transaction_id_hex: hex(&transaction_id),
        payload_hex: hex(material.payload.as_ref()),
    };
    publish_json_owner_only(path, &journal)?;
    Ok(JournaledMigration {
        material,
        transaction_id,
        target,
    })
}

fn load_migration_journal(
    path: &Path,
    authority_material: &RoamingMaterial,
) -> Result<JournaledMigration, &'static str> {
    let bytes = read_bounded(path, MIGRATION_JOURNAL_MAX_BYTES)
        .map_err(|_| "durable migration journal is absent or invalid")?;
    let journal: MigrationJournal = serde_json::from_slice(&bytes)
        .map_err(|_| "durable migration journal is malformed; no migration request was sent")?;
    if journal.schema_version != MIGRATION_JOURNAL_SCHEMA_VERSION
        || journal.phase != MIGRATION_PHASE_PENDING_COMMIT
    {
        return Err(
            "durable migration journal has an unsupported state; no migration request was sent",
        );
    }
    let device_id = parse_hex::<16>(
        &journal.device_id_hex,
        "durable migration journal device identity is invalid",
    )?;
    let transaction_id = parse_hex::<{ provisioning::TRANSACTION_ID_SIZE }>(
        &journal.transaction_id_hex,
        "durable migration journal transaction is invalid",
    )?;
    let recorded_hash = parse_hex::<32>(
        &journal.target_policy_hash_hex,
        "durable migration journal policy hash is invalid",
    )?;
    let payload_bytes = parse_hex_vec_exact(
        &journal.payload_hex,
        ROAMING_POLICY_PAYLOAD_LEN,
        "durable migration journal policy payload is invalid",
    )?;
    let payload: Box<[u8; ROAMING_POLICY_PAYLOAD_LEN]> = payload_bytes
        .into_boxed_slice()
        .try_into()
        .map_err(|_| "durable migration journal policy payload is invalid")?;
    let material = RoamingMaterial {
        device_id,
        recovery_secret: authority_material.recovery_secret,
        payload,
    };
    let target = migration_journal_target(&material);
    let authority_target = migration_journal_target(authority_material);
    if device_id != authority_material.device_id
        || transaction_id.iter().all(|byte| *byte == 0)
        || target.epoch != journal.target_policy_epoch
        || target.epoch != authority_target.epoch
        || target.sequence != journal.target_policy_sequence
        || target.hash != recorded_hash
        || material.payload[..64] != authority_material.payload[..64]
    {
        return Err("durable migration journal conflicts with the owner authority; no migration request was sent");
    }
    verify_journaled_policy(&material)?;
    Ok(JournaledMigration {
        material,
        transaction_id,
        target,
    })
}

fn verify_journaled_policy(material: &RoamingMaterial) -> Result<(), &'static str> {
    let payload = material.payload.as_ref();
    let mut canonical = Vec::with_capacity(POLICY_HASH_DOMAIN.len() + payload.len() - 64);
    canonical.extend_from_slice(POLICY_HASH_DOMAIN);
    canonical.extend_from_slice(&payload[..POLICY_HASH_OFFSET]);
    canonical.extend_from_slice(&payload[POLICY_HASH_OFFSET + 32..POLICY_AUTH_TAG_OFFSET]);
    canonical.extend_from_slice(&payload[POLICY_AUTH_TAG_OFFSET + 32..]);
    let calculated_hash: [u8; 32] = Sha256::digest(&canonical).into();
    let mut policy_hash = [0_u8; 32];
    policy_hash.copy_from_slice(&payload[POLICY_HASH_OFFSET..POLICY_HASH_OFFSET + 32]);
    if calculated_hash != policy_hash {
        return Err("durable migration journal policy payload hash is invalid; no migration request was sent");
    }
    let mut owner_id = [0_u8; 16];
    owner_id.copy_from_slice(&payload[16..32]);
    let auth_secret = derive_policy_auth_secret(
        &material.recovery_secret,
        &owner_id,
        &material.device_id,
        u64::from_be_bytes(
            payload[POLICY_EPOCH_OFFSET..POLICY_EPOCH_OFFSET + 8]
                .try_into()
                .unwrap(),
        ),
    )
    .map_err(|_| "durable migration journal authority is invalid; no migration request was sent")?;
    verify_roaming_policy_auth_tag(
        &auth_secret,
        &policy_hash,
        &payload[POLICY_AUTH_TAG_OFFSET..POLICY_AUTH_TAG_OFFSET + 32],
    )
    .map_err(|_| {
        "durable migration journal authentication is invalid; no migration request was sent"
    })
}

fn parse_hex_vec_exact(
    value: &str,
    length: usize,
    error: &'static str,
) -> Result<Vec<u8>, &'static str> {
    if value.len() != length * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| error)?;
            u8::from_str_radix(text, 16).map_err(|_| error)
        })
        .collect()
}

fn validate_commit_response(response: &Report) -> Result<(), CommitError> {
    if response[provisioning::RESPONSE_OPERATION_OFFSET]
        != provisioning_operation::COMMIT | RESPONSE_BIT
    {
        return Err(CommitError::Unknown);
    }
    if response[provisioning::RESPONSE_STATUS_OFFSET] != provisioning_status::OK {
        return Err(CommitError::Definite(status_error(
            response[provisioning::RESPONSE_STATUS_OFFSET],
        )));
    }
    if response[provisioning::COMMIT_GENERATION_OFFSET + 8..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(CommitError::Unknown);
    }
    Ok(())
}

fn exchange_ok(
    transport: &mut dyn ReportTransport,
    request: &Report,
    operation: u8,
    meaningful_end: usize,
) -> Result<Report, &'static str> {
    let response = transport.exchange(request).map_err(|error| match error {
        TransportError::BeforeWrite => "provisioning HID request was not written",
        TransportError::AfterWrite => {
            "provisioning HID response was not received after request write"
        }
    })?;
    validate_response(&response, operation, meaningful_end)?;
    Ok(response)
}

fn validate_response(
    response: &Report,
    operation: u8,
    meaningful_end: usize,
) -> Result<(), &'static str> {
    if response[provisioning::RESPONSE_OPERATION_OFFSET] != operation | RESPONSE_BIT {
        return Err("device returned a response for the wrong operation");
    }
    if response[provisioning::RESPONSE_STATUS_OFFSET] != provisioning_status::OK {
        return Err(status_error(response[provisioning::RESPONSE_STATUS_OFFSET]));
    }
    if meaningful_end > response.len() || response[meaningful_end..].iter().any(|byte| *byte != 0) {
        return Err("device returned a malformed provisioning response");
    }
    Ok(())
}

fn status_error(status: u8) -> &'static str {
    match status {
        provisioning_status::BAD_REPORT => "device rejected the provisioning report",
        provisioning_status::BAD_STATE => "device is not ready for provisioning",
        provisioning_status::BAD_TRANSACTION => "device rejected the transaction identifier",
        provisioning_status::BAD_OFFSET => "device rejected the payload ordering",
        provisioning_status::AUTHENTICATION_FAILED => {
            "device rejected the administrative authentication"
        }
        provisioning_status::INVALID_CONFIG => "device rejected the configuration payload",
        provisioning_status::IDENTITY_MISMATCH => "device rejected the configured identity",
        provisioning_status::COMMIT_FAILED => "device could not commit the configuration",
        provisioning_status::RANDOM_FAILED => "device random generation failed",
        _ => "device returned an unknown provisioning status",
    }
}

fn authentication_tag(
    key: &[u8; 32],
    authentication_domain: &[u8],
    challenge: &Challenge,
    transaction_id: &[u8; provisioning::TRANSACTION_ID_SIZE],
    payload: &[u8],
) -> Result<[u8; provisioning::AUTHENTICATION_TAG_SIZE], &'static str> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| "HMAC setup failed")?;
    mac.update(authentication_domain);
    mac.update(&challenge.device_id);
    mac.update(&challenge.nonce);
    mac.update(&challenge.generation.to_le_bytes());
    mac.update(transaction_id);
    mac.update(&(payload.len() as u32).to_le_bytes());
    mac.update(payload);
    Ok(mac.finalize().into_bytes().into())
}

fn load_material(bundle: &Path) -> Result<BundleMaterial, &'static str> {
    validate_bundle(bundle)?;
    let device: DeviceConfig = read_json_private(&bundle.join(DEVICE_CONFIG))?;
    let wifi: WifiConfig = read_json_private(&bundle.join(WIFI_CONFIG))?;
    let device_id = parse_uuid(&device.device_id)?;
    let provisioning_key_bytes = read_bounded(&bundle.join(RECOVERY_SECRET), 32)
        .map_err(|_| "administrative recovery secret is absent or invalid")?;
    let provisioning_key: [u8; 32] = provisioning_key_bytes
        .try_into()
        .map_err(|_| "administrative recovery secret is absent or invalid")?;
    let link_secret = parse_hex::<32>(&device.link_secret_hex, "link secret is invalid")?;
    let peer_spki_sha256 = parse_hex::<32>(&device.host_spki_sha256, "host SPKI pin is invalid")?;
    let host_id_bytes = read_bounded(&bundle.join(DAEMON_SECRETS).join("host-id"), 16)?;
    let host_id: [u8; 16] = host_id_bytes
        .try_into()
        .map_err(|_| "host identity is invalid")?;
    let host_address = device
        .host_address
        .parse::<Ipv4Addr>()
        .map_err(|_| "provisioned firmware requires an IPv4 host address")?;
    let certificate = read_bounded(
        &bundle.join(FIRMWARE_CERT),
        configuration::MAX_CA_CERTIFICATE_BYTES as u64,
    )?;

    let mut payload = Box::new([0_u8; configuration::PAYLOAD_BYTES]);
    payload[..16].copy_from_slice(&device_id);
    payload[16..48].copy_from_slice(&provisioning_key);
    payload[48] = 1;
    payload[49] = 1;

    let wifi_offset = configuration::FIXED_HEADER_BYTES;
    payload[wifi_offset] = WPA2_PERSONAL;
    payload[wifi_offset + 2] = FIRST_PROFILE_PRIORITY;
    payload[wifi_offset + 3] = wifi.ssid.len() as u8;
    payload[wifi_offset + 4] = wifi.password.len() as u8;
    payload[wifi_offset + 8..wifi_offset + 8 + wifi.ssid.len()]
        .copy_from_slice(wifi.ssid.as_bytes());
    let credential_offset = wifi_offset + 8 + configuration::MAX_SSID_BYTES;
    payload[credential_offset..credential_offset + wifi.password.len()]
        .copy_from_slice(wifi.password.as_bytes());

    let host_offset = configuration::FIXED_HEADER_BYTES
        + configuration::MAX_WIFI_PROFILES * configuration::WIFI_RECORD_BYTES;
    let mut offset = host_offset;
    payload[offset..offset + host_id.len()].copy_from_slice(&host_id);
    offset += host_id.len();
    payload[offset..offset + 4].copy_from_slice(&host_address.octets());
    offset += 4;
    put_u16(&mut payload[offset..], device.host_port);
    offset += 4; // Port plus two reserved bytes.
    put_u16(&mut payload[offset..], TLS_SERVER_NAME.len() as u16);
    offset += 2;
    put_u16(&mut payload[offset..], certificate.len() as u16);
    offset += 2;
    payload[offset..offset + TLS_SERVER_NAME.len()].copy_from_slice(TLS_SERVER_NAME);
    offset += configuration::MAX_SERVER_NAME_BYTES;
    payload[offset..offset + peer_spki_sha256.len()].copy_from_slice(&peer_spki_sha256);
    offset += peer_spki_sha256.len();
    payload[offset..offset + link_secret.len()].copy_from_slice(&link_secret);
    offset += link_secret.len();
    payload[offset..offset + certificate.len()].copy_from_slice(&certificate);

    Ok(BundleMaterial {
        device_id,
        provisioning_key,
        payload,
    })
}

fn load_roaming_material(
    bundle: &Path,
    owner_kit_path: &Path,
    passphrase: &[u8],
) -> Result<RoamingMaterial, &'static str> {
    load_roaming_material_selected(bundle, owner_kit_path, passphrase, None)
}

fn load_roaming_material_selected(
    bundle: &Path,
    owner_kit_path: &Path,
    passphrase: &[u8],
    selected_device_id: Option<[u8; 16]>,
) -> Result<RoamingMaterial, &'static str> {
    validate_bundle(bundle)?;
    let device: DeviceConfig = read_json_private(&bundle.join(DEVICE_CONFIG))?;
    let wifi: WifiConfig = read_json_private(&bundle.join(WIFI_CONFIG))?;
    let bundle_device_id = parse_uuid(&device.device_id)?;
    let kit = read_bounded(owner_kit_path, OWNER_KIT_MAX_BYTES)
        .map_err(|_| "owner-kit file is absent or invalid")?;
    let authority = selected_owner_authority(&kit, passphrase, selected_device_id)?;
    let bundle_secret: [u8; 32] = read_bounded(&bundle.join(RECOVERY_SECRET), 32)
        .map_err(|_| "administrative recovery secret is absent or invalid")?
        .try_into()
        .map_err(|_| "administrative recovery secret is absent or invalid")?;
    if selected_device_id.is_none()
        && (authority.device_id != bundle_device_id
            || authority.device_recovery_secret != bundle_secret)
    {
        return Err("owner kit does not match the private device bundle");
    }
    build_initial_roaming_material(&authority, &wifi)
}

fn build_initial_roaming_material(
    authority: &owner_kit::DeviceOwnerAuthority,
    wifi: &WifiConfig,
) -> Result<RoamingMaterial, &'static str> {
    if authority.owner_ca_der.len() > MAX_CA_CERTIFICATE_LEN {
        return Err("owner authority certificate exceeds the device bound");
    }
    let owner_ca_sha256: [u8; 32] = Sha256::digest(&authority.owner_ca_der).into();
    let mut policy = RoamingPolicyFields {
        device_id: authority.device_id,
        owner_id: authority.owner_id,
        owner_ca_sha256,
        epoch: authority.authority_epoch,
        sequence: 1,
        previous_sequence: 0,
        previous_hash: [0; 32],
        owner_ca_length: authority.owner_ca_der.len() as u16,
        wifi_count: 1,
        revoked_count: 0,
        owner_ca_der: [0; MAX_CA_CERTIFICATE_LEN],
        revoked_installation_ids: [[0; 16]; MAX_REVOKED_INSTALLATIONS],
        wifi_records: [[0; WIFI_RECORD_LEN]; MAX_WIFI_PROFILES],
    };
    policy.owner_ca_der[..authority.owner_ca_der.len()].copy_from_slice(&authority.owner_ca_der);
    policy.wifi_records[0] = wifi_record(wifi)?;
    let payload = authenticated_roaming_policy_payload(&policy, &authority.device_recovery_secret)
        .map_err(|_| "could not construct the authenticated roaming policy")?;
    Ok(RoamingMaterial {
        device_id: authority.device_id,
        recovery_secret: authority.device_recovery_secret,
        payload,
    })
}

fn build_successor_material(
    authority: &owner_kit::DeviceOwnerAuthority,
    desired: &DesiredRoamingPolicy,
    current: PolicyIdentity,
) -> Result<RoamingMaterial, &'static str> {
    let revoked = validate_desired_policy(desired)?;
    if authority.owner_ca_der.len() > MAX_CA_CERTIFICATE_LEN {
        return Err("owner authority certificate exceeds the device bound");
    }
    let sequence = current
        .sequence
        .checked_add(1)
        .ok_or("device policy sequence is exhausted")?;
    let mut policy = RoamingPolicyFields {
        device_id: authority.device_id,
        owner_id: authority.owner_id,
        owner_ca_sha256: Sha256::digest(&authority.owner_ca_der).into(),
        epoch: authority.authority_epoch,
        sequence,
        previous_sequence: current.sequence,
        previous_hash: current.hash,
        owner_ca_length: authority.owner_ca_der.len() as u16,
        wifi_count: desired.wifi_profiles.len() as u8,
        revoked_count: desired.revoked_installation_ids.len() as u8,
        owner_ca_der: [0; MAX_CA_CERTIFICATE_LEN],
        revoked_installation_ids: [[0; 16]; MAX_REVOKED_INSTALLATIONS],
        wifi_records: [[0; WIFI_RECORD_LEN]; MAX_WIFI_PROFILES],
    };
    policy.owner_ca_der[..authority.owner_ca_der.len()].copy_from_slice(&authority.owner_ca_der);
    for (index, wifi) in desired.wifi_profiles.iter().enumerate() {
        policy.wifi_records[index] = desired_wifi_record(wifi)?;
    }
    for (target, value) in policy.revoked_installation_ids.iter_mut().zip(revoked) {
        *target = value;
    }
    let payload = authenticated_roaming_policy_payload(&policy, &authority.device_recovery_secret)
        .map_err(|_| "could not construct the authenticated roaming policy")?;
    Ok(RoamingMaterial {
        device_id: authority.device_id,
        recovery_secret: authority.device_recovery_secret,
        payload,
    })
}

fn validate_desired_policy(desired: &DesiredRoamingPolicy) -> Result<Vec<[u8; 16]>, &'static str> {
    if desired.schema_version != 1 {
        return Err("roaming policy input has an unsupported schema version");
    }
    if desired.wifi_profiles.len() > MAX_WIFI_PROFILES {
        return Err("roaming policy exceeds the Wi-Fi profile bound");
    }
    if desired.revoked_installation_ids.len() > MAX_REVOKED_INSTALLATIONS {
        return Err("roaming policy exceeds the revocation bound");
    }
    for wifi in &desired.wifi_profiles {
        desired_wifi_record(wifi)?;
    }
    let mut revoked = desired
        .revoked_installation_ids
        .iter()
        .map(|value| {
            if !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("revoked installation ID is invalid");
            }
            parse_hex::<16>(value, "revoked installation ID is invalid")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if revoked
        .iter()
        .any(|identity| identity.iter().all(|byte| *byte == 0))
    {
        return Err("revoked installation ID is invalid");
    }
    revoked.sort_unstable();
    if revoked.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("roaming policy contains a duplicate revocation");
    }
    Ok(revoked)
}

fn wifi_record(wifi: &WifiConfig) -> Result<[u8; WIFI_RECORD_LEN], &'static str> {
    super::validate_wifi(wifi)?;
    let mut record = [0_u8; WIFI_RECORD_LEN];
    record[0] = WPA2_PERSONAL;
    record[2] = FIRST_PROFILE_PRIORITY;
    record[3] = wifi.ssid.len() as u8;
    record[4] = wifi.password.len() as u8;
    record[8..8 + wifi.ssid.len()].copy_from_slice(wifi.ssid.as_bytes());
    let credential_offset = 8 + configuration::MAX_SSID_BYTES;
    record[credential_offset..credential_offset + wifi.password.len()]
        .copy_from_slice(wifi.password.as_bytes());
    Ok(record)
}

fn desired_wifi_record(wifi: &DesiredWifiProfile) -> Result<[u8; WIFI_RECORD_LEN], &'static str> {
    if !(1..=configuration::MAX_SSID_BYTES).contains(&wifi.ssid.len()) || wifi.ssid.contains('\0') {
        return Err("Wi-Fi SSID must contain 1 through 32 bytes and no NUL");
    }
    if !(8..=configuration::MAX_WIFI_CREDENTIAL_BYTES).contains(&wifi.password.len())
        || wifi.password.contains('\0')
    {
        return Err("Wi-Fi password must contain 8 through 63 bytes and no NUL");
    }
    let mut record = [0_u8; WIFI_RECORD_LEN];
    record[0] = WPA2_PERSONAL;
    record[2] = wifi.priority;
    record[3] = wifi.ssid.len() as u8;
    record[4] = wifi.password.len() as u8;
    record[8..8 + wifi.ssid.len()].copy_from_slice(wifi.ssid.as_bytes());
    let credential_offset = 8 + configuration::MAX_SSID_BYTES;
    record[credential_offset..credential_offset + wifi.password.len()]
        .copy_from_slice(wifi.password.as_bytes());
    Ok(record)
}

fn put_u16(output: &mut [u8], value: u16) {
    output[..2].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(input: &[u8]) -> u16 {
    u16::from_le_bytes([input[0], input[1]])
}

fn get_u64(input: &[u8]) -> u64 {
    u64::from_le_bytes(input[..8].try_into().expect("eight-byte field"))
}

fn format_device_id(bytes: &[u8; 16]) -> String {
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

fn open_device(device_id: &[u8; 16]) -> Result<HidTransport, &'static str> {
    HidTransport::open(device_id)
        .map_err(|_| "could not open the exact keyferry provisioning interface")
}

impl ReportTransport for HidTransport {
    fn exchange(&mut self, request: &Report) -> Result<Report, TransportError> {
        let timeout = Duration::from_millis(report_timeout_ms(request[0]) as u64);
        match LocalReportTransport::exchange(self, request, timeout) {
            Ok(response) => Ok(response),
            Err(LocalTransportError::BeforeWrite) => Err(TransportError::BeforeWrite),
            Err(LocalTransportError::AfterWrite) => Err(TransportError::AfterWrite),
        }
    }
}

fn report_timeout_ms(operation: u8) -> i32 {
    if operation == provisioning_operation::COMMIT {
        COMMIT_REPORT_TIMEOUT_MS
    } else {
        REPORT_TIMEOUT_MS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Cursor, path::PathBuf};

    #[test]
    fn only_flash_commit_receives_the_longer_bounded_deadline() {
        assert_eq!(
            report_timeout_ms(provisioning_operation::COMMIT),
            COMMIT_REPORT_TIMEOUT_MS
        );
        for operation in [
            provisioning_operation::CHALLENGE,
            provisioning_operation::POLICY_STATUS,
            provisioning_operation::BEGIN,
            provisioning_operation::DATA,
            provisioning_operation::ABORT,
        ] {
            assert_eq!(report_timeout_ms(operation), REPORT_TIMEOUT_MS);
        }
    }

    #[test]
    fn local_policy_cleanup_accepts_abort_or_already_inactive_only() {
        for status in [provisioning_status::OK, provisioning_status::BAD_STATE] {
            let mut response = [0_u8; provisioning::REPORT_SIZE];
            response[provisioning::RESPONSE_OPERATION_OFFSET] =
                provisioning_operation::ABORT | RESPONSE_BIT;
            response[provisioning::RESPONSE_STATUS_OFFSET] = status;
            assert_eq!(validate_abort_cleanup_response(&response), Ok(()));
        }

        let mut rejected = [0_u8; provisioning::REPORT_SIZE];
        rejected[provisioning::RESPONSE_OPERATION_OFFSET] =
            provisioning_operation::ABORT | RESPONSE_BIT;
        rejected[provisioning::RESPONSE_STATUS_OFFSET] = provisioning_status::COMMIT_FAILED;
        assert_eq!(
            validate_abort_cleanup_response(&rejected),
            Err("local policy staging cleanup was not confirmed")
        );

        let mut malformed = [0_u8; provisioning::REPORT_SIZE];
        malformed[provisioning::RESPONSE_OPERATION_OFFSET] =
            provisioning_operation::ABORT | RESPONSE_BIT;
        malformed[provisioning::RESPONSE_STATUS_OFFSET] = provisioning_status::OK;
        malformed[2] = 1;
        assert_eq!(
            validate_abort_cleanup_response(&malformed),
            Err("local policy staging cleanup was not confirmed")
        );
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "keyferry-provisioner-test-{}",
                hex(&random_array::<12>().expect("random test path"))
            ));
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct FakeDevice {
        device_id: [u8; 16],
        provisioning_key: [u8; 32],
        format: u8,
        payload_size: usize,
        nonce: [u8; provisioning::CHALLENGE_SIZE],
        generation: u64,
        transaction_id: [u8; provisioning::TRANSACTION_ID_SIZE],
        payload: Vec<u8>,
        commit_count: usize,
        lose_commit_response: bool,
        stop_at_pending_migration: bool,
        pending_transaction: Option<[u8; provisioning::TRANSACTION_ID_SIZE]>,
        policy_status: Option<PolicyIdentity>,
        operations: Vec<u8>,
        challenge_active: bool,
        challenge_rejected: bool,
    }

    impl FakeDevice {
        fn new(material: &BundleMaterial) -> Self {
            Self {
                device_id: material.device_id,
                provisioning_key: material.provisioning_key,
                format: provisioning::VERSION,
                payload_size: configuration::PAYLOAD_BYTES,
                nonce: [0x5a; provisioning::CHALLENGE_SIZE],
                generation: 0,
                transaction_id: [0; provisioning::TRANSACTION_ID_SIZE],
                payload: Vec::new(),
                commit_count: 0,
                lose_commit_response: false,
                stop_at_pending_migration: false,
                pending_transaction: None,
                policy_status: None,
                operations: Vec::new(),
                challenge_active: false,
                challenge_rejected: false,
            }
        }

        fn roaming(material: &RoamingMaterial) -> Self {
            let mut hash = [0_u8; 32];
            hash.copy_from_slice(&material.payload[88..120]);
            Self {
                device_id: material.device_id,
                provisioning_key: material.recovery_secret,
                format: keyferry_protocol::roaming::VERSION,
                payload_size: ROAMING_POLICY_PAYLOAD_LEN,
                nonce: [0x5a; provisioning::CHALLENGE_SIZE],
                generation: 1,
                transaction_id: [0; provisioning::TRANSACTION_ID_SIZE],
                payload: Vec::new(),
                commit_count: 0,
                lose_commit_response: false,
                stop_at_pending_migration: false,
                pending_transaction: None,
                policy_status: Some(PolicyIdentity {
                    state: keyferry_protocol::provisioning_policy_state::ACTIVE,
                    epoch: u64::from_be_bytes(material.payload[64..72].try_into().unwrap()),
                    sequence: u64::from_be_bytes(material.payload[72..80].try_into().unwrap()),
                    hash,
                }),
                operations: Vec::new(),
                challenge_active: false,
                challenge_rejected: false,
            }
        }

        fn legacy(material: &RoamingMaterial) -> Self {
            let mut device = Self::roaming(material);
            // Legacy generation belongs to the KFC1 configuration slots and
            // is deliberately independent of the not-yet-created KFC2 policy
            // sequence. The deployed owner device is legacy generation 1.
            device.generation = 1;
            device.policy_status = Some(PolicyIdentity {
                state: keyferry_protocol::provisioning_policy_state::LEGACY,
                epoch: 0,
                sequence: 0,
                hash: [0; 32],
            });
            device
        }

        fn pending(migration: &JournaledMigration) -> Self {
            let mut device = Self::roaming(&migration.material);
            device.policy_status = Some(pending_identity(migration.target));
            device.pending_transaction = Some(migration.transaction_id);
            device
        }

        fn response(operation: u8) -> Report {
            let mut response = [0_u8; provisioning::REPORT_SIZE];
            response[0] = operation | RESPONSE_BIT;
            response[1] = provisioning_status::OK;
            response
        }
    }

    impl ReportTransport for FakeDevice {
        fn exchange(&mut self, request: &Report) -> Result<Report, TransportError> {
            self.operations.push(request[0]);
            match request[0] {
                provisioning_operation::CHALLENGE => {
                    assert!(request[1..].iter().all(|byte| *byte == 0));
                    if self.challenge_rejected {
                        let mut response = Self::response(provisioning_operation::CHALLENGE);
                        response[provisioning::RESPONSE_STATUS_OFFSET] =
                            provisioning_status::BAD_STATE;
                        return Ok(response);
                    }
                    self.payload.clear();
                    self.challenge_active = true;
                    let mut response = Self::response(provisioning_operation::CHALLENGE);
                    response[provisioning::CHALLENGE_VERSION_OFFSET] = self.format;
                    put_u16(
                        &mut response[provisioning::CHALLENGE_PAYLOAD_LENGTH_OFFSET..],
                        self.payload_size as u16,
                    );
                    response[provisioning::CHALLENGE_DEVICE_ID_OFFSET
                        ..provisioning::CHALLENGE_DEVICE_ID_OFFSET + 16]
                        .copy_from_slice(&self.device_id);
                    response[provisioning::CHALLENGE_NONCE_OFFSET
                        ..provisioning::CHALLENGE_NONCE_OFFSET + self.nonce.len()]
                        .copy_from_slice(&self.nonce);
                    response[provisioning::CHALLENGE_GENERATION_OFFSET
                        ..provisioning::CHALLENGE_GENERATION_OFFSET + 8]
                        .copy_from_slice(&self.generation.to_le_bytes());
                    Ok(response)
                }
                provisioning_operation::BEGIN => {
                    assert!(
                        self.challenge_active,
                        "BEGIN requires a fresh challenge after POLICY_STATUS"
                    );
                    assert_eq!(request[provisioning::BEGIN_VERSION_OFFSET], self.format);
                    assert_eq!(
                        get_u16(&request[provisioning::BEGIN_PAYLOAD_LENGTH_OFFSET..]) as usize,
                        self.payload_size
                    );
                    self.transaction_id.copy_from_slice(
                        &request[provisioning::BEGIN_TRANSACTION_ID_OFFSET
                            ..provisioning::BEGIN_TRANSACTION_ID_OFFSET
                                + provisioning::TRANSACTION_ID_SIZE],
                    );
                    assert!(self.transaction_id.iter().any(|byte| *byte != 0));
                    Ok(Self::response(provisioning_operation::BEGIN))
                }
                provisioning_operation::DATA => {
                    assert_eq!(
                        &request[provisioning::DATA_TRANSACTION_ID_OFFSET
                            ..provisioning::DATA_TRANSACTION_ID_OFFSET
                                + provisioning::TRANSACTION_ID_SIZE],
                        &self.transaction_id
                    );
                    assert_eq!(
                        get_u16(&request[provisioning::DATA_OFFSET_OFFSET..]) as usize,
                        self.payload.len()
                    );
                    let length = request[provisioning::DATA_LENGTH_OFFSET] as usize;
                    self.payload.extend_from_slice(
                        &request[provisioning::DATA_BYTES_OFFSET
                            ..provisioning::DATA_BYTES_OFFSET + length],
                    );
                    Ok(Self::response(provisioning_operation::DATA))
                }
                provisioning_operation::COMMIT => {
                    self.commit_count += 1;
                    assert_eq!(self.payload.len(), self.payload_size);
                    let challenge = Challenge {
                        version: self.format,
                        payload_length: self.payload_size,
                        device_id: self.device_id,
                        nonce: self.nonce,
                        generation: self.generation,
                    };
                    let expected = authentication_tag(
                        &self.provisioning_key,
                        if self.format == keyferry_protocol::roaming::VERSION {
                            keyferry_protocol::roaming::MAINTENANCE_AUTHENTICATION_DOMAIN
                        } else {
                            provisioning::AUTHENTICATION_DOMAIN
                        },
                        &challenge,
                        &self.transaction_id,
                        self.payload.as_slice(),
                    )
                    .expect("authentication tag");
                    assert_eq!(
                        &request[provisioning::COMMIT_TAG_OFFSET
                            ..provisioning::COMMIT_TAG_OFFSET
                                + provisioning::AUTHENTICATION_TAG_SIZE],
                        &expected
                    );
                    if self
                        .pending_transaction
                        .is_some_and(|expected| expected != self.transaction_id)
                    {
                        let mut response = Self::response(provisioning_operation::COMMIT);
                        response[provisioning::RESPONSE_STATUS_OFFSET] =
                            provisioning_status::COMMIT_FAILED;
                        return Ok(response);
                    }
                    if self.format == provisioning::VERSION {
                        self.generation += 1;
                    } else {
                        let epoch = u64::from_be_bytes(self.payload[64..72].try_into().unwrap());
                        let sequence = u64::from_be_bytes(self.payload[72..80].try_into().unwrap());
                        let mut hash = [0_u8; 32];
                        hash.copy_from_slice(&self.payload[88..120]);
                        self.generation = sequence;
                        self.policy_status = Some(PolicyIdentity {
                            state: if self.stop_at_pending_migration {
                                keyferry_protocol::provisioning_policy_state::MIGRATION_PENDING
                            } else {
                                keyferry_protocol::provisioning_policy_state::ACTIVE
                            },
                            epoch,
                            sequence,
                            hash,
                        });
                        if self.stop_at_pending_migration {
                            self.pending_transaction = Some(self.transaction_id);
                            return Err(TransportError::AfterWrite);
                        }
                    }
                    if self.lose_commit_response {
                        return Err(TransportError::AfterWrite);
                    }
                    self.challenge_active = false;
                    let mut response = Self::response(provisioning_operation::COMMIT);
                    response[provisioning::COMMIT_SLOT_OFFSET] =
                        if self.format == provisioning::VERSION {
                            1
                        } else {
                            0
                        };
                    response[provisioning::COMMIT_GENERATION_OFFSET
                        ..provisioning::COMMIT_GENERATION_OFFSET + 8]
                        .copy_from_slice(&self.generation.to_le_bytes());
                    Ok(response)
                }
                provisioning_operation::ABORT => {
                    self.payload.clear();
                    self.challenge_active = false;
                    Ok(Self::response(provisioning_operation::ABORT))
                }
                provisioning_operation::POLICY_STATUS => {
                    assert!(request[1..].iter().all(|byte| *byte == 0));
                    self.challenge_active = false;
                    let policy = self.policy_status.expect("roaming policy status");
                    let mut response = Self::response(provisioning_operation::POLICY_STATUS);
                    response[provisioning::POLICY_STATUS_STATE_OFFSET] = policy.state;
                    response[provisioning::POLICY_STATUS_EPOCH_OFFSET
                        ..provisioning::POLICY_STATUS_EPOCH_OFFSET + 8]
                        .copy_from_slice(&policy.epoch.to_le_bytes());
                    response[provisioning::POLICY_STATUS_SEQUENCE_OFFSET
                        ..provisioning::POLICY_STATUS_SEQUENCE_OFFSET + 8]
                        .copy_from_slice(&policy.sequence.to_le_bytes());
                    response[provisioning::POLICY_STATUS_HASH_OFFSET
                        ..provisioning::POLICY_STATUS_HASH_OFFSET + policy.hash.len()]
                        .copy_from_slice(&policy.hash);
                    Ok(response)
                }
                operation => panic!("unexpected operation {operation}"),
            }
        }
    }

    fn bundle() -> (TestRoot, BundleMaterial, WifiConfig, DeviceConfig) {
        let root = TestRoot::new();
        super::super::create_bundle(&root.0, "192.0.2.19".parse().unwrap(), 7443)
            .expect("create bundle");
        super::super::set_wifi(
            &root.0,
            &mut Cursor::new(
                b"{\"schema_version\":1,\"ssid\":\"ssid-sentinel\",\"password\":\"password-sentinel\"}",
            ),
            false,
        )
        .expect("set Wi-Fi");
        let wifi = read_json_private(&root.0.join(WIFI_CONFIG)).expect("Wi-Fi config");
        let device = read_json_private(&root.0.join(DEVICE_CONFIG)).expect("device config");
        let material = load_material(&root.0).expect("load material");
        (root, material, wifi, device)
    }

    #[test]
    fn payload_matches_the_firmware_layout_and_preserves_recovery_authority() {
        let (_root, material, wifi, device) = bundle();
        assert_eq!(&material.payload[..16], &material.device_id);
        assert_eq!(&material.payload[16..48], &material.provisioning_key);
        assert_eq!(&material.payload[48..52], &[1, 1, 0, 0]);
        let wifi_offset = configuration::FIXED_HEADER_BYTES;
        assert_eq!(material.payload[wifi_offset], WPA2_PERSONAL);
        assert_eq!(material.payload[wifi_offset + 3] as usize, wifi.ssid.len());
        assert_eq!(
            &material.payload[wifi_offset + 8..wifi_offset + 8 + wifi.ssid.len()],
            wifi.ssid.as_bytes()
        );
        let host_offset = configuration::FIXED_HEADER_BYTES
            + configuration::MAX_WIFI_PROFILES * configuration::WIFI_RECORD_BYTES;
        assert_eq!(
            &material.payload[host_offset + 16..host_offset + 20],
            &[192, 0, 2, 19]
        );
        assert_eq!(
            get_u16(&material.payload[host_offset + 20..]),
            device.host_port
        );
        assert!(
            material.payload[host_offset + configuration::HOST_RECORD_BYTES..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn status_is_one_side_effect_free_policy_read() {
        let (_root, material, _wifi, _device) = bundle();
        let mut fake = FakeDevice::new(&material);
        fake.policy_status = Some(PolicyIdentity {
            state: keyferry_protocol::provisioning_policy_state::LEGACY,
            epoch: 0,
            sequence: 0,
            hash: [0; 32],
        });
        let mut output = Vec::new();
        status_with(&mut fake, material.device_id, &mut output).expect("status");
        let visible = String::from_utf8(output).expect("UTF-8 status");
        assert_eq!(fake.operations, vec![provisioning_operation::POLICY_STATUS]);
        assert!(!fake.challenge_active);
        assert!(visible.contains("policy_state=legacy"));
        assert!(visible.contains("status=ready"));
        assert!(!visible.contains(&hex(&material.provisioning_key)));
    }

    #[test]
    fn transport_failure_preserves_before_and_after_write_boundary() {
        struct FailingTransport(TransportError);

        impl ReportTransport for FailingTransport {
            fn exchange(&mut self, _request: &Report) -> Result<Report, TransportError> {
                Err(self.0)
            }
        }

        let request = [0_u8; provisioning::REPORT_SIZE];
        assert_eq!(
            exchange_ok(
                &mut FailingTransport(TransportError::BeforeWrite),
                &request,
                provisioning_operation::POLICY_STATUS,
                2,
            ),
            Err("provisioning HID request was not written")
        );
        assert_eq!(
            exchange_ok(
                &mut FailingTransport(TransportError::AfterWrite),
                &request,
                provisioning_operation::POLICY_STATUS,
                2,
            ),
            Err("provisioning HID response was not received after request write")
        );
    }

    #[test]
    fn provision_sends_one_authenticated_commit_and_logs_only_metadata() {
        let (_root, material, wifi, device) = bundle();
        let mut fake = FakeDevice::new(&material);
        let mut output = Vec::new();
        provision_with(&mut fake, &material, &mut output).expect("provision");
        assert_eq!(fake.commit_count, 1);
        assert_eq!(fake.payload.as_slice(), material.payload.as_slice());
        let visible = String::from_utf8(output).expect("UTF-8 status");
        assert!(visible.contains("generation=1 slot=A status=committed"));
        assert!(!visible.contains(&wifi.ssid));
        assert!(!visible.contains(&wifi.password));
        assert!(!visible.contains(&device.link_secret_hex));
        assert!(!visible.contains(&hex(&material.provisioning_key)));
    }

    #[test]
    fn roaming_migration_uses_owner_policy_and_one_distinct_commit() {
        let (root, legacy, wifi, _device) = bundle();
        let passphrase = b"owner passphrase sentinel value";
        let owner_id = [0x31; 16];
        let kit = owner_kit::create(
            legacy.device_id,
            legacy.provisioning_key,
            passphrase,
            [0x32; 16],
            [0x33; 12],
            owner_id,
        )
        .expect("owner kit");
        let kit_path = root.0.join("owner-kit.json");
        fs::write(&kit_path, kit).expect("owner-kit file");
        let roaming = load_roaming_material(&root.0, &kit_path, passphrase)
            .expect("roaming migration material");
        assert_eq!(&roaming.payload[..16], &legacy.device_id);
        assert_eq!(&roaming.payload[16..32], &owner_id);
        assert_eq!(&roaming.payload[64..72], &1_u64.to_be_bytes());
        assert_eq!(&roaming.payload[72..80], &1_u64.to_be_bytes());
        assert_eq!(roaming.payload[186], 1);
        let wifi_offset = keyferry_protocol::roaming::ROAMING_CONFIG_FIXED_HEADER_BYTES
            + MAX_CA_CERTIFICATE_LEN
            + MAX_REVOKED_INSTALLATIONS * 16;
        assert_eq!(roaming.payload[wifi_offset], WPA2_PERSONAL);
        assert_eq!(roaming.payload[wifi_offset + 3] as usize, wifi.ssid.len());

        let journal_path = root.0.join(RECOVERY_DIR).join(MIGRATION_JOURNAL);
        let migration = create_migration_journal(&journal_path, roaming).expect("journal");
        let mut fake = FakeDevice::legacy(&migration.material);
        assert_eq!(
            attempt_journaled_migration(&mut fake, &migration),
            Ok(MigrationAttempt::Reconnect)
        );
        assert_eq!(
            &fake.operations[..3],
            &[
                provisioning_operation::CHALLENGE,
                provisioning_operation::POLICY_STATUS,
                provisioning_operation::CHALLENGE,
            ],
            "policy inspection and mutation require separate challenges"
        );
        assert_eq!(fake.commit_count, 1);
        assert_eq!(
            fake.payload.as_slice(),
            migration.material.payload.as_slice()
        );
        let journal = String::from_utf8(fs::read(journal_path).expect("journal bytes"))
            .expect("UTF-8 journal");
        assert!(!journal.contains(&wifi.ssid));
        assert!(!journal.contains(&wifi.password));
        assert!(!journal.contains(&hex(&legacy.provisioning_key)));
    }

    fn migration_fixture() -> (TestRoot, RoamingMaterial) {
        let (root, legacy, _wifi, _device) = bundle();
        let passphrase = b"owner passphrase sentinel value";
        let kit = owner_kit::create(
            legacy.device_id,
            legacy.provisioning_key,
            passphrase,
            [0x61; 16],
            [0x62; 12],
            [0x63; 16],
        )
        .expect("owner kit");
        let kit_path = root.0.join("owner-kit-resume.json");
        fs::write(&kit_path, kit).expect("owner-kit file");
        let material = load_roaming_material(&root.0, &kit_path, passphrase)
            .expect("roaming migration material");
        (root, material)
    }

    #[test]
    fn portable_roaming_migration_resumes_after_lost_commit() {
        const CHILD_ROOT: &str = "KEYFERRY_MIGRATION_TEST_CHILD_ROOT";
        const TEST_NAME: &str =
            "provisioning_host::tests::portable_roaming_migration_resumes_after_lost_commit";

        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            let passphrase = b"owner passphrase sentinel value";
            let kit_path = root.join("owner-kit-resume.json");
            let authority_material = load_roaming_material(&root, &kit_path, passphrase)
                .expect("fresh process loads owner authority");
            let journal_path = root.join(RECOVERY_DIR).join(MIGRATION_JOURNAL);
            let migration = load_migration_journal(&journal_path, &authority_material)
                .expect("fresh process loads exact migration journal");
            let mut device = FakeDevice::pending(&migration);
            assert_eq!(
                attempt_journaled_migration(&mut device, &migration),
                Ok(MigrationAttempt::Reconnect)
            );
            assert_eq!(device.transaction_id, migration.transaction_id);
            assert_eq!(device.commit_count, 1);
            assert_eq!(
                attempt_journaled_migration(&mut device, &migration),
                Ok(MigrationAttempt::Active)
            );
            assert_eq!(
                device.commit_count, 1,
                "active reconciliation must not rewrite"
            );
            remove_private_durable(&journal_path).expect("remove completed journal durably");
            return;
        }

        let (root, material) = migration_fixture();
        let journal_path = root.0.join(RECOVERY_DIR).join(MIGRATION_JOURNAL);
        let migration = create_migration_journal(&journal_path, material)
            .expect("publish journal before migration");
        let mut first_process_device = FakeDevice::legacy(&migration.material);
        first_process_device.stop_at_pending_migration = true;
        assert_eq!(
            attempt_journaled_migration(&mut first_process_device, &migration),
            Ok(MigrationAttempt::Reconnect)
        );
        assert_eq!(
            first_process_device.policy_status,
            Some(pending_identity(migration.target))
        );
        assert!(journal_path.is_file());

        let result = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg(TEST_NAME)
            .arg("--exact")
            .arg("--nocapture")
            .env(CHILD_ROOT, &root.0)
            .status()
            .expect("start fresh migration host process");
        assert!(result.success(), "fresh migration host process failed");
        assert!(!journal_path.exists());
    }

    #[test]
    fn roaming_migration_reconciles_lost_ack_without_a_second_commit() {
        let (root, material) = migration_fixture();
        let journal_path = root.0.join(RECOVERY_DIR).join(MIGRATION_JOURNAL);
        let migration = create_migration_journal(&journal_path, material).expect("journal");
        let mut device = FakeDevice::legacy(&migration.material);
        device.lose_commit_response = true;
        assert_eq!(
            attempt_journaled_migration(&mut device, &migration),
            Ok(MigrationAttempt::Reconnect)
        );
        assert_eq!(device.commit_count, 1);
        assert_eq!(
            attempt_journaled_migration(&mut device, &migration),
            Ok(MigrationAttempt::Active)
        );
        assert_eq!(device.commit_count, 1);
    }

    #[test]
    fn migration_journal_conflicts_fail_before_any_transport_write() {
        let (root, material) = migration_fixture();
        let journal_path = root.0.join(RECOVERY_DIR).join(MIGRATION_JOURNAL);
        let migration = create_migration_journal(&journal_path, material).expect("journal");
        let original = fs::read(&journal_path).expect("journal bytes");
        let mut authority = load_roaming_material(
            &root.0,
            &root.0.join("owner-kit-resume.json"),
            b"owner passphrase sentinel value",
        )
        .expect("authority material");

        fs::write(&journal_path, &original[..original.len() / 2]).expect("truncate journal");
        assert!(load_migration_journal(&journal_path, &authority).is_err());

        let mut wrong_device: MigrationJournal =
            serde_json::from_slice(&original).expect("decode journal");
        wrong_device.device_id_hex = hex(&[0x99; 16]);
        fs::write(
            &journal_path,
            serde_json::to_vec(&wrong_device).expect("encode wrong device"),
        )
        .expect("write wrong device journal");
        assert!(load_migration_journal(&journal_path, &authority).is_err());

        let mut wrong_policy: MigrationJournal =
            serde_json::from_slice(&original).expect("decode journal");
        wrong_policy.target_policy_hash_hex = hex(&[0x88; 32]);
        fs::write(
            &journal_path,
            serde_json::to_vec(&wrong_policy).expect("encode wrong policy"),
        )
        .expect("write wrong policy journal");
        assert!(load_migration_journal(&journal_path, &authority).is_err());

        let mut wrong_epoch: MigrationJournal =
            serde_json::from_slice(&original).expect("decode journal");
        wrong_epoch.target_policy_epoch += 1;
        fs::write(
            &journal_path,
            serde_json::to_vec(&wrong_epoch).expect("encode wrong epoch"),
        )
        .expect("write wrong epoch journal");
        assert!(load_migration_journal(&journal_path, &authority).is_err());

        fs::write(&journal_path, &original).expect("restore journal");
        authority.payload[POLICY_EPOCH_OFFSET..POLICY_EPOCH_OFFSET + 8]
            .copy_from_slice(&2_u64.to_be_bytes());
        assert!(load_migration_journal(&journal_path, &authority).is_err());
        assert_eq!(migration.target.sequence, 1);
    }

    #[test]
    fn second_installation_cannot_replace_a_pending_migration_transaction() {
        let (root, material) = migration_fixture();
        let first_path = root.0.join(RECOVERY_DIR).join("migration-first.json");
        let first = create_migration_journal(&first_path, material).expect("first journal");
        let second_material = load_roaming_material(
            &root.0,
            &root.0.join("owner-kit-resume.json"),
            b"owner passphrase sentinel value",
        )
        .expect("second installation material");
        let second_path = root.0.join(RECOVERY_DIR).join("migration-second.json");
        let mut second =
            create_migration_journal(&second_path, second_material).expect("second journal");
        if second.transaction_id == first.transaction_id {
            second.transaction_id[0] ^= 1;
        }
        let mut device = FakeDevice::pending(&first);
        assert!(attempt_journaled_migration(&mut device, &second).is_err());
        assert_eq!(device.policy_status, Some(pending_identity(first.target)));
    }

    #[test]
    fn roaming_status_reports_exact_policy_identity_without_secrets() {
        let (root, legacy, _wifi, _device) = bundle();
        let passphrase = b"owner passphrase sentinel value";
        let kit = owner_kit::create(
            legacy.device_id,
            legacy.provisioning_key,
            passphrase,
            [0x35; 16],
            [0x36; 12],
            [0x37; 16],
        )
        .expect("owner kit");
        let kit_path = root.0.join("owner-kit-status.json");
        fs::write(&kit_path, kit).expect("owner-kit file");
        let roaming =
            load_roaming_material(&root.0, &kit_path, passphrase).expect("roaming material");
        let mut fake = FakeDevice::roaming(&roaming);
        let expected = fake.policy_status.expect("policy identity");
        let mut output = Vec::new();
        status_with(&mut fake, roaming.device_id, &mut output).expect("status");
        let visible = String::from_utf8(output).expect("UTF-8 status");
        assert!(visible.contains("policy_state=active epoch=1 policy=1"));
        assert!(visible.contains(&format!("policy_hash={}", hex(&expected.hash))));
        assert!(!visible.contains(&hex(&roaming.recovery_secret)));
    }

    #[test]
    fn locked_roaming_status_is_read_without_a_challenge() {
        let (_root, material) = migration_fixture();
        let mut fake = FakeDevice::roaming(&material);
        fake.challenge_rejected = true;
        fake.policy_status = Some(PolicyIdentity {
            state: keyferry_protocol::provisioning_policy_state::MALFORMED,
            epoch: 0,
            sequence: 0,
            hash: [0; 32],
        });
        let mut output = Vec::new();

        status_with(&mut fake, material.device_id, &mut output).expect("locked status");

        assert_eq!(fake.operations, vec![provisioning_operation::POLICY_STATUS]);
        let visible = String::from_utf8(output).expect("UTF-8 status");
        assert!(visible.contains("policy_state=malformed"));
        assert!(visible.contains("status=locked"));
    }

    #[test]
    fn initial_policy_recovery_is_read_only_and_requires_an_exact_active_match() {
        let (root, material) = migration_fixture();
        let wifi: WifiConfig = read_json_private(&root.0.join(WIFI_CONFIG)).expect("Wi-Fi config");
        let mut exact = FakeDevice::roaming(&material);
        let recovered = recover_initial_roaming_policy_with(&mut exact, &material, &wifi)
            .expect("exact initial policy is recoverable");
        let decoded: DesiredRoamingPolicy =
            serde_json::from_slice(&recovered).expect("recovered strict policy");
        assert_eq!(decoded.wifi_profiles.len(), 1);
        assert_eq!(decoded.wifi_profiles[0].ssid, wifi.ssid);
        assert_eq!(decoded.wifi_profiles[0].password, wifi.password);
        assert_eq!(decoded.wifi_profiles[0].priority, FIRST_PROFILE_PRIORITY);
        assert!(decoded.revoked_installation_ids.is_empty());
        assert_eq!(
            exact.operations,
            vec![
                provisioning_operation::CHALLENGE,
                provisioning_operation::POLICY_STATUS
            ]
        );
        assert_eq!(exact.commit_count, 0);

        let mut changed = FakeDevice::roaming(&material);
        changed.policy_status.as_mut().unwrap().sequence += 1;
        changed.generation += 1;
        assert_eq!(
            recover_initial_roaming_policy_with(&mut changed, &material, &wifi),
            Err("active policy does not exactly match the recoverable initial policy")
        );
        assert_eq!(changed.commit_count, 0);
    }

    #[test]
    fn roaming_update_uses_device_floor_and_commits_one_complete_policy() {
        let (root, legacy, _wifi, _device) = bundle();
        let passphrase = b"owner passphrase sentinel value";
        let kit = owner_kit::create(
            legacy.device_id,
            legacy.provisioning_key,
            passphrase,
            [0x38; 16],
            [0x39; 12],
            [0x3A; 16],
        )
        .expect("owner kit");
        let kit_path = root.0.join("owner-kit-update.json");
        fs::write(&kit_path, &kit).expect("owner-kit file");
        let initial = load_roaming_material(&root.0, &kit_path, passphrase)
            .expect("initial roaming material");
        let authority =
            owner_kit::unlock_device_authority(&kit, passphrase).expect("owner authority");
        let desired = DesiredRoamingPolicy {
            schema_version: 1,
            wifi_profiles: vec![DesiredWifiProfile {
                ssid: "new-network-sentinel".to_owned(),
                password: "new-password-sentinel".to_owned(),
                priority: 9,
            }],
            revoked_installation_ids: vec![hex(&[0x52; 16]), hex(&[0x41; 16])],
        };
        let mut fake = FakeDevice::roaming(&initial);
        let previous = fake.policy_status.expect("initial policy identity");
        let mut output = Vec::new();
        update_roaming_with(&mut fake, &authority, &desired, &mut output).expect("roaming update");
        assert_eq!(fake.commit_count, 1);
        assert_eq!(&fake.payload[72..80], &2_u64.to_be_bytes());
        assert_eq!(&fake.payload[80..88], &1_u64.to_be_bytes());
        assert_eq!(&fake.payload[120..152], &previous.hash);
        let revocation_offset =
            keyferry_protocol::roaming::ROAMING_CONFIG_FIXED_HEADER_BYTES + MAX_CA_CERTIFICATE_LEN;
        assert_eq!(
            &fake.payload[revocation_offset..revocation_offset + 16],
            &[0x41; 16]
        );
        assert_eq!(
            &fake.payload[revocation_offset + 16..revocation_offset + 32],
            &[0x52; 16]
        );
        let visible = String::from_utf8(output).expect("UTF-8 status");
        assert!(visible.contains("policy=2"));
        assert!(visible.contains("status=updated"));
        assert!(!visible.contains("new-network-sentinel"));
        assert!(!visible.contains("new-password-sentinel"));
        assert!(!visible.contains(&hex(&legacy.provisioning_key)));
    }

    #[test]
    fn selected_device_recovery_uses_its_authority_and_shared_network_source() {
        let (root, legacy, wifi, _device) = bundle();
        let passphrase = b"owner passphrase sentinel value";
        let first = owner_kit::create(
            legacy.device_id,
            legacy.provisioning_key,
            passphrase,
            [0x32; 16],
            [0x33; 12],
            [0x31; 16],
        )
        .expect("owner kit");
        let second_device = [0x72; 16];
        let second_secret = [0x73; 32];
        let expanded = owner_kit::add_device(
            &first,
            passphrase,
            second_device,
            second_secret,
            [0x74; 16],
            [0x75; 12],
        )
        .expect("expanded owner kit");
        let kit_path = root.0.join("owner-kit-multi.json");
        fs::write(&kit_path, expanded).expect("owner-kit file");

        let kit_bytes = fs::read(&kit_path).expect("owner-kit bytes");
        assert_eq!(
            selected_owner_authority(&kit_bytes, b"wrong password", Some(second_device))
                .err()
                .expect("wrong password"),
            "owner-kit password is incorrect"
        );
        assert_eq!(
            selected_owner_authority(&kit_bytes, passphrase, Some([0x76; 16]))
                .err()
                .expect("absent device"),
            "selected device is absent from the owner kit or its authority is invalid"
        );

        let selected =
            load_roaming_material_selected(&root.0, &kit_path, passphrase, Some(second_device))
                .expect("selected roaming material");

        assert_eq!(selected.device_id, second_device);
        assert_eq!(selected.recovery_secret, second_secret);
        assert_eq!(&selected.payload[..16], &second_device);
        let wifi_offset = keyferry_protocol::roaming::ROAMING_CONFIG_FIXED_HEADER_BYTES
            + MAX_CA_CERTIFICATE_LEN
            + MAX_REVOKED_INSTALLATIONS * 16;
        assert_eq!(selected.payload[wifi_offset], WPA2_PERSONAL);
        assert_eq!(selected.payload[wifi_offset + 3] as usize, wifi.ssid.len());
    }

    #[test]
    fn roaming_update_rejects_stale_authority_and_duplicate_revocation_before_commit() {
        let (root, legacy, _wifi, _device) = bundle();
        let passphrase = b"owner passphrase sentinel value";
        let kit = owner_kit::create(
            legacy.device_id,
            legacy.provisioning_key,
            passphrase,
            [0x3B; 16],
            [0x3C; 12],
            [0x3D; 16],
        )
        .expect("owner kit");
        let kit_path = root.0.join("owner-kit-update-negative.json");
        fs::write(&kit_path, &kit).expect("owner-kit file");
        let initial = load_roaming_material(&root.0, &kit_path, passphrase)
            .expect("initial roaming material");
        let mut authority =
            owner_kit::unlock_device_authority(&kit, passphrase).expect("owner authority");
        let mut fake = FakeDevice::roaming(&initial);
        authority.authority_epoch = 2;
        let empty = DesiredRoamingPolicy {
            schema_version: 1,
            wifi_profiles: Vec::new(),
            revoked_installation_ids: Vec::new(),
        };
        assert_eq!(
            update_roaming_with(&mut fake, &authority, &empty, &mut Vec::new()),
            Err("owner kit authority epoch does not match the device")
        );
        assert_eq!(fake.commit_count, 0);

        authority.authority_epoch = 1;
        let duplicate = DesiredRoamingPolicy {
            schema_version: 1,
            wifi_profiles: Vec::new(),
            revoked_installation_ids: vec![hex(&[0x61; 16]), hex(&[0x61; 16])],
        };
        assert_eq!(
            update_roaming_with(&mut fake, &authority, &duplicate, &mut Vec::new()),
            Err("roaming policy contains a duplicate revocation")
        );
        assert_eq!(fake.commit_count, 0);

        let uppercase = DesiredRoamingPolicy {
            schema_version: 1,
            wifi_profiles: Vec::new(),
            revoked_installation_ids: vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()],
        };
        assert_eq!(
            update_roaming_with(&mut fake, &authority, &uppercase, &mut Vec::new()),
            Err("revoked installation ID is invalid")
        );
        assert_eq!(fake.commit_count, 0);
    }

    #[test]
    fn roaming_update_reconciles_a_lost_commit_response_without_retrying() {
        let (root, legacy, _wifi, _device) = bundle();
        let passphrase = b"owner passphrase sentinel value";
        let kit = owner_kit::create(
            legacy.device_id,
            legacy.provisioning_key,
            passphrase,
            [0x71; 16],
            [0x72; 12],
            [0x73; 16],
        )
        .expect("owner kit");
        let kit_path = root.0.join("owner-kit-reconcile.json");
        fs::write(&kit_path, &kit).expect("owner-kit file");
        let initial = load_roaming_material(&root.0, &kit_path, passphrase)
            .expect("initial roaming material");
        let authority =
            owner_kit::unlock_device_authority(&kit, passphrase).expect("owner authority");
        let desired = DesiredRoamingPolicy {
            schema_version: 1,
            wifi_profiles: Vec::new(),
            revoked_installation_ids: Vec::new(),
        };
        let mut fake = FakeDevice::roaming(&initial);
        let prepared =
            prepare_roaming_update(&mut fake, &authority, &desired).expect("prepare update");
        fake.lose_commit_response = true;
        assert_eq!(
            commit_roaming_update(&mut fake, &prepared, &mut Vec::new()),
            Err(CommitError::Unknown)
        );
        assert_eq!(fake.commit_count, 1);

        let observed =
            query_policy_identity(&mut fake, authority.device_id).expect("reconciled status");
        let mut output = Vec::new();
        reconcile_roaming_observation(&authority.device_id, &prepared, observed, &mut output)
            .expect("committed update must reconcile");
        assert_eq!(fake.commit_count, 1);
        let visible = String::from_utf8(output).expect("UTF-8 status");
        assert!(visible.contains("policy=2"));
        assert!(visible.contains("status=updated-reconciled"));
    }

    #[test]
    fn lost_commit_response_is_unknown_and_is_never_retried() {
        let (_root, material, _wifi, _device) = bundle();
        let mut fake = FakeDevice::new(&material);
        fake.lose_commit_response = true;
        let error = provision_with(&mut fake, &material, &mut Vec::new())
            .expect_err("lost commit response must fail");
        assert_eq!(
            error,
            "configuration commit outcome is unknown; do not retry, reconnect and run status"
        );
        assert_eq!(fake.commit_count, 1);
        assert_eq!(fake.generation, 1);
    }

    #[test]
    fn mismatched_device_is_rejected_before_begin() {
        let (_root, material, _wifi, _device) = bundle();
        let mut fake = FakeDevice::new(&material);
        fake.device_id[0] ^= 1;
        let error = provision_with(&mut fake, &material, &mut Vec::new())
            .expect_err("identity mismatch must fail");
        assert_eq!(
            error,
            "connected device identity does not match the private bundle"
        );
        assert!(fake.payload.is_empty());
        assert_eq!(fake.commit_count, 0);
    }
}
