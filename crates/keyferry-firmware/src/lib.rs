#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const UPDATE_MANIFEST_SCHEMA: &str = "keyferry.firmware-update-manifest.v1";
pub const UPDATE_PLAN_SCHEMA: &str = "keyferry.firmware-update-plan.v1";
pub const EXACT_UPDATE_PLAN_SCHEMA: &str = "keyferry.firmware-update-exact-plan.v1";
pub const CLONE_SPLIT_BINDING_SCHEMA: &str = "keyferry.clone-split-binding.v1";
pub const CLONE_SPLIT_PLAN_SCHEMA: &str = "keyferry.clone-split-plan.v1";
pub const EXACT_UNIT_RECORD_SCHEMA: &str = "keyferry.exact-unit-record.v1";
pub const ROM_PROBE_RESULT_SCHEMA: &str = "keyferry.rom-probe-result.v1";
pub const MAX_METADATA_BYTES: usize = 65_536;
pub const MIN_APPLICATION_HEADROOM_BYTES: u64 = 32_768;
pub const APPLICATION_OFFSET: u64 = 0x1_0000;
pub const APPLICATION_PARTITION_SIZE: u64 = 0x10_0000;
pub const CLONE_SPLIT_HEADER_BYTES: u64 = 0x1000;
pub const CLONE_SPLIT_STATE_OFFSET: u64 = 0x11_0000;
pub const CLONE_SPLIT_STATE_BYTES: u64 = 0xB000;
pub const CLONE_SPLIT_PROTECTED_SUFFIX_OFFSET: u64 = 0x11_B000;
pub const CLONE_SPLIT_PROTECTED_SUFFIX_BYTES: u64 = 0x1000;
pub const BOARD_COMPATIBILITY_ID: u32 =
    keyferry_protocol::firmware_identity::BOARD_WAVESHARE_GEEK_V1_1_REFERENCE;
pub const PROJECT_NAME: &str = "keyferry_hil_endpoint";
pub const PINNED_ESP_IDF_VERSION: &str = "6.0.3";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirmwareUpdateManifestV1 {
    pub schema: String,
    pub identity: FirmwareIdentity,
    pub target: FirmwareTarget,
    pub image: FirmwareImage,
    pub preserved: PreservedArtifacts,
    pub tools: BuildTools,
    pub write: FirmwareWrite,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirmwareIdentity {
    pub project_name: String,
    pub version: String,
    pub source_revision: String,
    pub protocol_major: u8,
    pub protocol_min_minor: u8,
    pub protocol_max_minor: u8,
    pub board_compatibility_id: u32,
    pub elf_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirmwareTarget {
    pub board_profile: String,
    pub board_manifest_sha256: String,
    pub partition_map_sha256: String,
    pub chip: String,
    pub soc_revision: String,
    pub flash_manufacturer_id: String,
    pub flash_device_id: String,
    pub flash_size_bytes: u64,
    pub secure_boot: bool,
    pub flash_encryption: bool,
    pub secure_download_mode: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirmwareImage {
    pub file: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub elf_file: String,
    pub elf_size_bytes: u64,
    pub elf_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreservedArtifacts {
    pub bootloader_file: String,
    pub bootloader_size_bytes: u64,
    pub bootloader_sha256: String,
    pub partition_table_file: String,
    pub partition_table_size_bytes: u64,
    pub partition_table_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildTools {
    pub esp_idf_version: String,
    pub esptool_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirmwareWrite {
    pub offset: u64,
    pub partition_size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FirmwareUpdatePlanV1 {
    pub schema: &'static str,
    pub mode: &'static str,
    pub apply_available: bool,
    pub manifest_sha256: String,
    pub board_manifest_sha256: String,
    pub partition_map_sha256: String,
    pub target: PlannedTarget,
    pub firmware: PlannedFirmware,
    pub write: PlannedWrite,
    pub protected_regions: Vec<ProtectedRegion>,
    pub blocked_on: Vec<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlannedTarget {
    pub device_label: String,
    pub board_profile: String,
    pub chip: String,
    pub soc_revision: String,
    pub flash_manufacturer_id: String,
    pub flash_device_id: String,
    pub flash_size_bytes: u64,
    pub secure_boot: bool,
    pub flash_encryption: bool,
    pub secure_download_mode: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedFirmware {
    pub project_name: String,
    pub version: String,
    pub source_revision: String,
    pub protocol_major: u8,
    pub protocol_min_minor: u8,
    pub protocol_max_minor: u8,
    pub board_compatibility_id: u32,
    pub elf_sha256: String,
    pub image_file: String,
    pub image_size_bytes: u64,
    pub image_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedWrite {
    pub chip: String,
    pub offset: u64,
    pub length: u64,
    pub partition_size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedRegion {
    pub name: String,
    pub offset: u64,
    pub size_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    MetadataLimit,
    ManifestSyntax,
    ManifestSchema,
    ManifestValue,
    BoardSyntax,
    BoardNotQualified,
    BoardMismatch,
    RecoveryNotQualified,
    SecurityMismatch,
    PartitionSyntax,
    PartitionMismatch,
    ImageEmpty,
    ImageSize,
    ImageHash,
    ElfHash,
    PreservedArtifactHash,
    ImageDescriptor,
    ExactUnitRecord,
    RomProbe,
    ExactUnitMismatch,
    PlanAuthorization,
    CloneSplitBinding,
    Serialization,
}

impl PlanError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MetadataLimit => "firmware.metadata_limit",
            Self::ManifestSyntax => "firmware.manifest_syntax",
            Self::ManifestSchema => "firmware.manifest_schema",
            Self::ManifestValue => "firmware.manifest_value",
            Self::BoardSyntax => "firmware.board_manifest_syntax",
            Self::BoardNotQualified => "firmware.board_not_qualified",
            Self::BoardMismatch => "firmware.board_mismatch",
            Self::RecoveryNotQualified => "firmware.recovery_not_qualified",
            Self::SecurityMismatch => "firmware.security_mismatch",
            Self::PartitionSyntax => "firmware.partition_syntax",
            Self::PartitionMismatch => "firmware.partition_mismatch",
            Self::ImageEmpty => "firmware.image_empty",
            Self::ImageSize => "firmware.image_size",
            Self::ImageHash => "firmware.image_hash",
            Self::ElfHash => "firmware.elf_hash",
            Self::PreservedArtifactHash => "firmware.preserved_artifact_hash",
            Self::ImageDescriptor => "firmware.image_descriptor",
            Self::ExactUnitRecord => "firmware.exact_unit_record",
            Self::RomProbe => "firmware.rom_probe",
            Self::ExactUnitMismatch => "firmware.exact_unit_mismatch",
            Self::PlanAuthorization => "firmware.plan_authorization",
            Self::CloneSplitBinding => "firmware.clone_split_binding",
            Self::Serialization => "firmware.serialization",
        }
    }
}

#[derive(Debug, Deserialize)]
struct BoardManifest {
    manifest_version: u16,
    status: String,
    device_label: String,
    identity: BoardIdentity,
    flash: BoardFlash,
    security: BoardSecurity,
    pins: BoardPins,
    recovery: BoardRecovery,
}

#[derive(Debug, Deserialize)]
struct BoardIdentity {
    soc: String,
    soc_revision: String,
}

#[derive(Debug, Deserialize)]
struct BoardFlash {
    manufacturer_id: String,
    device_id: String,
    size_bytes: u64,
    partition_table_offset: u64,
}

#[derive(Debug, Deserialize)]
struct BoardSecurity {
    secure_boot: bool,
    flash_encryption: bool,
    secure_download_mode: bool,
    efuse_before_sha256: String,
    efuse_after_sha256: String,
}

#[derive(Debug, Deserialize)]
struct BoardPins {
    profile: String,
    compatibility_id: u32,
}

#[derive(Debug, Deserialize)]
struct BoardRecovery {
    cycle_a_passed: bool,
    cycle_b_passed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Partition {
    name: String,
    kind: String,
    subtype: String,
    offset: u64,
    size: u64,
}

pub fn build_update_plan(
    manifest_bytes: &[u8],
    board_manifest_bytes: &[u8],
    partition_map_bytes: &[u8],
    image: &[u8],
) -> Result<FirmwareUpdatePlanV1, PlanError> {
    if manifest_bytes.len() > MAX_METADATA_BYTES
        || board_manifest_bytes.len() > MAX_METADATA_BYTES
        || partition_map_bytes.len() > MAX_METADATA_BYTES
    {
        return Err(PlanError::MetadataLimit);
    }

    // Deserialize directly into the strict struct. Going through Value first silently
    // collapses duplicate object keys before serde can reject them.
    let manifest: FirmwareUpdateManifestV1 =
        serde_json::from_slice(manifest_bytes).map_err(|error| {
            if error.is_syntax() || error.is_eof() {
                PlanError::ManifestSyntax
            } else {
                PlanError::ManifestSchema
            }
        })?;
    validate_manifest_values(&manifest)?;
    let board: BoardManifest =
        toml::from_slice(board_manifest_bytes).map_err(|_| PlanError::BoardSyntax)?;
    if manifest.target.board_manifest_sha256 != sha256_hex(board_manifest_bytes) {
        return Err(PlanError::BoardMismatch);
    }
    if manifest.target.partition_map_sha256 != sha256_hex(partition_map_bytes) {
        return Err(PlanError::PartitionMismatch);
    }
    validate_board(&board, &manifest)?;
    let partitions = parse_partitions(partition_map_bytes)?;
    let factory = validate_partition_map(&partitions, &board, &manifest)?;
    validate_image(image, &manifest, factory.size)?;

    let canonical_manifest = serde_json::to_vec(&manifest).map_err(|_| PlanError::Serialization)?;
    let protected_regions = std::iter::once(ProtectedRegion {
        name: "bootloader_and_partition_table".to_owned(),
        offset: 0,
        size_bytes: factory.offset,
    })
    .chain(
        partitions
            .iter()
            .filter(|partition| partition.name != factory.name)
            .map(|partition| ProtectedRegion {
                name: partition.name.clone(),
                offset: partition.offset,
                size_bytes: partition.size,
            }),
    )
    .collect();

    Ok(FirmwareUpdatePlanV1 {
        schema: UPDATE_PLAN_SCHEMA,
        mode: "PLAN_ONLY",
        apply_available: false,
        manifest_sha256: sha256_hex(&canonical_manifest),
        board_manifest_sha256: sha256_hex(board_manifest_bytes),
        partition_map_sha256: sha256_hex(partition_map_bytes),
        target: PlannedTarget {
            device_label: board.device_label,
            board_profile: manifest.target.board_profile.clone(),
            chip: manifest.target.chip.clone(),
            soc_revision: manifest.target.soc_revision.clone(),
            flash_manufacturer_id: manifest.target.flash_manufacturer_id.clone(),
            flash_device_id: manifest.target.flash_device_id.clone(),
            flash_size_bytes: manifest.target.flash_size_bytes,
            secure_boot: manifest.target.secure_boot,
            flash_encryption: manifest.target.flash_encryption,
            secure_download_mode: manifest.target.secure_download_mode,
        },
        firmware: PlannedFirmware {
            project_name: manifest.identity.project_name.clone(),
            version: manifest.identity.version.clone(),
            source_revision: manifest.identity.source_revision.clone(),
            protocol_major: manifest.identity.protocol_major,
            protocol_min_minor: manifest.identity.protocol_min_minor,
            protocol_max_minor: manifest.identity.protocol_max_minor,
            board_compatibility_id: manifest.identity.board_compatibility_id,
            elf_sha256: manifest.identity.elf_sha256.clone(),
            image_file: manifest.image.file.clone(),
            image_size_bytes: manifest.image.size_bytes,
            image_sha256: manifest.image.sha256.clone(),
        },
        write: PlannedWrite {
            chip: manifest.target.chip.clone(),
            offset: manifest.write.offset,
            length: manifest.image.size_bytes,
            partition_size_bytes: manifest.write.partition_size_bytes,
        },
        protected_regions,
        blocked_on: vec![
            "authenticated_device_safe_state",
            "local_rom_identity_probe",
            "exact_hash_owner_approval",
            "apply_implementation_and_recovery_gate",
        ],
    })
}

fn validate_manifest_values(manifest: &FirmwareUpdateManifestV1) -> Result<(), PlanError> {
    if manifest.schema != UPDATE_MANIFEST_SCHEMA
        || manifest.identity.project_name != PROJECT_NAME
        || !valid_installable_release(&manifest.identity.version)
        || !lower_hex(&manifest.identity.source_revision, 40)
        || manifest.identity.protocol_major == 0
        || manifest.identity.protocol_min_minor > manifest.identity.protocol_max_minor
        || !matches!(
            manifest.identity.board_compatibility_id,
            keyferry_protocol::firmware_identity::BOARD_WAVESHARE_GEEK_V1_1_REFERENCE
                | keyferry_protocol::firmware_identity::BOARD_LILYGO_T_DONGLE_S3
        )
        || !lower_hex(&manifest.identity.elf_sha256, 64)
        || manifest.target.board_profile.is_empty()
        || manifest.target.board_profile.len() > 64
        || !lower_hex(&manifest.target.board_manifest_sha256, 64)
        || !lower_hex(&manifest.target.partition_map_sha256, 64)
        || manifest.target.chip != "esp32s3"
        || manifest.target.soc_revision.is_empty()
        || manifest.target.soc_revision.len() > 32
        || !lower_prefixed_hex(&manifest.target.flash_manufacturer_id, 2)
        || !lower_prefixed_hex(&manifest.target.flash_device_id, 4)
        || manifest.target.flash_size_bytes == 0
        || manifest.image.file != "keyferry_hil_endpoint.bin"
        || !lower_hex(&manifest.image.sha256, 64)
        || manifest.image.elf_file != "keyferry_hil_endpoint.elf"
        || manifest.image.elf_size_bytes == 0
        || !lower_hex(&manifest.image.elf_sha256, 64)
        || manifest.image.elf_sha256 != manifest.identity.elf_sha256
        || manifest.preserved.bootloader_file != "bootloader.bin"
        || manifest.preserved.bootloader_size_bytes == 0
        || !lower_hex(&manifest.preserved.bootloader_sha256, 64)
        || manifest.preserved.partition_table_file != "partition-table.bin"
        || manifest.preserved.partition_table_size_bytes == 0
        || !lower_hex(&manifest.preserved.partition_table_sha256, 64)
        || manifest.tools.esp_idf_version != PINNED_ESP_IDF_VERSION
        || !valid_release(&manifest.tools.esptool_version)
        || manifest.write.offset != APPLICATION_OFFSET
        || manifest.write.partition_size_bytes != APPLICATION_PARTITION_SIZE
    {
        return Err(if manifest.schema != UPDATE_MANIFEST_SCHEMA {
            PlanError::ManifestSchema
        } else {
            PlanError::ManifestValue
        });
    }
    Ok(())
}

fn validate_board(
    board: &BoardManifest,
    manifest: &FirmwareUpdateManifestV1,
) -> Result<(), PlanError> {
    if board.manifest_version != 2
        || !matches!(
            board.status.as_str(),
            "RECOVERY_QUALIFIED" | "OWNER_WAIVED_REDUNDANT_RECOVERY"
        )
    {
        return Err(PlanError::BoardNotQualified);
    }
    let recovery_qualified = board.status == "RECOVERY_QUALIFIED"
        && board.recovery.cycle_a_passed
        && board.recovery.cycle_b_passed;
    let exact_lilygo_waiver = board.status == "OWNER_WAIVED_REDUNDANT_RECOVERY"
        && board.pins.compatibility_id
            == keyferry_protocol::firmware_identity::BOARD_LILYGO_T_DONGLE_S3
        && board.recovery.cycle_a_passed
        && !board.recovery.cycle_b_passed;
    if !recovery_qualified && !exact_lilygo_waiver {
        return Err(PlanError::RecoveryNotQualified);
    }
    if board.pins.profile != manifest.target.board_profile
        || board.pins.compatibility_id != manifest.identity.board_compatibility_id
        || board.identity.soc != "ESP32-S3 QFN56"
        || manifest.target.chip != "esp32s3"
        || board.identity.soc_revision != manifest.target.soc_revision
        || board.flash.manufacturer_id.to_ascii_lowercase() != manifest.target.flash_manufacturer_id
        || board.flash.device_id.to_ascii_lowercase() != manifest.target.flash_device_id
        || board.flash.size_bytes != manifest.target.flash_size_bytes
    {
        return Err(PlanError::BoardMismatch);
    }
    if board.security.secure_boot != manifest.target.secure_boot
        || board.security.flash_encryption != manifest.target.flash_encryption
        || board.security.secure_download_mode != manifest.target.secure_download_mode
        || board.security.secure_boot
        || board.security.flash_encryption
        || board.security.secure_download_mode
        || !upper_hex(&board.security.efuse_before_sha256, 64)
        || board.security.efuse_before_sha256 != board.security.efuse_after_sha256
    {
        return Err(PlanError::SecurityMismatch);
    }
    Ok(())
}

fn validate_partition_map<'a>(
    partitions: &'a [Partition],
    board: &BoardManifest,
    manifest: &FirmwareUpdateManifestV1,
) -> Result<&'a Partition, PlanError> {
    let factory = partitions
        .iter()
        .find(|partition| partition.name == "factory")
        .ok_or(PlanError::PartitionMismatch)?;
    if factory.kind != "app"
        || factory.subtype != "factory"
        || factory.offset != manifest.write.offset
        || factory.size != manifest.write.partition_size_bytes
        || board.flash.partition_table_offset >= factory.offset
        || partitions.len() != 4
        || !["factory", "kf_cfg_a", "kf_cfg_b", "nvs"]
            .iter()
            .all(|name| partitions.iter().any(|partition| partition.name == *name))
    {
        return Err(PlanError::PartitionMismatch);
    }
    for (index, left) in partitions.iter().enumerate() {
        let left_end = left
            .offset
            .checked_add(left.size)
            .ok_or(PlanError::PartitionMismatch)?;
        if left.size == 0 || left_end > board.flash.size_bytes {
            return Err(PlanError::PartitionMismatch);
        }
        for right in &partitions[index + 1..] {
            let right_end = right
                .offset
                .checked_add(right.size)
                .ok_or(PlanError::PartitionMismatch)?;
            if left.offset < right_end && right.offset < left_end {
                return Err(PlanError::PartitionMismatch);
            }
        }
    }
    Ok(factory)
}

fn validate_image(
    image: &[u8],
    manifest: &FirmwareUpdateManifestV1,
    partition_size: u64,
) -> Result<(), PlanError> {
    if image.is_empty() {
        return Err(PlanError::ImageEmpty);
    }
    let length = u64::try_from(image.len()).map_err(|_| PlanError::ImageSize)?;
    if length != manifest.image.size_bytes
        || length > partition_size.saturating_sub(MIN_APPLICATION_HEADROOM_BYTES)
    {
        return Err(PlanError::ImageSize);
    }
    if sha256_hex(image) != manifest.image.sha256 {
        return Err(PlanError::ImageHash);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedUpdatePackage {
    manifest_bytes: Vec<u8>,
    board_manifest_bytes: Vec<u8>,
    partition_map_bytes: Vec<u8>,
    image: Vec<u8>,
    base_plan: FirmwareUpdatePlanV1,
}

impl PreparedUpdatePackage {
    #[must_use]
    pub fn image(&self) -> &[u8] {
        &self.image
    }

    #[must_use]
    pub fn plan_only(&self) -> &FirmwareUpdatePlanV1 {
        &self.base_plan
    }

    pub fn rom_probe_requirements(&self) -> Result<RomProbeRequirements, PlanError> {
        let manifest: FirmwareUpdateManifestV1 =
            serde_json::from_slice(&self.manifest_bytes).map_err(|_| PlanError::ManifestSchema)?;
        let board: BoardManifest =
            toml::from_slice(&self.board_manifest_bytes).map_err(|_| PlanError::BoardSyntax)?;
        Ok(RomProbeRequirements {
            bootloader_offset: 0,
            bootloader_size_bytes: manifest.preserved.bootloader_size_bytes,
            partition_table_offset: board.flash.partition_table_offset,
            partition_table_size_bytes: manifest.preserved.partition_table_size_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RomProbeRequirements {
    pub bootloader_offset: u64,
    pub bootloader_size_bytes: u64,
    pub partition_table_offset: u64,
    pub partition_table_size_bytes: u64,
}

pub fn prepare_update_package(
    manifest_bytes: &[u8],
    board_manifest_bytes: &[u8],
    partition_map_bytes: &[u8],
    image: &[u8],
    elf: &[u8],
    bootloader: &[u8],
    partition_table: &[u8],
) -> Result<PreparedUpdatePackage, PlanError> {
    let base_plan = build_update_plan(
        manifest_bytes,
        board_manifest_bytes,
        partition_map_bytes,
        image,
    )?;
    let manifest: FirmwareUpdateManifestV1 =
        serde_json::from_slice(manifest_bytes).map_err(|_| PlanError::ManifestSchema)?;
    if elf.is_empty()
        || u64::try_from(elf.len()).map_err(|_| PlanError::ElfHash)?
            != manifest.image.elf_size_bytes
        || sha256_hex(elf) != manifest.image.elf_sha256
    {
        return Err(PlanError::ElfHash);
    }
    if bootloader.is_empty()
        || partition_table.is_empty()
        || u64::try_from(bootloader.len()).map_err(|_| PlanError::PreservedArtifactHash)?
            != manifest.preserved.bootloader_size_bytes
        || u64::try_from(partition_table.len()).map_err(|_| PlanError::PreservedArtifactHash)?
            != manifest.preserved.partition_table_size_bytes
        || sha256_hex(bootloader) != manifest.preserved.bootloader_sha256
        || sha256_hex(partition_table) != manifest.preserved.partition_table_sha256
    {
        return Err(PlanError::PreservedArtifactHash);
    }
    validate_app_descriptor(image, &manifest)?;
    Ok(PreparedUpdatePackage {
        manifest_bytes: manifest_bytes.to_vec(),
        board_manifest_bytes: board_manifest_bytes.to_vec(),
        partition_map_bytes: partition_map_bytes.to_vec(),
        image: image.to_vec(),
        base_plan,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestMetadata<'a> {
    pub source_revision: &'a str,
    pub esptool_version: &'a str,
}

pub fn generate_update_manifest(
    metadata: ManifestMetadata<'_>,
    board_manifest_bytes: &[u8],
    partition_map_bytes: &[u8],
    image: &[u8],
    elf: &[u8],
    bootloader: &[u8],
    partition_table: &[u8],
) -> Result<FirmwareUpdateManifestV1, PlanError> {
    if board_manifest_bytes.len() > MAX_METADATA_BYTES
        || partition_map_bytes.len() > MAX_METADATA_BYTES
        || !lower_hex(metadata.source_revision, 40)
        || !valid_release(metadata.esptool_version)
    {
        return Err(PlanError::ManifestValue);
    }
    let board: BoardManifest =
        toml::from_slice(board_manifest_bytes).map_err(|_| PlanError::BoardSyntax)?;
    let partitions = parse_partitions(partition_map_bytes)?;
    let factory = partitions
        .iter()
        .find(|partition| partition.name == "factory")
        .ok_or(PlanError::PartitionMismatch)?;
    let descriptor = app_descriptor(image)?;
    if descriptor.project_name != PROJECT_NAME
        || !valid_installable_release(&descriptor.version)
        || descriptor.idf_version != format!("v{PINNED_ESP_IDF_VERSION}")
        || sha256_hex(elf) != descriptor.elf_sha256
    {
        return Err(PlanError::ImageDescriptor);
    }
    let manifest = FirmwareUpdateManifestV1 {
        schema: UPDATE_MANIFEST_SCHEMA.to_owned(),
        identity: FirmwareIdentity {
            project_name: descriptor.project_name,
            version: descriptor.version,
            source_revision: metadata.source_revision.to_owned(),
            protocol_major: keyferry_protocol::VERSION_MAJOR,
            protocol_min_minor: keyferry_protocol::VERSION_MINOR,
            protocol_max_minor: keyferry_protocol::VERSION_MINOR,
            board_compatibility_id: board.pins.compatibility_id,
            elf_sha256: descriptor.elf_sha256.clone(),
        },
        target: FirmwareTarget {
            board_profile: board.pins.profile.clone(),
            board_manifest_sha256: sha256_hex(board_manifest_bytes),
            partition_map_sha256: sha256_hex(partition_map_bytes),
            chip: "esp32s3".to_owned(),
            soc_revision: board.identity.soc_revision.clone(),
            flash_manufacturer_id: board.flash.manufacturer_id.to_ascii_lowercase(),
            flash_device_id: board.flash.device_id.to_ascii_lowercase(),
            flash_size_bytes: board.flash.size_bytes,
            secure_boot: board.security.secure_boot,
            flash_encryption: board.security.flash_encryption,
            secure_download_mode: board.security.secure_download_mode,
        },
        image: FirmwareImage {
            file: "keyferry_hil_endpoint.bin".to_owned(),
            size_bytes: u64::try_from(image.len()).map_err(|_| PlanError::ImageSize)?,
            sha256: sha256_hex(image),
            elf_file: "keyferry_hil_endpoint.elf".to_owned(),
            elf_size_bytes: u64::try_from(elf.len()).map_err(|_| PlanError::ElfHash)?,
            elf_sha256: descriptor.elf_sha256,
        },
        preserved: PreservedArtifacts {
            bootloader_file: "bootloader.bin".to_owned(),
            bootloader_size_bytes: u64::try_from(bootloader.len())
                .map_err(|_| PlanError::PreservedArtifactHash)?,
            bootloader_sha256: sha256_hex(bootloader),
            partition_table_file: "partition-table.bin".to_owned(),
            partition_table_size_bytes: u64::try_from(partition_table.len())
                .map_err(|_| PlanError::PreservedArtifactHash)?,
            partition_table_sha256: sha256_hex(partition_table),
        },
        tools: BuildTools {
            esp_idf_version: PINNED_ESP_IDF_VERSION.to_owned(),
            esptool_version: metadata.esptool_version.to_owned(),
        },
        write: FirmwareWrite {
            offset: factory.offset,
            partition_size_bytes: factory.size,
        },
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|_| PlanError::Serialization)?;
    prepare_update_package(
        &manifest_bytes,
        board_manifest_bytes,
        partition_map_bytes,
        image,
        elf,
        bootloader,
        partition_table,
    )?;
    Ok(manifest)
}

struct AppDescriptor {
    version: String,
    project_name: String,
    idf_version: String,
    elf_sha256: String,
}

fn app_descriptor(image: &[u8]) -> Result<AppDescriptor, PlanError> {
    const MAGIC: [u8; 4] = 0xABCD_5432_u32.to_le_bytes();
    const DESCRIPTOR_LEN: usize = 256;
    let mut matches = image
        .windows(MAGIC.len())
        .enumerate()
        .filter_map(|(index, candidate)| (candidate == MAGIC).then_some(index));
    let offset = matches.next().ok_or(PlanError::ImageDescriptor)?;
    if matches.next().is_some() || image.len().saturating_sub(offset) < DESCRIPTOR_LEN {
        return Err(PlanError::ImageDescriptor);
    }
    let descriptor = &image[offset..offset + DESCRIPTOR_LEN];
    Ok(AppDescriptor {
        version: nul_padded_text(&descriptor[16..48])?.to_owned(),
        project_name: nul_padded_text(&descriptor[48..80])?.to_owned(),
        idf_version: nul_padded_text(&descriptor[112..144])?.to_owned(),
        elf_sha256: hex_encode(&descriptor[144..176]),
    })
}

fn validate_app_descriptor(
    image: &[u8],
    manifest: &FirmwareUpdateManifestV1,
) -> Result<(), PlanError> {
    let descriptor = app_descriptor(image)?;
    if descriptor.version != manifest.identity.version
        || descriptor.project_name != manifest.identity.project_name
        || descriptor.idf_version != format!("v{}", manifest.tools.esp_idf_version)
        || descriptor.elf_sha256 != manifest.identity.elf_sha256
    {
        return Err(PlanError::ImageDescriptor);
    }
    Ok(())
}

fn nul_padded_text(field: &[u8]) -> Result<&str, PlanError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(PlanError::ImageDescriptor);
    }
    std::str::from_utf8(&field[..end]).map_err(|_| PlanError::ImageDescriptor)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactUnitObservation {
    pub port: String,
    pub unit_binding_sha256: String,
    pub chip: String,
    pub soc_revision: String,
    pub flash_manufacturer_id: String,
    pub flash_device_id: String,
    pub flash_size_bytes: u64,
    pub secure_boot: bool,
    pub flash_encryption: bool,
    pub secure_download_mode: bool,
    pub efuse_sha256: String,
    pub bootloader_sha256: String,
    pub partition_table_sha256: String,
    pub partition_map_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactUnitRecordV1 {
    pub schema: String,
    pub device_label: String,
    pub rom_mac: String,
    pub chip: String,
    pub soc_revision: String,
    pub flash_manufacturer_id: String,
    pub flash_device_id: String,
    pub flash_size_bytes: u64,
    pub secure_boot: bool,
    pub flash_encryption: bool,
    pub secure_download_mode: bool,
    pub board_manifest_sha256: String,
    pub partition_map_sha256: String,
    pub efuse_sha256: String,
    pub qualified_recovery_cycles: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RomProbeResultV1 {
    pub schema: String,
    pub mode: String,
    pub port: String,
    pub rom_mac: String,
    pub chip: String,
    pub soc_revision: String,
    pub flash_manufacturer_id: String,
    pub flash_device_id: String,
    pub flash_size_bytes: u64,
    pub secure_boot: bool,
    pub flash_encryption: bool,
    pub secure_download_mode: bool,
    pub efuse_sha256: String,
    pub bootloader_sha256: String,
    pub partition_table_sha256: String,
    pub esptool_version: String,
}

pub fn exact_observation_from_probe(
    package: &PreparedUpdatePackage,
    unit_record_bytes: &[u8],
    expected_port: &str,
    probe_bytes: &[u8],
) -> Result<ExactUnitObservation, PlanError> {
    if unit_record_bytes.len() > MAX_METADATA_BYTES || probe_bytes.len() > MAX_METADATA_BYTES {
        return Err(PlanError::MetadataLimit);
    }
    let record: ExactUnitRecordV1 =
        serde_json::from_slice(unit_record_bytes).map_err(|_| PlanError::ExactUnitRecord)?;
    let probe: RomProbeResultV1 =
        serde_json::from_slice(probe_bytes).map_err(|_| PlanError::RomProbe)?;
    let manifest: FirmwareUpdateManifestV1 =
        serde_json::from_slice(&package.manifest_bytes).map_err(|_| PlanError::ManifestSchema)?;
    let board: BoardManifest =
        toml::from_slice(&package.board_manifest_bytes).map_err(|_| PlanError::BoardSyntax)?;

    let record_valid = record.schema == EXACT_UNIT_RECORD_SCHEMA
        && valid_token(&record.device_label, 1, 64)
        && valid_rom_mac(&record.rom_mac)
        && record.chip == manifest.target.chip
        && record.soc_revision == manifest.target.soc_revision
        && record.flash_manufacturer_id == manifest.target.flash_manufacturer_id
        && record.flash_device_id == manifest.target.flash_device_id
        && record.flash_size_bytes == manifest.target.flash_size_bytes
        && record.secure_boot == manifest.target.secure_boot
        && record.flash_encryption == manifest.target.flash_encryption
        && record.secure_download_mode == manifest.target.secure_download_mode
        && record.device_label == package.base_plan.target.device_label
        && record.board_manifest_sha256 == package.base_plan.board_manifest_sha256
        && record.partition_map_sha256 == package.base_plan.partition_map_sha256
        && lower_hex(&record.efuse_sha256, 64)
        && record.efuse_sha256 == board.security.efuse_after_sha256.to_ascii_lowercase()
        && record.qualified_recovery_cycles >= 2;
    if !record_valid {
        return Err(PlanError::ExactUnitRecord);
    }

    let probe_valid = probe.schema == ROM_PROBE_RESULT_SCHEMA
        && probe.mode == "READ_ONLY_PLAN"
        && probe.port == expected_port
        && valid_rom_mac(&probe.rom_mac)
        && probe.rom_mac == record.rom_mac
        && probe.chip == record.chip
        && probe.soc_revision == record.soc_revision
        && probe.flash_manufacturer_id == record.flash_manufacturer_id
        && probe.flash_device_id == record.flash_device_id
        && probe.flash_size_bytes == record.flash_size_bytes
        && probe.secure_boot == record.secure_boot
        && probe.flash_encryption == record.flash_encryption
        && probe.secure_download_mode == record.secure_download_mode
        && probe.efuse_sha256 == record.efuse_sha256
        && probe.bootloader_sha256 == manifest.preserved.bootloader_sha256
        && probe.partition_table_sha256 == manifest.preserved.partition_table_sha256
        && probe.esptool_version == manifest.tools.esptool_version;
    if !probe_valid {
        return Err(PlanError::ExactUnitMismatch);
    }

    let canonical_record = serde_json::to_vec(&record).map_err(|_| PlanError::Serialization)?;
    let mut binding = b"keyferry.exact-unit-binding.v1\0".to_vec();
    binding.extend_from_slice(&canonical_record);
    Ok(ExactUnitObservation {
        port: probe.port,
        unit_binding_sha256: sha256_hex(&binding),
        chip: probe.chip,
        soc_revision: probe.soc_revision,
        flash_manufacturer_id: probe.flash_manufacturer_id,
        flash_device_id: probe.flash_device_id,
        flash_size_bytes: probe.flash_size_bytes,
        secure_boot: probe.secure_boot,
        flash_encryption: probe.flash_encryption,
        secure_download_mode: probe.secure_download_mode,
        efuse_sha256: probe.efuse_sha256,
        bootloader_sha256: probe.bootloader_sha256,
        partition_table_sha256: probe.partition_table_sha256,
        partition_map_sha256: manifest.target.partition_map_sha256,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactFirmwareUpdatePlanV1 {
    pub schema: String,
    pub mode: String,
    pub authorization_sha256: String,
    pub raw_manifest_sha256: String,
    pub board_manifest_sha256: String,
    pub partition_map_sha256: String,
    pub target: ExactUnitObservation,
    pub firmware: PlannedFirmware,
    pub write: PlannedWrite,
    pub protected_regions: Vec<ProtectedRegion>,
    pub tools: BuildTools,
}

pub fn build_exact_update_plan(
    package: &PreparedUpdatePackage,
    observation: ExactUnitObservation,
) -> Result<ExactFirmwareUpdatePlanV1, PlanError> {
    validate_exact_unit(package, &observation)?;
    let manifest: FirmwareUpdateManifestV1 =
        serde_json::from_slice(&package.manifest_bytes).map_err(|_| PlanError::ManifestSchema)?;
    let mut plan = ExactFirmwareUpdatePlanV1 {
        schema: EXACT_UPDATE_PLAN_SCHEMA.to_owned(),
        mode: "EXACT_UNIT_PLAN".to_owned(),
        authorization_sha256: String::new(),
        raw_manifest_sha256: sha256_hex(&package.manifest_bytes),
        board_manifest_sha256: sha256_hex(&package.board_manifest_bytes),
        partition_map_sha256: sha256_hex(&package.partition_map_bytes),
        target: observation,
        firmware: package.base_plan.firmware.clone(),
        write: package.base_plan.write.clone(),
        protected_regions: package.base_plan.protected_regions.clone(),
        tools: manifest.tools,
    };
    plan.authorization_sha256 = plan_authorization_sha256(&plan)?;
    Ok(plan)
}

fn validate_exact_unit(
    package: &PreparedUpdatePackage,
    observation: &ExactUnitObservation,
) -> Result<(), PlanError> {
    let manifest: FirmwareUpdateManifestV1 =
        serde_json::from_slice(&package.manifest_bytes).map_err(|_| PlanError::ManifestSchema)?;
    let board: BoardManifest =
        toml::from_slice(&package.board_manifest_bytes).map_err(|_| PlanError::BoardSyntax)?;
    let port_is_valid = !observation.port.is_empty()
        && observation.port.len() <= 260
        && observation.port.trim() == observation.port
        && observation.port.bytes().all(|byte| byte.is_ascii_graphic());
    if !port_is_valid
        || !lower_hex(&observation.unit_binding_sha256, 64)
        || observation.chip != manifest.target.chip
        || observation.soc_revision != manifest.target.soc_revision
        || observation.flash_manufacturer_id != manifest.target.flash_manufacturer_id
        || observation.flash_device_id != manifest.target.flash_device_id
        || observation.flash_size_bytes != manifest.target.flash_size_bytes
        || observation.secure_boot != manifest.target.secure_boot
        || observation.flash_encryption != manifest.target.flash_encryption
        || observation.secure_download_mode != manifest.target.secure_download_mode
        || !lower_hex(&observation.efuse_sha256, 64)
        || observation.efuse_sha256 != board.security.efuse_after_sha256.to_ascii_lowercase()
        || observation.bootloader_sha256 != manifest.preserved.bootloader_sha256
        || observation.partition_table_sha256 != manifest.preserved.partition_table_sha256
        || observation.partition_map_sha256 != manifest.target.partition_map_sha256
    {
        return Err(PlanError::ExactUnitMismatch);
    }
    Ok(())
}

fn plan_authorization_sha256(plan: &ExactFirmwareUpdatePlanV1) -> Result<String, PlanError> {
    let mut canonical = plan.clone();
    canonical.authorization_sha256.clear();
    serde_json::to_vec(&canonical)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| PlanError::Serialization)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendFailure {
    Unavailable,
    Timeout,
    Disconnected,
    Mismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteSafety {
    pub flash_mode_keep: bool,
    pub flash_frequency_keep: bool,
    pub flash_size_keep: bool,
    pub erase_all: bool,
    pub encrypt: bool,
    pub force: bool,
    pub ignore_flash_encryption_efuse: bool,
}

impl WriteSafety {
    pub const LOCKED: Self = Self {
        flash_mode_keep: true,
        flash_frequency_keep: true,
        flash_size_keep: true,
        erase_all: false,
        encrypt: false,
        force: false,
        ignore_flash_encryption_efuse: false,
    };
}

#[derive(Debug)]
pub struct ApplicationWrite<'a> {
    pub offset: u64,
    pub bytes: &'a [u8],
    pub safety: WriteSafety,
}

pub trait FirmwareUpdateBackend {
    fn observe(&mut self, port: &str) -> Result<ExactUnitObservation, BackendFailure>;
    fn write_application(&mut self, write: ApplicationWrite<'_>) -> Result<(), BackendFailure>;
    fn verify_application(&mut self, offset: u64, expected: &[u8]) -> Result<bool, BackendFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyError {
    PlanInvalid,
    AuthorizationMismatch,
    PackageMismatch,
    UnitMismatch,
    BackendUnavailable,
}

impl ApplyError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PlanInvalid => "firmware.apply_plan_invalid",
            Self::AuthorizationMismatch => "firmware.apply_authorization_mismatch",
            Self::PackageMismatch => "firmware.apply_package_mismatch",
            Self::UnitMismatch => "firmware.apply_unit_mismatch",
            Self::BackendUnavailable => "firmware.apply_backend_unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    WriteVerified,
    Rejected(ApplyError),
    UnknownWrite,
}

pub fn apply_exact_update<B: FirmwareUpdateBackend>(
    plan_bytes: &[u8],
    authorize: &str,
    package: &PreparedUpdatePackage,
    backend: &mut B,
) -> ApplyOutcome {
    if plan_bytes.len() > MAX_METADATA_BYTES {
        return ApplyOutcome::Rejected(ApplyError::PlanInvalid);
    }
    let plan: ExactFirmwareUpdatePlanV1 = match serde_json::from_slice(plan_bytes) {
        Ok(plan) => plan,
        Err(_) => return ApplyOutcome::Rejected(ApplyError::PlanInvalid),
    };
    if plan.schema != EXACT_UPDATE_PLAN_SCHEMA
        || plan.mode != "EXACT_UNIT_PLAN"
        || !lower_hex(&plan.authorization_sha256, 64)
        || plan_authorization_sha256(&plan).as_deref() != Ok(&plan.authorization_sha256)
    {
        return ApplyOutcome::Rejected(ApplyError::PlanInvalid);
    }
    if authorize != plan.authorization_sha256 {
        return ApplyOutcome::Rejected(ApplyError::AuthorizationMismatch);
    }
    let rebuilt = match build_exact_update_plan(package, plan.target.clone()) {
        Ok(rebuilt) => rebuilt,
        Err(_) => return ApplyOutcome::Rejected(ApplyError::PackageMismatch),
    };
    if rebuilt != plan {
        return ApplyOutcome::Rejected(ApplyError::PackageMismatch);
    }
    let observed = match backend.observe(&plan.target.port) {
        Ok(observed) => observed,
        Err(BackendFailure::Mismatch) => {
            return ApplyOutcome::Rejected(ApplyError::UnitMismatch);
        }
        Err(_) => return ApplyOutcome::Rejected(ApplyError::BackendUnavailable),
    };
    if observed != plan.target || validate_exact_unit(package, &observed).is_err() {
        return ApplyOutcome::Rejected(ApplyError::UnitMismatch);
    }
    if backend
        .write_application(ApplicationWrite {
            offset: APPLICATION_OFFSET,
            bytes: package.image(),
            safety: WriteSafety::LOCKED,
        })
        .is_err()
    {
        return ApplyOutcome::UnknownWrite;
    }
    match backend.verify_application(APPLICATION_OFFSET, package.image()) {
        Ok(true) => ApplyOutcome::WriteVerified,
        Ok(false) | Err(_) => ApplyOutcome::UnknownWrite,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloneSplitBindingV1 {
    pub schema: String,
    pub rom_mac: String,
    pub board_compatibility_id: u32,
    pub old_device_id: String,
    pub new_device_id: String,
    pub owner_transaction_id: String,
    pub unit_binding_sha256: String,
    pub source_application_sha256: String,
    pub source_state_sha256: String,
    pub protected_prefix_sha256: String,
    pub protected_suffix_sha256: String,
    pub private_input_sha256: String,
    pub fallback_fingerprint_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloneSplitLiveObservation {
    pub exact_unit: ExactUnitObservation,
    pub rom_mac: String,
    pub application_sha256: String,
    pub state_sha256: String,
    pub protected_prefix_sha256: String,
    pub protected_suffix_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloneSplitRegion {
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloneSplitMigrationPlanV1 {
    pub schema: String,
    pub mode: String,
    pub authorization_sha256: String,
    pub binding: CloneSplitBindingV1,
    pub target: CloneSplitLiveObservation,
    pub firmware: PlannedFirmware,
    pub invalidate_header: CloneSplitRegion,
    pub erase_application_tail: CloneSplitRegion,
    pub erase_state: CloneSplitRegion,
    pub protected_prefix: CloneSplitRegion,
    pub protected_suffix: CloneSplitRegion,
}

pub fn build_clone_split_plan(
    package: &PreparedUpdatePackage,
    binding: CloneSplitBindingV1,
    target: CloneSplitLiveObservation,
) -> Result<CloneSplitMigrationPlanV1, PlanError> {
    validate_clone_split_binding(package, &binding, &target)?;
    let mut plan = CloneSplitMigrationPlanV1 {
        schema: CLONE_SPLIT_PLAN_SCHEMA.to_owned(),
        mode: "EXACT_LILYGO_CLONE_SPLIT".to_owned(),
        authorization_sha256: String::new(),
        binding,
        target,
        firmware: package.base_plan.firmware.clone(),
        invalidate_header: CloneSplitRegion {
            offset: APPLICATION_OFFSET,
            length: CLONE_SPLIT_HEADER_BYTES,
        },
        erase_application_tail: CloneSplitRegion {
            offset: APPLICATION_OFFSET + CLONE_SPLIT_HEADER_BYTES,
            length: APPLICATION_PARTITION_SIZE - CLONE_SPLIT_HEADER_BYTES,
        },
        erase_state: CloneSplitRegion {
            offset: CLONE_SPLIT_STATE_OFFSET,
            length: CLONE_SPLIT_STATE_BYTES,
        },
        protected_prefix: CloneSplitRegion {
            offset: 0,
            length: APPLICATION_OFFSET,
        },
        protected_suffix: CloneSplitRegion {
            offset: CLONE_SPLIT_PROTECTED_SUFFIX_OFFSET,
            length: CLONE_SPLIT_PROTECTED_SUFFIX_BYTES,
        },
    };
    plan.authorization_sha256 = clone_split_authorization_sha256(&plan)?;
    Ok(plan)
}

fn validate_clone_split_binding(
    package: &PreparedUpdatePackage,
    binding: &CloneSplitBindingV1,
    target: &CloneSplitLiveObservation,
) -> Result<(), PlanError> {
    let required_hashes = [
        &binding.unit_binding_sha256,
        &binding.source_application_sha256,
        &binding.source_state_sha256,
        &binding.protected_prefix_sha256,
        &binding.protected_suffix_sha256,
        &binding.private_input_sha256,
        &binding.fallback_fingerprint_sha256,
        &target.application_sha256,
        &target.state_sha256,
        &target.protected_prefix_sha256,
        &target.protected_suffix_sha256,
    ];
    let lilygo = keyferry_protocol::firmware_identity::BOARD_LILYGO_T_DONGLE_S3;
    if binding.schema != CLONE_SPLIT_BINDING_SCHEMA
        || !valid_rom_mac(&binding.rom_mac)
        || binding.board_compatibility_id != lilygo
        || package.base_plan.firmware.board_compatibility_id != lilygo
        || package.image().is_empty()
        || package.image().len() as u64 > APPLICATION_PARTITION_SIZE
        || !valid_uuid(&binding.old_device_id)
        || !valid_uuid(&binding.new_device_id)
        || binding.old_device_id == binding.new_device_id
        || !valid_uuid(&binding.owner_transaction_id)
        || required_hashes.iter().any(|hash| !lower_hex(hash, 64))
        || target.rom_mac != binding.rom_mac
        || target.exact_unit.unit_binding_sha256 != binding.unit_binding_sha256
        || target.application_sha256 != binding.source_application_sha256
        || target.state_sha256 != binding.source_state_sha256
        || target.protected_prefix_sha256 != binding.protected_prefix_sha256
        || target.protected_suffix_sha256 != binding.protected_suffix_sha256
        || package.base_plan.firmware.image_sha256 == binding.source_application_sha256
        || validate_exact_unit(package, &target.exact_unit).is_err()
    {
        return Err(PlanError::CloneSplitBinding);
    }
    Ok(())
}

fn clone_split_authorization_sha256(plan: &CloneSplitMigrationPlanV1) -> Result<String, PlanError> {
    let mut canonical = plan.clone();
    canonical.authorization_sha256.clear();
    serde_json::to_vec(&canonical)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| PlanError::Serialization)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloneSplitStage {
    InvalidateHeader,
    EraseApplicationTail,
    EraseState,
    WriteApplication,
    VerifyApplication,
    VerifyProtected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloneSplitOutcome {
    Complete,
    Rejected(ApplyError),
    Interrupted(CloneSplitStage),
}

pub trait CloneSplitBackend {
    fn observe(&mut self, port: &str) -> Result<CloneSplitLiveObservation, BackendFailure>;
    fn erase_region(&mut self, region: &CloneSplitRegion) -> Result<(), BackendFailure>;
    fn verify_erased(&mut self, region: &CloneSplitRegion) -> Result<bool, BackendFailure>;
    fn write_application(&mut self, write: ApplicationWrite<'_>) -> Result<(), BackendFailure>;
    fn verify_application_partition(
        &mut self,
        image: &[u8],
        partition_size: u64,
    ) -> Result<bool, BackendFailure>;
    fn verify_protected(
        &mut self,
        prefix: &CloneSplitRegion,
        prefix_sha256: &str,
        suffix: &CloneSplitRegion,
        suffix_sha256: &str,
    ) -> Result<bool, BackendFailure>;
}

pub fn apply_clone_split<B: CloneSplitBackend>(
    plan_bytes: &[u8],
    authorize: &str,
    package: &PreparedUpdatePackage,
    backend: &mut B,
) -> CloneSplitOutcome {
    if plan_bytes.len() > MAX_METADATA_BYTES {
        return CloneSplitOutcome::Rejected(ApplyError::PlanInvalid);
    }
    let plan: CloneSplitMigrationPlanV1 = match serde_json::from_slice(plan_bytes) {
        Ok(plan) => plan,
        Err(_) => return CloneSplitOutcome::Rejected(ApplyError::PlanInvalid),
    };
    if plan.schema != CLONE_SPLIT_PLAN_SCHEMA
        || plan.mode != "EXACT_LILYGO_CLONE_SPLIT"
        || !lower_hex(&plan.authorization_sha256, 64)
        || clone_split_authorization_sha256(&plan).as_deref() != Ok(&plan.authorization_sha256)
    {
        return CloneSplitOutcome::Rejected(ApplyError::PlanInvalid);
    }
    if authorize != plan.authorization_sha256 {
        return CloneSplitOutcome::Rejected(ApplyError::AuthorizationMismatch);
    }
    let rebuilt = match build_clone_split_plan(package, plan.binding.clone(), plan.target.clone()) {
        Ok(rebuilt) => rebuilt,
        Err(_) => return CloneSplitOutcome::Rejected(ApplyError::PackageMismatch),
    };
    if rebuilt != plan {
        return CloneSplitOutcome::Rejected(ApplyError::PackageMismatch);
    }
    match backend.observe(&plan.target.exact_unit.port) {
        Ok(observed) if observed == plan.target => {}
        Ok(_) | Err(BackendFailure::Mismatch) => {
            return CloneSplitOutcome::Rejected(ApplyError::UnitMismatch);
        }
        Err(_) => return CloneSplitOutcome::Rejected(ApplyError::BackendUnavailable),
    }

    for (region, stage) in [
        (&plan.invalidate_header, CloneSplitStage::InvalidateHeader),
        (
            &plan.erase_application_tail,
            CloneSplitStage::EraseApplicationTail,
        ),
        (&plan.erase_state, CloneSplitStage::EraseState),
    ] {
        if backend.erase_region(region).is_err()
            || !matches!(backend.verify_erased(region), Ok(true))
        {
            return CloneSplitOutcome::Interrupted(stage);
        }
    }
    if backend
        .write_application(ApplicationWrite {
            offset: APPLICATION_OFFSET,
            bytes: package.image(),
            safety: WriteSafety::LOCKED,
        })
        .is_err()
    {
        return CloneSplitOutcome::Interrupted(CloneSplitStage::WriteApplication);
    }
    if !matches!(
        backend.verify_application_partition(package.image(), APPLICATION_PARTITION_SIZE),
        Ok(true)
    ) {
        return CloneSplitOutcome::Interrupted(CloneSplitStage::VerifyApplication);
    }
    if !matches!(
        backend.verify_protected(
            &plan.protected_prefix,
            &plan.binding.protected_prefix_sha256,
            &plan.protected_suffix,
            &plan.binding.protected_suffix_sha256,
        ),
        Ok(true)
    ) {
        return CloneSplitOutcome::Interrupted(CloneSplitStage::VerifyProtected);
    }
    CloneSplitOutcome::Complete
}

fn parse_partitions(bytes: &[u8]) -> Result<Vec<Partition>, PlanError> {
    let source = std::str::from_utf8(bytes).map_err(|_| PlanError::PartitionSyntax)?;
    let mut partitions = Vec::new();
    for line in source.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
        if fields.len() != 6 || fields[..5].iter().any(|field| field.is_empty()) {
            return Err(PlanError::PartitionSyntax);
        }
        partitions.push(Partition {
            name: fields[0].to_owned(),
            kind: fields[1].to_owned(),
            subtype: fields[2].to_owned(),
            offset: parse_size(fields[3])?,
            size: parse_size(fields[4])?,
        });
    }
    if partitions.is_empty() {
        return Err(PlanError::PartitionSyntax);
    }
    Ok(partitions)
}

fn parse_size(value: &str) -> Result<u64, PlanError> {
    if let Some(hex) = value.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).map_err(|_| PlanError::PartitionSyntax);
    }
    if let Some(megabytes) = value.strip_suffix('M') {
        return megabytes
            .parse::<u64>()
            .ok()
            .and_then(|value| value.checked_mul(1024 * 1024))
            .ok_or(PlanError::PartitionSyntax);
    }
    value.parse().map_err(|_| PlanError::PartitionSyntax)
}

fn valid_token(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+_-".contains(&byte))
}

fn valid_release(value: &str) -> bool {
    if !valid_token(value, 1, 64) {
        return false;
    }
    let Ok(parsed) = semver::Version::parse(value) else {
        return false;
    };
    parsed.build.is_empty() && parsed.to_string() == value
}

fn valid_installable_release(value: &str) -> bool {
    valid_release(value)
        && semver::Version::parse(value)
            .is_ok_and(|version| !version.pre.as_str().split('.').any(|part| part == "probe"))
}

fn lower_prefixed_hex(value: &str, digits: usize) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|suffix| lower_hex(suffix, digits))
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn upper_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

fn valid_rom_mac(value: &str) -> bool {
    value.len() == 17
        && value.split(':').count() == 6
        && value.split(':').all(|octet| lower_hex(octet, 2))
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        && value.bytes().any(|byte| byte != b'0' && byte != b'-')
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOARD: &str = r#"
manifest_version = 2
status = "RECOVERY_QUALIFIED"
device_label = "synthetic-test-unit"
[identity]
soc = "ESP32-S3 QFN56"
soc_revision = "v0.2"
[flash]
manufacturer_id = "0x20"
device_id = "0x4018"
size_bytes = 16777216
partition_table_offset = 32768
[security]
secure_boot = false
flash_encryption = false
secure_download_mode = false
efuse_before_sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
efuse_after_sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[pins]
profile = "waveshare_geek_v1_1_reference"
compatibility_id = 1
[recovery]
cycle_a_passed = true
cycle_b_passed = true
"#;
    const PARTITIONS: &str = r#"
factory, app, factory, 0x10000, 1M,
kf_cfg_a, data, 0x40, 0x110000, 0x4000,
kf_cfg_b, data, 0x41, 0x114000, 0x4000,
nvs, data, nvs, 0x118000, 0x3000,
"#;

    fn image() -> Vec<u8> {
        vec![0xA5; 4096]
    }

    fn descriptor_image() -> Vec<u8> {
        let mut image = image();
        let offset = 128;
        image[offset..offset + 256].fill(0);
        image[offset..offset + 4].copy_from_slice(&0xABCD_5432_u32.to_le_bytes());
        image[offset + 16..offset + 21].copy_from_slice(b"0.1.0");
        image[offset + 48..offset + 69].copy_from_slice(PROJECT_NAME.as_bytes());
        image[offset + 112..offset + 118].copy_from_slice(b"v6.0.3");
        image[offset + 144..offset + 176].copy_from_slice(&Sha256::digest(b"test-elf"));
        image
    }

    fn manifest(image: &[u8]) -> FirmwareUpdateManifestV1 {
        let elf = b"test-elf";
        FirmwareUpdateManifestV1 {
            schema: UPDATE_MANIFEST_SCHEMA.to_owned(),
            identity: FirmwareIdentity {
                project_name: PROJECT_NAME.to_owned(),
                version: "0.1.0".to_owned(),
                source_revision: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                protocol_major: 1,
                protocol_min_minor: 0,
                protocol_max_minor: 0,
                board_compatibility_id: BOARD_COMPATIBILITY_ID,
                elf_sha256: sha256_hex(elf),
            },
            target: FirmwareTarget {
                board_profile: "waveshare_geek_v1_1_reference".to_owned(),
                board_manifest_sha256: sha256_hex(BOARD.as_bytes()),
                partition_map_sha256: sha256_hex(PARTITIONS.as_bytes()),
                chip: "esp32s3".to_owned(),
                soc_revision: "v0.2".to_owned(),
                flash_manufacturer_id: "0x20".to_owned(),
                flash_device_id: "0x4018".to_owned(),
                flash_size_bytes: 16_777_216,
                secure_boot: false,
                flash_encryption: false,
                secure_download_mode: false,
            },
            image: FirmwareImage {
                file: "keyferry_hil_endpoint.bin".to_owned(),
                size_bytes: image.len() as u64,
                sha256: sha256_hex(image),
                elf_file: "keyferry_hil_endpoint.elf".to_owned(),
                elf_size_bytes: elf.len() as u64,
                elf_sha256: sha256_hex(elf),
            },
            preserved: PreservedArtifacts {
                bootloader_file: "bootloader.bin".to_owned(),
                bootloader_size_bytes: b"test-bootloader".len() as u64,
                bootloader_sha256: sha256_hex(b"test-bootloader"),
                partition_table_file: "partition-table.bin".to_owned(),
                partition_table_size_bytes: b"test-partition-table".len() as u64,
                partition_table_sha256: sha256_hex(b"test-partition-table"),
            },
            tools: BuildTools {
                esp_idf_version: PINNED_ESP_IDF_VERSION.to_owned(),
                esptool_version: "5.4.0".to_owned(),
            },
            write: FirmwareWrite {
                offset: 0x10000,
                partition_size_bytes: 0x100000,
            },
        }
    }

    fn plan(
        manifest: &FirmwareUpdateManifestV1,
        image: &[u8],
    ) -> Result<FirmwareUpdatePlanV1, PlanError> {
        build_update_plan(
            &serde_json::to_vec(manifest).unwrap(),
            BOARD.as_bytes(),
            PARTITIONS.as_bytes(),
            image,
        )
    }

    #[test]
    fn valid_plan_is_exactly_one_app_write_and_never_apply_ready() {
        let image = image();
        let plan = plan(&manifest(&image), &image).unwrap();
        assert_eq!(plan.schema, UPDATE_PLAN_SCHEMA);
        assert_eq!(plan.mode, "PLAN_ONLY");
        assert!(!plan.apply_available);
        assert_eq!(plan.target.device_label, "synthetic-test-unit");
        assert_eq!(plan.write.offset, 0x10000);
        assert_eq!(plan.write.length, 4096);
        assert_eq!(plan.protected_regions.len(), 4);
        assert_eq!(plan.protected_regions[0].offset, 0);
        assert_eq!(plan.protected_regions[0].size_bytes, 0x10000);
        assert_eq!(plan.blocked_on.len(), 4);
    }

    #[test]
    fn unknown_manifest_fields_and_noncanonical_values_fail_closed() {
        let image = image();
        let mut value = serde_json::to_value(manifest(&image)).unwrap();
        value["raw_usage"] = serde_json::json!(true);
        assert_eq!(
            build_update_plan(
                &serde_json::to_vec(&value).unwrap(),
                BOARD.as_bytes(),
                PARTITIONS.as_bytes(),
                &image,
            ),
            Err(PlanError::ManifestSchema)
        );

        let mut invalid = manifest(&image);
        invalid.image.file = "other.bin".to_owned();
        assert_eq!(plan(&invalid, &image), Err(PlanError::ManifestValue));
    }

    #[test]
    fn image_hash_size_board_security_and_recovery_must_match() {
        let image = image();
        let mut wrong_hash = manifest(&image);
        wrong_hash.image.sha256 = "0".repeat(64);
        assert_eq!(plan(&wrong_hash, &image), Err(PlanError::ImageHash));

        let mut wrong_size = manifest(&image);
        wrong_size.image.size_bytes += 1;
        assert_eq!(plan(&wrong_size, &image), Err(PlanError::ImageSize));

        let mut wrong_board = manifest(&image);
        wrong_board.target.soc_revision = "v0.1".to_owned();
        assert_eq!(plan(&wrong_board, &image), Err(PlanError::BoardMismatch));

        let unsafe_board = BOARD.replace("secure_boot = false", "secure_boot = true");
        let mut unsafe_manifest = manifest(&image);
        unsafe_manifest.target.board_manifest_sha256 = sha256_hex(unsafe_board.as_bytes());
        assert_eq!(
            build_update_plan(
                &serde_json::to_vec(&unsafe_manifest).unwrap(),
                unsafe_board.as_bytes(),
                PARTITIONS.as_bytes(),
                &image,
            ),
            Err(PlanError::SecurityMismatch)
        );

        let unqualified = BOARD.replace("cycle_b_passed = true", "cycle_b_passed = false");
        let mut unqualified_manifest = manifest(&image);
        unqualified_manifest.target.board_manifest_sha256 = sha256_hex(unqualified.as_bytes());
        assert_eq!(
            build_update_plan(
                &serde_json::to_vec(&unqualified_manifest).unwrap(),
                unqualified.as_bytes(),
                PARTITIONS.as_bytes(),
                &image,
            ),
            Err(PlanError::RecoveryNotQualified)
        );

        let waived_lilygo = BOARD
            .replace("RECOVERY_QUALIFIED", "OWNER_WAIVED_REDUNDANT_RECOVERY")
            .replace("synthetic-test-unit", "synthetic-second-unit")
            .replace("0x20", "0xef")
            .replace("waveshare_geek_v1_1_reference", "lilygo_t_dongle_s3")
            .replace("compatibility_id = 1", "compatibility_id = 2")
            .replace("cycle_b_passed = true", "cycle_b_passed = false");
        let mut waived_manifest = manifest(&image);
        waived_manifest.identity.board_compatibility_id =
            keyferry_protocol::firmware_identity::BOARD_LILYGO_T_DONGLE_S3;
        waived_manifest.target.board_profile = "lilygo_t_dongle_s3".to_owned();
        waived_manifest.target.flash_manufacturer_id = "0xef".to_owned();
        waived_manifest.target.board_manifest_sha256 = sha256_hex(waived_lilygo.as_bytes());
        assert!(build_update_plan(
            &serde_json::to_vec(&waived_manifest).unwrap(),
            waived_lilygo.as_bytes(),
            PARTITIONS.as_bytes(),
            &image,
        )
        .is_ok());

        let waived_waveshare = BOARD
            .replace("RECOVERY_QUALIFIED", "OWNER_WAIVED_REDUNDANT_RECOVERY")
            .replace("cycle_b_passed = true", "cycle_b_passed = false");
        let mut waived_waveshare_manifest = manifest(&image);
        waived_waveshare_manifest.target.board_manifest_sha256 =
            sha256_hex(waived_waveshare.as_bytes());
        assert_eq!(
            build_update_plan(
                &serde_json::to_vec(&waived_waveshare_manifest).unwrap(),
                waived_waveshare.as_bytes(),
                PARTITIONS.as_bytes(),
                &image,
            ),
            Err(PlanError::RecoveryNotQualified)
        );
    }

    #[test]
    fn partition_drift_and_insufficient_headroom_fail_closed() {
        let image = image();
        let shifted = PARTITIONS.replace("0x10000", "0x20000");
        assert_eq!(
            build_update_plan(
                &serde_json::to_vec(&manifest(&image)).unwrap(),
                BOARD.as_bytes(),
                shifted.as_bytes(),
                &image,
            ),
            Err(PlanError::PartitionMismatch)
        );

        let huge = vec![0_u8; 0xF8001];
        assert_eq!(plan(&manifest(&huge), &huge), Err(PlanError::ImageSize));

        let exact_boundary = vec![0_u8; 0xF8000];
        assert!(plan(&manifest(&exact_boundary), &exact_boundary).is_ok());
    }

    #[test]
    fn duplicate_manifest_fields_fail_closed() {
        let image = image();
        let original = serde_json::to_string(&manifest(&image)).unwrap();
        let duplicate = original.replacen(
            "\"schema\":",
            "\"schema\":\"keyferry.firmware-update-manifest.v1\",\"schema\":",
            1,
        );
        assert_eq!(
            build_update_plan(
                duplicate.as_bytes(),
                BOARD.as_bytes(),
                PARTITIONS.as_bytes(),
                &image,
            ),
            Err(PlanError::ManifestSchema)
        );
    }

    fn prepared(image: &[u8]) -> PreparedUpdatePackage {
        let manifest = manifest(image);
        prepare_update_package(
            &serde_json::to_vec(&manifest).unwrap(),
            BOARD.as_bytes(),
            PARTITIONS.as_bytes(),
            image,
            b"test-elf",
            b"test-bootloader",
            b"test-partition-table",
        )
        .unwrap()
    }

    fn observation() -> ExactUnitObservation {
        ExactUnitObservation {
            port: "COM7".to_owned(),
            unit_binding_sha256: "7".repeat(64),
            chip: "esp32s3".to_owned(),
            soc_revision: "v0.2".to_owned(),
            flash_manufacturer_id: "0x20".to_owned(),
            flash_device_id: "0x4018".to_owned(),
            flash_size_bytes: 16_777_216,
            secure_boot: false,
            flash_encryption: false,
            secure_download_mode: false,
            efuse_sha256: "a".repeat(64),
            bootloader_sha256: sha256_hex(b"test-bootloader"),
            partition_table_sha256: sha256_hex(b"test-partition-table"),
            partition_map_sha256: sha256_hex(PARTITIONS.as_bytes()),
        }
    }

    fn lilygo_prepared(image: &[u8]) -> PreparedUpdatePackage {
        let board = BOARD
            .replace("synthetic-test-unit", "synthetic-second-unit")
            .replace("waveshare_geek_v1_1_reference", "lilygo_t_dongle_s3")
            .replace("compatibility_id = 1", "compatibility_id = 2");
        let generated = generate_update_manifest(
            ManifestMetadata {
                source_revision: "0123456789abcdef0123456789abcdef01234567",
                esptool_version: "5.4.0",
            },
            board.as_bytes(),
            PARTITIONS.as_bytes(),
            image,
            b"test-elf",
            b"test-bootloader",
            b"test-partition-table",
        )
        .unwrap();
        prepare_update_package(
            &serde_json::to_vec(&generated).unwrap(),
            board.as_bytes(),
            PARTITIONS.as_bytes(),
            image,
            b"test-elf",
            b"test-bootloader",
            b"test-partition-table",
        )
        .unwrap()
    }

    fn clone_split_fixture() -> (
        PreparedUpdatePackage,
        CloneSplitBindingV1,
        CloneSplitLiveObservation,
    ) {
        let mut new_image = descriptor_image();
        new_image[2048] ^= 1;
        let package = lilygo_prepared(&new_image);
        let binding = CloneSplitBindingV1 {
            schema: CLONE_SPLIT_BINDING_SCHEMA.to_owned(),
            rom_mac: "02:00:00:00:00:02".to_owned(),
            board_compatibility_id: keyferry_protocol::firmware_identity::BOARD_LILYGO_T_DONGLE_S3,
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
        let exact_unit = ExactUnitObservation {
            port: "COM16".to_owned(),
            unit_binding_sha256: binding.unit_binding_sha256.clone(),
            chip: "esp32s3".to_owned(),
            soc_revision: "v0.2".to_owned(),
            flash_manufacturer_id: "0x20".to_owned(),
            flash_device_id: "0x4018".to_owned(),
            flash_size_bytes: 16_777_216,
            secure_boot: false,
            flash_encryption: false,
            secure_download_mode: false,
            efuse_sha256: "a".repeat(64),
            bootloader_sha256: sha256_hex(b"test-bootloader"),
            partition_table_sha256: sha256_hex(b"test-partition-table"),
            partition_map_sha256: sha256_hex(PARTITIONS.as_bytes()),
        };
        let observed = CloneSplitLiveObservation {
            exact_unit,
            rom_mac: binding.rom_mac.clone(),
            application_sha256: binding.source_application_sha256.clone(),
            state_sha256: binding.source_state_sha256.clone(),
            protected_prefix_sha256: binding.protected_prefix_sha256.clone(),
            protected_suffix_sha256: binding.protected_suffix_sha256.clone(),
        };
        (package, binding, observed)
    }

    #[test]
    fn clone_split_plan_is_fixed_to_the_exact_lilygo_unit_and_ranges() {
        let (package, binding, observed) = clone_split_fixture();
        let plan = build_clone_split_plan(&package, binding.clone(), observed.clone()).unwrap();
        assert_eq!(
            plan.invalidate_header,
            CloneSplitRegion {
                offset: 0x10000,
                length: 0x1000
            }
        );
        assert_eq!(
            plan.erase_application_tail,
            CloneSplitRegion {
                offset: 0x11000,
                length: 0xFF000
            }
        );
        assert_eq!(
            plan.erase_state,
            CloneSplitRegion {
                offset: 0x110000,
                length: 0xB000
            }
        );
        assert_eq!(
            plan.protected_prefix,
            CloneSplitRegion {
                offset: 0,
                length: 0x10000
            }
        );
        assert_eq!(
            plan.protected_suffix,
            CloneSplitRegion {
                offset: 0x11B000,
                length: 0x1000
            }
        );

        let mut wrong_mac = binding.clone();
        wrong_mac.rom_mac = "02:00:00:00:00:03".to_owned();
        assert_eq!(
            build_clone_split_plan(&package, wrong_mac, observed.clone()),
            Err(PlanError::CloneSplitBinding)
        );
        let mut same_id = binding.clone();
        same_id.new_device_id.clone_from(&same_id.old_device_id);
        assert_eq!(
            build_clone_split_plan(&package, same_id, observed.clone()),
            Err(PlanError::CloneSplitBinding)
        );
        assert_eq!(
            build_clone_split_plan(&prepared(&descriptor_image()), binding, observed),
            Err(PlanError::CloneSplitBinding)
        );
    }

    #[derive(Default)]
    struct FakeCloneSplitBackend {
        observed: Option<CloneSplitLiveObservation>,
        fail_at: Option<usize>,
        calls: usize,
        actions: Vec<String>,
    }

    impl FakeCloneSplitBackend {
        fn step(&mut self, action: String) -> Result<(), BackendFailure> {
            self.calls += 1;
            self.actions.push(action);
            if self.fail_at == Some(self.calls) {
                Err(BackendFailure::Disconnected)
            } else {
                Ok(())
            }
        }
    }

    impl CloneSplitBackend for FakeCloneSplitBackend {
        fn observe(&mut self, _port: &str) -> Result<CloneSplitLiveObservation, BackendFailure> {
            self.step("observe".to_owned())?;
            self.observed.clone().ok_or(BackendFailure::Unavailable)
        }

        fn erase_region(&mut self, region: &CloneSplitRegion) -> Result<(), BackendFailure> {
            self.step(format!("erase:{:x}:{:x}", region.offset, region.length))
        }

        fn verify_erased(&mut self, region: &CloneSplitRegion) -> Result<bool, BackendFailure> {
            self.step(format!(
                "verify-erased:{:x}:{:x}",
                region.offset, region.length
            ))?;
            Ok(true)
        }

        fn write_application(&mut self, write: ApplicationWrite<'_>) -> Result<(), BackendFailure> {
            assert_eq!(write.offset, APPLICATION_OFFSET);
            assert_eq!(write.safety, WriteSafety::LOCKED);
            self.step(format!("write:{}", write.bytes.len()))
        }

        fn verify_application_partition(
            &mut self,
            _image: &[u8],
            partition_size: u64,
        ) -> Result<bool, BackendFailure> {
            assert_eq!(partition_size, APPLICATION_PARTITION_SIZE);
            self.step("verify-application".to_owned())?;
            Ok(true)
        }

        fn verify_protected(
            &mut self,
            prefix: &CloneSplitRegion,
            _prefix_sha256: &str,
            suffix: &CloneSplitRegion,
            _suffix_sha256: &str,
        ) -> Result<bool, BackendFailure> {
            assert_eq!(prefix.offset, 0);
            assert_eq!(suffix.offset, CLONE_SPLIT_PROTECTED_SUFFIX_OFFSET);
            self.step("verify-protected".to_owned())?;
            Ok(true)
        }
    }

    #[test]
    fn clone_split_stops_at_every_boundary_and_never_erases_state_early() {
        let (package, binding, observed) = clone_split_fixture();
        let plan = build_clone_split_plan(&package, binding, observed.clone()).unwrap();
        let bytes = serde_json::to_vec(&plan).unwrap();
        let mut complete = FakeCloneSplitBackend {
            observed: Some(observed.clone()),
            ..FakeCloneSplitBackend::default()
        };
        assert_eq!(
            apply_clone_split(&bytes, &plan.authorization_sha256, &package, &mut complete),
            CloneSplitOutcome::Complete
        );
        let expected = complete.actions.clone();
        assert_eq!(expected.len(), 10);

        for fail_at in 1..=expected.len() {
            let mut backend = FakeCloneSplitBackend {
                observed: Some(observed.clone()),
                fail_at: Some(fail_at),
                ..FakeCloneSplitBackend::default()
            };
            let outcome =
                apply_clone_split(&bytes, &plan.authorization_sha256, &package, &mut backend);
            assert_ne!(outcome, CloneSplitOutcome::Complete);
            assert_eq!(backend.actions, expected[..fail_at]);
            if let Some(state_index) = backend
                .actions
                .iter()
                .position(|action| action == "erase:110000:b000")
            {
                assert!(state_index > 2);
                assert_eq!(backend.actions[1], "erase:10000:1000");
                assert_eq!(backend.actions[2], "verify-erased:10000:1000");
            }
        }
    }

    #[test]
    fn clone_split_rejects_tampering_before_erasing_anything() {
        let (package, binding, observed) = clone_split_fixture();
        let plan = build_clone_split_plan(&package, binding, observed.clone()).unwrap();
        let bytes = serde_json::to_vec(&plan).unwrap();
        let mut backend = FakeCloneSplitBackend {
            observed: Some(observed.clone()),
            ..FakeCloneSplitBackend::default()
        };
        assert_eq!(
            apply_clone_split(&bytes, &"0".repeat(64), &package, &mut backend),
            CloneSplitOutcome::Rejected(ApplyError::AuthorizationMismatch)
        );
        assert!(backend.actions.is_empty());

        let mut changed = observed;
        changed.application_sha256 = "8".repeat(64);
        backend.observed = Some(changed);
        assert_eq!(
            apply_clone_split(&bytes, &plan.authorization_sha256, &package, &mut backend),
            CloneSplitOutcome::Rejected(ApplyError::UnitMismatch)
        );
        assert_eq!(backend.actions, ["observe"]);
    }

    fn unit_record(package: &PreparedUpdatePackage) -> ExactUnitRecordV1 {
        ExactUnitRecordV1 {
            schema: EXACT_UNIT_RECORD_SCHEMA.to_owned(),
            device_label: "synthetic-test-unit".to_owned(),
            rom_mac: "02:00:00:00:00:01".to_owned(),
            chip: "esp32s3".to_owned(),
            soc_revision: "v0.2".to_owned(),
            flash_manufacturer_id: "0x20".to_owned(),
            flash_device_id: "0x4018".to_owned(),
            flash_size_bytes: 16_777_216,
            secure_boot: false,
            flash_encryption: false,
            secure_download_mode: false,
            board_manifest_sha256: package.base_plan.board_manifest_sha256.clone(),
            partition_map_sha256: package.base_plan.partition_map_sha256.clone(),
            efuse_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            qualified_recovery_cycles: 2,
        }
    }

    fn probe() -> RomProbeResultV1 {
        RomProbeResultV1 {
            schema: ROM_PROBE_RESULT_SCHEMA.to_owned(),
            mode: "READ_ONLY_PLAN".to_owned(),
            port: "COM7".to_owned(),
            rom_mac: "02:00:00:00:00:01".to_owned(),
            chip: "esp32s3".to_owned(),
            soc_revision: "v0.2".to_owned(),
            flash_manufacturer_id: "0x20".to_owned(),
            flash_device_id: "0x4018".to_owned(),
            flash_size_bytes: 16_777_216,
            secure_boot: false,
            flash_encryption: false,
            secure_download_mode: false,
            efuse_sha256: "a".repeat(64),
            bootloader_sha256: sha256_hex(b"test-bootloader"),
            partition_table_sha256: sha256_hex(b"test-partition-table"),
            esptool_version: "5.4.0".to_owned(),
        }
    }

    #[test]
    fn read_only_probe_is_bound_to_private_record_and_exact_preserved_lengths() {
        let image = descriptor_image();
        let package = prepared(&image);
        assert_eq!(
            package.rom_probe_requirements().unwrap(),
            RomProbeRequirements {
                bootloader_offset: 0,
                bootloader_size_bytes: b"test-bootloader".len() as u64,
                partition_table_offset: 0x8000,
                partition_table_size_bytes: b"test-partition-table".len() as u64,
            }
        );
        let record = serde_json::to_vec(&unit_record(&package)).unwrap();
        let probe = serde_json::to_vec(&probe()).unwrap();
        let observed = exact_observation_from_probe(&package, &record, "COM7", &probe).unwrap();
        assert_eq!(observed.port, "COM7");
        assert_eq!(observed.unit_binding_sha256.len(), 64);
        assert!(!serde_json::to_string(&observed)
            .unwrap()
            .contains("02:00:00:00:00:01"));
    }

    #[test]
    fn probe_port_hash_or_schema_drift_fails_closed() {
        let image = descriptor_image();
        let package = prepared(&image);
        let record = serde_json::to_vec(&unit_record(&package)).unwrap();

        let mut wrong_port = probe();
        wrong_port.port = "COM8".to_owned();
        assert_eq!(
            exact_observation_from_probe(
                &package,
                &record,
                "COM7",
                &serde_json::to_vec(&wrong_port).unwrap(),
            ),
            Err(PlanError::ExactUnitMismatch)
        );

        let mut wrong_hash = probe();
        wrong_hash.partition_table_sha256 = "0".repeat(64);
        assert_eq!(
            exact_observation_from_probe(
                &package,
                &record,
                "COM7",
                &serde_json::to_vec(&wrong_hash).unwrap(),
            ),
            Err(PlanError::ExactUnitMismatch)
        );

        let mut unknown_probe = serde_json::to_value(probe()).unwrap();
        unknown_probe["write"] = serde_json::json!(true);
        assert_eq!(
            exact_observation_from_probe(
                &package,
                &record,
                "COM7",
                &serde_json::to_vec(&unknown_probe).unwrap(),
            ),
            Err(PlanError::RomProbe)
        );

        let mut unknown_record = serde_json::to_value(unit_record(&package)).unwrap();
        unknown_record["owner"] = serde_json::json!("ignored");
        assert_eq!(
            exact_observation_from_probe(
                &package,
                &serde_json::to_vec(&unknown_record).unwrap(),
                "COM7",
                &serde_json::to_vec(&probe()).unwrap(),
            ),
            Err(PlanError::ExactUnitRecord)
        );
    }

    #[derive(Default)]
    struct FakeBackend {
        observed: Option<ExactUnitObservation>,
        write_failure: bool,
        verification: Option<bool>,
        writes: Vec<(u64, Vec<u8>, WriteSafety)>,
    }

    impl FirmwareUpdateBackend for FakeBackend {
        fn observe(&mut self, _port: &str) -> Result<ExactUnitObservation, BackendFailure> {
            self.observed.clone().ok_or(BackendFailure::Unavailable)
        }

        fn write_application(&mut self, write: ApplicationWrite<'_>) -> Result<(), BackendFailure> {
            self.writes
                .push((write.offset, write.bytes.to_vec(), write.safety));
            if self.write_failure {
                Err(BackendFailure::Disconnected)
            } else {
                Ok(())
            }
        }

        fn verify_application(
            &mut self,
            _offset: u64,
            _expected: &[u8],
        ) -> Result<bool, BackendFailure> {
            self.verification.ok_or(BackendFailure::Timeout)
        }
    }

    #[test]
    fn live_efuse_mismatch_fails_closed() {
        let image = descriptor_image();
        let package = prepared(&image);
        let record = serde_json::to_vec(&unit_record(&package)).unwrap();
        let mut wrong_probe = probe();
        wrong_probe.efuse_sha256 = "b".repeat(64);
        assert_eq!(
            exact_observation_from_probe(
                &package,
                &record,
                "COM7",
                &serde_json::to_vec(&wrong_probe).unwrap(),
            ),
            Err(PlanError::ExactUnitMismatch)
        );

        let plan = build_exact_update_plan(&package, observation()).unwrap();
        let bytes = serde_json::to_vec(&plan).unwrap();
        let mut changed = observation();
        changed.efuse_sha256 = "b".repeat(64);
        let mut backend = FakeBackend {
            observed: Some(changed),
            verification: Some(true),
            ..FakeBackend::default()
        };
        assert_eq!(
            apply_exact_update(&bytes, &plan.authorization_sha256, &package, &mut backend),
            ApplyOutcome::Rejected(ApplyError::UnitMismatch)
        );
        assert!(backend.writes.is_empty());
    }

    #[test]
    fn relocated_candidate_cannot_use_the_application_only_updater() {
        let candidate = include_bytes!(
            "../../../firmware/esp32s3/hil_endpoint/spikes/partitions.msc-memory.csv"
        );
        let image = descriptor_image();
        assert_eq!(
            generate_update_manifest(
                ManifestMetadata {
                    source_revision: "0123456789abcdef0123456789abcdef01234567",
                    esptool_version: "5.4.0",
                },
                BOARD.as_bytes(),
                candidate,
                &image,
                b"test-elf",
                b"test-bootloader",
                b"test-partition-table",
            ),
            Err(PlanError::ManifestValue)
        );
    }

    #[test]
    fn reserved_probe_versions_are_inventory_only() {
        assert!(valid_release("0.0.0-probe.mem"));
        assert!(!valid_installable_release("0.0.0-probe.mem"));
        assert!(!valid_installable_release("1.2.3-probe"));
        assert!(valid_installable_release("1.2.3-rc.1"));
        assert!(valid_installable_release("1.2.3"));
    }

    #[test]
    fn compile_only_msc_image_cannot_be_packaged_as_a_release() {
        for probe_version in ["msc-size-probe", "0.0.0-probe.mem"] {
            let mut image = descriptor_image();
            let version = 128 + 16;
            image[version..version + 32].fill(0);
            image[version..version + probe_version.len()].copy_from_slice(probe_version.as_bytes());
            assert_eq!(
                generate_update_manifest(
                    ManifestMetadata {
                        source_revision: "0123456789abcdef0123456789abcdef01234567",
                        esptool_version: "5.4.0",
                    },
                    BOARD.as_bytes(),
                    PARTITIONS.as_bytes(),
                    &image,
                    b"test-elf",
                    b"test-bootloader",
                    b"test-partition-table",
                ),
                Err(PlanError::ImageDescriptor)
            );

            // A hand-written release manifest cannot hide the image's probe version.
            let release = manifest(&image);
            assert!(matches!(
                prepare_update_package(
                    &serde_json::to_vec(&release).unwrap(),
                    BOARD.as_bytes(),
                    PARTITIONS.as_bytes(),
                    &image,
                    b"test-elf",
                    b"test-bootloader",
                    b"test-partition-table",
                ),
                Err(PlanError::ImageDescriptor)
            ));
            let mut probe = release;
            probe.identity.version = probe_version.to_owned();
            assert_eq!(plan(&probe, &image), Err(PlanError::ManifestValue));
        }
    }

    #[test]
    fn exact_plan_authorizes_one_locked_application_write() {
        let image = descriptor_image();
        let generated = generate_update_manifest(
            ManifestMetadata {
                source_revision: "0123456789abcdef0123456789abcdef01234567",
                esptool_version: "5.4.0",
            },
            BOARD.as_bytes(),
            PARTITIONS.as_bytes(),
            &image,
            b"test-elf",
            b"test-bootloader",
            b"test-partition-table",
        )
        .unwrap();
        assert_eq!(generated, manifest(&image));
        let package = prepared(&image);
        let plan = build_exact_update_plan(&package, observation()).unwrap();
        assert_eq!(plan.write.offset, APPLICATION_OFFSET);
        assert_eq!(plan.authorization_sha256.len(), 64);
        let bytes = serde_json::to_vec(&plan).unwrap();
        let mut backend = FakeBackend {
            observed: Some(observation()),
            verification: Some(true),
            ..FakeBackend::default()
        };
        assert_eq!(
            apply_exact_update(&bytes, &plan.authorization_sha256, &package, &mut backend,),
            ApplyOutcome::WriteVerified
        );
        assert_eq!(backend.writes.len(), 1);
        assert_eq!(backend.writes[0].0, APPLICATION_OFFSET);
        assert_eq!(backend.writes[0].1, image);
        assert_eq!(backend.writes[0].2, WriteSafety::LOCKED);
        assert!(!backend.writes[0].2.erase_all);
        assert!(!backend.writes[0].2.encrypt);
        assert!(!backend.writes[0].2.force);
    }

    #[test]
    fn authorization_package_and_unit_drift_are_prewrite_rejections() {
        let image = descriptor_image();
        let package = prepared(&image);
        let plan = build_exact_update_plan(&package, observation()).unwrap();
        let bytes = serde_json::to_vec(&plan).unwrap();

        let mut backend = FakeBackend {
            observed: Some(observation()),
            verification: Some(true),
            ..FakeBackend::default()
        };
        assert_eq!(
            apply_exact_update(&bytes, &"0".repeat(64), &package, &mut backend),
            ApplyOutcome::Rejected(ApplyError::AuthorizationMismatch)
        );
        assert!(backend.writes.is_empty());

        let mut changed_image = image.clone();
        *changed_image.last_mut().unwrap() ^= 1;
        let changed_package = prepared(&changed_image);
        assert_eq!(
            apply_exact_update(
                &bytes,
                &plan.authorization_sha256,
                &changed_package,
                &mut backend,
            ),
            ApplyOutcome::Rejected(ApplyError::PackageMismatch)
        );
        assert!(backend.writes.is_empty());

        let mut wrong_unit = observation();
        wrong_unit.unit_binding_sha256 = "8".repeat(64);
        backend.observed = Some(wrong_unit);
        assert_eq!(
            apply_exact_update(&bytes, &plan.authorization_sha256, &package, &mut backend,),
            ApplyOutcome::Rejected(ApplyError::UnitMismatch)
        );
        assert!(backend.writes.is_empty());
    }

    #[test]
    fn uncertain_write_or_verification_never_retries() {
        let image = descriptor_image();
        let package = prepared(&image);
        let plan = build_exact_update_plan(&package, observation()).unwrap();
        let bytes = serde_json::to_vec(&plan).unwrap();

        for (write_failure, verification) in
            [(true, Some(true)), (false, Some(false)), (false, None)]
        {
            let mut backend = FakeBackend {
                observed: Some(observation()),
                write_failure,
                verification,
                ..FakeBackend::default()
            };
            assert_eq!(
                apply_exact_update(&bytes, &plan.authorization_sha256, &package, &mut backend,),
                ApplyOutcome::UnknownWrite
            );
            assert_eq!(backend.writes.len(), 1);
        }
    }
}
