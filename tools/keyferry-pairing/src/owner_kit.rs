use argon2::{Algorithm, Argon2, Params, Version};
use keyferry_gateway::{
    derive_device_link_secret, derive_route_proof_secret, device_gateway_name,
    installation_gateway_name, installation_id_for_spki, DeviceGrantV1, InstallationCredentials,
    InstallationDeviceV3, InstallationManifestV3,
};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData, PKCS_ECDSA_P256_SHA256,
};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use serde::{Deserialize, Serialize};
use x509_parser::parse_x509_certificate;
use zeroize::{Zeroize, Zeroizing};

const OWNER_KIT_SCHEMA_VERSION: u8 = 2;
const OWNER_KIT_SCHEMA_VERSION_V3: u8 = 3;
const INSTALLATION_SCHEMA_VERSION: u8 = 2;
const KDF_NAME: &str = "argon2id-v19";
const CIPHER_NAME: &str = "aes-256-gcm";
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const OWNER_KIT_AAD: &[u8] = b"keyferry/owner-kit-envelope/v2";
const OWNER_KIT_AAD_V3: &[u8] = b"keyferry/owner-kit-envelope/v3";
const MAX_OWNER_DEVICES: usize = 8;
const MAX_OWNER_KIT_BYTES: usize = 16 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 1024;
const MAX_PASSPHRASE_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OwnerKitError {
    InvalidPassphrase,
    InvalidEnvelope,
    InvalidAuthority,
    AuthenticationFailed,
    CryptoFailed,
    EncodingFailed,
}

impl std::fmt::Display for OwnerKitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidPassphrase => "owner-kit passphrase is invalid",
            Self::InvalidEnvelope => "owner-kit envelope is invalid",
            Self::InvalidAuthority => "owner-kit authority is invalid",
            Self::AuthenticationFailed => "owner-kit authentication failed",
            Self::CryptoFailed => "owner-kit cryptographic operation failed",
            Self::EncodingFailed => "owner-kit encoding failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OwnerKitError {}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerKitEnvelope {
    schema_version: u8,
    kdf: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt_hex: String,
    cipher: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerKitPlaintext {
    schema_version: u8,
    owner_id_hex: String,
    owner_ca_key_der_hex: String,
    owner_ca_der_hex: String,
    device_id_hex: String,
    device_recovery_secret_hex: String,
    authority_epoch: u64,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerKitPlaintextV3 {
    schema_version: u8,
    owner_id_hex: String,
    owner_ca_key_der_hex: String,
    owner_ca_der_hex: String,
    devices: Vec<OwnerKitDeviceV3>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerKitDeviceV3 {
    device_id_hex: String,
    device_recovery_secret_hex: String,
    authority_epoch: u64,
}

impl Drop for OwnerKitPlaintext {
    fn drop(&mut self) {
        self.owner_ca_key_der_hex.zeroize();
        self.device_recovery_secret_hex.zeroize();
    }
}

impl Drop for OwnerKitPlaintextV3 {
    fn drop(&mut self) {
        self.owner_ca_key_der_hex.zeroize();
    }
}

impl Drop for OwnerKitDeviceV3 {
    fn drop(&mut self) {
        self.device_recovery_secret_hex.zeroize();
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationManifest {
    pub schema_version: u8,
    pub owner_id_hex: String,
    pub device_id_hex: String,
    pub installation_id_hex: String,
    pub authority_epoch: u64,
    pub device_dns_name: String,
    pub desktop_dns_name: String,
    pub owner_ca_der: String,
    pub installation_spki_der: String,
    pub installation_key_der: String,
    pub device_server_certificate_der: String,
    pub desktop_server_certificate_der: String,
    pub desktop_client_certificate_der: String,
    pub device_link_secret: String,
    pub route_proof_secret: String,
}

pub struct IssuedInstallation {
    pub manifest: InstallationManifest,
    pub owner_id: [u8; 16],
    pub device_id: [u8; 16],
    pub installation_id: [u8; 16],
    pub owner_ca_der: Vec<u8>,
    pub installation_spki_der: Vec<u8>,
    pub installation_key_der: Vec<u8>,
    pub device_server_certificate_der: Vec<u8>,
    pub desktop_server_certificate_der: Vec<u8>,
    pub desktop_client_certificate_der: Vec<u8>,
    pub device_link_secret: [u8; 32],
    pub route_proof_secret: [u8; 32],
}

pub struct ExpandedInstallationV3 {
    pub manifest: InstallationManifestV3,
    pub owner_id: [u8; 16],
    pub installation_id: [u8; 16],
    pub owner_ca_der: Vec<u8>,
    pub installation_spki_der: Vec<u8>,
    pub installation_key_der: Vec<u8>,
    pub desktop_server_certificate_der: Vec<u8>,
    pub desktop_client_certificate_der: Vec<u8>,
    pub devices: Vec<IssuedDeviceGrantV1>,
}

pub struct IssuedDeviceGrantV1 {
    pub device_id: [u8; 16],
    pub authority_epoch: u64,
    pub device_server_certificate_der: Vec<u8>,
    pub device_link_secret: [u8; 32],
    pub route_proof_secret: [u8; 32],
    pub grant: DeviceGrantV1,
}

pub(super) struct DeviceOwnerAuthority {
    pub owner_id: [u8; 16],
    pub device_id: [u8; 16],
    pub owner_ca_der: Vec<u8>,
    pub device_recovery_secret: [u8; 32],
    pub authority_epoch: u64,
}

struct SelectedOwnerAuthority {
    owner_id: [u8; 16],
    device_id: [u8; 16],
    owner_ca_key_der: Zeroizing<Vec<u8>>,
    owner_ca_der: Vec<u8>,
    device_recovery_secret: Zeroizing<[u8; 32]>,
    authority_epoch: u64,
}

impl Drop for DeviceOwnerAuthority {
    fn drop(&mut self) {
        self.device_recovery_secret.zeroize();
    }
}

impl Drop for IssuedInstallation {
    fn drop(&mut self) {
        self.installation_key_der.zeroize();
        self.device_link_secret.zeroize();
        self.route_proof_secret.zeroize();
    }
}

impl Drop for ExpandedInstallationV3 {
    fn drop(&mut self) {
        self.installation_key_der.zeroize();
    }
}

impl Drop for IssuedDeviceGrantV1 {
    fn drop(&mut self) {
        self.device_link_secret.zeroize();
        self.route_proof_secret.zeroize();
    }
}

pub fn create(
    device_id: [u8; 16],
    device_recovery_secret: [u8; 32],
    passphrase: &[u8],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    owner_id: [u8; 16],
) -> Result<Vec<u8>, OwnerKitError> {
    validate_passphrase(passphrase)?;
    let device_recovery_secret = Zeroizing::new(device_recovery_secret);
    if owner_id.iter().all(|byte| *byte == 0)
        || device_id.iter().all(|byte| *byte == 0)
        || device_recovery_secret.iter().all(|byte| *byte == 0)
    {
        return Err(OwnerKitError::InvalidAuthority);
    }

    let ca_key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| OwnerKitError::CryptoFailed)?;
    let ca_key_der = Zeroizing::new(ca_key.serialize_der());
    let ca = CertifiedIssuer::self_signed(owner_ca_parameters(&owner_id), ca_key)
        .map_err(|_| OwnerKitError::CryptoFailed)?;
    if ca.der().len() > MAX_CERTIFICATE_BYTES {
        return Err(OwnerKitError::InvalidAuthority);
    }

    let plaintext = OwnerKitPlaintext {
        schema_version: OWNER_KIT_SCHEMA_VERSION,
        owner_id_hex: hex(&owner_id),
        owner_ca_key_der_hex: hex(ca_key_der.as_slice()),
        owner_ca_der_hex: hex(ca.der().as_ref()),
        device_id_hex: hex(&device_id),
        device_recovery_secret_hex: hex(device_recovery_secret.as_slice()),
        authority_epoch: 1,
    };
    encrypt_plaintext(&plaintext, passphrase, salt, nonce)
}

pub fn change_passphrase(
    owner_kit: &[u8],
    current_passphrase: &[u8],
    new_passphrase: &[u8],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Result<Vec<u8>, OwnerKitError> {
    let (schema_version, plaintext) = decrypt_payload(owner_kit, current_passphrase)?;
    match schema_version {
        OWNER_KIT_SCHEMA_VERSION => {
            let plaintext: OwnerKitPlaintext =
                serde_json::from_slice(&plaintext).map_err(|_| OwnerKitError::InvalidAuthority)?;
            validate_plaintext_authority(&plaintext)?;
            encrypt_plaintext(&plaintext, new_passphrase, salt, nonce)
        }
        OWNER_KIT_SCHEMA_VERSION_V3 => {
            let plaintext: OwnerKitPlaintextV3 =
                serde_json::from_slice(&plaintext).map_err(|_| OwnerKitError::InvalidAuthority)?;
            validate_plaintext_authority_v3(&plaintext)?;
            encrypt_plaintext_v3(&plaintext, new_passphrase, salt, nonce)
        }
        _ => Err(OwnerKitError::InvalidEnvelope),
    }
}

pub fn add_device(
    owner_kit: &[u8],
    passphrase: &[u8],
    device_id: [u8; 16],
    device_recovery_secret: [u8; 32],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Result<Vec<u8>, OwnerKitError> {
    if device_id.iter().all(|byte| *byte == 0)
        || device_recovery_secret.iter().all(|byte| *byte == 0)
    {
        return Err(OwnerKitError::InvalidAuthority);
    }
    let recovery = Zeroizing::new(device_recovery_secret);
    let (schema_version, plaintext) = decrypt_payload(owner_kit, passphrase)?;
    let mut authority = match schema_version {
        OWNER_KIT_SCHEMA_VERSION => {
            let original: OwnerKitPlaintext =
                serde_json::from_slice(&plaintext).map_err(|_| OwnerKitError::InvalidAuthority)?;
            validate_plaintext_authority(&original)?;
            OwnerKitPlaintextV3 {
                schema_version: OWNER_KIT_SCHEMA_VERSION_V3,
                owner_id_hex: original.owner_id_hex.clone(),
                owner_ca_key_der_hex: original.owner_ca_key_der_hex.clone(),
                owner_ca_der_hex: original.owner_ca_der_hex.clone(),
                devices: vec![OwnerKitDeviceV3 {
                    device_id_hex: original.device_id_hex.clone(),
                    device_recovery_secret_hex: original.device_recovery_secret_hex.clone(),
                    authority_epoch: original.authority_epoch,
                }],
            }
        }
        OWNER_KIT_SCHEMA_VERSION_V3 => {
            let authority: OwnerKitPlaintextV3 =
                serde_json::from_slice(&plaintext).map_err(|_| OwnerKitError::InvalidAuthority)?;
            validate_plaintext_authority_v3(&authority)?;
            authority
        }
        _ => return Err(OwnerKitError::InvalidEnvelope),
    };
    if authority.devices.len() >= MAX_OWNER_DEVICES
        || authority
            .devices
            .iter()
            .any(|device| device.device_id_hex == hex(&device_id))
    {
        return Err(OwnerKitError::InvalidAuthority);
    }
    authority.devices.push(OwnerKitDeviceV3 {
        device_id_hex: hex(&device_id),
        device_recovery_secret_hex: hex(recovery.as_slice()),
        authority_epoch: 1,
    });
    authority
        .devices
        .sort_unstable_by(|left, right| left.device_id_hex.cmp(&right.device_id_hex));
    validate_plaintext_authority_v3(&authority)?;
    encrypt_plaintext_v3(&authority, passphrase, salt, nonce)
}

pub fn device_ids(owner_kit: &[u8], passphrase: &[u8]) -> Result<Vec<[u8; 16]>, OwnerKitError> {
    let (schema_version, plaintext) = decrypt_payload(owner_kit, passphrase)?;
    match schema_version {
        OWNER_KIT_SCHEMA_VERSION => {
            let authority: OwnerKitPlaintext =
                serde_json::from_slice(&plaintext).map_err(|_| OwnerKitError::InvalidAuthority)?;
            validate_plaintext_authority(&authority)?;
            Ok(vec![parse_hex_array::<16>(&authority.device_id_hex)?])
        }
        OWNER_KIT_SCHEMA_VERSION_V3 => {
            let authority: OwnerKitPlaintextV3 =
                serde_json::from_slice(&plaintext).map_err(|_| OwnerKitError::InvalidAuthority)?;
            validate_plaintext_authority_v3(&authority)?;
            authority
                .devices
                .iter()
                .map(|device| parse_hex_array::<16>(&device.device_id_hex))
                .collect()
        }
        _ => Err(OwnerKitError::InvalidEnvelope),
    }
}

fn encrypt_plaintext(
    plaintext: &OwnerKitPlaintext,
    passphrase: &[u8],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Result<Vec<u8>, OwnerKitError> {
    encrypt_serialized(
        plaintext,
        OWNER_KIT_SCHEMA_VERSION,
        OWNER_KIT_AAD,
        passphrase,
        salt,
        nonce,
    )
}

fn encrypt_plaintext_v3(
    plaintext: &OwnerKitPlaintextV3,
    passphrase: &[u8],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Result<Vec<u8>, OwnerKitError> {
    encrypt_serialized(
        plaintext,
        OWNER_KIT_SCHEMA_VERSION_V3,
        OWNER_KIT_AAD_V3,
        passphrase,
        salt,
        nonce,
    )
}

fn encrypt_serialized<T: Serialize>(
    plaintext: &T,
    schema_version: u8,
    aad: &'static [u8],
    passphrase: &[u8],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Result<Vec<u8>, OwnerKitError> {
    validate_passphrase(passphrase)?;
    let mut encoded =
        Zeroizing::new(serde_json::to_vec(plaintext).map_err(|_| OwnerKitError::EncodingFailed)?);
    let key = derive_envelope_key(passphrase, &salt)?;
    let cipher = LessSafeKey::new(
        UnboundKey::new(&aead::AES_256_GCM, key.as_slice())
            .map_err(|_| OwnerKitError::CryptoFailed)?,
    );
    let encoded_vec: &mut Vec<u8> = &mut encoded;
    cipher
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            encoded_vec,
        )
        .map_err(|_| OwnerKitError::CryptoFailed)?;

    let envelope = OwnerKitEnvelope {
        schema_version,
        kdf: KDF_NAME.to_owned(),
        memory_kib: ARGON2_MEMORY_KIB,
        iterations: ARGON2_ITERATIONS,
        parallelism: ARGON2_PARALLELISM,
        salt_hex: hex(&salt),
        cipher: CIPHER_NAME.to_owned(),
        nonce_hex: hex(&nonce),
        ciphertext_hex: hex(encoded.as_slice()),
    };
    let mut output =
        serde_json::to_vec_pretty(&envelope).map_err(|_| OwnerKitError::EncodingFailed)?;
    output.push(b'\n');
    if output.len() > MAX_OWNER_KIT_BYTES {
        return Err(OwnerKitError::EncodingFailed);
    }
    Ok(output)
}

pub fn issue_installation(
    owner_kit: &[u8],
    passphrase: &[u8],
) -> Result<IssuedInstallation, OwnerKitError> {
    let authority = select_authority(owner_kit, passphrase, None)?;
    issue_installation_for_authority(authority)
}

pub fn issue_installation_for_device(
    owner_kit: &[u8],
    passphrase: &[u8],
    device_id: [u8; 16],
) -> Result<IssuedInstallation, OwnerKitError> {
    let authority = select_authority(owner_kit, passphrase, Some(device_id))?;
    issue_installation_for_authority(authority)
}

fn issue_installation_for_authority(
    authority: SelectedOwnerAuthority,
) -> Result<IssuedInstallation, OwnerKitError> {
    let owner_id = authority.owner_id;
    let device_id = authority.device_id;
    let owner_ca_der = authority.owner_ca_der;
    let ca_key = KeyPair::try_from(authority.owner_ca_key_der.as_slice())
        .map_err(|_| OwnerKitError::InvalidAuthority)?;
    let ca = CertifiedIssuer::self_signed(owner_ca_parameters(&owner_id), ca_key)
        .map_err(|_| OwnerKitError::InvalidAuthority)?;

    let installation_key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| OwnerKitError::CryptoFailed)?;
    let installation_key_der = installation_key.serialize_der();
    let installation_spki_der = installation_key.subject_public_key_info();
    let installation_id = installation_id_for_spki(&installation_spki_der)
        .map_err(|_| OwnerKitError::InvalidAuthority)?;
    let device_dns_name =
        device_gateway_name(&device_id).map_err(|_| OwnerKitError::InvalidAuthority)?;
    let desktop_dns_name =
        installation_gateway_name(&installation_id).map_err(|_| OwnerKitError::InvalidAuthority)?;

    let device_certificate = certificate(
        &device_dns_name,
        ExtendedKeyUsagePurpose::ServerAuth,
        false,
        &installation_key,
        &ca,
    )?;
    let desktop_server_certificate = certificate(
        &desktop_dns_name,
        ExtendedKeyUsagePurpose::ServerAuth,
        true,
        &installation_key,
        &ca,
    )?;
    let desktop_client_certificate = certificate(
        &desktop_dns_name,
        ExtendedKeyUsagePurpose::ClientAuth,
        true,
        &installation_key,
        &ca,
    )?;
    let device_link_secret = derive_device_link_secret(
        &authority.device_recovery_secret,
        &owner_id,
        &device_id,
        authority.authority_epoch,
        &installation_spki_der,
    )
    .map_err(|_| OwnerKitError::CryptoFailed)?;
    let route_proof_secret = derive_route_proof_secret(
        &authority.device_recovery_secret,
        &owner_id,
        &device_id,
        authority.authority_epoch,
        &installation_id,
    )
    .map_err(|_| OwnerKitError::CryptoFailed)?;

    Ok(IssuedInstallation {
        manifest: InstallationManifest {
            schema_version: INSTALLATION_SCHEMA_VERSION,
            owner_id_hex: hex(&owner_id),
            device_id_hex: hex(&device_id),
            installation_id_hex: hex(&installation_id),
            authority_epoch: authority.authority_epoch,
            device_dns_name,
            desktop_dns_name,
            owner_ca_der: "owner-ca.der".to_owned(),
            installation_spki_der: "installation-spki.der".to_owned(),
            installation_key_der: "installation-key.der".to_owned(),
            device_server_certificate_der: "device-server-cert.der".to_owned(),
            desktop_server_certificate_der: "desktop-server-cert.der".to_owned(),
            desktop_client_certificate_der: "desktop-client-cert.der".to_owned(),
            device_link_secret: "device-link-secret.bin".to_owned(),
            route_proof_secret: "route-proof-secret.bin".to_owned(),
        },
        owner_id,
        device_id,
        installation_id,
        owner_ca_der,
        installation_spki_der,
        installation_key_der,
        device_server_certificate_der: device_certificate,
        desktop_server_certificate_der: desktop_server_certificate,
        desktop_client_certificate_der: desktop_client_certificate,
        device_link_secret,
        route_proof_secret,
    })
}

pub fn expand_installation_with_device(
    owner_kit: &[u8],
    passphrase: &[u8],
    existing: &InstallationCredentials,
    new_device_id: [u8; 16],
) -> Result<ExpandedInstallationV3, OwnerKitError> {
    if new_device_id == existing.device_id() {
        return Err(OwnerKitError::InvalidAuthority);
    }
    let old_authority = select_authority(owner_kit, passphrase, Some(existing.device_id()))?;
    let new_authority = select_authority(owner_kit, passphrase, Some(new_device_id))?;
    if old_authority.owner_id != existing.owner_id()
        || new_authority.owner_id != existing.owner_id()
        || old_authority.owner_ca_der != existing.owner_ca_der()
        || new_authority.owner_ca_der != existing.owner_ca_der()
        || old_authority.owner_ca_key_der.as_slice() != new_authority.owner_ca_key_der.as_slice()
    {
        return Err(OwnerKitError::InvalidAuthority);
    }

    let old_link_secret = derive_device_link_secret(
        &old_authority.device_recovery_secret,
        &old_authority.owner_id,
        &old_authority.device_id,
        old_authority.authority_epoch,
        existing.installation_spki_der(),
    )
    .map_err(|_| OwnerKitError::CryptoFailed)?;
    let old_route_secret = derive_route_proof_secret(
        &old_authority.device_recovery_secret,
        &old_authority.owner_id,
        &old_authority.device_id,
        old_authority.authority_epoch,
        &existing.installation_id(),
    )
    .map_err(|_| OwnerKitError::CryptoFailed)?;
    if old_link_secret != existing.device_link_secret()
        || old_route_secret != existing.route_proof_secret()
    {
        return Err(OwnerKitError::InvalidAuthority);
    }

    let ca_key = KeyPair::try_from(new_authority.owner_ca_key_der.as_slice())
        .map_err(|_| OwnerKitError::InvalidAuthority)?;
    let ca = CertifiedIssuer::self_signed(owner_ca_parameters(&new_authority.owner_id), ca_key)
        .map_err(|_| OwnerKitError::InvalidAuthority)?;
    let installation_key = KeyPair::try_from(existing.installation_key_der())
        .map_err(|_| OwnerKitError::InvalidAuthority)?;
    if installation_key.subject_public_key_info() != existing.installation_spki_der() {
        return Err(OwnerKitError::InvalidAuthority);
    }
    let new_dns_name =
        device_gateway_name(&new_device_id).map_err(|_| OwnerKitError::InvalidAuthority)?;
    let new_certificate = certificate(
        &new_dns_name,
        ExtendedKeyUsagePurpose::ServerAuth,
        false,
        &installation_key,
        &ca,
    )?;
    let new_link_secret = derive_device_link_secret(
        &new_authority.device_recovery_secret,
        &new_authority.owner_id,
        &new_authority.device_id,
        new_authority.authority_epoch,
        existing.installation_spki_der(),
    )
    .map_err(|_| OwnerKitError::CryptoFailed)?;
    let new_route_secret = derive_route_proof_secret(
        &new_authority.device_recovery_secret,
        &new_authority.owner_id,
        &new_authority.device_id,
        new_authority.authority_epoch,
        &existing.installation_id(),
    )
    .map_err(|_| OwnerKitError::CryptoFailed)?;

    let old_grant = DeviceGrantV1::sign(
        old_authority.owner_ca_key_der.as_slice(),
        existing.owner_id(),
        existing.owner_ca_der(),
        existing.device_id(),
        old_authority.authority_epoch,
        existing.installation_id(),
        existing.installation_spki_der(),
        existing.device_server_certificate_der(),
        &old_link_secret,
        &old_route_secret,
    )
    .map_err(|_| OwnerKitError::CryptoFailed)?;
    let new_grant = DeviceGrantV1::sign(
        new_authority.owner_ca_key_der.as_slice(),
        existing.owner_id(),
        existing.owner_ca_der(),
        new_device_id,
        new_authority.authority_epoch,
        existing.installation_id(),
        existing.installation_spki_der(),
        &new_certificate,
        &new_link_secret,
        &new_route_secret,
    )
    .map_err(|_| OwnerKitError::CryptoFailed)?;

    let mut devices = vec![
        IssuedDeviceGrantV1 {
            device_id: existing.device_id(),
            authority_epoch: old_authority.authority_epoch,
            device_server_certificate_der: existing.device_server_certificate_der().to_vec(),
            device_link_secret: old_link_secret,
            route_proof_secret: old_route_secret,
            grant: old_grant,
        },
        IssuedDeviceGrantV1 {
            device_id: new_device_id,
            authority_epoch: new_authority.authority_epoch,
            device_server_certificate_der: new_certificate,
            device_link_secret: new_link_secret,
            route_proof_secret: new_route_secret,
            grant: new_grant,
        },
    ];
    devices.sort_unstable_by_key(|device| device.device_id);
    let manifest = InstallationManifestV3 {
        schema_version: OWNER_KIT_SCHEMA_VERSION_V3,
        owner_id_hex: hex(&existing.owner_id()),
        installation_id_hex: hex(&existing.installation_id()),
        devices: devices
            .iter()
            .map(|device| InstallationDeviceV3 {
                device_id_hex: hex(&device.device_id),
                authority_epoch: device.authority_epoch,
            })
            .collect(),
    };
    Ok(ExpandedInstallationV3 {
        manifest,
        owner_id: existing.owner_id(),
        installation_id: existing.installation_id(),
        owner_ca_der: existing.owner_ca_der().to_vec(),
        installation_spki_der: existing.installation_spki_der().to_vec(),
        installation_key_der: existing.installation_key_der().to_vec(),
        desktop_server_certificate_der: existing.desktop_server_certificate_der().to_vec(),
        desktop_client_certificate_der: existing.desktop_client_certificate_der().to_vec(),
        devices,
    })
}

fn select_authority(
    owner_kit: &[u8],
    passphrase: &[u8],
    requested_device: Option<[u8; 16]>,
) -> Result<SelectedOwnerAuthority, OwnerKitError> {
    let (schema_version, plaintext) = decrypt_payload(owner_kit, passphrase)?;
    let (owner_id_hex, owner_ca_key_der_hex, owner_ca_der_hex, selected) = match schema_version {
        OWNER_KIT_SCHEMA_VERSION => {
            let authority: OwnerKitPlaintext =
                serde_json::from_slice(&plaintext).map_err(|_| OwnerKitError::InvalidAuthority)?;
            validate_plaintext_authority(&authority)?;
            let device_id = parse_hex_array::<16>(&authority.device_id_hex)?;
            if requested_device.is_some_and(|requested| requested != device_id) {
                return Err(OwnerKitError::InvalidAuthority);
            }
            (
                authority.owner_id_hex.clone(),
                Zeroizing::new(authority.owner_ca_key_der_hex.clone()),
                authority.owner_ca_der_hex.clone(),
                OwnerKitDeviceV3 {
                    device_id_hex: authority.device_id_hex.clone(),
                    device_recovery_secret_hex: authority.device_recovery_secret_hex.clone(),
                    authority_epoch: authority.authority_epoch,
                },
            )
        }
        OWNER_KIT_SCHEMA_VERSION_V3 => {
            let authority: OwnerKitPlaintextV3 =
                serde_json::from_slice(&plaintext).map_err(|_| OwnerKitError::InvalidAuthority)?;
            validate_plaintext_authority_v3(&authority)?;
            let requested = requested_device.ok_or(OwnerKitError::InvalidAuthority)?;
            let selected = authority
                .devices
                .iter()
                .find(|device| parse_hex_array::<16>(&device.device_id_hex) == Ok(requested))
                .ok_or(OwnerKitError::InvalidAuthority)?;
            (
                authority.owner_id_hex.clone(),
                Zeroizing::new(authority.owner_ca_key_der_hex.clone()),
                authority.owner_ca_der_hex.clone(),
                OwnerKitDeviceV3 {
                    device_id_hex: selected.device_id_hex.clone(),
                    device_recovery_secret_hex: selected.device_recovery_secret_hex.clone(),
                    authority_epoch: selected.authority_epoch,
                },
            )
        }
        _ => return Err(OwnerKitError::InvalidEnvelope),
    };
    let owner_id = parse_hex_array::<16>(&owner_id_hex)?;
    let device_id = parse_hex_array::<16>(&selected.device_id_hex)?;
    let device_recovery_secret =
        Zeroizing::new(parse_hex_array::<32>(&selected.device_recovery_secret_hex)?);
    let owner_ca_key_der = Zeroizing::new(parse_hex_vec(&owner_ca_key_der_hex, 8192)?);
    let owner_ca_der = parse_hex_vec(&owner_ca_der_hex, MAX_CERTIFICATE_BYTES)?;
    validate_ca_key_pair(owner_ca_key_der.as_slice(), &owner_ca_der)?;
    Ok(SelectedOwnerAuthority {
        owner_id,
        device_id,
        owner_ca_key_der,
        owner_ca_der,
        device_recovery_secret,
        authority_epoch: selected.authority_epoch,
    })
}

pub(super) fn unlock_device_authority(
    owner_kit: &[u8],
    passphrase: &[u8],
) -> Result<DeviceOwnerAuthority, OwnerKitError> {
    let authority = decrypt(owner_kit, passphrase)?;
    let owner_id = parse_hex_array::<16>(&authority.owner_id_hex)?;
    let device_id = parse_hex_array::<16>(&authority.device_id_hex)?;
    let device_recovery_secret = parse_hex_array::<32>(&authority.device_recovery_secret_hex)?;
    let owner_ca_der = parse_hex_vec(&authority.owner_ca_der_hex, MAX_CERTIFICATE_BYTES)?;
    let ca_key_der = Zeroizing::new(parse_hex_vec(&authority.owner_ca_key_der_hex, 8192)?);
    if owner_id.iter().all(|byte| *byte == 0)
        || device_id.iter().all(|byte| *byte == 0)
        || device_recovery_secret.iter().all(|byte| *byte == 0)
        || authority.authority_epoch == 0
    {
        return Err(OwnerKitError::InvalidAuthority);
    }
    validate_ca_key_pair(ca_key_der.as_slice(), &owner_ca_der)?;
    Ok(DeviceOwnerAuthority {
        owner_id,
        device_id,
        owner_ca_der,
        device_recovery_secret,
        authority_epoch: authority.authority_epoch,
    })
}

pub(super) fn unlock_device_authority_for_device(
    owner_kit: &[u8],
    passphrase: &[u8],
    device_id: [u8; 16],
) -> Result<DeviceOwnerAuthority, OwnerKitError> {
    let authority = select_authority(owner_kit, passphrase, Some(device_id))?;
    Ok(DeviceOwnerAuthority {
        owner_id: authority.owner_id,
        device_id: authority.device_id,
        owner_ca_der: authority.owner_ca_der,
        device_recovery_secret: *authority.device_recovery_secret,
        authority_epoch: authority.authority_epoch,
    })
}

fn decrypt(owner_kit: &[u8], passphrase: &[u8]) -> Result<OwnerKitPlaintext, OwnerKitError> {
    let (schema_version, plaintext) = decrypt_payload(owner_kit, passphrase)?;
    if schema_version != OWNER_KIT_SCHEMA_VERSION {
        return Err(OwnerKitError::InvalidAuthority);
    }
    let authority: OwnerKitPlaintext =
        serde_json::from_slice(&plaintext).map_err(|_| OwnerKitError::InvalidAuthority)?;
    if authority.schema_version != OWNER_KIT_SCHEMA_VERSION {
        return Err(OwnerKitError::InvalidAuthority);
    }
    Ok(authority)
}

fn decrypt_payload(
    owner_kit: &[u8],
    passphrase: &[u8],
) -> Result<(u8, Zeroizing<Vec<u8>>), OwnerKitError> {
    validate_passphrase(passphrase)?;
    if owner_kit.len() > MAX_OWNER_KIT_BYTES {
        return Err(OwnerKitError::InvalidEnvelope);
    }
    let envelope: OwnerKitEnvelope =
        serde_json::from_slice(owner_kit).map_err(|_| OwnerKitError::InvalidEnvelope)?;
    if !matches!(
        envelope.schema_version,
        OWNER_KIT_SCHEMA_VERSION | OWNER_KIT_SCHEMA_VERSION_V3
    ) || envelope.kdf != KDF_NAME
        || envelope.memory_kib != ARGON2_MEMORY_KIB
        || envelope.iterations != ARGON2_ITERATIONS
        || envelope.parallelism != ARGON2_PARALLELISM
        || envelope.cipher != CIPHER_NAME
    {
        return Err(OwnerKitError::InvalidEnvelope);
    }
    let salt = parse_hex_array::<SALT_BYTES>(&envelope.salt_hex)?;
    let nonce = parse_hex_array::<NONCE_BYTES>(&envelope.nonce_hex)?;
    let mut ciphertext = Zeroizing::new(parse_hex_vec(
        &envelope.ciphertext_hex,
        MAX_OWNER_KIT_BYTES,
    )?);
    let key = derive_envelope_key(passphrase, &salt)?;
    let cipher = LessSafeKey::new(
        UnboundKey::new(&aead::AES_256_GCM, key.as_slice())
            .map_err(|_| OwnerKitError::CryptoFailed)?,
    );
    let aad = match envelope.schema_version {
        OWNER_KIT_SCHEMA_VERSION => OWNER_KIT_AAD,
        OWNER_KIT_SCHEMA_VERSION_V3 => OWNER_KIT_AAD_V3,
        _ => return Err(OwnerKitError::InvalidEnvelope),
    };
    let plaintext_len = cipher
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| OwnerKitError::AuthenticationFailed)?
        .len();
    ciphertext.truncate(plaintext_len);
    Ok((envelope.schema_version, ciphertext))
}

fn validate_plaintext_authority(authority: &OwnerKitPlaintext) -> Result<(), OwnerKitError> {
    let owner_id = parse_hex_array::<16>(&authority.owner_id_hex)?;
    let device_id = parse_hex_array::<16>(&authority.device_id_hex)?;
    let recovery = Zeroizing::new(parse_hex_array::<32>(
        &authority.device_recovery_secret_hex,
    )?);
    let key = Zeroizing::new(parse_hex_vec(&authority.owner_ca_key_der_hex, 8192)?);
    let certificate = parse_hex_vec(&authority.owner_ca_der_hex, MAX_CERTIFICATE_BYTES)?;
    if owner_id.iter().all(|byte| *byte == 0)
        || device_id.iter().all(|byte| *byte == 0)
        || recovery.iter().all(|byte| *byte == 0)
        || authority.authority_epoch == 0
    {
        return Err(OwnerKitError::InvalidAuthority);
    }
    validate_ca_key_pair(key.as_slice(), &certificate)
}

fn validate_plaintext_authority_v3(authority: &OwnerKitPlaintextV3) -> Result<(), OwnerKitError> {
    let owner_id = parse_hex_array::<16>(&authority.owner_id_hex)?;
    let key = Zeroizing::new(parse_hex_vec(&authority.owner_ca_key_der_hex, 8192)?);
    let certificate = parse_hex_vec(&authority.owner_ca_der_hex, MAX_CERTIFICATE_BYTES)?;
    if authority.schema_version != OWNER_KIT_SCHEMA_VERSION_V3
        || owner_id.iter().all(|byte| *byte == 0)
        || authority.devices.is_empty()
        || authority.devices.len() > MAX_OWNER_DEVICES
    {
        return Err(OwnerKitError::InvalidAuthority);
    }
    let mut previous: Option<[u8; 16]> = None;
    for device in &authority.devices {
        let device_id = parse_hex_array::<16>(&device.device_id_hex)?;
        let recovery = Zeroizing::new(parse_hex_array::<32>(&device.device_recovery_secret_hex)?);
        if device.device_id_hex != hex(&device_id)
            || device_id.iter().all(|byte| *byte == 0)
            || recovery.iter().all(|byte| *byte == 0)
            || device.authority_epoch == 0
            || previous.is_some_and(|prior| prior >= device_id)
        {
            return Err(OwnerKitError::InvalidAuthority);
        }
        previous = Some(device_id);
    }
    validate_ca_key_pair(key.as_slice(), &certificate)
}

fn derive_envelope_key(
    passphrase: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Result<Zeroizing<[u8; 32]>, OwnerKitError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|_| OwnerKitError::CryptoFailed)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| OwnerKitError::CryptoFailed)?;
    Ok(key)
}

fn owner_ca_parameters(owner_id: &[u8; 16]) -> CertificateParams {
    let mut name = DistinguishedName::new();
    name.push(
        DnType::CommonName,
        format!("Keyferry owner {}", hex(owner_id)),
    );
    let mut parameters = CertificateParams::new(Vec::<String>::new())
        .expect("an empty SAN list is valid for the owner CA");
    parameters.distinguished_name = name;
    parameters.not_before = date_time_ymd(2020, 1, 1);
    parameters.not_after = date_time_ymd(4096, 1, 1);
    parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    parameters
}

fn certificate(
    dns_name: &str,
    role: ExtendedKeyUsagePurpose,
    normal_clock: bool,
    installation_key: &KeyPair,
    ca: &CertifiedIssuer<'_, KeyPair>,
) -> Result<Vec<u8>, OwnerKitError> {
    let mut parameters = CertificateParams::new(vec![dns_name.to_owned()])
        .map_err(|_| OwnerKitError::InvalidAuthority)?;
    parameters.not_before = date_time_ymd(if normal_clock { 2025 } else { 2020 }, 1, 1);
    parameters.not_after = date_time_ymd(if normal_clock { 2036 } else { 4096 }, 1, 1);
    parameters.is_ca = IsCa::ExplicitNoCa;
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![role];
    let der = parameters
        .signed_by(installation_key, ca)
        .map_err(|_| OwnerKitError::CryptoFailed)?
        .der()
        .to_vec();
    if der.len() > MAX_CERTIFICATE_BYTES {
        return Err(OwnerKitError::InvalidAuthority);
    }
    Ok(der)
}

fn validate_ca_key_pair(key_der: &[u8], certificate_der: &[u8]) -> Result<(), OwnerKitError> {
    let key = KeyPair::try_from(key_der).map_err(|_| OwnerKitError::InvalidAuthority)?;
    if key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        return Err(OwnerKitError::InvalidAuthority);
    }
    let (remainder, certificate) =
        parse_x509_certificate(certificate_der).map_err(|_| OwnerKitError::InvalidAuthority)?;
    if !remainder.is_empty()
        || certificate.tbs_certificate.subject_pki.raw != key.subject_public_key_info()
        || certificate.tbs_certificate.subject != certificate.tbs_certificate.issuer
        || !certificate
            .basic_constraints()
            .map_err(|_| OwnerKitError::InvalidAuthority)?
            .is_some_and(|constraints| constraints.value.ca)
        || !certificate
            .key_usage()
            .map_err(|_| OwnerKitError::InvalidAuthority)?
            .is_some_and(|usage| usage.value.key_cert_sign())
    {
        return Err(OwnerKitError::InvalidAuthority);
    }
    Ok(())
}

fn validate_passphrase(passphrase: &[u8]) -> Result<(), OwnerKitError> {
    if passphrase.is_empty()
        || passphrase.len() > MAX_PASSPHRASE_BYTES
        || passphrase.contains(&0)
        || passphrase.contains(&b'\n')
        || passphrase.contains(&b'\r')
    {
        return Err(OwnerKitError::InvalidPassphrase);
    }
    Ok(())
}

fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N], OwnerKitError> {
    parse_hex_vec(value, N)?
        .try_into()
        .map_err(|_| OwnerKitError::InvalidEnvelope)
}

fn parse_hex_vec(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, OwnerKitError> {
    if !value.len().is_multiple_of(2) || value.len() / 2 > maximum_bytes {
        return Err(OwnerKitError::InvalidEnvelope);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(OwnerKitError::InvalidEnvelope)?;
            let low = hex_nibble(pair[1]).ok_or(OwnerKitError::InvalidEnvelope)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &[u8] = b"correct horse battery staple";

    #[test]
    fn encrypted_kit_issues_distinct_bounded_installations() {
        let kit = create(
            [0x22; 16], [0x33; 32], PASSPHRASE, [0x44; 16], [0x55; 12], [0x66; 16],
        )
        .expect("create owner kit");
        assert!(kit.len() < MAX_OWNER_KIT_BYTES);
        let text = String::from_utf8(kit.clone()).unwrap();
        assert!(!text.contains(&hex(&[0x33; 32])));
        assert!(!text.contains("correct horse"));

        let first = issue_installation(&kit, PASSPHRASE).expect("first installation");
        let second = issue_installation(&kit, PASSPHRASE).expect("second installation");
        assert_ne!(
            first.manifest.installation_id_hex,
            second.manifest.installation_id_hex
        );
        assert_ne!(first.device_link_secret, second.device_link_secret);
        assert_ne!(first.route_proof_secret, second.route_proof_secret);
        assert_eq!(first.manifest.device_id_hex, hex(&[0x22; 16]));
        assert_eq!(first.manifest.owner_id_hex, hex(&[0x66; 16]));
        assert_eq!(first.manifest.authority_epoch, 1);
        assert_eq!(first.installation_spki_der.len(), 91);
        for certificate in [
            &first.owner_ca_der,
            &first.device_server_certificate_der,
            &first.desktop_server_certificate_der,
            &first.desktop_client_certificate_der,
        ] {
            assert!(certificate.len() <= MAX_CERTIFICATE_BYTES);
            assert!(parse_x509_certificate(certificate).is_ok());
        }
        let (_, owner_ca) = parse_x509_certificate(&first.owner_ca_der).unwrap();
        assert!(
            owner_ca
                .basic_constraints()
                .unwrap()
                .expect("owner CA basic constraints")
                .value
                .ca
        );
        for (certificate, server_auth, client_auth) in [
            (&first.device_server_certificate_der, true, false),
            (&first.desktop_server_certificate_der, true, false),
            (&first.desktop_client_certificate_der, false, true),
        ] {
            let (_, leaf) = parse_x509_certificate(certificate).unwrap();
            assert!(
                !leaf
                    .basic_constraints()
                    .unwrap()
                    .expect("leaf basic constraints")
                    .value
                    .ca
            );
            assert_eq!(
                leaf.tbs_certificate.subject_pki.raw,
                first.installation_spki_der
            );
            let usage = leaf
                .extended_key_usage()
                .unwrap()
                .expect("leaf extended key usage")
                .value;
            assert_eq!(usage.server_auth, server_auth);
            assert_eq!(usage.client_auth, client_auth);
            assert!(!usage.any);
        }
    }

    #[test]
    fn multi_device_add_migrates_v2_without_changing_existing_authority() {
        let original = create(
            [0x22; 16], [0x33; 32], PASSPHRASE, [0x44; 16], [0x55; 12], [0x66; 16],
        )
        .unwrap();
        let before = decrypt(&original, PASSPHRASE).unwrap();
        let changed = add_device(
            &original, PASSPHRASE, [0x77; 16], [0x88; 32], [0x99; 16], [0xaa; 12],
        )
        .unwrap();
        let envelope: OwnerKitEnvelope = serde_json::from_slice(&changed).unwrap();
        assert_eq!(envelope.schema_version, OWNER_KIT_SCHEMA_VERSION_V3);
        let (schema, plaintext) = decrypt_payload(&changed, PASSPHRASE).unwrap();
        assert_eq!(schema, OWNER_KIT_SCHEMA_VERSION_V3);
        let after: OwnerKitPlaintextV3 = serde_json::from_slice(&plaintext).unwrap();
        validate_plaintext_authority_v3(&after).unwrap();
        assert_eq!(after.owner_id_hex, before.owner_id_hex);
        assert_eq!(after.owner_ca_key_der_hex, before.owner_ca_key_der_hex);
        assert_eq!(after.owner_ca_der_hex, before.owner_ca_der_hex);
        assert_eq!(after.devices.len(), 2);
        assert_eq!(after.devices[0].device_id_hex, before.device_id_hex);
        assert_eq!(
            after.devices[0].device_recovery_secret_hex,
            before.device_recovery_secret_hex
        );
        assert_eq!(after.devices[0].authority_epoch, before.authority_epoch);
        assert_eq!(after.devices[1].device_id_hex, hex(&[0x77; 16]));
        assert_eq!(
            after.devices[1].device_recovery_secret_hex,
            hex(&[0x88; 32])
        );
        assert_eq!(after.devices[1].authority_epoch, 1);
        assert_eq!(
            device_ids(&changed, PASSPHRASE).unwrap(),
            vec![[0x22; 16], [0x77; 16]]
        );
    }

    #[test]
    fn multi_device_duplicate_add_and_v3_wrong_passphrase_fail_closed() {
        let original = create(
            [0x22; 16], [0x33; 32], PASSPHRASE, [0x44; 16], [0x55; 12], [0x66; 16],
        )
        .unwrap();
        let changed = add_device(
            &original, PASSPHRASE, [0x77; 16], [0x88; 32], [0x99; 16], [0xaa; 12],
        )
        .unwrap();
        assert_eq!(
            decrypt_payload(&changed, b"wrong passphrase value").err(),
            Some(OwnerKitError::AuthenticationFailed)
        );
        assert_eq!(
            add_device(&changed, PASSPHRASE, [0x77; 16], [0xbb; 32], [0xcc; 16], [0xdd; 12],).err(),
            Some(OwnerKitError::InvalidAuthority)
        );
    }

    #[test]
    fn multi_device_v3_passphrase_change_preserves_every_authority() {
        let original = create(
            [0x22; 16], [0x33; 32], PASSPHRASE, [0x44; 16], [0x55; 12], [0x66; 16],
        )
        .unwrap();
        let expanded = add_device(
            &original, PASSPHRASE, [0x77; 16], [0x88; 32], [0x99; 16], [0xaa; 12],
        )
        .unwrap();
        let changed = change_passphrase(
            &expanded,
            PASSPHRASE,
            b"new owner passphrase",
            [0xbb; 16],
            [0xcc; 12],
        )
        .unwrap();
        assert_eq!(
            decrypt_payload(&changed, PASSPHRASE).err(),
            Some(OwnerKitError::AuthenticationFailed)
        );
        let (_, before) = decrypt_payload(&expanded, PASSPHRASE).unwrap();
        let (_, after) = decrypt_payload(&changed, b"new owner passphrase").unwrap();
        assert_eq!(before.as_slice(), after.as_slice());
    }

    #[test]
    fn wrong_passphrase_and_tamper_fail_but_short_owner_choice_is_accepted() {
        let kit = create([1; 16], [2; 32], PASSPHRASE, [3; 16], [4; 12], [5; 16]).unwrap();
        assert_eq!(
            issue_installation(&kit, b"wrong passphrase value").err(),
            Some(OwnerKitError::AuthenticationFailed)
        );
        let mut envelope: OwnerKitEnvelope = serde_json::from_slice(&kit).unwrap();
        envelope.ciphertext_hex.replace_range(0..2, "00");
        let tampered = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(
            issue_installation(&tampered, PASSPHRASE).err(),
            Some(OwnerKitError::AuthenticationFailed)
        );
        let short = create([1; 16], [2; 32], b"short", [3; 16], [4; 12], [5; 16])
            .expect("owner-selected short passphrase");
        issue_installation(&short, b"short").expect("short passphrase decrypts its kit");
        assert_eq!(
            create([1; 16], [2; 32], b"", [3; 16], [4; 12], [5; 16]).err(),
            Some(OwnerKitError::InvalidPassphrase)
        );
    }

    #[test]
    fn passphrase_change_preserves_authority_and_rejects_the_old_secret() {
        let original = create(
            [0x11; 16], [0x22; 32], b"old", [0x33; 16], [0x44; 12], [0x55; 16],
        )
        .expect("original owner kit");
        let expected = decrypt(&original, b"old").expect("original authority");
        let changed = change_passphrase(&original, b"old", b"new", [0x66; 16], [0x77; 12])
            .expect("change passphrase");
        let original_envelope: OwnerKitEnvelope =
            serde_json::from_slice(&original).expect("original envelope");
        let changed_envelope: OwnerKitEnvelope =
            serde_json::from_slice(&changed).expect("changed envelope");

        assert_ne!(changed, original);
        assert_eq!(
            changed_envelope.schema_version,
            original_envelope.schema_version
        );
        assert_eq!(changed_envelope.kdf, original_envelope.kdf);
        assert_eq!(changed_envelope.memory_kib, original_envelope.memory_kib);
        assert_eq!(changed_envelope.iterations, original_envelope.iterations);
        assert_eq!(changed_envelope.parallelism, original_envelope.parallelism);
        assert_eq!(changed_envelope.cipher, original_envelope.cipher);
        assert_ne!(changed_envelope.salt_hex, original_envelope.salt_hex);
        assert_ne!(changed_envelope.nonce_hex, original_envelope.nonce_hex);
        assert_ne!(
            changed_envelope.ciphertext_hex,
            original_envelope.ciphertext_hex
        );
        assert_eq!(
            decrypt(&changed, b"old").err(),
            Some(OwnerKitError::AuthenticationFailed)
        );
        assert_eq!(decrypt(&changed, b"new").unwrap(), expected);
        issue_installation(&changed, b"new").expect("new passphrase issues credentials");
    }

    #[test]
    fn passphrase_change_rejects_bad_current_or_empty_new_secret() {
        let original = create(
            [0x11; 16], [0x22; 32], b"old", [0x33; 16], [0x44; 12], [0x55; 16],
        )
        .expect("original owner kit");
        assert_eq!(
            change_passphrase(&original, b"wrong", b"new", [0x66; 16], [0x77; 12]).err(),
            Some(OwnerKitError::AuthenticationFailed)
        );
        assert_eq!(
            change_passphrase(&original, b"old", b"", [0x66; 16], [0x77; 12]).err(),
            Some(OwnerKitError::InvalidPassphrase)
        );
    }

    #[test]
    fn envelope_rejects_cost_downgrade_before_kdf_work() {
        let kit = create([1; 16], [2; 32], PASSPHRASE, [3; 16], [4; 12], [5; 16]).unwrap();
        let mut envelope: OwnerKitEnvelope = serde_json::from_slice(&kit).unwrap();
        envelope.memory_kib = 8;
        let downgraded = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(
            issue_installation(&downgraded, PASSPHRASE).err(),
            Some(OwnerKitError::InvalidEnvelope)
        );
    }
}
