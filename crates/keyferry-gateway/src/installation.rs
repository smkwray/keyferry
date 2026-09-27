use super::{device_gateway_name, installation_gateway_name, installation_id_for_spki};
use ring::{
    digest::{digest, SHA256},
    rand::SystemRandom,
    signature::{
        EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt, fs, io, io::Read as _, path::Path};
use x509_parser::parse_x509_certificate;

const MAX_KEY_BYTES: usize = 512;
const MAX_SPKI_BYTES: usize = 256;
const MAX_CERTIFICATE_BYTES: usize = 2048;
const MAX_INSTALLATION_MANIFEST_BYTES: usize = 16 * 1024;
const MAX_GRANT_BYTES: usize = 8 * 1024;
const MAX_INSTALLATION_DEVICES: usize = 8;
const INSTALLATION_SCHEMA_V3: u8 = 3;
const DEVICE_GRANT_SCHEMA_V1: u8 = 1;
const DEVICE_GRANT_DOMAIN: &str = "keyferry-device-installation-grant-v1";

#[derive(Clone, Debug)]
pub struct InstallationCredentialSet {
    credentials: Vec<InstallationCredentials>,
}

#[derive(Debug, Deserialize)]
struct InstallationManifestVersion {
    schema_version: u8,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationManifestV3 {
    pub schema_version: u8,
    pub owner_id_hex: String,
    pub installation_id_hex: String,
    pub devices: Vec<InstallationDeviceV3>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationDeviceV3 {
    pub device_id_hex: String,
    pub authority_epoch: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceGrantV1 {
    pub schema_version: u8,
    pub domain: String,
    pub owner_id_hex: String,
    pub owner_ca_sha256_hex: String,
    pub device_id_hex: String,
    pub authority_epoch: u64,
    pub installation_id_hex: String,
    pub installation_spki_sha256_hex: String,
    pub device_server_certificate_sha256_hex: String,
    pub device_link_secret_sha256_hex: String,
    pub route_proof_secret_sha256_hex: String,
    pub signature_der_hex: String,
}

impl DeviceGrantV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        owner_key_der: &[u8],
        owner_id: [u8; 16],
        owner_ca_der: &[u8],
        device_id: [u8; 16],
        authority_epoch: u64,
        installation_id: [u8; 16],
        installation_spki_der: &[u8],
        device_server_certificate_der: &[u8],
        device_link_secret: &[u8; 32],
        route_proof_secret: &[u8; 32],
    ) -> io::Result<Self> {
        if authority_epoch == 0 {
            return invalid("device grant authority epoch is zero");
        }
        let fields = DeviceGrantFields {
            owner_id,
            owner_ca_sha256: sha256(owner_ca_der),
            device_id,
            authority_epoch,
            installation_id,
            installation_spki_sha256: sha256(installation_spki_der),
            device_server_certificate_sha256: sha256(device_server_certificate_der),
            device_link_secret_sha256: sha256(device_link_secret),
            route_proof_secret_sha256: sha256(route_proof_secret),
        };
        let owner_key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            owner_key_der,
            &SystemRandom::new(),
        )
        .map_err(|_| invalid_error("owner signing key is invalid"))?;
        let signature = owner_key
            .sign(&SystemRandom::new(), &grant_signing_bytes(&fields))
            .map_err(|_| invalid_error("device grant signing failed"))?;
        Ok(Self {
            schema_version: DEVICE_GRANT_SCHEMA_V1,
            domain: DEVICE_GRANT_DOMAIN.to_owned(),
            owner_id_hex: hex(&fields.owner_id),
            owner_ca_sha256_hex: hex(&fields.owner_ca_sha256),
            device_id_hex: hex(&fields.device_id),
            authority_epoch: fields.authority_epoch,
            installation_id_hex: hex(&fields.installation_id),
            installation_spki_sha256_hex: hex(&fields.installation_spki_sha256),
            device_server_certificate_sha256_hex: hex(&fields.device_server_certificate_sha256),
            device_link_secret_sha256_hex: hex(&fields.device_link_secret_sha256),
            route_proof_secret_sha256_hex: hex(&fields.route_proof_secret_sha256),
            signature_der_hex: hex(signature.as_ref()),
        })
    }
}

impl InstallationCredentialSet {
    /// Loads the unchanged singleton layout or an explicitly activated schema-3 generation.
    ///
    /// `installation-v3.json` is the activation marker. Once it exists, any malformed schema-3
    /// material is an error and the loader never falls back to singleton credentials.
    pub fn load(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        let marker = root.join("installation-v3.json");
        if !marker.exists() {
            return Ok(Self {
                credentials: vec![InstallationCredentials::load(root)?],
            });
        }
        load_v3(root, &marker)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &InstallationCredentials> {
        self.credentials.iter()
    }

    #[must_use]
    pub fn get(&self, device_id: [u8; 16]) -> Option<&InstallationCredentials> {
        self.credentials
            .binary_search_by_key(&device_id, InstallationCredentials::device_id)
            .ok()
            .map(|index| &self.credentials[index])
    }
}

#[derive(Clone)]
pub struct InstallationCredentials {
    owner_id: [u8; 16],
    device_id: [u8; 16],
    installation_id: [u8; 16],
    owner_ca_der: Vec<u8>,
    installation_spki_der: Vec<u8>,
    installation_key_der: Vec<u8>,
    device_server_certificate_der: Vec<u8>,
    desktop_server_certificate_der: Vec<u8>,
    desktop_client_certificate_der: Vec<u8>,
    device_link_secret: [u8; 32],
    route_proof_secret: [u8; 32],
    device_server_name: String,
    desktop_server_name: String,
}

impl fmt::Debug for InstallationCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallationCredentials")
            .field("owner_id", &self.owner_id)
            .field("device_id", &self.device_id)
            .field("installation_id", &self.installation_id)
            .field("installation_key_der", &"[secret key elided]")
            .field("device_link_secret", &"[secret elided]")
            .field("route_proof_secret", &"[secret elided]")
            .finish_non_exhaustive()
    }
}

impl InstallationCredentials {
    pub fn load(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        let owner_id = read_fixed::<16>(&root.join("owner-id.bin"))?;
        let device_id = read_fixed::<16>(&root.join("device-id.bin"))?;
        let installation_id = read_fixed::<16>(&root.join("installation-id.bin"))?;
        if owner_id.iter().all(|byte| *byte == 0)
            || device_id.iter().all(|byte| *byte == 0)
            || installation_id.iter().all(|byte| *byte == 0)
        {
            return invalid("installation identity contains an all-zero identifier");
        }

        let installation_spki_der =
            read_bounded(&root.join("installation-spki.der"), MAX_SPKI_BYTES)?;
        let derived_id = installation_id_for_spki(&installation_spki_der)
            .map_err(|_| invalid_error("installation SPKI is not canonical P-256 DER"))?;
        if derived_id != installation_id {
            return invalid("installation ID does not match installation SPKI");
        }

        let installation_key_der = read_bounded(&root.join("installation-key.der"), MAX_KEY_BYTES)?;
        let key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &installation_key_der,
            &SystemRandom::new(),
        )
        .map_err(|_| invalid_error("installation private key is invalid"))?;
        if installation_spki_der.get(26..) != Some(key.public_key().as_ref()) {
            return invalid("installation private key does not match installation SPKI");
        }

        let owner_ca_der = read_bounded(&root.join("owner-ca.der"), MAX_CERTIFICATE_BYTES)?;
        let device_server_certificate_der =
            read_bounded(&root.join("device-server-cert.der"), MAX_CERTIFICATE_BYTES)?;
        let desktop_server_certificate_der =
            read_bounded(&root.join("desktop-server-cert.der"), MAX_CERTIFICATE_BYTES)?;
        let desktop_client_certificate_der =
            read_bounded(&root.join("desktop-client-cert.der"), MAX_CERTIFICATE_BYTES)?;
        let device_link_secret = read_fixed::<32>(&root.join("device-link-secret.bin"))?;
        let route_proof_secret = read_fixed::<32>(&root.join("route-proof-secret.bin"))?;
        if device_link_secret.iter().all(|byte| *byte == 0)
            || route_proof_secret.iter().all(|byte| *byte == 0)
        {
            return invalid("installation secret is all zero");
        }

        Ok(Self {
            owner_id,
            device_id,
            installation_id,
            owner_ca_der,
            installation_spki_der,
            installation_key_der,
            device_server_certificate_der,
            desktop_server_certificate_der,
            desktop_client_certificate_der,
            device_link_secret,
            route_proof_secret,
            device_server_name: device_gateway_name(&device_id)
                .map_err(|_| invalid_error("device identity is invalid"))?,
            desktop_server_name: installation_gateway_name(&installation_id)
                .map_err(|_| invalid_error("installation identity is invalid"))?,
        })
    }

    pub fn owner_id(&self) -> [u8; 16] {
        self.owner_id
    }
    pub fn device_id(&self) -> [u8; 16] {
        self.device_id
    }
    pub fn installation_id(&self) -> [u8; 16] {
        self.installation_id
    }
    pub fn owner_ca_der(&self) -> &[u8] {
        &self.owner_ca_der
    }
    pub fn installation_spki_der(&self) -> &[u8] {
        &self.installation_spki_der
    }
    pub fn installation_key_der(&self) -> &[u8] {
        &self.installation_key_der
    }
    pub fn device_server_certificate_der(&self) -> &[u8] {
        &self.device_server_certificate_der
    }
    pub fn desktop_server_certificate_der(&self) -> &[u8] {
        &self.desktop_server_certificate_der
    }
    pub fn desktop_client_certificate_der(&self) -> &[u8] {
        &self.desktop_client_certificate_der
    }
    pub fn device_link_secret(&self) -> [u8; 32] {
        self.device_link_secret
    }
    pub fn route_proof_secret(&self) -> [u8; 32] {
        self.route_proof_secret
    }
    pub fn device_server_name(&self) -> &str {
        &self.device_server_name
    }
    pub fn desktop_server_name(&self) -> &str {
        &self.desktop_server_name
    }
}

fn load_v3(root: &Path, marker: &Path) -> io::Result<InstallationCredentialSet> {
    let marker_bytes = read_bounded_nosymlink(marker, MAX_INSTALLATION_MANIFEST_BYTES)?;
    let version: InstallationManifestVersion = serde_json::from_slice(&marker_bytes)
        .map_err(|_| invalid_error("schema-3 installation manifest is invalid"))?;
    if version.schema_version != INSTALLATION_SCHEMA_V3 {
        return invalid("installation-v3.json has an unsupported schema version");
    }
    let manifest: InstallationManifestV3 = serde_json::from_slice(&marker_bytes)
        .map_err(|_| invalid_error("schema-3 installation manifest is invalid"))?;
    if manifest.schema_version != INSTALLATION_SCHEMA_V3
        || manifest.devices.is_empty()
        || manifest.devices.len() > MAX_INSTALLATION_DEVICES
    {
        return invalid("schema-3 installation manifest has an invalid device count");
    }

    let owner_id = parse_hex_array::<16>(&manifest.owner_id_hex, "owner ID")?;
    let installation_id = parse_hex_array::<16>(&manifest.installation_id_hex, "installation ID")?;
    if owner_id.iter().all(|byte| *byte == 0) || installation_id.iter().all(|byte| *byte == 0) {
        return invalid("schema-3 installation contains an all-zero identifier");
    }
    if read_fixed_nosymlink::<16>(&root.join("owner-id.bin"))? != owner_id
        || read_fixed_nosymlink::<16>(&root.join("installation-id.bin"))? != installation_id
    {
        return invalid("schema-3 manifest does not match root identity files");
    }

    let installation_spki_der =
        read_bounded_nosymlink(&root.join("installation-spki.der"), MAX_SPKI_BYTES)?;
    let derived_id = installation_id_for_spki(&installation_spki_der)
        .map_err(|_| invalid_error("installation SPKI is not canonical P-256 DER"))?;
    if derived_id != installation_id {
        return invalid("installation ID does not match installation SPKI");
    }
    let installation_key_der =
        read_bounded_nosymlink(&root.join("installation-key.der"), MAX_KEY_BYTES)?;
    let key = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &installation_key_der,
        &SystemRandom::new(),
    )
    .map_err(|_| invalid_error("installation private key is invalid"))?;
    if installation_spki_der.get(26..) != Some(key.public_key().as_ref()) {
        return invalid("installation private key does not match installation SPKI");
    }

    let owner_ca_der = read_bounded_nosymlink(&root.join("owner-ca.der"), MAX_CERTIFICATE_BYTES)?;
    let (_, owner_ca) = parse_x509_certificate(&owner_ca_der)
        .map_err(|_| invalid_error("owner CA certificate is invalid"))?;
    let owner_public_key = owner_ca.public_key().subject_public_key.data.as_ref();
    if owner_public_key.len() != 65 {
        return invalid("owner CA public key is not canonical P-256");
    }
    let desktop_server_certificate_der =
        read_bounded_nosymlink(&root.join("desktop-server-cert.der"), MAX_CERTIFICATE_BYTES)?;
    let desktop_client_certificate_der =
        read_bounded_nosymlink(&root.join("desktop-client-cert.der"), MAX_CERTIFICATE_BYTES)?;
    let desktop_server_name = installation_gateway_name(&installation_id)
        .map_err(|_| invalid_error("installation identity is invalid"))?;

    let devices_root = root.join("devices");
    require_real_directory(&devices_root)?;
    let mut expected_names = HashSet::with_capacity(manifest.devices.len());
    let mut credentials = Vec::with_capacity(manifest.devices.len());
    for entry in manifest.devices {
        let device_id = parse_hex_array::<16>(&entry.device_id_hex, "device ID")?;
        if device_id.iter().all(|byte| *byte == 0) || entry.authority_epoch == 0 {
            return invalid("schema-3 device authority is invalid");
        }
        let canonical_name = hex(&device_id);
        if entry.device_id_hex != canonical_name || !expected_names.insert(canonical_name.clone()) {
            return invalid("schema-3 device IDs are duplicate or non-canonical");
        }
        let device_root = devices_root.join(&canonical_name);
        require_real_directory(&device_root)?;
        if read_fixed_nosymlink::<16>(&device_root.join("device-id.bin"))? != device_id {
            return invalid("schema-3 device directory has a mismatched device ID");
        }
        let device_server_certificate_der = read_bounded_nosymlink(
            &device_root.join("device-server-cert.der"),
            MAX_CERTIFICATE_BYTES,
        )?;
        let device_link_secret =
            read_fixed_nosymlink::<32>(&device_root.join("device-link-secret.bin"))?;
        let route_proof_secret =
            read_fixed_nosymlink::<32>(&device_root.join("route-proof-secret.bin"))?;
        if device_link_secret.iter().all(|byte| *byte == 0)
            || route_proof_secret.iter().all(|byte| *byte == 0)
        {
            return invalid("schema-3 installation secret is all zero");
        }

        let grant_bytes = read_bounded_nosymlink(&device_root.join("grant.json"), MAX_GRANT_BYTES)?;
        let grant: DeviceGrantV1 = serde_json::from_slice(&grant_bytes)
            .map_err(|_| invalid_error("schema-3 device grant is invalid"))?;
        verify_grant(
            &grant,
            owner_id,
            &owner_ca_der,
            owner_public_key,
            device_id,
            entry.authority_epoch,
            installation_id,
            &installation_spki_der,
            &device_server_certificate_der,
            &device_link_secret,
            &route_proof_secret,
        )?;

        credentials.push(InstallationCredentials {
            owner_id,
            device_id,
            installation_id,
            owner_ca_der: owner_ca_der.clone(),
            installation_spki_der: installation_spki_der.clone(),
            installation_key_der: installation_key_der.clone(),
            device_server_certificate_der,
            desktop_server_certificate_der: desktop_server_certificate_der.clone(),
            desktop_client_certificate_der: desktop_client_certificate_der.clone(),
            device_link_secret,
            route_proof_secret,
            device_server_name: device_gateway_name(&device_id)
                .map_err(|_| invalid_error("device identity is invalid"))?,
            desktop_server_name: desktop_server_name.clone(),
        });
    }

    for entry in fs::read_dir(&devices_root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid_error("schema-3 device directory name is not UTF-8"))?;
        if !expected_names.contains(&name) {
            return invalid("schema-3 devices directory contains an unmanifested entry");
        }
    }
    credentials.sort_unstable_by_key(InstallationCredentials::device_id);
    Ok(InstallationCredentialSet { credentials })
}

#[allow(clippy::too_many_arguments)]
fn verify_grant(
    grant: &DeviceGrantV1,
    owner_id: [u8; 16],
    owner_ca_der: &[u8],
    owner_public_key: &[u8],
    device_id: [u8; 16],
    authority_epoch: u64,
    installation_id: [u8; 16],
    installation_spki_der: &[u8],
    device_server_certificate_der: &[u8],
    device_link_secret: &[u8; 32],
    route_proof_secret: &[u8; 32],
) -> io::Result<()> {
    let expected = DeviceGrantFields {
        owner_id,
        owner_ca_sha256: sha256(owner_ca_der),
        device_id,
        authority_epoch,
        installation_id,
        installation_spki_sha256: sha256(installation_spki_der),
        device_server_certificate_sha256: sha256(device_server_certificate_der),
        device_link_secret_sha256: sha256(device_link_secret),
        route_proof_secret_sha256: sha256(route_proof_secret),
    };
    if grant.schema_version != DEVICE_GRANT_SCHEMA_V1
        || grant.domain != DEVICE_GRANT_DOMAIN
        || parse_hex_array::<16>(&grant.owner_id_hex, "grant owner ID")? != expected.owner_id
        || parse_hex_array::<32>(&grant.owner_ca_sha256_hex, "grant owner CA digest")?
            != expected.owner_ca_sha256
        || parse_hex_array::<16>(&grant.device_id_hex, "grant device ID")? != expected.device_id
        || grant.authority_epoch != expected.authority_epoch
        || parse_hex_array::<16>(&grant.installation_id_hex, "grant installation ID")?
            != expected.installation_id
        || parse_hex_array::<32>(
            &grant.installation_spki_sha256_hex,
            "grant installation SPKI digest",
        )? != expected.installation_spki_sha256
        || parse_hex_array::<32>(
            &grant.device_server_certificate_sha256_hex,
            "grant device certificate digest",
        )? != expected.device_server_certificate_sha256
        || parse_hex_array::<32>(
            &grant.device_link_secret_sha256_hex,
            "grant link-secret digest",
        )? != expected.device_link_secret_sha256
        || parse_hex_array::<32>(
            &grant.route_proof_secret_sha256_hex,
            "grant route-proof digest",
        )? != expected.route_proof_secret_sha256
    {
        return invalid("schema-3 device grant does not match credential material");
    }
    let signature = parse_hex_bounded(&grant.signature_der_hex, 72, "grant signature")?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, owner_public_key)
        .verify(&grant_signing_bytes(&expected), &signature)
        .map_err(|_| invalid_error("schema-3 device grant signature is invalid"))
}

struct DeviceGrantFields {
    owner_id: [u8; 16],
    owner_ca_sha256: [u8; 32],
    device_id: [u8; 16],
    authority_epoch: u64,
    installation_id: [u8; 16],
    installation_spki_sha256: [u8; 32],
    device_server_certificate_sha256: [u8; 32],
    device_link_secret_sha256: [u8; 32],
    route_proof_secret_sha256: [u8; 32],
}

fn grant_signing_bytes(fields: &DeviceGrantFields) -> Vec<u8> {
    let mut output = Vec::with_capacity(249);
    output.extend_from_slice(DEVICE_GRANT_DOMAIN.as_bytes());
    output.push(0);
    output.extend_from_slice(&fields.owner_id);
    output.extend_from_slice(&fields.owner_ca_sha256);
    output.extend_from_slice(&fields.device_id);
    output.extend_from_slice(&fields.authority_epoch.to_le_bytes());
    output.extend_from_slice(&fields.installation_id);
    output.extend_from_slice(&fields.installation_spki_sha256);
    output.extend_from_slice(&fields.device_server_certificate_sha256);
    output.extend_from_slice(&fields.device_link_secret_sha256);
    output.extend_from_slice(&fields.route_proof_secret_sha256);
    output
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    digest(&SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 output has 32 bytes")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn parse_hex_array<const N: usize>(value: &str, label: &str) -> io::Result<[u8; N]> {
    parse_hex_bounded(value, N, label)?
        .try_into()
        .map_err(|_| invalid_error(&format!("{label} has an invalid length")))
}

fn parse_hex_bounded(value: &str, maximum_bytes: usize, label: &str) -> io::Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || value.len() > maximum_bytes * 2 || value.is_empty() {
        return invalid(&format!("{label} has an invalid length"));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high =
            hex_nibble(pair[0]).ok_or_else(|| invalid_error(&format!("{label} is invalid")))?;
        let low =
            hex_nibble(pair[1]).ok_or_else(|| invalid_error(&format!("{label} is invalid")))?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn require_real_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return invalid(&format!("{} is not a real directory", path.display()));
    }
    Ok(())
}

fn read_fixed_nosymlink<const N: usize>(path: &Path) -> io::Result<[u8; N]> {
    read_bounded_nosymlink(path, N)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            invalid_error(&format!(
                "{} has {} bytes, expected {N}",
                path.display(),
                bytes.len()
            ))
        })
}

fn read_bounded_nosymlink(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return invalid(&format!("{} is not a real file", path.display()));
    }
    read_bounded(path, maximum)
}

fn read_fixed<const N: usize>(path: &Path) -> io::Result<[u8; N]> {
    let bytes = fs::read(path)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        invalid_error(&format!(
            "{} has {} bytes, expected {N}",
            path.display(),
            bytes.len()
        ))
    })
}

fn read_bounded(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return invalid(&format!("{} has an invalid size", path.display()));
    }
    Ok(bytes)
}

fn invalid<T>(message: &str) -> io::Result<T> {
    Err(invalid_error(message))
}

fn invalid_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName,
        DnType, IsCa, KeyPair as RcgenKeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "keyferry-installation-test-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create test root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        root: TestRoot,
        owner_id: [u8; 16],
        installation_id: [u8; 16],
        owner_ca_der: Vec<u8>,
        owner_key_der: Vec<u8>,
        installation_spki_der: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let root = TestRoot::new();
            let owner_id = [0x11; 16];
            let owner_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let owner_key_der = owner_key.serialize_der();
            let mut name = DistinguishedName::new();
            name.push(DnType::CommonName, "Keyferry test owner");
            let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
            parameters.distinguished_name = name;
            parameters.not_before = date_time_ymd(2020, 1, 1);
            parameters.not_after = date_time_ymd(4096, 1, 1);
            parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let owner_ca_der = CertifiedIssuer::self_signed(parameters, owner_key)
                .unwrap()
                .der()
                .to_vec();

            let installation_key_der =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                    .unwrap();
            let installation_key = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                installation_key_der.as_ref(),
                &SystemRandom::new(),
            )
            .unwrap();
            let mut installation_spki_der = vec![
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
            ];
            installation_spki_der.extend_from_slice(installation_key.public_key().as_ref());
            let installation_id = installation_id_for_spki(&installation_spki_der).unwrap();

            for (name, bytes) in [
                ("owner-id.bin", owner_id.as_slice()),
                ("installation-id.bin", installation_id.as_slice()),
                ("owner-ca.der", owner_ca_der.as_slice()),
                ("installation-spki.der", installation_spki_der.as_slice()),
                ("installation-key.der", installation_key_der.as_ref()),
                ("desktop-server-cert.der", b"desktop-server".as_slice()),
                ("desktop-client-cert.der", b"desktop-client".as_slice()),
            ] {
                fs::write(root.0.join(name), bytes).unwrap();
            }
            Self {
                root,
                owner_id,
                installation_id,
                owner_ca_der,
                owner_key_der,
                installation_spki_der,
            }
        }

        fn add_v2_device(&self, device_id: [u8; 16]) {
            for (name, bytes) in [
                ("device-id.bin", device_id.as_slice()),
                ("device-server-cert.der", b"v2-device-cert".as_slice()),
                ("device-link-secret.bin", [0x61; 32].as_slice()),
                ("route-proof-secret.bin", [0x62; 32].as_slice()),
            ] {
                fs::write(self.root.0.join(name), bytes).unwrap();
            }
        }

        fn add_v3_device(&self, device_id: [u8; 16], epoch: u64, secret_byte: u8) {
            let device_root = self.root.0.join("devices").join(hex(&device_id));
            fs::create_dir_all(&device_root).unwrap();
            let certificate = format!("device-certificate-{secret_byte}").into_bytes();
            let link_secret = [secret_byte; 32];
            let route_secret = [secret_byte.wrapping_add(1); 32];
            fs::write(device_root.join("device-id.bin"), device_id).unwrap();
            fs::write(device_root.join("device-server-cert.der"), &certificate).unwrap();
            fs::write(device_root.join("device-link-secret.bin"), link_secret).unwrap();
            fs::write(device_root.join("route-proof-secret.bin"), route_secret).unwrap();

            let fields = DeviceGrantFields {
                owner_id: self.owner_id,
                owner_ca_sha256: sha256(&self.owner_ca_der),
                device_id,
                authority_epoch: epoch,
                installation_id: self.installation_id,
                installation_spki_sha256: sha256(&self.installation_spki_der),
                device_server_certificate_sha256: sha256(&certificate),
                device_link_secret_sha256: sha256(&link_secret),
                route_proof_secret_sha256: sha256(&route_secret),
            };
            let owner_key = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                &self.owner_key_der,
                &SystemRandom::new(),
            )
            .unwrap();
            let signature = owner_key
                .sign(&SystemRandom::new(), &grant_signing_bytes(&fields))
                .unwrap();
            let grant = DeviceGrantV1 {
                schema_version: DEVICE_GRANT_SCHEMA_V1,
                domain: DEVICE_GRANT_DOMAIN.to_owned(),
                owner_id_hex: hex(&fields.owner_id),
                owner_ca_sha256_hex: hex(&fields.owner_ca_sha256),
                device_id_hex: hex(&fields.device_id),
                authority_epoch: fields.authority_epoch,
                installation_id_hex: hex(&fields.installation_id),
                installation_spki_sha256_hex: hex(&fields.installation_spki_sha256),
                device_server_certificate_sha256_hex: hex(&fields.device_server_certificate_sha256),
                device_link_secret_sha256_hex: hex(&fields.device_link_secret_sha256),
                route_proof_secret_sha256_hex: hex(&fields.route_proof_secret_sha256),
                signature_der_hex: hex(signature.as_ref()),
            };
            fs::write(
                device_root.join("grant.json"),
                serde_json::to_vec_pretty(&grant).unwrap(),
            )
            .unwrap();
        }

        fn activate_v3(&self, devices: Vec<InstallationDeviceV3>) {
            let manifest = InstallationManifestV3 {
                schema_version: INSTALLATION_SCHEMA_V3,
                owner_id_hex: hex(&self.owner_id),
                installation_id_hex: hex(&self.installation_id),
                devices,
            };
            fs::write(
                self.root.0.join("installation-v3.json"),
                serde_json::to_vec_pretty(&manifest).unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn multi_device_v2_layout_loads_unchanged_as_one_device() {
        let fixture = Fixture::new();
        let device_id = [0x22; 16];
        fixture.add_v2_device(device_id);
        let set = InstallationCredentialSet::load(&fixture.root.0).unwrap();
        assert_eq!(set.len(), 1);
        assert_eq!(set.iter().next().unwrap().device_id(), device_id);
        assert_eq!(
            set.iter().next().unwrap().installation_id(),
            fixture.installation_id
        );
    }

    #[test]
    fn multi_device_v3_loads_two_exact_grants_under_one_installation() {
        let fixture = Fixture::new();
        let first = [0x22; 16];
        let second = [0x33; 16];
        fs::create_dir(fixture.root.0.join("devices")).unwrap();
        fixture.add_v3_device(second, 7, 0x70);
        fixture.add_v3_device(first, 3, 0x50);
        fixture.activate_v3(vec![
            InstallationDeviceV3 {
                device_id_hex: hex(&second),
                authority_epoch: 7,
            },
            InstallationDeviceV3 {
                device_id_hex: hex(&first),
                authority_epoch: 3,
            },
        ]);

        let set = InstallationCredentialSet::load(&fixture.root.0).unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(
            set.iter()
                .map(InstallationCredentials::device_id)
                .collect::<Vec<_>>(),
            vec![first, second]
        );
        assert_eq!(
            set.get(first).unwrap().installation_id(),
            fixture.installation_id
        );
        assert_eq!(
            set.get(second).unwrap().installation_id(),
            fixture.installation_id
        );
    }

    #[test]
    fn multi_device_v3_tamper_fails_without_v2_fallback() {
        let fixture = Fixture::new();
        let v2 = [0x22; 16];
        let v3 = [0x33; 16];
        fixture.add_v2_device(v2);
        fs::create_dir(fixture.root.0.join("devices")).unwrap();
        fixture.add_v3_device(v3, 1, 0x50);
        fixture.activate_v3(vec![InstallationDeviceV3 {
            device_id_hex: hex(&v3),
            authority_epoch: 1,
        }]);
        fs::write(
            fixture
                .root
                .0
                .join("devices")
                .join(hex(&v3))
                .join("device-link-secret.bin"),
            [0x99; 32],
        )
        .unwrap();

        let error = InstallationCredentialSet::load(&fixture.root.0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("grant"));
    }
}
