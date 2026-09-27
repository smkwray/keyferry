#![forbid(unsafe_code)]

use ring::{
    digest::{digest, SHA256},
    rand::SystemRandom,
    signature::{
        EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING,
    },
};
use std::{fmt, net::IpAddr};

mod installation;
pub mod roaming;
pub mod tailnet;
pub use installation::{
    DeviceGrantV1, InstallationCredentialSet, InstallationCredentials, InstallationDeviceV3,
    InstallationManifestV3,
};
pub use roaming::*;

pub const GATEWAY_PROOF_DOMAIN: &[u8] = b"keyferry-gateway-proof-v1";
pub const GATEWAY_PROOF_VERSION: u16 = 1;
pub const MAX_GATEWAY_DEVICES: usize = 8;

/// Accepts only addresses assigned by Tailscale itself, never LAN, loopback, or wildcard binds.
#[must_use]
pub fn is_tailscale_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => u32::from(address) & 0xffc0_0000 == 0x6440_0000,
        IpAddr::V6(address) => address.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const P256_PUBLIC_KEY_LEN: usize = 65;
const P256_SPKI_LEN: usize = P256_SPKI_PREFIX.len() + P256_PUBLIC_KEY_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GatewayLinkPath {
    Offline = 0,
    Wifi = 1,
    Bluetooth = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GatewayArmMode {
    Disarmed = 0,
    CommandScoped = 1,
    Temporary = 2,
    AlwaysReady = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayDeviceSummary {
    pub device_id: [u8; 16],
    pub configured_here: bool,
    pub session_online: bool,
    pub link_path: GatewayLinkPath,
    pub tls_hmac_authenticated: bool,
    pub protocol_session_id: Option<[u8; 16]>,
    pub armed: bool,
    pub arm_mode: GatewayArmMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayProofPayload {
    pub protocol_version: u16,
    pub request_nonce: [u8; 32],
    pub gateway_id: [u8; 32],
    pub daemon_boot_id: [u8; 16],
    pub api_version: u16,
    pub devices: Vec<GatewayDeviceSummary>,
}

impl GatewayProofPayload {
    /// Returns the only byte representation covered by the gateway signature.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>, GatewayProofError> {
        canonical_signing_bytes(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedGatewayProof {
    pub payload: GatewayProofPayload,
    pub signature_der: Vec<u8>,
}

/// A proof that has passed canonical validation, freshness, identity, and signature checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGatewayProof {
    proof: SignedGatewayProof,
}

impl VerifiedGatewayProof {
    #[must_use]
    pub fn payload(&self) -> &GatewayProofPayload {
        &self.proof.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayProofError {
    InvalidHostKey,
    InvalidTrustedSpki,
    TooManyDevices,
    DuplicateDevice,
    InconsistentDeviceState,
    UnsupportedProtocolVersion,
    NonCanonicalDeviceOrder,
    NonceMismatch,
    GatewayIdMismatch,
    InvalidSignatureEncoding,
    InvalidSignature,
}

impl fmt::Display for GatewayProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidHostKey => "gateway host key is not a valid P-256 signing key",
            Self::InvalidTrustedSpki => "trusted gateway SPKI is not canonical P-256 DER",
            Self::TooManyDevices => "gateway proof contains too many devices",
            Self::DuplicateDevice => "gateway proof contains a duplicate device",
            Self::InconsistentDeviceState => "gateway proof contains inconsistent device state",
            Self::UnsupportedProtocolVersion => "gateway proof protocol version is unsupported",
            Self::NonCanonicalDeviceOrder => "gateway proof devices are not canonically ordered",
            Self::NonceMismatch => "gateway proof nonce does not match this request",
            Self::GatewayIdMismatch => "gateway proof does not identify the trusted gateway",
            Self::InvalidSignatureEncoding => "gateway proof signature is not canonical P-256 DER",
            Self::InvalidSignature => "gateway proof signature is invalid",
        };
        f.write_str(message)
    }
}

impl std::error::Error for GatewayProofError {}

/// Signs a bounded metadata-only gateway statement with the daemon's existing PKCS#8 TLS key.
pub fn sign_gateway_proof(
    private_key_der: &[u8],
    request_nonce: [u8; 32],
    daemon_boot_id: [u8; 16],
    api_version: u16,
    mut devices: Vec<GatewayDeviceSummary>,
) -> Result<SignedGatewayProof, GatewayProofError> {
    validate_devices_for_signing(&mut devices)?;
    let rng = SystemRandom::new();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private_key_der, &rng)
        .map_err(|_| GatewayProofError::InvalidHostKey)?;
    let spki = p256_spki(key_pair.public_key().as_ref())?;
    let payload = GatewayProofPayload {
        protocol_version: GATEWAY_PROOF_VERSION,
        request_nonce,
        gateway_id: sha256(&spki),
        daemon_boot_id,
        api_version,
        devices,
    };
    let signature_der = key_pair
        .sign(&rng, &canonical_signing_bytes(&payload)?)
        .map_err(|_| GatewayProofError::InvalidHostKey)?
        .as_ref()
        .to_vec();
    Ok(SignedGatewayProof {
        payload,
        signature_der,
    })
}

/// Verifies trust, freshness, canonical state, and signature as one fail-closed operation.
pub fn verify_gateway_proof(
    proof: &SignedGatewayProof,
    expected_nonce: [u8; 32],
    trusted_spki_der: &[u8],
) -> Result<VerifiedGatewayProof, GatewayProofError> {
    let public_key = validate_p256_spki(trusted_spki_der)?;
    validate_gateway_proof_structure(proof)?;
    if proof.payload.request_nonce != expected_nonce {
        return Err(GatewayProofError::NonceMismatch);
    }
    if proof.payload.gateway_id != gateway_id_for_spki(trusted_spki_der)? {
        return Err(GatewayProofError::GatewayIdMismatch);
    }
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(
            &canonical_signing_bytes(&proof.payload)?,
            &proof.signature_der,
        )
        .map_err(|_| GatewayProofError::InvalidSignature)?;
    Ok(VerifiedGatewayProof {
        proof: proof.clone(),
    })
}

/// Validates the bounded canonical payload independently of any trust decision.
pub fn validate_gateway_proof_structure(
    proof: &SignedGatewayProof,
) -> Result<(), GatewayProofError> {
    validate_payload(&proof.payload)?;
    validate_p256_signature_der(&proof.signature_der)
}

/// Returns the stable gateway identifier for a canonical P-256 SPKI.
pub fn gateway_id_for_spki(spki_der: &[u8]) -> Result<[u8; 32], GatewayProofError> {
    validate_p256_spki(spki_der)?;
    Ok(sha256(spki_der))
}

fn validate_devices_for_signing(
    devices: &mut [GatewayDeviceSummary],
) -> Result<(), GatewayProofError> {
    validate_device_count(devices)?;
    for device in devices.iter() {
        validate_device(device)?;
    }
    devices.sort_unstable_by_key(|device| device.device_id);
    if devices
        .windows(2)
        .any(|pair| pair[0].device_id == pair[1].device_id)
    {
        return Err(GatewayProofError::DuplicateDevice);
    }
    Ok(())
}

fn validate_payload(payload: &GatewayProofPayload) -> Result<(), GatewayProofError> {
    if payload.protocol_version != GATEWAY_PROOF_VERSION {
        return Err(GatewayProofError::UnsupportedProtocolVersion);
    }
    validate_device_count(&payload.devices)?;
    for device in &payload.devices {
        validate_device(device)?;
    }
    if payload
        .devices
        .windows(2)
        .any(|pair| pair[0].device_id >= pair[1].device_id)
    {
        return Err(GatewayProofError::NonCanonicalDeviceOrder);
    }
    Ok(())
}

fn validate_device(device: &GatewayDeviceSummary) -> Result<(), GatewayProofError> {
    if device.session_online != device.tls_hmac_authenticated
        || device.session_online != device.protocol_session_id.is_some()
        || (device.link_path == GatewayLinkPath::Offline && device.session_online)
        || (device.link_path != GatewayLinkPath::Offline && !device.session_online)
        || device.armed != (device.arm_mode != GatewayArmMode::Disarmed)
        || (device.armed && !device.tls_hmac_authenticated)
    {
        return Err(GatewayProofError::InconsistentDeviceState);
    }
    Ok(())
}

fn validate_device_count(devices: &[GatewayDeviceSummary]) -> Result<(), GatewayProofError> {
    if devices.len() > MAX_GATEWAY_DEVICES {
        return Err(GatewayProofError::TooManyDevices);
    }
    Ok(())
}

fn canonical_signing_bytes(payload: &GatewayProofPayload) -> Result<Vec<u8>, GatewayProofError> {
    validate_payload(payload)?;
    let mut bytes =
        Vec::with_capacity(GATEWAY_PROOF_DOMAIN.len() + 86 + payload.devices.len() * 39);
    bytes.extend_from_slice(GATEWAY_PROOF_DOMAIN);
    bytes.extend_from_slice(&payload.protocol_version.to_be_bytes());
    bytes.extend_from_slice(&payload.request_nonce);
    bytes.extend_from_slice(&payload.gateway_id);
    bytes.extend_from_slice(&payload.daemon_boot_id);
    bytes.extend_from_slice(&payload.api_version.to_be_bytes());
    bytes.push(payload.devices.len() as u8);
    for device in &payload.devices {
        bytes.extend_from_slice(&device.device_id);
        bytes.push(u8::from(device.configured_here));
        bytes.push(u8::from(device.session_online));
        bytes.push(device.link_path as u8);
        bytes.push(u8::from(device.tls_hmac_authenticated));
        match device.protocol_session_id {
            Some(session_id) => {
                bytes.push(1);
                bytes.extend_from_slice(&session_id);
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 16]);
            }
        }
        bytes.push(u8::from(device.armed));
        bytes.push(device.arm_mode as u8);
    }
    Ok(bytes)
}

fn p256_spki(public_key: &[u8]) -> Result<Vec<u8>, GatewayProofError> {
    if public_key.len() != P256_PUBLIC_KEY_LEN || public_key.first() != Some(&0x04) {
        return Err(GatewayProofError::InvalidHostKey);
    }
    let mut spki = Vec::with_capacity(P256_SPKI_LEN);
    spki.extend_from_slice(&P256_SPKI_PREFIX);
    spki.extend_from_slice(public_key);
    Ok(spki)
}

fn validate_p256_spki(spki_der: &[u8]) -> Result<&[u8], GatewayProofError> {
    if spki_der.len() != P256_SPKI_LEN || !spki_der.starts_with(&P256_SPKI_PREFIX) {
        return Err(GatewayProofError::InvalidTrustedSpki);
    }
    let public_key = &spki_der[P256_SPKI_PREFIX.len()..];
    if public_key.first() != Some(&0x04) {
        return Err(GatewayProofError::InvalidTrustedSpki);
    }
    Ok(public_key)
}

fn validate_p256_signature_der(signature: &[u8]) -> Result<(), GatewayProofError> {
    if !(8..=72).contains(&signature.len())
        || signature[0] != 0x30
        || usize::from(signature[1]) != signature.len() - 2
    {
        return Err(GatewayProofError::InvalidSignatureEncoding);
    }
    let next = validate_der_integer(signature, 2)?;
    let end = validate_der_integer(signature, next)?;
    if end != signature.len() {
        return Err(GatewayProofError::InvalidSignatureEncoding);
    }
    Ok(())
}

fn validate_der_integer(bytes: &[u8], offset: usize) -> Result<usize, GatewayProofError> {
    if bytes.get(offset) != Some(&0x02) {
        return Err(GatewayProofError::InvalidSignatureEncoding);
    }
    let length = usize::from(
        *bytes
            .get(offset + 1)
            .ok_or(GatewayProofError::InvalidSignatureEncoding)?,
    );
    if !(1..=33).contains(&length) {
        return Err(GatewayProofError::InvalidSignatureEncoding);
    }
    let start = offset + 2;
    let end = start
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or(GatewayProofError::InvalidSignatureEncoding)?;
    let value = &bytes[start..end];
    if value[0] & 0x80 != 0
        || value.iter().all(|byte| *byte == 0)
        || (value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0)
        || (value.len() == 33 && value[0] != 0)
    {
        return Err(GatewayProofError::InvalidSignatureEncoding);
    }
    Ok(end)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    digest(&SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 has a fixed 32-byte output")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_key() -> Vec<u8> {
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .unwrap()
            .as_ref()
            .to_vec()
    }

    fn spki(private_key: &[u8]) -> Vec<u8> {
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            private_key,
            &SystemRandom::new(),
        )
        .unwrap();
        p256_spki(key_pair.public_key().as_ref()).unwrap()
    }

    fn online_device(device_id: [u8; 16]) -> GatewayDeviceSummary {
        GatewayDeviceSummary {
            device_id,
            configured_here: true,
            session_online: true,
            link_path: GatewayLinkPath::Bluetooth,
            tls_hmac_authenticated: true,
            protocol_session_id: Some([0x44; 16]),
            armed: true,
            arm_mode: GatewayArmMode::CommandScoped,
        }
    }

    #[test]
    fn signs_and_verifies_one_canonical_proof() {
        let key = private_key();
        let trusted_spki = spki(&key);
        let nonce = [0x11; 32];
        let proof = sign_gateway_proof(&key, nonce, [0x22; 16], 1, vec![online_device([0x33; 16])])
            .unwrap();
        assert_eq!(
            proof.payload.gateway_id,
            gateway_id_for_spki(&trusted_spki).unwrap()
        );
        verify_gateway_proof(&proof, nonce, &trusted_spki).unwrap();
    }

    #[test]
    fn replay_wrong_key_signature_and_metadata_fail_closed() {
        let key = private_key();
        let other_key = private_key();
        let trusted_spki = spki(&key);
        let other_spki = spki(&other_key);
        let nonce = [0x21; 32];
        let proof = sign_gateway_proof(&key, nonce, [0x22; 16], 1, Vec::new()).unwrap();
        assert_eq!(
            verify_gateway_proof(&proof, [0x23; 32], &trusted_spki),
            Err(GatewayProofError::NonceMismatch)
        );
        assert_eq!(
            verify_gateway_proof(&proof, nonce, &other_spki),
            Err(GatewayProofError::GatewayIdMismatch)
        );

        let mut altered = proof.clone();
        let last = altered.signature_der.len() - 1;
        altered.signature_der[last] ^= 1;
        assert_eq!(
            verify_gateway_proof(&altered, nonce, &trusted_spki),
            Err(GatewayProofError::InvalidSignature)
        );
        let mut altered = proof;
        altered.payload.api_version += 1;
        assert_eq!(
            verify_gateway_proof(&altered, nonce, &trusted_spki),
            Err(GatewayProofError::InvalidSignature)
        );
    }

    #[test]
    fn signing_sorts_and_rejects_duplicate_or_inconsistent_devices() {
        let key = private_key();
        let proof = sign_gateway_proof(
            &key,
            [1; 32],
            [2; 16],
            1,
            vec![online_device([2; 16]), online_device([1; 16])],
        )
        .unwrap();
        assert_eq!(proof.payload.devices[0].device_id, [1; 16]);
        assert_eq!(
            sign_gateway_proof(
                &key,
                [1; 32],
                [2; 16],
                1,
                vec![online_device([1; 16]), online_device([1; 16])],
            ),
            Err(GatewayProofError::DuplicateDevice)
        );
        let mut inconsistent = online_device([3; 16]);
        inconsistent.protocol_session_id = None;
        assert_eq!(
            sign_gateway_proof(&key, [1; 32], [2; 16], 1, vec![inconsistent]),
            Err(GatewayProofError::InconsistentDeviceState)
        );
    }

    #[test]
    fn malformed_signature_der_never_qualifies_as_a_structured_proof() {
        let key = private_key();
        let mut proof = sign_gateway_proof(&key, [1; 32], [2; 16], 1, Vec::new()).unwrap();
        let malformed = [
            Vec::new(),
            vec![0x30],
            vec![0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01],
            vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01],
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00],
            vec![0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        ];
        for signature in malformed {
            proof.signature_der = signature;
            assert_eq!(
                validate_gateway_proof_structure(&proof),
                Err(GatewayProofError::InvalidSignatureEncoding)
            );
        }

        let mut overlong_integer = vec![0x30, 0x26, 0x02, 0x22];
        overlong_integer.extend_from_slice(&[1; 34]);
        overlong_integer.extend_from_slice(&[0x02, 0x01, 0x01]);
        proof.signature_der = overlong_integer;
        assert_eq!(
            validate_gateway_proof_structure(&proof),
            Err(GatewayProofError::InvalidSignatureEncoding)
        );
    }

    #[test]
    fn tailscale_address_ranges_are_exact() {
        assert!(is_tailscale_ip("100.64.0.1".parse().unwrap()));
        assert!(is_tailscale_ip("100.127.255.254".parse().unwrap()));
        assert!(is_tailscale_ip("fd7a:115c:a1e0::1".parse().unwrap()));
        for address in ["127.0.0.1", "0.0.0.0", "100.128.0.1", "192.168.1.10", "::1"] {
            assert!(!is_tailscale_ip(address.parse().unwrap()));
        }
    }

    #[test]
    fn roaming_identity_and_link_vector_match_the_frozen_profile() {
        let mut spki = P256_SPKI_PREFIX.to_vec();
        spki.push(0x04);
        spki.extend(1_u8..=64);
        let owner_id: [u8; 16] = core::array::from_fn(|index| 0x10 + index as u8);
        let device_id: [u8; 16] = core::array::from_fn(|index| 0x20 + index as u8);
        let recovery_secret: [u8; 32] = core::array::from_fn(|index| 0x40 + index as u8);

        let installation_id = [
            0x04, 0x00, 0xbe, 0x80, 0xf1, 0xda, 0x22, 0xaa, 0xaa, 0xc4, 0xc4, 0x38, 0x05, 0x4b,
            0xf1, 0xa8,
        ];
        assert_eq!(installation_id_for_spki(&spki).unwrap(), installation_id);
        assert_eq!(
            device_gateway_name(&device_id).unwrap(),
            "d-202122232425262728292a2b2c2d2e2f.gateway.keyferry.invalid"
        );
        assert_eq!(
            installation_gateway_name(&installation_id).unwrap(),
            "i-0400be80f1da22aaaac4c438054bf1a8.desktop.keyferry.invalid"
        );
        assert_eq!(
            derive_device_link_secret(&recovery_secret, &owner_id, &device_id, 1, &spki).unwrap(),
            [
                0x38, 0x88, 0x05, 0x0e, 0x07, 0xf2, 0x6f, 0x1d, 0xf3, 0xb4, 0x88, 0x33, 0x2c, 0xe3,
                0xc9, 0xc4, 0xa7, 0xeb, 0x16, 0x25, 0x85, 0x53, 0x9a, 0x47, 0x6d, 0x1c, 0xef, 0xb1,
                0xbb, 0xb6, 0x52, 0xd1,
            ]
        );
    }

    #[test]
    fn roaming_derivation_is_scoped_and_rejects_zero_authority() {
        let mut spki = P256_SPKI_PREFIX.to_vec();
        spki.push(0x04);
        spki.extend(1_u8..=64);
        let owner_id = [1_u8; 16];
        let device_id = [2_u8; 16];
        let recovery_secret = [3_u8; 32];
        let baseline =
            derive_device_link_secret(&recovery_secret, &owner_id, &device_id, 1, &spki).unwrap();
        assert_ne!(
            baseline,
            derive_device_link_secret(&recovery_secret, &owner_id, &device_id, 2, &spki).unwrap()
        );
        assert_ne!(
            baseline,
            derive_device_link_secret(&recovery_secret, &owner_id, &[4_u8; 16], 1, &spki).unwrap()
        );
        assert_eq!(
            derive_device_link_secret(&recovery_secret, &[0; 16], &device_id, 1, &spki),
            Err(RoamingCredentialError::ZeroOwnerId)
        );
        assert_eq!(
            derive_device_link_secret(&recovery_secret, &owner_id, &device_id, 0, &spki),
            Err(RoamingCredentialError::ZeroEpoch)
        );
        assert_eq!(
            installation_id_for_spki(&spki[..90]),
            Err(RoamingCredentialError::InvalidP256Spki)
        );
    }

    #[test]
    fn owner_gateway_candidate_is_only_a_nonzero_routing_hint() {
        assert_eq!(
            OwnerGatewayCandidate::new([0x44; 16]).unwrap(),
            OwnerGatewayCandidate {
                installation_id: [0x44; 16]
            }
        );
        assert_eq!(
            OwnerGatewayCandidate::new([0; 16]),
            Err(RoamingCredentialError::ZeroInstallationId)
        );
        assert_eq!(OWNER_GATEWAY_PROBE_PORT, 18_043);
        assert_eq!(OWNER_GATEWAY_CONTROL_PORT, 18_044);

        let candidate = OwnerGatewayCandidate::new([0x4a; 16]).unwrap();
        let json = candidate.to_json();
        assert_eq!(
            json,
            format!(
                r#"{{"schema_version":2,"installation_id":"{}"}}"#,
                "4a".repeat(16)
            )
        );
        assert_eq!(
            OwnerGatewayCandidate::from_json(json.as_bytes()),
            Ok(candidate)
        );
        for invalid in [
            format!(
                r#"{{"schema_version":1,"installation_id":"{}"}}"#,
                "4a".repeat(16)
            ),
            format!(
                r#"{{"schema_version":2,"installation_id":"{}"}}"#,
                "4A".repeat(16)
            ),
            format!(
                r#"{{"schema_version":2,"installation_id":"{}"}}"#,
                "00".repeat(16)
            ),
            format!(
                r#"{{"schema_version":2,"installation_id":"{}"}}"#,
                "4a".repeat(15)
            ),
            format!(
                r#"{{"schema_version":2,"installation_id":"{}","devices":[]}}"#,
                "4a".repeat(16)
            ),
            format!("{json}{}", " ".repeat(MAX_OWNER_GATEWAY_CANDIDATE_BYTES)),
        ] {
            assert!(OwnerGatewayCandidate::from_json(invalid.as_bytes()).is_err());
        }
    }

    #[test]
    fn route_proof_vector_is_scoped_to_controller_nonce_and_live_session() {
        let owner_id: [u8; 16] = core::array::from_fn(|index| 0x10 + index as u8);
        let device_id: [u8; 16] = core::array::from_fn(|index| 0x20 + index as u8);
        let recovery_secret: [u8; 32] = core::array::from_fn(|index| 0x40 + index as u8);
        let controller_installation_id = [
            0x04, 0x00, 0xbe, 0x80, 0xf1, 0xda, 0x22, 0xaa, 0xaa, 0xc4, 0xc4, 0x38, 0x05, 0x4b,
            0xf1, 0xa8,
        ];
        let secret = derive_route_proof_secret(
            &recovery_secret,
            &owner_id,
            &device_id,
            1,
            &controller_installation_id,
        )
        .unwrap();
        assert_eq!(
            secret,
            [
                0x3a, 0xdd, 0x63, 0x06, 0x2f, 0x65, 0xb8, 0x7f, 0xd7, 0x35, 0xb6, 0xf2, 0xe4, 0x09,
                0x41, 0x6b, 0xd7, 0x76, 0xb7, 0xcc, 0xa8, 0x23, 0x75, 0x37, 0xdc, 0xdd, 0xe6, 0xcb,
                0xf6, 0xc4, 0x1e, 0x13,
            ]
        );
        let input = RouteProofInput {
            owner_id,
            device_id,
            epoch: 1,
            policy_sequence: 7,
            policy_hash: core::array::from_fn(|index| 0x80 + index as u8),
            gateway_installation_id: core::array::from_fn(|index| 0x70 + index as u8),
            controller_installation_id,
            controller_nonce: core::array::from_fn(|index| 0xa0 + index as u8),
            device_boot_nonce: core::array::from_fn(|index| 0xc0 + index as u8),
            endpoint_session_id: core::array::from_fn(|index| 0xd0 + index as u8),
            link_path: GatewayLinkPath::Bluetooth,
            usb_ready: true,
        };
        let tag = route_proof_tag(&secret, &input).unwrap();
        assert_eq!(
            tag,
            [
                0x74, 0x43, 0x50, 0x64, 0xf1, 0x33, 0xfa, 0x78, 0xde, 0xec, 0x7c, 0x8d, 0xb0, 0x7f,
                0x38, 0x94, 0x93, 0xc2, 0x7d, 0xe2, 0x91, 0x50, 0xf9, 0xe7, 0x18, 0xd1, 0xa0, 0xc8,
                0x85, 0xa5, 0x0d, 0x77,
            ]
        );
        verify_route_proof_tag(&secret, &input, &tag).unwrap();
        let response = encode_route_proof_response(&input, &tag).unwrap();
        assert_eq!(response.len(), ROUTE_PROOF_RESPONSE_LEN);
        let decoded = decode_route_proof_response(&response).unwrap();
        assert_eq!(decoded.input, input);
        assert_eq!(decoded.tag, tag);
        verify_route_proof_tag(&secret, &decoded.input, &decoded.tag).unwrap();
        let binding = RouteProofBinding {
            owner_id,
            device_id,
            gateway_installation_id: input.gateway_installation_id,
            controller_installation_id,
            controller_nonce: input.controller_nonce,
        };
        assert_eq!(
            verify_route_proof_response(&secret, &binding, &response).unwrap(),
            decoded
        );
        for wrong in [
            RouteProofBinding {
                gateway_installation_id: [0x71; 16],
                ..binding
            },
            RouteProofBinding {
                controller_nonce: [0xa1; 32],
                ..binding
            },
            RouteProofBinding {
                device_id: [0x21; 16],
                ..binding
            },
        ] {
            assert_eq!(
                verify_route_proof_response(&secret, &wrong, &response),
                Err(RoamingCredentialError::InvalidRouteProof)
            );
        }
        assert_eq!(
            verify_route_proof_response(&[0x99; 32], &binding, &response),
            Err(RoamingCredentialError::DerivationFailed)
        );

        let mut malformed = response;
        malformed[ROUTE_PROOF_FIELDS_LEN - 2] = GatewayLinkPath::Offline as u8;
        assert_eq!(
            decode_route_proof_response(&malformed),
            Err(RoamingCredentialError::InvalidRouteProof)
        );

        let mut stale = input.clone();
        stale.endpoint_session_id[0] ^= 1;
        assert_eq!(
            verify_route_proof_tag(&secret, &stale, &tag),
            Err(RoamingCredentialError::DerivationFailed)
        );
        let mut replay = input;
        replay.controller_nonce[0] ^= 1;
        assert_eq!(
            verify_route_proof_tag(&secret, &replay, &tag),
            Err(RoamingCredentialError::DerivationFailed)
        );
    }

    #[test]
    fn roaming_policy_vector_authenticates_zero_wifi_and_revocation_state() {
        let owner_id = core::array::from_fn(|index| 0x10 + index as u8);
        let device_id = core::array::from_fn(|index| 0x20 + index as u8);
        let recovery_secret = core::array::from_fn(|index| 0x40 + index as u8);
        let ca_der = [0x30, 0x03, 0x01, 0x02, 0x03];
        let mut policy = RoamingPolicyFields {
            device_id,
            owner_id,
            owner_ca_sha256: sha256(&ca_der),
            epoch: 1,
            sequence: 1,
            previous_sequence: 0,
            previous_hash: [0; 32],
            owner_ca_length: ca_der.len() as u16,
            wifi_count: 0,
            revoked_count: 0,
            owner_ca_der: [0; MAX_CA_CERTIFICATE_LEN],
            revoked_installation_ids: [[0; 16]; MAX_REVOKED_INSTALLATIONS],
            wifi_records: [[0; WIFI_RECORD_LEN]; MAX_WIFI_PROFILES],
        };
        policy.owner_ca_der[..ca_der.len()].copy_from_slice(&ca_der);
        let bytes = canonical_roaming_policy_bytes(&policy).unwrap();
        assert_eq!(bytes.len(), POLICY_HASH_INPUT_LEN);
        assert_eq!(&bytes[..POLICY_HASH_DOMAIN.len()], POLICY_HASH_DOMAIN);
        let crc = bytes.iter().fold(0xffff_ffff_u32, |mut crc, byte| {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
            }
            crc
        }) ^ 0xffff_ffff;
        assert_eq!(crc, 0xcd23_c1f3);
        let policy_hash = roaming_policy_hash(&policy).unwrap();
        assert_eq!(
            policy_hash,
            [
                0x14, 0x83, 0x0f, 0x9b, 0x90, 0x4c, 0x81, 0x0f, 0x34, 0xb3, 0xae, 0x27, 0xe9, 0x4f,
                0x73, 0x64, 0x17, 0x98, 0x4b, 0x45, 0x35, 0x45, 0x31, 0x40, 0x67, 0xcf, 0xa9, 0xa7,
                0xbd, 0x28, 0x04, 0xf9,
            ]
        );
        let auth_secret =
            derive_policy_auth_secret(&recovery_secret, &owner_id, &device_id, policy.epoch)
                .unwrap();
        assert_eq!(
            auth_secret,
            [
                0xb2, 0xfc, 0x36, 0x64, 0xfe, 0x0c, 0xa7, 0x4c, 0x4f, 0x6a, 0x3e, 0x7a, 0x74, 0x11,
                0xb5, 0x30, 0xc0, 0x49, 0x66, 0x8a, 0xe9, 0x08, 0xef, 0xeb, 0xad, 0xe6, 0xb5, 0x3a,
                0x0c, 0x01, 0x02, 0x17,
            ]
        );
        let tag = roaming_policy_auth_tag(&auth_secret, &policy_hash).unwrap();
        assert_eq!(
            tag,
            [
                0xc3, 0x6f, 0x60, 0x24, 0x86, 0x63, 0x62, 0xf6, 0xd7, 0x19, 0xf0, 0x32, 0x1f, 0x1a,
                0x8b, 0x3f, 0xc4, 0x9f, 0xa2, 0xe8, 0xcc, 0x7f, 0xb6, 0xe6, 0x08, 0x5a, 0x9c, 0x19,
                0x7b, 0x73, 0x95, 0xbf,
            ]
        );
        verify_roaming_policy_auth_tag(&auth_secret, &policy_hash, &tag).unwrap();
        let payload = authenticated_roaming_policy_payload(&policy, &recovery_secret).unwrap();
        assert_eq!(payload.len(), ROAMING_POLICY_PAYLOAD_LEN);
        assert_eq!(&payload[..16], &device_id);
        assert_eq!(&payload[88..120], &policy_hash);
        assert_eq!(&payload[120..152], &policy.previous_hash);
        assert_eq!(&payload[152..184], &tag);
        assert_eq!(&payload[184..186], &(ca_der.len() as u16).to_be_bytes());
        assert_eq!(&payload[192..192 + ca_der.len()], &ca_der);

        let mut altered = policy.clone();
        altered.revoked_count = 1;
        altered.revoked_installation_ids[0] = [0x55; 16];
        assert_ne!(roaming_policy_hash(&altered).unwrap(), policy_hash);
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        assert_eq!(
            verify_roaming_policy_auth_tag(&auth_secret, &policy_hash, &bad_tag),
            Err(RoamingCredentialError::InvalidPolicy)
        );
    }
}
