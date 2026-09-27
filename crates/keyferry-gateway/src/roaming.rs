use super::{sha256, validate_p256_spki, GatewayLinkPath};
use ring::{
    hkdf::{KeyType, Salt, HKDF_SHA256},
    hmac,
};
use std::fmt;

pub const INSTALLATION_ID_DOMAIN: &[u8] = keyferry_protocol::roaming::INSTALLATION_ID_DOMAIN;
pub const LINK_SALT_DOMAIN: &[u8] = keyferry_protocol::roaming::LINK_SALT_DOMAIN;
pub const DEVICE_LINK_DOMAIN: &[u8] = keyferry_protocol::roaming::DEVICE_LINK_DOMAIN;
pub const ROUTE_PROOF_KEY_DOMAIN: &[u8] = keyferry_protocol::roaming::ROUTE_PROOF_KEY_DOMAIN;
pub const ROUTE_PROOF_DOMAIN: &[u8] = keyferry_protocol::roaming::ROUTE_PROOF_DOMAIN;
pub const POLICY_HASH_DOMAIN: &[u8] = keyferry_protocol::roaming::POLICY_HASH_DOMAIN;
pub const POLICY_AUTH_KEY_DOMAIN: &[u8] = keyferry_protocol::roaming::POLICY_AUTH_KEY_DOMAIN;
pub const POLICY_AUTH_DOMAIN: &[u8] = keyferry_protocol::roaming::POLICY_AUTH_DOMAIN;
pub const INSTALLATION_ID_LEN: usize = keyferry_protocol::roaming::INSTALLATION_ID_BYTES;
pub const DEVICE_LINK_SECRET_LEN: usize = keyferry_protocol::roaming::DEVICE_LINK_SECRET_BYTES;
pub const ROUTE_PROOF_SECRET_LEN: usize = keyferry_protocol::roaming::ROUTE_PROOF_SECRET_BYTES;
pub const ROUTE_PROOF_TAG_LEN: usize = keyferry_protocol::roaming::ROUTE_PROOF_TAG_BYTES;
pub const ROUTE_PROOF_FIELDS_LEN: usize = keyferry_protocol::roaming::ROUTE_PROOF_FIELDS_BYTES;
pub const ROUTE_PROOF_RESPONSE_LEN: usize = keyferry_protocol::roaming::ROUTE_PROOF_RESPONSE_BYTES;
pub const ROUTE_PROOF_TTL_MS: usize = keyferry_protocol::roaming::ROUTE_PROOF_TTL_MS;
pub const POLICY_HASH_INPUT_LEN: usize = keyferry_protocol::roaming::POLICY_HASH_INPUT_BYTES;
pub const POLICY_AUTH_INPUT_LEN: usize = keyferry_protocol::roaming::POLICY_AUTH_INPUT_BYTES;
pub const ROAMING_POLICY_PAYLOAD_LEN: usize =
    keyferry_protocol::roaming::ROAMING_CONFIG_PAYLOAD_BYTES;
pub const MAX_REVOKED_INSTALLATIONS: usize =
    keyferry_protocol::roaming::MAXIMUM_REVOKED_INSTALLATIONS;
pub const MAX_WIFI_PROFILES: usize = keyferry_protocol::configuration::MAX_WIFI_PROFILES;
pub const WIFI_RECORD_LEN: usize = keyferry_protocol::configuration::WIFI_RECORD_BYTES;
pub const MAX_CA_CERTIFICATE_LEN: usize =
    keyferry_protocol::configuration::MAX_CA_CERTIFICATE_BYTES;
pub const OWNER_GATEWAY_CANDIDATE_VERSION: u16 = 2;
pub const OWNER_GATEWAY_PROBE_PORT: u16 = 18_043;
pub const OWNER_GATEWAY_CONTROL_PORT: u16 = 18_044;
pub const OWNER_GATEWAY_CANDIDATE_PATH: &str = "/v2/gateway/candidate";
pub const MAX_OWNER_GATEWAY_CANDIDATE_BYTES: usize = 256;

/// Untrusted routing hint returned by the fixed plaintext probe endpoint.
///
/// This grants no authority. The controller authenticates the claimed installation through the
/// owner-rooted mTLS control endpoint before it may use the route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerGatewayCandidate {
    pub installation_id: [u8; INSTALLATION_ID_LEN],
}

impl OwnerGatewayCandidate {
    pub fn new(installation_id: [u8; INSTALLATION_ID_LEN]) -> Result<Self, RoamingCredentialError> {
        if installation_id.iter().all(|byte| *byte == 0) {
            return Err(RoamingCredentialError::ZeroInstallationId);
        }
        Ok(Self { installation_id })
    }

    /// Encodes the fixed probe body. It names an installation and carries no status or authority.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut installation_id = String::with_capacity(INSTALLATION_ID_LEN * 2);
        append_lower_hex(&mut installation_id, &self.installation_id);
        format!(
            "{{\"schema_version\":{OWNER_GATEWAY_CANDIDATE_VERSION},\"installation_id\":\"{installation_id}\"}}"
        )
    }

    /// Parses one bounded probe body; any other shape, version, or identity encoding fails.
    pub fn from_json(body: &[u8]) -> Result<Self, RoamingCredentialError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: u16,
            installation_id: String,
        }
        if body.len() > MAX_OWNER_GATEWAY_CANDIDATE_BYTES {
            return Err(RoamingCredentialError::InvalidCandidate);
        }
        let wire: Wire =
            serde_json::from_slice(body).map_err(|_| RoamingCredentialError::InvalidCandidate)?;
        if wire.schema_version != OWNER_GATEWAY_CANDIDATE_VERSION {
            return Err(RoamingCredentialError::InvalidCandidate);
        }
        Self::new(
            decode_lower_hex::<INSTALLATION_ID_LEN>(&wire.installation_id)
                .ok_or(RoamingCredentialError::InvalidCandidate)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoamingCredentialError {
    InvalidP256Spki,
    ZeroOwnerId,
    ZeroDeviceId,
    ZeroInstallationId,
    ZeroRecoverySecret,
    ZeroEpoch,
    InvalidRouteProof,
    InvalidPolicy,
    InvalidCandidate,
    DerivationFailed,
}

impl fmt::Display for RoamingCredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidP256Spki => "installation SPKI is not canonical P-256 DER",
            Self::ZeroOwnerId => "owner ID must not be zero",
            Self::ZeroDeviceId => "device ID must not be zero",
            Self::ZeroInstallationId => "installation ID must not be zero",
            Self::ZeroRecoverySecret => "device recovery secret must not be zero",
            Self::ZeroEpoch => "owner authority epoch must not be zero",
            Self::InvalidRouteProof => "route proof fields are malformed or inconsistent",
            Self::InvalidPolicy => "roaming policy is malformed or inconsistent",
            Self::InvalidCandidate => "owner gateway candidate is malformed",
            Self::DerivationFailed => "roaming key or proof operation failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for RoamingCredentialError {}

#[derive(Clone, Copy)]
struct SecretLength;

impl KeyType for SecretLength {
    fn len(&self) -> usize {
        DEVICE_LINK_SECRET_LEN
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteProofInput {
    pub owner_id: [u8; 16],
    pub device_id: [u8; 16],
    pub epoch: u64,
    pub policy_sequence: u64,
    pub policy_hash: [u8; 32],
    pub gateway_installation_id: [u8; INSTALLATION_ID_LEN],
    pub controller_installation_id: [u8; INSTALLATION_ID_LEN],
    pub controller_nonce: [u8; 32],
    pub device_boot_nonce: [u8; 16],
    pub endpoint_session_id: [u8; 16],
    pub link_path: GatewayLinkPath,
    pub usb_ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRouteProof {
    pub input: RouteProofInput,
    pub tag: [u8; ROUTE_PROOF_TAG_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoamingPolicyFields {
    pub device_id: [u8; 16],
    pub owner_id: [u8; 16],
    pub owner_ca_sha256: [u8; 32],
    pub epoch: u64,
    pub sequence: u64,
    pub previous_sequence: u64,
    pub previous_hash: [u8; 32],
    pub owner_ca_length: u16,
    pub wifi_count: u8,
    pub revoked_count: u8,
    pub owner_ca_der: [u8; MAX_CA_CERTIFICATE_LEN],
    pub revoked_installation_ids: [[u8; 16]; MAX_REVOKED_INSTALLATIONS],
    pub wifi_records: [[u8; WIFI_RECORD_LEN]; MAX_WIFI_PROFILES],
}

/// Returns the stable v2 installation identity derived from a canonical P-256 SPKI.
pub fn installation_id_for_spki(
    spki_der: &[u8],
) -> Result<[u8; INSTALLATION_ID_LEN], RoamingCredentialError> {
    validate_p256_spki(spki_der).map_err(|_| RoamingCredentialError::InvalidP256Spki)?;
    let mut input = Vec::with_capacity(INSTALLATION_ID_DOMAIN.len() + spki_der.len());
    input.extend_from_slice(INSTALLATION_ID_DOMAIN);
    input.extend_from_slice(spki_der);
    let full = sha256(&input);
    Ok(full[..INSTALLATION_ID_LEN]
        .try_into()
        .expect("installation ID length is fixed"))
}

/// Returns the exact device-scoped DNS identity used by endpoint-facing gateway certificates.
pub fn device_gateway_name(device_id: &[u8; 16]) -> Result<String, RoamingCredentialError> {
    if device_id.iter().all(|byte| *byte == 0) {
        return Err(RoamingCredentialError::ZeroDeviceId);
    }
    let prefix = std::str::from_utf8(keyferry_protocol::roaming::DEVICE_GATEWAY_DNS_PREFIX)
        .expect("generated DNS prefix is ASCII");
    let suffix = std::str::from_utf8(keyferry_protocol::roaming::DEVICE_GATEWAY_DNS_SUFFIX)
        .expect("generated DNS suffix is ASCII");
    let mut name = String::with_capacity(prefix.len() + 32 + suffix.len());
    name.push_str(prefix);
    append_lower_hex(&mut name, device_id);
    name.push_str(suffix);
    Ok(name)
}

/// Returns the exact DNS identity used by an installation's remote desktop listener.
pub fn installation_gateway_name(
    installation_id: &[u8; INSTALLATION_ID_LEN],
) -> Result<String, RoamingCredentialError> {
    if installation_id.iter().all(|byte| *byte == 0) {
        return Err(RoamingCredentialError::ZeroInstallationId);
    }
    let prefix = std::str::from_utf8(keyferry_protocol::roaming::INSTALLATION_GATEWAY_DNS_PREFIX)
        .expect("generated DNS prefix is ASCII");
    let suffix = std::str::from_utf8(keyferry_protocol::roaming::INSTALLATION_GATEWAY_DNS_SUFFIX)
        .expect("generated DNS suffix is ASCII");
    let mut name = String::with_capacity(prefix.len() + 32 + suffix.len());
    name.push_str(prefix);
    append_lower_hex(&mut name, installation_id);
    name.push_str(suffix);
    Ok(name)
}

/// Derives the v2 per-installation device HMAC key. This does not persist either input.
pub fn derive_device_link_secret(
    device_recovery_secret: &[u8; 32],
    owner_id: &[u8; 16],
    device_id: &[u8; 16],
    epoch: u64,
    spki_der: &[u8],
) -> Result<[u8; DEVICE_LINK_SECRET_LEN], RoamingCredentialError> {
    validate_derivation_authority(device_recovery_secret, owner_id, device_id, epoch)?;
    let installation_id = installation_id_for_spki(spki_der)?;
    derive_secret(
        device_recovery_secret,
        owner_id,
        device_id,
        epoch,
        &[DEVICE_LINK_DOMAIN, installation_id.as_slice(), spki_der],
    )
}

/// Derives the controller-specific key used only to verify fresh device route proofs.
pub fn derive_route_proof_secret(
    device_recovery_secret: &[u8; 32],
    owner_id: &[u8; 16],
    device_id: &[u8; 16],
    epoch: u64,
    controller_installation_id: &[u8; INSTALLATION_ID_LEN],
) -> Result<[u8; ROUTE_PROOF_SECRET_LEN], RoamingCredentialError> {
    validate_derivation_authority(device_recovery_secret, owner_id, device_id, epoch)?;
    if controller_installation_id.iter().all(|byte| *byte == 0) {
        return Err(RoamingCredentialError::InvalidP256Spki);
    }
    derive_secret(
        device_recovery_secret,
        owner_id,
        device_id,
        epoch,
        &[
            ROUTE_PROOF_KEY_DOMAIN,
            controller_installation_id.as_slice(),
        ],
    )
}

pub fn derive_policy_auth_secret(
    device_recovery_secret: &[u8; 32],
    owner_id: &[u8; 16],
    device_id: &[u8; 16],
    epoch: u64,
) -> Result<[u8; 32], RoamingCredentialError> {
    validate_derivation_authority(device_recovery_secret, owner_id, device_id, epoch)?;
    derive_secret(
        device_recovery_secret,
        owner_id,
        device_id,
        epoch,
        &[POLICY_AUTH_KEY_DOMAIN],
    )
}

pub fn roaming_policy_hash(
    policy: &RoamingPolicyFields,
) -> Result<[u8; 32], RoamingCredentialError> {
    Ok(sha256(&canonical_roaming_policy_bytes(policy)?))
}

pub fn roaming_policy_auth_tag(
    policy_auth_secret: &[u8; 32],
    policy_hash: &[u8; 32],
) -> Result<[u8; 32], RoamingCredentialError> {
    if policy_auth_secret.iter().all(|byte| *byte == 0) || policy_hash.iter().all(|byte| *byte == 0)
    {
        return Err(RoamingCredentialError::InvalidPolicy);
    }
    let mut input = [0_u8; POLICY_AUTH_INPUT_LEN];
    input[..POLICY_AUTH_DOMAIN.len()].copy_from_slice(POLICY_AUTH_DOMAIN);
    input[POLICY_AUTH_DOMAIN.len()..].copy_from_slice(policy_hash);
    Ok(hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, policy_auth_secret),
        &input,
    )
    .as_ref()
    .try_into()
    .expect("HMAC-SHA256 output length is fixed"))
}

/// Builds the exact authenticated `KFC2` payload consumed by the firmware A/B writer.
///
/// The returned bytes do not contain the device recovery secret. That secret only derives the
/// policy-authentication key and remains in the owner kit and the device recovery anchor.
pub fn authenticated_roaming_policy_payload(
    policy: &RoamingPolicyFields,
    device_recovery_secret: &[u8; 32],
) -> Result<Box<[u8; ROAMING_POLICY_PAYLOAD_LEN]>, RoamingCredentialError> {
    const PREFIX_BEFORE_POLICY_HASH: usize = 16 + 16 + 32 + 8 + 8 + 8;
    const PREVIOUS_POLICY_HASH_BYTES: usize = 32;
    let canonical = canonical_roaming_policy_bytes(policy)?;
    let policy_hash = sha256(&canonical);
    let auth_secret = derive_policy_auth_secret(
        device_recovery_secret,
        &policy.owner_id,
        &policy.device_id,
        policy.epoch,
    )?;
    let policy_auth_tag = roaming_policy_auth_tag(&auth_secret, &policy_hash)?;
    let fields = &canonical[POLICY_HASH_DOMAIN.len()..];
    let mut payload: Box<[u8; ROAMING_POLICY_PAYLOAD_LEN]> = vec![0; ROAMING_POLICY_PAYLOAD_LEN]
        .into_boxed_slice()
        .try_into()
        .expect("generated roaming payload length is exact");
    let mut cursor = 0;
    append_slice(
        payload.as_mut(),
        &mut cursor,
        &fields[..PREFIX_BEFORE_POLICY_HASH],
    );
    append(payload.as_mut(), &mut cursor, &policy_hash);
    append_slice(
        payload.as_mut(),
        &mut cursor,
        &fields[PREFIX_BEFORE_POLICY_HASH..PREFIX_BEFORE_POLICY_HASH + PREVIOUS_POLICY_HASH_BYTES],
    );
    append(payload.as_mut(), &mut cursor, &policy_auth_tag);
    append_slice(
        payload.as_mut(),
        &mut cursor,
        &fields[PREFIX_BEFORE_POLICY_HASH + PREVIOUS_POLICY_HASH_BYTES..],
    );
    debug_assert_eq!(cursor, payload.len());
    Ok(payload)
}

pub fn verify_roaming_policy_auth_tag(
    policy_auth_secret: &[u8; 32],
    policy_hash: &[u8; 32],
    tag: &[u8],
) -> Result<(), RoamingCredentialError> {
    if policy_auth_secret.iter().all(|byte| *byte == 0) || policy_hash.iter().all(|byte| *byte == 0)
    {
        return Err(RoamingCredentialError::InvalidPolicy);
    }
    let mut input = [0_u8; POLICY_AUTH_INPUT_LEN];
    input[..POLICY_AUTH_DOMAIN.len()].copy_from_slice(POLICY_AUTH_DOMAIN);
    input[POLICY_AUTH_DOMAIN.len()..].copy_from_slice(policy_hash);
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, policy_auth_secret),
        &input,
        tag,
    )
    .map_err(|_| RoamingCredentialError::InvalidPolicy)
}

pub fn canonical_roaming_policy_bytes(
    policy: &RoamingPolicyFields,
) -> Result<[u8; POLICY_HASH_INPUT_LEN], RoamingCredentialError> {
    validate_roaming_policy(policy)?;
    let mut output = [0_u8; POLICY_HASH_INPUT_LEN];
    let mut cursor = 0;
    append_slice(&mut output, &mut cursor, POLICY_HASH_DOMAIN);
    append(&mut output, &mut cursor, &policy.device_id);
    append(&mut output, &mut cursor, &policy.owner_id);
    append(&mut output, &mut cursor, &policy.owner_ca_sha256);
    append(&mut output, &mut cursor, &policy.epoch.to_be_bytes());
    append(&mut output, &mut cursor, &policy.sequence.to_be_bytes());
    append(
        &mut output,
        &mut cursor,
        &policy.previous_sequence.to_be_bytes(),
    );
    append(&mut output, &mut cursor, &policy.previous_hash);
    append(
        &mut output,
        &mut cursor,
        &policy.owner_ca_length.to_be_bytes(),
    );
    output[cursor] = policy.wifi_count;
    cursor += 1;
    output[cursor] = policy.revoked_count;
    cursor += 1;
    cursor += 4;
    append(&mut output, &mut cursor, &policy.owner_ca_der);
    for revoked in &policy.revoked_installation_ids {
        append(&mut output, &mut cursor, revoked);
    }
    for wifi in &policy.wifi_records {
        append(&mut output, &mut cursor, wifi);
    }
    debug_assert_eq!(cursor, output.len());
    Ok(output)
}

/// Authenticates one fixed-size, metadata-only statement from a live endpoint session.
pub fn route_proof_tag(
    route_secret: &[u8; ROUTE_PROOF_SECRET_LEN],
    input: &RouteProofInput,
) -> Result<[u8; ROUTE_PROOF_TAG_LEN], RoamingCredentialError> {
    validate_route_proof_input(input)?;
    Ok(hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, route_secret),
        &canonical_route_proof_bytes(input),
    )
    .as_ref()
    .try_into()
    .expect("HMAC-SHA256 output length is fixed"))
}

/// Verifies a route proof without exposing a timing-dependent tag comparison.
pub fn verify_route_proof_tag(
    route_secret: &[u8; ROUTE_PROOF_SECRET_LEN],
    input: &RouteProofInput,
    tag: &[u8],
) -> Result<(), RoamingCredentialError> {
    validate_route_proof_input(input)?;
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, route_secret),
        &canonical_route_proof_bytes(input),
        tag,
    )
    .map_err(|_| RoamingCredentialError::DerivationFailed)
}

/// Encodes the exact fixed route-proof response carried by the endpoint protocol.
pub fn encode_route_proof_response(
    input: &RouteProofInput,
    tag: &[u8; ROUTE_PROOF_TAG_LEN],
) -> Result<[u8; ROUTE_PROOF_RESPONSE_LEN], RoamingCredentialError> {
    let fields = encode_route_proof_fields(input)?;
    let mut response = [0_u8; ROUTE_PROOF_RESPONSE_LEN];
    response[..ROUTE_PROOF_FIELDS_LEN].copy_from_slice(&fields);
    response[ROUTE_PROOF_FIELDS_LEN..].copy_from_slice(tag);
    Ok(response)
}

/// Parses fixed route-proof fields without assigning trust to their HMAC tag.
pub fn decode_route_proof_response(
    response: &[u8],
) -> Result<SignedRouteProof, RoamingCredentialError> {
    if response.len() != ROUTE_PROOF_RESPONSE_LEN {
        return Err(RoamingCredentialError::InvalidRouteProof);
    }
    let input = decode_route_proof_fields(&response[..ROUTE_PROOF_FIELDS_LEN])?;
    let tag = response[ROUTE_PROOF_FIELDS_LEN..]
        .try_into()
        .map_err(|_| RoamingCredentialError::InvalidRouteProof)?;
    Ok(SignedRouteProof { input, tag })
}

/// The exact route a controller asked a live endpoint to prove.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteProofBinding {
    pub owner_id: [u8; 16],
    pub device_id: [u8; 16],
    pub gateway_installation_id: [u8; INSTALLATION_ID_LEN],
    pub controller_installation_id: [u8; INSTALLATION_ID_LEN],
    pub controller_nonce: [u8; 32],
}

/// Decodes one route-proof response and accepts it only for exactly the requested route and
/// under this controller's own device-scoped route-proof secret.
pub fn verify_route_proof_response(
    route_secret: &[u8; ROUTE_PROOF_SECRET_LEN],
    binding: &RouteProofBinding,
    response: &[u8],
) -> Result<SignedRouteProof, RoamingCredentialError> {
    let proof = decode_route_proof_response(response)?;
    if proof.input.owner_id != binding.owner_id
        || proof.input.device_id != binding.device_id
        || proof.input.gateway_installation_id != binding.gateway_installation_id
        || proof.input.controller_installation_id != binding.controller_installation_id
        || proof.input.controller_nonce != binding.controller_nonce
    {
        return Err(RoamingCredentialError::InvalidRouteProof);
    }
    verify_route_proof_tag(route_secret, &proof.input, &proof.tag)?;
    Ok(proof)
}

fn derive_secret(
    device_recovery_secret: &[u8; 32],
    owner_id: &[u8; 16],
    device_id: &[u8; 16],
    epoch: u64,
    info: &[&[u8]],
) -> Result<[u8; 32], RoamingCredentialError> {
    let salt_bytes = link_salt(owner_id, device_id, epoch);
    let salt = Salt::new(HKDF_SHA256, &salt_bytes);
    let prk = salt.extract(device_recovery_secret);
    let okm = prk
        .expand(info, SecretLength)
        .map_err(|_| RoamingCredentialError::DerivationFailed)?;
    let mut output = [0_u8; 32];
    okm.fill(&mut output)
        .map_err(|_| RoamingCredentialError::DerivationFailed)?;
    Ok(output)
}

fn validate_derivation_authority(
    device_recovery_secret: &[u8; 32],
    owner_id: &[u8; 16],
    device_id: &[u8; 16],
    epoch: u64,
) -> Result<(), RoamingCredentialError> {
    if owner_id.iter().all(|byte| *byte == 0) {
        return Err(RoamingCredentialError::ZeroOwnerId);
    }
    if device_id.iter().all(|byte| *byte == 0) {
        return Err(RoamingCredentialError::ZeroDeviceId);
    }
    if device_recovery_secret.iter().all(|byte| *byte == 0) {
        return Err(RoamingCredentialError::ZeroRecoverySecret);
    }
    if epoch == 0 {
        return Err(RoamingCredentialError::ZeroEpoch);
    }
    Ok(())
}

fn link_salt(owner_id: &[u8; 16], device_id: &[u8; 16], epoch: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(LINK_SALT_DOMAIN.len() + 16 + 16 + 8);
    input.extend_from_slice(LINK_SALT_DOMAIN);
    input.extend_from_slice(owner_id);
    input.extend_from_slice(device_id);
    input.extend_from_slice(&epoch.to_be_bytes());
    sha256(&input)
}

fn validate_route_proof_input(input: &RouteProofInput) -> Result<(), RoamingCredentialError> {
    if input.owner_id.iter().all(|byte| *byte == 0) {
        return Err(RoamingCredentialError::ZeroOwnerId);
    }
    if input.device_id.iter().all(|byte| *byte == 0) {
        return Err(RoamingCredentialError::ZeroDeviceId);
    }
    if input.epoch == 0 {
        return Err(RoamingCredentialError::ZeroEpoch);
    }
    if input.gateway_installation_id.iter().all(|byte| *byte == 0)
        || input
            .controller_installation_id
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(RoamingCredentialError::InvalidP256Spki);
    }
    if input.policy_sequence == 0
        || input.policy_hash.iter().all(|byte| *byte == 0)
        || input.controller_nonce.iter().all(|byte| *byte == 0)
        || input.device_boot_nonce.iter().all(|byte| *byte == 0)
        || input.endpoint_session_id.iter().all(|byte| *byte == 0)
    {
        return Err(RoamingCredentialError::InvalidRouteProof);
    }
    Ok(())
}

fn validate_roaming_policy(policy: &RoamingPolicyFields) -> Result<(), RoamingCredentialError> {
    let ca_length = usize::from(policy.owner_ca_length);
    if policy.device_id.iter().all(|byte| *byte == 0)
        || policy.owner_id.iter().all(|byte| *byte == 0)
        || policy.owner_ca_sha256.iter().all(|byte| *byte == 0)
        || policy.epoch == 0
        || policy.sequence == 0
        || ca_length == 0
        || ca_length > policy.owner_ca_der.len()
        || policy.owner_ca_der[0] != 0x30
        || policy.owner_ca_der[ca_length..]
            .iter()
            .any(|byte| *byte != 0)
        || usize::from(policy.wifi_count) > policy.wifi_records.len()
        || usize::from(policy.revoked_count) > policy.revoked_installation_ids.len()
        || sha256(&policy.owner_ca_der[..ca_length]) != policy.owner_ca_sha256
    {
        return Err(RoamingCredentialError::InvalidPolicy);
    }
    if (policy.sequence == 1
        && (policy.previous_sequence != 0 || policy.previous_hash.iter().any(|byte| *byte != 0)))
        || (policy.sequence > 1
            && (policy.previous_sequence != policy.sequence - 1
                || policy.previous_hash.iter().all(|byte| *byte == 0)))
    {
        return Err(RoamingCredentialError::InvalidPolicy);
    }
    let revoked_count = usize::from(policy.revoked_count);
    for (index, revoked) in policy.revoked_installation_ids.iter().enumerate() {
        if index < revoked_count {
            if revoked.iter().all(|byte| *byte == 0)
                || (index > 0 && policy.revoked_installation_ids[index - 1] >= *revoked)
            {
                return Err(RoamingCredentialError::InvalidPolicy);
            }
        } else if revoked.iter().any(|byte| *byte != 0) {
            return Err(RoamingCredentialError::InvalidPolicy);
        }
    }
    for (index, wifi) in policy.wifi_records.iter().enumerate() {
        if index < usize::from(policy.wifi_count) {
            if !valid_wifi_record(wifi) {
                return Err(RoamingCredentialError::InvalidPolicy);
            }
        } else if wifi.iter().any(|byte| *byte != 0) {
            return Err(RoamingCredentialError::InvalidPolicy);
        }
    }
    Ok(())
}

fn valid_wifi_record(record: &[u8; WIFI_RECORD_LEN]) -> bool {
    let security = record[0];
    let open_approved = record[1];
    let ssid_length = usize::from(record[3]);
    let credential_length = usize::from(record[4]);
    let ssid_end = 8 + keyferry_protocol::configuration::MAX_SSID_BYTES;
    let credential_end = ssid_end + keyferry_protocol::configuration::MAX_WIFI_CREDENTIAL_BYTES;
    if open_approved > 1
        || record[5..8].iter().any(|byte| *byte != 0)
        || ssid_length == 0
        || ssid_length > keyferry_protocol::configuration::MAX_SSID_BYTES
        || credential_length > keyferry_protocol::configuration::MAX_WIFI_CREDENTIAL_BYTES
        || record[8 + ssid_length..ssid_end]
            .iter()
            .any(|byte| *byte != 0)
        || record[ssid_end + credential_length..credential_end]
            .iter()
            .any(|byte| *byte != 0)
    {
        return false;
    }
    (security == 1 && open_approved == 0 && credential_length >= 8)
        || (security == 2 && open_approved == 1 && credential_length == 0)
}

fn canonical_route_proof_bytes(input: &RouteProofInput) -> Vec<u8> {
    let fields = encode_route_proof_fields(input)
        .expect("validated route proof fields always have one canonical encoding");
    let mut bytes = Vec::with_capacity(ROUTE_PROOF_DOMAIN.len() + ROUTE_PROOF_FIELDS_LEN);
    bytes.extend_from_slice(ROUTE_PROOF_DOMAIN);
    bytes.extend_from_slice(&fields);
    bytes
}

fn encode_route_proof_fields(
    input: &RouteProofInput,
) -> Result<[u8; ROUTE_PROOF_FIELDS_LEN], RoamingCredentialError> {
    validate_route_proof_input(input)?;
    let mut output = [0_u8; ROUTE_PROOF_FIELDS_LEN];
    let mut cursor = 0;
    append(&mut output, &mut cursor, &input.owner_id);
    append(&mut output, &mut cursor, &input.device_id);
    append(&mut output, &mut cursor, &input.epoch.to_be_bytes());
    append(
        &mut output,
        &mut cursor,
        &input.policy_sequence.to_be_bytes(),
    );
    append(&mut output, &mut cursor, &input.policy_hash);
    append(&mut output, &mut cursor, &input.gateway_installation_id);
    append(&mut output, &mut cursor, &input.controller_installation_id);
    append(&mut output, &mut cursor, &input.controller_nonce);
    append(&mut output, &mut cursor, &input.device_boot_nonce);
    append(&mut output, &mut cursor, &input.endpoint_session_id);
    output[cursor] = input.link_path as u8;
    cursor += 1;
    output[cursor] = u8::from(input.usb_ready);
    cursor += 1;
    debug_assert_eq!(cursor, output.len());
    Ok(output)
}

fn decode_route_proof_fields(fields: &[u8]) -> Result<RouteProofInput, RoamingCredentialError> {
    if fields.len() != ROUTE_PROOF_FIELDS_LEN {
        return Err(RoamingCredentialError::InvalidRouteProof);
    }
    let mut cursor = 0;
    let owner_id = take::<16>(fields, &mut cursor)?;
    let device_id = take::<16>(fields, &mut cursor)?;
    let epoch = u64::from_be_bytes(take::<8>(fields, &mut cursor)?);
    let policy_sequence = u64::from_be_bytes(take::<8>(fields, &mut cursor)?);
    let policy_hash = take::<32>(fields, &mut cursor)?;
    let gateway_installation_id = take::<16>(fields, &mut cursor)?;
    let controller_installation_id = take::<16>(fields, &mut cursor)?;
    let controller_nonce = take::<32>(fields, &mut cursor)?;
    let device_boot_nonce = take::<16>(fields, &mut cursor)?;
    let endpoint_session_id = take::<16>(fields, &mut cursor)?;
    let link_path = match fields.get(cursor).copied() {
        Some(value) if value == GatewayLinkPath::Wifi as u8 => GatewayLinkPath::Wifi,
        Some(value) if value == GatewayLinkPath::Bluetooth as u8 => GatewayLinkPath::Bluetooth,
        _ => return Err(RoamingCredentialError::InvalidRouteProof),
    };
    cursor += 1;
    let usb_ready = match fields.get(cursor).copied() {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(RoamingCredentialError::InvalidRouteProof),
    };
    cursor += 1;
    if cursor != fields.len() {
        return Err(RoamingCredentialError::InvalidRouteProof);
    }
    let input = RouteProofInput {
        owner_id,
        device_id,
        epoch,
        policy_sequence,
        policy_hash,
        gateway_installation_id,
        controller_installation_id,
        controller_nonce,
        device_boot_nonce,
        endpoint_session_id,
        link_path,
        usb_ready,
    };
    validate_route_proof_input(&input)?;
    Ok(input)
}

fn append<const N: usize>(output: &mut [u8], cursor: &mut usize, value: &[u8; N]) {
    output[*cursor..*cursor + N].copy_from_slice(value);
    *cursor += N;
}

fn append_slice(output: &mut [u8], cursor: &mut usize, value: &[u8]) {
    output[*cursor..*cursor + value.len()].copy_from_slice(value);
    *cursor += value.len();
}

fn take<const N: usize>(
    input: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], RoamingCredentialError> {
    let value = input
        .get(*cursor..*cursor + N)
        .ok_or(RoamingCredentialError::InvalidRouteProof)?
        .try_into()
        .map_err(|_| RoamingCredentialError::InvalidRouteProof)?;
    *cursor += N;
    Ok(value)
}

fn append_lower_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn decode_lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    let bytes = value.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (nibble(bytes[index * 2])? << 4) | nibble(bytes[index * 2 + 1])?;
    }
    Some(output)
}
