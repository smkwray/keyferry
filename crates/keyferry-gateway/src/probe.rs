//! Bounded response classification shared by clients and daemon tests.
use crate::*;
use serde::Deserialize;
use std::fmt;

pub const MAX_GATEWAY_PROOF_BYTES: usize = 16 * 1024;
pub const MAX_P256_SIGNATURE_DER_BYTES: usize = 72;
pub const SUPPORTED_GATEWAY_API_VERSION: u16 = 1;
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayCandidateClassification {
    AuthenticatedGateway(VerifiedGatewayProof),
    AuthenticatedIncompatible(VerifiedGatewayProof),
    /// The response is canonical and fresh, but its gateway ID is not in the local trust set.
    UntrustedKeyferry(SignedGatewayProof),
    NotKeyferry(GatewayProbeError),
    TrustConfigurationError(GatewayProofError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayProbeError {
    ResponseTooLarge(usize),
    InvalidJson,
    InvalidHex(&'static str),
    InvalidSignatureLength,
    UnsupportedProtocolVersion,
    NonceMismatch,
    TooManyDevices,
    NonCanonicalDeviceOrder,
    InconsistentDeviceState,
    InvalidProof(GatewayProofError),
}

impl fmt::Display for GatewayProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResponseTooLarge(bytes) => write!(
                formatter,
                "gateway proof is {bytes} bytes; limit is {MAX_GATEWAY_PROOF_BYTES}"
            ),
            Self::InvalidJson => formatter.write_str("gateway proof JSON is invalid"),
            Self::InvalidHex(field) => write!(formatter, "gateway proof {field} is invalid"),
            Self::InvalidSignatureLength => {
                formatter.write_str("gateway proof signature length is invalid")
            }
            Self::UnsupportedProtocolVersion => {
                formatter.write_str("gateway proof protocol version is unsupported")
            }
            Self::NonceMismatch => {
                formatter.write_str("gateway proof nonce does not match this request")
            }
            Self::TooManyDevices => formatter.write_str("gateway proof contains too many devices"),
            Self::NonCanonicalDeviceOrder => {
                formatter.write_str("gateway proof devices are not canonically ordered")
            }
            Self::InconsistentDeviceState => {
                formatter.write_str("gateway proof contains inconsistent device state")
            }
            Self::InvalidProof(error) => write!(formatter, "gateway proof is invalid: {error}"),
        }
    }
}

impl std::error::Error for GatewayProbeError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGatewayProof {
    protocol_version: u16,
    request_nonce: String,
    gateway_id: String,
    daemon_boot_id: String,
    api_version: u16,
    devices: Vec<WireDeviceSummary>,
    signature_der: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDeviceSummary {
    device_id: String,
    configured_here: bool,
    session_online: bool,
    link_path: WireLinkPath,
    tls_hmac_authenticated: bool,
    protocol_session_id: Option<String>,
    armed: bool,
    arm_mode: WireArmMode,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireLinkPath {
    Offline,
    Wifi,
    Bluetooth,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireArmMode {
    Disarmed,
    CommandScoped,
    Temporary,
    AlwaysReady,
}

/// Parse a metadata-only proof and bind it to the nonce generated for this request.
///
/// Success does not authenticate a gateway. The caller must pass the returned value to the
/// shared P-256/SPKI verifier before granting any authority.
pub fn parse_unverified_gateway_proof(
    bytes: &[u8],
    expected_nonce: [u8; 32],
) -> Result<SignedGatewayProof, GatewayProbeError> {
    if bytes.len() > MAX_GATEWAY_PROOF_BYTES {
        return Err(GatewayProbeError::ResponseTooLarge(bytes.len()));
    }
    let wire: WireGatewayProof =
        serde_json::from_slice(bytes).map_err(|_| GatewayProbeError::InvalidJson)?;
    if wire.protocol_version != GATEWAY_PROOF_VERSION {
        return Err(GatewayProbeError::UnsupportedProtocolVersion);
    }
    if wire.devices.len() > MAX_GATEWAY_DEVICES {
        return Err(GatewayProbeError::TooManyDevices);
    }

    let request_nonce = decode_fixed::<32>(&wire.request_nonce, "request_nonce")?;
    if request_nonce != expected_nonce {
        return Err(GatewayProbeError::NonceMismatch);
    }
    let gateway_id = decode_fixed::<32>(&wire.gateway_id, "gateway_id")?;
    let daemon_boot_id = decode_fixed::<16>(&wire.daemon_boot_id, "daemon_boot_id")?;
    let signature_der = decode_bytes(&wire.signature_der, "signature_der")?;
    if signature_der.is_empty() || signature_der.len() > MAX_P256_SIGNATURE_DER_BYTES {
        return Err(GatewayProbeError::InvalidSignatureLength);
    }

    let mut devices = Vec::with_capacity(wire.devices.len());
    for device in wire.devices {
        let device = GatewayDeviceSummary {
            device_id: decode_fixed::<16>(&device.device_id, "device_id")?,
            configured_here: device.configured_here,
            session_online: device.session_online,
            link_path: match device.link_path {
                WireLinkPath::Offline => GatewayLinkPath::Offline,
                WireLinkPath::Wifi => GatewayLinkPath::Wifi,
                WireLinkPath::Bluetooth => GatewayLinkPath::Bluetooth,
            },
            tls_hmac_authenticated: device.tls_hmac_authenticated,
            protocol_session_id: device
                .protocol_session_id
                .as_deref()
                .map(|value| decode_fixed::<16>(value, "protocol_session_id"))
                .transpose()?,
            armed: device.armed,
            arm_mode: match device.arm_mode {
                WireArmMode::Disarmed => GatewayArmMode::Disarmed,
                WireArmMode::CommandScoped => GatewayArmMode::CommandScoped,
                WireArmMode::Temporary => GatewayArmMode::Temporary,
                WireArmMode::AlwaysReady => GatewayArmMode::AlwaysReady,
            },
        };
        devices.push(device);
    }
    if devices
        .windows(2)
        .any(|pair| pair[0].device_id >= pair[1].device_id)
    {
        return Err(GatewayProbeError::NonCanonicalDeviceOrder);
    }

    let proof = SignedGatewayProof {
        payload: GatewayProofPayload {
            protocol_version: wire.protocol_version,
            request_nonce,
            gateway_id,
            daemon_boot_id,
            api_version: wire.api_version,
            devices,
        },
        signature_der,
    };
    validate_gateway_proof_structure(&proof).map_err(|error| match error {
        GatewayProofError::InconsistentDeviceState => GatewayProbeError::InconsistentDeviceState,
        error => GatewayProbeError::InvalidProof(error),
    })?;
    Ok(proof)
}

/// Parse and authenticate a gateway response against the local trusted-SPKI registry.
#[must_use]
pub fn classify_gateway_response(
    bytes: &[u8],
    expected_nonce: [u8; 32],
    trusted_spkis: &[Vec<u8>],
) -> GatewayCandidateClassification {
    let proof = match parse_unverified_gateway_proof(bytes, expected_nonce) {
        Ok(proof) => proof,
        Err(error) => return GatewayCandidateClassification::NotKeyferry(error),
    };
    let mut matching_spki = None;
    for spki in trusted_spkis {
        let gateway_id = match gateway_id_for_spki(spki) {
            Ok(gateway_id) => gateway_id,
            Err(error) => return GatewayCandidateClassification::TrustConfigurationError(error),
        };
        if gateway_id == proof.payload.gateway_id {
            matching_spki = Some(spki.as_slice());
            break;
        }
    }
    let Some(trusted_spki) = matching_spki else {
        return GatewayCandidateClassification::UntrustedKeyferry(proof);
    };
    match verify_gateway_proof(&proof, expected_nonce, trusted_spki) {
        Ok(verified) if verified.payload().api_version == SUPPORTED_GATEWAY_API_VERSION => {
            GatewayCandidateClassification::AuthenticatedGateway(verified)
        }
        Ok(verified) => GatewayCandidateClassification::AuthenticatedIncompatible(verified),
        Err(error) => {
            GatewayCandidateClassification::NotKeyferry(GatewayProbeError::InvalidProof(error))
        }
    }
}

pub fn decode_fixed<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], GatewayProbeError> {
    let bytes = decode_bytes(value, field)?;
    bytes
        .try_into()
        .map_err(|_| GatewayProbeError::InvalidHex(field))
}

pub fn decode_bytes(value: &str, field: &'static str) -> Result<Vec<u8>, GatewayProbeError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GatewayProbeError::InvalidHex(field));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(GatewayProbeError::InvalidHex(field))?;
            let low = hex_nibble(pair[1]).ok_or(GatewayProbeError::InvalidHex(field))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
    };
    const NONCE: [u8; 32] = [0x11; 32];
    fn proof_json(devices: &str) -> Vec<u8> {
        format!(
            r#"{{
                "protocol_version":1,
                "request_nonce":"{}",
                "gateway_id":"{}",
                "daemon_boot_id":"{}",
                "api_version":1,
                "devices":{devices},
                "signature_der":"3006020101020101"
            }}"#,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(16),
        )
        .into_bytes()
    }

    fn online_device(id: u8) -> String {
        format!(
            r#"{{
                "device_id":"{}",
                "configured_here":true,
                "session_online":true,
                "link_path":"bluetooth",
                "tls_hmac_authenticated":true,
                "protocol_session_id":"{}",
                "armed":false,
                "arm_mode":"disarmed"
            }}"#,
            format!("{id:02x}").repeat(16),
            "44".repeat(16),
        )
    }

    #[test]
    fn fresh_bounded_proof_with_unknown_key_is_only_untrusted() {
        let bytes = proof_json(&format!("[{}]", online_device(1)));
        let GatewayCandidateClassification::UntrustedKeyferry(proof) =
            classify_gateway_response(&bytes, NONCE, &[])
        else {
            panic!("valid wire proof must remain untrusted");
        };
        assert_eq!(proof.payload.request_nonce, NONCE);
        assert_eq!(proof.payload.gateway_id, [0x22; 32]);
        assert_eq!(proof.payload.devices.len(), 1);
        assert_eq!(
            proof.payload.devices[0].link_path,
            GatewayLinkPath::Bluetooth
        );
    }

    #[test]
    fn replayed_nonce_is_not_keyferry() {
        let bytes = proof_json("[]");
        assert!(matches!(
            classify_gateway_response(&bytes, [0x99; 32], &[]),
            GatewayCandidateClassification::NotKeyferry(GatewayProbeError::NonceMismatch)
        ));
    }

    #[test]
    fn trusted_gateway_is_authenticated_and_tampering_is_rejected() {
        let (private_key, spki) = signing_material();
        let proof = sign_gateway_proof(
            private_key.as_ref(),
            NONCE,
            [0x33; 16],
            1,
            vec![GatewayDeviceSummary {
                device_id: [1; 16],
                configured_here: true,
                session_online: true,
                link_path: GatewayLinkPath::Bluetooth,
                tls_hmac_authenticated: true,
                protocol_session_id: Some([0x44; 16]),
                armed: false,
                arm_mode: GatewayArmMode::Disarmed,
            }],
        )
        .unwrap();
        let json = proof_to_json(&proof);
        assert!(matches!(
            classify_gateway_response(&json, NONCE, std::slice::from_ref(&spki)),
            GatewayCandidateClassification::AuthenticatedGateway(_)
        ));

        let mut tampered = String::from_utf8(json).unwrap();
        tampered = tampered.replace("\"api_version\":1", "\"api_version\":2");
        assert!(matches!(
            classify_gateway_response(tampered.as_bytes(), NONCE, &[spki]),
            GatewayCandidateClassification::NotKeyferry(GatewayProbeError::InvalidProof(
                GatewayProofError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn correctly_signed_future_api_is_authenticated_but_not_usable() {
        let (private_key, spki) = signing_material();
        let proof = sign_gateway_proof(
            &private_key,
            NONCE,
            [0x33; 16],
            SUPPORTED_GATEWAY_API_VERSION + 1,
            Vec::new(),
        )
        .unwrap();
        assert!(matches!(
            classify_gateway_response(&proof_to_json(&proof), NONCE, &[spki]),
            GatewayCandidateClassification::AuthenticatedIncompatible(_)
        ));
    }

    #[test]
    fn malformed_oversized_or_noncanonical_proofs_fail_closed() {
        assert!(matches!(
            parse_unverified_gateway_proof(b"not json", NONCE),
            Err(GatewayProbeError::InvalidJson)
        ));
        assert!(matches!(
            parse_unverified_gateway_proof(&vec![b' '; MAX_GATEWAY_PROOF_BYTES + 1], NONCE),
            Err(GatewayProbeError::ResponseTooLarge(_))
        ));

        let descending = proof_json(&format!("[{},{}]", online_device(2), online_device(1)));
        assert!(matches!(
            parse_unverified_gateway_proof(&descending, NONCE),
            Err(GatewayProbeError::NonCanonicalDeviceOrder)
        ));

        let duplicate = proof_json(&format!("[{},{}]", online_device(1), online_device(1)));
        assert!(matches!(
            parse_unverified_gateway_proof(&duplicate, NONCE),
            Err(GatewayProbeError::NonCanonicalDeviceOrder)
        ));
    }

    #[test]
    fn unknown_fields_uppercase_hex_and_inconsistent_state_fail_closed() {
        let unknown = String::from_utf8(proof_json("[]"))
            .unwrap()
            .replace("\"api_version\":1", "\"api_version\":1,\"extra\":true");
        assert!(matches!(
            parse_unverified_gateway_proof(unknown.as_bytes(), NONCE),
            Err(GatewayProbeError::InvalidJson)
        ));

        let uppercase = String::from_utf8(proof_json("[]"))
            .unwrap()
            .replace(&"22".repeat(32), &"AA".repeat(32));
        assert!(matches!(
            parse_unverified_gateway_proof(uppercase.as_bytes(), NONCE),
            Err(GatewayProbeError::InvalidHex("gateway_id"))
        ));

        let inconsistent = online_device(1).replace(
            "\"protocol_session_id\":\"44444444444444444444444444444444\"",
            "\"protocol_session_id\":null",
        );
        assert!(matches!(
            parse_unverified_gateway_proof(&proof_json(&format!("[{inconsistent}]")), NONCE),
            Err(GatewayProbeError::InconsistentDeviceState)
        ));
    }

    #[test]
    fn device_and_signature_limits_are_enforced() {
        let devices = (1..=9).map(online_device).collect::<Vec<_>>().join(",");
        assert!(matches!(
            parse_unverified_gateway_proof(&proof_json(&format!("[{devices}]")), NONCE),
            Err(GatewayProbeError::TooManyDevices)
        ));

        let oversized_signature = String::from_utf8(proof_json("[]"))
            .unwrap()
            .replace("3006020101020101", &"01".repeat(73));
        assert!(matches!(
            parse_unverified_gateway_proof(oversized_signature.as_bytes(), NONCE),
            Err(GatewayProbeError::InvalidSignatureLength)
        ));
    }

    fn proof_to_json(proof: &SignedGatewayProof) -> Vec<u8> {
        let devices = proof
            .payload
            .devices
            .iter()
            .map(|device| {
                format!(
                    r#"{{"device_id":"{}","configured_here":{},"session_online":{},"link_path":"{}","tls_hmac_authenticated":{},"protocol_session_id":{},"armed":{},"arm_mode":"{}"}}"#,
                    hex(&device.device_id),
                    device.configured_here,
                    device.session_online,
                    match device.link_path {
                        GatewayLinkPath::Offline => "offline",
                        GatewayLinkPath::Wifi => "wifi",
                        GatewayLinkPath::Bluetooth => "bluetooth",
                    },
                    device.tls_hmac_authenticated,
                    device
                        .protocol_session_id
                        .map(|id| format!("\"{}\"", hex(&id)))
                        .unwrap_or_else(|| "null".to_owned()),
                    device.armed,
                    match device.arm_mode {
                        GatewayArmMode::Disarmed => "disarmed",
                        GatewayArmMode::CommandScoped => "command_scoped",
                        GatewayArmMode::Temporary => "temporary",
                        GatewayArmMode::AlwaysReady => "always_ready",
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"protocol_version":{},"request_nonce":"{}","gateway_id":"{}","daemon_boot_id":"{}","api_version":{},"devices":[{}],"signature_der":"{}"}}"#,
            proof.payload.protocol_version,
            hex(&proof.payload.request_nonce),
            hex(&proof.payload.gateway_id),
            hex(&proof.payload.daemon_boot_id),
            proof.payload.api_version,
            devices,
            hex(&proof.signature_der),
        )
        .into_bytes()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn signing_material() -> (Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let private_key =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private_key.as_ref(), &rng)
                .unwrap();
        let mut spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        spki.extend_from_slice(key_pair.public_key().as_ref());
        (private_key.as_ref().to_vec(), spki)
    }
}
