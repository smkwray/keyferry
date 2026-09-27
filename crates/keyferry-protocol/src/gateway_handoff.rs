use std::fmt;

use crate::{
    gateway_handoff_operation as operation, gateway_handoff_phase as phase,
    gateway_handoff_reason as reason, gateway_handoff_status as status, roaming,
};

pub const SCHEMA_VERSION: u8 = 1;
pub const INSTALLATION_ID_BYTES: usize = 16;
pub const TRANSACTION_ID_BYTES: usize = 16;
pub const NONCE_BYTES: usize = 16;
pub const DIGEST_BYTES: usize = 32;
pub const SESSION_ID_BYTES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Start {
    pub transaction_id: [u8; TRANSACTION_ID_BYTES],
    pub target_installation_id: [u8; INSTALLATION_ID_BYTES],
    pub readiness_nonce: [u8; NONCE_BYTES],
    pub proof_digest: [u8; DIGEST_BYTES],
    pub target_ipv4: [u8; 4],
    pub target_port: u16,
    pub target_valid_ms: u32,
    pub recovery_ms: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Accept {
    pub transaction_id: [u8; TRANSACTION_ID_BYTES],
    pub readiness_nonce: [u8; NONCE_BYTES],
    pub proof_digest: [u8; DIGEST_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Query {
    pub transaction_id: [u8; TRANSACTION_ID_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    Start(Start),
    Accept(Accept),
    Query(Query),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    pub reply_operation: u8,
    pub status: u16,
    pub transaction_id: [u8; TRANSACTION_ID_BYTES],
    pub phase: u8,
    pub reason: u8,
    pub remaining_phase_ms: u32,
    pub remaining_recovery_ms: u32,
    pub target_installation_id: [u8; INSTALLATION_ID_BYTES],
    pub previous_installation_id: [u8; INSTALLATION_ID_BYTES],
    pub device_boot_nonce: [u8; NONCE_BYTES],
    pub current_endpoint_session: [u8; SESSION_ID_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    WrongLength { expected: usize, actual: usize },
    UnsupportedSchema(u8),
    UnsupportedOperation(u8),
    InvalidStatus(u16),
    InvalidPhase(u8),
    InvalidReason(u8),
    ZeroIdentifier(&'static str),
    InvalidTargetAddress,
    InvalidTargetPort(u16),
    InvalidBudget,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(
                    f,
                    "gateway handoff payload length {actual}, expected {expected}"
                )
            }
            Self::UnsupportedSchema(value) => {
                write!(f, "unsupported gateway handoff schema {value}")
            }
            Self::UnsupportedOperation(value) => {
                write!(f, "unsupported gateway handoff operation {value}")
            }
            Self::InvalidStatus(value) => write!(f, "invalid gateway handoff status {value}"),
            Self::InvalidPhase(value) => write!(f, "invalid gateway handoff phase {value}"),
            Self::InvalidReason(value) => write!(f, "invalid gateway handoff reason {value}"),
            Self::ZeroIdentifier(name) => write!(f, "gateway handoff {name} is zero"),
            Self::InvalidTargetAddress => write!(f, "invalid gateway handoff target address"),
            Self::InvalidTargetPort(value) => {
                write!(f, "invalid gateway handoff target port {value}")
            }
            Self::InvalidBudget => write!(f, "invalid gateway handoff timing budget"),
        }
    }
}

impl std::error::Error for Error {}

#[must_use]
pub fn encode_request(request: &Request) -> Vec<u8> {
    match request {
        Request::Start(value) => {
            let mut output = Vec::with_capacity(roaming::GATEWAY_HANDOFF_START_PAYLOAD_BYTES);
            output.push(SCHEMA_VERSION);
            output.push(operation::START);
            output.extend_from_slice(&value.transaction_id);
            output.extend_from_slice(&value.target_installation_id);
            output.extend_from_slice(&value.readiness_nonce);
            output.extend_from_slice(&value.proof_digest);
            output.extend_from_slice(&value.target_ipv4);
            output.extend_from_slice(&value.target_port.to_le_bytes());
            output.extend_from_slice(&value.target_valid_ms.to_le_bytes());
            output.extend_from_slice(&value.recovery_ms.to_le_bytes());
            output
        }
        Request::Accept(value) => {
            let mut output = Vec::with_capacity(roaming::GATEWAY_HANDOFF_ACCEPT_PAYLOAD_BYTES);
            output.push(SCHEMA_VERSION);
            output.push(operation::ACCEPT);
            output.extend_from_slice(&value.transaction_id);
            output.extend_from_slice(&value.readiness_nonce);
            output.extend_from_slice(&value.proof_digest);
            output
        }
        Request::Query(value) => {
            let mut output = Vec::with_capacity(roaming::GATEWAY_HANDOFF_QUERY_PAYLOAD_BYTES);
            output.push(SCHEMA_VERSION);
            output.push(operation::QUERY);
            output.extend_from_slice(&value.transaction_id);
            output
        }
    }
}

pub fn decode_request(bytes: &[u8]) -> Result<Request, Error> {
    if bytes.len() < 2 {
        return Err(Error::WrongLength {
            expected: roaming::GATEWAY_HANDOFF_QUERY_PAYLOAD_BYTES,
            actual: bytes.len(),
        });
    }
    if bytes[0] != SCHEMA_VERSION {
        return Err(Error::UnsupportedSchema(bytes[0]));
    }
    match bytes[1] {
        operation::START => {
            exact_len(bytes, roaming::GATEWAY_HANDOFF_START_PAYLOAD_BYTES)?;
            let value = Start {
                transaction_id: take(bytes, 2),
                target_installation_id: take(bytes, 18),
                readiness_nonce: take(bytes, 34),
                proof_digest: take(bytes, 50),
                target_ipv4: take(bytes, 82),
                target_port: u16::from_le_bytes(take(bytes, 86)),
                target_valid_ms: u32::from_le_bytes(take(bytes, 88)),
                recovery_ms: u32::from_le_bytes(take(bytes, 92)),
            };
            validate_start(&value)?;
            Ok(Request::Start(value))
        }
        operation::ACCEPT => {
            exact_len(bytes, roaming::GATEWAY_HANDOFF_ACCEPT_PAYLOAD_BYTES)?;
            let value = Accept {
                transaction_id: take(bytes, 2),
                readiness_nonce: take(bytes, 18),
                proof_digest: take(bytes, 34),
            };
            require_nonzero(&value.transaction_id, "transaction ID")?;
            require_nonzero(&value.readiness_nonce, "readiness nonce")?;
            require_nonzero(&value.proof_digest, "proof digest")?;
            Ok(Request::Accept(value))
        }
        operation::QUERY => {
            exact_len(bytes, roaming::GATEWAY_HANDOFF_QUERY_PAYLOAD_BYTES)?;
            let value = Query {
                transaction_id: take(bytes, 2),
            };
            require_nonzero(&value.transaction_id, "transaction ID")?;
            Ok(Request::Query(value))
        }
        other => Err(Error::UnsupportedOperation(other)),
    }
}

#[must_use]
pub fn encode_status(value: &Status) -> [u8; roaming::GATEWAY_HANDOFF_STATUS_PAYLOAD_BYTES] {
    let mut output = [0_u8; roaming::GATEWAY_HANDOFF_STATUS_PAYLOAD_BYTES];
    output[0] = SCHEMA_VERSION;
    output[1] = value.reply_operation;
    output[2..4].copy_from_slice(&value.status.to_le_bytes());
    output[4..20].copy_from_slice(&value.transaction_id);
    output[20] = value.phase;
    output[21] = value.reason;
    output[22..26].copy_from_slice(&value.remaining_phase_ms.to_le_bytes());
    output[26..30].copy_from_slice(&value.remaining_recovery_ms.to_le_bytes());
    output[30..46].copy_from_slice(&value.target_installation_id);
    output[46..62].copy_from_slice(&value.previous_installation_id);
    output[62..78].copy_from_slice(&value.device_boot_nonce);
    output[78..94].copy_from_slice(&value.current_endpoint_session);
    output
}

pub fn decode_status(bytes: &[u8]) -> Result<Status, Error> {
    exact_len(bytes, roaming::GATEWAY_HANDOFF_STATUS_PAYLOAD_BYTES)?;
    if bytes[0] != SCHEMA_VERSION {
        return Err(Error::UnsupportedSchema(bytes[0]));
    }
    validate_operation(bytes[1])?;
    let decoded_status = u16::from_le_bytes(take(bytes, 2));
    validate_status(decoded_status)?;
    validate_phase(bytes[20])?;
    validate_reason(bytes[21])?;
    let value = Status {
        reply_operation: bytes[1],
        status: decoded_status,
        transaction_id: take(bytes, 4),
        phase: bytes[20],
        reason: bytes[21],
        remaining_phase_ms: u32::from_le_bytes(take(bytes, 22)),
        remaining_recovery_ms: u32::from_le_bytes(take(bytes, 26)),
        target_installation_id: take(bytes, 30),
        previous_installation_id: take(bytes, 46),
        device_boot_nonce: take(bytes, 62),
        current_endpoint_session: take(bytes, 78),
    };
    require_nonzero(&value.transaction_id, "transaction ID")?;
    Ok(value)
}

fn validate_start(value: &Start) -> Result<(), Error> {
    require_nonzero(&value.transaction_id, "transaction ID")?;
    require_nonzero(&value.target_installation_id, "target installation ID")?;
    require_nonzero(&value.readiness_nonce, "readiness nonce")?;
    require_nonzero(&value.proof_digest, "proof digest")?;
    if !valid_unicast_ipv4(value.target_ipv4) {
        return Err(Error::InvalidTargetAddress);
    }
    if value.target_port != roaming::DEVICE_TLS_PORT {
        return Err(Error::InvalidTargetPort(value.target_port));
    }
    if value.target_valid_ms != roaming::GATEWAY_HANDOFF_TARGET_VALID_MS as u32
        || value.recovery_ms != roaming::GATEWAY_HANDOFF_RECOVERY_MS as u32
    {
        return Err(Error::InvalidBudget);
    }
    Ok(())
}

fn valid_unicast_ipv4(value: [u8; 4]) -> bool {
    value != [255; 4] && value[0] != 0 && value[0] != 127 && value[0] < 224
}

fn validate_operation(value: u8) -> Result<(), Error> {
    match value {
        operation::START | operation::ACCEPT | operation::QUERY => Ok(()),
        other => Err(Error::UnsupportedOperation(other)),
    }
}

fn validate_status(value: u16) -> Result<(), Error> {
    match value {
        status::OK
        | status::BUSY
        | status::STALE_PROOF
        | status::NOT_READY
        | status::UNSUPPORTED
        | status::RELEASE_FAILED
        | status::UNKNOWN_TRANSACTION
        | status::INVALID_TRANSITION => Ok(()),
        other => Err(Error::InvalidStatus(other)),
    }
}

fn validate_phase(value: u8) -> Result<(), Error> {
    match value {
        phase::UNKNOWN
        | phase::RELEASING
        | phase::TARGETING
        | phase::TARGET_PROVISIONAL
        | phase::RESTORING
        | phase::TRANSFERRED
        | phase::RESTORED
        | phase::NOT_STARTED
        | phase::RECOVERY_UNAVAILABLE => Ok(()),
        other => Err(Error::InvalidPhase(other)),
    }
}

fn validate_reason(value: u8) -> Result<(), Error> {
    match value {
        reason::NONE
        | reason::TARGET_ABSENT
        | reason::TRANSPORT_FAILED
        | reason::IDENTITY_FAILED
        | reason::AUTHORIZATION_FAILED
        | reason::ACCEPTANCE_TIMEOUT
        | reason::RELEASE_FAILED
        | reason::PREVIOUS_GATEWAY_UNAVAILABLE => Ok(()),
        other => Err(Error::InvalidReason(other)),
    }
}

fn exact_len(bytes: &[u8], expected: usize) -> Result<(), Error> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::WrongLength {
            expected,
            actual: bytes.len(),
        })
    }
}

fn require_nonzero(bytes: &[u8], name: &'static str) -> Result<(), Error> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(Error::ZeroIdentifier(name))
    } else {
        Ok(())
    }
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("length checked before fixed-width decode")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> Start {
        Start {
            transaction_id: [0x11; 16],
            target_installation_id: [0x22; 16],
            readiness_nonce: [0x33; 16],
            proof_digest: [0x44; 32],
            target_ipv4: [192, 168, 30, 120],
            target_port: roaming::DEVICE_TLS_PORT,
            target_valid_ms: roaming::GATEWAY_HANDOFF_TARGET_VALID_MS as u32,
            recovery_ms: roaming::GATEWAY_HANDOFF_RECOVERY_MS as u32,
        }
    }

    #[test]
    fn gateway_handoff_requests_round_trip_exact_layouts() {
        let requests = [
            Request::Start(start()),
            Request::Accept(Accept {
                transaction_id: [0x11; 16],
                readiness_nonce: [0x33; 16],
                proof_digest: [0x55; 32],
            }),
            Request::Query(Query {
                transaction_id: [0x11; 16],
            }),
        ];
        let expected = [
            roaming::GATEWAY_HANDOFF_START_PAYLOAD_BYTES,
            roaming::GATEWAY_HANDOFF_ACCEPT_PAYLOAD_BYTES,
            roaming::GATEWAY_HANDOFF_QUERY_PAYLOAD_BYTES,
        ];
        for (request, expected_len) in requests.iter().zip(expected) {
            let encoded = encode_request(request);
            assert_eq!(encoded.len(), expected_len);
            assert_eq!(decode_request(&encoded).unwrap(), *request);
        }
    }

    #[test]
    fn gateway_handoff_start_rejects_sketch_and_unsafe_targets() {
        assert!(matches!(
            decode_request(&[1_u8; 20]),
            Err(Error::UnsupportedOperation(1)) | Err(Error::WrongLength { .. })
        ));

        let mut invalid = start();
        invalid.target_ipv4 = [127, 0, 0, 1];
        assert_eq!(
            decode_request(&encode_request(&Request::Start(invalid))),
            Err(Error::InvalidTargetAddress)
        );

        let mut invalid = start();
        invalid.target_valid_ms += 1;
        assert_eq!(
            decode_request(&encode_request(&Request::Start(invalid))),
            Err(Error::InvalidBudget)
        );
    }

    #[test]
    fn gateway_handoff_status_round_trips() {
        let value = Status {
            reply_operation: operation::START,
            status: status::OK,
            transaction_id: [0x11; 16],
            phase: phase::TARGETING,
            reason: reason::NONE,
            remaining_phase_ms: 5_500,
            remaining_recovery_ms: 6_000,
            target_installation_id: [0x22; 16],
            previous_installation_id: [0x66; 16],
            device_boot_nonce: [0x77; 16],
            current_endpoint_session: [0x88; 16],
        };
        let encoded = encode_status(&value);
        assert_eq!(decode_status(&encoded).unwrap(), value);
    }
}
