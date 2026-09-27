#![forbid(unsafe_code)]

use std::fmt;

pub const MAGIC: u16 = 0x4248; // little-endian bytes: b"HB"
pub const VERSION_MAJOR: u8 = 1;
pub const VERSION_MINOR: u8 = 0;
pub const HEADER_LEN: usize = 12;
pub const CRC_LEN: usize = 2;
pub const MIN_DECODED_FRAME: usize = HEADER_LEN + CRC_LEN;
pub const MAX_DECODED_FRAME: usize = 256;
pub const MAX_PAYLOAD: usize = MAX_DECODED_FRAME - HEADER_LEN - CRC_LEN;

pub mod file;
pub mod file_set;
pub mod firmware_identity;
pub mod gateway_handoff;
pub mod local_management;
mod registry;

pub use registry::{
    action, arm_policy, ble_transport, capability, command_kind, configuration, discovery,
    display_orientation, error_code, gateway_handoff_operation, gateway_handoff_phase,
    gateway_handoff_reason, gateway_handoff_status, local_management as local_management_registry,
    local_management_bond_state, local_management_operation, local_management_probe_outcome,
    local_management_probe_phase, local_management_receipt_state, local_management_status,
    local_management_status_page, message, operational_mode, output_mode, provisioning,
    provisioning_operation, provisioning_policy_state, provisioning_status, result_code, roaming,
    screen_power,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub major: u8,
    pub minor: u8,
    pub message_type: u8,
    pub flags: u8,
    pub sequence: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    #[must_use]
    pub fn v1(message_type: u8, sequence: u32, payload: Vec<u8>) -> Self {
        Self {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            message_type,
            flags: 0,
            sequence,
            payload,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    FrameTooShort(usize),
    FrameTooLarge(usize),
    PayloadTooLarge(usize),
    BadMagic(u16),
    LengthMismatch { declared: usize, actual: usize },
    CrcMismatch { expected: u16, actual: u16 },
    MissingWireDelimiter,
    InteriorWireDelimiter,
    EmptyCobsFrame,
    MalformedCobs,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooShort(n) => write!(f, "decoded frame is too short: {n}"),
            Self::FrameTooLarge(n) => {
                write!(f, "decoded frame exceeds {MAX_DECODED_FRAME} bytes: {n}")
            }
            Self::PayloadTooLarge(n) => write!(f, "payload exceeds {MAX_PAYLOAD} bytes: {n}"),
            Self::BadMagic(value) => write!(f, "bad frame magic: 0x{value:04x}"),
            Self::LengthMismatch { declared, actual } => {
                write!(
                    f,
                    "payload length mismatch: declared {declared}, actual {actual}"
                )
            }
            Self::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "CRC mismatch: expected 0x{expected:04x}, actual 0x{actual:04x}"
                )
            }
            Self::MissingWireDelimiter => {
                write!(f, "wire frame is missing the final zero delimiter")
            }
            Self::InteriorWireDelimiter => {
                write!(f, "wire frame contains an interior zero delimiter")
            }
            Self::EmptyCobsFrame => write!(f, "COBS frame is empty"),
            Self::MalformedCobs => write!(f, "malformed COBS frame"),
        }
    }
}

impl std::error::Error for ProtocolError {}

pub fn encode_decoded(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
    if frame.payload.len() > MAX_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge(frame.payload.len()));
    }

    let mut out = Vec::with_capacity(HEADER_LEN + frame.payload.len() + CRC_LEN);
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.push(frame.major);
    out.push(frame.minor);
    out.push(frame.message_type);
    out.push(frame.flags);
    out.extend_from_slice(&frame.sequence.to_le_bytes());
    out.extend_from_slice(&(frame.payload.len() as u16).to_le_bytes());
    out.extend_from_slice(&frame.payload);
    let crc = crc16_ccitt_false(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    debug_assert!(out.len() <= MAX_DECODED_FRAME);
    Ok(out)
}

pub fn decode_decoded(bytes: &[u8]) -> Result<Frame, ProtocolError> {
    if bytes.len() < MIN_DECODED_FRAME {
        return Err(ProtocolError::FrameTooShort(bytes.len()));
    }
    if bytes.len() > MAX_DECODED_FRAME {
        return Err(ProtocolError::FrameTooLarge(bytes.len()));
    }

    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    if magic != MAGIC {
        return Err(ProtocolError::BadMagic(magic));
    }

    let declared = u16::from_le_bytes([bytes[10], bytes[11]]) as usize;
    let actual = bytes.len() - HEADER_LEN - CRC_LEN;
    if declared != actual {
        return Err(ProtocolError::LengthMismatch { declared, actual });
    }

    let crc_offset = bytes.len() - CRC_LEN;
    let expected = u16::from_le_bytes([bytes[crc_offset], bytes[crc_offset + 1]]);
    let actual_crc = crc16_ccitt_false(&bytes[..crc_offset]);
    if expected != actual_crc {
        return Err(ProtocolError::CrcMismatch {
            expected,
            actual: actual_crc,
        });
    }

    Ok(Frame {
        major: bytes[2],
        minor: bytes[3],
        message_type: bytes[4],
        flags: bytes[5],
        sequence: u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
        payload: bytes[HEADER_LEN..crc_offset].to_vec(),
    })
}

pub fn encode_wire(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
    let decoded = encode_decoded(frame)?;
    let mut wire = cobs_encode(&decoded);
    wire.push(0);
    Ok(wire)
}

pub fn decode_wire(wire: &[u8]) -> Result<Frame, ProtocolError> {
    if wire.last().copied() != Some(0) {
        return Err(ProtocolError::MissingWireDelimiter);
    }
    let encoded = &wire[..wire.len() - 1];
    if encoded.contains(&0) {
        return Err(ProtocolError::InteriorWireDelimiter);
    }
    let decoded = cobs_decode(encoded)?;
    decode_decoded(&decoded)
}

#[must_use]
pub fn crc16_ccitt_false(bytes: &[u8]) -> u16 {
    let mut crc = 0xffff_u16;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[must_use]
pub fn cobs_encode(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len() + input.len() / 254 + 1);
    let mut code_index = 0_usize;
    let mut code = 1_u8;
    output.push(0);

    for byte in input {
        if *byte == 0 {
            output[code_index] = code;
            code_index = output.len();
            output.push(0);
            code = 1;
        } else {
            output.push(*byte);
            code += 1;
            if code == 0xff {
                output[code_index] = code;
                code_index = output.len();
                output.push(0);
                code = 1;
            }
        }
    }

    output[code_index] = code;
    output
}

pub fn cobs_decode(input: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if input.is_empty() {
        return Err(ProtocolError::EmptyCobsFrame);
    }

    let mut output = Vec::with_capacity(input.len());
    let mut index = 0_usize;

    while index < input.len() {
        let code = input[index];
        if code == 0 {
            return Err(ProtocolError::MalformedCobs);
        }
        index += 1;
        let copy_len = usize::from(code - 1);
        let end = index
            .checked_add(copy_len)
            .ok_or(ProtocolError::MalformedCobs)?;
        if end > input.len() {
            return Err(ProtocolError::MalformedCobs);
        }
        output.extend_from_slice(&input[index..end]);
        index = end;
        if code != 0xff && index < input.len() {
            output.push(0);
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known_answer() {
        assert_eq!(crc16_ccitt_false(b"123456789"), 0x29b1);
    }

    #[test]
    fn cobs_round_trips_zero_rich_input() {
        let input = [0, 1, 2, 0, 0xff, 0, 3, 0];
        let encoded = cobs_encode(&input);
        assert!(!encoded.contains(&0));
        assert_eq!(cobs_decode(&encoded).unwrap(), input);
    }

    #[test]
    fn empty_cobs_payload_round_trips() {
        let encoded = cobs_encode(&[]);
        assert_eq!(encoded, vec![1]);
        assert_eq!(cobs_decode(&encoded).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hello_matches_golden_vector() {
        let frame = Frame::v1(message::HELLO, 1, vec![]);
        assert_eq!(
            hex(&encode_decoded(&frame).unwrap()),
            "48420100010001000000000041cb"
        );
        assert_eq!(
            hex(&encode_wire(&frame).unwrap()),
            "0448420102010201010101010341cb00"
        );
        assert_eq!(decode_wire(&encode_wire(&frame).unwrap()).unwrap(), frame);
    }

    #[test]
    fn rejects_crc_corruption() {
        let frame = Frame::v1(message::STATUS, 7, vec![0, 1, 0xff]);
        let mut decoded = encode_decoded(&frame).unwrap();
        decoded[5] ^= 0x01;
        assert!(matches!(
            decode_decoded(&decoded),
            Err(ProtocolError::CrcMismatch { .. })
        ));
    }

    #[test]
    fn rejects_interior_wire_delimiter() {
        let wire = [1, 0, 1, 0];
        assert_eq!(
            decode_wire(&wire),
            Err(ProtocolError::InteriorWireDelimiter)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}
