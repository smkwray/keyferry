//! Error-variant coverage for the decoders.
//!
//! The volume fuzz in `fuzz.rs` proves the parser never panics or overflows, but
//! it does not pin *which* error fires for a given malformed input, and its
//! zero-biased random data rarely reaches a full 254-byte COBS block. These
//! cases (from an independent coverage audit) assert the exact failure surface.

use keyferry_protocol::{
    cobs_decode, cobs_encode, decode_decoded, decode_wire, encode_decoded, Frame, ProtocolError,
};

fn hexb(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn valid_magic_but_wrong_declared_length_is_length_mismatch() {
    // HB/v1 header claims payload_len = 5 but the buffer carries 0 payload.
    let buf = hexb("48420100010001000000050034b4");
    assert!(matches!(
        decode_decoded(&buf),
        Err(ProtocolError::LengthMismatch {
            declared: 5,
            actual: 0
        })
    ));
}

#[test]
fn trailing_byte_after_a_complete_frame_is_rejected() {
    // A valid hello frame plus one extra byte: declared 0, actual 1.
    let mut buf = hexb("48420100010001000000000041cb");
    buf.push(0x00);
    assert!(matches!(
        decode_decoded(&buf),
        Err(ProtocolError::LengthMismatch {
            declared: 0,
            actual: 1
        })
    ));
}

#[test]
fn empty_and_tiny_buffers_are_frame_too_short() {
    assert!(matches!(
        decode_decoded(&[]),
        Err(ProtocolError::FrameTooShort(0))
    ));
    assert!(matches!(
        decode_decoded(&[0x48]),
        Err(ProtocolError::FrameTooShort(1))
    ));
}

#[test]
fn oversize_buffer_is_frame_too_large() {
    let buf = vec![0u8; 257];
    assert!(matches!(
        decode_decoded(&buf),
        Err(ProtocolError::FrameTooLarge(257))
    ));
}

#[test]
fn bad_magic_is_reported() {
    let mut buf = hexb("48420100010001000000000041cb");
    buf[0] = 0x00; // corrupt the 'H'
    assert!(matches!(
        decode_decoded(&buf),
        Err(ProtocolError::BadMagic(_))
    ));
}

#[test]
fn wire_delimiter_and_interior_zero_rules() {
    assert!(matches!(
        decode_wire(&[]),
        Err(ProtocolError::MissingWireDelimiter)
    ));
    assert!(matches!(
        decode_wire(&[0x01]),
        Err(ProtocolError::MissingWireDelimiter)
    ));
    assert!(matches!(
        decode_wire(&[0x00]),
        Err(ProtocolError::EmptyCobsFrame)
    ));
    assert!(matches!(
        decode_wire(&[0x00, 0x00]),
        Err(ProtocolError::InteriorWireDelimiter)
    ));
}

#[test]
fn valid_cobs_but_truncated_frame_is_frame_too_short() {
    // COBS body decodes to only 5 bytes: below the 14-byte frame minimum.
    let wire = hexb("04484201020100");
    assert!(matches!(
        decode_wire(&wire),
        Err(ProtocolError::FrameTooShort(_))
    ));
}

#[test]
fn cobs_handles_a_full_254_byte_run() {
    // A 254-byte zero-free run exercises the 0xFF COBS block boundary that the
    // zero-biased fuzz rarely reaches.
    let run = vec![0x01u8; 254];
    let encoded = cobs_encode(&run);
    assert_eq!(encoded[0], 0xFF, "a 254-run opens with the 0xFF block code");
    assert!(encoded.iter().all(|&b| b != 0));
    assert_eq!(cobs_decode(&encoded).unwrap(), run);
    // 253 and 255 straddle the boundary.
    for n in [253usize, 255] {
        let r = vec![0x01u8; n];
        assert_eq!(
            cobs_decode(&cobs_encode(&r)).unwrap(),
            r,
            "roundtrip len {n}"
        );
    }
}

#[test]
fn codec_does_not_enforce_version_that_is_a_session_rule() {
    // Per protocol-v1.md, UNSUPPORTED_VERSION is a session decision, not a codec
    // one. A CRC-valid frame with major=2 decodes cleanly at the codec layer.
    let mut frame = Frame::v1(0x01, 1, vec![]);
    frame.major = 2;
    let decoded = encode_decoded(&frame).unwrap();
    assert_eq!(decode_decoded(&decoded).unwrap(), frame);
    assert_eq!(decode_decoded(&decoded).unwrap().major, 2);
}
