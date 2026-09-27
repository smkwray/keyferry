//! Property and bounded-fuzz coverage for the wire codec.
//!
//! Closes Phase-1 gate items: a CRC known-answer test, valid-frame round-trips,
//! and >=1,000,000 malformed/random parser cases that must never panic and never
//! yield a frame outside the fixed 256-byte / 242-payload bounds. Standard
//! library only: a deterministic xorshift keeps it reproducible without adding a
//! fuzzing dependency to the Phase-1 surface.

use keyferry_protocol::{
    cobs_decode, cobs_encode, crc16_ccitt_false, decode_decoded, decode_wire, encode_decoded,
    encode_wire, Frame,
};

const MAX_DECODED: usize = 256;
const MAX_PAYLOAD: usize = 242;

struct XorShift(u64);
impl XorShift {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    /// Random buffer, biased toward zero bytes to stress COBS framing.
    fn buf(&mut self, max_len: usize, zero_bias: bool) -> Vec<u8> {
        let len = self.below(max_len + 1);
        (0..len)
            .map(|_| {
                if zero_bias && self.next_u64() & 3 == 0 {
                    0
                } else {
                    self.byte()
                }
            })
            .collect()
    }
}

#[test]
fn crc_known_answer() {
    // Canonical CRC-16/CCITT-FALSE check value for ASCII "123456789".
    assert_eq!(crc16_ccitt_false(b"123456789"), 0x29B1);
    assert_eq!(crc16_ccitt_false(&[]), 0xFFFF);
}

#[test]
fn valid_frames_round_trip_and_wire_is_well_formed() {
    let mut rng = XorShift::new(0xA5A5_1234_DEAD_BEEF);
    for _ in 0..50_000 {
        let mut frame = Frame::v1(
            rng.byte(),
            rng.next_u64() as u32,
            rng.buf(MAX_PAYLOAD, true),
        );
        frame.major = rng.byte();
        frame.minor = rng.byte();
        frame.flags = rng.byte();

        let decoded = encode_decoded(&frame).expect("valid payload encodes");
        assert!(decoded.len() <= MAX_DECODED);
        assert_eq!(decode_decoded(&decoded).expect("round-trips"), frame);

        let wire = encode_wire(&frame).expect("valid payload wire-encodes");
        assert_eq!(
            *wire.last().unwrap(),
            0,
            "wire ends with the zero delimiter"
        );
        assert!(
            wire[..wire.len() - 1].iter().all(|&b| b != 0),
            "COBS body carries no interior zero"
        );
        assert_eq!(decode_wire(&wire).expect("wire round-trips"), frame);
    }
}

#[test]
fn oversize_payload_is_rejected_not_truncated() {
    let frame = Frame::v1(0x10, 1, vec![0xAB; MAX_PAYLOAD + 1]);
    assert!(encode_decoded(&frame).is_err());
    assert!(encode_wire(&frame).is_err());
}

#[test]
fn fuzz_decode_wire_never_panics_and_stays_bounded() {
    let mut rng = XorShift::new(0x0BAD_F00D_CAFE_1111);
    for _ in 0..1_200_000 {
        let raw = rng.buf(300, true);
        if let Ok(frame) = decode_wire(&raw) {
            assert!(frame.payload.len() <= MAX_PAYLOAD);
            let re = encode_decoded(&frame).expect("decoded frame re-encodes");
            assert!(re.len() <= MAX_DECODED);
            assert_eq!(decode_decoded(&re), Ok(frame));
        }
    }
}

#[test]
fn fuzz_decode_decoded_never_panics_and_stays_bounded() {
    let mut rng = XorShift::new(0x1357_9BDF_2468_ACE0);
    for _ in 0..600_000 {
        let raw = rng.buf(300, true);
        if let Ok(frame) = decode_decoded(&raw) {
            assert!(frame.payload.len() <= MAX_PAYLOAD);
            let re = encode_decoded(&frame).expect("re-encodes");
            assert!(re.len() <= MAX_DECODED);
            assert_eq!(decode_decoded(&re), Ok(frame));
        }
    }
}

#[test]
fn fuzz_cobs_never_panics_and_is_invertible() {
    let mut rng = XorShift::new(0xFEED_FACE_9999_0001);
    for _ in 0..400_000 {
        let original = rng.buf(260, true);
        let encoded = cobs_encode(&original);
        assert!(
            encoded.iter().all(|&b| b != 0),
            "COBS output has no zero byte"
        );
        assert_eq!(cobs_decode(&encoded).expect("COBS inverts"), original);

        // Adversarial decode of arbitrary bytes must never panic; a clean decode
        // survives a re-encode/decode cycle.
        let raw = rng.buf(300, true);
        if let Ok(decoded) = cobs_decode(&raw) {
            assert_eq!(cobs_decode(&cobs_encode(&decoded)), Ok(decoded));
        }
    }
}
