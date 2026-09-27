//! Data-driven golden-vector agreement.
//!
//! Loads every `protocol/vectors/*.json` and asserts the Rust codec reproduces
//! the committed `decoded_hex` and `wire_hex` and round-trips them back to the
//! semantic frame. Adding a vector file automatically extends Rust coverage;
//! `scripts/check_seed.py` recomputes the same files independently, and the C++
//! codec test consumes them too, giving cross-language agreement per the
//! Phase-1 qualification gate. Standard library only: a minimal leaf-key reader
//! avoids a JSON dependency on the Phase-1 surface.

use keyferry_protocol::{decode_decoded, decode_wire, encode_decoded, encode_wire, Frame};
use std::fs;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../protocol/vectors")
}

/// Value of `"key"` as a quoted string (keys are unique across a vector file).
fn json_string(src: &str, key: &str) -> String {
    let anchor = format!("\"{key}\"");
    let start = src
        .find(&anchor)
        .unwrap_or_else(|| panic!("missing key {key}"));
    let after = &src[start + anchor.len()..];
    let q1 = after.find('"').expect("opening quote");
    let rest = &after[q1 + 1..];
    let q2 = rest.find('"').expect("closing quote");
    rest[..q2].to_string()
}

/// Value of `"key"` as an unquoted integer.
fn json_u64(src: &str, key: &str) -> u64 {
    let anchor = format!("\"{key}\"");
    let start = src
        .find(&anchor)
        .unwrap_or_else(|| panic!("missing key {key}"));
    let after = &src[start + anchor.len()..];
    let colon = after.find(':').expect("colon");
    let tail = after[colon + 1..].trim_start();
    let end = tail
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(tail.len());
    tail[..end].parse().expect("integer value")
}

fn parse_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex byte"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn parse_hex_byte(s: &str) -> u8 {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u8::from_str_radix(s, 16).expect("hex byte field")
}

#[test]
fn all_golden_vectors_agree_with_the_rust_codec() {
    let dir = vectors_dir();
    let mut checked = 0;
    for entry in fs::read_dir(&dir).expect("vectors dir readable") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let src = fs::read_to_string(&path).expect("vector readable");
        let name = json_string(&src, "name");

        let frame = Frame {
            major: json_u64(&src, "major") as u8,
            minor: json_u64(&src, "minor") as u8,
            message_type: parse_hex_byte(&json_string(&src, "message_type")),
            flags: parse_hex_byte(&json_string(&src, "flags")),
            sequence: json_u64(&src, "sequence") as u32,
            payload: parse_hex(&json_string(&src, "payload_hex")),
        };
        let decoded_hex = json_string(&src, "decoded_hex");
        let wire_hex = json_string(&src, "wire_hex");

        assert_eq!(
            to_hex(&encode_decoded(&frame).expect("encodes")),
            decoded_hex,
            "decoded_hex mismatch in {name}"
        );
        assert_eq!(
            to_hex(&encode_wire(&frame).expect("wire-encodes")),
            wire_hex,
            "wire_hex mismatch in {name}"
        );
        assert_eq!(
            decode_decoded(&parse_hex(&decoded_hex)).expect("decodes"),
            frame,
            "decoded round-trip mismatch in {name}"
        );
        assert_eq!(
            decode_wire(&parse_hex(&wire_hex)).expect("wire-decodes"),
            frame,
            "wire round-trip mismatch in {name}"
        );
        checked += 1;
    }
    assert!(
        checked >= 4,
        "expected at least the seed vectors, found {checked}"
    );
    eprintln!("verified {checked} golden vectors");
}
