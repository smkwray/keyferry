use crate::{capability, VERSION_MAJOR, VERSION_MINOR};

pub const PAYLOAD_LEN: usize = 77;
pub const SCHEMA_V1: u8 = 1;
pub const RELEASE_BYTES: usize = 32;
pub const BOARD_WAVESHARE_GEEK_V1_1_REFERENCE: u32 = 1;
pub const BOARD_LILYGO_T_DONGLE_S3: u32 = 2;
pub const DIGEST_ESP_APP_ELF_SHA256: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirmwareIdentityV1 {
    pub device_capability_mask: u32,
    pub protocol_min_minor: u8,
    pub protocol_max_minor: u8,
    pub release: String,
    pub board_compatibility_id: u32,
    pub elf_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareIdentityError {
    Length,
    Schema,
    Capability,
    Protocol,
    Release,
    Board,
    Digest,
}

impl FirmwareIdentityError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Length => "firmware.identity_length",
            Self::Schema => "firmware.identity_schema",
            Self::Capability => "firmware.identity_capability",
            Self::Protocol => "firmware.identity_protocol",
            Self::Release => "firmware.identity_release",
            Self::Board => "firmware.identity_board",
            Self::Digest => "firmware.identity_digest",
        }
    }
}

impl std::fmt::Display for FirmwareIdentityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for FirmwareIdentityError {}

pub fn decode_v1(payload: &[u8]) -> Result<FirmwareIdentityV1, FirmwareIdentityError> {
    if payload.len() != PAYLOAD_LEN {
        return Err(FirmwareIdentityError::Length);
    }
    if payload[0] != SCHEMA_V1 {
        return Err(FirmwareIdentityError::Schema);
    }

    let device_capability_mask = u32::from_le_bytes(payload[1..5].try_into().expect("exact slice"));
    let required = capability::KEYBOARD | capability::FIRMWARE_IDENTITY_V1;
    if device_capability_mask & required != required {
        return Err(FirmwareIdentityError::Capability);
    }
    if payload[5] != VERSION_MAJOR || payload[6] != VERSION_MINOR || payload[7] != VERSION_MINOR {
        return Err(FirmwareIdentityError::Protocol);
    }

    let release_field = &payload[8..8 + RELEASE_BYTES];
    let Some(terminator) = release_field.iter().position(|byte| *byte == 0) else {
        return Err(FirmwareIdentityError::Release);
    };
    if terminator == 0
        || release_field[terminator + 1..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(FirmwareIdentityError::Release);
    }
    let release = std::str::from_utf8(&release_field[..terminator])
        .map_err(|_| FirmwareIdentityError::Release)?;
    if release.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) || release.contains('+') {
        return Err(FirmwareIdentityError::Release);
    }
    let parsed = semver::Version::parse(release).map_err(|_| FirmwareIdentityError::Release)?;
    if !parsed.build.is_empty() || parsed.to_string() != release {
        return Err(FirmwareIdentityError::Release);
    }

    let board_compatibility_id =
        u32::from_le_bytes(payload[40..44].try_into().expect("exact slice"));
    if !matches!(
        board_compatibility_id,
        BOARD_WAVESHARE_GEEK_V1_1_REFERENCE | BOARD_LILYGO_T_DONGLE_S3
    ) {
        return Err(FirmwareIdentityError::Board);
    }
    if payload[44] != DIGEST_ESP_APP_ELF_SHA256 {
        return Err(FirmwareIdentityError::Digest);
    }
    let elf_sha256: [u8; 32] = payload[45..77].try_into().expect("exact slice");
    if elf_sha256.iter().all(|byte| *byte == 0) {
        return Err(FirmwareIdentityError::Digest);
    }

    Ok(FirmwareIdentityV1 {
        device_capability_mask,
        protocol_min_minor: payload[6],
        protocol_max_minor: payload[7],
        release: release.to_owned(),
        board_compatibility_id,
        elf_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> [u8; PAYLOAD_LEN] {
        let mut payload = [0_u8; PAYLOAD_LEN];
        payload[0] = SCHEMA_V1;
        payload[1..5].copy_from_slice(
            &(capability::KEYBOARD | capability::FIRMWARE_IDENTITY_V1).to_le_bytes(),
        );
        payload[5] = VERSION_MAJOR;
        payload[6] = VERSION_MINOR;
        payload[7] = VERSION_MINOR;
        payload[8..13].copy_from_slice(b"0.1.0");
        payload[40..44].copy_from_slice(&BOARD_WAVESHARE_GEEK_V1_1_REFERENCE.to_le_bytes());
        payload[44] = DIGEST_ESP_APP_ELF_SHA256;
        for (index, byte) in payload[45..].iter_mut().enumerate() {
            *byte = u8::try_from(index + 1).expect("fixture byte");
        }
        payload
    }

    #[test]
    fn decodes_the_fixed_identity_vector() {
        let decoded = decode_v1(&payload()).expect("identity");
        assert_eq!(decoded.release, "0.1.0");
        assert_eq!(decoded.board_compatibility_id, 1);
        assert_eq!(decoded.elf_sha256[0], 1);
        assert_eq!(decoded.elf_sha256[31], 32);
    }

    #[test]
    fn authenticated_inventory_accepts_the_memory_probe_release() {
        let release = b"0.0.0-probe.mem";
        let mut candidate = payload();
        candidate[8..40].fill(0);
        candidate[8..8 + release.len()].copy_from_slice(release);
        assert_eq!(decode_v1(&candidate).unwrap().release, "0.0.0-probe.mem");
    }

    #[test]
    fn accepts_each_registered_board_compatibility_id() {
        for board in [
            BOARD_WAVESHARE_GEEK_V1_1_REFERENCE,
            BOARD_LILYGO_T_DONGLE_S3,
        ] {
            let mut candidate = payload();
            candidate[40..44].copy_from_slice(&board.to_le_bytes());
            assert_eq!(
                decode_v1(&candidate)
                    .expect("registered board")
                    .board_compatibility_id,
                board
            );
        }
    }

    #[test]
    fn rejects_malformed_identity_without_echoing_payload() {
        let cases = [
            (0, 2, FirmwareIdentityError::Schema),
            (1, 0, FirmwareIdentityError::Capability),
            (5, 2, FirmwareIdentityError::Protocol),
            (8, 0, FirmwareIdentityError::Release),
            (40, 3, FirmwareIdentityError::Board),
            (44, 2, FirmwareIdentityError::Digest),
        ];
        for (offset, value, expected) in cases {
            let mut malformed = payload();
            malformed[offset] = value;
            assert_eq!(decode_v1(&malformed), Err(expected));
            assert!(expected.code().starts_with("firmware.identity_"));
        }
        assert_eq!(
            decode_v1(&payload()[..76]),
            Err(FirmwareIdentityError::Length)
        );
    }

    #[test]
    fn rejects_noncanonical_or_unbounded_release_values() {
        for release in ["01.2.3", "1.2.3+build", "1.2", "1.2.3 "] {
            let mut candidate = payload();
            candidate[8..40].fill(0);
            candidate[8..8 + release.len()].copy_from_slice(release.as_bytes());
            assert_eq!(decode_v1(&candidate), Err(FirmwareIdentityError::Release));
        }
        let mut unterminated = payload();
        unterminated[8..40].fill(b'1');
        assert_eq!(
            decode_v1(&unterminated),
            Err(FirmwareIdentityError::Release)
        );
    }
}
