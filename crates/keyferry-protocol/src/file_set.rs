//! Bounded, volatile replacement of one USB file set.

pub use crate::file::{Error, State};
pub use crate::registry::file_handoff::{
    FILE_SET_STATUS_BYTES as STATUS_BYTES, MAX_BUNDLE_BYTES, MAX_CHUNK_BYTES, MAX_FILES,
    MAX_FILE_BYTES, MAX_NAME_BYTES,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct File {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub index: u8,
    pub name: String,
    pub size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    Begin { size: u32, sha256: [u8; 32] },
    Chunk { offset: u32, bytes: Vec<u8> },
    Commit,
    Clear,
    Status { index: u8 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    pub state: State,
    pub error: Error,
    pub wire_size: u32,
    pub received: u32,
    pub count: u8,
    pub entry: Option<Entry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecError;

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid file-set control payload")
    }
}

impl std::error::Error for CodecError {}

pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_NAME_BYTES || !bytes.is_ascii() {
        return false;
    }
    if matches!(bytes.first(), Some(b' ' | b'.')) || matches!(bytes.last(), Some(b' ' | b'.')) {
        return false;
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b" ._-".contains(byte))
    {
        return false;
    }
    let base = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    !matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !matches!(
            base.as_str(),
            "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9"
        )
        && !matches!(
            base.as_str(),
            "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
        )
}

pub fn validate_names(names: &[&str]) -> Result<(), CodecError> {
    if names.is_empty() || names.len() > MAX_FILES {
        return Err(CodecError);
    }
    let mut unique = std::collections::HashSet::new();
    for name in names {
        if !valid_name(name) || !unique.insert(name.to_ascii_lowercase()) {
            return Err(CodecError);
        }
    }
    Ok(())
}

pub fn encode_bundle(files: &[File]) -> Result<Vec<u8>, CodecError> {
    validate_names(
        &files
            .iter()
            .map(|file| file.name.as_str())
            .collect::<Vec<_>>(),
    )?;
    let mut total = 0usize;
    for file in files {
        total = total.checked_add(file.bytes.len()).ok_or(CodecError)?;
        if total > MAX_FILE_BYTES {
            return Err(CodecError);
        }
    }
    let manifest_len = 1 + files
        .iter()
        .map(|file| 1 + file.name.len() + 4)
        .sum::<usize>();
    let wire_len = manifest_len.checked_add(total).ok_or(CodecError)?;
    if wire_len > MAX_BUNDLE_BYTES {
        return Err(CodecError);
    }
    let mut bundle = Vec::with_capacity(wire_len);
    bundle.push(files.len() as u8);
    for file in files {
        bundle.push(file.name.len() as u8);
        bundle.extend_from_slice(file.name.as_bytes());
        bundle.extend_from_slice(&(file.bytes.len() as u32).to_le_bytes());
    }
    for file in files {
        bundle.extend_from_slice(&file.bytes);
    }
    Ok(bundle)
}

impl Request {
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        Ok(match self {
            Self::Begin { size, sha256 } if *size as usize <= MAX_BUNDLE_BYTES => {
                let mut payload = Vec::with_capacity(37);
                payload.push(1);
                payload.extend_from_slice(&size.to_le_bytes());
                payload.extend_from_slice(sha256);
                payload
            }
            Self::Chunk { offset, bytes }
                if !bytes.is_empty()
                    && bytes.len() <= MAX_CHUNK_BYTES
                    && (*offset as usize) < MAX_BUNDLE_BYTES
                    && (*offset as usize) + bytes.len() <= MAX_BUNDLE_BYTES =>
            {
                let mut payload = Vec::with_capacity(5 + bytes.len());
                payload.push(2);
                payload.extend_from_slice(&offset.to_le_bytes());
                payload.extend_from_slice(bytes);
                payload
            }
            Self::Commit => vec![3],
            Self::Clear => vec![4],
            Self::Status { index } if *index == u8::MAX || (*index as usize) < MAX_FILES => {
                vec![5, *index]
            }
            _ => return Err(CodecError),
        })
    }

    pub fn decode(payload: &[u8]) -> Result<Self, CodecError> {
        let request = match payload {
            [1, rest @ ..] if rest.len() == 36 => Self::Begin {
                size: u32::from_le_bytes(rest[..4].try_into().map_err(|_| CodecError)?),
                sha256: rest[4..].try_into().map_err(|_| CodecError)?,
            },
            [2, rest @ ..] if rest.len() >= 5 => Self::Chunk {
                offset: u32::from_le_bytes(rest[..4].try_into().map_err(|_| CodecError)?),
                bytes: rest[4..].to_vec(),
            },
            [3] => Self::Commit,
            [4] => Self::Clear,
            [5, index] => Self::Status { index: *index },
            _ => return Err(CodecError),
        };
        request.encode()?;
        Ok(request)
    }
}

impl Status {
    pub fn decode(payload: &[u8]) -> Result<Self, CodecError> {
        if payload.len() < STATUS_BYTES {
            return Err(CodecError);
        }
        let state = match payload[0] {
            0 => State::Empty,
            1 => State::Receiving,
            2 => State::Published,
            _ => return Err(CodecError),
        };
        let error = match payload[1] {
            0 => Error::Ok,
            1 => Error::Busy,
            2 => Error::Limit,
            3 => Error::Order,
            4 => Error::Digest,
            5 => Error::Memory,
            6 => Error::Unavailable,
            _ => return Err(CodecError),
        };
        let wire_size = u32::from_le_bytes(payload[2..6].try_into().map_err(|_| CodecError)?);
        let received = u32::from_le_bytes(payload[6..10].try_into().map_err(|_| CodecError)?);
        let count = payload[10];
        if wire_size as usize > MAX_BUNDLE_BYTES
            || received > wire_size
            || count as usize > MAX_FILES
        {
            return Err(CodecError);
        }
        if error == Error::Ok {
            match state {
                State::Empty if wire_size != 0 || received != 0 || count != 0 => {
                    return Err(CodecError)
                }
                State::Receiving if count != 0 => return Err(CodecError),
                State::Published if count == 0 || received != wire_size => return Err(CodecError),
                _ => {}
            }
        }
        let entry = if payload.len() == STATUS_BYTES {
            None
        } else {
            if state != State::Published || payload.len() < STATUS_BYTES + 2 + 4 {
                return Err(CodecError);
            }
            let index = payload[11];
            let name_len = payload[12] as usize;
            if index >= count
                || name_len == 0
                || name_len > MAX_NAME_BYTES
                || payload.len() != STATUS_BYTES + 2 + name_len + 4
            {
                return Err(CodecError);
            }
            let name = std::str::from_utf8(&payload[13..13 + name_len]).map_err(|_| CodecError)?;
            if !valid_name(name) {
                return Err(CodecError);
            }
            let size = u32::from_le_bytes(
                payload[13 + name_len..]
                    .try_into()
                    .map_err(|_| CodecError)?,
            );
            if size > MAX_FILE_BYTES as u32 {
                return Err(CodecError);
            }
            Some(Entry {
                index,
                name: name.to_owned(),
                size,
            })
        };
        Ok(Self {
            state,
            error,
            wire_size,
            received,
            count,
            entry,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_encodes_manifest_and_data_without_renaming() {
        let bundle = encode_bundle(&[
            File {
                name: "Note 1.txt".into(),
                bytes: b"abc".to_vec(),
            },
            File {
                name: "blank.bin".into(),
                bytes: Vec::new(),
            },
        ])
        .unwrap();
        let mut expected = vec![2, 10];
        expected.extend_from_slice(b"Note 1.txt");
        expected.extend_from_slice(&3u32.to_le_bytes());
        expected.push(9);
        expected.extend_from_slice(b"blank.bin");
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.extend_from_slice(b"abc");
        assert_eq!(bundle, expected);
        assert_eq!(bundle.len(), 1 + 2 * 5 + 10 + 9 + 3);
    }

    #[test]
    fn names_and_total_are_strict_before_transfer() {
        for name in [
            "",
            " name",
            "name.",
            "a/b",
            "a\\b",
            "naïve",
            "CON.txt",
            "CON .txt",
            "lPt9.log",
            "COM1",
            "x".repeat(65).as_str(),
        ] {
            assert!(!valid_name(name), "{name}");
        }
        assert!(validate_names(&["Read me.txt", "read ME.TXT"]).is_err());
        assert!(validate_names(&[]).is_err());
        assert!(encode_bundle(&[File {
            name: "ok".into(),
            bytes: vec![0; MAX_FILE_BYTES + 1]
        }])
        .is_err());
        let files = (0..MAX_FILES)
            .map(|index| File {
                name: format!("F{index}"),
                bytes: Vec::new(),
            })
            .collect::<Vec<_>>();
        assert!(encode_bundle(&files).is_ok());
        let mut too_many = files;
        too_many.push(File {
            name: "extra".into(),
            bytes: Vec::new(),
        });
        assert!(encode_bundle(&too_many).is_err());
    }

    #[test]
    fn request_and_status_reject_wrong_lengths_and_corrupt_entries() {
        let request = Request::Status { index: 255 };
        assert_eq!(
            Request::decode(&request.encode().unwrap()).unwrap(),
            request
        );
        assert!(Request::decode(&[5]).is_err());
        assert!(Request::Status { index: 16 }.encode().is_err());
        assert!(Request::Chunk {
            offset: MAX_BUNDLE_BYTES as u32 - 1,
            bytes: vec![1, 2]
        }
        .encode()
        .is_err());
        let mut status = vec![2, 0];
        status.extend_from_slice(&7u32.to_le_bytes());
        status.extend_from_slice(&7u32.to_le_bytes());
        status.push(1);
        status.extend_from_slice(&[0, 1, b'A']);
        status.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(Status::decode(&status).unwrap().entry.unwrap().name, "A");
        status[11] = 1;
        assert!(Status::decode(&status).is_err());
        status[11] = 0;
        status[12] = 0;
        assert!(Status::decode(&status).is_err());
        assert!(Status::decode(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        let mut legacy_empty = vec![2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(Status::decode(&legacy_empty).unwrap().wire_size, 0);
        legacy_empty.extend_from_slice(&[0, 11]);
        legacy_empty.extend_from_slice(b"MESSAGE.TXT");
        legacy_empty.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            Status::decode(&legacy_empty).unwrap().entry.unwrap().size,
            0
        );
    }
}
