//! Authenticated, volatile USB file handoff control payloads.

pub use crate::registry::file_handoff::{MAX_CHUNK_BYTES, MAX_FILE_BYTES, STATUS_BYTES};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    Begin { size: u32, sha256: [u8; 32] },
    Chunk { offset: u32, bytes: Vec<u8> },
    Commit,
    Clear,
    Status,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum State {
    Empty = 0,
    Receiving = 1,
    Published = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Error {
    Ok = 0,
    Busy = 1,
    Limit = 2,
    Order = 3,
    Digest = 4,
    Memory = 5,
    Unavailable = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    pub state: State,
    pub error: Error,
    pub size: u32,
    pub received: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecError;

impl std::fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid file control payload")
    }
}

impl std::error::Error for CodecError {}

impl Request {
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        Ok(match self {
            Self::Begin { size, sha256 } if *size <= MAX_FILE_BYTES as u32 => {
                let mut payload = Vec::with_capacity(37);
                payload.push(1);
                payload.extend_from_slice(&size.to_le_bytes());
                payload.extend_from_slice(sha256);
                payload
            }
            Self::Chunk { offset, bytes }
                if !bytes.is_empty()
                    && bytes.len() <= MAX_CHUNK_BYTES
                    && (*offset as usize) < MAX_FILE_BYTES
                    && (*offset as usize) + bytes.len() <= MAX_FILE_BYTES =>
            {
                let mut payload = Vec::with_capacity(5 + bytes.len());
                payload.push(2);
                payload.extend_from_slice(&offset.to_le_bytes());
                payload.extend_from_slice(bytes);
                payload
            }
            Self::Commit => vec![3],
            Self::Clear => vec![4],
            Self::Status => vec![5],
            _ => return Err(CodecError),
        })
    }

    pub fn decode(payload: &[u8]) -> Result<Self, CodecError> {
        match payload {
            [1, rest @ ..] if rest.len() == 36 => {
                let size = u32::from_le_bytes(rest[..4].try_into().map_err(|_| CodecError)?);
                let sha256 = rest[4..].try_into().map_err(|_| CodecError)?;
                let request = Self::Begin { size, sha256 };
                request.encode()?;
                Ok(request)
            }
            [2, rest @ ..] if rest.len() >= 5 => {
                let offset = u32::from_le_bytes(rest[..4].try_into().map_err(|_| CodecError)?);
                let request = Self::Chunk {
                    offset,
                    bytes: rest[4..].to_vec(),
                };
                request.encode()?;
                Ok(request)
            }
            [3] => Ok(Self::Commit),
            [4] => Ok(Self::Clear),
            [5] => Ok(Self::Status),
            _ => Err(CodecError),
        }
    }
}

impl Status {
    pub fn decode(payload: &[u8]) -> Result<Self, CodecError> {
        let [state, error, size0, size1, size2, size3, recv0, recv1, recv2, recv3] = payload else {
            return Err(CodecError);
        };
        let state = match state {
            0 => State::Empty,
            1 => State::Receiving,
            2 => State::Published,
            _ => return Err(CodecError),
        };
        let error = match error {
            0 => Error::Ok,
            1 => Error::Busy,
            2 => Error::Limit,
            3 => Error::Order,
            4 => Error::Digest,
            5 => Error::Memory,
            6 => Error::Unavailable,
            _ => return Err(CodecError),
        };
        let size = u32::from_le_bytes([*size0, *size1, *size2, *size3]);
        let received = u32::from_le_bytes([*recv0, *recv1, *recv2, *recv3]);
        if size > MAX_FILE_BYTES as u32 || received > size {
            return Err(CodecError);
        }
        Ok(Self {
            state,
            error,
            size,
            received,
        })
    }

    pub fn encode(self) -> [u8; STATUS_BYTES] {
        let mut payload = [0; STATUS_BYTES];
        payload[0] = self.state as u8;
        payload[1] = self.error as u8;
        payload[2..6].copy_from_slice(&self.size.to_le_bytes());
        payload[6..10].copy_from_slice(&self.received.to_le_bytes());
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_file_roundtrips_and_one_byte_over_is_rejected() {
        let size = MAX_FILE_BYTES as u32;
        let begin = Request::Begin {
            size,
            sha256: [0x5a; 32],
        };
        assert_eq!(Request::decode(&begin.encode().unwrap()).unwrap(), begin);
        let last = Request::Chunk {
            offset: size - 1,
            bytes: vec![0xff],
        };
        assert_eq!(Request::decode(&last.encode().unwrap()).unwrap(), last);
        let status = Status {
            state: State::Published,
            error: Error::Ok,
            size,
            received: size,
        };
        assert_eq!(Status::decode(&status.encode()).unwrap(), status);
        let oversized = Request::Begin {
            size: size + 1,
            sha256: [0; 32],
        };
        assert!(oversized.encode().is_err());
        let mut oversized_wire = begin.encode().unwrap();
        oversized_wire[1..5].copy_from_slice(&(size + 1).to_le_bytes());
        assert!(Request::decode(&oversized_wire).is_err());
        assert!(Request::Chunk {
            offset: size - 1,
            bytes: vec![0; 2]
        }
        .encode()
        .is_err());
        assert!(Status::decode(
            &Status {
                size: size + 1,
                received: size + 1,
                ..status
            }
            .encode()
        )
        .is_err());
    }

    #[test]
    fn cross_language_file_vectors_and_bounds() {
        let begin = Request::Begin {
            size: 3,
            sha256: [0x5a; 32],
        };
        let mut expected = vec![1, 3, 0, 0, 0];
        expected.extend([0x5a; 32]);
        assert_eq!(begin.encode().unwrap(), expected);
        assert_eq!(Request::decode(&expected).unwrap(), begin);
        let chunk = Request::Chunk {
            offset: 1,
            bytes: vec![0x41, 0x42],
        };
        assert_eq!(chunk.encode().unwrap(), vec![2, 1, 0, 0, 0, 0x41, 0x42]);
        assert_eq!(Request::decode(&chunk.encode().unwrap()).unwrap(), chunk);
        let status = Status {
            state: State::Published,
            error: Error::Ok,
            size: 3,
            received: 3,
        };
        assert_eq!(status.encode(), [2, 0, 3, 0, 0, 0, 3, 0, 0, 0]);
        assert_eq!(Status::decode(&status.encode()).unwrap(), status);
        assert!(Request::Begin {
            size: 0,
            sha256: [0; 32]
        }
        .encode()
        .is_ok());
        assert!(Request::Chunk {
            offset: 0,
            bytes: vec![0; 201]
        }
        .encode()
        .is_err());
        assert!(Status::decode(&[2, 0, 1, 0, 0, 0, 2, 0, 0, 0]).is_err());
    }
}
