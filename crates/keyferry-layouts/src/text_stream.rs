use crate::TypingTiming;
use serde::{Deserialize, Serialize};
use std::io::Read;

pub const TEXT_STREAM_SCHEMA_V1: &str = "keyferry.text-stream.v1";
pub const TEXT_STREAM_RECEIPT_SCHEMA_V1: &str = "keyferry.text-stream-receipt.v1";
pub const TEXT_STREAM_RESULT_SCHEMA_V1: &str = "keyferry.text-stream-result.v1";
pub const TEXT_STREAM_READ_BYTES: usize = 8 * 1024;
pub const TEXT_STREAM_CHILD_BUDGET_MS: u16 = 2_000;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UnsupportedTextPolicy {
    #[default]
    Reject,
    Replace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextStreamErrorKind {
    InvalidUtf8,
    UnsupportedText,
    SourceIo,
    CounterOverflow,
    Empty,
    NoncanonicalPart,
}

impl TextStreamErrorKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "input.invalid_utf8",
            Self::UnsupportedText => "input.unsupported_text",
            Self::SourceIo => "input.source_io",
            Self::CounterOverflow => "input.counter_overflow",
            Self::Empty => "input.empty",
            Self::NoncanonicalPart => "input.noncanonical_part",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextStreamError {
    pub kind: TextStreamErrorKind,
    pub byte_offset: u64,
    pub scalar_offset: u64,
}

impl TextStreamError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextStreamPart {
    pub text: String,
    pub start_bytes: u64,
    pub end_bytes: u64,
    pub start_scalars: u64,
    pub end_scalars: u64,
    pub gestures: u16,
    pub replacements: u16,
    pub end_of_input: bool,
}

#[derive(Clone, Copy)]
struct ScalarToken {
    value: char,
    start_bytes: u64,
    end_bytes: u64,
    start_scalars: u64,
    end_scalars: u64,
}

#[derive(Clone, Copy)]
struct Atom {
    first: char,
    second: Option<char>,
    start_bytes: u64,
    end_bytes: u64,
    start_scalars: u64,
    end_scalars: u64,
    replaced: bool,
}

pub struct TextStreamReader<R> {
    reader: R,
    timing: TypingTiming,
    input: [u8; TEXT_STREAM_READ_BYTES],
    input_start: usize,
    input_end: usize,
    bytes: u64,
    scalars: u64,
    pending_cr: Option<ScalarToken>,
    lookahead: Option<ScalarToken>,
    eof: bool,
    unsupported: UnsupportedTextPolicy,
}

impl<R: Read> TextStreamReader<R> {
    pub fn new(reader: R, timing: TypingTiming) -> Result<Self, TextStreamError> {
        Self::with_unsupported_policy(reader, timing, UnsupportedTextPolicy::Reject)
    }

    pub fn with_unsupported_policy(
        reader: R,
        timing: TypingTiming,
        unsupported: UnsupportedTextPolicy,
    ) -> Result<Self, TextStreamError> {
        timing.validate().map_err(|_| TextStreamError {
            kind: TextStreamErrorKind::NoncanonicalPart,
            byte_offset: 0,
            scalar_offset: 0,
        })?;
        Ok(Self {
            reader,
            timing,
            input: [0; TEXT_STREAM_READ_BYTES],
            input_start: 0,
            input_end: 0,
            bytes: 0,
            scalars: 0,
            pending_cr: None,
            lookahead: None,
            eof: false,
            unsupported,
        })
    }

    #[must_use]
    pub fn child_capacity(&self) -> u16 {
        text_stream_child_capacity(self.timing)
    }

    pub fn next_part(&mut self) -> Result<Option<TextStreamPart>, TextStreamError> {
        let capacity = usize::from(self.child_capacity());
        let mut text = String::with_capacity(capacity.saturating_mul(2));
        let mut start = None;
        let mut end_bytes = 0;
        let mut end_scalars = 0;
        let mut gestures = 0usize;
        let mut replacements = 0usize;

        while gestures < capacity {
            let Some(atom) = self.next_atom()? else {
                if gestures == 0 {
                    return Ok(None);
                }
                let (start_bytes, start_scalars) = start.expect("nonempty part has a start");
                return Ok(Some(TextStreamPart {
                    text,
                    start_bytes,
                    end_bytes,
                    start_scalars,
                    end_scalars,
                    gestures: gestures as u16,
                    replacements: replacements as u16,
                    end_of_input: true,
                }));
            };
            start.get_or_insert((atom.start_bytes, atom.start_scalars));
            text.push(atom.first);
            if let Some(second) = atom.second {
                text.push(second);
            }
            end_bytes = atom.end_bytes;
            end_scalars = atom.end_scalars;
            replacements += usize::from(atom.replaced);
            gestures += 1;
        }

        let (start_bytes, start_scalars) = start.expect("full part has a start");
        Ok(Some(TextStreamPart {
            text,
            start_bytes,
            end_bytes,
            start_scalars,
            end_scalars,
            gestures: gestures as u16,
            replacements: replacements as u16,
            end_of_input: false,
        }))
    }

    fn next_atom(&mut self) -> Result<Option<Atom>, TextStreamError> {
        let token = if let Some(token) = self.lookahead.take() {
            Some(token)
        } else {
            self.next_scalar()?
        };

        if let Some(cr) = self.pending_cr.take() {
            if let Some(token) = token {
                if token.value == '\n' {
                    return Ok(Some(Atom {
                        first: '\r',
                        second: Some('\n'),
                        start_bytes: cr.start_bytes,
                        end_bytes: token.end_bytes,
                        start_scalars: cr.start_scalars,
                        end_scalars: token.end_scalars,
                        replaced: false,
                    }));
                }
                self.lookahead = Some(token);
            }
            return Ok(Some(atom_from_token(cr)));
        }

        let Some(token) = token else { return Ok(None) };
        match token.value {
            '\r' => {
                self.pending_cr = Some(token);
                self.next_atom()
            }
            '\t' | '\n' | ' '..='~' => Ok(Some(atom_from_token(token))),
            _ if self.unsupported == UnsupportedTextPolicy::Replace => Ok(Some(Atom {
                first: '?',
                second: None,
                start_bytes: token.start_bytes,
                end_bytes: token.end_bytes,
                start_scalars: token.start_scalars,
                end_scalars: token.end_scalars,
                replaced: true,
            })),
            _ => Err(TextStreamError {
                kind: TextStreamErrorKind::UnsupportedText,
                byte_offset: token.start_bytes,
                scalar_offset: token.start_scalars,
            }),
        }
    }

    fn next_scalar(&mut self) -> Result<Option<ScalarToken>, TextStreamError> {
        let Some(first) = self.read_byte()? else {
            return Ok(None);
        };
        let start_bytes = self.bytes;
        let start_scalars = self.scalars;
        let width = match first {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err(self.error(TextStreamErrorKind::InvalidUtf8)),
        };
        let mut encoded = [0u8; 4];
        encoded[0] = first;
        for slot in encoded.iter_mut().take(width).skip(1) {
            let Some(next) = self.read_byte()? else {
                return Err(self.error(TextStreamErrorKind::InvalidUtf8));
            };
            *slot = next;
        }
        let text = std::str::from_utf8(&encoded[..width])
            .map_err(|_| self.error(TextStreamErrorKind::InvalidUtf8))?;
        let value = text
            .chars()
            .next()
            .ok_or_else(|| self.error(TextStreamErrorKind::InvalidUtf8))?;
        self.bytes = self
            .bytes
            .checked_add(width as u64)
            .ok_or_else(|| self.error(TextStreamErrorKind::CounterOverflow))?;
        self.scalars = self
            .scalars
            .checked_add(1)
            .ok_or_else(|| self.error(TextStreamErrorKind::CounterOverflow))?;
        Ok(Some(ScalarToken {
            value,
            start_bytes,
            end_bytes: self.bytes,
            start_scalars,
            end_scalars: self.scalars,
        }))
    }

    fn read_byte(&mut self) -> Result<Option<u8>, TextStreamError> {
        if self.input_start == self.input_end {
            if self.eof {
                return Ok(None);
            }
            self.input_start = 0;
            self.input_end = 0;
            let count = loop {
                match self.reader.read(&mut self.input) {
                    Ok(0) => {
                        self.eof = true;
                        return Ok(None);
                    }
                    Ok(count) => break count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(self.error(TextStreamErrorKind::SourceIo)),
                }
            };
            self.input_end = count;
        }
        let byte = self.input[self.input_start];
        self.input_start += 1;
        Ok(Some(byte))
    }

    fn error(&self, kind: TextStreamErrorKind) -> TextStreamError {
        TextStreamError {
            kind,
            byte_offset: self.bytes,
            scalar_offset: self.scalars,
        }
    }
}

fn atom_from_token(token: ScalarToken) -> Atom {
    Atom {
        first: token.value,
        second: None,
        start_bytes: token.start_bytes,
        end_bytes: token.end_bytes,
        start_scalars: token.start_scalars,
        end_scalars: token.end_scalars,
        replaced: false,
    }
}

#[must_use]
pub fn replace_unsupported_text(text: &str) -> (String, u64) {
    let mut replacements = 0_u64;
    let replaced = text
        .chars()
        .map(|value| match value {
            '\t' | '\n' | '\r' | ' '..='~' => value,
            _ => {
                replacements = replacements.saturating_add(1);
                '?'
            }
        })
        .collect();
    (replaced, replacements)
}

#[must_use]
pub fn text_stream_child_capacity(timing: TypingTiming) -> u16 {
    TEXT_STREAM_CHILD_BUDGET_MS / (timing.key_down_ms + timing.release_gap_ms)
}

pub fn validate_text_stream_part(
    text: &str,
    timing: TypingTiming,
    end_of_input: bool,
) -> Result<TextStreamPart, TextStreamError> {
    let mut reader = TextStreamReader::new(text.as_bytes(), timing)?;
    let Some(mut part) = reader.next_part()? else {
        return Err(TextStreamError {
            kind: TextStreamErrorKind::Empty,
            byte_offset: 0,
            scalar_offset: 0,
        });
    };
    if reader.next_part()?.is_some()
        || (!end_of_input && part.gestures != text_stream_child_capacity(timing))
        || (end_of_input && !part.end_of_input)
        || (!end_of_input && text.ends_with('\r'))
    {
        return Err(TextStreamError {
            kind: TextStreamErrorKind::NoncanonicalPart,
            byte_offset: part.end_bytes,
            scalar_offset: part.end_scalars,
        });
    }
    part.end_of_input = end_of_input;
    Ok(part)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    struct Fragmented {
        bytes: Cursor<Vec<u8>>,
        limit: usize,
    }

    impl Read for Fragmented {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let limit = self.limit.min(buffer.len());
            self.bytes.read(&mut buffer[..limit])
        }
    }

    fn collect(
        data: &[u8],
        timing: TypingTiming,
        limit: usize,
    ) -> Result<Vec<TextStreamPart>, TextStreamError> {
        let mut reader = TextStreamReader::new(
            Fragmented {
                bytes: Cursor::new(data.to_vec()),
                limit,
            },
            timing,
        )?;
        let mut parts = Vec::new();
        while let Some(part) = reader.next_part()? {
            parts.push(part);
        }
        Ok(parts)
    }

    #[test]
    fn text_stream_partition_and_offsets_ignore_io_boundaries() {
        let timing = TypingTiming {
            key_down_ms: 100,
            release_gap_ms: 100,
        };
        let data = b"123456789\r\nA\tB\rC\n";
        let expected = collect(data, timing, data.len()).unwrap();
        for limit in 1..=data.len() {
            assert_eq!(collect(data, timing, limit).unwrap(), expected);
        }
        assert_eq!(expected.len(), 2);
        assert_eq!(expected[0].gestures, 10);
        assert_eq!(expected[0].text, "123456789\r\n");
        assert_eq!(expected[0].end_bytes, 11);
        assert_eq!(expected[0].end_scalars, 11);
        assert!(!expected[0].end_of_input);
        assert!(expected[1].end_of_input);
    }

    #[test]
    fn text_stream_strict_input_reports_only_numeric_positions() {
        let timing = TypingTiming::DESKTOP_SAFE;
        for bytes in [
            b"ok\xe2\x80\x94".as_slice(),
            b"ok\x1b".as_slice(),
            b"ok\x08".as_slice(),
        ] {
            let error = collect(bytes, timing, 1).unwrap_err();
            assert_eq!(error.kind, TextStreamErrorKind::UnsupportedText);
            assert_eq!(error.byte_offset, 2);
            assert_eq!(error.scalar_offset, 2);
        }
        for bytes in [b"ok\xc0\xaf".as_slice(), b"ok\xe2\x82".as_slice()] {
            let error = collect(bytes, timing, 1).unwrap_err();
            assert_eq!(error.kind, TextStreamErrorKind::InvalidUtf8);
            assert_eq!(error.byte_offset, 2);
            assert_eq!(error.scalar_offset, 2);
        }
    }

    #[test]
    fn replacement_policy_is_explicit_one_for_one_and_preserves_source_offsets() {
        let timing = TypingTiming {
            key_down_ms: 100,
            release_gap_ms: 100,
        };
        let source = "A—B\u{1b}C\r\n";
        let mut reader = TextStreamReader::with_unsupported_policy(
            Fragmented {
                bytes: Cursor::new(source.as_bytes().to_vec()),
                limit: 1,
            },
            timing,
            UnsupportedTextPolicy::Replace,
        )
        .unwrap();
        let part = reader.next_part().unwrap().unwrap();
        assert_eq!(part.text, "A?B?C\r\n");
        assert_eq!(part.replacements, 2);
        assert_eq!(part.end_bytes, source.len() as u64);
        assert_eq!(part.end_scalars, source.chars().count() as u64);
        assert_eq!(part.gestures, 6);
        assert!(part.end_of_input);
        assert!(reader.next_part().unwrap().is_none());

        let (replaced, count) = replace_unsupported_text(source);
        assert_eq!(replaced, "A?B?C\r\n");
        assert_eq!(count, 2);
    }

    #[test]
    fn text_stream_compile_limits_cover_every_timing_pair() {
        for key_down_ms in 5..=100 {
            for release_gap_ms in 5..=100 {
                let timing = TypingTiming {
                    key_down_ms,
                    release_gap_ms,
                };
                let capacity = text_stream_child_capacity(timing);
                assert!((10..=200).contains(&capacity));
                assert!(u32::from(capacity) * u32::from(key_down_ms + release_gap_ms) <= 2_000);
            }
        }
    }

    #[test]
    fn text_stream_part_validation_preserves_crlf_canonicality() {
        let timing = TypingTiming {
            key_down_ms: 100,
            release_gap_ms: 100,
        };
        assert!(validate_text_stream_part("123456789\r\n", timing, false).is_ok());
        assert_eq!(
            validate_text_stream_part("short", timing, false)
                .unwrap_err()
                .kind,
            TextStreamErrorKind::NoncanonicalPart
        );
        assert_eq!(
            validate_text_stream_part("123456789\r", timing, false)
                .unwrap_err()
                .kind,
            TextStreamErrorKind::NoncanonicalPart
        );
        assert!(validate_text_stream_part("short", timing, true).is_ok());
    }
}
