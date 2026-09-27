use crate::api::{ApiClient, ApiError, CommandOutcome};
use keyferry_layouts::{
    text_stream::{
        TextStreamError, TextStreamErrorKind, TextStreamReader, UnsupportedTextPolicy,
        TEXT_STREAM_RECEIPT_SCHEMA_V1, TEXT_STREAM_SCHEMA_V1,
    },
    TypingTiming,
};
use serde::Deserialize;
use std::{
    fs::{self, File, Metadata},
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroize;

const POLL_INTERVAL: Duration = Duration::from_millis(250);
const LEASE_RENEWAL_INTERVAL: Duration = Duration::from_secs(5);
const LOST_POST_RECONCILIATION: Duration = Duration::from_secs(2);
const CANCEL_RECONCILIATION: Duration = Duration::from_secs(125);

#[derive(Clone, Debug)]
pub struct TextFileOptions {
    pub path: PathBuf,
    pub timing: TypingTiming,
    pub send_after_seconds: u16,
    pub unsupported: UnsupportedTextPolicy,
}

#[derive(Clone, Copy, Debug)]
pub struct TextValueOptions {
    pub timing: TypingTiming,
    pub send_after_seconds: u16,
    pub unsupported: UnsupportedTextPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextFileSummary {
    pub source_bytes: u64,
    pub source_scalars: u64,
    pub lines: u64,
    pub children: u64,
    pub gestures: u64,
    pub replacements: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextFileProgress {
    pub job_id: String,
    pub confirmed_bytes: u64,
    pub confirmed_children: u64,
    pub total_bytes: u64,
    pub total_children: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextFileResult {
    pub job_id: String,
    pub outcome: CommandOutcome,
    pub confirmed_bytes: u64,
    pub total_bytes: u64,
    pub possible_start: bool,
    pub terminal_zero_confirmed: bool,
}

#[derive(Debug)]
pub enum TextFileError {
    Input {
        code: &'static str,
        byte_offset: u64,
        scalar_offset: u64,
    },
    Api(ApiError),
    Protocol(&'static str),
    SourceChanged,
    OutcomeUnknown {
        job_id: String,
        confirmed_bytes: u64,
    },
    CancelReconciliation,
}

impl std::fmt::Display for TextFileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input {
                code,
                byte_offset,
                scalar_offset,
            } => write!(
                formatter,
                "{code} at byte {byte_offset}, character {scalar_offset}"
            ),
            Self::Api(error) => error.fmt(formatter),
            Self::Protocol(code) => formatter.write_str(code),
            Self::SourceChanged => {
                formatter.write_str("the selected file changed after validation")
            }
            Self::OutcomeUnknown {
                job_id,
                confirmed_bytes,
            } => write!(
                formatter,
                "stream {job_id} became uncertain after {confirmed_bytes} confirmed bytes; do not resend automatically"
            ),
            Self::CancelReconciliation => formatter.write_str(
                "cancellation was requested, but the terminal stream result was not confirmed",
            ),
        }
    }
}

impl std::error::Error for TextFileError {}

impl From<ApiError> for TextFileError {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

impl From<TextStreamError> for TextFileError {
    fn from(error: TextStreamError) -> Self {
        Self::Input {
            code: error.code(),
            byte_offset: error.byte_offset,
            scalar_offset: error.scalar_offset,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamCapabilities {
    schema: String,
    epoch: String,
    text_stream: String,
    child_budget_ms: u16,
    source_read_bytes: usize,
    lease_ms: u64,
    source_idle_ms: u64,
    receipt_retention_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct StreamCursor {
    bytes: String,
    scalars: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ConfirmedPrefix {
    bytes: String,
    scalars: String,
    children: String,
    gestures: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CurrentChild {
    index: String,
    command_id: String,
    outcome: CommandOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct StreamRange {
    start: StreamCursor,
    end: StreamCursor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct StreamReceipt {
    schema: String,
    epoch: String,
    job_id: String,
    device_id: String,
    source_kind: String,
    unsupported: UnsupportedTextPolicy,
    phase: String,
    outcome: Option<CommandOutcome>,
    terminal: bool,
    reason: Option<String>,
    source_complete: bool,
    source_total_bytes: Option<String>,
    source_total_scalars: Option<String>,
    confirmed_prefix: ConfirmedPrefix,
    uncertain_range: Option<StreamRange>,
    not_dispatched_from: StreamCursor,
    next_index: String,
    current_child: Option<CurrentChild>,
    possible_start: bool,
    terminal_zero_confirmed: bool,
    continuation_allowed: bool,
    expires_at: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceIdentity {
    length: u64,
    modified: Option<SystemTime>,
}

pub fn preflight_text_file(options: &TextFileOptions) -> Result<TextFileSummary, TextFileError> {
    let file = File::open(&options.path).map_err(|_| input_error(TextStreamErrorKind::SourceIo))?;
    summarize_reader(file, options.timing, options.unsupported)
}

pub fn preflight_text_value(
    value: &str,
    options: TextValueOptions,
) -> Result<TextFileSummary, TextFileError> {
    summarize_reader(
        Cursor::new(value.as_bytes()),
        options.timing,
        options.unsupported,
    )
}

fn summarize_reader<R: Read>(
    source: R,
    timing: TypingTiming,
    unsupported: UnsupportedTextPolicy,
) -> Result<TextFileSummary, TextFileError> {
    let mut reader = TextStreamReader::with_unsupported_policy(source, timing, unsupported)?;
    let mut summary = TextFileSummary {
        source_bytes: 0,
        source_scalars: 0,
        lines: 0,
        children: 0,
        gestures: 0,
        replacements: 0,
    };
    let mut newlines = 0_u64;
    let mut ends_with_newline = false;
    while let Some(part) = reader.next_part()? {
        summary.source_bytes = part.end_bytes;
        summary.source_scalars = part.end_scalars;
        summary.children = summary.children.saturating_add(1);
        summary.gestures = summary.gestures.saturating_add(u64::from(part.gestures));
        summary.replacements = summary
            .replacements
            .saturating_add(u64::from(part.replacements));
        newlines = newlines.saturating_add(
            u64::try_from(part.text.bytes().filter(|byte| *byte == b'\n').count())
                .unwrap_or(u64::MAX),
        );
        ends_with_newline = part.text.ends_with('\n');
    }
    if summary.children == 0 {
        return Err(input_error(TextStreamErrorKind::Empty));
    }
    summary.lines = newlines.saturating_add(u64::from(!ends_with_newline));
    Ok(summary)
}

pub fn run_text_file(
    client: &ApiClient,
    device_id: &str,
    options: &TextFileOptions,
    cancel: &AtomicBool,
    on_progress: impl Fn(TextFileProgress),
) -> Result<TextFileResult, TextFileError> {
    let summary = preflight_text_file(options)?;
    let initial_source_identity = source_identity(&options.path)?;
    let file = File::open(&options.path).map_err(|_| input_error(TextStreamErrorKind::SourceIo))?;
    let reader =
        TextStreamReader::with_unsupported_policy(file, options.timing, options.unsupported)?;
    let path = options.path.clone();
    run_text_reader(
        client,
        device_id,
        options.timing,
        options.send_after_seconds,
        options.unsupported,
        summary,
        reader,
        cancel,
        on_progress,
        move || Ok(source_identity(&path)? == initial_source_identity),
    )
}

pub fn run_text_value(
    client: &ApiClient,
    device_id: &str,
    mut value: String,
    options: TextValueOptions,
    cancel: &AtomicBool,
    on_progress: impl Fn(TextFileProgress),
) -> Result<TextFileResult, TextFileError> {
    let summary = preflight_text_value(&value, options)?;
    let bytes = std::mem::take(&mut value).into_bytes();
    let reader = TextStreamReader::with_unsupported_policy(
        SensitiveText::new(bytes),
        options.timing,
        options.unsupported,
    )?;
    run_text_reader(
        client,
        device_id,
        options.timing,
        options.send_after_seconds,
        options.unsupported,
        summary,
        reader,
        cancel,
        on_progress,
        || Ok(true),
    )
}

struct SensitiveText {
    cursor: Cursor<Vec<u8>>,
}

impl SensitiveText {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            cursor: Cursor::new(bytes),
        }
    }
}

impl Read for SensitiveText {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.cursor.read(buffer)
    }
}

impl Drop for SensitiveText {
    fn drop(&mut self) {
        self.cursor.get_mut().zeroize();
    }
}

#[allow(clippy::too_many_arguments)]
fn run_text_reader<R: Read>(
    client: &ApiClient,
    device_id: &str,
    timing: TypingTiming,
    send_after_seconds: u16,
    unsupported: UnsupportedTextPolicy,
    summary: TextFileSummary,
    mut reader: TextStreamReader<R>,
    cancel: &AtomicBool,
    on_progress: impl Fn(TextFileProgress),
    source_is_unchanged: impl Fn() -> Result<bool, TextFileError>,
) -> Result<TextFileResult, TextFileError> {
    let capabilities: StreamCapabilities = client.text_stream_capabilities()?;
    validate_capabilities(&capabilities)?;
    let job_id = uuid::Uuid::now_v7().to_string();
    let create = serde_json::json!({
        "schema": TEXT_STREAM_SCHEMA_V1,
        "epoch": capabilities.epoch,
        "job_id": job_id,
        "profile": "windows-us",
        "key_down_ms": timing.key_down_ms,
        "key_gap_ms": timing.release_gap_ms,
        "send_after_seconds": send_after_seconds,
        "source_kind": "text",
        "validation": "preflight",
        "unsupported": unsupported,
    });
    let mut receipt = match client.create_text_stream(device_id, &create) {
        Ok(receipt) => receipt,
        Err(error) => match client.text_stream_status(device_id, &job_id) {
            Ok(receipt) => receipt,
            Err(_) => return Err(TextFileError::Api(error)),
        },
    };
    validate_receipt(&receipt, &capabilities.epoch, &job_id, device_id)?;

    let mut index = 0_u64;
    loop {
        if cancel.load(Ordering::Acquire) {
            receipt = request_cancel(
                client,
                device_id,
                &job_id,
                &capabilities.epoch,
                "user_cancel",
                None,
            )
            .unwrap_or(receipt);
            return wait_for_terminal(
                client,
                device_id,
                &job_id,
                &capabilities.epoch,
                receipt,
                &summary,
            );
        }
        let source_unchanged = match source_is_unchanged() {
            Ok(unchanged) => unchanged,
            Err(error) => {
                let _ = request_cancel(
                    client,
                    device_id,
                    &job_id,
                    &capabilities.epoch,
                    "source_io",
                    None,
                );
                return Err(error);
            }
        };
        if !source_unchanged {
            let _ = request_cancel(
                client,
                device_id,
                &job_id,
                &capabilities.epoch,
                "source_changed",
                None,
            );
            return Err(TextFileError::SourceChanged);
        }
        let part = match reader.next_part() {
            Ok(part) => part,
            Err(error) => {
                let _ = request_cancel(
                    client,
                    device_id,
                    &job_id,
                    &capabilities.epoch,
                    "source_invalid",
                    Some((error.byte_offset, error.scalar_offset)),
                );
                return Err(error.into());
            }
        };
        let Some(part) = part else {
            if receipt.terminal {
                return result_from_receipt(receipt, &summary);
            }
            let finish = serde_json::json!({
                "epoch": capabilities.epoch,
                "next_index": index.to_string(),
                "final_position": {
                    "bytes": summary.source_bytes.to_string(),
                    "scalars": summary.source_scalars.to_string(),
                },
            });
            receipt = match client.finish_text_stream(device_id, &job_id, &finish) {
                Ok(receipt) => receipt,
                Err(_) => match client.text_stream_status::<StreamReceipt>(device_id, &job_id) {
                    Ok(receipt) if receipt.terminal => receipt,
                    _ => {
                        let confirmed_bytes = parse_counter(&receipt.confirmed_prefix.bytes)?;
                        match request_cancel(
                            client,
                            device_id,
                            &job_id,
                            &capabilities.epoch,
                            "producer_lost",
                            None,
                        ) {
                            Ok(cancelled) => {
                                return wait_for_terminal(
                                    client,
                                    device_id,
                                    &job_id,
                                    &capabilities.epoch,
                                    cancelled,
                                    &summary,
                                );
                            }
                            Err(_) => {
                                return Err(TextFileError::OutcomeUnknown {
                                    job_id: job_id.clone(),
                                    confirmed_bytes,
                                });
                            }
                        }
                    }
                },
            };
            validate_receipt(&receipt, &capabilities.epoch, &job_id, device_id)?;
            return result_from_receipt(receipt, &summary);
        };
        let child_command_id = uuid::Uuid::now_v7().to_string();
        let part_request = serde_json::json!({
            "epoch": capabilities.epoch,
            "child_command_id": child_command_id,
            "source_start": {
                "bytes": part.start_bytes.to_string(),
                "scalars": part.start_scalars.to_string(),
            },
            "source_end": {
                "bytes": part.end_bytes.to_string(),
                "scalars": part.end_scalars.to_string(),
            },
            "text": part.text,
            "end_of_input": part.end_of_input,
        });
        // Stream creation has just established the owner route for child zero. Later
        // children refresh it only after the preceding child has reached a released
        // boundary, when the endpoint can safely answer a route-proof request.
        receipt = match client.submit_text_stream_part(
            device_id,
            &job_id,
            index,
            &part_request,
            index != 0,
        ) {
            Ok(next) => next,
            Err(_) => reconcile_after_lost_post(
                client,
                device_id,
                &job_id,
                &capabilities.epoch,
                &child_command_id,
                index,
                parse_counter(&receipt.confirmed_prefix.bytes)?,
            )?,
        };
        validate_receipt(&receipt, &capabilities.epoch, &job_id, device_id)?;
        receipt = wait_for_child(
            client,
            device_id,
            &job_id,
            &capabilities.epoch,
            &child_command_id,
            index,
            receipt,
            cancel,
        )?;
        on_progress(progress_from_receipt(&receipt, &summary)?);
        if receipt.terminal {
            return result_from_receipt(receipt, &summary);
        }
        index = index.saturating_add(1);
    }
}

// Stream and child identities stay explicit so cancellation and lost-response
// reconciliation cannot accidentally fall back to ambient mutable state.
#[allow(clippy::too_many_arguments)]
fn wait_for_child(
    client: &ApiClient,
    device_id: &str,
    job_id: &str,
    epoch: &str,
    child_command_id: &str,
    index: u64,
    mut receipt: StreamReceipt,
    cancel: &AtomicBool,
) -> Result<StreamReceipt, TextFileError> {
    let mut renewed_at = Instant::now();
    let mut cancellation_sent = false;
    let mut cancellation_attempted_at = None;
    let mut status_failure_started = None;
    loop {
        let next_index = parse_counter(&receipt.next_index)?;
        if receipt.terminal || next_index > index {
            return Ok(receipt);
        }
        if let Some(child) = receipt.current_child.as_ref() {
            if child.command_id != child_command_id || parse_counter(&child.index)? != index {
                return Err(TextFileError::Protocol("protocol.child_identity"));
            }
        }
        let cancellation_requested = cancel.load(Ordering::Acquire);
        if cancellation_requested
            && !cancellation_sent
            && cancellation_attempted_at
                .is_none_or(|attempted: Instant| attempted.elapsed() >= Duration::from_secs(1))
        {
            cancellation_attempted_at = Some(Instant::now());
            if let Ok(cancelled) =
                request_cancel(client, device_id, job_id, epoch, "user_cancel", None)
            {
                receipt = cancelled;
                cancellation_sent = true;
                continue;
            }
        }
        if !cancellation_requested && renewed_at.elapsed() >= LEASE_RENEWAL_INTERVAL {
            let body = serde_json::json!({"epoch": epoch});
            let _: Result<StreamReceipt, _> = client.renew_text_stream(device_id, job_id, &body);
            renewed_at = Instant::now();
        }
        thread::sleep(POLL_INTERVAL);
        receipt = match client.text_stream_status(device_id, job_id) {
            Ok(receipt) => {
                status_failure_started = None;
                receipt
            }
            Err(_) => {
                let started = status_failure_started.get_or_insert_with(Instant::now);
                if started.elapsed() >= CANCEL_RECONCILIATION {
                    return Err(TextFileError::OutcomeUnknown {
                        job_id: job_id.to_owned(),
                        confirmed_bytes: parse_counter(&receipt.confirmed_prefix.bytes)?,
                    });
                }
                continue;
            }
        };
        validate_receipt(&receipt, epoch, job_id, device_id)?;
    }
}

fn wait_for_terminal(
    client: &ApiClient,
    device_id: &str,
    job_id: &str,
    epoch: &str,
    mut receipt: StreamReceipt,
    summary: &TextFileSummary,
) -> Result<TextFileResult, TextFileError> {
    let deadline = Instant::now() + CANCEL_RECONCILIATION;
    while !receipt.terminal && Instant::now() < deadline {
        thread::sleep(POLL_INTERVAL);
        if let Ok(next) = client.text_stream_status(device_id, job_id) {
            validate_receipt(&next, epoch, job_id, device_id)?;
            receipt = next;
        }
    }
    if !receipt.terminal {
        return Err(TextFileError::CancelReconciliation);
    }
    result_from_receipt(receipt, summary)
}

fn reconcile_after_lost_post(
    client: &ApiClient,
    device_id: &str,
    job_id: &str,
    epoch: &str,
    child_command_id: &str,
    index: u64,
    confirmed_bytes: u64,
) -> Result<StreamReceipt, TextFileError> {
    let deadline = Instant::now() + LOST_POST_RECONCILIATION;
    while Instant::now() < deadline {
        if let Ok(receipt) = client.text_stream_status(device_id, job_id) {
            validate_receipt(&receipt, epoch, job_id, device_id)?;
            let admitted = receipt
                .current_child
                .as_ref()
                .is_some_and(|child| child.command_id == child_command_id)
                || parse_counter(&receipt.next_index)? > index
                || receipt.terminal;
            if admitted {
                return Ok(receipt);
            }
        }
        thread::sleep(POLL_INTERVAL);
    }
    match request_cancel(client, device_id, job_id, epoch, "producer_lost", None) {
        Ok(cancelled) => Ok(cancelled),
        Err(_) => Err(TextFileError::OutcomeUnknown {
            job_id: job_id.to_owned(),
            confirmed_bytes,
        }),
    }
}

fn request_cancel(
    client: &ApiClient,
    device_id: &str,
    job_id: &str,
    epoch: &str,
    reason: &str,
    source_error: Option<(u64, u64)>,
) -> Result<StreamReceipt, TextFileError> {
    let mut body = serde_json::json!({"epoch": epoch, "reason": reason});
    if let Some((bytes, scalars)) = source_error {
        body["source_error"] = serde_json::json!({
            "bytes": bytes.to_string(),
            "scalars": scalars.to_string(),
        });
    }
    let receipt = client.cancel_text_stream(device_id, job_id, &body)?;
    validate_receipt(&receipt, epoch, job_id, device_id)?;
    Ok(receipt)
}

fn progress_from_receipt(
    receipt: &StreamReceipt,
    summary: &TextFileSummary,
) -> Result<TextFileProgress, TextFileError> {
    Ok(TextFileProgress {
        job_id: receipt.job_id.clone(),
        confirmed_bytes: parse_counter(&receipt.confirmed_prefix.bytes)?,
        confirmed_children: parse_counter(&receipt.confirmed_prefix.children)?,
        total_bytes: summary.source_bytes,
        total_children: summary.children,
    })
}

fn result_from_receipt(
    receipt: StreamReceipt,
    summary: &TextFileSummary,
) -> Result<TextFileResult, TextFileError> {
    if !receipt.terminal {
        return Err(TextFileError::Protocol("protocol.nonterminal_result"));
    }
    let outcome = receipt.outcome.unwrap_or(CommandOutcome::Unknown);
    if !outcome.is_terminal() {
        return Err(TextFileError::Protocol("protocol.nonterminal_result"));
    }
    Ok(TextFileResult {
        job_id: receipt.job_id,
        outcome,
        confirmed_bytes: parse_counter(&receipt.confirmed_prefix.bytes)?,
        total_bytes: summary.source_bytes,
        possible_start: receipt.possible_start,
        terminal_zero_confirmed: receipt.terminal_zero_confirmed,
    })
}

fn validate_capabilities(capabilities: &StreamCapabilities) -> Result<(), TextFileError> {
    if capabilities.schema != "keyferry.capabilities.v1"
        || capabilities.text_stream != TEXT_STREAM_SCHEMA_V1
        || capabilities.epoch.is_empty()
        || capabilities.child_budget_ms == 0
        || capabilities.source_read_bytes == 0
        || capabilities.lease_ms == 0
        || capabilities.source_idle_ms == 0
        || capabilities.receipt_retention_ms == 0
    {
        return Err(TextFileError::Protocol("protocol.capability"));
    }
    Ok(())
}

fn validate_receipt(
    receipt: &StreamReceipt,
    epoch: &str,
    job_id: &str,
    device_id: &str,
) -> Result<(), TextFileError> {
    if receipt.schema != TEXT_STREAM_RECEIPT_SCHEMA_V1
        || receipt.epoch != epoch
        || receipt.job_id != job_id
        || receipt.device_id != device_id
        || receipt.source_kind != "text"
        || receipt.phase.is_empty()
        || receipt.reason.as_ref().is_some_and(String::is_empty)
        || receipt
            .source_total_bytes
            .as_deref()
            .is_some_and(|value| parse_counter(value).is_err())
        || receipt
            .source_total_scalars
            .as_deref()
            .is_some_and(|value| parse_counter(value).is_err())
        || parse_counter(&receipt.confirmed_prefix.bytes).is_err()
        || parse_counter(&receipt.confirmed_prefix.scalars).is_err()
        || parse_counter(&receipt.confirmed_prefix.children).is_err()
        || parse_counter(&receipt.confirmed_prefix.gestures).is_err()
        || parse_counter(&receipt.not_dispatched_from.bytes).is_err()
        || parse_counter(&receipt.not_dispatched_from.scalars).is_err()
        || parse_counter(&receipt.next_index).is_err()
        || receipt.current_child.as_ref().is_some_and(|child| {
            child.command_id.is_empty()
                || parse_counter(&child.index).is_err()
                || child.outcome.is_terminal()
        })
        || receipt.uncertain_range.as_ref().is_some_and(|range| {
            parse_counter(&range.start.bytes).is_err()
                || parse_counter(&range.start.scalars).is_err()
                || parse_counter(&range.end.bytes).is_err()
                || parse_counter(&range.end.scalars).is_err()
        })
        || (receipt.terminal && receipt.continuation_allowed)
        || receipt.expires_at.as_ref().is_some_and(String::is_empty)
    {
        return Err(TextFileError::Protocol("protocol.invalid_response"));
    }
    Ok(())
}

fn parse_counter(value: &str) -> Result<u64, TextFileError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(TextFileError::Protocol("protocol.invalid_response"));
    }
    value
        .parse()
        .map_err(|_| TextFileError::Protocol("protocol.invalid_response"))
}

fn source_identity(path: &Path) -> Result<SourceIdentity, TextFileError> {
    let metadata = fs::metadata(path).map_err(|_| input_error(TextStreamErrorKind::SourceIo))?;
    validate_source_metadata(&metadata)?;
    Ok(SourceIdentity {
        length: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

fn validate_source_metadata(metadata: &Metadata) -> Result<(), TextFileError> {
    if !metadata.is_file() {
        return Err(input_error(TextStreamErrorKind::SourceIo));
    }
    Ok(())
}

fn input_error(kind: TextStreamErrorKind) -> TextFileError {
    TextFileError::Input {
        code: kind.code(),
        byte_offset: 0,
        scalar_offset: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Endpoint;
    use std::{
        io::Write,
        net::{TcpListener, TcpStream},
    };

    fn accept_request(listener: &TcpListener) -> (TcpStream, String) {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        let headers = String::from_utf8(request).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
            })
            .unwrap_or(0);
        let mut body = vec![0_u8; content_length];
        stream.read_exact(&mut body).unwrap();
        (stream, headers)
    }

    fn receipt_json(terminal: bool) -> String {
        serde_json::json!({
            "schema": TEXT_STREAM_RECEIPT_SCHEMA_V1,
            "epoch": "epoch-1",
            "job_id": "019d1234-5678-7abc-8123-456789abcdef",
            "device_id": "device-1",
            "source_kind": "text",
            "unsupported": "reject",
            "phase": if terminal { "terminal" } else { "ready" },
            "outcome": if terminal { serde_json::Value::String("REJECTED".to_owned()) } else { serde_json::Value::Null },
            "terminal": terminal,
            "reason": if terminal { serde_json::Value::String("producer_lost".to_owned()) } else { serde_json::Value::Null },
            "source_complete": false,
            "source_total_bytes": serde_json::Value::Null,
            "source_total_scalars": serde_json::Value::Null,
            "confirmed_prefix": {"bytes":"0","scalars":"0","children":"0","gestures":"0"},
            "uncertain_range": serde_json::Value::Null,
            "not_dispatched_from": {"bytes":"0","scalars":"0"},
            "next_index": "0",
            "current_child": serde_json::Value::Null,
            "possible_start": false,
            "terminal_zero_confirmed": true,
            "continuation_allowed": !terminal,
            "expires_at": serde_json::Value::Null,
        })
        .to_string()
    }

    #[test]
    fn preflight_counts_crlf_lines_without_loading_the_source() {
        let path = std::env::temp_dir().join(format!("keyferry-{}.txt", uuid::Uuid::now_v7()));
        let mut file = File::create(&path).unwrap();
        file.write_all(b"one\r\ntwo\r\nthree\r\n").unwrap();
        let options = TextFileOptions {
            path: path.clone(),
            timing: TypingTiming::DESKTOP_SAFE,
            send_after_seconds: 0,
            unsupported: UnsupportedTextPolicy::Reject,
        };
        let summary = preflight_text_file(&options).unwrap();
        assert_eq!(summary.source_bytes, 17);
        assert_eq!(summary.source_scalars, 17);
        assert_eq!(summary.lines, 3);
        assert_eq!(summary.gestures, 14);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn preflight_reports_numeric_unsupported_position() {
        let path = std::env::temp_dir().join(format!("keyferry-{}.txt", uuid::Uuid::now_v7()));
        fs::write(&path, "plain\nem dash: —\n").unwrap();
        let options = TextFileOptions {
            path: path.clone(),
            timing: TypingTiming::DESKTOP_SAFE,
            send_after_seconds: 0,
            unsupported: UnsupportedTextPolicy::Reject,
        };
        let error = preflight_text_file(&options).unwrap_err();
        assert!(matches!(
            error,
            TextFileError::Input {
                code: "input.unsupported_text",
                ..
            }
        ));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn preflight_accepts_a_thousand_line_file_beyond_the_single_command_limit() {
        let path = std::env::temp_dir().join(format!("keyferry-{}.ahk", uuid::Uuid::now_v7()));
        let mut file = File::create(&path).unwrap();
        for index in 0..1_000 {
            writeln!(file, "rows.Push(\"row {index:04}\")").unwrap();
        }
        drop(file);
        let options = TextFileOptions {
            path: path.clone(),
            timing: TypingTiming {
                key_down_ms: 5,
                release_gap_ms: 5,
            },
            send_after_seconds: 5,
            unsupported: UnsupportedTextPolicy::Reject,
        };
        let summary = preflight_text_file(&options).unwrap();
        assert_eq!(summary.lines, 1_000);
        assert!(summary.source_bytes > 4_096);
        assert!(summary.children > 1);
        assert_eq!(summary.replacements, 0);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn preflight_accepts_a_large_pasted_value_beyond_the_single_command_limit() {
        let value = (0..1_000)
            .map(|index| format!("rows.Push(\"row {index:04}\")\r\n"))
            .collect::<String>();
        let options = TextValueOptions {
            timing: TypingTiming {
                key_down_ms: 12,
                release_gap_ms: 5,
            },
            send_after_seconds: 2,
            unsupported: UnsupportedTextPolicy::Reject,
        };

        let summary = preflight_text_value(&value, options).unwrap();

        assert_eq!(summary.lines, 1_000);
        assert!(summary.source_bytes > 4_096);
        assert!(summary.children > 1);
        assert_eq!(summary.replacements, 0);
    }

    #[test]
    fn uncertain_delivery_message_forbids_automatic_resend() {
        let message = TextFileError::OutcomeUnknown {
            job_id: "019d1234-5678-7abc-8123-456789abcdef".to_owned(),
            confirmed_bytes: 2_400,
        }
        .to_string();
        assert!(message.contains("019d1234-5678-7abc-8123-456789abcdef"));
        assert!(message.contains("2400 confirmed bytes"));
        assert!(message.contains("do not resend automatically"));
    }

    #[test]
    fn lost_unadmitted_part_returns_the_confirmed_cancellation_receipt() {
        serde_json::from_str::<StreamReceipt>(&receipt_json(true)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = ApiClient::new(
            Endpoint::from_url(&format!("http://127.0.0.1:{port}")).unwrap(),
            "test-token",
        )
        .unwrap();
        let worker = thread::spawn(move || loop {
            let (mut stream, headers) = accept_request(&listener);
            let terminal = headers.starts_with(
                "POST /v1/devices/device-1/text-streams/019d1234-5678-7abc-8123-456789abcdef/cancel HTTP/1.1",
            );
            let response = receipt_json(terminal);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response,
            )
            .unwrap();
            if terminal {
                break;
            }
        });

        let receipt = reconcile_after_lost_post(
            &client,
            "device-1",
            "019d1234-5678-7abc-8123-456789abcdef",
            "epoch-1",
            "019d1234-5678-7abc-8123-456789abcdee",
            0,
            0,
        )
        .unwrap();
        worker.join().unwrap();

        assert!(receipt.terminal);
        assert_eq!(receipt.outcome, Some(CommandOutcome::Rejected));
        assert!(!receipt.possible_start);
        assert!(receipt.terminal_zero_confirmed);
    }

    #[test]
    fn job_unknown_to_a_restarted_daemon_is_reported_as_uncertain() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = ApiClient::new(
            Endpoint::from_url(&format!("http://127.0.0.1:{port}")).unwrap(),
            "test-token",
        )
        .unwrap();
        let worker = thread::spawn(move || loop {
            let (mut stream, headers) = accept_request(&listener);
            let response =
                r#"{"error":"text_stream.not_found","outcome":"REJECTED","command_id":null}"#;
            write!(
                stream,
                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response,
            )
            .unwrap();
            if headers.starts_with("POST ") {
                break;
            }
        });

        let error = reconcile_after_lost_post(
            &client,
            "device-1",
            "019d1234-5678-7abc-8123-456789abcdef",
            "epoch-1",
            "019d1234-5678-7abc-8123-456789abcdee",
            3,
            2_400,
        )
        .unwrap_err();
        worker.join().unwrap();

        assert!(matches!(
            error,
            TextFileError::OutcomeUnknown {
                confirmed_bytes: 2_400,
                ..
            }
        ));
    }
}
