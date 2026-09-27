//! Fixed-size Local Management v1 reports.
//!
//! Cryptographic calculation and session policy live above this codec. The
//! codec makes every byte covered by a proof or envelope tag explicit and
//! rejects reserved bytes and identity/sequence shape errors before dispatch.

use crate::{
    local_management_bond_state as bond_state, local_management_operation as operation,
    local_management_probe_outcome as probe_outcome, local_management_probe_phase as probe_phase,
    local_management_receipt_state as receipt_state, local_management_registry as limits,
    local_management_status as status, local_management_status_page as status_page, output_mode,
};
use std::fmt;

pub type Report = [u8; limits::REPORT_SIZE];
pub type SessionId = [u8; limits::SESSION_ID_SIZE];
pub type DeviceNonce = [u8; limits::DEVICE_NONCE_SIZE];
pub type HostNonce = [u8; limits::HOST_NONCE_SIZE];
pub type AuthenticationTag = [u8; limits::AUTHENTICATION_TAG_SIZE];
pub type EnvelopeTag = [u8; limits::ENVELOPE_TAG_SIZE];
pub type OperationId = [u8; limits::OPERATION_ID_SIZE];
pub type RequestPayload = [u8; limits::REQUEST_PAYLOAD_SIZE];
pub type ResponsePayload = [u8; limits::RESPONSE_PAYLOAD_SIZE];

const RESPONSE_BIT: u8 = 0x80;
const ENVELOPE_TAG_OFFSET: usize = limits::REPORT_SIZE - limits::ENVELOPE_TAG_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    BadLength(usize),
    UnexpectedOperation { expected: u8, actual: u8 },
    MissingResponseBit,
    UnexpectedResponseBit,
    UnsupportedOperation(u8),
    UnsupportedVersion(u8),
    NonzeroReserved,
    ZeroSessionId,
    ZeroSequence,
    MissingOperationId,
    UnexpectedOperationId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusPageError {
    UnsupportedPage(u8),
    UnsupportedSchema(u8),
    NonzeroReserved,
    InvalidValue,
    InvalidRelease,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceStatus {
    pub active_output_mode: u8,
    pub stored_output_mode: u8,
    pub board_compatibility_id: u8,
    pub release: [u8; 8],
    pub capabilities: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyStatus {
    pub maintenance_active: bool,
    pub command_active: bool,
    pub armed: bool,
    pub usb_mounted: bool,
    pub keyboard_neutral: bool,
    pub mouse_neutral: bool,
    pub restart_pending: bool,
    pub receipt_storage_healthy: bool,
    pub usb_attachment_generation: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkStatus {
    pub wifi_stage: u8,
    pub active_path: u8,
    pub running: bool,
    pub wifi_available: bool,
    pub ble_available: bool,
    pub endpoint_authenticated: bool,
    pub configuration_valid: bool,
    pub wifi_profile_count: u8,
    pub paired_host_count: u8,
    pub policy_state: u8,
    pub wifi_error: i32,
    pub nvs_error: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BleHidStatus {
    pub bond_state: u8,
    pub peripheral_stage: u8,
    pub advertising: bool,
    pub connected: bool,
    pub authenticated: bool,
    pub subscribed: bool,
    pub ready: bool,
    pub enrollment_active: bool,
    pub error: i32,
    pub generation: u32,
    pub enrollment_remaining_ms: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyStatus {
    pub state: u8,
    pub sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptStatus {
    pub state: u8,
    pub operation: u8,
    pub result: u8,
    pub flags: u8,
    pub argument: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeRunStatus {
    pub sample_sequence: u16,
    pub phase: u8,
    pub uptime_seconds: u32,
    pub held_flags: u8,
    pub first_outcome: u8,
    pub second_outcome: u8,
    pub transport_running: bool,
    pub link_path: u8,
    pub output_mode: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeHeapStatus {
    pub sample_sequence: u16,
    pub free_bytes: u32,
    pub largest_bytes: u32,
    pub minimum_bytes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeStackStatus {
    pub sample_sequence: u16,
    pub main_bytes: u32,
    pub transport_bytes: u32,
    pub probe_bytes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatusPage {
    Device(DeviceStatus),
    Safety(SafetyStatus),
    Network(NetworkStatus),
    BleHid(BleHidStatus),
    Policy(PolicyStatus),
    LastReceipt(Option<ReceiptStatus>),
    ProbeRun(ProbeRunStatus),
    ProbeHeap(ProbeHeapStatus),
    ProbeStack(ProbeStackStatus),
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength(length) => write!(formatter, "local report length is {length}"),
            Self::UnexpectedOperation { expected, actual } => write!(
                formatter,
                "local report operation 0x{actual:02x} does not match 0x{expected:02x}"
            ),
            Self::MissingResponseBit => write!(formatter, "local response bit is missing"),
            Self::UnexpectedResponseBit => write!(formatter, "local request has response bit"),
            Self::UnsupportedOperation(operation) => {
                write!(formatter, "unsupported local operation 0x{operation:02x}")
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported local management version {version}")
            }
            Self::NonzeroReserved => write!(formatter, "local report reserved bytes are nonzero"),
            Self::ZeroSessionId => write!(formatter, "local session ID is zero"),
            Self::ZeroSequence => write!(formatter, "local sequence is zero"),
            Self::MissingOperationId => write!(formatter, "local mutation operation ID is zero"),
            Self::UnexpectedOperationId => {
                write!(formatter, "local read operation ID must be zero")
            }
        }
    }
}

impl std::error::Error for CodecError {}

impl fmt::Display for StatusPageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPage(page) => write!(formatter, "unsupported status page {page}"),
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported status schema {schema}")
            }
            Self::NonzeroReserved => write!(formatter, "status page reserved bytes are nonzero"),
            Self::InvalidValue => write!(formatter, "status page contains an invalid value"),
            Self::InvalidRelease => write!(formatter, "status release is not canonical ASCII"),
        }
    }
}

impl std::error::Error for StatusPageError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeResponse {
    pub status: u8,
    pub capabilities: u32,
    pub device_id: [u8; 16],
    pub device_nonce: DeviceNonce,
    pub session_id: SessionId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticateRequest {
    pub session_id: SessionId,
    pub host_nonce: HostNonce,
    pub proof: AuthenticationTag,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticateResponse {
    pub status: u8,
    pub session_id: SessionId,
    pub proof: AuthenticationTag,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedRequest {
    pub operation: u8,
    pub session_id: SessionId,
    pub sequence: u32,
    pub operation_id: OperationId,
    pub payload: RequestPayload,
    pub tag: EnvelopeTag,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedResponse {
    pub operation: u8,
    pub status: u8,
    pub flags: u8,
    pub session_id: SessionId,
    pub sequence: u32,
    pub operation_id: OperationId,
    pub payload: ResponsePayload,
    pub tag: EnvelopeTag,
}

#[must_use]
pub fn challenge_request() -> Report {
    let mut report = [0; limits::REPORT_SIZE];
    report[0] = operation::CHALLENGE;
    report
}

pub fn status_request_payload(page: u8) -> Result<RequestPayload, StatusPageError> {
    if !matches!(
        page,
        status_page::DEVICE
            | status_page::SAFETY
            | status_page::NETWORK
            | status_page::BLE_HID
            | status_page::POLICY
            | status_page::LAST_RECEIPT
            | status_page::PROBE_RUN
            | status_page::PROBE_HEAP
            | status_page::PROBE_STACK
    ) {
        return Err(StatusPageError::UnsupportedPage(page));
    }
    let mut payload = [0; limits::REQUEST_PAYLOAD_SIZE];
    payload[0] = page;
    Ok(payload)
}

pub fn receipt_request_payload(operation_id: &OperationId) -> Result<RequestPayload, CodecError> {
    if all_zero(operation_id) {
        return Err(CodecError::MissingOperationId);
    }
    let mut payload = [0; limits::REQUEST_PAYLOAD_SIZE];
    payload[..operation_id.len()].copy_from_slice(operation_id);
    Ok(payload)
}

pub fn decode_receipt_payload(payload: &ResponsePayload) -> Result<ReceiptStatus, StatusPageError> {
    if !all_zero(&payload[6..]) {
        return Err(StatusPageError::NonzeroReserved);
    }
    let receipt = ReceiptStatus {
        state: payload[0],
        operation: payload[1],
        result: payload[2],
        flags: payload[3],
        argument: u16::from_le_bytes(array(&payload[4..6])),
    };
    if valid_receipt_status(&receipt) {
        Ok(receipt)
    } else {
        Err(StatusPageError::InvalidValue)
    }
}

pub fn decode_status_page(
    page: u8,
    payload: &ResponsePayload,
) -> Result<StatusPage, StatusPageError> {
    if payload[0] != limits::STATUS_SCHEMA {
        return Err(StatusPageError::UnsupportedSchema(payload[0]));
    }
    match page {
        status_page::DEVICE => {
            if !matches!(payload[1], output_mode::USB_HID | output_mode::BLE_HID)
                || !matches!(payload[2], output_mode::USB_HID | output_mode::BLE_HID)
                || payload[3] == 0
            {
                return Err(StatusPageError::InvalidValue);
            }
            let release = array(&payload[4..12]);
            if !canonical_release(&release) {
                return Err(StatusPageError::InvalidRelease);
            }
            Ok(StatusPage::Device(DeviceStatus {
                active_output_mode: payload[1],
                stored_output_mode: payload[2],
                board_compatibility_id: payload[3],
                release,
                capabilities: u32::from_le_bytes(array(&payload[12..16])),
            }))
        }
        status_page::SAFETY => {
            if payload[2] != 0 || payload[3] != 0 || !all_zero(&payload[8..]) {
                return Err(StatusPageError::NonzeroReserved);
            }
            let flags = payload[1];
            Ok(StatusPage::Safety(SafetyStatus {
                maintenance_active: flags & 0x01 != 0,
                command_active: flags & 0x02 != 0,
                armed: flags & 0x04 != 0,
                usb_mounted: flags & 0x08 != 0,
                keyboard_neutral: flags & 0x10 != 0,
                mouse_neutral: flags & 0x20 != 0,
                restart_pending: flags & 0x40 != 0,
                receipt_storage_healthy: flags & 0x80 != 0,
                usb_attachment_generation: u32::from_le_bytes(array(&payload[4..8])),
            }))
        }
        status_page::NETWORK => {
            if payload[1] > 15
                || payload[2] > 2
                || payload[3] & !0x1F != 0
                || payload[4] > 8
                || payload[5] > 8
                || payload[6] > 5
            {
                return Err(StatusPageError::InvalidValue);
            }
            if payload[7] != 0 {
                return Err(StatusPageError::NonzeroReserved);
            }
            let flags = payload[3];
            Ok(StatusPage::Network(NetworkStatus {
                wifi_stage: payload[1],
                active_path: payload[2],
                running: flags & 0x01 != 0,
                wifi_available: flags & 0x02 != 0,
                ble_available: flags & 0x04 != 0,
                endpoint_authenticated: flags & 0x08 != 0,
                configuration_valid: flags & 0x10 != 0,
                wifi_profile_count: payload[4],
                paired_host_count: payload[5],
                policy_state: payload[6],
                wifi_error: i32::from_le_bytes(array(&payload[8..12])),
                nvs_error: i32::from_le_bytes(array(&payload[12..16])),
            }))
        }
        status_page::BLE_HID => {
            if payload[1] > bond_state::STORE_ERROR || payload[2] > 8 || payload[3] & !0x3F != 0 {
                return Err(StatusPageError::InvalidValue);
            }
            let enrollment_remaining_ms = u32::from_le_bytes(array(&payload[12..16]));
            if enrollment_remaining_ms > limits::ENROLLMENT_TIMEOUT_MS as u32 {
                return Err(StatusPageError::InvalidValue);
            }
            let flags = payload[3];
            Ok(StatusPage::BleHid(BleHidStatus {
                bond_state: payload[1],
                peripheral_stage: payload[2],
                advertising: flags & 0x01 != 0,
                connected: flags & 0x02 != 0,
                authenticated: flags & 0x04 != 0,
                subscribed: flags & 0x08 != 0,
                ready: flags & 0x10 != 0,
                enrollment_active: flags & 0x20 != 0,
                error: i32::from_le_bytes(array(&payload[4..8])),
                generation: u32::from_le_bytes(array(&payload[8..12])),
                enrollment_remaining_ms,
            }))
        }
        status_page::POLICY => {
            if payload[1] > 5 {
                return Err(StatusPageError::InvalidValue);
            }
            if !all_zero(&payload[2..8]) {
                return Err(StatusPageError::NonzeroReserved);
            }
            Ok(StatusPage::Policy(PolicyStatus {
                state: payload[1],
                sequence: u64::from_le_bytes(array(&payload[8..16])),
            }))
        }
        status_page::LAST_RECEIPT => {
            if !all_zero(&payload[7..]) {
                return Err(StatusPageError::NonzeroReserved);
            }
            if payload[1] == receipt_state::NONE {
                if !all_zero(&payload[2..]) {
                    return Err(StatusPageError::NonzeroReserved);
                }
                return Ok(StatusPage::LastReceipt(None));
            }
            let receipt = ReceiptStatus {
                state: payload[1],
                operation: payload[2],
                result: payload[3],
                flags: payload[4],
                argument: u16::from_le_bytes(array(&payload[5..7])),
            };
            if !valid_receipt_status(&receipt) {
                return Err(StatusPageError::InvalidValue);
            }
            Ok(StatusPage::LastReceipt(Some(receipt)))
        }
        status_page::PROBE_RUN => {
            let sample_sequence = u16::from_le_bytes(array(&payload[1..3]));
            if sample_sequence == 0
                || !(probe_phase::BOOT..=probe_phase::WAITING).contains(&payload[3])
                || payload[8] & !0x03 != 0
                || payload[9] > probe_outcome::POST_GUARD_FAILED
                || payload[10] > probe_outcome::POST_GUARD_FAILED
                || payload[11] > 1
                || payload[12] > 2
                || !matches!(payload[13], output_mode::USB_HID | output_mode::BLE_HID)
            {
                return Err(StatusPageError::InvalidValue);
            }
            if !all_zero(&payload[14..]) {
                return Err(StatusPageError::NonzeroReserved);
            }
            Ok(StatusPage::ProbeRun(ProbeRunStatus {
                sample_sequence,
                phase: payload[3],
                uptime_seconds: u32::from_le_bytes(array(&payload[4..8])),
                held_flags: payload[8],
                first_outcome: payload[9],
                second_outcome: payload[10],
                transport_running: payload[11] != 0,
                link_path: payload[12],
                output_mode: payload[13],
            }))
        }
        status_page::PROBE_HEAP => {
            if payload[3] != 0 {
                return Err(StatusPageError::NonzeroReserved);
            }
            let sample_sequence = u16::from_le_bytes(array(&payload[1..3]));
            if sample_sequence == 0 {
                return Err(StatusPageError::InvalidValue);
            }
            Ok(StatusPage::ProbeHeap(ProbeHeapStatus {
                sample_sequence,
                free_bytes: u32::from_le_bytes(array(&payload[4..8])),
                largest_bytes: u32::from_le_bytes(array(&payload[8..12])),
                minimum_bytes: u32::from_le_bytes(array(&payload[12..16])),
            }))
        }
        status_page::PROBE_STACK => {
            if payload[3] != 0 {
                return Err(StatusPageError::NonzeroReserved);
            }
            let sample_sequence = u16::from_le_bytes(array(&payload[1..3]));
            if sample_sequence == 0 {
                return Err(StatusPageError::InvalidValue);
            }
            Ok(StatusPage::ProbeStack(ProbeStackStatus {
                sample_sequence,
                main_bytes: u32::from_le_bytes(array(&payload[4..8])),
                transport_bytes: u32::from_le_bytes(array(&payload[8..12])),
                probe_bytes: u32::from_le_bytes(array(&payload[12..16])),
            }))
        }
        other => Err(StatusPageError::UnsupportedPage(other)),
    }
}

pub fn decode_challenge_response(bytes: &[u8]) -> Result<ChallengeResponse, CodecError> {
    let report = report(bytes)?;
    response_operation(report[0], operation::CHALLENGE)?;
    version(report[2])?;
    if report[63] != 0 {
        return Err(CodecError::NonzeroReserved);
    }
    let session_id = array(&report[55..63]);
    require_nonzero_session(&session_id)?;
    Ok(ChallengeResponse {
        status: report[1],
        capabilities: u32::from_le_bytes(array(&report[3..7])),
        device_id: array(&report[7..23]),
        device_nonce: array(&report[23..55]),
        session_id,
    })
}

impl AuthenticateRequest {
    #[must_use]
    pub fn encode(&self) -> Report {
        let mut report = [0; limits::REPORT_SIZE];
        report[0] = operation::AUTHENTICATE;
        report[1] = limits::VERSION;
        report[2..10].copy_from_slice(&self.session_id);
        report[10..26].copy_from_slice(&self.host_nonce);
        report[26..58].copy_from_slice(&self.proof);
        report
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let report = report(bytes)?;
        request_operation(report[0], operation::AUTHENTICATE)?;
        version(report[1])?;
        if !all_zero(&report[58..]) {
            return Err(CodecError::NonzeroReserved);
        }
        let session_id = array(&report[2..10]);
        require_nonzero_session(&session_id)?;
        Ok(Self {
            session_id,
            host_nonce: array(&report[10..26]),
            proof: array(&report[26..58]),
        })
    }
}

pub fn decode_authenticate_response(bytes: &[u8]) -> Result<AuthenticateResponse, CodecError> {
    let report = report(bytes)?;
    response_operation(report[0], operation::AUTHENTICATE)?;
    version(report[2])?;
    if report[3] != 0 || !all_zero(&report[44..]) {
        return Err(CodecError::NonzeroReserved);
    }
    let session_id = array(&report[4..12]);
    require_nonzero_session(&session_id)?;
    Ok(AuthenticateResponse {
        status: report[1],
        session_id,
        proof: array(&report[12..44]),
    })
}

impl AuthenticatedRequest {
    #[must_use]
    pub fn encode(&self) -> Report {
        let mut report = self.signing_bytes();
        report[ENVELOPE_TAG_OFFSET..].copy_from_slice(&self.tag);
        report
    }

    #[must_use]
    pub fn signing_bytes(&self) -> Report {
        let mut report = [0; limits::REPORT_SIZE];
        report[0] = self.operation;
        report[1] = limits::VERSION;
        report[2..10].copy_from_slice(&self.session_id);
        report[10..14].copy_from_slice(&self.sequence.to_le_bytes());
        report[14..30].copy_from_slice(&self.operation_id);
        report[30..48].copy_from_slice(&self.payload);
        report
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let report = report(bytes)?;
        if report[0] & RESPONSE_BIT != 0 {
            return Err(CodecError::UnexpectedResponseBit);
        }
        if !is_authenticated_operation(report[0]) {
            return Err(CodecError::UnsupportedOperation(report[0]));
        }
        version(report[1])?;
        let session_id = array(&report[2..10]);
        require_nonzero_session(&session_id)?;
        let sequence = u32::from_le_bytes(array(&report[10..14]));
        if sequence == 0 {
            return Err(CodecError::ZeroSequence);
        }
        let operation_id = array(&report[14..30]);
        validate_operation_id(report[0], &operation_id)?;
        Ok(Self {
            operation: report[0],
            session_id,
            sequence,
            operation_id,
            payload: array(&report[30..48]),
            tag: array(&report[48..64]),
        })
    }
}

impl AuthenticatedResponse {
    #[must_use]
    pub fn encode(&self) -> Report {
        let mut report = self.signing_bytes();
        report[ENVELOPE_TAG_OFFSET..].copy_from_slice(&self.tag);
        report
    }

    #[must_use]
    pub fn signing_bytes(&self) -> Report {
        let mut report = [0; limits::REPORT_SIZE];
        report[0] = self.operation | RESPONSE_BIT;
        report[1] = self.status;
        report[2] = limits::VERSION;
        report[3] = self.flags;
        report[4..12].copy_from_slice(&self.session_id);
        report[12..16].copy_from_slice(&self.sequence.to_le_bytes());
        report[16..32].copy_from_slice(&self.operation_id);
        report[32..48].copy_from_slice(&self.payload);
        report
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let report = report(bytes)?;
        if report[0] & RESPONSE_BIT == 0 {
            return Err(CodecError::MissingResponseBit);
        }
        version(report[2])?;
        let session_id = array(&report[4..12]);
        require_nonzero_session(&session_id)?;
        let sequence = u32::from_le_bytes(array(&report[12..16]));
        if sequence == 0 {
            return Err(CodecError::ZeroSequence);
        }
        let operation = report[0] & !RESPONSE_BIT;
        if !is_authenticated_operation(operation) {
            return Err(CodecError::UnsupportedOperation(operation));
        }
        let operation_id = array(&report[16..32]);
        validate_operation_id(operation, &operation_id)?;
        Ok(Self {
            operation,
            status: report[1],
            flags: report[3],
            session_id,
            sequence,
            operation_id,
            payload: array(&report[32..48]),
            tag: array(&report[48..64]),
        })
    }
}

#[must_use]
pub fn is_authenticated_operation(value: u8) -> bool {
    matches!(
        value,
        operation::GET_STATUS
            | operation::OPEN_MAINTENANCE
            | operation::CLOSE_MAINTENANCE
            | operation::RESTART_NETWORK
            | operation::CLEAR_BLE_BOND_AND_ENROLL
            | operation::CANCEL_ENROLLMENT
            | operation::SET_OUTPUT_MODE
            | operation::REBOOT
            | operation::GET_RECEIPT
    )
}

#[must_use]
pub fn is_mutation(value: u8) -> bool {
    matches!(
        value,
        operation::OPEN_MAINTENANCE
            | operation::CLOSE_MAINTENANCE
            | operation::RESTART_NETWORK
            | operation::CLEAR_BLE_BOND_AND_ENROLL
            | operation::CANCEL_ENROLLMENT
            | operation::SET_OUTPUT_MODE
            | operation::REBOOT
    )
}

fn validate_operation_id(value: u8, operation_id: &OperationId) -> Result<(), CodecError> {
    let missing = all_zero(operation_id);
    if is_mutation(value) && missing {
        Err(CodecError::MissingOperationId)
    } else if !is_mutation(value) && !missing {
        Err(CodecError::UnexpectedOperationId)
    } else {
        Ok(())
    }
}

fn report(bytes: &[u8]) -> Result<&Report, CodecError> {
    bytes
        .try_into()
        .map_err(|_| CodecError::BadLength(bytes.len()))
}

fn request_operation(actual: u8, expected: u8) -> Result<(), CodecError> {
    if actual & RESPONSE_BIT != 0 {
        Err(CodecError::UnexpectedResponseBit)
    } else if actual != expected {
        Err(CodecError::UnexpectedOperation { expected, actual })
    } else {
        Ok(())
    }
}

fn response_operation(actual: u8, expected: u8) -> Result<(), CodecError> {
    if actual & RESPONSE_BIT == 0 {
        Err(CodecError::MissingResponseBit)
    } else if actual & !RESPONSE_BIT != expected {
        Err(CodecError::UnexpectedOperation {
            expected,
            actual: actual & !RESPONSE_BIT,
        })
    } else {
        Ok(())
    }
}

fn version(value: u8) -> Result<(), CodecError> {
    if value == limits::VERSION {
        Ok(())
    } else {
        Err(CodecError::UnsupportedVersion(value))
    }
}

fn require_nonzero_session(session_id: &SessionId) -> Result<(), CodecError> {
    if all_zero(session_id) {
        Err(CodecError::ZeroSessionId)
    } else {
        Ok(())
    }
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn canonical_release(release: &[u8; 8]) -> bool {
    let mut ended = false;
    release.iter().all(|byte| {
        if *byte == 0 {
            ended = true;
            true
        } else {
            !ended && (0x20..=0x7E).contains(byte)
        }
    })
}

fn valid_receipt_status(receipt: &ReceiptStatus) -> bool {
    if !(receipt_state::IN_PROGRESS..=receipt_state::UNKNOWN).contains(&receipt.state)
        || !(operation::OPEN_MAINTENANCE..=operation::REBOOT).contains(&receipt.operation)
        || receipt.flags & !0x02 != 0
    {
        return false;
    }
    if receipt.operation == operation::SET_OUTPUT_MODE {
        if !matches!(receipt.argument, 1 | 2) {
            return false;
        }
    } else if receipt.argument != 0 {
        return false;
    }
    match receipt.state {
        receipt_state::IN_PROGRESS => receipt.result == status::IN_PROGRESS && receipt.flags == 0,
        receipt_state::COMMITTED => receipt.result == status::OK,
        receipt_state::FAILED => !matches!(receipt.result, status::OK | status::IN_PROGRESS),
        receipt_state::UNKNOWN => receipt.result == status::INTERNAL && receipt.flags == 0,
        _ => false,
    }
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("fixed report slice")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{capability, local_management_status as status};

    fn session_id() -> SessionId {
        [0x21; limits::SESSION_ID_SIZE]
    }

    fn operation_id() -> OperationId {
        [0x42; limits::OPERATION_ID_SIZE]
    }

    #[test]
    fn challenge_is_side_effect_free_shape_and_decodes_exact_identity() {
        let request = challenge_request();
        assert_eq!(request[0], operation::CHALLENGE);
        assert!(all_zero(&request[1..]));

        let mut response = [0; limits::REPORT_SIZE];
        response[0] = operation::CHALLENGE | RESPONSE_BIT;
        response[1] = status::OK;
        response[2] = limits::VERSION;
        response[3..7].copy_from_slice(&capability::LOCAL_MANAGEMENT_V1.to_le_bytes());
        response[7..23].copy_from_slice(&[0x11; 16]);
        response[23..55].copy_from_slice(&[0x22; limits::DEVICE_NONCE_SIZE]);
        response[55..63].copy_from_slice(&session_id());

        let decoded = decode_challenge_response(&response).expect("challenge response");
        assert_eq!(decoded.status, status::OK);
        assert_eq!(decoded.capabilities, capability::LOCAL_MANAGEMENT_V1);
        assert_eq!(decoded.device_id, [0x11; 16]);
        assert_eq!(decoded.device_nonce, [0x22; limits::DEVICE_NONCE_SIZE]);
        assert_eq!(decoded.session_id, session_id());

        response[63] = 1;
        assert_eq!(
            decode_challenge_response(&response),
            Err(CodecError::NonzeroReserved)
        );
    }

    #[test]
    fn authenticate_request_round_trips_and_covers_full_proof() {
        let request = AuthenticateRequest {
            session_id: session_id(),
            host_nonce: [0x33; limits::HOST_NONCE_SIZE],
            proof: [0x44; limits::AUTHENTICATION_TAG_SIZE],
        };
        let encoded = request.encode();
        assert_eq!(encoded[0], operation::AUTHENTICATE);
        assert_eq!(encoded[1], limits::VERSION);
        assert_eq!(AuthenticateRequest::decode(&encoded), Ok(request));
        assert!(all_zero(&encoded[58..]));

        let mut malformed = encoded;
        malformed[63] = 1;
        assert_eq!(
            AuthenticateRequest::decode(&malformed),
            Err(CodecError::NonzeroReserved)
        );
    }

    #[test]
    fn authenticate_response_rejects_wrong_session_shape_and_reserved_bytes() {
        let mut response = [0; limits::REPORT_SIZE];
        response[0] = operation::AUTHENTICATE | RESPONSE_BIT;
        response[1] = status::OK;
        response[2] = limits::VERSION;
        response[4..12].copy_from_slice(&session_id());
        response[12..44].copy_from_slice(&[0x55; limits::AUTHENTICATION_TAG_SIZE]);
        let decoded = decode_authenticate_response(&response).expect("authenticate response");
        assert_eq!(decoded.session_id, session_id());
        assert_eq!(decoded.proof, [0x55; limits::AUTHENTICATION_TAG_SIZE]);

        response[4..12].fill(0);
        assert_eq!(
            decode_authenticate_response(&response),
            Err(CodecError::ZeroSessionId)
        );
    }

    #[test]
    fn authenticated_mutation_round_trips_and_tag_is_not_in_signing_bytes() {
        let request = AuthenticatedRequest {
            operation: operation::CLEAR_BLE_BOND_AND_ENROLL,
            session_id: session_id(),
            sequence: 7,
            operation_id: operation_id(),
            payload: [0x66; limits::REQUEST_PAYLOAD_SIZE],
            tag: [0x77; limits::ENVELOPE_TAG_SIZE],
        };
        let encoded = request.encode();
        assert_eq!(AuthenticatedRequest::decode(&encoded), Ok(request.clone()));
        assert!(all_zero(&request.signing_bytes()[ENVELOPE_TAG_OFFSET..]));
        assert_eq!(&encoded[ENVELOPE_TAG_OFFSET..], &request.tag);
    }

    #[test]
    fn authenticated_response_round_trips_without_losing_evidence_fields() {
        let response = AuthenticatedResponse {
            operation: operation::RESTART_NETWORK,
            status: status::IN_PROGRESS,
            flags: 0x03,
            session_id: session_id(),
            sequence: 9,
            operation_id: operation_id(),
            payload: [0x88; limits::RESPONSE_PAYLOAD_SIZE],
            tag: [0x99; limits::ENVELOPE_TAG_SIZE],
        };
        let encoded = response.encode();
        assert_eq!(
            AuthenticatedResponse::decode(&encoded),
            Ok(response.clone())
        );
        assert!(all_zero(&response.signing_bytes()[ENVELOPE_TAG_OFFSET..]));
    }

    #[test]
    fn operation_ids_are_mandatory_for_mutations_and_forbidden_for_reads() {
        let mutation = AuthenticatedRequest {
            operation: operation::REBOOT,
            session_id: session_id(),
            sequence: 1,
            operation_id: [0; limits::OPERATION_ID_SIZE],
            payload: [0; limits::REQUEST_PAYLOAD_SIZE],
            tag: [0; limits::ENVELOPE_TAG_SIZE],
        };
        assert_eq!(
            AuthenticatedRequest::decode(&mutation.encode()),
            Err(CodecError::MissingOperationId)
        );

        let read = AuthenticatedRequest {
            operation: operation::GET_STATUS,
            operation_id: operation_id(),
            ..mutation
        };
        assert_eq!(
            AuthenticatedRequest::decode(&read.encode()),
            Err(CodecError::UnexpectedOperationId)
        );
    }

    #[test]
    fn malformed_envelope_headers_fail_closed() {
        let valid = AuthenticatedRequest {
            operation: operation::GET_STATUS,
            session_id: session_id(),
            sequence: 1,
            operation_id: [0; limits::OPERATION_ID_SIZE],
            payload: [0; limits::REQUEST_PAYLOAD_SIZE],
            tag: [0; limits::ENVELOPE_TAG_SIZE],
        }
        .encode();

        assert_eq!(
            AuthenticatedRequest::decode(&valid[..63]),
            Err(CodecError::BadLength(63))
        );
        let mut malformed = valid;
        malformed[0] |= RESPONSE_BIT;
        assert_eq!(
            AuthenticatedRequest::decode(&malformed),
            Err(CodecError::UnexpectedResponseBit)
        );
        malformed = valid;
        malformed[0] = 0x7f;
        assert_eq!(
            AuthenticatedRequest::decode(&malformed),
            Err(CodecError::UnsupportedOperation(0x7f))
        );
        malformed = valid;
        malformed[1] = 2;
        assert_eq!(
            AuthenticatedRequest::decode(&malformed),
            Err(CodecError::UnsupportedVersion(2))
        );
        malformed = valid;
        malformed[10..14].fill(0);
        assert_eq!(
            AuthenticatedRequest::decode(&malformed),
            Err(CodecError::ZeroSequence)
        );
    }

    #[test]
    fn typed_status_pages_decode_the_fixed_payloads() {
        let request = status_request_payload(status_page::DEVICE).expect("known page");
        assert_eq!(request[0], status_page::DEVICE);
        assert!(all_zero(&request[1..]));
        assert_eq!(
            status_request_payload(0x7F),
            Err(StatusPageError::UnsupportedPage(0x7F))
        );

        let mut device = [0; limits::RESPONSE_PAYLOAD_SIZE];
        device[..12].copy_from_slice(&[
            limits::STATUS_SCHEMA,
            output_mode::USB_HID,
            output_mode::BLE_HID,
            1,
            b'7',
            b'D',
            b'9',
            b'8',
            b'7',
            b'C',
            b'6',
            b'5',
        ]);
        device[12..16].copy_from_slice(&0x0080_0041_u32.to_le_bytes());
        assert_eq!(
            decode_status_page(status_page::DEVICE, &device),
            Ok(StatusPage::Device(DeviceStatus {
                active_output_mode: output_mode::USB_HID,
                stored_output_mode: output_mode::BLE_HID,
                board_compatibility_id: 1,
                release: *b"7D987C65",
                capabilities: 0x0080_0041,
            }))
        );

        let mut safety = [0; limits::RESPONSE_PAYLOAD_SIZE];
        safety[0] = limits::STATUS_SCHEMA;
        safety[1] = 0xB9;
        safety[4..8].copy_from_slice(&17_u32.to_le_bytes());
        assert_eq!(
            decode_status_page(status_page::SAFETY, &safety),
            Ok(StatusPage::Safety(SafetyStatus {
                maintenance_active: true,
                command_active: false,
                armed: false,
                usb_mounted: true,
                keyboard_neutral: true,
                mouse_neutral: true,
                restart_pending: false,
                receipt_storage_healthy: true,
                usb_attachment_generation: 17,
            }))
        );

        let mut network = [0; limits::RESPONSE_PAYLOAD_SIZE];
        network[..8].copy_from_slice(&[limits::STATUS_SCHEMA, 14, 1, 0x1F, 2, 3, 4, 0]);
        network[8..12].copy_from_slice(&(-7_i32).to_le_bytes());
        network[12..16].copy_from_slice(&11_i32.to_le_bytes());
        assert_eq!(
            decode_status_page(status_page::NETWORK, &network),
            Ok(StatusPage::Network(NetworkStatus {
                wifi_stage: 14,
                active_path: 1,
                running: true,
                wifi_available: true,
                ble_available: true,
                endpoint_authenticated: true,
                configuration_valid: true,
                wifi_profile_count: 2,
                paired_host_count: 3,
                policy_state: 4,
                wifi_error: -7,
                nvs_error: 11,
            }))
        );

        let mut ble = [0; limits::RESPONSE_PAYLOAD_SIZE];
        ble[..4].copy_from_slice(&[limits::STATUS_SCHEMA, bond_state::SINGLE, 7, 0x1F]);
        ble[4..8].copy_from_slice(&(-2_i32).to_le_bytes());
        ble[8..12].copy_from_slice(&9_u32.to_le_bytes());
        assert!(matches!(
            decode_status_page(status_page::BLE_HID, &ble),
            Ok(StatusPage::BleHid(BleHidStatus {
                bond_state: bond_state::SINGLE,
                peripheral_stage: 7,
                ready: true,
                error: -2,
                generation: 9,
                ..
            }))
        ));

        let mut policy = [0; limits::RESPONSE_PAYLOAD_SIZE];
        policy[0] = limits::STATUS_SCHEMA;
        policy[1] = 4;
        policy[8..16].copy_from_slice(&77_u64.to_le_bytes());
        assert_eq!(
            decode_status_page(status_page::POLICY, &policy),
            Ok(StatusPage::Policy(PolicyStatus {
                state: 4,
                sequence: 77,
            }))
        );

        let mut receipt = [0; limits::RESPONSE_PAYLOAD_SIZE];
        receipt[..7].copy_from_slice(&[
            limits::STATUS_SCHEMA,
            receipt_state::COMMITTED,
            operation::REBOOT,
            status::OK,
            0x02,
            0,
            0,
        ]);
        assert!(matches!(
            decode_status_page(status_page::LAST_RECEIPT, &receipt),
            Ok(StatusPage::LastReceipt(Some(ReceiptStatus {
                state: receipt_state::COMMITTED,
                operation: operation::REBOOT,
                result: status::OK,
                flags: 0x02,
                argument: 0,
            })))
        ));
    }

    #[test]
    fn typed_status_pages_reject_unknown_or_noncanonical_data() {
        let mut payload = [0; limits::RESPONSE_PAYLOAD_SIZE];
        payload[0] = 2;
        assert_eq!(
            decode_status_page(status_page::DEVICE, &payload),
            Err(StatusPageError::UnsupportedSchema(2))
        );
        payload[0] = limits::STATUS_SCHEMA;
        payload[1] = 1;
        payload[2] = 1;
        payload[3] = 1;
        payload[4..12].copy_from_slice(&[b'A', 0, b'B', 0, 0, 0, 0, 0]);
        assert_eq!(
            decode_status_page(status_page::DEVICE, &payload),
            Err(StatusPageError::InvalidRelease)
        );
        payload = [0; limits::RESPONSE_PAYLOAD_SIZE];
        payload[0] = limits::STATUS_SCHEMA;
        payload[8] = 1;
        assert_eq!(
            decode_status_page(status_page::SAFETY, &payload),
            Err(StatusPageError::NonzeroReserved)
        );
        assert_eq!(
            decode_status_page(0x7F, &payload),
            Err(StatusPageError::UnsupportedPage(0x7F))
        );
    }

    #[test]
    fn probe_pages_decode_exact_cross_language_vectors_and_reject_malformed() {
        let run = [1, 0x34, 0x12, 5, 4, 3, 2, 1, 3, 1, 2, 1, 2, 1, 0, 0];
        assert_eq!(
            decode_status_page(status_page::PROBE_RUN, &run),
            Ok(StatusPage::ProbeRun(ProbeRunStatus {
                sample_sequence: 0x1234,
                phase: 5,
                uptime_seconds: 0x01020304,
                held_flags: 3,
                first_outcome: 1,
                second_outcome: 2,
                transport_running: true,
                link_path: 2,
                output_mode: 1,
            }))
        );
        let heap = [
            1, 0x34, 0x12, 0, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xCC, 0xBB, 0xAA,
            0x99,
        ];
        assert_eq!(
            decode_status_page(status_page::PROBE_HEAP, &heap),
            Ok(StatusPage::ProbeHeap(ProbeHeapStatus {
                sample_sequence: 0x1234,
                free_bytes: 0x11223344,
                largest_bytes: 0x55667788,
                minimum_bytes: 0x99AABBCC,
            }))
        );
        let stack = [
            1, 0x34, 0x12, 0, 0x40, 0x30, 0x20, 0x10, 0x80, 0x70, 0x60, 0x50, 0xC0, 0xB0, 0xA0,
            0x90,
        ];
        assert_eq!(
            decode_status_page(status_page::PROBE_STACK, &stack),
            Ok(StatusPage::ProbeStack(ProbeStackStatus {
                sample_sequence: 0x1234,
                main_bytes: 0x10203040,
                transport_bytes: 0x50607080,
                probe_bytes: 0x90A0B0C0,
            }))
        );
        for (page, index) in [
            (status_page::PROBE_RUN, 8),
            (status_page::PROBE_RUN, 14),
            (status_page::PROBE_HEAP, 3),
            (status_page::PROBE_STACK, 3),
        ] {
            let mut invalid = match page {
                status_page::PROBE_RUN => run,
                status_page::PROBE_HEAP => heap,
                _ => stack,
            };
            invalid[index] = 0xFF;
            assert!(decode_status_page(page, &invalid).is_err());
        }
        let mut invalid_held = run;
        invalid_held[8] = 0x04;
        assert_eq!(
            decode_status_page(status_page::PROBE_RUN, &invalid_held),
            Err(StatusPageError::InvalidValue)
        );
        let mut invalid_sequence = stack;
        invalid_sequence[1..3].fill(0);
        assert_eq!(
            decode_status_page(status_page::PROBE_STACK, &invalid_sequence),
            Err(StatusPageError::InvalidValue)
        );
        assert!(status_request_payload(status_page::PROBE_RUN).is_ok());
        assert!(status_request_payload(status_page::PROBE_HEAP).is_ok());
        assert!(status_request_payload(status_page::PROBE_STACK).is_ok());
    }

    #[test]
    fn receipt_request_and_response_shapes_are_exact() {
        let operation_id = operation_id();
        let request = receipt_request_payload(&operation_id).expect("receipt request");
        assert_eq!(&request[..16], &operation_id);
        assert!(request[16..].iter().all(|byte| *byte == 0));
        assert_eq!(
            receipt_request_payload(&[0; limits::OPERATION_ID_SIZE]),
            Err(CodecError::MissingOperationId)
        );

        let mut response = [0; limits::RESPONSE_PAYLOAD_SIZE];
        response[..6].copy_from_slice(&[
            receipt_state::COMMITTED,
            operation::SET_OUTPUT_MODE,
            status::OK,
            0x02,
            output_mode::BLE_HID,
            0,
        ]);
        assert_eq!(
            decode_receipt_payload(&response),
            Ok(ReceiptStatus {
                state: receipt_state::COMMITTED,
                operation: operation::SET_OUTPUT_MODE,
                result: status::OK,
                flags: 0x02,
                argument: output_mode::BLE_HID as u16,
            })
        );
        response[15] = 1;
        assert_eq!(
            decode_receipt_payload(&response),
            Err(StatusPageError::NonzeroReserved)
        );
    }
}
