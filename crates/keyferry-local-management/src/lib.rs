#![deny(unsafe_code)]

use hmac::{Hmac, Mac};
use keyferry_protocol::{
    capability,
    local_management::{
        self, AuthenticatedRequest, AuthenticatedResponse, OperationId, ReceiptStatus, Report,
        RequestPayload, ResponsePayload, SessionId, StatusPage,
    },
    local_management_operation as operation, local_management_registry as limits,
    local_management_status as status, output_mode,
};
use sha2::Sha256;
use std::{fmt, thread, time::Duration};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

pub const USB_VENDOR_ID: u16 = 0x303a;
pub const USB_HID_PRODUCT_ID: u16 = 0x4004;
pub const BLE_CONTROL_PRODUCT_ID: u16 = 0x4005;
pub const USB_HID_FILE_PRODUCT_ID: u16 = 0x4008;
pub const BLE_CONTROL_FILE_PRODUCT_ID: u16 = 0x4009;
pub const USB_HID_MANAGEMENT_INTERFACE: i32 = 1;
pub const BLE_CONTROL_MANAGEMENT_INTERFACE: i32 = 0;
pub const MANAGEMENT_USAGE_PAGE: u16 = 0xff00;
pub const MANAGEMENT_USAGE: u16 = 0x0001;
pub const REPORT_TIMEOUT: Duration = Duration::from_secs(5);
pub const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(50);
pub const RECEIPT_POLL_ATTEMPTS: usize = 50;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    BeforeWrite,
    AfterWrite,
}

pub trait ReportTransport {
    fn exchange(&mut self, request: &Report, timeout: Duration) -> Result<Report, TransportError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidAuthority,
    RandomUnavailable,
    TransportBeforeWrite,
    TransportAfterWrite,
    UncertainMutation {
        operation: u8,
        operation_id: OperationId,
    },
    Codec,
    IdentityMismatch,
    CapabilityMissing,
    DeviceRejected(u8),
    AuthenticationFailed,
    ResponseMismatch,
    ResponseAuthenticationFailed,
    SequenceExhausted,
    ReconciliationTimeout,
    SnapshotChanged,
}

impl Error {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidAuthority => "local.invalid_authority",
            Self::RandomUnavailable => "local.random_unavailable",
            Self::TransportBeforeWrite => "local.transport_before_write",
            Self::TransportAfterWrite => "local.transport_after_write",
            Self::UncertainMutation { .. } => "local.mutation_uncertain",
            Self::Codec => "local.protocol_invalid",
            Self::IdentityMismatch => "local.identity_mismatch",
            Self::CapabilityMissing => "local.capability_missing",
            Self::DeviceRejected(_) => "local.device_rejected",
            Self::AuthenticationFailed => "local.authentication_failed",
            Self::ResponseMismatch => "local.response_mismatch",
            Self::ResponseAuthenticationFailed => "local.response_authentication_failed",
            Self::SequenceExhausted => "local.sequence_exhausted",
            Self::ReconciliationTimeout => "local.reconciliation_timeout",
            Self::SnapshotChanged => "local.snapshot_changed",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str((*self).code())
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub status: u8,
    pub flags: u8,
    pub payload: ResponsePayload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationResult {
    pub operation_id: OperationId,
    pub status: u8,
    pub envelope_flags: u8,
    pub receipt: Option<ReceiptStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeSnapshot {
    pub run: local_management::ProbeRunStatus,
    pub heap: local_management::ProbeHeapStatus,
    pub stack: local_management::ProbeStackStatus,
}

pub struct Client<T: ReportTransport> {
    transport: T,
    session_id: SessionId,
    session_key: [u8; 32],
    device_id: [u8; 16],
    capabilities: u32,
    sequence: u32,
    usable: bool,
}

impl<T: ReportTransport> Client<T> {
    pub fn connect(
        transport: T,
        expected_device_id: [u8; 16],
        recovery_secret: &[u8; 32],
    ) -> Result<Self, Error> {
        let mut host_nonce = [0_u8; limits::HOST_NONCE_SIZE];
        getrandom::fill(&mut host_nonce).map_err(|_| Error::RandomUnavailable)?;
        if host_nonce.iter().all(|byte| *byte == 0) {
            return Err(Error::RandomUnavailable);
        }
        Self::connect_with_nonce(transport, expected_device_id, recovery_secret, host_nonce)
    }

    fn connect_with_nonce(
        mut transport: T,
        expected_device_id: [u8; 16],
        recovery_secret: &[u8; 32],
        host_nonce: [u8; limits::HOST_NONCE_SIZE],
    ) -> Result<Self, Error> {
        if expected_device_id.iter().all(|byte| *byte == 0)
            || recovery_secret.iter().all(|byte| *byte == 0)
            || host_nonce.iter().all(|byte| *byte == 0)
        {
            return Err(Error::InvalidAuthority);
        }

        let challenge_report = exchange(&mut transport, &local_management::challenge_request())?;
        let challenge = local_management::decode_challenge_response(&challenge_report)
            .map_err(|_| Error::Codec)?;
        if challenge.status != status::OK {
            return Err(Error::DeviceRejected(challenge.status));
        }
        if challenge.device_id != expected_device_id {
            return Err(Error::IdentityMismatch);
        }
        if challenge.capabilities & capability::LOCAL_MANAGEMENT_V1 == 0 {
            return Err(Error::CapabilityMissing);
        }

        let admin_key = Zeroizing::new(mac(
            recovery_secret,
            &[limits::ADMIN_KEY_DOMAIN, expected_device_id.as_slice()],
        )?);
        let version = [limits::VERSION];
        let transcript = [
            limits::AUTHENTICATION_DOMAIN,
            version.as_slice(),
            expected_device_id.as_slice(),
            challenge.device_nonce.as_slice(),
            challenge.session_id.as_slice(),
            host_nonce.as_slice(),
        ];
        let host_proof = Zeroizing::new(mac(&admin_key[..], &transcript)?);
        let mut session_key_parts = Vec::with_capacity(transcript.len() + 1);
        session_key_parts.push(limits::SESSION_KEY_DOMAIN);
        session_key_parts.extend_from_slice(&transcript);
        let session_key = Zeroizing::new(mac(&admin_key[..], &session_key_parts)?);

        let authenticate = local_management::AuthenticateRequest {
            session_id: challenge.session_id,
            host_nonce,
            proof: *host_proof,
        };
        let authenticate_report = exchange(&mut transport, &authenticate.encode())?;
        let authenticated = local_management::decode_authenticate_response(&authenticate_report)
            .map_err(|_| Error::Codec)?;
        if authenticated.status != status::OK {
            return Err(Error::AuthenticationFailed);
        }
        if authenticated.session_id != challenge.session_id {
            return Err(Error::ResponseMismatch);
        }
        let expected_proof = Zeroizing::new(mac(
            &session_key[..],
            &[limits::DEVICE_PROOF_DOMAIN]
                .into_iter()
                .chain(transcript.iter().copied())
                .collect::<Vec<_>>(),
        )?);
        if !equal_constant_time(&expected_proof[..], &authenticated.proof) {
            return Err(Error::AuthenticationFailed);
        }

        Ok(Self {
            transport,
            session_id: challenge.session_id,
            session_key: *session_key,
            device_id: expected_device_id,
            capabilities: challenge.capabilities,
            sequence: 0,
            usable: true,
        })
    }

    #[must_use]
    pub const fn device_id(&self) -> [u8; 16] {
        self.device_id
    }

    #[must_use]
    pub const fn capabilities(&self) -> u32 {
        self.capabilities
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn status(&mut self, page: u8) -> Result<StatusPage, Error> {
        let payload = local_management::status_request_payload(page).map_err(|_| Error::Codec)?;
        let response = self.request(operation::GET_STATUS, [0; 16], payload)?;
        if response.status != status::OK {
            return Err(Error::DeviceRejected(response.status));
        }
        local_management::decode_status_page(page, &response.payload).map_err(|_| Error::Codec)
    }

    /// Read metadata only. Retry a changed sample, never a failed exchange.
    pub fn probe_snapshot(&mut self) -> Result<ProbeSnapshot, Error> {
        use keyferry_protocol::local_management_status_page as page;
        for _ in 0..4 {
            let StatusPage::ProbeRun(run) = self.status(page::PROBE_RUN)? else {
                return Err(Error::Codec);
            };
            let StatusPage::ProbeHeap(heap) = self.status(page::PROBE_HEAP)? else {
                return Err(Error::Codec);
            };
            let StatusPage::ProbeStack(stack) = self.status(page::PROBE_STACK)? else {
                return Err(Error::Codec);
            };
            if run.sample_sequence == heap.sample_sequence
                && run.sample_sequence == stack.sample_sequence
            {
                return Ok(ProbeSnapshot { run, heap, stack });
            }
        }
        Err(Error::SnapshotChanged)
    }

    pub fn receipt(&mut self, operation_id: OperationId) -> Result<Option<ReceiptStatus>, Error> {
        let payload =
            local_management::receipt_request_payload(&operation_id).map_err(|_| Error::Codec)?;
        let response = self.request(operation::GET_RECEIPT, [0; 16], payload)?;
        if response.status == status::OPERATION_UNKNOWN {
            return Ok(None);
        }
        let receipt = local_management::decode_receipt_payload(&response.payload)
            .map_err(|_| Error::Codec)?;
        if response.status != receipt_status(&receipt) {
            return Err(Error::ResponseMismatch);
        }
        Ok(Some(receipt))
    }

    pub fn mutate(&mut self, mutation: u8, argument: Option<u8>) -> Result<MutationResult, Error> {
        self.mutate_with_id(mutation, argument, generate_operation_id()?)
    }

    pub fn mutate_with_id(
        &mut self,
        mutation: u8,
        argument: Option<u8>,
        operation_id: OperationId,
    ) -> Result<MutationResult, Error> {
        if !matches!(
            mutation,
            operation::OPEN_MAINTENANCE
                | operation::CLOSE_MAINTENANCE
                | operation::RESTART_NETWORK
                | operation::CLEAR_BLE_BOND_AND_ENROLL
                | operation::CANCEL_ENROLLMENT
                | operation::SET_OUTPUT_MODE
                | operation::REBOOT
        ) {
            return Err(Error::Codec);
        }
        if operation_id.iter().all(|byte| *byte == 0) {
            return Err(Error::Codec);
        }
        let mut payload = [0; limits::REQUEST_PAYLOAD_SIZE];
        match (mutation, argument) {
            (operation::SET_OUTPUT_MODE, Some(value))
                if matches!(value, output_mode::USB_HID | output_mode::BLE_HID) =>
            {
                payload[0] = value;
            }
            (operation::SET_OUTPUT_MODE, _) => return Err(Error::Codec),
            (_, None) => {}
            (_, Some(_)) => return Err(Error::Codec),
        }
        let response = match self.request(mutation, operation_id, payload) {
            Ok(response) => response,
            Err(Error::TransportAfterWrite) => {
                return Err(Error::UncertainMutation {
                    operation: mutation,
                    operation_id,
                });
            }
            Err(error) => return Err(error),
        };
        let receipt = if matches!(response.status, status::OK | status::IN_PROGRESS)
            || response.payload.iter().any(|byte| *byte != 0)
        {
            let receipt = local_management::decode_receipt_payload(&response.payload)
                .map_err(|_| Error::Codec)?;
            if response.status != receipt_status(&receipt) {
                return Err(Error::ResponseMismatch);
            }
            Some(receipt)
        } else {
            None
        };
        Ok(MutationResult {
            operation_id,
            status: response.status,
            envelope_flags: response.flags,
            receipt,
        })
    }

    pub fn mutate_and_reconcile_with_id(
        &mut self,
        mutation: u8,
        argument: Option<u8>,
        operation_id: OperationId,
    ) -> Result<MutationResult, Error> {
        let mut result = self.mutate_with_id(mutation, argument, operation_id)?;
        for _ in 0..RECEIPT_POLL_ATTEMPTS {
            let Some(receipt) = result.receipt.as_ref() else {
                return Ok(result);
            };
            if receipt.state != keyferry_protocol::local_management_receipt_state::IN_PROGRESS {
                return Ok(result);
            }
            thread::sleep(RECEIPT_POLL_INTERVAL);
            let receipt = self.receipt(operation_id)?.ok_or(Error::ResponseMismatch)?;
            result.status = receipt_status(&receipt);
            result.receipt = Some(receipt);
        }
        Err(Error::ReconciliationTimeout)
    }

    fn request(
        &mut self,
        request_operation: u8,
        operation_id: OperationId,
        payload: RequestPayload,
    ) -> Result<Response, Error> {
        if !self.usable {
            return Err(Error::ResponseMismatch);
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        if self.sequence == 0 {
            return Err(Error::SequenceExhausted);
        }
        let mut request = AuthenticatedRequest {
            operation: request_operation,
            session_id: self.session_id,
            sequence: self.sequence,
            operation_id,
            payload,
            tag: [0; limits::ENVELOPE_TAG_SIZE],
        };
        let signing = request.signing_bytes();
        let tag = mac(&self.session_key, &[limits::REQUEST_DOMAIN, &signing[..48]])?;
        request
            .tag
            .copy_from_slice(&tag[..limits::ENVELOPE_TAG_SIZE]);
        let response_report = match self.transport.exchange(&request.encode(), REPORT_TIMEOUT) {
            Ok(response) => response,
            Err(TransportError::BeforeWrite) => {
                self.usable = false;
                return Err(Error::TransportBeforeWrite);
            }
            Err(TransportError::AfterWrite) => {
                self.usable = false;
                return Err(Error::TransportAfterWrite);
            }
        };
        let response = AuthenticatedResponse::decode(&response_report).map_err(|_| {
            self.usable = false;
            Error::Codec
        })?;
        if response.operation != request_operation
            || response.session_id != self.session_id
            || response.sequence != self.sequence
            || response.operation_id != operation_id
        {
            self.usable = false;
            return Err(Error::ResponseMismatch);
        }
        if response.flags & !0x03 != 0 {
            self.usable = false;
            return Err(Error::Codec);
        }
        let signing = response.signing_bytes();
        let expected = mac(
            &self.session_key,
            &[limits::RESPONSE_DOMAIN, &signing[..48]],
        )?;
        if !equal_constant_time(&expected[..limits::ENVELOPE_TAG_SIZE], &response.tag) {
            self.usable = false;
            return Err(Error::ResponseAuthenticationFailed);
        }
        Ok(Response {
            status: response.status,
            flags: response.flags,
            payload: response.payload,
        })
    }
}

impl<T: ReportTransport> Drop for Client<T> {
    fn drop(&mut self) {
        self.session_key.zeroize();
        self.session_id.zeroize();
    }
}

fn exchange<T: ReportTransport>(transport: &mut T, request: &Report) -> Result<Report, Error> {
    match transport.exchange(request, REPORT_TIMEOUT) {
        Ok(response) => Ok(response),
        Err(TransportError::BeforeWrite) => Err(Error::TransportBeforeWrite),
        Err(TransportError::AfterWrite) => Err(Error::TransportAfterWrite),
    }
}

fn mac(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], Error> {
    let mut calculator = HmacSha256::new_from_slice(key).map_err(|_| Error::InvalidAuthority)?;
    for part in parts {
        calculator.update(part);
    }
    Ok(calculator.finalize().into_bytes().into())
}

fn equal_constant_time(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

pub fn generate_operation_id() -> Result<OperationId, Error> {
    let mut operation_id = [0_u8; limits::OPERATION_ID_SIZE];
    getrandom::fill(&mut operation_id).map_err(|_| Error::RandomUnavailable)?;
    if operation_id.iter().all(|byte| *byte == 0) {
        return Err(Error::RandomUnavailable);
    }
    Ok(operation_id)
}

fn receipt_status(receipt: &ReceiptStatus) -> u8 {
    if receipt.state == keyferry_protocol::local_management_receipt_state::IN_PROGRESS {
        status::IN_PROGRESS
    } else {
        receipt.result
    }
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub mod hid {
    use super::*;

    pub struct HidTransport {
        _api: hidapi::HidApi,
        device: hidapi::HidDevice,
    }

    impl HidTransport {
        pub fn open(device_id: &[u8; 16]) -> Result<Self, Error> {
            let api = hidapi::HidApi::new().map_err(|_| Error::TransportBeforeWrite)?;
            let matches = api
                .device_list()
                .filter(|info| {
                    is_management_interface(
                        info.vendor_id(),
                        info.product_id(),
                        info.interface_number(),
                        info.usage_page(),
                        info.usage(),
                    ) && info
                        .serial_number()
                        .is_some_and(|serial| serial_matches_device_id(serial, device_id))
                })
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(Error::IdentityMismatch);
            }
            let device = matches[0]
                .open_device(&api)
                .map_err(|_| Error::TransportBeforeWrite)?;
            Ok(Self { _api: api, device })
        }
    }

    pub fn unique_present_device_id(known_device_ids: &[[u8; 16]]) -> Result<[u8; 16], Error> {
        let api = hidapi::HidApi::new().map_err(|_| Error::TransportBeforeWrite)?;
        let serials = api
            .device_list()
            .filter(|info| {
                is_management_interface(
                    info.vendor_id(),
                    info.product_id(),
                    info.interface_number(),
                    info.usage_page(),
                    info.usage(),
                )
            })
            .filter_map(|info| info.serial_number())
            .collect::<Vec<_>>();
        unique_matching_device_id(known_device_ids, &serials).ok_or(Error::IdentityMismatch)
    }

    pub(crate) fn unique_matching_device_id(
        known_device_ids: &[[u8; 16]],
        serials: &[&str],
    ) -> Option<[u8; 16]> {
        let mut matches = known_device_ids.iter().copied().filter(|device_id| {
            serials
                .iter()
                .any(|serial| serial_matches_device_id(serial, device_id))
        });
        let selected = matches.next()?;
        matches.next().is_none().then_some(selected)
    }

    impl ReportTransport for HidTransport {
        fn exchange(
            &mut self,
            request: &Report,
            timeout: Duration,
        ) -> Result<Report, TransportError> {
            let mut wire = [0_u8; limits::REPORT_SIZE + 1];
            wire[1..].copy_from_slice(request);
            match self.device.write(&wire) {
                Ok(length) if length == wire.len() => {}
                Ok(_) => return Err(TransportError::AfterWrite),
                Err(_) => return Err(TransportError::BeforeWrite),
            }
            let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
            let mut response = [0_u8; limits::REPORT_SIZE];
            match self.device.read_timeout(&mut response, timeout_ms) {
                Ok(length) if length == response.len() => Ok(response),
                Ok(_) | Err(_) => Err(TransportError::AfterWrite),
            }
        }
    }

    #[must_use]
    pub fn is_management_interface(
        vendor_id: u16,
        product_id: u16,
        interface_number: i32,
        usage_page: u16,
        usage: u16,
    ) -> bool {
        let product_and_interface = ((product_id == USB_HID_PRODUCT_ID
            || product_id == USB_HID_FILE_PRODUCT_ID)
            && interface_number == USB_HID_MANAGEMENT_INTERFACE)
            || ((product_id == BLE_CONTROL_PRODUCT_ID
                || product_id == BLE_CONTROL_FILE_PRODUCT_ID)
                && interface_number == BLE_CONTROL_MANAGEMENT_INTERFACE);
        vendor_id == USB_VENDOR_ID
            && product_and_interface
            && usage_page == MANAGEMENT_USAGE_PAGE
            && usage == MANAGEMENT_USAGE
    }

    #[must_use]
    pub fn serial_matches_device_id(serial: &str, device_id: &[u8; 16]) -> bool {
        let expected = device_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        serial.eq_ignore_ascii_case(&expected)
            || (serial.len() == 31 && expected[..31].eq_ignore_ascii_case(serial))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyferry_protocol::{local_management_status_page as status_page, output_mode};

    const DEVICE_ID: [u8; 16] = [0x11; 16];
    const RECOVERY_SECRET: [u8; 32] = [0x22; 32];
    const HOST_NONCE: [u8; 16] = [0x33; 16];
    const DEVICE_NONCE: [u8; 32] = [0x44; 32];
    const SESSION_ID: [u8; 8] = [0x55; 8];

    #[derive(Clone, Copy)]
    enum FinalStep {
        DeviceStatus,
        AfterWrite,
        InProgressThenCommitted,
    }

    struct ScriptedTransport {
        step: u8,
        final_step: FinalStep,
    }

    impl ScriptedTransport {
        fn new(final_step: FinalStep) -> Self {
            Self {
                step: 0,
                final_step,
            }
        }
    }

    impl ReportTransport for ScriptedTransport {
        fn exchange(
            &mut self,
            request: &Report,
            timeout: Duration,
        ) -> Result<Report, TransportError> {
            assert_eq!(timeout, REPORT_TIMEOUT);
            self.step += 1;
            match self.step {
                1 => {
                    assert_eq!(*request, local_management::challenge_request());
                    let mut response = [0; limits::REPORT_SIZE];
                    response[0] = operation::CHALLENGE | 0x80;
                    response[1] = status::OK;
                    response[2] = limits::VERSION;
                    response[3..7].copy_from_slice(&capability::LOCAL_MANAGEMENT_V1.to_le_bytes());
                    response[7..23].copy_from_slice(&DEVICE_ID);
                    response[23..55].copy_from_slice(&DEVICE_NONCE);
                    response[55..63].copy_from_slice(&SESSION_ID);
                    Ok(response)
                }
                2 => {
                    let decoded = local_management::AuthenticateRequest::decode(request)
                        .expect("authenticate request");
                    assert_eq!(decoded.session_id, SESSION_ID);
                    assert_eq!(decoded.host_nonce, HOST_NONCE);
                    assert_eq!(
                        decoded.proof,
                        hex_array(
                            "1a654845ed0508e387254405623c3fa176c5c236223a9a63dcb0b17094d19acd"
                        )
                    );
                    let mut response = [0; limits::REPORT_SIZE];
                    response[0] = operation::AUTHENTICATE | 0x80;
                    response[1] = status::OK;
                    response[2] = limits::VERSION;
                    response[4..12].copy_from_slice(&SESSION_ID);
                    response[12..44].copy_from_slice(&hex_array::<32>(
                        "b1a4a445dc8a4c9d7c44ef341ca897babec6819ba394ff9a809be5a961a64922",
                    ));
                    Ok(response)
                }
                3 => match self.final_step {
                    FinalStep::AfterWrite => Err(TransportError::AfterWrite),
                    FinalStep::InProgressThenCommitted => {
                        let decoded = AuthenticatedRequest::decode(request)
                            .expect("open-maintenance request");
                        assert_eq!(decoded.operation, operation::OPEN_MAINTENANCE);
                        let mut payload = [0; limits::RESPONSE_PAYLOAD_SIZE];
                        payload[..3].copy_from_slice(&[
                            keyferry_protocol::local_management_receipt_state::IN_PROGRESS,
                            operation::OPEN_MAINTENANCE,
                            status::IN_PROGRESS,
                        ]);
                        Ok(signed_response(&decoded, status::IN_PROGRESS, 0, payload))
                    }
                    FinalStep::DeviceStatus => {
                        let decoded =
                            AuthenticatedRequest::decode(request).expect("authenticated request");
                        assert_eq!(decoded.operation, operation::GET_STATUS);
                        assert_eq!(decoded.session_id, SESSION_ID);
                        assert_eq!(decoded.sequence, 1);
                        assert_eq!(decoded.operation_id, [0; 16]);
                        assert_eq!(decoded.payload[0], status_page::DEVICE);
                        let signing = decoded.signing_bytes();
                        let expected =
                            mac(&session_key(), &[limits::REQUEST_DOMAIN, &signing[..48]])
                                .expect("request tag");
                        assert_eq!(decoded.tag, expected[..16]);

                        let mut payload = [0; limits::RESPONSE_PAYLOAD_SIZE];
                        payload[0] = limits::STATUS_SCHEMA;
                        payload[1] = output_mode::USB_HID;
                        payload[2] = output_mode::BLE_HID;
                        payload[3] = 1;
                        payload[4..9].copy_from_slice(b"0.1.0");
                        payload[12..16]
                            .copy_from_slice(&capability::LOCAL_MANAGEMENT_V1.to_le_bytes());
                        let mut response = AuthenticatedResponse {
                            operation: operation::GET_STATUS,
                            status: status::OK,
                            flags: 0,
                            session_id: SESSION_ID,
                            sequence: 1,
                            operation_id: [0; 16],
                            payload,
                            tag: [0; 16],
                        };
                        let signing = response.signing_bytes();
                        let tag = mac(&session_key(), &[limits::RESPONSE_DOMAIN, &signing[..48]])
                            .expect("response tag");
                        response.tag.copy_from_slice(&tag[..16]);
                        Ok(response.encode())
                    }
                },
                4 if matches!(self.final_step, FinalStep::InProgressThenCommitted) => {
                    let decoded = AuthenticatedRequest::decode(request).expect("receipt request");
                    assert_eq!(decoded.operation, operation::GET_RECEIPT);
                    assert_eq!(decoded.sequence, 2);
                    assert_eq!(&decoded.payload[..16], &[0x77; 16]);
                    let mut payload = [0; limits::RESPONSE_PAYLOAD_SIZE];
                    payload[..3].copy_from_slice(&[
                        keyferry_protocol::local_management_receipt_state::COMMITTED,
                        operation::OPEN_MAINTENANCE,
                        status::OK,
                    ]);
                    Ok(signed_response(&decoded, status::OK, 0x01, payload))
                }
                _ => panic!("unexpected exchange"),
            }
        }
    }

    fn signed_response(
        request: &AuthenticatedRequest,
        response_status: u8,
        flags: u8,
        payload: ResponsePayload,
    ) -> Report {
        let mut response = AuthenticatedResponse {
            operation: request.operation,
            status: response_status,
            flags,
            session_id: request.session_id,
            sequence: request.sequence,
            operation_id: request.operation_id,
            payload,
            tag: [0; 16],
        };
        let signing = response.signing_bytes();
        let tag =
            mac(&session_key(), &[limits::RESPONSE_DOMAIN, &signing[..48]]).expect("response tag");
        response.tag.copy_from_slice(&tag[..16]);
        response.encode()
    }

    fn session_key() -> [u8; 32] {
        hex_array("8fc94fb75cb1ab40ba9f00f6a0d5ae60decd5f8d737efa9ad4c1f4b1781075bc")
    }

    struct ProbeTransport {
        handshake: ScriptedTransport,
        reads: usize,
        changing_groups: usize,
        rejection: Option<u8>,
        failed_exchange: bool,
    }

    impl ReportTransport for ProbeTransport {
        fn exchange(
            &mut self,
            request: &Report,
            timeout: Duration,
        ) -> Result<Report, TransportError> {
            if self.handshake.step < 2 {
                return self.handshake.exchange(request, timeout);
            }
            let decoded = AuthenticatedRequest::decode(request).expect("probe request");
            assert_eq!(decoded.operation, operation::GET_STATUS);
            assert_eq!(decoded.operation_id, [0; 16]);
            assert!(decoded.payload[1..].iter().all(|byte| *byte == 0));
            let page_index = self.reads % 3;
            assert_eq!(
                decoded.payload[0],
                [
                    status_page::PROBE_RUN,
                    status_page::PROBE_HEAP,
                    status_page::PROBE_STACK
                ][page_index]
            );
            let group = self.reads / 3;
            self.reads += 1;
            if self.failed_exchange {
                return Err(TransportError::AfterWrite);
            }
            let mut payload = [0; limits::RESPONSE_PAYLOAD_SIZE];
            if let Some(rejection) = self.rejection {
                return Ok(signed_response(&decoded, rejection, 0, payload));
            }
            payload[0] = limits::STATUS_SCHEMA;
            let sequence: u16 = if group < self.changing_groups && page_index == 0 {
                1
            } else {
                2
            };
            payload[1..3].copy_from_slice(&sequence.to_le_bytes());
            if page_index == 0 {
                payload[3] = keyferry_protocol::local_management_probe_phase::RELEASED;
                payload[4..8].copy_from_slice(&61_u32.to_le_bytes());
                payload[9] = 1;
                payload[10] = 2;
                payload[11] = 1;
                payload[12] = 1;
                payload[13] = output_mode::USB_HID;
            } else {
                payload[4..8].copy_from_slice(&80_123_u32.to_le_bytes());
                payload[8..12].copy_from_slice(&70_011_u32.to_le_bytes());
                payload[12..16].copy_from_slice(&33_001_u32.to_le_bytes());
            }
            Ok(signed_response(&decoded, status::OK, 0, payload))
        }
    }

    fn probe_client(
        changing_groups: usize,
        rejection: Option<u8>,
        failed_exchange: bool,
    ) -> Client<ProbeTransport> {
        Client::connect_with_nonce(
            ProbeTransport {
                handshake: ScriptedTransport::new(FinalStep::DeviceStatus),
                reads: 0,
                changing_groups,
                rejection,
                failed_exchange,
            },
            DEVICE_ID,
            &RECOVERY_SECRET,
            HOST_NONCE,
        )
        .expect("authenticated probe client")
    }

    #[test]
    fn probe_snapshot_retries_only_incoherent_read_groups_and_preserves_exact_values() {
        let mut client = probe_client(1, None, false);
        let snapshot = client.probe_snapshot().expect("coherent second group");
        assert_eq!(client.transport.reads, 6);
        assert_eq!(snapshot.run.sample_sequence, 2);
        assert_eq!(snapshot.run.first_outcome, 1);
        assert_eq!(snapshot.run.second_outcome, 2);
        assert_eq!(snapshot.heap.free_bytes, 80_123);
        assert_eq!(snapshot.heap.minimum_bytes, 33_001);
        assert_eq!(snapshot.stack.transport_bytes, 70_011);
    }

    #[test]
    fn probe_snapshot_bounds_churn_and_does_not_retry_rejections_or_failed_exchanges() {
        let mut changing = probe_client(4, None, false);
        assert_eq!(changing.probe_snapshot(), Err(Error::SnapshotChanged));
        assert_eq!(changing.transport.reads, 12);
        let mut ordinary = probe_client(0, Some(status::UNSUPPORTED), false);
        assert_eq!(
            ordinary.probe_snapshot(),
            Err(Error::DeviceRejected(status::UNSUPPORTED))
        );
        assert_eq!(ordinary.transport.reads, 1);
        let mut lost = probe_client(0, None, true);
        assert_eq!(lost.probe_snapshot(), Err(Error::TransportAfterWrite));
        assert_eq!(lost.transport.reads, 1);
    }

    fn hex_array<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        let mut output = [0; N];
        for (index, output_byte) in output.iter_mut().enumerate() {
            *output_byte =
                u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex fixture");
        }
        output
    }

    #[test]
    fn fixed_authentication_vector_and_typed_status_round_trip() {
        let admin =
            mac(&RECOVERY_SECRET, &[limits::ADMIN_KEY_DOMAIN, &DEVICE_ID]).expect("admin key");
        assert_eq!(
            admin,
            hex_array("dd6d43a40f14c7500556c10c8c5a111b3fe641a2d8423299e78e82043cc6c18d")
        );

        let mut client = Client::connect_with_nonce(
            ScriptedTransport::new(FinalStep::DeviceStatus),
            DEVICE_ID,
            &RECOVERY_SECRET,
            HOST_NONCE,
        )
        .expect("authenticated client");
        assert_eq!(client.device_id(), DEVICE_ID);
        assert_eq!(client.capabilities(), capability::LOCAL_MANAGEMENT_V1);
        assert!(matches!(
            client.status(status_page::DEVICE),
            Ok(StatusPage::Device(local_management::DeviceStatus {
                active_output_mode: output_mode::USB_HID,
                stored_output_mode: output_mode::BLE_HID,
                board_compatibility_id: 1,
                ..
            }))
        ));
    }

    #[test]
    fn after_write_mutation_is_uncertain_and_carries_its_reconciliation_id() {
        let mut client = Client::connect_with_nonce(
            ScriptedTransport::new(FinalStep::AfterWrite),
            DEVICE_ID,
            &RECOVERY_SECRET,
            HOST_NONCE,
        )
        .expect("authenticated client");
        let error = client
            .mutate(operation::OPEN_MAINTENANCE, None)
            .expect_err("lost response must be uncertain");
        match error {
            Error::UncertainMutation {
                operation: actual,
                operation_id,
            } => {
                assert_eq!(actual, operation::OPEN_MAINTENANCE);
                assert!(operation_id.iter().any(|byte| *byte != 0));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn in_progress_mutation_is_reconciled_by_receipt_without_resubmission() {
        let mut client = Client::connect_with_nonce(
            ScriptedTransport::new(FinalStep::InProgressThenCommitted),
            DEVICE_ID,
            &RECOVERY_SECRET,
            HOST_NONCE,
        )
        .expect("authenticated client");
        let operation_id = [0x77; 16];
        let result = client
            .mutate_and_reconcile_with_id(operation::OPEN_MAINTENANCE, None, operation_id)
            .expect("reconciled mutation");
        assert_eq!(result.operation_id, operation_id);
        assert_eq!(result.status, status::OK);
        assert!(matches!(
            result.receipt,
            Some(ReceiptStatus {
                state: keyferry_protocol::local_management_receipt_state::COMMITTED,
                operation: operation::OPEN_MAINTENANCE,
                result: status::OK,
                ..
            })
        ));
    }

    #[test]
    fn hid_identity_filter_accepts_both_personalities_and_exact_serial() {
        assert!(hid::is_management_interface(
            USB_VENDOR_ID,
            USB_HID_PRODUCT_ID,
            USB_HID_MANAGEMENT_INTERFACE,
            MANAGEMENT_USAGE_PAGE,
            MANAGEMENT_USAGE,
        ));
        assert!(hid::is_management_interface(
            USB_VENDOR_ID,
            BLE_CONTROL_PRODUCT_ID,
            BLE_CONTROL_MANAGEMENT_INTERFACE,
            MANAGEMENT_USAGE_PAGE,
            MANAGEMENT_USAGE,
        ));
        for (product, interface) in [
            (USB_HID_FILE_PRODUCT_ID, USB_HID_MANAGEMENT_INTERFACE),
            (
                BLE_CONTROL_FILE_PRODUCT_ID,
                BLE_CONTROL_MANAGEMENT_INTERFACE,
            ),
        ] {
            assert!(hid::is_management_interface(
                USB_VENDOR_ID,
                product,
                interface,
                MANAGEMENT_USAGE_PAGE,
                MANAGEMENT_USAGE
            ));
            assert!(!hid::is_management_interface(
                USB_VENDOR_ID,
                product,
                interface + 1,
                MANAGEMENT_USAGE_PAGE,
                MANAGEMENT_USAGE
            ));
        }
        assert!(!hid::is_management_interface(
            USB_VENDOR_ID,
            USB_HID_PRODUCT_ID,
            0,
            MANAGEMENT_USAGE_PAGE,
            MANAGEMENT_USAGE,
        ));
        assert!(hid::serial_matches_device_id(
            "11111111111111111111111111111111",
            &DEVICE_ID,
        ));
        assert!(hid::serial_matches_device_id(
            "1111111111111111111111111111111",
            &DEVICE_ID,
        ));
        assert_eq!(
            hid::unique_matching_device_id(&[DEVICE_ID], &["1111111111111111111111111111111"]),
            Some(DEVICE_ID)
        );
        assert_eq!(
            hid::unique_matching_device_id(
                &[DEVICE_ID, [0x11; 16]],
                &["1111111111111111111111111111111"]
            ),
            None,
            "a truncated serial shared by two known identifiers is ambiguous"
        );
        assert_eq!(hid::unique_matching_device_id(&[DEVICE_ID], &[]), None);
    }
}
