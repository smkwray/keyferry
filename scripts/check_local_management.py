#!/usr/bin/env python3
"""Static gates for the bounded Local Management v1 codec foundation."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"check_local_management: {message}")


def require(source: str, tokens: tuple[str, ...], surface: str) -> None:
    for token in tokens:
        if token not in source:
            fail(f"{surface} is missing {token}")


def main() -> None:
    registry = (ROOT / "protocol/messages.yaml").read_text(encoding="utf-8")
    protocol = (ROOT / "protocol/local-management-v1.md").read_text(encoding="utf-8")
    rust = (
        ROOT / "crates/keyferry-protocol/src/local_management.rs"
    ).read_text(encoding="utf-8")
    host = (
        ROOT / "crates/keyferry-local-management/src/lib.rs"
    ).read_text(encoding="utf-8")
    cli = (ROOT / "apps/keyctl/src/main.rs").read_text(encoding="utf-8")
    helper = (
        ROOT / "tools/keyferry-pairing/src/main.rs"
    ).read_text(encoding="utf-8")
    desktop = (ROOT / "apps/keyferry/src/main.rs").read_text(encoding="utf-8")
    desktop_provisioning = (
        ROOT / "apps/keyferry/src/provisioning.rs"
    ).read_text(encoding="utf-8")
    desktop_ui = (ROOT / "apps/keyferry/ui/main.slint").read_text(encoding="utf-8")
    provisioning_host = (
        ROOT / "tools/keyferry-pairing/src/provisioning_host.rs"
    ).read_text(encoding="utf-8")
    cpp_header = (
        ROOT
        / "firmware/esp32s3/components/kf_provisioning/include/keyferry/local_management_codec.h"
    ).read_text(encoding="utf-8")
    cpp_source = (
        ROOT
        / "firmware/esp32s3/components/kf_provisioning/src/local_management_codec.cpp"
    ).read_text(encoding="utf-8")
    session_header = (
        ROOT
        / "firmware/esp32s3/components/kf_provisioning/include/keyferry/local_management.h"
    ).read_text(encoding="utf-8")
    session_source = (
        ROOT
        / "firmware/esp32s3/components/kf_provisioning/src/local_management.cpp"
    ).read_text(encoding="utf-8")
    coordinator_header = (
        ROOT
        / "firmware/esp32s3/components/kf_provisioning/include/keyferry/local_management_coordinator.h"
    ).read_text(encoding="utf-8")
    coordinator_source = (
        ROOT
        / "firmware/esp32s3/components/kf_provisioning/src/local_management_coordinator.cpp"
    ).read_text(encoding="utf-8")
    receipt_header = (
        ROOT
        / "firmware/esp32s3/components/kf_provisioning/include/keyferry/local_management_receipts.h"
    ).read_text(encoding="utf-8")
    receipt_source = (
        ROOT
        / "firmware/esp32s3/components/kf_provisioning/src/local_management_receipts.cpp"
    ).read_text(encoding="utf-8")
    idf_receipt_source = (
        ROOT
        / "firmware/esp32s3/components/kf_provisioning/src/idf_local_management_receipts.cpp"
    ).read_text(encoding="utf-8")
    status_header = (
        ROOT
        / "firmware/esp32s3/components/kf_provisioning/include/keyferry/local_management_status.h"
    ).read_text(encoding="utf-8")
    status_source = (
        ROOT
        / "firmware/esp32s3/components/kf_provisioning/src/local_management_status.cpp"
    ).read_text(encoding="utf-8")
    adapter_header = (
        ROOT / "firmware/esp32s3/hil_endpoint/main/provisioning_adapter.h"
    ).read_text(encoding="utf-8")
    adapter_source = (
        ROOT / "firmware/esp32s3/hil_endpoint/main/provisioning_adapter.cpp"
    ).read_text(encoding="utf-8")
    app_main = (
        ROOT / "firmware/esp32s3/hil_endpoint/main/app_main.cpp"
    ).read_text(encoding="utf-8")
    secure_header = (
        ROOT
        / "firmware/esp32s3/components/kf_secure_endpoint/include/keyferry/secure_endpoint.h"
    ).read_text(encoding="utf-8")
    secure_source = (
        ROOT
        / "firmware/esp32s3/components/kf_secure_endpoint/src/secure_endpoint.cpp"
    ).read_text(encoding="utf-8")
    sdkconfig = (
        ROOT / "firmware/esp32s3/hil_endpoint/sdkconfig.defaults"
    ).read_text(encoding="utf-8")

    require(
        registry,
        (
            "report_size: 64",
            "authentication_tag_size: 32",
            "envelope_tag_size: 16",
            "operation_id_size: 16",
            "request_payload_size: 18",
            "response_payload_size: 16",
            "admin_key_domain_ascii: keyferry/local-admin-key/v1",
            "request_domain_ascii: keyferry/local-request/v1",
            "response_domain_ascii: keyferry/local-response/v1",
            "name: LOCAL_MANAGEMENT_V1",
            "status_schema: 1",
        ),
        "registry",
    )
    require(
        protocol,
        (
            "side-effect-free",
            "first 16 bytes of request HMAC-SHA256",
            "exact monotonic sequence",
            "never causes blind retry",
            "cannot emit a nonzero keyboard or mouse report",
            "MULTIPLE_INVALID",
        ),
        "protocol",
    )
    require(
        rust,
        (
            "pub fn signing_bytes",
            "validate_operation_id",
            "UnexpectedOperationId",
            "MissingOperationId",
            "UnexpectedResponseBit",
            "UnsupportedOperation",
            "NonzeroReserved",
        ),
        "Rust codec",
    )
    require(
        host,
        (
            "pub trait ReportTransport",
            "pub struct Client",
            "LOCAL_MANAGEMENT_V1",
            "equal_constant_time",
            "UncertainMutation",
            "receipt_request_payload",
            "pub struct HidTransport",
            "BLE_CONTROL_MANAGEMENT_INTERFACE",
        ),
        "shared Rust local-management host",
    )
    require(
        cli + helper,
        (
            "local-status --owner-kit PATH",
            "local-recover --owner-kit PATH ACTION",
            "mutate_and_reconcile_with_id",
            "keyferry.local-recovery-attempt.v1",
            "keyferry.local-recovery-result.v1",
            "passphrase from stdin",
        ),
        "agent local-management CLI",
    )
    require(
        desktop_ui,
        (
            'title: "USB maintenance · " + root.selected-device',
            "subtitle: root.selected-device-id",
            "callback refresh-local-status()",
            "callback run-local-recovery(string)",
            'root.run-local-recovery("restart-network")',
            'root.run-local-recovery("forget-bluetooth")',
            "root.local-recovery-confirm-device-id = root.selected-device-id",
            "root.local-recovery-confirm-device-id == root.selected-device-id",
            "input-type: InputType.password",
            "These controls require this stick's USB connection on this computer.",
        ),
        "desktop selected-device USB maintenance UI",
    )
    require(
        desktop,
        (
            "provisioning::local_status",
            "provisioning::local_recover",
            "window.set_local_recovery_password(\"\".into())",
            "let device_id = window.get_selected_device_id().to_string()",
        ),
        "desktop selected-device local recovery",
    )
    require(
        desktop_provisioning,
        (
            "local_recover_args(owner_kit_text.as_ref(), device_id, action)",
            "run_helper_capture",
            "Do not repeat it automatically",
        ),
        "desktop local recovery helper",
    )
    require(
        provisioning_host + adapter_source + app_main,
        (
            "LocalClient::connect",
            "local_operation::OPEN_MAINTENANCE",
            "cleanup_local_policy_session",
            "provisioning_operation::ABORT",
            "local_coordinator_->maintenance_active()",
            "EnterProvisioning(local_maintenance_authorized)",
            "provisioning_from_local_maintenance_",
            "NeutralizationSatisfied",
            "output_transport_unavailable",
        ),
        "maintenance-owned roaming-policy compatibility path",
    )
    require(
        cpp_header + cpp_source,
        (
            "DecodeAuthenticateRequest",
            "DecodeAuthenticatedRequest",
            "EncodeChallengeResponse",
            "EncodeAuthenticatedResponse",
            "kUnexpectedOperationId",
            "kMissingOperationId",
        ),
        "C++ codec",
    )
    require(
        session_header + session_source,
        (
            "kLocalManagementAdminKeyDomain",
            "kLocalManagementAuthenticationDomain",
            "kLocalManagementSessionKeyDomain",
            "kLocalManagementDeviceProofDomain",
            "kLocalManagementRequestDomain",
            "kLocalManagementResponseDomain",
            "EqualConstantTime",
            "decoded.sequence != last_sequence_ + 1",
            "handler_.Handle",
            "ResetEphemeral",
        ),
        "C++ session",
    )
    require(
        coordinator_header + coordinator_source,
        (
            "class Coordinator final : public Handler",
            "RequestNeutralization",
            "SetMaintenanceActive",
            "NeutralConfirmed",
            "FindInProgress",
            "kNeutralizationDeadlineMs = 2000",
            "ResponseCompleted",
            "ReceiptState::kUnknown",
            "storage_.Save(receipt)",
        ),
        "C++ coordinator",
    )
    require(
        receipt_header + receipt_source + idf_receipt_source,
        (
            "kReceiptCapacity = 16",
            "kReceiptJournalBytes",
            "class ReceiptJournal final : public ReceiptStorage",
            "config::Crc32",
            "generation_ == std::numeric_limits<std::uint64_t>::max()",
            "bool ReceiptJournal::Last",
            "verified != encoded",
            'kNamespace[] = "kf_local_mgmt"',
            "nvs_commit",
        ),
        "bounded receipt journal",
    )
    require(
        status_header + status_source,
        (
            "struct DeviceStatus",
            "struct SafetyStatus",
            "struct NetworkStatus",
            "struct BleHidStatus",
            "struct PolicyStatus",
            "EncodeStatusPage",
            "kLocalManagementStatusSchema",
            "CanonicalRelease",
        ),
        "typed status pages",
    )
    require(
        adapter_header + adapter_source,
        (
            "IsLocalManagementRequest",
            "PrepareUnsupportedLocalResponse",
            "ProcessLocalManagementRequest",
            "local_session_->authenticated()",
            "local_session_->last_sequence() == decoded.sequence",
            "local_coordinator_->ResponseCompleted",
            "local_coordinator_->TransportLost",
        ),
        "shared USB adapter",
    )
    require(
        app_main,
        (
            "public keyferry::local_management::Platform",
            "local_maintenance_active_",
            "command_.EndSession()",
            "hid_.request_dual_neutral()",
            "EncodeStatusPage",
            "active_recovery_authority && provisioning_random_ready",
            "local_receipts.Initialize()",
            "local_coordinator->Initialize()",
            "identity.local_management_v1 = local_management_ready;",
            "local_management_ready ? &*local_session : nullptr",
            "runtime.ConfigureLocalManagement(metadata)",
        ),
        "live local-management platform",
    )
    require(
        secure_header + secure_source,
        (
            "bool local_management_v1{};",
            "FirmwareCapabilityMask",
            "identity.local_management_v1",
            "Capability::kLocalManagementV1",
        ),
        "authenticated capability advertisement",
    )
    require(
        sdkconfig,
        (
            "CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED=y",
            "# CONFIG_MBEDTLS_ECP_DP_SECP384R1_ENABLED is not set",
            "# CONFIG_MBEDTLS_ECP_DP_SECP521R1_ENABLED is not set",
            "# CONFIG_MBEDTLS_ECP_DP_CURVE25519_ENABLED is not set",
        ),
        "exact P-256 endpoint profile",
    )
    portable_cpp = (
        cpp_header
        + cpp_source
        + session_header
        + session_source
        + coordinator_header
        + coordinator_source
        + receipt_header
        + receipt_source
        + status_header
        + status_source
    )
    for forbidden in (
        "CommandExecutor",
        "KeyboardReport",
        "MouseReport",
        "esp_restart",
        "tud_hid",
        "nvs_open(",
        "nvs_set_",
        "nvs_get_",
        "nvs_commit(",
    ):
        if forbidden in portable_cpp:
            fail(f"portable C++ codec crosses authority boundary: {forbidden}")
    if 30 + 18 != 48 or 32 + 16 != 48 or 48 + 16 != 64:
        fail("authenticated report layout arithmetic changed")
    print("check_local_management: ok")


if __name__ == "__main__":
    main()
