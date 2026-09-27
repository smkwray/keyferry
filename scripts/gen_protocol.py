#!/usr/bin/env python3
"""Generate protocol registry constants from protocol/messages.yaml.

This intentionally parses only the small, constrained registry shape used by this repository. It is
not a general YAML parser. Use --check in validation and --write only when intentionally changing the
registry.
"""

from __future__ import annotations

import argparse
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "protocol/messages.yaml"
RUST_OUT = ROOT / "crates/keyferry-protocol/src/registry.rs"
CPP_OUT = ROOT / "firmware/common/include/keyferry_protocol_generated.h"

SECTION_RE = re.compile(r"^([a-z_]+):\s*$")
ITEM_RE = re.compile(r"^\s+- name:\s+([A-Z0-9_]+)\s*$")
NUMBER_RE = re.compile(r"^\s+(id|tag|bit):\s+(0x[0-9A-Fa-f]+|\d+)\s*$")
TOP_NUMBER_RE = re.compile(r"^(max_decoded_frame):\s+(0x[0-9A-Fa-f]+|\d+)\s*$")
TOP_TEXT_RE = re.compile(r"^(magic_ascii):\s+([A-Za-z0-9]+)\s*$")
DISCOVERY_RE = re.compile(
    r"^\s+(magic_ascii|version|beacon_size|port):\s+([A-Za-z0-9]+)\s*$"
)
PROVISIONING_RE = re.compile(
    r"^\s+(version|report_size|challenge_size|transaction_id_size|authentication_tag_size|data_bytes_per_report|idle_timeout_ms|authentication_domain_ascii|request_operation_offset|response_operation_offset|response_status_offset|challenge_version_offset|challenge_payload_length_offset|challenge_device_id_offset|challenge_nonce_offset|challenge_generation_offset|begin_version_offset|begin_payload_length_offset|begin_transaction_id_offset|data_transaction_id_offset|data_offset_offset|data_length_offset|data_bytes_offset|commit_transaction_id_offset|commit_tag_offset|commit_slot_offset|commit_generation_offset|policy_status_state_offset|policy_status_epoch_offset|policy_status_sequence_offset|policy_status_hash_offset):\s+([A-Za-z0-9-]+)\s*$"
)
LOCAL_MANAGEMENT_RE = re.compile(
    r"^\s+(version|status_schema|report_size|session_id_size|device_nonce_size|host_nonce_size|authentication_tag_size|envelope_tag_size|operation_id_size|request_payload_size|response_payload_size|idle_timeout_ms|hard_timeout_ms|enrollment_timeout_ms|admin_key_domain_ascii|authentication_domain_ascii|session_key_domain_ascii|device_proof_domain_ascii|request_domain_ascii|response_domain_ascii):\s+([A-Za-z0-9_./-]+)\s*$"
)
BLE_TRANSPORT_RE = re.compile(
    r"^\s+(version|service_uuid|gateway_to_device_uuid|device_to_gateway_uuid|minimum_att_mtu|preferred_att_mtu|maximum_fragment_bytes|receive_ring_bytes|transmit_staging_bytes|connection_metadata_max_bytes|cccd_setup_timeout_ms|authentication_timeout_ms|progress_timeout_ms|operation_timeout_ms|host_candidate_timeout_ms|advertising_delay_ms|wifi_preference_ms|wifi_retry_interval_ms|failed_candidates_before_wifi_retry):\s+([A-Za-z0-9-]+)\s*$"
)
CONFIGURATION_RE = re.compile(
    r"^\s+(max_wifi_profiles|max_paired_hosts|max_ssid_bytes|max_wifi_credential_bytes|max_server_name_bytes|max_ca_certificate_bytes|fixed_header_bytes|wifi_record_bytes|host_record_bytes|payload_bytes):\s+(\d+)\s*$"
)
FILE_HANDOFF_RE = re.compile(r"^\s+(max_file_bytes|max_chunk_bytes|status_bytes|max_files|max_name_bytes|file_set_status_bytes):\s+(\d+)\s*$")
ROAMING_RE = re.compile(
    r"^\s+(version|device_tls_port|installation_id_bytes|owner_id_bytes|device_id_bytes|recovery_secret_bytes|device_link_secret_bytes|p256_spki_bytes|route_proof_secret_bytes|route_proof_tag_bytes|route_proof_body_bytes|route_proof_fields_bytes|route_proof_response_bytes|policy_auth_tag_bytes|revocation_entry_bytes|roaming_config_fixed_header_bytes|roaming_config_payload_bytes|policy_hash_input_bytes|policy_auth_input_bytes|maximum_revoked_installations|route_proof_ttl_ms|gateway_handoff_start_payload_bytes|gateway_handoff_accept_payload_bytes|gateway_handoff_query_payload_bytes|gateway_handoff_status_payload_bytes|gateway_handoff_target_valid_ms|gateway_handoff_recovery_ms|gateway_handoff_reservation_ms|installation_id_domain_ascii|link_salt_domain_ascii|device_link_domain_ascii|route_proof_key_domain_ascii|route_proof_domain_ascii|policy_hash_domain_ascii|policy_auth_key_domain_ascii|policy_auth_domain_ascii|maintenance_authentication_domain_ascii|device_gateway_dns_prefix_ascii|device_gateway_dns_suffix_ascii|installation_gateway_dns_prefix_ascii|installation_gateway_dns_suffix_ascii):\s+([A-Za-z0-9_./-]+)\s*$"
)

VALUE_FIELD = {
    "messages": "id",
    "command_kinds": "id",
    "report_actions": "tag",
    "provisioning_operations": "id",
    "provisioning_policy_states": "id",
    "provisioning_statuses": "id",
    "local_management_operations": "id",
    "local_management_statuses": "id",
    "local_management_status_pages": "id",
    "local_management_probe_phases": "id",
    "local_management_probe_outcomes": "id",
    "local_management_bond_states": "id",
    "local_management_receipt_states": "id",
    "capabilities": "bit",
    "output_modes": "id",
    "display_orientations": "id",
    "screen_powers": "id",
    "operational_modes": "id",
    "arm_policies": "id",
    "result_codes": "id",
    "error_codes": "id",
    "gateway_handoff_operations": "id",
    "gateway_handoff_statuses": "id",
    "gateway_handoff_phases": "id",
    "gateway_handoff_reasons": "id",
}

PROVISIONING_OFFSET_FIELDS = (
    "request_operation_offset",
    "response_operation_offset",
    "response_status_offset",
    "challenge_version_offset",
    "challenge_payload_length_offset",
    "challenge_device_id_offset",
    "challenge_nonce_offset",
    "challenge_generation_offset",
    "begin_version_offset",
    "begin_payload_length_offset",
    "begin_transaction_id_offset",
    "data_transaction_id_offset",
    "data_offset_offset",
    "data_length_offset",
    "data_bytes_offset",
    "commit_transaction_id_offset",
    "commit_tag_offset",
    "commit_slot_offset",
    "commit_generation_offset",
    "policy_status_state_offset",
    "policy_status_epoch_offset",
    "policy_status_sequence_offset",
    "policy_status_hash_offset",
)


@dataclass(frozen=True)
class Entry:
    name: str
    value: int


@dataclass(frozen=True)
class Registry:
    magic_ascii: str
    max_decoded_frame: int
    discovery_magic_ascii: str
    discovery_version: int
    discovery_beacon_size: int
    discovery_port: int
    ble_transport: dict[str, str]
    roaming: dict[str, str]
    provisioning: dict[str, str]
    local_management: dict[str, str]
    configuration: dict[str, int]
    file_handoff: dict[str, int]
    sections: dict[str, list[Entry]]


def parse_registry() -> Registry:
    top: dict[str, str] = {}
    sections: dict[str, list[Entry]] = {name: [] for name in VALUE_FIELD}
    current_section: str | None = None
    current_name: str | None = None
    discovery: dict[str, str] = {}
    provisioning: dict[str, str] = {}
    local_management: dict[str, str] = {}
    ble_transport: dict[str, str] = {}
    roaming: dict[str, str] = {}
    configuration: dict[str, int] = {}
    file_handoff: dict[str, int] = {}

    for line_number, raw in enumerate(REGISTRY.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].rstrip()
        if not line:
            continue
        match = TOP_TEXT_RE.match(line)
        if match:
            top[match.group(1)] = match.group(2)
            continue
        match = TOP_NUMBER_RE.match(line)
        if match:
            top[match.group(1)] = match.group(2)
            continue
        match = SECTION_RE.match(line)
        if match:
            current_section = match.group(1)
            current_name = None
            continue
        match = ITEM_RE.match(line)
        if match:
            current_name = match.group(1)
            continue
        match = DISCOVERY_RE.match(line)
        if match and current_section == "discovery":
            discovery[match.group(1)] = match.group(2)
            continue
        match = PROVISIONING_RE.match(line)
        if match and current_section == "provisioning":
            provisioning[match.group(1)] = match.group(2)
            continue
        match = LOCAL_MANAGEMENT_RE.match(line)
        if match and current_section == "local_management":
            local_management[match.group(1)] = match.group(2)
            continue
        match = BLE_TRANSPORT_RE.match(line)
        if match and current_section == "ble_transport":
            ble_transport[match.group(1)] = match.group(2)
            continue
        match = ROAMING_RE.match(line)
        if match and current_section == "roaming":
            roaming[match.group(1)] = match.group(2)
            continue
        match = CONFIGURATION_RE.match(line)
        if match and current_section == "configuration":
            configuration[match.group(1)] = int(match.group(2))
            continue
        match = FILE_HANDOFF_RE.match(line)
        if match and current_section == "file_handoff":
            file_handoff[match.group(1)] = int(match.group(2))
            continue
        match = NUMBER_RE.match(line)
        if match and current_section in VALUE_FIELD and current_name:
            field, raw_value = match.groups()
            if field != VALUE_FIELD[current_section]:
                continue
            sections[current_section].append(Entry(current_name, int(raw_value, 0)))
            current_name = None

    magic = top.get("magic_ascii")
    if magic is None or len(magic.encode("ascii", errors="ignore")) != 2:
        raise SystemExit("protocol registry must define a two-byte ASCII magic_ascii value")
    maximum = int(top.get("max_decoded_frame", "0"), 0)
    if maximum < 14 or maximum > 4096:
        raise SystemExit("protocol max_decoded_frame is outside the generator's safe range")
    for section, entries in sections.items():
        if not entries:
            raise SystemExit(f"protocol registry section is empty or malformed: {section}")
        names = {entry.name for entry in entries}
        values = {entry.value for entry in entries}
        if len(names) != len(entries) or len(values) != len(entries):
            raise SystemExit(f"duplicate name or value in protocol section: {section}")

    discovery_magic = discovery.get("magic_ascii", "")
    if len(discovery_magic.encode("ascii", errors="ignore")) != 4:
        raise SystemExit("discovery must define a four-byte ASCII magic_ascii value")
    discovery_version = int(discovery.get("version", "0"), 0)
    discovery_size = int(discovery.get("beacon_size", "0"), 0)
    discovery_port = int(discovery.get("port", "0"), 0)
    if discovery_version != 1 or discovery_size != 22 or not 1 <= discovery_port <= 65535:
        raise SystemExit("discovery version, beacon size, or port is invalid")

    required_ble_transport = {
        "version": 1,
        "minimum_att_mtu": 23,
        "preferred_att_mtu": 247,
        "maximum_fragment_bytes": 244,
        "receive_ring_bytes": 1024,
        "transmit_staging_bytes": 244,
        "connection_metadata_max_bytes": 256,
        "cccd_setup_timeout_ms": 20000,
        "authentication_timeout_ms": 20000,
        "progress_timeout_ms": 5000,
        "operation_timeout_ms": 8000,
        "host_candidate_timeout_ms": 40000,
        "wifi_retry_interval_ms": 30000,
    }
    for name, expected in required_ble_transport.items():
        if int(ble_transport.get(name, "0"), 0) != expected:
            raise SystemExit(f"BLE transport {name} must be {expected}")
    for name in (
        "service_uuid",
        "gateway_to_device_uuid",
        "device_to_gateway_uuid",
    ):
        try:
            uuid.UUID(ble_transport.get(name, ""))
        except ValueError as error:
            raise SystemExit(f"BLE transport {name} is not a UUID") from error
    if len(
        {
            ble_transport["service_uuid"],
            ble_transport["gateway_to_device_uuid"],
            ble_transport["device_to_gateway_uuid"],
        }
    ) != 3:
        raise SystemExit("BLE transport UUIDs must be distinct")

    required_roaming_numbers = {
        "version": 2,
        "device_tls_port": 7443,
        "installation_id_bytes": 16,
        "owner_id_bytes": 16,
        "device_id_bytes": 16,
        "recovery_secret_bytes": 32,
        "device_link_secret_bytes": 32,
        "p256_spki_bytes": 91,
        "route_proof_secret_bytes": 32,
        "route_proof_tag_bytes": 32,
        "route_proof_body_bytes": 201,
        "route_proof_fields_bytes": 178,
        "route_proof_response_bytes": 210,
        "policy_auth_tag_bytes": 32,
        "revocation_entry_bytes": 16,
        "roaming_config_fixed_header_bytes": 192,
        "roaming_config_payload_bytes": 3064,
        "policy_hash_input_bytes": 3018,
        "policy_auth_input_bytes": 55,
        "maximum_revoked_installations": 64,
        "route_proof_ttl_ms": 5000,
        "gateway_handoff_start_payload_bytes": 96,
        "gateway_handoff_accept_payload_bytes": 66,
        "gateway_handoff_query_payload_bytes": 18,
        "gateway_handoff_status_payload_bytes": 94,
        "gateway_handoff_target_valid_ms": 6000,
        "gateway_handoff_recovery_ms": 6000,
        "gateway_handoff_reservation_ms": 20000,
    }
    for name, expected in required_roaming_numbers.items():
        if int(roaming.get(name, "0"), 0) != expected:
            raise SystemExit(f"roaming {name} must be {expected}")
    required_roaming_domains = {
        "installation_id_domain_ascii": "keyferry/installation-id/v2",
        "link_salt_domain_ascii": "keyferry/link-salt/v2",
        "device_link_domain_ascii": "keyferry/device-link/v2",
        "route_proof_key_domain_ascii": "keyferry/route-proof-key/v2",
        "route_proof_domain_ascii": "keyferry/route-proof/v2",
        "policy_hash_domain_ascii": "keyferry/policy/v2",
        "policy_auth_key_domain_ascii": "keyferry/policy-auth-key/v2",
        "policy_auth_domain_ascii": "keyferry/policy-auth/v2",
        "maintenance_authentication_domain_ascii": "keyferry/maintenance/v2",
        "device_gateway_dns_prefix_ascii": "d-",
        "device_gateway_dns_suffix_ascii": ".gateway.keyferry.invalid",
        "installation_gateway_dns_prefix_ascii": "i-",
        "installation_gateway_dns_suffix_ascii": ".desktop.keyferry.invalid",
    }
    for name, expected in required_roaming_domains.items():
        if roaming.get(name) != expected:
            raise SystemExit(f"roaming {name} is invalid")

    required_provisioning = {
        "version": 1,
        "report_size": 64,
        "challenge_size": 32,
        "transaction_id_size": 16,
        "authentication_tag_size": 32,
        "data_bytes_per_report": 44,
        "idle_timeout_ms": 30000,
        "request_operation_offset": 0,
        "response_operation_offset": 0,
        "response_status_offset": 1,
        "challenge_version_offset": 2,
        "challenge_payload_length_offset": 3,
        "challenge_device_id_offset": 5,
        "challenge_nonce_offset": 21,
        "challenge_generation_offset": 53,
        "begin_version_offset": 1,
        "begin_payload_length_offset": 2,
        "begin_transaction_id_offset": 4,
        "data_transaction_id_offset": 1,
        "data_offset_offset": 17,
        "data_length_offset": 19,
        "data_bytes_offset": 20,
        "commit_transaction_id_offset": 1,
        "commit_tag_offset": 17,
        "commit_slot_offset": 2,
        "commit_generation_offset": 3,
        "policy_status_state_offset": 2,
        "policy_status_epoch_offset": 3,
        "policy_status_sequence_offset": 11,
        "policy_status_hash_offset": 19,
    }
    for name, expected in required_provisioning.items():
        if int(provisioning.get(name, "0"), 0) != expected:
            raise SystemExit(f"provisioning {name} must be {expected}")
    if provisioning.get("authentication_domain_ascii") != "keyferry-provision-v1":
        raise SystemExit("provisioning authentication domain is invalid")

    required_local_management = {
        "version": 1,
        "status_schema": 1,
        "report_size": 64,
        "session_id_size": 8,
        "device_nonce_size": 32,
        "host_nonce_size": 16,
        "authentication_tag_size": 32,
        "envelope_tag_size": 16,
        "operation_id_size": 16,
        "request_payload_size": 18,
        "response_payload_size": 16,
        "idle_timeout_ms": 60000,
        "hard_timeout_ms": 300000,
        "enrollment_timeout_ms": 120000,
    }
    for name, expected in required_local_management.items():
        if int(local_management.get(name, "0"), 0) != expected:
            raise SystemExit(f"local management {name} must be {expected}")
    required_local_management_domains = {
        "admin_key_domain_ascii": "keyferry/local-admin-key/v1",
        "authentication_domain_ascii": "keyferry/local-auth/v1",
        "session_key_domain_ascii": "keyferry/local-session/v1",
        "device_proof_domain_ascii": "keyferry/local-device-proof/v1",
        "request_domain_ascii": "keyferry/local-request/v1",
        "response_domain_ascii": "keyferry/local-response/v1",
    }
    for name, expected in required_local_management_domains.items():
        if local_management.get(name) != expected:
            raise SystemExit(f"local management {name} is invalid")

    required_configuration = {
        "max_wifi_profiles": 8,
        "max_paired_hosts": 8,
        "max_ssid_bytes": 32,
        "max_wifi_credential_bytes": 63,
        "max_server_name_bytes": 253,
        "max_ca_certificate_bytes": 1024,
        "fixed_header_bytes": 52,
        "wifi_record_bytes": 103,
        "host_record_bytes": 1369,
        "payload_bytes": 11828,
    }
    if configuration != required_configuration:
        raise SystemExit("configuration layout constants are incomplete or invalid")
    if (set(file_handoff) != {"max_file_bytes", "max_chunk_bytes", "status_bytes", "max_files", "max_name_bytes", "file_set_status_bytes"}
            or not 0 < file_handoff.get("max_file_bytes", 0) <= 0xFFFFFFFF
            or file_handoff.get("max_chunk_bytes") != 200
            or file_handoff.get("status_bytes") != 10
            or file_handoff.get("max_files") != 16
            or file_handoff.get("max_name_bytes") != 64
            or file_handoff.get("file_set_status_bytes") != 11):
        raise SystemExit("file handoff layout constants are incomplete or invalid")

    return Registry(
        magic,
        maximum,
        discovery_magic,
        discovery_version,
        discovery_size,
        discovery_port,
        ble_transport,
        roaming,
        provisioning,
        local_management,
        configuration,
        file_handoff,
        sections,
    )


def camel(name: str) -> str:
    return "".join(word.capitalize() for word in name.lower().split("_"))


def rust_number(value: int, bits: int) -> str:
    width = bits // 4
    return f"0x{value:0{width}X}"


def uuid_bytes(raw: str) -> list[int]:
    return list(uuid.UUID(raw).bytes)


def generate_rust(registry: Registry) -> str:
    specs = [
        ("message", "messages", "u8", 8),
        ("command_kind", "command_kinds", "u8", 8),
        ("action", "report_actions", "u8", 8),
        ("provisioning_operation", "provisioning_operations", "u8", 8),
        ("provisioning_policy_state", "provisioning_policy_states", "u8", 8),
        ("provisioning_status", "provisioning_statuses", "u8", 8),
        ("local_management_operation", "local_management_operations", "u8", 8),
        ("local_management_status", "local_management_statuses", "u8", 8),
        ("local_management_status_page", "local_management_status_pages", "u8", 8),
        ("local_management_probe_phase", "local_management_probe_phases", "u8", 8),
        ("local_management_probe_outcome", "local_management_probe_outcomes", "u8", 8),
        ("local_management_bond_state", "local_management_bond_states", "u8", 8),
        ("local_management_receipt_state", "local_management_receipt_states", "u8", 8),
        ("capability", "capabilities", "u32", 32),
        ("output_mode", "output_modes", "u8", 8),
        ("display_orientation", "display_orientations", "u8", 8),
        ("screen_power", "screen_powers", "u8", 8),
        ("operational_mode", "operational_modes", "u8", 8),
        ("arm_policy", "arm_policies", "u8", 8),
        ("result_code", "result_codes", "u8", 8),
        ("error_code", "error_codes", "u16", 16),
        ("gateway_handoff_operation", "gateway_handoff_operations", "u8", 8),
        ("gateway_handoff_status", "gateway_handoff_statuses", "u16", 16),
        ("gateway_handoff_phase", "gateway_handoff_phases", "u8", 8),
        ("gateway_handoff_reason", "gateway_handoff_reasons", "u8", 8),
    ]
    lines = [
        "// @generated by scripts/gen_protocol.py from protocol/messages.yaml.",
        "// Do not edit by hand.",
        "",
    ]
    lines.extend(
        [
            "pub mod discovery {",
            f'    pub const MAGIC: [u8; 4] = *b"{registry.discovery_magic_ascii}";',
            f"    pub const VERSION: u8 = {registry.discovery_version};",
            f"    pub const BEACON_SIZE: usize = {registry.discovery_beacon_size};",
            f"    pub const PORT: u16 = {registry.discovery_port};",
            "}",
            "",
            "pub mod ble_transport {",
            f"    pub const VERSION: u8 = {registry.ble_transport['version']};",
        ]
    )
    for name in (
        "service_uuid",
        "gateway_to_device_uuid",
        "device_to_gateway_uuid",
    ):
        values = uuid_bytes(registry.ble_transport[name])
        lines.append(f"    pub const {name.upper()}: [u8; 16] = [")
        first_line = ", ".join(f"0x{value:02X}" for value in values[:15])
        lines.append(f"        {first_line},")
        lines.append(f"        0x{values[15]:02X},")
        lines.append("    ];")
    for name in (
        "minimum_att_mtu",
        "preferred_att_mtu",
        "maximum_fragment_bytes",
        "receive_ring_bytes",
        "transmit_staging_bytes",
        "connection_metadata_max_bytes",
        "cccd_setup_timeout_ms",
        "authentication_timeout_ms",
        "progress_timeout_ms",
        "operation_timeout_ms",
        "host_candidate_timeout_ms",
        "advertising_delay_ms",
        "wifi_preference_ms",
        "wifi_retry_interval_ms",
        "failed_candidates_before_wifi_retry",
    ):
        lines.append(f"    pub const {name.upper()}: usize = {registry.ble_transport[name]};")
    lines.extend(
        [
            "}",
            "",
            "pub mod configuration {",
        ]
    )
    for name, value in registry.configuration.items():
        lines.append(f"    pub const {name.upper()}: usize = {value};")
    lines.extend(["}", "", "pub mod file_handoff {"])
    for name, value in registry.file_handoff.items():
        lines.append(f"    pub const {name.upper()}: usize = {value};")
    lines.append("    pub const MAX_BUNDLE_BYTES: usize = 1 + MAX_FILES * (1 + MAX_NAME_BYTES + 4) + MAX_FILE_BYTES;")
    lines.extend(
        [
            "}",
            "",
            "pub mod roaming {",
            f"    pub const VERSION: u8 = {registry.roaming['version']};",
            f"    pub const DEVICE_TLS_PORT: u16 = {registry.roaming['device_tls_port']};",
        ]
    )
    for name in (
        "installation_id_bytes",
        "owner_id_bytes",
        "device_id_bytes",
        "recovery_secret_bytes",
        "device_link_secret_bytes",
        "p256_spki_bytes",
        "route_proof_secret_bytes",
        "route_proof_tag_bytes",
        "route_proof_body_bytes",
        "route_proof_fields_bytes",
        "route_proof_response_bytes",
        "policy_auth_tag_bytes",
        "revocation_entry_bytes",
        "roaming_config_fixed_header_bytes",
        "roaming_config_payload_bytes",
        "policy_hash_input_bytes",
        "policy_auth_input_bytes",
        "maximum_revoked_installations",
        "route_proof_ttl_ms",
        "gateway_handoff_start_payload_bytes",
        "gateway_handoff_accept_payload_bytes",
        "gateway_handoff_query_payload_bytes",
        "gateway_handoff_status_payload_bytes",
        "gateway_handoff_target_valid_ms",
        "gateway_handoff_recovery_ms",
        "gateway_handoff_reservation_ms",
    ):
        lines.append(f"    pub const {name.upper()}: usize = {registry.roaming[name]};")
    for name in (
        "installation_id_domain_ascii",
        "link_salt_domain_ascii",
        "device_link_domain_ascii",
        "route_proof_key_domain_ascii",
        "route_proof_domain_ascii",
        "policy_hash_domain_ascii",
        "policy_auth_key_domain_ascii",
        "policy_auth_domain_ascii",
        "maintenance_authentication_domain_ascii",
        "device_gateway_dns_prefix_ascii",
        "device_gateway_dns_suffix_ascii",
        "installation_gateway_dns_prefix_ascii",
        "installation_gateway_dns_suffix_ascii",
    ):
        constant = name.removesuffix("_ascii").upper()
        lines.append(f'    pub const {constant}: &[u8] = b"{registry.roaming[name]}";')
    lines.extend(["}", ""])
    lines.extend(
        [
            "pub mod provisioning {",
            f"    pub const VERSION: u8 = {registry.provisioning['version']};",
            f"    pub const REPORT_SIZE: usize = {registry.provisioning['report_size']};",
            f"    pub const CHALLENGE_SIZE: usize = {registry.provisioning['challenge_size']};",
            f"    pub const TRANSACTION_ID_SIZE: usize = {registry.provisioning['transaction_id_size']};",
            f"    pub const AUTHENTICATION_TAG_SIZE: usize = {registry.provisioning['authentication_tag_size']};",
            f"    pub const DATA_BYTES_PER_REPORT: usize = {registry.provisioning['data_bytes_per_report']};",
            f"    pub const IDLE_TIMEOUT_MS: u64 = {registry.provisioning['idle_timeout_ms']};",
            f"    pub const AUTHENTICATION_DOMAIN: &[u8] = b\"{registry.provisioning['authentication_domain_ascii']}\";",
        ]
    )
    for name in PROVISIONING_OFFSET_FIELDS:
        lines.append(f"    pub const {name.upper()}: usize = {registry.provisioning[name]};")
    lines.extend(["}", ""])
    lines.extend(
        [
            "pub mod local_management {",
            f"    pub const VERSION: u8 = {registry.local_management['version']};",
            f"    pub const STATUS_SCHEMA: u8 = {registry.local_management['status_schema']};",
        ]
    )
    for name in (
        "report_size",
        "session_id_size",
        "device_nonce_size",
        "host_nonce_size",
        "authentication_tag_size",
        "envelope_tag_size",
        "operation_id_size",
        "request_payload_size",
        "response_payload_size",
    ):
        lines.append(
            f"    pub const {name.upper()}: usize = {registry.local_management[name]};"
        )
    for name in ("idle_timeout_ms", "hard_timeout_ms", "enrollment_timeout_ms"):
        lines.append(
            f"    pub const {name.upper()}: u64 = {registry.local_management[name]};"
        )
    for name in (
        "admin_key_domain_ascii",
        "authentication_domain_ascii",
        "session_key_domain_ascii",
        "device_proof_domain_ascii",
        "request_domain_ascii",
        "response_domain_ascii",
    ):
        lines.append(
            f'    pub const {name.removesuffix("_ascii").upper()}: &[u8] = b"{registry.local_management[name]}";'
        )
    lines.extend(["}", ""])
    for module, section, rust_type, bits in specs:
        lines.append(f"pub mod {module} {{")
        for entry in registry.sections[section]:
            lines.append(
                f"    pub const {entry.name}: {rust_type} = {rust_number(entry.value, bits)};"
            )
        lines.extend(["}", ""])
    return "\n".join(lines)


def generate_cpp(registry: Registry) -> str:
    magic_bytes = registry.magic_ascii.encode("ascii")
    magic_value = magic_bytes[0] | (magic_bytes[1] << 8)
    lines = [
        "#pragma once",
        "",
        "#include <array>",
        "#include <cstddef>",
        "#include <cstdint>",
        "",
        "// @generated by scripts/gen_protocol.py from protocol/messages.yaml.",
        "// Do not edit by hand.",
        "namespace keyferry::protocol {",
        "",
        f"constexpr std::uint16_t kMagic = 0x{magic_value:04X};",
        "constexpr std::uint8_t kMajor = 1;",
        "constexpr std::uint8_t kMinor = 0;",
        "constexpr std::size_t kHeaderLength = 12;",
        "constexpr std::size_t kCrcLength = 2;",
        f"constexpr std::size_t kMaxDecodedFrame = {registry.max_decoded_frame};",
        "constexpr std::size_t kMaxPayload = kMaxDecodedFrame - kHeaderLength - kCrcLength;",
        "constexpr std::array<std::uint8_t, 4> kDiscoveryMagic{"
        + ", ".join(f"'{character}'" for character in registry.discovery_magic_ascii)
        + "};",
        f"constexpr std::uint8_t kDiscoveryVersion = {registry.discovery_version};",
        f"constexpr std::size_t kDiscoveryBeaconSize = {registry.discovery_beacon_size};",
        f"constexpr std::uint16_t kDiscoveryPort = {registry.discovery_port};",
        f"constexpr std::uint8_t kBleTransportVersion = {registry.ble_transport['version']};",
    ]
    for name in (
        "service_uuid",
        "gateway_to_device_uuid",
        "device_to_gateway_uuid",
    ):
        values = ", ".join(f"0x{value:02X}" for value in uuid_bytes(registry.ble_transport[name]))
        lines.append(
            f"constexpr std::array<std::uint8_t, 16> kBle{camel(name)}{{{values}}};"
        )
    for name in (
        "minimum_att_mtu",
        "preferred_att_mtu",
        "maximum_fragment_bytes",
        "receive_ring_bytes",
        "transmit_staging_bytes",
        "connection_metadata_max_bytes",
        "cccd_setup_timeout_ms",
        "authentication_timeout_ms",
        "progress_timeout_ms",
        "operation_timeout_ms",
        "host_candidate_timeout_ms",
        "advertising_delay_ms",
        "wifi_preference_ms",
        "wifi_retry_interval_ms",
        "failed_candidates_before_wifi_retry",
    ):
        lines.append(
            f"constexpr std::size_t kBle{camel(name)} = {registry.ble_transport[name]};"
        )
    lines.append(f"constexpr std::uint8_t kRoamingVersion = {registry.roaming['version']};")
    lines.append(
        f"constexpr std::uint16_t kRoamingDeviceTlsPort = {registry.roaming['device_tls_port']};"
    )
    for name in (
        "installation_id_bytes",
        "owner_id_bytes",
        "device_id_bytes",
        "recovery_secret_bytes",
        "device_link_secret_bytes",
        "p256_spki_bytes",
        "route_proof_secret_bytes",
        "route_proof_tag_bytes",
        "route_proof_body_bytes",
        "route_proof_fields_bytes",
        "route_proof_response_bytes",
        "policy_auth_tag_bytes",
        "revocation_entry_bytes",
        "roaming_config_fixed_header_bytes",
        "roaming_config_payload_bytes",
        "policy_hash_input_bytes",
        "policy_auth_input_bytes",
        "maximum_revoked_installations",
        "route_proof_ttl_ms",
        "gateway_handoff_start_payload_bytes",
        "gateway_handoff_accept_payload_bytes",
        "gateway_handoff_query_payload_bytes",
        "gateway_handoff_status_payload_bytes",
        "gateway_handoff_target_valid_ms",
        "gateway_handoff_recovery_ms",
        "gateway_handoff_reservation_ms",
    ):
        lines.append(
            f"constexpr std::size_t kRoaming{camel(name)} = {registry.roaming[name]};"
        )
    for name in (
        "installation_id_domain_ascii",
        "link_salt_domain_ascii",
        "device_link_domain_ascii",
        "route_proof_key_domain_ascii",
        "route_proof_domain_ascii",
        "policy_hash_domain_ascii",
        "policy_auth_key_domain_ascii",
        "policy_auth_domain_ascii",
        "maintenance_authentication_domain_ascii",
        "device_gateway_dns_prefix_ascii",
        "device_gateway_dns_suffix_ascii",
        "installation_gateway_dns_prefix_ascii",
        "installation_gateway_dns_suffix_ascii",
    ):
        value = registry.roaming[name]
        constant = camel(name.removesuffix("_ascii"))
        lines.append(
            f"constexpr std::array<std::uint8_t, {len(value)}> kRoaming{constant}{{"
            + ", ".join(f"'{character}'" for character in value)
            + "};"
        )
    lines.extend([
        f"constexpr std::uint8_t kProvisioningVersion = {registry.provisioning['version']};",
        f"constexpr std::size_t kProvisioningReportSize = {registry.provisioning['report_size']};",
        f"constexpr std::size_t kProvisioningChallengeSize = {registry.provisioning['challenge_size']};",
        f"constexpr std::size_t kProvisioningTransactionIdSize = {registry.provisioning['transaction_id_size']};",
        f"constexpr std::size_t kProvisioningAuthenticationTagSize = {registry.provisioning['authentication_tag_size']};",
        f"constexpr std::size_t kProvisioningDataBytesPerReport = {registry.provisioning['data_bytes_per_report']};",
        f"constexpr std::uint64_t kProvisioningIdleTimeoutMs = {registry.provisioning['idle_timeout_ms']};",
        "constexpr std::array<std::uint8_t, 21> kProvisioningAuthenticationDomain{"
        + ", ".join(
            f"'{character}'"
            for character in registry.provisioning["authentication_domain_ascii"]
        )
        + "};",
        "",
    ])
    for name, value in registry.configuration.items():
        lines.append(f"constexpr std::size_t kConfig{camel(name)} = {value};")
    for name, value in registry.file_handoff.items():
        lines.append(f"constexpr std::size_t kFileHandoff{camel(name)} = {value};")
    lines.append("constexpr std::size_t kFileHandoffMaxBundleBytes = 1 + kFileHandoffMaxFiles * (1 + kFileHandoffMaxNameBytes + 4) + kFileHandoffMaxFileBytes;")
    for name in PROVISIONING_OFFSET_FIELDS:
        lines.append(
            f"constexpr std::size_t kProvisioning{camel(name)} = {registry.provisioning[name]};"
        )
    lines.append("")
    lines.extend(
        [
            f"constexpr std::uint8_t kLocalManagementVersion = {registry.local_management['version']};",
            f"constexpr std::uint8_t kLocalManagementStatusSchema = {registry.local_management['status_schema']};",
        ]
    )
    for name in (
        "report_size",
        "session_id_size",
        "device_nonce_size",
        "host_nonce_size",
        "authentication_tag_size",
        "envelope_tag_size",
        "operation_id_size",
        "request_payload_size",
        "response_payload_size",
        "idle_timeout_ms",
        "hard_timeout_ms",
        "enrollment_timeout_ms",
    ):
        lines.append(
            f"constexpr std::size_t kLocalManagement{camel(name)} = {registry.local_management[name]};"
        )
    for name in (
        "admin_key_domain_ascii",
        "authentication_domain_ascii",
        "session_key_domain_ascii",
        "device_proof_domain_ascii",
        "request_domain_ascii",
        "response_domain_ascii",
    ):
        value = registry.local_management[name]
        lines.append(
            f"constexpr std::array<std::uint8_t, {len(value)}> kLocalManagement{camel(name.removesuffix('_ascii'))}{{"
            + ", ".join(f"'{character}'" for character in value)
            + "};"
        )
    lines.append("")

    enum_specs = [
        ("MessageType", "messages", "std::uint8_t", 2),
        ("CommandKind", "command_kinds", "std::uint8_t", 2),
        ("ReportAction", "report_actions", "std::uint8_t", 2),
        ("ProvisioningOperation", "provisioning_operations", "std::uint8_t", 2),
        ("ProvisioningPolicyState", "provisioning_policy_states", "std::uint8_t", 2),
        ("ProvisioningStatus", "provisioning_statuses", "std::uint8_t", 2),
        ("LocalManagementOperation", "local_management_operations", "std::uint8_t", 2),
        ("LocalManagementStatus", "local_management_statuses", "std::uint8_t", 2),
        ("LocalManagementStatusPage", "local_management_status_pages", "std::uint8_t", 2),
        ("LocalManagementProbePhase", "local_management_probe_phases", "std::uint8_t", 2),
        ("LocalManagementProbeOutcome", "local_management_probe_outcomes", "std::uint8_t", 2),
        ("LocalManagementBondState", "local_management_bond_states", "std::uint8_t", 2),
        ("LocalManagementReceiptState", "local_management_receipt_states", "std::uint8_t", 2),
        ("Capability", "capabilities", "std::uint32_t", 8),
        ("OutputMode", "output_modes", "std::uint8_t", 2),
        ("DisplayOrientation", "display_orientations", "std::uint8_t", 2),
        ("ScreenPower", "screen_powers", "std::uint8_t", 2),
        ("OperationalMode", "operational_modes", "std::uint8_t", 2),
        ("ArmPolicy", "arm_policies", "std::uint8_t", 2),
        ("ResultCode", "result_codes", "std::uint8_t", 2),
        ("ErrorCode", "error_codes", "std::uint16_t", 4),
        ("GatewayHandoffOperation", "gateway_handoff_operations", "std::uint8_t", 2),
        ("GatewayHandoffStatus", "gateway_handoff_statuses", "std::uint16_t", 4),
        ("GatewayHandoffPhase", "gateway_handoff_phases", "std::uint8_t", 2),
        ("GatewayHandoffReason", "gateway_handoff_reasons", "std::uint8_t", 2),
    ]
    for enum_name, section, cpp_type, width in enum_specs:
        lines.append(f"enum class {enum_name} : {cpp_type} {{")
        for entry in registry.sections[section]:
            lines.append(f"  k{camel(entry.name)} = 0x{entry.value:0{width}X},")
        lines.extend(["};", ""])

    lines.extend(["}  // namespace keyferry::protocol", ""])
    return "\n".join(lines)


def check_or_write(path: Path, expected: str, *, write: bool) -> bool:
    current = path.read_text(encoding="utf-8") if path.exists() else None
    if current == expected:
        print(f"ok       {path.relative_to(ROOT)}")
        return True
    if write:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(expected, encoding="utf-8", newline="\n")
        print(f"updated  {path.relative_to(ROOT)}")
        return True
    print(f"STALE    {path.relative_to(ROOT)}")
    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()

    registry = parse_registry()
    ok = True
    ok &= check_or_write(RUST_OUT, generate_rust(registry), write=args.write)
    ok &= check_or_write(CPP_OUT, generate_cpp(registry), write=args.write)
    if not ok:
        raise SystemExit("generated protocol files are stale; run scripts/gen_protocol.py --write")


if __name__ == "__main__":
    main()
