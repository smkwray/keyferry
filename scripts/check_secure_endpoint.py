#!/usr/bin/env python3
"""Fail closed if the offline secure-endpoint skeleton broadens its authority."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "firmware" / "esp32s3" / "secure_endpoint"
COMPONENT = ROOT / "firmware" / "esp32s3" / "components" / "kf_secure_endpoint"
HEADER = COMPONENT / "include" / "keyferry" / "secure_endpoint.h"
SOURCE = COMPONENT / "src" / "secure_endpoint.cpp"
TEST = COMPONENT / "test" / "secure_endpoint_test.cpp"
APP = PROJECT / "main" / "app_main.cpp"
DEFAULTS = PROJECT / "sdkconfig.defaults"

REQUIRED_CONFIG = {
    "CONFIG_MBEDTLS_CHACHAPOLY_C": "1",
    "CONFIG_MBEDTLS_CHACHA20_C": "1",
    "CONFIG_MBEDTLS_ECDH_C": "1",
    "CONFIG_MBEDTLS_ECDSA_C": "1",
    "CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED": "1",
    "CONFIG_MBEDTLS_SSL_PROTO_TLS1_2": "1",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_source() -> None:
    header = HEADER.read_text(encoding="utf-8")
    source = SOURCE.read_text(encoding="utf-8")
    test = TEST.read_text(encoding="utf-8")
    app = APP.read_text(encoding="utf-8")
    defaults = DEFAULTS.read_text(encoding="utf-8")

    required_source = {
        "kTls12Version = 0x0303",
        "kRequiredCipherSuite = 0xCCA9",
        "kLilygoTDongleS3CompatibilityId = 2",
        "PeerKeyAlgorithm::kEcdsaP256",
        "ConstantTimeEqual",
        "kChallengeLength = 66",
        "kResponseLength = 80",
        "std::array<std::uint8_t, 131> hmac_input",
        "identity.board_compatibility_id == kLilygoTDongleS3CompatibilityId",
        "frame.sequence != 0",
        "frame.sequence != 1",
        "frame.sequence != expected_sequence_",
        "expected_sequence_ == UINT32_MAX",
        "effects_.FailClosed(epoch_)",
    }
    combined = header + source
    for token in sorted(required_source):
        if token not in combined:
            fail(f"missing secure-endpoint invariant: {token}")

    required_tests = {
        "TestHandshakeAndControlBoundary",
        "TestMalformedAndOversizeFailClosed",
        "TestHandshakeSequenceAndEpochOverflow",
        "Frame(MessageType::kAuthChallenge, 0",
        "Frame(MessageType::kSessionReady, 1",
        "Frame(MessageType::kRouteProofRequest, 2",
        "Frame(MessageType::kArm, 4",
    }
    for token in sorted(required_tests):
        if token not in test:
            fail(f"missing focused endpoint test: {token}")

    if "CONFIG_MBEDTLS_SSL_PROTO_TLS1_2=y" not in defaults:
        fail("TLS 1.2 is not enabled in the skeleton defaults")
    for token in (
        "# CONFIG_MBEDTLS_SSL_PROTO_TLS1_3 is not set",
        "# CONFIG_SECURE_BOOT is not set",
        "# CONFIG_SECURE_FLASH_ENC_ENABLED is not set",
    ):
        if token not in defaults:
            fail(f"missing fail-closed Kconfig default: {token}")

    forbidden_app = {
        "esp_wifi_init",
        "esp_wifi_start",
        "esp_tls_conn_new",
        "mbedtls_ssl_handshake",
        "tinyusb_driver_install",
        "tud_hid_report",
    }
    for token in sorted(forbidden_app):
        if token in app:
            fail(f"compile-only skeleton gained live behavior: {token}")
    if "credentials absent; network and HID inactive" not in app:
        fail("compile-only runtime guard is missing")

    credential_patterns = (
        r"(?i)wifi_(?:password|passphrase)\s*=",
        r"(?i)link_secret\s*=",
        r"(?i)private_key\s*=",
        r"-----BEGIN (?:EC |RSA )?PRIVATE KEY-----",
    )
    production_text = header + source + app + defaults
    for pattern in credential_patterns:
        if re.search(pattern, production_text):
            fail(f"credential-like material found: {pattern}")


def validate_build(build: Path) -> None:
    sdkconfig = build / "config" / "sdkconfig.h"
    description = build / "project_description.json"
    flash_args = build / "flasher_args.json"
    for path in (sdkconfig, description, flash_args):
        if not path.is_file():
            fail(f"missing build artifact: {path}")

    config = sdkconfig.read_text(encoding="utf-8")
    for name, value in sorted(REQUIRED_CONFIG.items()):
        if not re.search(rf"^#define {re.escape(name)} {value}$", config, re.MULTILINE):
            fail(f"built skeleton requires {name}={value}")
    for name in (
        "CONFIG_MBEDTLS_SSL_PROTO_TLS1_3",
        "CONFIG_SECURE_BOOT",
        "CONFIG_SECURE_FLASH_ENC_ENABLED",
        "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK",
    ):
        if re.search(rf"^#define {re.escape(name)} 1$", config, re.MULTILINE):
            fail(f"built skeleton enabled {name}")

    project = json.loads(description.read_text(encoding="utf-8"))
    if project.get("target") != "esp32s3":
        fail("secure endpoint target is not ESP32-S3")
    if project.get("project_version") != "secure-endpoint-skeleton-v0":
        fail("unexpected secure endpoint project version")
    components = set(project.get("build_components", []))
    missing = sorted({"esp_wifi", "esp_netif", "kf_secure_endpoint", "main", "mbedtls"} - components)
    if missing:
        fail(f"missing compile-time endpoint components: {', '.join(missing)}")
    forbidden = sorted({"bt", "esp_http_server", "esp_https_server", "esp_tinyusb"} & components)
    if forbidden:
        fail(f"forbidden endpoint components: {', '.join(forbidden)}")

    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    match = re.search(r"^KEYFERRY_BOARD:STRING=([a-z0-9][a-z0-9_]*)$", cache, re.MULTILINE)
    if match is None:
        fail("secure endpoint build lacks a valid selected board profile")
    manifest = ROOT / "firmware" / "esp32s3" / "boards" / match.group(1) / "board.json"
    if not manifest.is_file():
        fail("secure endpoint selected board manifest is absent")

    flash = json.loads(flash_args.read_text(encoding="utf-8"))
    if flash.get("flash_files") != {
        "0x0": "bootloader/bootloader.bin",
        "0x8000": "partition_table/partition-table.bin",
        "0x10000": "keyferry_secure_endpoint.bin",
    }:
        fail("secure endpoint flash offsets differ from the qualified layout")
    if flash.get("flash_settings") != {
        "flash_mode": "dio",
        "flash_size": "16MB",
        "flash_freq": "80m",
    }:
        fail("secure endpoint flash settings differ from the qualified board")
    raw_flash = json.dumps(flash).lower()
    for token in ("--force", "erase_flash", "erase-region", "burn_efuse"):
        if token in raw_flash:
            fail(f"unsafe token in generated endpoint flash plan: {token}")

    compiler = Path(project["c_compiler"])
    nm = compiler.with_name(project["monitor_toolprefix"] + "nm" + compiler.suffix)
    app_elf = Path(project["app_elf"])
    if not app_elf.is_absolute():
        app_elf = build / app_elf
    component_archive = build / "esp-idf" / "kf_secure_endpoint" / "libkf_secure_endpoint.a"
    if not component_archive.is_file():
        fail(f"missing secure endpoint component archive: {component_archive}")
    component_symbols = subprocess.run(
        [str(nm), "-C", "-g", str(component_archive)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for token in (
        "keyferry::endpoint::EndpointSession::BeginTls",
        "keyferry::endpoint::EndpointSession::ConsumeTls",
        "keyferry::endpoint::ValidateTlsPolicy",
    ):
        if token not in component_symbols:
            fail(f"secure endpoint implementation is not linked: {token}")
    symbols = subprocess.run(
        [str(nm), "-C", "-g", str(app_elf)], check=True, capture_output=True, text=True
    ).stdout
    for token in ("esp_wifi_init", "esp_tls_conn_new", "tud_hid_report"):
        if token in symbols:
            fail(f"compile-only image gained live authority: {token}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    validate_source()
    if args.build_dir:
        validate_build(args.build_dir.resolve())
    print("check_secure_endpoint: ok")


if __name__ == "__main__":
    main()
