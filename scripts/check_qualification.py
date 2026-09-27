#!/usr/bin/env python3
"""Fail closed if the ESP32-S3 qualification image gains unsafe behavior."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = ROOT / "firmware" / "esp32s3"
DEFAULTS = FIRMWARE / "sdkconfig.defaults"
PARTITIONS = FIRMWARE / "partitions.csv"
IDF_VERSION = FIRMWARE / "IDF_VERSION"
DEPENDENCIES_LOCK = FIRMWARE / "dependencies.lock"

REQUIRED_DISABLED = {
    "CONFIG_ESP_CONSOLE_USB_CDC",
    "CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG",
    "CONFIG_SECURE_BOOT",
    "CONFIG_SECURE_FLASH_ENC_ENABLED",
}

FORBIDDEN_COMPONENTS = {
    "bt",
    "esp_hid",
    "esp_lcd",
    "esp_local_ctrl",
    "esp_psram",
    "esp_wifi",
    "fatfs",
    "nvs_flash",
    "openthread",
    "protocomm",
    "sdmmc",
    "spiffs",
    "wear_levelling",
    "wpa_supplicant",
}

FORBIDDEN_ENABLED_CONFIG = {
    "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK",
    "CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES",
    "CONFIG_SECURE_BOOT_V1_ENABLED",
    "CONFIG_SECURE_BOOT_V2_ECDSA_ENABLED",
    "CONFIG_SECURE_BOOT_V2_ENABLED",
    "CONFIG_SECURE_BOOT_V2_RSA_ENABLED",
}

FORBIDDEN_LINKED_SYMBOLS = {
    "esp_bt_controller_init",
    "esp_efuse_batch_write",
    "esp_efuse_set_write_protect",
    "esp_efuse_utility_burn_efuses",
    "esp_efuse_write",
    "esp_lcd_",
    "esp_wifi_init",
    "nvs_flash_init",
    "tinyusb_driver_install",
    "tud_hid_",
}

REPRODUCIBLE_ARTIFACTS = {
    "app": Path("keyferry_qualification.bin"),
    "bootloader": Path("bootloader/bootloader.bin"),
    "partition": Path("partition_table/partition-table.bin"),
}

FORBIDDEN_SOURCE = {
    "tinyusb",
    "tusb_",
    "usb_hid",
    "esp_wifi",
    "esp_bt",
    "nimble",
    "nvs_flash",
    "esp_efuse",
    "secure_boot",
    "flash_encrypt",
    "st7789",
    "esp_lcd",
    "sdmmc",
    "fatfs",
}

BOARD_SPECIFIC = re.compile(r"waveshare|st7789|\bgpio\d+\b", re.IGNORECASE)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def config_value(text: str, name: str) -> str | None:
    enabled = re.search(rf"^{re.escape(name)}=(.+)$", text, re.MULTILINE)
    if enabled:
        return enabled.group(1).strip()
    if re.search(rf"^# {re.escape(name)} is not set$", text, re.MULTILINE):
        return "n"
    return None


def validate_defaults() -> None:
    text = DEFAULTS.read_text(encoding="utf-8")
    for name in sorted(REQUIRED_DISABLED):
        if config_value(text, name) != "n":
            fail(f"qualification default must disable {name}")


def validate_sources() -> None:
    app_source = (FIRMWARE / "main" / "app_main.cpp").read_text(encoding="utf-8")
    if "KEYFERRY_QUALIFICATION_IMAGE" not in app_source:
        fail("qualification source guard is missing")

    qualification_sources = [
        path
        for path in (FIRMWARE / "main").rglob("*")
        if path.is_file()
        and path.suffix.lower() in {".c", ".cc", ".cpp", ".h", ".hpp"}
    ]
    for path in qualification_sources:
        source = path.read_text(encoding="utf-8")
        lowered = source.lower()
        for token in sorted(FORBIDDEN_SOURCE):
            if token in lowered:
                fail(f"qualification source contains forbidden token {token!r}: {path.relative_to(ROOT)}")
        if BOARD_SPECIFIC.search(source):
            fail(f"board-specific fact escaped the profile: {path.relative_to(ROOT)}")


def validate_toolchain_pin() -> None:
    version = IDF_VERSION.read_text(encoding="utf-8")
    lock = DEPENDENCIES_LOCK.read_text(encoding="utf-8")
    cmake = (FIRMWARE / "CMakeLists.txt").read_text(encoding="utf-8")
    if "tag = v6.0.3" not in version or "76f5dedd9950a3012fee8fb7d5586df21fc67802" not in version:
        fail("ESP-IDF tag and commit are not exactly pinned")
    if not re.search(r"^\s+version: 6\.0\.3$", lock, re.MULTILINE):
        fail("dependencies.lock does not pin ESP-IDF 6.0.3")
    if "idf_build_set_property(MINIMAL_BUILD ON)" not in cmake:
        fail("qualification build must use ESP-IDF minimal-build mode")


def validate_partitions() -> None:
    rows = []
    with PARTITIONS.open(encoding="utf-8", newline="") as stream:
        for row in csv.reader(line for line in stream if not line.lstrip().startswith("#")):
            if row and any(cell.strip() for cell in row):
                rows.append([cell.strip() for cell in row])
    if rows != [["factory", "app", "factory", "0x10000", "1M", ""]]:
        fail(f"qualification partition table must contain one factory app only: {rows!r}")


def validate_build(build: Path) -> None:
    sdkconfig = (build / "config" / "sdkconfig.h")
    description = build / "project_description.json"
    flash_args = build / "flasher_args.json"
    for path in (sdkconfig, description, flash_args):
        if not path.is_file():
            fail(f"missing build artifact: {path}")

    header = sdkconfig.read_text(encoding="utf-8")
    for name in sorted(REQUIRED_DISABLED):
        if re.search(rf"^#define {re.escape(name)}\s+1$", header, re.MULTILINE):
            fail(f"built qualification image enabled {name}")
    for name in sorted(FORBIDDEN_ENABLED_CONFIG):
        if re.search(rf"^#define {re.escape(name)}\s+1$", header, re.MULTILINE):
            fail(f"built qualification image enabled {name}")

    project = json.loads(description.read_text(encoding="utf-8"))
    if project.get("target") != "esp32s3":
        fail(f"unexpected IDF target: {project.get('target')!r}")
    if project.get("project_version") != "qualification-v0":
        fail(f"unexpected qualification version: {project.get('project_version')!r}")
    components = set(project.get("build_components", []))
    forbidden = sorted(components & FORBIDDEN_COMPONENTS)
    if forbidden:
        fail(f"forbidden components in qualification build: {', '.join(forbidden)}")
    if not {"main", "esp_stdio", "freertos"}.issubset(components):
        fail("qualification component graph is incomplete")

    for name in (
        "CONFIG_ESP_CONSOLE_UART_DEFAULT",
        "CONFIG_ESP_CONSOLE_SECONDARY_USB_SERIAL_JTAG",
        "CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG_ENABLED",
    ):
        if not re.search(rf"^#define {re.escape(name)}\s+1$", header, re.MULTILINE):
            fail(f"built qualification image must enable {name}")

    flash = flash_args.read_text(encoding="utf-8").lower()
    for token in ("--force", "erase_flash", "erase-region", "burn_efuse"):
        if token in flash:
            fail(f"unsafe token in generated flash plan: {token}")

    compiler = Path(project["c_compiler"])
    nm = compiler.with_name(project["monitor_toolprefix"] + "nm" + compiler.suffix)
    app_elf = Path(project["app_elf"])
    if not app_elf.is_absolute():
        app_elf = build / app_elf
    if not nm.is_file() or not app_elf.is_file():
        fail("cannot inspect linked qualification symbols")
    symbols = subprocess.run(
        [str(nm), "-g", str(app_elf)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for token in sorted(FORBIDDEN_LINKED_SYMBOLS):
        if token in symbols:
            fail(f"forbidden linked symbol in qualification image: {token}")


def compare_builds(first: Path, second: Path) -> None:
    for label, relative in REPRODUCIBLE_ARTIFACTS.items():
        left = (first / relative).read_bytes()
        right = (second / relative).read_bytes()
        if left != right:
            fail(f"{label} differs between qualification builds")
        digest = hashlib.sha256(left).hexdigest().upper()
        print(f"{label}: sha256={digest} bytes={len(left)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--compare-build-dir", type=Path)
    args = parser.parse_args()
    validate_defaults()
    validate_sources()
    validate_toolchain_pin()
    validate_partitions()
    if args.build_dir:
        first = args.build_dir.resolve()
        validate_build(first)
        if args.compare_build_dir:
            second = args.compare_build_dir.resolve()
            validate_build(second)
            compare_builds(first, second)
    elif args.compare_build_dir:
        fail("--compare-build-dir requires --build-dir")
    print("check_qualification: ok")


if __name__ == "__main__":
    main()
