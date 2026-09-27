#!/usr/bin/env python3
"""Fail closed if the offline native-USB executor gains command or network authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "firmware" / "esp32s3" / "usb_executor"
APP_SOURCE = PROJECT / "main" / "app_main.cpp"
DEFAULTS = PROJECT / "sdkconfig.defaults"
MANIFEST = PROJECT / "main" / "idf_component.yml"

REQUIRED_DISABLED = {
    "CONFIG_ESP_CONSOLE_USB_CDC",
    "CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG",
    "CONFIG_SECURE_BOOT",
    "CONFIG_SECURE_FLASH_ENC_ENABLED",
    "CONFIG_TINYUSB_CDC_ENABLED",
    "CONFIG_TINYUSB_BTH_ENABLED",
    "CONFIG_TINYUSB_MSC_ENABLED",
}

REQUIRED_VALUES = {
    "CONFIG_ESP_CONSOLE_SECONDARY_NONE": "y",
    "CONFIG_TINYUSB_DFU_MODE_NONE": "y",
    "CONFIG_TINYUSB_HID_COUNT": "1",
    "CONFIG_TINYUSB_MIDI_COUNT": "0",
    "CONFIG_TINYUSB_NET_MODE_NONE": "y",
    "CONFIG_TINYUSB_VENDOR_COUNT": "0",
}

FORBIDDEN_COMPONENTS = {
    "bt",
    "esp_lcd",
    "esp_local_ctrl",
    "esp_wifi",
    "nvs_flash",
    "openthread",
    "protocomm",
    "spiffs",
    "wpa_supplicant",
}

FORBIDDEN_LINKED_SYMBOLS = {
    "esp_bt_controller_init",
    "esp_efuse_batch_write",
    "esp_efuse_set_write_protect",
    "esp_efuse_utility_burn_efuses",
    "esp_efuse_write",
    "esp_lcd_",
    "esp_netif_init",
    "esp_psram_init",
    "esp_wifi_init",
    "esp_vfs_fat_register",
    "esp_vfs_fat_sdmmc_mount",
    "esp_vfs_fat_spiflash_mount",
    "nvs_flash_init",
    "sdmmc_card_init",
    "wl_mount",
}

REPRODUCIBLE_ARTIFACTS = {
    "app": Path("keyferry_usb_executor.bin"),
    "bootloader": Path("bootloader/bootloader.bin"),
    "partition": Path("partition_table/partition-table.bin"),
}


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


def validate_source() -> None:
    defaults = DEFAULTS.read_text(encoding="utf-8")
    for name in sorted(REQUIRED_DISABLED):
        if config_value(defaults, name) != "n":
            fail(f"offline executor default must disable {name}")
    for name, expected in sorted(REQUIRED_VALUES.items()):
        if config_value(defaults, name) != expected:
            fail(f"offline executor default requires {name}={expected}")

    manifest = MANIFEST.read_text(encoding="utf-8")
    if 'idf: "==6.0.3"' not in manifest or 'espressif/esp_tinyusb: "==2.0.1~1"' not in manifest:
        fail("ESP-IDF and esp_tinyusb dependencies must be exactly pinned")

    source = APP_SOURCE.read_text(encoding="utf-8")
    required = {
        "TUD_HID_REPORT_DESC_KEYBOARD()",
        "HID_ITF_PROTOCOL_KEYBOARD",
        "tinyusb_driver_install",
        "tud_hid_report(0, &report, sizeof(report))",
    }
    for token in sorted(required):
        if token not in source:
            fail(f"offline executor is missing required USB behavior: {token}")
    for token in ("HID_REPORT_DESC_MOUSE", "HID_REPORT_DESC_CONSUMER", "REMOTE_WAKEUP", ".arm("):
        if token in source:
            fail(f"offline executor contains forbidden behavior: {token}")


def validate_build(build: Path) -> None:
    sdkconfig = build / "config" / "sdkconfig.h"
    description = build / "project_description.json"
    flash_args = build / "flasher_args.json"
    for path in (sdkconfig, description, flash_args):
        if not path.is_file():
            fail(f"missing build artifact: {path}")

    header = sdkconfig.read_text(encoding="utf-8")
    for name in sorted(REQUIRED_DISABLED):
        if re.search(rf"^#define {re.escape(name)}\s+1$", header, re.MULTILINE):
            fail(f"built offline executor enabled {name}")
    for name in (
        "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK",
        "CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES",
        "CONFIG_SECURE_BOOT_V1_ENABLED",
        "CONFIG_SECURE_BOOT_V2_ENABLED",
    ):
        if re.search(rf"^#define {re.escape(name)}\s+1$", header, re.MULTILINE):
            fail(f"built offline executor enabled {name}")
    for name, expected in sorted(REQUIRED_VALUES.items()):
        header_expected = "1" if expected == "y" else expected
        if not re.search(
            rf"^#define {re.escape(name)} {re.escape(header_expected)}$", header, re.MULTILINE
        ):
            fail(f"built offline executor requires {name}={expected}")

    project = json.loads(description.read_text(encoding="utf-8"))
    if project.get("target") != "esp32s3" or project.get("project_version") != "offline-executor-v0":
        fail("unexpected offline executor target or version")
    components = set(project.get("build_components", []))
    missing = sorted({"main", "kf_hid_core", "espressif__esp_tinyusb", "espressif__tinyusb"} - components)
    if missing:
        fail(f"missing executor components: {', '.join(missing)}")
    forbidden = sorted(components & FORBIDDEN_COMPONENTS)
    if forbidden:
        fail(f"forbidden components in offline executor: {', '.join(forbidden)}")

    cmake_cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    match = re.search(
        r"^KEYFERRY_BOARD:STRING=([a-z0-9][a-z0-9_]*)$", cmake_cache, re.MULTILINE
    )
    if match is None:
        fail("offline executor build lacks a valid selected board profile")
    manifest = ROOT / "firmware" / "esp32s3" / "boards" / match.group(1) / "board.json"
    if not manifest.is_file():
        fail("offline executor selected board manifest is absent")

    flash = json.loads(flash_args.read_text(encoding="utf-8"))
    if flash.get("flash_files") != {
        "0x0": "bootloader/bootloader.bin",
        "0x8000": "partition_table/partition-table.bin",
        "0x10000": "keyferry_usb_executor.bin",
    }:
        fail("offline executor flash offsets differ from the inspected single-app plan")
    raw_flash = json.dumps(flash).lower()
    if flash.get("flash_settings") != {
        "flash_mode": "dio",
        "flash_size": "16MB",
        "flash_freq": "80m",
    }:
        fail("offline executor flash settings differ from the selected board profile")
    for token in ("--force", "erase_flash", "erase-region", "burn_efuse"):
        if token in raw_flash:
            fail(f"unsafe token in generated executor flash plan: {token}")

    compiler = Path(project["c_compiler"])
    nm = compiler.with_name(project["monitor_toolprefix"] + "nm" + compiler.suffix)
    app_elf = Path(project["app_elf"])
    if not app_elf.is_absolute():
        app_elf = build / app_elf
    bootloader_elf = build / "bootloader" / "bootloader.elf"
    if not bootloader_elf.is_file():
        fail(f"missing build artifact: {bootloader_elf}")
    linked_symbols = {}
    for label, elf in (("application", app_elf), ("bootloader", bootloader_elf)):
        linked_symbols[label] = subprocess.run(
            [str(nm), "-g", str(elf)], check=True, capture_output=True, text=True
        ).stdout
        for token in sorted(FORBIDDEN_LINKED_SYMBOLS):
            if token in linked_symbols[label]:
                fail(f"forbidden linked symbol in offline executor {label}: {token}")
    symbols = linked_symbols["application"]
    for token in ("tinyusb_driver_install", "tud_hid_report"):
        if token not in symbols:
            fail(f"required linked USB symbol is missing: {token}")


def compare_builds(first: Path, second: Path) -> None:
    for label, relative in REPRODUCIBLE_ARTIFACTS.items():
        left = (first / relative).read_bytes()
        right = (second / relative).read_bytes()
        if left != right:
            fail(f"{label} differs between offline executor builds")
        print(f"{label}: sha256={hashlib.sha256(left).hexdigest().upper()} bytes={len(left)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--compare-build-dir", type=Path)
    args = parser.parse_args()
    validate_source()
    if args.build_dir:
        first = args.build_dir.resolve()
        validate_build(first)
        if args.compare_build_dir:
            second = args.compare_build_dir.resolve()
            validate_build(second)
            compare_builds(first, second)
    elif args.compare_build_dir:
        fail("--compare-build-dir requires --build-dir")
    print("check_usb_executor: ok")


if __name__ == "__main__":
    main()
