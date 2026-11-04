#!/usr/bin/env python3
"""Fail-closed inspection for BLE HID production and resource-spike builds."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_RESERVE_BYTES = 32 * 1024
MD5_ENTRY_MAGIC = b"\xeb\xeb"


def partition_tool():
    """The pinned ESP-IDF partition parser (IDF_PATH when exported, else the project toolchain)."""
    idf = Path(os.environ.get("IDF_PATH") or ROOT / ".tools/esp-idf-v6.0.3")
    path = idf / "components/partition_table/gen_esp32part.py"
    if not path.is_file():
        raise SystemExit(f"BLE HID spike partition tool absent: {path}")
    spec = importlib.util.spec_from_file_location("keyferry_gen_esp32part", path)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    tool.quiet = True
    return tool


def factory_app_bytes(table_path: Path, table_offset: int) -> int:
    """Size of the single factory app partition in the build's own compiled, verified table."""
    if not table_path.is_file():
        raise SystemExit(f"BLE HID spike partition table absent: {table_path}")
    data = table_path.read_bytes()
    if not any(data[offset:offset + 2] == MD5_ENTRY_MAGIC for offset in range(0, len(data), 32)):
        raise SystemExit("BLE HID spike partition table has no MD5 entry")
    tool = partition_tool()
    tool.md5sum = True
    tool.offset_part_table = table_offset
    try:
        table = tool.PartitionTable.from_binary(data)
        table.verify()
    except tool.InputError as error:
        raise SystemExit(f"BLE HID spike partition table invalid: {error}") from None
    factories = [entry for entry in table if entry.type == tool.APP_TYPE and entry.subtype == 0]
    if len(factories) != 1:
        raise SystemExit(f"BLE HID spike needs exactly one factory app partition: found {len(factories)}")
    return factories[0].size


def table_offset_from(config: str) -> int:
    for line in config.splitlines():
        if line.startswith("CONFIG_PARTITION_TABLE_OFFSET="):
            return int(line.split("=", 1)[1], 0)
    raise SystemExit("BLE HID spike sdkconfig missing CONFIG_PARTITION_TABLE_OFFSET")


def require_line(config: str, line: str) -> None:
    if line not in config.splitlines():
        raise SystemExit(f"BLE HID spike sdkconfig missing: {line}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--level", required=True, choices=("security", "hid"))
    args = parser.parse_args()

    sdkconfig_path = args.build_dir / "sdkconfig"
    binary_path = args.build_dir / "keyferry_hil_endpoint.bin"
    map_path = args.build_dir / "keyferry_hil_endpoint.map"
    if not sdkconfig_path.is_file():
        raise SystemExit(f"BLE HID spike sdkconfig absent: {sdkconfig_path}")
    if not binary_path.is_file():
        raise SystemExit(f"BLE HID spike binary absent: {binary_path}")
    if not map_path.is_file():
        raise SystemExit(f"BLE HID spike map absent: {map_path}")

    config = sdkconfig_path.read_text(encoding="utf-8")
    for line in (
        "CONFIG_BT_NIMBLE_SECURITY_ENABLE=y",
        "# CONFIG_BT_NIMBLE_SM_LEGACY is not set",
        "CONFIG_BT_NIMBLE_SM_SC=y",
        "# CONFIG_BT_NIMBLE_SM_SC_DEBUG_KEYS is not set",
        "CONFIG_BT_NIMBLE_LL_CFG_FEAT_LE_ENCRYPTION=y",
        "CONFIG_BT_NIMBLE_SM_LVL=3",
        "CONFIG_BT_NIMBLE_SM_SC_ONLY=1",
        "CONFIG_BT_NIMBLE_NVS_PERSIST=y",
        "CONFIG_BT_NIMBLE_MAX_BONDS=2",
        "CONFIG_BT_NIMBLE_MAX_CCCDS=4",
        "# CONFIG_BT_NIMBLE_HANDLE_REPEAT_PAIRING_DELETION is not set",
        "CONFIG_BT_NIMBLE_HS_PVCY=y",
        "CONFIG_BT_CTRL_BLE_SECURITY_ENABLE=y",
        "CONFIG_BT_NIMBLE_MAX_CONNECTIONS=1",
        "CONFIG_BT_CTRL_BLE_MAX_ACT=2",
    ):
        require_line(config, line)

    if args.level == "hid":
        for line in (
            "CONFIG_BT_NIMBLE_HID_SERVICE=y",
            "CONFIG_BT_NIMBLE_SVC_HID_MAX_INSTANCES=1",
            "CONFIG_BT_NIMBLE_SVC_HID_MAX_RPTS=2",
            "# CONFIG_BT_NIMBLE_BAS_SERVICE is not set",
            "# CONFIG_BT_NIMBLE_DIS_SERVICE is not set",
            "CONFIG_BT_NIMBLE_GAP_SERVICE=y",
        ):
            require_line(config, line)

        link_map = map_path.read_text(encoding="utf-8", errors="strict")
        for symbol in (
            "keyferry::ble_hid::IdfBleHidPeripheral::Initialize()",
            "keyferry::ble_hid::IdfBleHidPeripheral::Submit(",
            "keyferry::ble_hid::ReleaseBurst::Start(",
            "keyferry::ble_hid::ReleaseBurst::MarkZeroAccepted(",
            "ble_svc_hid_add",
            "ble_gatts_notify_custom",
        ):
            if symbol not in link_map:
                raise SystemExit(
                    f"BLE HID spike did not retain required linked symbol: {symbol}"
                )

        source_root = Path(__file__).resolve().parents[1]
        peripheral_source = (
            source_root
            / "firmware/esp32s3/components/kf_ble_hid/src/idf_ble_hid_peripheral.cpp"
        ).read_text(encoding="utf-8")
        for token in (
            "security_rc != 0 && security_rc != BLE_HS_EALREADY",
            "ble_gap_security_initiate(event->connect.conn_handle)",
            "BondStoreStatus IdfBleHidPeripheral::bond_status() const",
            "BondStoreState::kMultipleInvalid",
            "ResetBondAndEnroll",
            "CancelEnrollment",
            "g_state.enrollment.Poll(now_ms)",
        ):
            if token not in peripheral_source:
                raise SystemExit(
                    "BLE HID pairing no longer tolerates concurrent security start: "
                    f"missing {token}"
                )

        runtime_source = (
            source_root / "firmware/esp32s3/hil_endpoint/main/app_main.cpp"
        ).read_text(encoding="utf-8")
        for token in (
            "OutputReadyLocked() &&",
            "hid_.on_transport_ready();",
            "hid_.on_transport_lost();",
            "bool ble_transport_ready_{false};",
        ):
            if token not in runtime_source:
                raise SystemExit(
                    "BLE HID runtime lost its control/output lifecycle separation: "
                    f"missing {token}"
                )

    app_partition_bytes = factory_app_bytes(
        args.build_dir / "partition_table/partition-table.bin", table_offset_from(config))
    max_image_bytes = app_partition_bytes - APP_RESERVE_BYTES
    size = binary_path.stat().st_size
    if size > max_image_bytes:
        raise SystemExit(
            "BLE HID spike exceeded the app reserve gate: "
            f"bytes={size} maximum={max_image_bytes}"
        )
    remaining = app_partition_bytes - size
    growth_before_reserve = max_image_bytes - size
    print(
        "check_ble_hid_spike: ok "
        f"level={args.level} bytes={size} raw_free={remaining} "
        f"growth_before_32k_reserve={growth_before_reserve}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
