#!/usr/bin/env python3
"""Freeze one off-device Wi-Fi image; never open a device or authorize a write."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import check_msc_size_probe as inspector


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--size-json", type=Path,
                        help="ESP-IDF size --format json2 output for static RAM evidence")
    parser.add_argument("--build-command", help="Exact offline command used to build this image")
    args = parser.parse_args()
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], check=True)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    inspector.inspect_file_handoff(args.build)
    cache = (args.build / "CMakeCache.txt").read_text(encoding="utf-8")
    if "KEYFERRY_BOARD:STRING=waveshare_geek_v1_1_reference\n" not in cache:
        raise SystemExit("not the requested Waveshare profile")
    pointer = "KEYFERRY_POINTER_EXTENDED:BOOL=ON\n" in cache
    descriptor_check = None
    if pointer:
        descriptor_check = subprocess.check_output([
            sys.executable, str(Path(__file__).with_name("check_hil_pointer.py")),
            "--build-dir", str(args.build),
        ], text=True)
    static_memory = None
    if args.size_json:
        size = json.loads(args.size_json.read_text(encoding="utf-8-sig"))
        static_memory = size.get("layout") if isinstance(size, dict) else None
        if not isinstance(static_memory, list) or not any(
                row.get("name") == "DIRAM" and all(
                    isinstance(row.get(field), int) and row[field] >= 0
                    for field in ("used", "free", "total"))
                and row["used"] + row["free"] == row["total"]
                for row in static_memory if isinstance(row, dict)):
            raise SystemExit("static size evidence lacks valid DIRAM counts")
    args.output.mkdir(parents=True, exist_ok=False)
    members = (
        "keyferry_hil_endpoint.bin", "keyferry_hil_endpoint.elf",
        "keyferry_hil_endpoint.map", "CMakeCache.txt", "sdkconfig",
        "flasher_args.json", "bootloader/bootloader.bin",
        "partition_table/partition-table.bin",
    )
    artifacts = {}
    for name in members:
        source = args.build / name
        if source.is_symlink() or not source.is_file():
            raise SystemExit(f"missing or linked artifact: {name}")
        destination = args.output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        artifacts[name] = {
            "bytes": destination.stat().st_size,
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        }
    receipt = {
        "schema": "keyferry.wifi-build.v1", "source_head": head,
        "producer": "scripts/freeze_wifi_build.py",
        "board": "waveshare_geek_v1_1_reference",
        "version": inspector.app_version(args.build / members[0]).decode("ascii"),
        "artifacts": artifacts,
        "app_headroom_bytes": 0x200000 - artifacts[members[0]]["bytes"],
        "hardware_writes": False, "physical_gate": "OPEN",
        "update_plan": "requires exact installed build and installed plan",
    }
    if descriptor_check is not None:
        (args.output / "descriptor-check.txt").write_text(
            descriptor_check, encoding="utf-8", newline="\n")
        receipt["descriptor_check"] = descriptor_check
    if static_memory is not None:
        receipt["static_memory"] = static_memory
        receipt["runtime_heap"] = "NOT_MEASURED: static RAM is not runtime heap"
    if args.build_command:
        receipt["build_command"] = args.build_command
    (args.output / "build-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
