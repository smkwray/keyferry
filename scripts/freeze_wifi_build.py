#!/usr/bin/env python3
"""Freeze one off-device Wi-Fi image; never open a device or authorize a write."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import check_msc_size_probe as inspector


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], check=True)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    inspector.inspect_file_handoff(args.build)
    cache = (args.build / "CMakeCache.txt").read_text(encoding="utf-8")
    if "KEYFERRY_BOARD:STRING=waveshare_geek_v1_1_reference\n" not in cache:
        raise SystemExit("not the requested Waveshare profile")
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
    (args.output / "build-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
