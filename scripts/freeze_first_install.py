#!/usr/bin/env python3
"""Freeze an IDF build and its first-install proposal. Never accesses hardware."""
import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def freeze(build, output, idf_root):
    description = json.loads((build / "project_description.json").read_text())
    flash = json.loads((build / "flasher_args.json").read_text())
    sizes = {"8MB": 8*1024*1024, "16MB": 16*1024*1024}
    flash_bytes = sizes.get(flash["flash_settings"]["flash_size"])
    if description["target"] != "esp32s3" or flash_bytes is None:
        raise ValueError("expected ESP32-S3 and supported 8/16 MB flash")
    spec = importlib.util.spec_from_file_location("gen_esp32part", idf_root/"components/partition_table/gen_esp32part.py")
    decoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decoder)
    table = decoder.PartitionTable.from_binary((build/"partition_table/partition-table.bin").read_bytes())
    decoder.offset_part_table = int(flash["partition-table"]["offset"], 0)
    table.verify()
    table.verify_size_fits(flash_bytes)
    apps = [p for p in table if p.type == decoder.APP_TYPE]
    if len(apps) != 1 or apps[0].offset != 0x10000 or apps[0].subtype != 0:
        raise ValueError("expected one factory app at 0x10000")
    records = []
    for address, relative in sorted(flash["flash_files"].items(), key=lambda item: int(item[0], 0)):
        data = (build/relative).read_bytes()
        if int(address, 0) + len(data) > flash_bytes:
            raise ValueError("flash image exceeds device")
        records.append(dict(offset=int(address, 0), file=relative, size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    if {item["offset"] for item in records} != {0, 0x8000, 0x10000}:
        raise ValueError("unexpected first-install write set")
    app_size = next(item["size_bytes"] for item in records if item["offset"] == apps[0].offset)
    if apps[0].size - app_size < 32768:
        raise ValueError("less than 32 KiB app headroom")
    state = sorted([p for p in table if p.name in {"kf_cfg_a", "kf_cfg_b", "nvs"}], key=lambda p: p.offset)
    erases = []
    if state:
        if len(state) != 3 or any(a.offset+a.size != b.offset for a,b in zip(state,state[1:])):
            raise ValueError("configuration partitions must be one exact contiguous range")
        erases = [dict(offset=state[0].offset, size_bytes=sum(p.size for p in state), reason="first-install configuration and NVS initialization")]
    project = description["project_name"]
    artifacts = [item["file"] for item in records] + [f"{project}.elf", f"{project}.map", "sdkconfig", "flash_args", "flasher_args.json", "project_description.json", "generated-board/board_profile.h"]
    if (build/"size-summary.json").is_file(): artifacts.append("size-summary.json")
    if output.exists(): raise ValueError("frozen output already exists; choose a new output directory")
    output.mkdir(parents=True)
    hashes = {}
    for relative in artifacts:
        target = output/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(build/relative, target)
        hashes[relative] = dict(size_bytes=target.stat().st_size, sha256=hashlib.sha256(target.read_bytes()).hexdigest())
    version = description["project_version"]
    plan = dict(schema="keyferry.first-install-plan.v1", status="DRY_RUN_ONLY",
                artifact_role="RECOVERY_QUALIFICATION" if project == "keyferry_qualification" else "RESOURCE_ONLY_NEVER_FLASH" if "probe" in version.split("-")[-1].split(".") else "DEVICE_PRIVATE_CANDIDATE",
                hardware_authorized=False, version=version, producer_commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT).decode().strip(),
                flash_settings=flash["flash_settings"], flash_size_bytes=flash_bytes,
                erase_before_first_install=erases, writes=records,
                application_slot_bytes=apps[0].size, application_headroom_bytes=apps[0].size-app_size,
                artifacts=hashes)
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    plan["proposal_sha256"] = hashlib.sha256(canonical).hexdigest()
    (output/"first-install-plan.json").write_text(json.dumps(plan,indent=2)+"\n")
    print(json.dumps({"status":"FROZEN_OFFLINE", "artifact_role":plan["artifact_role"], "proposal_sha256":plan["proposal_sha256"]}))
    return plan


def main():
    parser=argparse.ArgumentParser()
    for name in ("build", "output", "idf-root"): parser.add_argument("--"+name, required=True, type=Path)
    args=parser.parse_args()
    freeze(args.build.resolve(), args.output.resolve(), args.idf_root.resolve())


if __name__ == "__main__": main()
