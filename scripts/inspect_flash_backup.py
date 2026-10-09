#!/usr/bin/env python3
"""Offline factory-layout inspection using the pinned IDF partition decoder.

Never opens a port or writes a device. Only table metadata leaves this process.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def inspect(snapshot, idf_root):
    decoder = idf_root / "components/partition_table/gen_esp32part.py"
    spec = importlib.util.spec_from_file_location("gen_esp32part", decoder)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    data = snapshot.read_bytes()
    if len(data) != 8 * 1024 * 1024:
        raise ValueError("backup must contain exactly 8 MiB")
    found = []
    for offset in range(0, len(data), 4096):
        if data[offset:offset+2] != b"\xaa\x50":
            continue
        try:
            table = module.PartitionTable.from_binary(data[offset:offset+0xC00])
            module.offset_part_table = offset
            table.verify()
            if not table or any(p.offset+p.size > len(data) for p in table):
                continue
            apps = [p for p in table if p.type == module.APP_TYPE]
            if not apps or any(data[p.offset] != 0xE9 for p in apps):
                continue
            found.append((offset, table))
        except (ValueError, module.InputError):
            continue
    if len(found) != 1:
        raise ValueError("factory partition table is absent or ambiguous")
    offset, table = found[0]
    return {
        "schema": "keyferry.factory-layout.v1", "status": "INSPECTED_OFFLINE",
        "flash_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "partition_table_offset": offset,
        "partitions": [dict(name=p.name, type=p.type, subtype=p.subtype,
                            offset=p.offset, size=p.size) for p in table],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--idf-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = inspect(args.snapshot, args.idf_root)
    except Exception:
        print(json.dumps({"status": "REJECTED", "error": "factory_layout_invalid"}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
