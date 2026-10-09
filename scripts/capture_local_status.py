#!/usr/bin/env python3
"""Hushrun recipient: inherit secret stdin, retain only typed USB status metadata."""

import argparse
import json
from pathlib import Path
import subprocess
import uuid


def status_document(raw: bytes, device: str) -> dict:
    if len(raw) > 16384:
        raise ValueError("oversized status")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result
    document = json.loads(raw, object_pairs_hook=unique)
    pages = {"device", "safety", "network", "ble_hid", "policy", "last_receipt", "wifi_diagnostic"}
    if (not isinstance(document, dict)
            or document.get("schema") != "keyferry.local-status.v1"
            or document.get("device_id") != uuid.UUID(device).hex
            or set(document) != pages | {"schema", "device_id"}):
        raise ValueError("unexpected status document")
    # The trusted Rust helper validates the wire. As a second persistence guard,
    # only scalar metadata, the bounded release, and registered reason may be strings.
    from gen_protocol import parse_registry
    reasons = {entry.name.lower() for entry in parse_registry().sections["wifi_reject_reasons"]}
    for page in pages & document.keys():
        values = document[page]
        if values is None and page in {"last_receipt", "wifi_diagnostic"}:
            continue
        if not isinstance(values, dict):
            raise ValueError("invalid status page")
        for key, value in values.items():
            if type(value) in (bool, int):
                continue
            if page == "device" and key == "release" and isinstance(value, str):
                if 1 <= len(value) <= 8 and all(0x20 <= ord(char) <= 0x7E for char in value):
                    continue
            if page == "wifi_diagnostic" and key == "last_wifi_reject_reason" and value in reasons:
                continue
            raise ValueError("non-metadata status value")
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keyctl", required=True, type=Path)
    parser.add_argument("--owner-kit", required=True, type=Path)
    parser.add_argument("--device", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.keyctl.is_absolute() or args.output.exists():
        raise ValueError("absolute executable and unused output required")
    result = subprocess.run(
        [str(args.keyctl), "local-status", "--owner-kit", str(args.owner_kit), "--device", args.device],
        stdin=None, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, check=False)
    if result.returncode:
        return 10
    document = status_document(result.stdout, args.device)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(document, output, sort_keys=True)
        output.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        raise SystemExit(20)
