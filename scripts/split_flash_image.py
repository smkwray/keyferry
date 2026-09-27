#!/usr/bin/env python3
"""Split an Intel HEX flash image at a boundary address.

Caterina (AVR109) cannot rewrite its own boot section, so a full-flash backup
must be truncated to the application region before it is restored. Emits the
records strictly below --boundary and reports the split.

  python scripts/split_flash_image.py IN.hex OUT.hex --boundary 0x7000
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def parse(line: str) -> tuple[int, int, int]:
    count = int(line[1:3], 16)
    addr = int(line[3:7], 16)
    rtype = int(line[7:9], 16)
    return count, addr, rtype


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source", type=Path)
    ap.add_argument("dest", type=Path)
    ap.add_argument("--boundary", required=True)
    args = ap.parse_args()

    boundary = int(args.boundary, 0)
    kept: list[str] = []
    dropped = 0
    for raw in args.source.read_text().splitlines():
        line = raw.strip()
        if not line.startswith(":"):
            continue
        count, addr, rtype = parse(line)
        if rtype == 1:
            continue
        if rtype != 0:
            raise SystemExit(f"unsupported record type {rtype:#04x}: {line}")
        if addr + count > boundary:
            if addr < boundary:
                raise SystemExit(f"record straddles boundary: {line}")
            dropped += 1
            continue
        kept.append(line)

    if not kept:
        raise SystemExit("no records below boundary")
    args.dest.write_text("\n".join(kept) + "\n:00000001FF\n")
    print(f"kept {len(kept)} records below {boundary:#06x}, dropped {dropped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
