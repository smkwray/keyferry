#!/usr/bin/env python3
"""Report prerequisites without silently installing or changing the host."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TOOLS = [
    ("python", [sys.executable], True),
    ("cargo", ["cargo"], True),
    ("C++17 compiler", ["g++", "clang++", "cl"], True),
    ("ESP-IDF", ["idf.py"], False),
    ("esptool", ["esptool.py", "esptool"], False),
    ("espefuse", ["espefuse.py", "espefuse"], False),
]


def first_found(candidates: list[str]) -> str | None:
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def main() -> None:
    print(f"Repository: {ROOT}")
    missing_required = False
    for label, candidates, required in TOOLS:
        if label == "python":
            found = sys.executable
        else:
            found = first_found(candidates)
        state = found or ("MISSING" if required else "not installed yet")
        print(f"{label:18} {state}")
        missing_required |= required and not bool(found)

    print()
    print("Host/protocol work needs Python, Rust, and a C++17 compiler.")
    print("The qualification build uses pinned ESP-IDF v6.0.3; hardware writes remain separately gated.")
    print("This script never installs packages or alters the system.")
    if missing_required:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
