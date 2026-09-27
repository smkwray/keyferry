#!/usr/bin/env python3
"""Rename the provisional project in text paths and text contents.

Run from an extracted seed before substantive implementation. The outer directory is not renamed.
"""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)?$")
TEXT_SUFFIXES = {
    "",
    ".md",
    ".toml",
    ".yaml",
    ".yml",
    ".json",
    ".rs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".ini",
    ".py",
    ".slint",
    ".txt",
}
SKIP_PARTS = {".git", "target", ".pio", "dist", "release"}


def validate(name: str) -> None:
    if not 3 <= len(name) <= 9:
        raise SystemExit("name must contain 3–9 characters")
    if not NAME_RE.fullmatch(name):
        raise SystemExit("name must be lowercase ASCII letters/numbers with at most one internal hyphen")


def paths() -> list[Path]:
    return [
        path
        for path in ROOT.rglob("*")
        if not any(part in SKIP_PARTS for part in path.relative_to(ROOT).parts)
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("new_name")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    validate(args.new_name)

    project = tomllib.loads((ROOT / "project.toml").read_text(encoding="utf-8"))
    old = project["working_name"]
    new = args.new_name
    if old == new:
        print("name is already set")
        return

    replacements = [
        (old.upper(), new.upper()),
        (old.capitalize(), new.capitalize()),
        (old, new),
    ]

    text_changes: list[Path] = []
    for path in paths():
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            original = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        updated = original
        for before, after in replacements:
            updated = updated.replace(before, after)
        if updated != original:
            text_changes.append(path)
            if not args.dry_run:
                path.write_text(updated, encoding="utf-8", newline="\n")

    rename_pairs: list[tuple[Path, Path]] = []
    for path in sorted(paths(), key=lambda value: len(value.parts), reverse=True):
        new_name = path.name
        for before, after in replacements:
            new_name = new_name.replace(before, after)
        if new_name != path.name:
            rename_pairs.append((path, path.with_name(new_name)))

    print(f"content updates: {len(text_changes)}")
    for path in text_changes:
        print("  text ", path.relative_to(ROOT))
    print(f"path renames: {len(rename_pairs)}")
    for source, destination in rename_pairs:
        print("  path ", source.relative_to(ROOT), "->", destination.relative_to(ROOT))
        if not args.dry_run:
            source.rename(destination)

    if not args.dry_run:
        print("rename complete; run python scripts/check.py --strict")


if __name__ == "__main__":
    main()
