#!/usr/bin/env python3
"""Compare a Windows-extracted icon with the matching frame in its source ICO."""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageChops


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--extracted", type=Path, required=True)
    args = parser.parse_args()

    with Image.open(args.extracted) as extracted_file:
        extracted = extracted_file.convert("RGBA")
    with Image.open(args.source) as source_file:
        if not hasattr(source_file, "ico"):
            parser.error("source is not a multi-frame ICO")
        available = source_file.ico.sizes()
        if extracted.size not in available:
            parser.error(
                f"source ICO has no {extracted.width}x{extracted.height} frame"
            )
        source = source_file.ico.getimage(extracted.size).convert("RGBA")

    if ImageChops.difference(source, extracted).getbbox() is not None:
        parser.error("embedded Windows controller icon does not match the source ICO")
    print(f"embedded Windows icon: ok ({extracted.width}x{extracted.height})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
