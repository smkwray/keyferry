#!/usr/bin/env python3
"""Generate desktop icon formats from the two committed masters.

Producer for everything under apps/keyferry/assets/icons/ except the masters
themselves. Re-runnable and deterministic:

    python scripts/gen_icons.py

Masters (committed, hand-supplied):
    keyferry-desktop.png     transparent-corner app squircle
    keyferry-tray-black.png  menubar/tray glyph for light bars
    keyferry-tray-white.png  menubar/tray glyph for dark bars
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
ICONS = ROOT / "apps/keyferry/assets/icons"

# Windows .ico carries every size in one file.
ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]
# Apple's .icns set. Names are fixed by the .iconset convention.
ICNS_SIZES = [16, 32, 64, 128, 256, 512, 1024]
# Freedesktop hicolor sizes worth shipping.
LINUX_SIZES = [48, 128, 256, 512]
# Notification area / menubar. 16 and 32 cover Windows @1x/@2x; 18/36 macOS.
TRAY_SIZES = [16, 18, 24, 32, 36]



def resized(master: Image.Image, size: int) -> Image.Image:
    return master.resize((size, size), Image.LANCZOS)


def main() -> None:
    desktop = Image.open(ICONS / "keyferry-desktop.png").convert("RGBA")
    written: list[str] = []

    # Windows: one multi-resolution .ico
    ico = ICONS / "keyferry.ico"
    desktop.save(ico, format="ICO", sizes=[(s, s) for s in ICO_SIZES])
    written.append(f"{ico.name} ({','.join(str(s) for s in ICO_SIZES)})")

    # macOS: .icns if Pillow can write it here, otherwise the .iconset that
    # `iconutil -c icns` consumes on a Mac.
    try:
        icns = ICONS / "keyferry.icns"
        desktop.save(icns, format="ICNS")
        written.append(icns.name)
    except Exception as error:  # noqa: BLE001 - platform-dependent encoder
        iconset = ICONS / "keyferry.iconset"
        iconset.mkdir(exist_ok=True)
        for size in ICNS_SIZES:
            if size <= 512:
                resized(desktop, size).save(iconset / f"icon_{size}x{size}.png")
            if size >= 32:
                half = size // 2
                resized(desktop, size).save(iconset / f"icon_{half}x{half}@2x.png")
        written.append(f"keyferry.iconset/ (no .icns encoder here: {type(error).__name__})")

    # Linux: individual hicolor PNGs
    png_dir = ICONS / "png"
    png_dir.mkdir(exist_ok=True)
    for size in LINUX_SIZES:
        resized(desktop, size).save(png_dir / f"keyferry-{size}.png")
    written.append("png/keyferry-{" + ",".join(str(s) for s in LINUX_SIZES) + "}.png")

    # Tray, both polarities
    tray_dir = ICONS / "tray"
    tray_dir.mkdir(exist_ok=True)
    for polarity in ("black", "white"):
        master = Image.open(ICONS / f"keyferry-tray-{polarity}.png").convert("RGBA")
        for size in TRAY_SIZES:
            resized(master, size).save(tray_dir / f"keyferry-tray-{polarity}-{size}.png")
    written.append("tray/keyferry-tray-{black,white}-{" + ",".join(str(s) for s in TRAY_SIZES) + "}.png")

    for line in written:
        print("wrote", line)


if __name__ == "__main__":
    main()
