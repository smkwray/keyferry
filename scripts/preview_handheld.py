"""Render the AMOLED handheld screens on this computer, from the same ui.cpp the device runs.

LVGL is compiled from the device build's managed component with that build's sdkconfig.h, so
fonts and widgets match the firmware. Run a device build first (scripts/build_handheld.ps1).
Writes one PNG per scene plus screens.png (all scenes on one sheet) to --out.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDHELD = ROOT / "firmware/esp32s3/handheld"
LVGL = HANDHELD / "check/managed_components/lvgl__lvgl"
SOURCES = [
    HANDHELD / "kf_handheld/src/ui.cpp",
    HANDHELD / "kf_handheld/src/macros.cpp",
    HANDHELD / "preview/preview.cpp",
]
WIDTH, HEIGHT = 368, 448


def msvc_environment() -> dict[str, str]:
    """cl.exe environment from the newest Build Tools and Windows SDK, without a vcvars shell."""
    env = dict(os.environ)
    if shutil.which("cl"):
        return env
    program_files = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    tools = sorted((program_files / "Microsoft Visual Studio").glob("*/*/VC/Tools/MSVC/*"))
    kits = program_files / "Windows Kits/10"
    versions = sorted(p.name for p in (kits / "Include").glob("*") if (p / "ucrt").is_dir())
    if not tools or not versions:
        raise SystemExit("preview: MSVC Build Tools and a Windows 10/11 SDK are required")
    msvc, kit = tools[-1], versions[-1]
    env["INCLUDE"] = os.pathsep.join(
        str(p) for p in [msvc / "include", *(kits / "Include" / kit / d for d in ("ucrt", "um", "shared"))]
    )
    env["LIB"] = os.pathsep.join(
        str(p) for p in [msvc / "lib/x64", kits / "Lib" / kit / "ucrt/x64", kits / "Lib" / kit / "um/x64"]
    )
    env["PATH"] = str(msvc / "bin/Hostx64/x64") + os.pathsep + env["PATH"]
    return env


class Toolchain:
    def __init__(self, out: Path) -> None:
        self.msvc = os.name == "nt"
        self.env = msvc_environment() if self.msvc else dict(os.environ)
        self.includes = [out, LVGL, LVGL / "include", HANDHELD / "kf_handheld/src"]
        self.cl = shutil.which("cl", path=self.env["PATH"]) if self.msvc else None
        # No console window per compile on Windows.
        self.flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.defines = ["LV_CONF_KCONFIG_EXTERNAL_INCLUDE=<host_kconfig.h>"]

    def compile(self, source: Path, obj: Path) -> None:
        cpp = source.suffix == ".cpp"
        if self.msvc:
            command = [self.cl, "/nologo", "/c", "/O1", "/utf-8", "/W3", "/D_CRT_SECURE_NO_WARNINGS"]
            command += ["/std:c++20", "/EHsc"] if cpp else ["/std:c11"]
            command += [f"/D{d}" for d in self.defines] + [f"/I{i}" for i in self.includes]
            command += [str(source), f"/Fo{obj}"]
        else:
            command = ["c++" if cpp else "cc", "-c", "-O1", "-std=c++20" if cpp else "-std=c11"]
            command += [f"-D{d}" for d in self.defines] + [f"-I{i}" for i in self.includes]
            command += [str(source), "-o", str(obj)]
        result = subprocess.run(command, env=self.env, capture_output=True, text=True, creationflags=self.flags)
        if result.returncode != 0:
            raise SystemExit(f"preview: compile failed: {source}\n{result.stdout}{result.stderr}")

    def link(self, objects: list[Path], exe: Path) -> None:
        response = exe.with_suffix(".rsp")
        response.write_text("\n".join(f'"{o}"' for o in objects), encoding="utf-8")
        if self.msvc:
            command = [self.cl, "/nologo", f"/Fe{exe}", f"@{response}"]
        else:
            command = ["c++", "-o", str(exe), f"@{response}"]
        result = subprocess.run(command, env=self.env, capture_output=True, text=True, creationflags=self.flags)
        if result.returncode != 0:
            raise SystemExit(f"preview: link failed\n{result.stdout}{result.stderr}")


def build(out: Path, sdkconfig: Path, jobs: int) -> Path:
    obj_dir = out / "obj"
    obj_dir.mkdir(parents=True, exist_ok=True)
    (out / "host_kconfig.h").write_text(f'#include "{sdkconfig.as_posix()}"\n', encoding="utf-8")
    toolchain = Toolchain(out)
    suffix = ".obj" if toolchain.msvc else ".o"
    config_time = sdkconfig.stat().st_mtime
    work: list[tuple[Path, Path]] = []
    objects: list[Path] = []
    for source in sorted((LVGL / "src").rglob("*.c")) + SOURCES:
        name = source.relative_to(ROOT).as_posix().replace("/", "_")
        obj = obj_dir / (name + suffix)
        objects.append(obj)
        if not obj.exists() or obj.stat().st_mtime < max(source.stat().st_mtime, config_time):
            work.append((source, obj))
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        list(pool.map(lambda item: toolchain.compile(*item), work))
    exe = out / ("preview.exe" if toolchain.msvc else "preview")
    if work or not exe.exists():
        toolchain.link(objects, exe)
    print(f"preview: compiled {len(work)} of {len(objects)} sources")
    return exe


def to_rgb(raw: bytes) -> bytes:
    pixels = memoryview(raw).cast("H")
    out = bytearray(len(pixels) * 3)
    for i, v in enumerate(pixels):
        out[3 * i] = (v >> 11) * 255 // 31
        out[3 * i + 1] = ((v >> 5) & 0x3F) * 255 // 63
        out[3 * i + 2] = (v & 0x1F) * 255 // 31
    return bytes(out)


def render(exe: Path, out: Path) -> list[Path]:
    from PIL import Image, ImageDraw

    scenes = subprocess.run([str(exe), "--list"], check=True, capture_output=True, text=True).stdout.split()
    images: list[Path] = []
    for scene in scenes:
        raw = out / f"{scene}.rgb565"
        subprocess.run([str(exe), scene, str(raw)], check=True)
        png = out / f"{scene}.png"
        Image.frombytes("RGB", (WIDTH, HEIGHT), to_rgb(raw.read_bytes())).save(png)
        raw.unlink()
        images.append(png)
    columns, gap, caption = 4, 24, 28
    rows = (len(images) + columns - 1) // columns
    sheet = Image.new("RGB", (columns * (WIDTH + gap) + gap, rows * (HEIGHT + gap + caption) + gap), (60, 63, 70))
    draw = ImageDraw.Draw(sheet)
    for index, png in enumerate(images):
        x = gap + (index % columns) * (WIDTH + gap)
        y = gap + (index // columns) * (HEIGHT + gap + caption)
        draw.text((x, y), png.stem, fill=(230, 230, 230))
        sheet.paste(Image.open(png), (x, y + caption))
    sheet.save(out / "screens.png")
    return images


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--build-dir", default="build/handheld-check", help="device build with config/sdkconfig.h")
    parser.add_argument("--out", default="build/handheld-preview")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    args = parser.parse_args()
    sdkconfig = (ROOT / args.build_dir / "config/sdkconfig.h").resolve()
    if not sdkconfig.is_file() or not (LVGL / "src").is_dir():
        print(f"preview: run a device build first ({sdkconfig} or LVGL source missing)", file=sys.stderr)
        return 2
    out = (ROOT / args.out).resolve()
    exe = build(out, sdkconfig, args.jobs)
    images = render(exe, out)
    print(f"preview: {len(images)} scenes -> {out / 'screens.png'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
