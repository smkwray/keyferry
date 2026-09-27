#!/usr/bin/env python3
"""Build and scan one identity-clean Keyferry controller ZIP."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_public_tree import (  # noqa: E402
    CANONICAL_ARCHIVES,
    MACOS_MEMBERS,
    WINDOWS_MEMBERS,
    artifact_failures,
    private_patterns,
)

VERSION_RE = re.compile(r"(?:v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?|[0-9a-f]{7,40})\Z")
MACOS_APP_FILES = {
    name.removeprefix("Keyferry.app/")
    for name in MACOS_MEMBERS
    if name.startswith("Keyferry.app/")
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & 0x400)


def _regular_files(root: Path) -> set[str]:
    files: set[str] = set()
    for path in root.rglob("*"):
        if _is_link_or_reparse(path):
            raise ValueError(f"links and reparse points are forbidden: {path.name}")
        if path.is_file():
            if not stat.S_ISREG(path.stat().st_mode):
                raise ValueError(f"non-regular files are forbidden: {path.name}")
            files.add(path.relative_to(root).as_posix())
    return files


def _copy_regular(source: Path, destination: Path) -> None:
    if not source.is_file() or _is_link_or_reparse(source):
        raise ValueError(f"required input is not a regular file: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _readme(platform: str) -> str:
    text = (
        "Generic Keyferry controller programs.\n"
        "This archive has passed the local private-identity byte scanner. It contains no\n"
        "registered device identity, computer identity, certificates, link secrets,\n"
        "recovery secrets, owner kit, or installation credentials. Each authorized\n"
        "computer receives a separate private credential directory. A computer's display\n"
        "name comes from the running operating system, not from those credentials.\n\n"
        "The archive is generic and may be distributed separately from private credentials.\n\n"
    )
    if platform == "windows":
        text += (
            "INSTALL (PowerShell opened in this extracted folder):\n"
            ".\\install.ps1 -ControllerExecutable .\\keyferry.exe "
            "-DaemonExecutable .\\keyferryd.exe "
            "-PairingExecutable .\\keyferry-pairing.exe "
            "-CliExecutable .\\keyctl.exe -Mode Plan\n"
            "Review the plan, rerun with -Mode Apply, then rerun with -Mode Verify.\n\n"
            "AGENT USE:\n"
            "$keyctl = \"$env:LOCALAPPDATA\\Programs\\Keyferry\\keyctl.exe\"\n"
            "& $keyctl --help\n"
            "& $keyctl devices\n"
            "& $keyctl status DEVICE-UUID\n"
            "& $keyctl capabilities\n"
            "& $keyctl stream DEVICE-UUID --input C:\\path\\to\\message.txt\n"
            "& $keyctl screen-power DEVICE-UUID off\n"
        )
    else:
        text += (
            "INSTALL (Terminal opened in this extracted folder):\n"
            "sh ./install.sh --controller ./Keyferry.app --mode Plan\n"
            "Review the plan, rerun with --mode Apply, then rerun with --mode Verify.\n\n"
            "AGENT USE:\n"
            "~/Applications/Keyferry.app/Contents/MacOS/keyctl --help\n"
            "~/Applications/Keyferry.app/Contents/MacOS/keyctl devices\n"
            "~/Applications/Keyferry.app/Contents/MacOS/keyctl status DEVICE-UUID\n"
            "~/Applications/Keyferry.app/Contents/MacOS/keyctl capabilities\n"
            "~/Applications/Keyferry.app/Contents/MacOS/keyctl stream DEVICE-UUID "
            "--input /path/to/message.txt\n"
            "~/Applications/Keyferry.app/Contents/MacOS/keyctl screen-power DEVICE-UUID off\n"
        )
    return text + (
        "\nKeyferry's background service runs only while Keyferry is open: opening the app\n"
        "starts it and closing the app stops it. Installing never leaves it running, and\n"
        "keyctl opens Keyferry automatically when its local service is unavailable.\n"
        "\nAGENT FIRST USE:\n"
        "1. The USB target needs no app. Install this generic package on the intended\n"
        "   sending computer. A new computer cannot type until the owner approves it\n"
        "   for the exact device: open Keyferry there and the owner uses Authorize this\n"
        "   computer (owner-kit file, owner password, device). Never ask for or handle\n"
        "   the owner password yourself.\n"
        "2. Launch Keyferry near the USB stick; the daemon discovers its BLE control\n"
        "   link automatically. Do not pair it as an OS Bluetooth keyboard. If the\n"
        "   requested computer is not authorized, ask the owner to authorize it; do\n"
        "   not substitute a distant computer that happens to have a device grant.\n"
        "3. With Keyferry open, run `keyctl devices` using the platform path above.\n"
        "4. Use the `id` of exactly one device whose `link` is `authenticated`. Never\n"
        "   guess, select an offline device, or silently choose when several are authenticated.\n"
        "5. Put the requested text in a UTF-8 file, then pass that file to `keyctl stream`.\n"
        "6. Do not retry an interrupted or uncertain stream. `EMITTED` confirms device-side\n"
        "   report completion, not that the focused application displayed the text.\n\n"
        "For ordered physical hotkeys use Keyboard Sequence v1 action\n"
        "`{\"type\":\"ordered_chord\",\"keys\":[\"SPACE\",\"Q\"]}`. Ordinary `chord`\n"
        "presses all keys together; ordered_chord holds keys in listed order and\n"
        "releases them in reverse. Both end with all keys up.\n\n"
        "Use `keyctl --help` to discover the full command list. `status DEVICE-UUID`\n"
        "reads only that stick; `capabilities` describes the local daemon. Screen power\n"
        "can be set to `off` or `on`: it persists, takes effect without a restart, and\n"
        "its status has `available`, `active`, and `stored`. Check `available` and\n"
        "`active` before claiming that the screen visibly changed.\n\n"
        "This computer's daemon automatically forwards sends to an authorized owner\n"
        "computer holding the selected stick on the tailnet. `keyctl devices` shows\n"
        "link_path and via for that route; a local connection takes precedence.\n"
        "Keep Keyferry open on the computer holding the stick. Screen, orientation,\n"
        "output, and Bluetooth-bond settings require that holder's direct authenticated\n"
        "Wi-Fi/Bluetooth session; settings do not forward through a tailnet relay.\n"
        "Screen power changes do not restart; output, orientation, and bond changes do.\n\n"
        "OWNER-OPERATED USB MAINTENANCE (use the installed keyctl path above):\n"
        "keyctl local-status --owner-kit PATH --device DEVICE-UUID\n"
        "keyctl local-recover --owner-kit PATH --device DEVICE-UUID restart-network\n"
        "The exact stick must be attached by USB to this computer. The owner enters\n"
        "the owner-kit password through stdin personally; never put it in command\n"
        "arguments, shell history, or agent output. Restart networking interrupts\n"
        "the connection and clears any published USB file. Local reboot and output\n"
        "mode changes also restart the stick. Read the helper's attempt/result JSON\n"
        "for the selected device; an UNKNOWN result may have acted and must not be\n"
        "retried automatically. An interrupted send is likewise never replayed.\n\n"
        "The selected device must report authenticated before sending. File input keeps\n"
        "payloads out of shell history. Printable ASCII, TAB, CR, and LF are supported;\n"
        "unsupported text rejects before contact unless explicit replacement is requested.\n"
    )


def _write_zip(stage: Path, archive: Path) -> None:
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for path in sorted(item for item in stage.rglob("*") if item.is_file()):
            relative = path.relative_to(stage).as_posix()
            info = zipfile.ZipInfo(relative, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            executable = relative == "install.sh" or "/MacOS/" in relative
            info.external_attr = ((0o100755 if executable else 0o100644) << 16)
            output.writestr(info, path.read_bytes(), compresslevel=9)


def package(
    platform: str,
    controller: Path,
    daemon: Path | None,
    pairing: Path | None,
    cli: Path | None,
    output: Path,
    version: str,
    project_root: Path,
    registry_path: Path,
) -> None:
    if not VERSION_RE.fullmatch(version):
        raise ValueError("version must be semantic (for example 1.2.3) or a 7-40 digit lowercase Git revision")
    expected_name = CANONICAL_ARCHIVES.get(platform)
    if expected_name is None:
        raise ValueError("only Windows and macOS are supported")
    if output.name != expected_name:
        raise ValueError(f"output filename must be exactly {expected_name}")
    if output.exists():
        raise FileExistsError(f"refusing to overwrite existing output: {output}")
    patterns = private_patterns(project_root, registry_path)
    if not registry_path.is_file() or not patterns:
        raise ValueError("a populated private-identifier registry is required")

    if platform == "macos":
        if not controller.is_dir() or controller.suffix != ".app" or _is_link_or_reparse(controller):
            raise ValueError("macOS controller must be a regular .app directory")
        members = _regular_files(controller)
        if members != MACOS_APP_FILES:
            raise ValueError(f"macOS app manifest mismatch ({len(MACOS_APP_FILES - members)} missing, {len(members - MACOS_APP_FILES)} extra)")
        installer = project_root / "scripts" / "install_unix_controller.sh"
    else:
        if daemon is None or pairing is None or cli is None:
            raise ValueError("Windows controller, daemon, pairing helper, and CLI are required")
        installer = project_root / "scripts" / "install_windows_controller.ps1"
        for path in (controller, daemon, pairing, cli):
            if not path.is_file() or _is_link_or_reparse(path):
                raise ValueError("Windows program inputs must be regular files")
    if not installer.is_file() or _is_link_or_reparse(installer):
        raise ValueError("desktop installer is missing or linked")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".keyferry-release-", dir=output.parent))
    stage = temporary / "stage"
    stage.mkdir()
    candidate = temporary / expected_name
    try:
        if platform == "macos":
            for relative in sorted(MACOS_APP_FILES):
                _copy_regular(controller / Path(relative), stage / "Keyferry.app" / Path(relative))
            _copy_regular(installer, stage / "install.sh")
        else:
            assert daemon is not None and pairing is not None and cli is not None
            for source, name in ((controller, "keyferry.exe"), (daemon, "keyferryd.exe"),
                                 (pairing, "keyferry-pairing.exe"), (cli, "keyctl.exe")):
                _copy_regular(source, stage / name)
            _copy_regular(installer, stage / "install.ps1")
        (stage / "VERSION").write_bytes((version + "\n").encode("utf-8"))
        (stage / "README.txt").write_bytes(_readme(platform).encode("utf-8"))
        records = [f"{sha256(path)}  {path.relative_to(stage).as_posix()}"
                   for path in sorted(item for item in stage.rglob("*") if item.is_file())]
        (stage / "SHA256SUMS").write_bytes(("\n".join(records) + "\n").encode("ascii"))
        expected = WINDOWS_MEMBERS if platform == "windows" else MACOS_MEMBERS
        actual = _regular_files(stage)
        if actual != expected:
            raise ValueError("internal release member manifest mismatch")
        failures = artifact_failures(stage, patterns, platform, require_canonical_name=False)
        if failures:
            raise ValueError("release privacy scan failed: " + "; ".join(failures))
        _write_zip(stage, candidate)
        failures = artifact_failures(candidate, patterns, platform, require_canonical_name=True)
        if failures:
            raise ValueError("final ZIP privacy scan failed: " + "; ".join(failures))
        os.replace(candidate, output)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=("windows", "macos"), required=True)
    parser.add_argument("--controller", type=Path, required=True)
    parser.add_argument("--daemon", type=Path)
    parser.add_argument("--pairing", type=Path)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--private-identifiers", type=Path, required=True)
    args = parser.parse_args()
    try:
        package(args.platform, args.controller.resolve(),
                args.daemon.resolve() if args.daemon else None,
                args.pairing.resolve() if args.pairing else None,
                args.cli.resolve() if args.cli else None,
                args.output.resolve(), args.version,
                Path(__file__).resolve().parent.parent,
                args.private_identifiers.resolve())
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"created identity-clean {args.platform} controller ZIP: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
