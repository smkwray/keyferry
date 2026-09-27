#!/usr/bin/env python3
"""Fail closed when public Keyferry material contains private identity bytes."""

from __future__ import annotations

import argparse
import base64
import re
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_PREFIXES = (
    ".claude/", ".codex/", ".cursor/", ".tools/", "build/", "do/",
    "docs/", "workorders/", ".worktrees/", "hardware/board-manifest.toml",
    "hardware/evidence/private/", "release/", "secrets/", "target/",
)
PRIVATE_ROOT_FILES = {"agents.md", "claude.md", "start_here.md", "seed_validation.md"}
PRIVATE_FILENAMES = {
    "board-manifest.toml", "desktop-client-cert.der", "desktop-server-cert.der",
    "device-grant.json", "device-id.bin", "device-link-secret.bin",
    "device-server-cert.der", "gateway.json", "installation-key.der",
    "installation-spki.der", "owner-ca.der", "owner-kit.json",
    "route-proof-secret.bin", "secret.bin",
}
PRIVATE_NAME_PARTS = ("credential", "installation", "owner-kit", "recovery", "secret")
MAC_RE = re.compile(rb"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])")
SYNTHETIC_MAC_PREFIX = b"02:00:00:00:00:"
# Absolute home paths name the person who built or wrote them, registered or not. Build paths leak
# through panic locations, so release builds must remap them; fixtures use a placeholder account.
USER_PATH_RE = re.compile(rb"(?i)(?:[a-z]:[\\/]+users|/users|/home)[\\/]+([a-z0-9._-]{1,64})[\\/]")
PLACEHOLDER_ACCOUNTS = {b"owner", b"user", b"username", b"public", b"default", b"shared"}
UUID_RE = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
MAC_TOKEN_RE = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")
HEX_RE = re.compile(r"[0-9a-fA-F]{32,}\Z")
NESTED_ARCHIVE_SUFFIXES = (".zip", ".tar", ".tgz", ".tar.gz", ".7z", ".rar")

WINDOWS_MEMBERS = {
    "README.txt", "SHA256SUMS", "VERSION", "install.ps1", "keyctl.exe",
    "keyferry-pairing.exe", "keyferry.exe", "keyferryd.exe",
}
MACOS_MEMBERS = {
    "README.txt", "SHA256SUMS", "VERSION", "install.sh",
    "Keyferry.app/Contents/Info.plist",
    "Keyferry.app/Contents/Resources/keyferry.icns",
    "Keyferry.app/Contents/_CodeSignature/CodeResources",
    "Keyferry.app/Contents/MacOS/keyctl",
    "Keyferry.app/Contents/MacOS/keyferry",
    "Keyferry.app/Contents/MacOS/keyferry-ble-bridge",
    "Keyferry.app/Contents/MacOS/keyferry-pairing",
    "Keyferry.app/Contents/MacOS/keyferryd",
}
CANONICAL_ARCHIVES = {
    "windows": "keyferry-windows-x64.zip",
    "macos": "keyferry-macos-arm64.zip",
}


@dataclass(frozen=True)
class PrivatePattern:
    value: bytes
    folded: bool = False


def _run_git(root: Path, *args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True).stdout


def tracked_paths(root: Path = ROOT) -> list[str]:
    return [item.decode("utf-8", errors="surrogateescape")
            for item in _run_git(root, "ls-files", "-z").split(b"\0") if item]


def _add_pattern(patterns: set[PrivatePattern], value: bytes, folded: bool = False) -> None:
    if len(value) >= 4:
        patterns.add(PrivatePattern(value.lower() if folded else value, folded))


def _add_secret_encodings(patterns: set[PrivatePattern], value: bytes) -> None:
    if value:
        _add_pattern(patterns, value)
        _add_pattern(patterns, value.hex().encode("ascii"), True)
        _add_pattern(patterns, base64.b64encode(value))


def private_patterns(root: Path = ROOT, registry_path: Path | None = None) -> list[PrivatePattern]:
    registry = registry_path or root / "secrets" / "private-identifiers.txt"
    patterns: set[PrivatePattern] = set()
    if registry.is_file():
        for raw_line in registry.read_text(encoding="utf-8").splitlines():
            token = raw_line.strip()
            if not token or token.startswith("#"):
                continue
            _add_pattern(patterns, token.encode("utf-8"), True)
            _add_pattern(patterns, token.encode("utf-16-le"), True)
            compact = token.replace("-", "").replace(":", "")
            if UUID_RE.fullmatch(token) or MAC_TOKEN_RE.fullmatch(token):
                raw = bytes.fromhex(compact)
                _add_secret_encodings(patterns, raw)
                _add_pattern(patterns, compact.encode("ascii"), True)
            elif HEX_RE.fullmatch(token) and len(token) % 2 == 0:
                _add_secret_encodings(patterns, bytes.fromhex(token))
    secret_root = root / "secrets"
    if secret_root.is_dir():
        for path in secret_root.rglob("*"):
            if path.is_file() and (path.name.casefold() in PRIVATE_FILENAMES
                                   or path.suffix.casefold() in {".der", ".bin"}):
                _add_secret_encodings(patterns, path.read_bytes())
    return sorted(patterns, key=lambda item: (item.folded, item.value))


def _content_failure(data: bytes, patterns: list[PrivatePattern]) -> str | None:
    folded = data.lower()
    for pattern in patterns:
        if pattern.value in (folded if pattern.folded else data):
            return "matches local private identity material"
    for match in MAC_RE.finditer(data):
        if not match.group(0).lower().startswith(SYNTHETIC_MAC_PREFIX):
            return "contains a non-synthetic hardware MAC address"
    for view in (data, data.replace(b"\0", b"")):
        for match in USER_PATH_RE.finditer(view):
            if match.group(1).lower() not in PLACEHOLDER_ACCOUNTS:
                return "contains an absolute user home path"
    return None


def _path_failure(relative: str) -> str | None:
    normalized = relative.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    folded = normalized.casefold()
    if folded in PRIVATE_ROOT_FILES:
        return "private root control file"
    if any(folded == prefix.rstrip("/") or folded.startswith(prefix)
           for prefix in PRIVATE_PREFIXES):
        return "private path"
    if PurePosixPath(normalized).name.casefold() in PRIVATE_FILENAMES:
        return "private credential filename"
    return None


def current_tree_failures(root: Path, patterns: list[PrivatePattern]) -> list[str]:
    failures: list[str] = []
    for relative in tracked_paths(root):
        reason = _path_failure(relative)
        if reason:
            failures.append(f"{relative}: {reason} is tracked")
            continue
        path = root / relative
        if path.is_file():
            reason = _content_failure(path.read_bytes(), patterns)
            if reason:
                failures.append(f"{relative}: {reason}")
    return failures


def history_failures(patterns: list[PrivatePattern], root: Path = ROOT) -> list[str]:
    failures: list[str] = []
    object_ids: list[bytes] = []
    for line in _run_git(root, "rev-list", "--objects", "--all").splitlines():
        oid, _, raw_path = line.partition(b" ")
        object_ids.append(oid)
        if raw_path and _path_failure(raw_path.decode("utf-8", errors="replace")):
            failures.append("Git history contains a prohibited private path or filename")
    process = subprocess.Popen(["git", "cat-file", "--batch"], cwd=root,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert process.stdin is not None and process.stdout is not None
    try:
        matched = 0
        for oid in object_ids:
            process.stdin.write(oid + b"\n")
            process.stdin.flush()
            parts = process.stdout.readline().rstrip(b"\n").split()
            if len(parts) != 3:
                raise RuntimeError("unexpected git cat-file response")
            size = int(parts[2])
            data = process.stdout.read(size)
            if len(data) != size or process.stdout.read(1) != b"\n":
                raise RuntimeError("truncated git cat-file response")
            if _content_failure(data, patterns):
                matched += 1
        process.stdin.close()
        if matched:
            failures.append(f"Git reachable objects contain private identity material ({matched} object(s))")
    finally:
        if not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()
        if process.wait() != 0:
            raise RuntimeError("git cat-file failed")
    return list(dict.fromkeys(failures))


def _expected_members(platform: str) -> set[str]:
    return WINDOWS_MEMBERS if platform == "windows" else MACOS_MEMBERS


def _infer_platform(names: set[str]) -> str | None:
    if "keyferry.exe" in names:
        return "windows"
    if "Keyferry.app/Contents/MacOS/keyferry" in names:
        return "macos"
    return None


def _member_path_failure(name: str) -> str | None:
    if "\\" in name or name.startswith("/"):
        return "unsafe archive member path"
    pure = PurePosixPath(name)
    if not name or any(part in {"", ".", ".."} for part in pure.parts):
        return "unsafe archive member path"
    if pure.name.casefold() in PRIVATE_FILENAMES:
        return "private credential filename"
    folded = name.casefold()
    if any(part in folded for part in PRIVATE_NAME_PARTS):
        return "private-looking artifact filename"
    if any(folded.endswith(suffix) for suffix in NESTED_ARCHIVE_SUFFIXES):
        return "nested archive"
    return None


def _verify_checksums(files: dict[str, bytes]) -> list[str]:
    import hashlib
    failures: list[str] = []
    raw = files.get("SHA256SUMS")
    if raw is None:
        return ["SHA256SUMS is missing"]
    expected: dict[str, str] = {}
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return ["SHA256SUMS is not ASCII"]
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            failures.append("SHA256SUMS has an invalid record")
            continue
        digest, name = line[:64], line[66:]
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or name in expected:
            failures.append("SHA256SUMS has an invalid or duplicate record")
            continue
        expected[name] = digest
    actual_names = set(files) - {"SHA256SUMS"}
    if set(expected) != actual_names:
        failures.append("SHA256SUMS member set does not match the archive")
    for name in actual_names & set(expected):
        if hashlib.sha256(files[name]).hexdigest() != expected[name]:
            failures.append(f"{name}: checksum mismatch")
    return failures


def artifact_failures(artifact: Path, patterns: list[PrivatePattern], platform: str | None = None,
                      require_canonical_name: bool = True) -> list[str]:
    if not patterns:
        return ["artifact scan requires a populated private identity registry"]
    failures: list[str] = []
    files: dict[str, bytes] = {}
    if require_canonical_name:
        folded_root = artifact.name.casefold()
        if (PurePosixPath(artifact.name).name.casefold() in PRIVATE_FILENAMES
                or any(part in folded_root for part in PRIVATE_NAME_PARTS)):
            failures.append("artifact root has a private-looking name")
    if artifact.is_dir():
        for path in artifact.rglob("*"):
            if path.is_symlink():
                failures.append(f"{path.relative_to(artifact).as_posix()}: link is forbidden")
            elif path.is_file():
                files[path.relative_to(artifact).as_posix()] = path.read_bytes()
    elif artifact.is_file() and artifact.suffix.casefold() == ".zip":
        try:
            with zipfile.ZipFile(artifact) as archive:
                seen: set[str] = set()
                for info in archive.infolist():
                    name = info.filename.rstrip("/")
                    if not name:
                        continue
                    if name in seen:
                        failures.append(f"{name}: duplicate archive member")
                    seen.add(name)
                    if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                        failures.append(f"{name}: link is forbidden")
                    reason = _member_path_failure(name)
                    if reason:
                        failures.append(f"{name}: {reason}")
                    if not info.is_dir():
                        files[name] = archive.read(info)
        except (OSError, zipfile.BadZipFile, RuntimeError):
            return ["artifact is not a readable ZIP archive"]
    else:
        return [f"artifact must be a directory or ZIP archive: {artifact}"]
    selected = platform or _infer_platform(set(files))
    if selected not in CANONICAL_ARCHIVES:
        failures.append("artifact platform cannot be determined")
    else:
        if require_canonical_name and artifact.is_file() and artifact.name != CANONICAL_ARCHIVES[selected]:
            failures.append("archive filename is not canonical")
        expected = _expected_members(selected)
        if set(files) != expected:
            failures.append(f"artifact member manifest mismatch ({len(expected - set(files))} missing, {len(set(files) - expected)} extra)")
    for name, data in files.items():
        reason = _member_path_failure(name)
        if reason:
            failures.append(f"{name}: {reason}")
        reason = _content_failure(data, patterns)
        if reason:
            failures.append(f"{name}: {reason}")
    failures.extend(_verify_checksums(files))
    return list(dict.fromkeys(failures))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--private-identifiers", type=Path)
    parser.add_argument("--require-private-registry", action="store_true")
    args = parser.parse_args()
    registry = args.private_identifiers.resolve() if args.private_identifiers else None
    patterns = private_patterns(ROOT, registry)
    failures = current_tree_failures(ROOT, patterns)
    if args.require_private_registry and not patterns:
        failures.append("a populated private identity registry is required")
    if args.history:
        failures.extend(history_failures(patterns, ROOT))
    if args.artifact:
        failures.extend(artifact_failures(args.artifact.resolve(), patterns))
    if failures:
        for failure in failures:
            print(f"private-boundary error: {failure}")
        return 1
    scopes = ["current tree"]
    if args.history:
        scopes.append("all reachable Git objects")
    if args.artifact:
        scopes.append("final archive")
    print(f"public privacy boundary: ok ({', '.join(scopes)}; {len(patterns)} private patterns)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
