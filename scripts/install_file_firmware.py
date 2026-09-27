#!/usr/bin/env python3
"""Exact-unit ROM layout migration for the qualified Waveshare USB-file image.

Plan is offline. Apply and rollback require a matching plan digest and physical
ROM mode; neither is called by build or install scripts automatically.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
INSPECTOR = ROOT / "scripts/check_msc_size_probe.py"
BACKEND = ROOT / "tools/keyferry-firmware/esptool_backend.py"
SITE_ROOT = ROOT / ".tools/idf-tools-v6.0.3/python_env"
SCHEMA = "keyferry.file-layout-plan.v1"
UNIT_KEYS = ("rom_mac", "chip", "soc_revision", "flash_manufacturer_id",
             "flash_device_id", "flash_size_bytes", "secure_boot",
             "flash_encryption", "secure_download_mode", "efuse_sha256")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"module unavailable: {name}")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def pinned_site():
    sites = list(SITE_ROOT.glob("*/Lib/site-packages")) + list(
        SITE_ROOT.glob("*/lib/python*/site-packages"))
    if len(sites) != 1:
        raise ValueError("one pinned ESP-IDF Python environment is required")
    if str(sites[0]) not in sys.path:
        sys.path.insert(0, str(sites[0]))
    import esptool
    if (esptool.__version__ != "5.4.0"
            or not Path(esptool.__file__).resolve().is_relative_to(sites[0].resolve())):
        raise ValueError("esptool is not the pinned version")
    return sites[0]


def image_valid(image: bytes) -> bool:
    from esptool.bin_image import ESP32S3FirmwareImage
    try:
        parsed = ESP32S3FirmwareImage(io.BytesIO(image))
        return (parsed.append_digest and parsed.data_length is not None
                and parsed.data_length + 32 == len(image)
                and parsed.stored_digest == parsed.calc_digest
                and parsed.checksum == parsed.calculate_checksum()
                and parsed.chip_id == parsed.ROM_LOADER.IMAGE_CHIP_ID
                and image[2:4] == bytes([2, 0x4F]))
    except Exception:
        return False


def sources(backup: Path, package: Path, unit_record: Path, build: Path,
            current_config: Path | None = None):
    pinned_site()
    inspector = module(INSPECTOR, "keyferry_layout_inspector")
    with contextlib.redirect_stdout(io.StringIO()):
        inspector.inspect_file_handoff(build)
        inspector.inspect_backup(build, backup, package, unit_record)
    receipt = inspector.review_json(backup / "receipt.json")
    manifest = inspector.review_json(package / "manifest.json")
    record = inspector.review_json(unit_record)
    image = inspector.bounded_file(build / "keyferry_hil_endpoint.bin", 0x200000)
    if not image_valid(image):
        raise ValueError("candidate app image format, checksum or digest invalid")
    table = inspector.bounded_file(build / "partition_table/partition-table.bin", 0x1000)
    if len(table) != 0xC00:
        raise ValueError("candidate table size differs")
    table_sector = table.ljust(0x1000, b"\xff")
    footprint = (len(image) + 4095) // 4096 * 4096
    snapshot = backup / "full-flash.bin"
    with snapshot.open("rb") as data:
        def read_region(offset, length):
            data.seek(offset)
            result = data.read(length)
            if len(result) != length:
                raise ValueError("backup region incomplete")
            return result
        prefix = read_region(0, 0x8000)
        old_table_sector = read_region(0x8000, 0x1000)
        retained = read_region(0x9000, 0x120000 - 0x9000)
        old_stage = read_region(0x120000, footprint)
    expected_unit = {key: record[key] for key in UNIT_KEYS}
    expected_unit.update({
        "bootloader_sha256": manifest["preserved"]["bootloader_sha256"],
        "partition_table_sha256": manifest["preserved"]["partition_table_sha256"],
    })
    config_binding = {}
    if current_config is not None:
        config_receipt = inspector.review_json(current_config / "receipt.json")
        config = inspector.bounded_file(current_config / "config.bin", 0xB000)
        if (config_receipt.get("schema") != "keyferry.layout-config-receipt.v1"
                or config_receipt.get("expected_unit") != expected_unit
                or config_receipt.get("backup_receipt_sha256") !=
                inspector.sha256(backup / "receipt.json")
                or config_receipt.get("backup_snapshot_sha256") !=
                receipt["snapshot"]["sha256"]
                or config_receipt.get("offset") != 0x110000
                or config_receipt.get("size_bytes") != 0xB000
                or config_receipt.get("second_pass_equal") is not True
                or len(config) != 0xB000
                or config_receipt.get("config_sha256") != digest(config)):
            raise ValueError("current config capture binding differs")
        start = 0x110000 - 0x9000
        retained = retained[:start] + config + retained[start + len(config):]
        config_binding = {"current_config": str(current_config.resolve()),
                          "current_config_receipt_sha256": inspector.sha256(
                              current_config / "receipt.json"),
                          "current_config_sha256": digest(config)}
    if (receipt["port"] == "" or record["qualified_recovery_cycles"] < 2
            or expected_unit["secure_boot"] or expected_unit["flash_encryption"]
            or expected_unit["secure_download_mode"]):
        raise ValueError("exact-unit recovery/security gate differs")
    common = {
        "schema": SCHEMA,
        "backup": str(backup.resolve()), "package": str(package.resolve()),
        "unit_record": str(unit_record.resolve()), "build": str(build.resolve()),
        "receipt_sha256": inspector.sha256(backup / "receipt.json"),
        "snapshot_sha256": receipt["snapshot"]["sha256"],
        "candidate_image_sha256": digest(image),
        "candidate_table_sector_sha256": digest(table_sector),
        "stage_bytes": footprint,
        "port": receipt["port"],
        "expected_unit": expected_unit,
        "boot_prefix_sha256": digest(prefix),
        "preserved_after_sha256": digest(retained),
        "old_table_sector_sha256": digest(old_table_sector),
        "stage_before_sha256": digest(old_stage),
    }
    common.update(config_binding)
    return common, image, table_sector, old_stage, old_table_sector


def plan_hash(plan):
    copy = dict(plan)
    copy.pop("authorization_sha256", None)
    return digest(json.dumps(copy, sort_keys=True, separators=(",", ":")).encode())


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate plan field")
        result[key] = value
    return result


def require_board_profile(build: Path, profile: str) -> None:
    if not isinstance(profile, str) or not re.fullmatch(r"[a-z0-9_]+", profile):
        raise ValueError("invalid package board profile")
    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    selected = re.findall(r"^KEYFERRY_BOARD:STRING=([^\r\n]*)$", cache, re.MULTILINE)
    if selected != [profile]:
        raise ValueError("build board profile differs from exact-unit package")


def require_private_capture_dir(output: Path) -> None:
    private = (ROOT / "hardware/evidence/private").resolve()
    if (output.is_symlink() or not output.resolve().is_relative_to(private)
            or not output.is_dir() or any(output.iterdir())):
        raise ValueError("empty private capture directory with owner-only ACL required")
    if os.name == "nt":
        script = r'''
$path = $env:KEYFERRY_CAPTURE_DIR
$acl = [System.IO.Directory]::GetAccessControl($path)
$self = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($self, 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-4')
if (-not $acl.AreAccessRulesProtected) { exit 1 }
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $self) {
    exit 1
}
$rules = $acl.GetAccessRules($true, $true,
    [System.Security.Principal.SecurityIdentifier])
$selfAllowed = $false
foreach ($rule in $rules) {
    if ($rule.AccessControlType -ne 'Allow') { continue }
    $sid = $rule.IdentityReference.Value
    if ($sid -notin $allowed) { exit 1 }
    if ($sid -eq $self) { $selfAllowed = $true }
}
if (-not $selfAllowed) { exit 1 }
'''
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            env={**os.environ, "KEYFERRY_CAPTURE_DIR": str(output.resolve())},
            text=True, capture_output=True, timeout=15,
            check=False)
        if result.returncode:
            raise ValueError("private capture directory ACL is not owner-only")
    elif stat.S_IMODE(output.stat().st_mode) & 0o077:
        raise ValueError("private capture directory permissions are not owner-only")


def make_update_plan(installed_plan: Path, installed_build: Path, build: Path):
    pinned_site()
    inspector = module(INSPECTOR, "keyferry_update_inspector")
    previous = json.loads(installed_plan.read_text(encoding="utf-8"),
                          object_pairs_hook=unique_fields)
    if (previous.get("schema") != SCHEMA
            or previous.get("mode") not in ("STAGE_SWITCH", "APP_UPDATE")
            or previous.get("authorization_sha256") != plan_hash(previous)):
        raise ValueError("installed layout plan invalid")
    previous_image_hash = (previous["candidate_image_sha256"]
                           if previous["mode"] == "STAGE_SWITCH"
                           else previous["image_sha256"])
    previous_table_hash = (previous["candidate_table_sector_sha256"]
                           if previous["mode"] == "STAGE_SWITCH"
                           else previous["table_sector_sha256"])
    with contextlib.redirect_stdout(io.StringIO()):
        inspector.inspect_file_handoff(build)
    manifest = inspector.review_json(Path(previous["package"]) / "manifest.json")
    profile = manifest["target"]["board_profile"]
    require_board_profile(installed_build, profile)
    require_board_profile(build, profile)
    old = inspector.bounded_file(installed_build / "keyferry_hil_endpoint.bin", 0x200000)
    image = inspector.bounded_file(build / "keyferry_hil_endpoint.bin", 0x200000)
    old_table = inspector.bounded_file(
        installed_build / "partition_table/partition-table.bin", 0x1000)
    table = inspector.bounded_file(build / "partition_table/partition-table.bin", 0x1000)
    if (not image_valid(old) or not image_valid(image)
            or len(old) > 0x1F8000 or len(image) > 0x1F8000
            or len(table) != 0xC00 or table != old_table
            or len(old) != previous["image_bytes"]
            or digest(old) != previous_image_hash
            or digest(old_table.ljust(4096, b"\xff")) != previous_table_hash):
        raise ValueError("installed image or unchanged partition table differs")
    unit_record = inspector.review_json(Path(previous["unit_record"]))
    expected = {key: unit_record[key] for key in UNIT_KEYS}
    expected.update({"bootloader_sha256": manifest["preserved"]["bootloader_sha256"],
                     "partition_table_sha256": digest(table)})
    if (any(expected[key] != previous["expected_unit"][key]
            for key in UNIT_KEYS + ("bootloader_sha256",))
            or (previous["mode"] == "APP_UPDATE" and
                previous["expected_unit"]["partition_table_sha256"] != digest(table))
            or expected["secure_boot"] or expected["flash_encryption"]
            or expected["secure_download_mode"]
            or unit_record["qualified_recovery_cycles"] < 2):
        raise ValueError("installed exact-unit identity differs")
    plan = {
        "schema": SCHEMA, "mode": "APP_UPDATE",
        "installed_plan": str(installed_plan.resolve()),
        "installed_plan_sha256": inspector.sha256(installed_plan),
        "installed_build": str(installed_build.resolve()),
        "build": str(build.resolve()),
        "package": previous["package"], "unit_record": previous["unit_record"],
        "port": previous["port"], "expected_unit": expected,
        "boot_prefix_sha256": previous["boot_prefix_sha256"],
        "table_sector_sha256": digest(table.ljust(4096, b"\xff")),
        "installed_image_bytes": len(old), "installed_image_sha256": digest(old),
        "image_bytes": len(image), "image_sha256": digest(image),
    }
    plan["authorization_sha256"] = plan_hash(plan)
    return plan, image


def make_plans(backup, package, unit_record, build, current_config=None):
    common, image, table, old_stage, old_table = sources(
        backup, package, unit_record, build, current_config)
    forward = dict(common, mode="STAGE_SWITCH", image_bytes=len(image),
                   image_sha256=digest(image), table_sha256=digest(table))
    rollback = dict(common, mode="ROLLBACK", image_bytes=len(old_stage),
                    image_sha256=digest(old_stage), table_sha256=digest(old_table))
    for plan in (forward, rollback):
        plan["authorization_sha256"] = plan_hash(plan)
    return forward, rollback, image, table, old_stage, old_table


def request(plan, image, table):
    return {
        "schema": "keyferry.layout-request.v1",
        "action": "stage_switch" if plan["mode"] == "STAGE_SWITCH" else "rollback",
        "expected_unit": plan["expected_unit"],
        "boot_prefix_sha256": plan["boot_prefix_sha256"],
        "preserved_after_sha256": plan["preserved_after_sha256"],
        "old_table_sector_sha256": plan["old_table_sector_sha256"],
        "stage_before_sha256": plan["stage_before_sha256"],
        "stage_bytes": plan["stage_bytes"], "image_bytes": len(image),
        "image_sha256": digest(image), "table_sha256": digest(table),
    }


def apply(plan_file: Path, authorize: str, port: str, mode: str):
    supplied = json.loads(plan_file.read_text(encoding="utf-8"), object_pairs_hook=unique_fields)
    if (supplied.get("schema") != SCHEMA or supplied.get("mode") != mode
            or supplied.get("authorization_sha256") != authorize
            or plan_hash(supplied) != authorize
            or supplied.get("port") != port):
        raise ValueError("plan authorization or port mismatch")
    forward, rollback, image, table, old_stage, old_table = make_plans(
        *(Path(supplied[name]) for name in ("backup", "package", "unit_record", "build")),
        Path(supplied["current_config"]) if "current_config" in supplied else None)
    rebuilt = forward if mode == "STAGE_SWITCH" else rollback
    if rebuilt != supplied:
        raise ValueError("plan or source artifacts changed")
    if mode == "ROLLBACK":
        image, table = old_stage, old_table
    site = pinned_site()
    if not (port.startswith("COM") and port[3:].isdigit()
            and 1 <= len(port[3:]) <= 3 and port[3] != "0"):
        raise ValueError("invalid local ROM port")
    manifest = json.loads((Path(supplied["package"]) / "manifest.json").read_text())
    # The pinned backend owns the ROM session and process timeout. The public
    # app-only updater is never used for the partition-table write.
    wire = (json.dumps(request(supplied, image, table), separators=(",", ":")).encode()
            + b"\n" + image + table)
    environment = site.parents[1] if site.parent.name == "Lib" else site.parents[2]
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    if not python.is_file():
        raise ValueError("pinned Python executable missing")
    command = [str(python), "-I", str(BACKEND), "layout-session", "--port", port,
               "--bootloader-offset", "0", "--bootloader-size",
               str(manifest["preserved"]["bootloader_size_bytes"]),
               "--partition-table-offset", "32768", "--partition-table-size",
               str(manifest["preserved"]["partition_table_size_bytes"])]
    try:
        completed = subprocess.run(command, input=wire, capture_output=True,
                                   timeout=600, check=False)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("firmware.layout_unknown_write") from error
    if len(completed.stdout) > 4096:
        raise RuntimeError("firmware.layout_unknown_write")
    result = json.loads(completed.stdout)
    if not completed.returncode and result == {
        "schema": "keyferry.layout-result.v1",
        "outcome": "SWITCH_VERIFIED" if mode == "STAGE_SWITCH" else "ROLLBACK_VERIFIED",
    }:
        return result
    code = result.get("error", {}).get("code")
    if code == "firmware.layout_unknown_write":
        raise RuntimeError(code)
    raise ValueError(code if isinstance(code, str) else "firmware.layout_backend")


def apply_update(plan_file: Path, authorize: str, port: str):
    supplied = json.loads(plan_file.read_text(encoding="utf-8"),
                          object_pairs_hook=unique_fields)
    if (supplied.get("schema") != SCHEMA or supplied.get("mode") != "APP_UPDATE"
            or supplied.get("authorization_sha256") != authorize
            or plan_hash(supplied) != authorize or supplied.get("port") != port):
        raise ValueError("update plan authorization or port mismatch")
    rebuilt, image = make_update_plan(
        Path(supplied["installed_plan"]), Path(supplied["installed_build"]),
        Path(supplied["build"]))
    if rebuilt != supplied:
        raise ValueError("update plan or source artifacts changed")
    site = pinned_site()
    if not (port.startswith("COM") and port[3:].isdigit()
            and 1 <= len(port[3:]) <= 3 and port[3] != "0"):
        raise ValueError("invalid local ROM port")
    manifest = json.loads((Path(supplied["package"]) / "manifest.json").read_text())
    environment = site.parents[1] if site.parent.name == "Lib" else site.parents[2]
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    if not python.is_file():
        raise ValueError("pinned Python executable missing")
    wire = json.dumps({
        "schema": "keyferry.layout-update-request.v1",
        "expected_unit": supplied["expected_unit"],
        "boot_prefix_sha256": supplied["boot_prefix_sha256"],
        "table_sector_sha256": supplied["table_sector_sha256"],
        "installed_image_bytes": supplied["installed_image_bytes"],
        "installed_image_sha256": supplied["installed_image_sha256"],
        "image_bytes": len(image), "image_sha256": digest(image),
    }, separators=(",", ":")).encode() + b"\n" + image
    command = [str(python), "-I", str(BACKEND), "layout-update-session",
               "--port", port, "--bootloader-offset", "0", "--bootloader-size",
               str(manifest["preserved"]["bootloader_size_bytes"]),
               "--partition-table-offset", "32768", "--partition-table-size",
               str(manifest["preserved"]["partition_table_size_bytes"])]
    try:
        completed = subprocess.run(command, input=wire, capture_output=True,
                                   timeout=600, check=False)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("firmware.layout_unknown_write") from error
    if len(completed.stdout) > 4096:
        raise RuntimeError("firmware.layout_unknown_write")
    result = json.loads(completed.stdout)
    if not completed.returncode and result == {
            "schema": "keyferry.layout-result.v1", "outcome": "APP_UPDATE_VERIFIED"}:
        return result
    code = result.get("error", {}).get("code")
    if code == "firmware.layout_unknown_write":
        raise RuntimeError(code)
    raise ValueError(code if isinstance(code, str) else "firmware.layout_update_backend")


def refresh_config(backup: Path, package: Path, unit_record: Path, build: Path,
                   port: str, output: Path):
    common, *_ = sources(backup, package, unit_record, build)
    if port != common["port"] or not (port.startswith("COM") and port[3:].isdigit()):
        raise ValueError("exact unit port differs")
    require_private_capture_dir(output)
    site = pinned_site()
    environment = site.parents[1] if site.parent.name == "Lib" else site.parents[2]
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    if not python.is_file():
        raise ValueError("pinned Python executable missing")
    manifest = json.loads((package / "manifest.json").read_text())
    command = [str(python), "-I", str(BACKEND), "layout-config-refresh",
               "--port", port, "--bootloader-offset", "0", "--bootloader-size",
               str(manifest["preserved"]["bootloader_size_bytes"]),
               "--partition-table-offset", "32768", "--partition-table-size",
               str(manifest["preserved"]["partition_table_size_bytes"]),
               "--output", str(output.resolve())]
    wire = json.dumps({
        "schema": "keyferry.layout-config-request.v1",
        "expected_unit": common["expected_unit"],
        "backup_receipt_sha256": common["receipt_sha256"],
        "backup_snapshot_sha256": common["snapshot_sha256"],
    }, separators=(",", ":")).encode() + b"\n"
    try:
        completed = subprocess.run(command, input=wire, capture_output=True,
                                   timeout=60, check=False)
    except subprocess.TimeoutExpired as error:
        raise ValueError("firmware.layout_config_timeout") from error
    if len(completed.stdout) > 4096:
        raise ValueError("firmware.layout_config_response")
    result = json.loads(completed.stdout)
    if (completed.returncode or result.get("schema") != "keyferry.layout-config-result.v1"
            or result.get("outcome") != "CAPTURED"):
        code = result.get("error", {}).get("code")
        raise ValueError(code if isinstance(code, str) else "firmware.layout_config_backend")
    # Re-validate the private output before calling it a usable capture.
    sources(backup, package, unit_record, build, output)
    return result


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    planned = commands.add_parser("plan")
    for name in ("backup", "package", "unit-record", "build", "output-dir"):
        planned.add_argument("--" + name, required=True, type=Path)
    planned.add_argument("--current-config", type=Path)
    updated = commands.add_parser("update-plan")
    for name in ("installed-plan", "installed-build", "build", "output-dir"):
        updated.add_argument("--" + name, required=True, type=Path)
    refreshed = commands.add_parser("refresh-config")
    for name in ("backup", "package", "unit-record", "build", "output-dir"):
        refreshed.add_argument("--" + name, required=True, type=Path)
    refreshed.add_argument("--port", required=True)
    for mode in ("apply", "rollback"):
        command = commands.add_parser(mode)
        command.add_argument("--plan", required=True, type=Path)
        command.add_argument("--authorize", required=True)
        command.add_argument("--port", required=True)
    update_apply = commands.add_parser("apply-update")
    update_apply.add_argument("--plan", required=True, type=Path)
    update_apply.add_argument("--authorize", required=True)
    update_apply.add_argument("--port", required=True)
    args = parser.parse_args()
    try:
        if args.command == "plan":
            forward, rollback, *_ = make_plans(args.backup, args.package,
                                                args.unit_record, args.build,
                                                args.current_config)
            args.output_dir.mkdir(parents=False, exist_ok=False)
            for name, plan in (("stage-switch-plan.json", forward),
                               ("rollback-plan.json", rollback)):
                (args.output_dir / name).write_text(
                    json.dumps(plan, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            result = {"schema": SCHEMA, "outcome": "PLANNED_ONLY",
                      "stage_switch_authorization_sha256": forward["authorization_sha256"],
                      "rollback_authorization_sha256": rollback["authorization_sha256"]}
        elif args.command == "refresh-config":
            result = refresh_config(args.backup, args.package, args.unit_record,
                                    args.build, args.port, args.output_dir)
        elif args.command == "update-plan":
            plan, _ = make_update_plan(args.installed_plan, args.installed_build,
                                       args.build)
            args.output_dir.mkdir(parents=False, exist_ok=False)
            (args.output_dir / "app-update-plan.json").write_text(
                json.dumps(plan, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            result = {"schema": SCHEMA, "outcome": "PLANNED_ONLY",
                      "app_update_authorization_sha256": plan["authorization_sha256"]}
        elif args.command == "apply-update":
            result = apply_update(args.plan, args.authorize, args.port)
        else:
            mode = "STAGE_SWITCH" if args.command == "apply" else "ROLLBACK"
            result = apply(args.plan, args.authorize, args.port, mode)
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except Exception as error:
        unknown = isinstance(error, RuntimeError) and str(error) == "firmware.layout_unknown_write"
        print(json.dumps({"schema": SCHEMA,
                          "outcome": "UNKNOWN_WRITE" if unknown else "REJECTED",
                          "error": str(error) if str(error).startswith("firmware.")
                                   else "firmware.layout_validation"}, separators=(",", ":")))
        return 25 if unknown else 20


if __name__ == "__main__":
    raise SystemExit(main())
