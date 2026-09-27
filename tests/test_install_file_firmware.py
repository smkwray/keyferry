"""Offline authorization boundary for the exact-unit layout installer."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install_file_firmware.py"
SPEC = importlib.util.spec_from_file_location("install_file_firmware", SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallFileFirmwareTest(unittest.TestCase):
    def test_successive_app_update_binds_prior_plan_and_image(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            installed, candidate, package = (base / name for name in
                                             ("installed", "candidate", "package"))
            for path in (installed / "partition_table",
                         candidate / "partition_table", package):
                path.mkdir(parents=True)
            old, new, table = b"oldapp", b"newapp", b"T" * 3072
            (installed / "keyferry_hil_endpoint.bin").write_bytes(old)
            (candidate / "keyferry_hil_endpoint.bin").write_bytes(new)
            for path in (installed, candidate):
                (path / "partition_table/partition-table.bin").write_bytes(table)
                (path / "CMakeCache.txt").write_text(
                    "KEYFERRY_BOARD:STRING=waveshare_geek_v1_1_reference\n")
            (package / "manifest.json").write_text(json.dumps({
                "target": {"board_profile": "waveshare_geek_v1_1_reference"},
                "preserved": {"bootloader_sha256": "a" * 64}}))
            unit = {key: "unit" for key in installer.UNIT_KEYS}
            unit.update({"qualified_recovery_cycles": 2, "secure_boot": False,
                         "flash_encryption": False, "secure_download_mode": False})
            record = base / "unit.json"
            record.write_text(json.dumps(unit))
            expected = {key: unit[key] for key in installer.UNIT_KEYS}
            expected.update({"bootloader_sha256": "a" * 64,
                             "partition_table_sha256": installer.digest(table)})
            previous = {
                "schema": installer.SCHEMA, "mode": "APP_UPDATE",
                "package": str(package), "unit_record": str(record), "port": "COM7",
                "expected_unit": expected, "boot_prefix_sha256": "b" * 64,
                "image_bytes": len(old), "image_sha256": installer.digest(old),
                "table_sector_sha256": installer.digest(table.ljust(4096, b"\xff")),
            }
            previous["authorization_sha256"] = installer.plan_hash(previous)
            prior = base / "prior.json"
            prior.write_text(json.dumps(previous))
            class Inspector:
                inspect_file_handoff = staticmethod(lambda *_: None)
                bounded_file = staticmethod(lambda path, maximum: path.read_bytes())
                review_json = staticmethod(lambda path: json.loads(path.read_text()))
                sha256 = staticmethod(lambda path: installer.digest(path.read_bytes()))
            with patch.object(installer, "pinned_site"), patch.object(
                    installer, "module", return_value=Inspector), patch.object(
                    installer, "image_valid", return_value=True):
                plan, payload = installer.make_update_plan(prior, installed, candidate)
                self.assertEqual(payload, new)
                self.assertEqual(plan["installed_image_sha256"], installer.digest(old))
                self.assertEqual(plan["table_sector_sha256"],
                                 previous["table_sector_sha256"])
                (candidate / "CMakeCache.txt").write_text(
                    "KEYFERRY_BOARD:STRING=lilygo_t_dongle_s3\n")
                with self.assertRaisesRegex(ValueError, "board profile"):
                    installer.make_update_plan(prior, installed, candidate)
                (candidate / "CMakeCache.txt").write_text(
                    "KEYFERRY_BOARD:STRING=waveshare_geek_v1_1_reference\n")
                (installed / "CMakeCache.txt").write_text(
                    "KEYFERRY_BOARD:STRING=lilygo_t_dongle_s3\n")
                with self.assertRaisesRegex(ValueError, "board profile"):
                    installer.make_update_plan(prior, installed, candidate)
                (installed / "CMakeCache.txt").write_text(
                    "KEYFERRY_BOARD:STRING=waveshare_geek_v1_1_reference\n")
                (installed / "keyferry_hil_endpoint.bin").write_bytes(b"?" + old[1:])
                with self.assertRaisesRegex(ValueError, "installed image"):
                    installer.make_update_plan(prior, installed, candidate)
                (installed / "keyferry_hil_endpoint.bin").write_bytes(old)
                previous["image_sha256"] = "0" * 64
                prior.write_text(json.dumps(previous))
                with self.assertRaisesRegex(ValueError, "plan invalid"):
                    installer.make_update_plan(prior, installed, candidate)

    def test_config_capture_rejects_broad_permissions_before_rom(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "hardware/evidence/private/capture"
            output.mkdir(parents=True)
            with patch.object(installer, "ROOT", root), patch.object(
                    installer, "sources", return_value=({"port": "COM7"},)), patch.object(
                    installer, "pinned_site") as pinned, patch.object(
                    installer.subprocess, "run") as rom:
                if os.name == "nt":
                    rom.return_value.returncode = 1
                else:
                    output.chmod(0o755)
                with self.assertRaisesRegex(ValueError, "owner-only"):
                    installer.refresh_config(root, root, root, root, "COM7", output)
                pinned.assert_not_called()
                if os.name == "nt":
                    self.assertEqual(rom.call_count, 1)
                    self.assertEqual(rom.call_args.args[0][0], "powershell.exe")
                else:
                    rom.assert_not_called()

    def test_private_capture_directory_requires_restricted_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "hardware/evidence/private/capture"
            output.mkdir(parents=True)
            with patch.object(installer, "ROOT", root):
                if os.name == "nt":
                    subprocess.run(["icacls", str(output), "/grant:r",
                                    "*S-1-1-0:(OI)(CI)R", "/q"],
                                   capture_output=True, check=True)
                else:
                    output.chmod(0o755)
                with self.assertRaisesRegex(ValueError, "owner-only"):
                    installer.require_private_capture_dir(output)
                if os.name == "nt":
                    identity = subprocess.check_output(
                        ["whoami", "/user", "/fo", "csv", "/nh"], text=True)
                    sid = identity.split(",")[1].strip().strip('"')
                    subprocess.run(["icacls", str(output), "/inheritance:r",
                                    f"/grant:r", f"*{sid}:(OI)(CI)F", "/remove:g",
                                    "*S-1-1-0", "/q"], capture_output=True, check=True)
                else:
                    output.chmod(0o700)
                installer.require_private_capture_dir(output)

    def test_config_overlay_changes_only_bound_preserved_span(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            backup, package, build, config = (base / name for name in
                                              ("backup", "package", "build", "config"))
            for path in (backup, package, build / "partition_table", config):
                path.mkdir(parents=True)
            snapshot = b"X" * (0x120000 + 4096)
            (backup / "full-flash.bin").write_bytes(snapshot)
            (backup / "receipt.json").write_text(json.dumps({
                "port": "COM7", "snapshot": {"sha256": installer.digest(snapshot)}}))
            (package / "manifest.json").write_text(json.dumps({"preserved": {
                "bootloader_sha256": "a" * 64, "partition_table_sha256": "b" * 64}}))
            unit = {key: "unit" for key in installer.UNIT_KEYS}
            unit.update({"qualified_recovery_cycles": 2, "secure_boot": False,
                         "flash_encryption": False, "secure_download_mode": False})
            record = base / "unit.json"
            record.write_text(json.dumps(unit))
            (build / "keyferry_hil_endpoint.bin").write_bytes(b"image")
            (build / "partition_table/partition-table.bin").write_bytes(b"T" * 3072)
            class Inspector:
                inspect_file_handoff = staticmethod(lambda *_: None)
                inspect_backup = staticmethod(lambda *_: None)
                review_json = staticmethod(lambda path: json.loads(path.read_text()))
                bounded_file = staticmethod(lambda path, maximum: path.read_bytes())
                sha256 = staticmethod(lambda path: installer.digest(path.read_bytes()))
            with patch.object(installer, "pinned_site"), patch.object(
                    installer, "module", return_value=Inspector), patch.object(
                    installer, "image_valid", return_value=True):
                original, *_ = installer.sources(backup, package, record, build)
                captured = b"C" * 0xB000
                (config / "config.bin").write_bytes(captured)
                receipt = {
                    "schema": "keyferry.layout-config-receipt.v1",
                    "expected_unit": original["expected_unit"],
                    "backup_receipt_sha256": original["receipt_sha256"],
                    "backup_snapshot_sha256": original["snapshot_sha256"],
                    "offset": 0x110000, "size_bytes": 0xB000,
                    "config_sha256": installer.digest(captured),
                    "second_pass_equal": True,
                }
                (config / "receipt.json").write_text(json.dumps(receipt))
                overlaid, *_ = installer.sources(backup, package, record, build, config)
                retained = snapshot[0x9000:0x120000]
                start = 0x110000 - 0x9000
                expected = retained[:start] + captured + retained[start + len(captured):]
                self.assertEqual(overlaid["preserved_after_sha256"],
                                 installer.digest(expected))
                self.assertEqual(overlaid["boot_prefix_sha256"],
                                 original["boot_prefix_sha256"])
                self.assertEqual(overlaid["stage_before_sha256"],
                                 original["stage_before_sha256"])
                (config / "config.bin").write_bytes(b"?" + captured[1:])
                with self.assertRaisesRegex(ValueError, "binding differs"):
                    installer.sources(backup, package, record, build, config)

    def test_rejects_tampered_plan_before_sources_or_rom(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = {"schema": installer.SCHEMA, "mode": "STAGE_SWITCH",
                    "port": "COM7", "backup": "source"}
            plan["authorization_sha256"] = installer.plan_hash(plan)
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(plan), encoding="utf-8")
            with patch.object(installer, "make_plans") as sources, patch.object(
                    installer.subprocess, "run") as rom:
                plan["backup"] = "tampered"
                path.write_text(json.dumps(plan), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "authorization"):
                    installer.apply(path, plan["authorization_sha256"], "COM7",
                                    "STAGE_SWITCH")
                sources.assert_not_called()
                rom.assert_not_called()

    def test_matching_plan_sends_only_bounded_layout_request(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site = base / "environment/Lib/site-packages"
            site.mkdir(parents=True)
            binary = base / "environment/Scripts/python.exe"
            binary.parent.mkdir(parents=True)
            binary.touch()
            package = base / "package"
            package.mkdir()
            (package / "manifest.json").write_text(json.dumps({"preserved": {
                "bootloader_size_bytes": 21136, "partition_table_size_bytes": 3072}}),
                encoding="utf-8")
            plan = {
                "schema": installer.SCHEMA, "mode": "STAGE_SWITCH", "port": "COM7",
                "backup": str(base / "backup"), "package": str(package),
                "unit_record": str(base / "unit-record.json"), "build": str(base / "build"),
                "expected_unit": {}, "boot_prefix_sha256": "a" * 64,
                "preserved_after_sha256": "b" * 64,
                "old_table_sector_sha256": "c" * 64,
                "stage_before_sha256": "d" * 64, "stage_bytes": 4096,
            }
            plan["authorization_sha256"] = installer.plan_hash(plan)
            path = base / "plan.json"
            path.write_text(json.dumps(plan), encoding="utf-8")
            image, table = b"image", b"T" * 4096
            result = {"schema": "keyferry.layout-result.v1", "outcome": "SWITCH_VERIFIED"}
            with patch.object(installer, "make_plans", return_value=(
                    plan, {}, image, table, b"", b"")), patch.object(
                    installer, "pinned_site", return_value=site), patch.object(
                    installer.subprocess, "run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = json.dumps(result).encode()
                self.assertEqual(installer.apply(path, plan["authorization_sha256"],
                                                 "COM7", "STAGE_SWITCH"), result)
                args, kwargs = run.call_args
                self.assertEqual(Path(args[0][0]), binary)
                self.assertEqual(args[0][3], "layout-session")
                self.assertEqual(kwargs["timeout"], 600)
                self.assertTrue(kwargs["input"].endswith(image + table))

    def test_app_update_authorization_and_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site = base / "environment/Lib/site-packages"
            site.mkdir(parents=True)
            binary = base / "environment/Scripts/python.exe"
            binary.parent.mkdir(parents=True)
            binary.touch()
            package = base / "package"
            package.mkdir()
            (package / "manifest.json").write_text(json.dumps({"preserved": {
                "bootloader_size_bytes": 21136, "partition_table_size_bytes": 3072}}))
            plan = {"schema": installer.SCHEMA, "mode": "APP_UPDATE", "port": "COM7",
                    "installed_plan": str(base / "installed-plan.json"),
                    "installed_build": str(base / "installed"),
                    "build": str(base / "candidate"), "package": str(package),
                    "expected_unit": {}, "boot_prefix_sha256": "a" * 64,
                    "table_sector_sha256": "b" * 64,
                    "installed_image_bytes": 5,
                    "installed_image_sha256": "c" * 64,
                    "image_bytes": 6, "image_sha256": installer.digest(b"newapp")}
            plan["authorization_sha256"] = installer.plan_hash(plan)
            path = base / "plan.json"
            path.write_text(json.dumps(plan))
            with patch.object(installer, "make_update_plan",
                              return_value=(plan, b"newapp")) as rebuild, patch.object(
                    installer, "pinned_site", return_value=site), patch.object(
                    installer.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "authorization"):
                    installer.apply_update(path, "0" * 64, "COM7")
                rebuild.assert_not_called()
                run.assert_not_called()
                result = {"schema": "keyferry.layout-result.v1",
                          "outcome": "APP_UPDATE_VERIFIED"}
                run.return_value.returncode = 0
                run.return_value.stdout = json.dumps(result).encode()
                self.assertEqual(installer.apply_update(
                    path, plan["authorization_sha256"], "COM7"), result)
                args, kwargs = run.call_args
                self.assertEqual(Path(args[0][0]), binary)
                self.assertEqual(args[0][3], "layout-update-session")
                self.assertTrue(kwargs["input"].endswith(b"newapp"))


if __name__ == "__main__":
    unittest.main()
