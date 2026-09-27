"""Exact layout writes are exercised only against an in-memory fake ROM."""

import hashlib
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from tests.test_firmware_backup_backend import Rom, backend


def sha(data):
    return hashlib.sha256(data).hexdigest()


class LayoutBackendTest(unittest.TestCase):
    def setUp(self):
        self.b = backend()
        self.rom = Rom()
        self.flash = bytearray(b"\xff" * 0x124000)
        self.old_table = b"T" * 4096
        self.flash[0x8000:0x9000] = self.old_table
        self.image = b"I" * 5000
        self.padded = self.image.ljust(8192, b"\xff")
        self.new_table = b"N" * 4096
        self.unit = {
            "rom_mac": "02:00:00:00:00:55", "chip": "esp32s3",
            "soc_revision": "v0.2", "flash_manufacturer_id": "0xef",
            "flash_device_id": "0x4018", "flash_size_bytes": 0x1000000,
            "secure_boot": False, "flash_encryption": False,
            "secure_download_mode": False, "efuse_sha256": "a" * 64,
            "bootloader_sha256": "b" * 64,
            "partition_table_sha256": "c" * 64,
        }
        self.request = {
            "schema": "keyferry.layout-request.v1", "action": "stage_switch",
            "expected_unit": dict(self.unit),
            "boot_prefix_sha256": sha(self.flash[:0x8000]),
            "old_table_sector_sha256": sha(self.old_table),
            "preserved_after_sha256": sha(self.flash[0x9000:0x120000]),
            "stage_before_sha256": sha(self.flash[0x120000:0x122000]),
            "stage_bytes": 8192, "image_bytes": len(self.image),
            "image_sha256": sha(self.image), "table_sha256": sha(self.new_table),
        }
        self.writes = []
        self.original_stdin = self.b.sys.stdin
        self.open_patch = patch.object(self.b, "_open_rom", return_value=self.rom)
        self.observe_patch = patch.object(self.b, "_observe_attached",
                                          side_effect=lambda *_: dict(self.unit))
        self.open_patch.start()
        self.observe_patch.start()
        self.b.cmds.read_flash = lambda _esp, offset, length, **_kwargs: bytes(
            self.flash[offset:offset + length])
        self.b.cmds.write_flash = self.write

    def tearDown(self):
        self.open_patch.stop()
        self.observe_patch.stop()
        self.b.sys.stdin = self.original_stdin

    def write(self, _esp, regions, **_kwargs):
        for offset, data in regions:
            self.writes.append((offset, len(data)))
            self.flash[offset:offset + len(data)] = data

    def run_session(self, image=None, table=None):
        image = self.image if image is None else image
        table = self.new_table if table is None else table
        wire = json.dumps(self.request).encode() + b"\n" + image + table
        self.b.sys.stdin = types.SimpleNamespace(buffer=io.BytesIO(wire))
        args = types.SimpleNamespace(port="COM7", bootloader_offset=0,
                                     bootloader_size=21136,
                                     partition_table_offset=0x8000,
                                     partition_table_size=3072)
        return self.b._layout_session(args)

    def test_stage_then_table_only_switch(self):
        result = self.run_session()
        self.assertEqual(result["outcome"], "SWITCH_VERIFIED")
        self.assertEqual(self.writes, [(0x120000, 8192), (0x8000, 4096)])
        self.assertEqual(self.flash[0x120000:0x122000], self.padded)
        self.assertEqual(self.flash[0x8000:0x9000], self.new_table)
        self.assertTrue(self.rom.closed)

    def test_mismatch_rejects_before_any_write(self):
        for field in ("boot_prefix_sha256", "preserved_after_sha256",
                      "stage_before_sha256", "old_table_sector_sha256"):
            with self.subTest(field=field):
                self.request[field] = "0" * 64
                with self.assertRaises(self.b._ProbeError):
                    self.run_session()
                self.assertEqual(self.writes, [])
                self.request[field] = sha(self.flash[
                    {"boot_prefix_sha256": slice(0, 0x8000),
                     "preserved_after_sha256": slice(0x9000, 0x120000),
                     "stage_before_sha256": slice(0x120000, 0x122000),
                     "old_table_sector_sha256": slice(0x8000, 0x9000)}[field]])
        self.request["expected_unit"]["efuse_sha256"] = "0" * 64
        with self.assertRaises(self.b._ProbeError):
            self.run_session()
        self.assertEqual(self.writes, [])

    def test_stage_failure_never_writes_table_and_is_unknown(self):
        def broken(_esp, regions, **_kwargs):
            self.writes.append((regions[0][0], len(regions[0][1])))
            raise RuntimeError("interrupted after possible write")
        self.b.cmds.write_flash = broken
        with self.assertRaisesRegex(self.b._ProbeError, "firmware.layout_unknown_write"):
            self.run_session()
        self.assertEqual(self.writes, [(0x120000, 8192)])
        self.assertEqual(self.flash[0x8000:0x9000], self.old_table)

    def test_payload_digest_failure_does_not_open_rom_or_write(self):
        self.request["image_sha256"] = "0" * 64
        with self.assertRaisesRegex(self.b._ProbeError, "firmware.layout_protocol"):
            self.run_session()
        self.assertEqual(self.writes, [])
        self.assertFalse(self.rom.closed)

    def test_table_failure_is_unknown_without_automatic_rollback(self):
        original = self.write
        def broken(esp, regions, **kwargs):
            if regions[0][0] == 0x8000:
                self.writes.append((0x8000, 4096))
                self.flash[0x8000:0x8800] = b"?" * 2048
                raise RuntimeError("partial table")
            original(esp, regions, **kwargs)
        self.b.cmds.write_flash = broken
        with self.assertRaisesRegex(self.b._ProbeError, "firmware.layout_unknown_write"):
            self.run_session()
        self.assertEqual(self.writes, [(0x120000, 8192), (0x8000, 4096)])
        self.assertNotEqual(self.flash[0x8000:0x9000], self.old_table)

    def test_explicit_rollback_accepts_torn_table_and_restores_stage(self):
        self.flash[0x8000:0x9000] = b"?" * 4096
        self.flash[0x120000:0x122000] = self.padded
        self.request["action"] = "rollback"
        self.request["image_bytes"] = 8192
        self.request["image_sha256"] = sha(b"\xff" * 8192)
        self.request["table_sha256"] = sha(self.old_table)
        result = self.run_session(b"\xff" * 8192, self.old_table)
        self.assertEqual(result["outcome"], "ROLLBACK_VERIFIED")
        self.assertEqual(self.writes, [(0x8000, 4096), (0x120000, 8192)])
        self.assertEqual(self.flash[0x8000:0x9000], self.old_table)
        self.assertEqual(self.flash[0x120000:0x122000], b"\xff" * 8192)

    def test_rollback_rejects_changed_old_app_before_table_write(self):
        self.request["action"] = "rollback"
        self.request["image_bytes"] = 8192
        self.request["image_sha256"] = sha(b"\xff" * 8192)
        self.request["table_sha256"] = sha(self.old_table)
        self.flash[0x10000] = 0x12
        with self.assertRaisesRegex(self.b._ProbeError, "firmware.layout_preserved_mismatch"):
            self.run_session(b"\xff" * 8192, self.old_table)
        self.assertEqual(self.writes, [])

    def test_config_refresh_reads_only_bounded_span_twice(self):
        reads = []
        def read(_esp, offset, length, **_kwargs):
            reads.append((offset, length))
            return bytes(self.flash[offset:offset + length])
        self.b.cmds.read_flash = read
        request = {"schema": "keyferry.layout-config-request.v1",
                   "expected_unit": self.unit,
                   "backup_receipt_sha256": "a" * 64,
                   "backup_snapshot_sha256": "b" * 64}
        self.b.sys.stdin = types.SimpleNamespace(buffer=io.BytesIO(
            json.dumps(request).encode() + b"\n"))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capture"
            output.mkdir()
            args = types.SimpleNamespace(port="COM7", output=str(output),
                                         bootloader_offset=0, bootloader_size=21136,
                                         partition_table_offset=0x8000,
                                         partition_table_size=3072)
            result = self.b._layout_config_refresh(args)
            self.assertEqual(result["outcome"], "CAPTURED")
            self.assertEqual(reads, [(0x110000, 0xB000)] * 2)
            self.assertEqual((output / "config.bin").read_bytes(),
                             bytes(self.flash[0x110000:0x11B000]))
            self.assertEqual(json.loads((output / "receipt.json").read_text())[
                "backup_snapshot_sha256"], "b" * 64)
            self.assertEqual(self.writes, [])

    def test_config_refresh_changed_second_read_keeps_output_empty(self):
        calls = 0
        def read(_esp, offset, length, **_kwargs):
            nonlocal calls
            calls += 1
            return bytes([calls]) * length
        self.b.cmds.read_flash = read
        request = {"schema": "keyferry.layout-config-request.v1",
                   "expected_unit": self.unit,
                   "backup_receipt_sha256": "a" * 64,
                   "backup_snapshot_sha256": "b" * 64}
        self.b.sys.stdin = types.SimpleNamespace(buffer=io.BytesIO(
            json.dumps(request).encode() + b"\n"))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capture"
            output.mkdir()
            args = types.SimpleNamespace(port="COM7", output=str(output),
                                         bootloader_offset=0, bootloader_size=21136,
                                         partition_table_offset=0x8000,
                                         partition_table_size=3072)
            with self.assertRaisesRegex(self.b._ProbeError,
                                        "firmware.layout_config_changed"):
                self.b._layout_config_refresh(args)
            self.assertEqual(list(output.iterdir()), [])

    def run_update(self, image=b"J" * 6000):
        self.flash[0x120000:0x120000 + len(self.image)] = self.image
        request = {
            "schema": "keyferry.layout-update-request.v1",
            "expected_unit": self.unit,
            "boot_prefix_sha256": sha(self.flash[:0x8000]),
            "table_sector_sha256": sha(self.old_table),
            "installed_image_bytes": len(self.image),
            "installed_image_sha256": sha(self.image),
            "image_bytes": len(image), "image_sha256": sha(image),
        }
        self.b.sys.stdin = types.SimpleNamespace(buffer=io.BytesIO(
            json.dumps(request).encode() + b"\n" + image))
        args = types.SimpleNamespace(port="COM7", bootloader_offset=0,
                                     bootloader_size=21136,
                                     partition_table_offset=0x8000,
                                     partition_table_size=3072)
        return self.b._layout_update_session(args)

    def test_update_writes_only_app_and_preserves_live_config(self):
        self.flash[0x110000:0x11B000] = b"C" * 0xB000
        protected = bytes(self.flash[:0x120000])
        result = self.run_update()
        self.assertEqual(result["outcome"], "APP_UPDATE_VERIFIED")
        self.assertEqual(self.writes, [(0x120000, 8192)])
        self.assertEqual(bytes(self.flash[:0x120000]), protected)

    def test_update_mismatched_installed_app_rejects_before_write(self):
        self.image = b"Q" * 5000
        def read(_esp, offset, length, **_kwargs):
            data = bytes(self.flash[offset:offset + length])
            return b"?" + data[1:] if offset == 0x120000 else data
        self.b.cmds.read_flash = read
        with self.assertRaisesRegex(self.b._ProbeError,
                                    "firmware.layout_update_before_mismatch"):
            self.run_update()
        self.assertEqual(self.writes, [])

    def test_update_protected_change_after_write_is_unknown(self):
        original = self.write
        def changed(esp, regions, **kwargs):
            original(esp, regions, **kwargs)
            self.flash[0x110000] ^= 1
        self.b.cmds.write_flash = changed
        with self.assertRaisesRegex(self.b._ProbeError, "firmware.layout_unknown_write"):
            self.run_update()
        self.assertEqual(self.writes, [(0x120000, 8192)])


if __name__ == "__main__":
    unittest.main()
