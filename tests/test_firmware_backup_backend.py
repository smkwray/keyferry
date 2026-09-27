"""Exercise ROM backup behavior without contacting a device."""
import importlib.util
import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def backend():
    root = Path(__file__).resolve().parents[1]
    esptool = types.ModuleType("esptool")
    esptool.__version__ = "5.4.0"
    esptool.cmds = types.ModuleType("esptool.cmds")
    logger = types.ModuleType("esptool.logger")
    logger.TemplateLogger = type("TemplateLogger", (), {})
    logger.log = types.SimpleNamespace()
    util = types.ModuleType("esptool.util")
    util.flash_size_bytes = lambda value: value
    efuse = types.ModuleType("espefuse.efuse_interface")
    efuse.init_commands = lambda **kwargs: None
    modules = {"esptool": esptool, "esptool.cmds": esptool.cmds,
               "esptool.logger": logger, "esptool.util": util,
               "espefuse": types.ModuleType("espefuse"),
               "espefuse.efuse_interface": efuse}
    with patch.dict(sys.modules, modules):
        spec = importlib.util.spec_from_file_location(
            "backup_backend_under_test", root / "tools/keyferry-firmware/esptool_backend.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


class Rom:
    def __init__(self):
        self.closed = False

    def __exit__(self, *_):
        self.closed = True


class BackupTest(unittest.TestCase):
    def setUp(self):
        self.b = backend()
        self.rom = Rom()
        self.flash = bytes(i % 251 for i in range(2 * 65536))
        self.reads = []
        self.old_stdin, self.old_stdout = self.b.sys.stdin, self.b.sys.stdout
        self.b.sys.stdin = types.SimpleNamespace(buffer=io.BytesIO(
            json.dumps({"schema": "keyferry.backup-request.v1", "action": "read_full_flash",
                        "flash_size_bytes": len(self.flash)}).encode() + b"\n"))
        self.b.sys.stdout = io.StringIO()
        self.open_patch = patch.object(self.b, "_open_rom", return_value=self.rom)
        self.observe_patch = patch.object(self.b, "_observe_attached", return_value={
            "flash_size_bytes": len(self.flash), "port": "COM7"})
        self.open_patch.start()
        self.observe_patch.start()

    def tearDown(self):
        self.open_patch.stop()
        self.observe_patch.stop()
        self.b.sys.stdin, self.b.sys.stdout = self.old_stdin, self.old_stdout

    def execute(self, reader):
        self.b.cmds.read_flash = reader
        self.b.cmds.write_flash = lambda *_args, **_kwargs: self.fail("device write")
        self.b.cmds.erase_region = lambda *_args, **_kwargs: self.fail("device erase")
        with tempfile.TemporaryDirectory() as temp:
            args = types.SimpleNamespace(port="COM7", output=temp)
            try:
                result = self.b._backup_session(args)
                partial = (Path(temp) / "full-flash.partial").read_bytes()
                self.assertFalse((Path(temp) / "full-flash.bin").exists())
                return result, partial
            finally:
                self.assertTrue(self.rom.closed)
                self.assertFalse((Path(temp) / "full-flash.bin").exists())
                if sys.exc_info()[0] is not None:
                    self.assertFalse((Path(temp) / "full-flash.partial").exists())

    def test_two_bounded_identical_passes(self):
        def read(_rom, offset, size, **_):
            self.reads.append((offset, size))
            return self.flash[offset:offset + size]
        result, partial = self.execute(read)
        self.assertEqual(partial, self.flash)
        self.assertTrue(result["second_pass_equal"])
        self.assertEqual(self.reads, [(0, 65536), (65536, 65536)] * 2)

    def test_second_pass_difference(self):
        def read(_rom, offset, size, **_):
            self.reads.append(offset)
            return bytes(size) if len(self.reads) > 2 else self.flash[offset:offset + size]
        with self.assertRaisesRegex(Exception, "firmware.backup_difference"):
            self.execute(read)

    def test_short_read(self):
        with self.assertRaisesRegex(Exception, "firmware.backup_short_read"):
            self.execute(lambda _rom, offset, size, **_: bytes(size - 1))

    def test_io_failure(self):
        def fail(*_args, **_kwargs):
            raise OSError("read failed")
        with self.assertRaisesRegex(Exception, "firmware.backup_read"):
            self.execute(fail)

    def test_changed_final_identity(self):
        observations = [{"flash_size_bytes": len(self.flash), "port": "COM7"},
                        {"flash_size_bytes": len(self.flash), "port": "COM8"}]
        self.observe_patch.stop()
        self.observe_patch = patch.object(self.b, "_observe_attached", side_effect=observations)
        self.observe_patch.start()
        with self.assertRaisesRegex(Exception, "firmware.backup_identity_changed"):
            self.execute(lambda _rom, offset, size, **_: self.flash[offset:offset + size])

    def test_interruption_retains_only_private_partial(self):
        calls = 0

        def interrupt(_rom, offset, size, **_):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise KeyboardInterrupt()
            return self.flash[offset:offset + size]

        self.b.cmds.read_flash = interrupt
        with tempfile.TemporaryDirectory() as temp:
            args = types.SimpleNamespace(port="COM7", output=temp)
            with self.assertRaises(KeyboardInterrupt):
                self.b._backup_session(args)
            self.assertTrue((Path(temp) / "full-flash.partial").exists())
            self.assertFalse((Path(temp) / "full-flash.bin").exists())
            self.assertFalse((Path(temp) / "receipt.json").exists())
            self.assertTrue(self.rom.closed)

    def test_bad_request_never_bulk_reads(self):
        self.b.sys.stdin = types.SimpleNamespace(buffer=io.BytesIO(b"{}\n"))
        with self.assertRaisesRegex(Exception, "firmware.backup_protocol"):
            self.execute(lambda *_args, **_kwargs: self.fail("unauthorized read"))

    def test_existing_snapshot_refuses_without_bulk_read(self):
        self.b.cmds.read_flash = lambda *_args, **_kwargs: self.fail("bulk read into reused output")
        with tempfile.TemporaryDirectory() as temp:
            existing = Path(temp) / "full-flash.bin"
            existing.write_bytes(b"keep")
            args = types.SimpleNamespace(port="COM7", output=temp)
            with self.assertRaisesRegex(Exception, "firmware.backup_output"):
                self.b._backup_session(args)
            self.assertEqual(existing.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
