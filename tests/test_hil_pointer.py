"""Reject an Atom image with the wrong compiled USB personality."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pointer", ROOT / "scripts/check_hil_pointer.py")
pointer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pointer)


class AtomPointerDescriptorTests(unittest.TestCase):
    def setUp(self):
        self.report = pointer.descriptor()
        # USB byte fixture independent of the source's TinyUSB macro expansion.
        self.config = bytes.fromhex(
            "09025b000301008032"
            "0904000001030101040921110100012241000705810308000a"
            "0904010002030000050921110100012222000705020340000a0705820340000a"
            "0904020001030000060921110100012280000705830308000a")
        self.device = bytes.fromhex("12010002000000403a300440020101020301")

    def test_three_interface_extended_personality(self):
        pointer.atom_usb_descriptors(self.config + self.device, self.report)

    def test_legacy_pointer_or_msc_is_rejected(self):
        for offset, value in ((4, 4), (72, 1), (73, 2), (82, 50)):
            bad = bytearray(self.config)
            bad[offset] = value
            with self.subTest(offset=offset), self.assertRaises(SystemExit):
                pointer.atom_usb_descriptors(bytes(bad) + self.device, self.report)

    def test_keyboard_provisioning_or_endpoint_drift_is_rejected(self):
        for offset in (16, 54, 61, 86):
            bad = bytearray(self.config)
            bad[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(SystemExit):
                pointer.atom_usb_descriptors(bytes(bad) + self.device, self.report)

    def test_old_revision_is_rejected(self):
        bad = bytearray(self.device)
        bad[12] = 1
        with self.assertRaises(SystemExit):
            pointer.atom_usb_descriptors(self.config + bytes(bad), self.report)


if __name__ == "__main__":
    unittest.main()
