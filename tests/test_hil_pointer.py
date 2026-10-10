"""Reject an Atom image with the wrong compiled USB personality."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
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
        pointer.no_msc_usb_descriptors(self.config + self.device, self.report)

    def test_legacy_pointer_or_msc_is_rejected(self):
        for offset, value in ((4, 4), (72, 1), (73, 2), (82, 50)):
            bad = bytearray(self.config)
            bad[offset] = value
            with self.subTest(offset=offset), self.assertRaises(SystemExit):
                pointer.no_msc_usb_descriptors(bytes(bad) + self.device, self.report)

    def test_keyboard_provisioning_or_endpoint_drift_is_rejected(self):
        for offset in (16, 54, 61, 86):
            bad = bytearray(self.config)
            bad[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(SystemExit):
                pointer.no_msc_usb_descriptors(bytes(bad) + self.device, self.report)

    def test_lilygo_uses_same_no_msc_personality(self):
        pointer.no_msc_usb_descriptors(self.config + self.device, self.report)
        with self.assertRaises(SystemExit):
            pointer.no_msc_usb_descriptors(self.config + self.device.replace(bytes.fromhex("0440"), bytes.fromhex("0840")), self.report)

    def test_old_revision_is_rejected(self):
        bad = bytearray(self.device)
        bad[12] = 1
        with self.assertRaises(SystemExit):
            pointer.no_msc_usb_descriptors(self.config + bytes(bad), self.report)


class UsbIdentityTests(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / "firmware/esp32s3/hil_endpoint/main/app_main.cpp").read_text()

    def test_generic_names_and_unchanged_serial(self):
        from check_hil_mouse import check_usb_identity
        check_usb_identity(self.source)

    def test_old_product_or_changed_serial_is_rejected(self):
        from check_hil_mouse import check_usb_identity
        for old, new in (
            ("keyferry::usb_identity::kProduct,", '"keyferry owner device",'),
            ("kSerialDescriptor.data(),", '"GENERIC-SERIAL",'),
            ("0123456789ABCDEF", "0123456789abcdef"),
            ("BuildSerialDescriptor(keyferry::hil_private::kDeviceId);", "BuildSerialDescriptor({});"),
        ):
            with self.subTest(old=old), self.assertRaises(SystemExit):
                check_usb_identity(self.source.replace(old, new))

    def test_compiled_names_are_required(self):
        from check_hil_mouse import check_usb_identity
        strings = b"Generic\0USB Input Device\0Keyboard\0USB Interface\0Mouse\0"
        check_usb_identity(self.source, strings)
        for bad in (strings.replace(b"Generic", b"keyferry"),
                    strings + b"keyferry owner device\0"):
            with self.assertRaises(SystemExit):
                check_usb_identity(self.source, bad)


if __name__ == "__main__":
    unittest.main()
