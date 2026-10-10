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
            "090402000103000006092111010001228e000705830308000a")
        self.device = bytes.fromhex("12010002000000403a300440040101020301")

    def test_three_interface_extended_personality(self):
        pointer.no_msc_usb_descriptors(self.config + self.device, self.report)

    def test_button_layout_and_logical_range_on_both_reports(self):
        button = bytes.fromhex("05091901290515002501750195058102750395018103")
        for occurrence in (0, 1):
            start = self.report.find(button)
            if occurrence:
                start = self.report.find(button, start + len(button))
            self.assertGreaterEqual(start, 0)
            # Page, usage range, logical min/max, size/count, data flag, padding size/count/flag.
            for offset in (1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21):
                bad = bytearray(self.report)
                bad[start + offset] ^= 1
                with self.subTest(report=occurrence, offset=offset), self.assertRaises(SystemExit):
                    pointer.descriptor(bytes(bad))

    def test_each_report_requires_mouse_application_pointer_physical_collection(self):
        prefix = bytes.fromhex("05010902a10185")
        for occurrence in (0, 1):
            start = self.report.find(prefix)
            if occurrence:
                start = self.report.find(prefix, start + len(prefix))
            for offset in (3, 5, 9, 11):
                bad = bytearray(self.report)
                bad[start + offset] ^= 1
                with self.subTest(report=occurrence, offset=offset), self.assertRaises(SystemExit):
                    pointer.descriptor(bytes(bad))

    def test_pointer6_descriptor_that_broke_macos_drag_is_rejected(self):
        # Exact IF2 descriptor example-host's ioreg read from 0.3.0-pointer.6: its RelativePointer
        # element group held report 4's buttons, so every held absolute move released.
        live = bytes.fromhex(
            "05010902a10185010901a1000509190129051500250175019505810275039501810305010930"
            "093109381581257f750895038106050c0a380295018106c0c005010902a10185040901a10005"
            "091901290515002501750195058102750395018103050109300931150026ff7f751095028102"
            "09381581257f750895018106050c0a38028106c0c0")
        with self.assertRaises(SystemExit):
            pointer.descriptor(live)

    def test_report4_wheel_and_pan_stay_outside_the_stylus_collection(self):
        end = self.report.index(bytes.fromhex("c00938"))  # Stylus end, then report-4 wheel
        moved = self.report[:end] + self.report[end + 1:-2] + bytes.fromhex("c0c0c0")
        self.assertEqual(len(moved), len(self.report))
        with self.assertRaises(SystemExit):
            pointer.descriptor(moved)

    def test_stylus_collection_identity_is_exact(self):
        start = self.report.index(bytes.fromhex("050d0920a102"))
        for offset in (1, 3, 5):
            bad = bytearray(self.report)
            bad[start + offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(SystemExit):
                pointer.descriptor(bytes(bad))

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
        for revision in (1, 2, 3):
            bad = bytearray(self.device)
            bad[12] = revision
            with self.subTest(revision=revision), self.assertRaises(SystemExit):
                pointer.no_msc_usb_descriptors(self.config + bytes(bad), self.report)

    def test_wheel_and_pan_must_be_relative_signed_bytes_on_both_reports(self):
        pan = bytes.fromhex("050c0a3802")
        for occurrence in (0, 1):
            start = self.report.find(pan)
            if occurrence:
                start = self.report.find(pan, start + len(pan))
            self.assertGreaterEqual(start, 0)
            for offset in (1, 3, 4):
                bad = bytearray(self.report)
                bad[start + offset] ^= 1
                with self.subTest(report=occurrence, offset=offset), self.assertRaises(SystemExit):
                    pointer.descriptor(bytes(bad))
        wheel = bytes.fromhex("09381581257f750895018106")
        start = self.report.index(wheel)
        for offset in (1, 3, 5, 7, 9, 11):
            bad = bytearray(self.report)
            bad[start + offset] ^= 1
            with self.subTest(wheel_offset=offset), self.assertRaises(SystemExit):
                pointer.descriptor(bytes(bad))


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
