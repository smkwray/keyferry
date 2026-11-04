import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("transport_gate", ROOT / "scripts/check_esp_transport.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

HANDHELD = "waveshare_amoled_1_8"
BRIDGE_ONLY = "waveshare_geek_v1_1_reference"
CALLBACKS = ("tud_msc_read10_cb", "tud_msc_write10_cb", "tud_msc_scsi_cb")


DRIVE = "esp-idf/kf_handheld/libkf_handheld.a(drive.cpp.obj)"
BRIDGE = "esp-idf/main/libmain.a(app_main.cpp.obj)"


def sections(owner: str) -> str:
    return "".join(
        f" .text.{name}\n                0x42016f54       0x1e {owner}\n"
        f"                0x42016f54                {name}\n"
        for name in CALLBACKS
    )


def map_text(owner: str, discarded: str = "") -> str:
    """A linker map: discarded input sections first, then what was linked."""
    return (
        "Discarded input sections\n\n"
        + (sections(discarded) if discarded else "")
        + "\nMemory Configuration\n\nLinker script and memory map\n\n"
        + sections(owner)
    )


class HandheldMscGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.build = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def check(self, board: str, owner: str | None, cache: str = "", discarded: str = "") -> None:
        link_map = self.build / "keyferry_hil_endpoint.map"
        if owner is None:
            link_map.unlink(missing_ok=True)
        else:
            link_map.write_text(map_text(owner, discarded))
        gate.check_handheld_msc(self.build, cache, board)

    def test_handheld_drive_callbacks_pass(self):
        self.check(HANDHELD, DRIVE)

    def test_discarded_bridge_sections_do_not_matter(self):
        self.check(HANDHELD, DRIVE, discarded=BRIDGE)

    def test_rejects_msc_outside_the_handheld_drive(self):
        cases = {
            "bridge-only board": (BRIDGE_ONLY, DRIVE, "", ""),
            "bridge serves storage": (HANDHELD, BRIDGE, "", ""),
            "drive only discarded": (HANDHELD, BRIDGE, "", DRIVE),
            "other handheld object": (HANDHELD, "esp-idf/kf_handheld/libkf_handheld.a(shell.cpp.obj)", "", ""),
            "file handoff on": (HANDHELD, DRIVE, "KEYFERRY_FILE_HANDOFF:BOOL=ON\n", ""),
            "no linker map": (HANDHELD, None, "", ""),
        }
        for name, (board, owner, cache, discarded) in cases.items():
            with self.subTest(case=name), self.assertRaises(SystemExit):
                self.check(board, owner, cache, discarded)

    def test_missing_callback_fails_closed(self):
        (self.build / "keyferry_hil_endpoint.map").write_text(
            "Linker script and memory map\n .text.tud_msc_read10_cb\n")
        with self.assertRaises(SystemExit):
            gate.check_handheld_msc(self.build, "", HANDHELD)


if __name__ == "__main__":
    unittest.main()
