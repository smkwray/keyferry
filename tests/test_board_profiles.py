import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("boards", ROOT / "scripts/gen_board_profile.py")
boards = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boards)
BOARDS = ROOT / "firmware/esp32s3/boards"

class BoardProfileTests(unittest.TestCase):
    def test_existing_generated_headers_match_golden(self):
        # Frozen public outputs from scripts/gen_board_profile.py before displayless profiles.
        # These digests preserve the baseline without requiring an old Git object in a clone.
        golden = {
            "lilygo_t_dongle_s3": (
                "33c15094b6bfde15c14a378cc9e9b0e55b4bdf670419afde636e19fa47a1427c",
                "a411f522cf2726b072a1034a55d6ca34aff8dd9ce9a4db327f4f9997203f800d",
            ),
            "waveshare_geek_v1_1_reference": (
                "6482360cf8c88b41a31239f476386557deab8f0a4ef612246ce655a0e518f869",
                "f21261fb5f62c18215a08fee3dc711a733f4fa4696615abff42e690e621310e8",
            ),
        }
        for name, (header_sha256, manifest_sha256) in golden.items():
            path = BOARDS / name / "board.json"
            with self.subTest(board=name):
                rendered = boards.render(boards.load_profile(path), path).encode("utf-8")
                self.assertEqual(hashlib.sha256(rendered).hexdigest(), header_sha256)
                manifest = path.read_bytes().replace(b"\r\n", b"\n")
                self.assertEqual(hashlib.sha256(manifest).hexdigest(), manifest_sha256)

    def test_board_sdkconfig_defaults_match_flash_and_keep_assertions_fatal(self):
        # CMake loads these hand-maintained overrides; the header generator does not emit them.
        for path in sorted(BOARDS.glob("*/board.json")):
            profile = boards.load_profile(path)
            settings = (path.parent / "sdkconfig.defaults").read_text().splitlines()
            with self.subTest(board=profile["id"]):
                flash = [line for line in settings
                         if line.startswith("CONFIG_ESPTOOLPY_FLASHSIZE_") and line.endswith("=y")]
                self.assertEqual(flash, [f"CONFIG_ESPTOOLPY_FLASHSIZE_{profile['flash']['size_mb']}MB=y"])
                assertions = [line for line in settings
                              if line.startswith("CONFIG_COMPILER_OPTIMIZATION_ASSERTIONS_")
                              and line.endswith("=y")]
                self.assertLessEqual(len(assertions), 1)
                for setting in assertions:
                    self.assertIn(setting, ("CONFIG_COMPILER_OPTIMIZATION_ASSERTIONS_ENABLE=y",
                                            "CONFIG_COMPILER_OPTIMIZATION_ASSERTIONS_SILENT=y"))
                if profile["id"] == "lilygo_t_dongle_s3":
                    self.assertEqual(assertions, ["CONFIG_COMPILER_OPTIMIZATION_ASSERTIONS_SILENT=y"])

    def test_atoms3_pins_and_flash(self):
        p = boards.load_profile(BOARDS / "m5stack_atoms3_lite/board.json")
        self.assertEqual(p["flash"]["size_mb"], 8)
        self.assertEqual(p["compatibility_id"], 3)
        self.assertFalse(p["qualified"])
        self.assertFalse(p["display"]["present"])
        self.assertEqual(p["indicators"], dict(rgb_gpio=35, button_gpio=41, ir_gpio=4, max_channel=8))
        self.assertEqual(p["pins"]["boot_gpio"], 0)
        self.assertFalse(p["capabilities"]["uart0_header"])

    def test_indicator_configuration_rejects_unsafe_or_incomplete_pins(self):
        p = json.loads((BOARDS / "m5stack_atoms3_lite/board.json").read_text())
        cases = []
        for field,value in (("rgb_gpio",19),("button_gpio",0),("ir_gpio",35),("max_channel",255),("ir_gpio",True)):
            candidate = copy.deepcopy(p)
            candidate["indicators"][field] = value
            cases.append(candidate)
        candidate = copy.deepcopy(p)
        del candidate["indicators"]["ir_gpio"]
        cases.append(candidate)
        for candidate in cases:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)/"board.json"
                path.write_text(json.dumps(candidate))
                with self.assertRaises(ValueError): boards.load_profile(path)

    def test_handheld_profile_selects_shell_and_rejects_conflicts(self):
        path = BOARDS / "waveshare_amoled_1_8/board.json"
        p = boards.load_profile(path)
        self.assertEqual((p["compatibility_id"], p["flash"]["size_mb"]), (4, 16))
        self.assertFalse(p["display"]["present"])
        self.assertIn("#define KEYFERRY_BOARD_HANDHELD 1", boards.render(p, path))
        source = json.loads(path.read_text())
        cases = []
        for mutate in (lambda c: c["capabilities"].update(touch=False),
                       lambda c: c["handheld"].update(shell="unknown"),
                       lambda c: c.update(handheld={"shell": "waveshare_amoled_1_8", "extra": 1}),
                       lambda c: c.pop("handheld")):
            candidate = copy.deepcopy(source)
            mutate(candidate)
            cases.append(candidate)
        for candidate in cases:
            with tempfile.TemporaryDirectory() as directory:
                candidate_path = Path(directory)/"board.json"
                candidate_path.write_text(json.dumps(candidate))
                with self.assertRaises(ValueError): boards.load_profile(candidate_path)

if __name__ == "__main__": unittest.main()
