import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("boards", ROOT / "scripts/gen_board_profile.py")
boards = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boards)
BOARDS = ROOT / "firmware/esp32s3/boards"

class BoardProfileTests(unittest.TestCase):
    def test_existing_generated_headers_match_base(self):
        # Frozen producer, not a mirror of the new implementation.
        original = subprocess.check_output(["git", "show", "71104ff:scripts/gen_board_profile.py"], cwd=ROOT).decode()
        old = {}
        exec(compile(original, "baseline_generator", "exec"), old)
        for name in ("lilygo_t_dongle_s3", "waveshare_geek_v1_1_reference"):
            path = BOARDS / name / "board.json"
            self.assertEqual(boards.render(boards.load_profile(path), path),
                             old["render"](old["load_profile"](path), path))
            for filename in ("board.json", "sdkconfig.defaults"):
                expected = subprocess.check_output(["git", "show", f"71104ff:firmware/esp32s3/boards/{name}/{filename}"], cwd=ROOT)
                self.assertEqual((BOARDS/name/filename).read_bytes().replace(b"\r\n",b"\n"), expected)

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

if __name__ == "__main__": unittest.main()
