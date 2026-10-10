import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("materialize", ROOT / "scripts/materialize_private_config.py")
materialize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(materialize)


class MaterializeTests(unittest.TestCase):
    def test_content_identity_missing_input_and_changed_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as tmp:
            root = Path(tmp)
            source = root / "input"
            source.write_bytes(b"synthetic-input")
            output = root / "output"
            output.mkdir()
            header = output / "keyferry_hil_private.h"

            def generate(*args, **kwargs):
                header.write_bytes(b"synthetic-header")

            with patch.object(materialize, "inputs", return_value=[source]), patch.object(
                    materialize.subprocess, "run", side_effect=generate) as run:
                self.assertTrue(materialize.materialize(root, root, output))
                before = header.stat().st_mtime_ns
                self.assertFalse(materialize.materialize(root, root, output))
                self.assertEqual(header.stat().st_mtime_ns, before)
                self.assertEqual(run.call_count, 1)
                source.write_bytes(b"changed-synthetic-input")
                self.assertTrue(materialize.materialize(root, root, output))
                header.write_bytes(b"corrupted-output")
                self.assertTrue(materialize.materialize(root, root, output))
                header.unlink()
                self.assertTrue(materialize.materialize(root, root, output))
                source.unlink()
                with self.assertRaises(FileNotFoundError):
                    materialize.materialize(root, root, output)
                self.assertEqual(run.call_count, 4)


if __name__ == "__main__":
    unittest.main()
