"""The live eFuse digest must work with the pinned espefuse `summary()`, not a stand-in.

Runs against the project-local ESP-IDF Python environment when it is installed and skips with an
explicit reason otherwise. espefuse's own emulated ESP32-S3 supplies the eFuse values.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE_PACKAGES = sorted((ROOT / ".tools").glob("idf-tools-*/python_env/*/Lib/site-packages")) + sorted(
    (ROOT / ".tools").glob("idf-tools-*/python_env/*/lib/python3*/site-packages")
)


def _load_backend():
    if not SITE_PACKAGES:
        raise unittest.SkipTest("pinned ESP-IDF Python environment is not installed under .tools/")
    sys.path.insert(0, str(SITE_PACKAGES[-1]))
    spec = importlib.util.spec_from_file_location(
        "keyferry_esptool_backend", ROOT / "tools" / "keyferry-firmware" / "esptool_backend.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EsptoolSummaryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = _load_backend()
        from espefuse.efuse_interface import init_commands

        cls.init_commands = staticmethod(init_commands)

    def test_digest_is_captured_from_the_real_summary(self):
        first = self.backend._efuse_summary_sha256(self.init_commands(chip="esp32s3", virt=True))
        second = self.backend._efuse_summary_sha256(self.init_commands(chip="esp32s3", virt=True))
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertEqual(first, second)

    def test_digest_covers_the_crlf_summary_that_unit_records_bind(self):
        commands = self.init_commands(chip="esp32s3", virt=True)
        sink = self.backend._SummarySink()
        commands.summary([], "json", sink, False)
        text = sink.getvalue()
        sink.release()
        self.assertIn("\n", text)
        expected = hashlib.sha256(text.replace("\n", "\r\n").encode("utf-8")).hexdigest()
        digest = self.backend._efuse_summary_sha256(self.init_commands(chip="esp32s3", virt=True))
        self.assertEqual(digest, expected)

    def test_a_plain_string_buffer_does_not_satisfy_the_contract(self):
        with self.assertRaises((AttributeError, ValueError)):
            buffer = io.StringIO()
            self.init_commands(chip="esp32s3", virt=True).summary([], "json", buffer, False)
            buffer.getvalue()


if __name__ == "__main__":
    unittest.main()
