import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ble_gate", ROOT / "scripts/check_ble_hid_spike.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

CSV = "factory, app, factory, 0x10000, 4M,\nnvs, data, nvs, 0x410000, 0x6000,\n"


class PartitionGateTests(unittest.TestCase):
    def setUp(self):
        self.tool = gate.partition_tool()
        self.tool.md5sum = True
        self.directory = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.directory.cleanup()

    def table(self, data: bytes) -> Path:
        path = Path(self.directory.name) / "partition-table.bin"
        path.write_bytes(data)
        return path

    def valid(self, csv: str = CSV) -> bytes:
        return self.tool.PartitionTable.from_csv(csv).to_binary()

    def test_reads_factory_size_from_a_valid_table(self):
        self.assertEqual(gate.factory_app_bytes(self.table(self.valid()), 0x8000), 4 * 1024 * 1024)

    def test_rejects_malformed_tables(self):
        good = self.valid()
        corrupt = bytearray(good)
        corrupt[12] ^= 0x01  # factory size byte: MD5 no longer matches
        self.tool.md5sum = False
        no_md5 = self.tool.PartitionTable.from_csv(CSV).to_binary()
        self.tool.md5sum = True
        cases = {
            "truncated": good[:32],
            "partial entry": good[:48],
            "corrupt size": bytes(corrupt),
            "no md5": no_md5,
            "two factories": self.valid(CSV + "factory2, app, factory, 0x420000, 1M,\n"),
        }
        for name, data in cases.items():
            with self.subTest(case=name), self.assertRaises(SystemExit):
                gate.factory_app_bytes(self.table(data), 0x8000)

    def test_missing_table_fails_closed(self):
        with self.assertRaises(SystemExit):
            gate.factory_app_bytes(Path(self.directory.name) / "absent.bin", 0x8000)


if __name__ == "__main__":
    unittest.main()
