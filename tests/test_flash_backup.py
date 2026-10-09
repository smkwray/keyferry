import hashlib
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("inspect_flash_backup", ROOT/"scripts/inspect_flash_backup.py")
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)
IDF = ROOT.parent.parent/".tools/esp-idf-v6.0.3"

@unittest.skipUnless(IDF.is_dir(), "pinned IDF decoder required")
class FlashBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)/"snapshot.bin"
        self.image = bytearray(b"\xff" * (8*1024*1024))
        entry = struct.pack("<HBBII16sI", 0x50aa, 0, 0, 0x10000, 0x100000, b"factory", 0)
        self.table = entry + b"\xeb\xeb" + b"\xff"*14 + hashlib.md5(entry).digest() + b"\xff"*(0xc00-64)
        self.image[0x8000:0x8c00] = self.table
        self.image[0x10000] = 0xe9
    def tearDown(self): self.temp.cleanup()
    def test_real_idf_decoder_and_bounds(self):
        self.path.write_bytes(self.image)
        result = backup.inspect(self.path, IDF)
        self.assertEqual(result["partition_table_offset"], 0x8000)
        self.assertEqual(result["partitions"][0]["offset"], 0x10000)
        self.assertEqual(result["sha256"], hashlib.sha256(self.image).hexdigest())
    def test_missing_image_and_wrong_length_reject(self):
        self.image[0x10000] = 0xff
        self.path.write_bytes(self.image)
        with self.assertRaises(ValueError): backup.inspect(self.path, IDF)
        self.path.write_bytes(self.image[:-1])
        with self.assertRaises(ValueError): backup.inspect(self.path, IDF)
    def test_ambiguous_table_and_bad_digest_reject(self):
        self.image[0x9000:0x9c00] = self.table
        self.path.write_bytes(self.image)
        with self.assertRaises(ValueError): backup.inspect(self.path, IDF)
        self.image[0x9000:0x9c00] = b"\xff"*0xc00
        self.image[0x8005] ^= 1
        self.path.write_bytes(self.image)
        with self.assertRaises(ValueError): backup.inspect(self.path, IDF)

if __name__ == "__main__": unittest.main()
