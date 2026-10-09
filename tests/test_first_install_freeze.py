import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
IDF = ROOT.parent.parent/".tools/esp-idf-v6.0.3"
BUILD = ROOT/"build/atoms3-resource"
SPEC = importlib.util.spec_from_file_location("freeze_first_install",ROOT/"scripts/freeze_first_install.py")
freeze = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(freeze)


@unittest.skipUnless(IDF.is_dir(), "pinned IDF partition decoder required")
class SyntheticFreezeTests(unittest.TestCase):
    def test_supported_flash_capacities_use_generated_partition_decoder(self):
        decoder_spec = importlib.util.spec_from_file_location(
            "synthetic_partitions", IDF / "components/partition_table/gen_esp32part.py")
        decoder = importlib.util.module_from_spec(decoder_spec)
        decoder_spec.loader.exec_module(decoder)
        table = decoder.PartitionTable.from_csv(
            "factory,app,factory,0x10000,1M,\n"
            "kf_cfg_a,data,0x40,0x110000,0x4000,\n"
            "kf_cfg_b,data,0x41,0x114000,0x4000,\n"
            "nvs,data,nvs,0x118000,0x3000,\n")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for size in (8, 16):
                with self.subTest(size_mb=size):
                    build = root / f"build-{size}"
                    build.mkdir()
                    (build / "partition_table").mkdir()
                    (build / "generated-board").mkdir()
                    files = {"0x0": "bootloader.bin", "0x8000": "partition_table/partition-table.bin",
                             "0x10000": "keyferry_hil_endpoint.bin"}
                    for name in ("bootloader.bin", "keyferry_hil_endpoint.bin", "keyferry_hil_endpoint.elf",
                                 "keyferry_hil_endpoint.map", "sdkconfig", "flash_args", "generated-board/board_profile.h"):
                        (build / name).write_bytes(b"synthetic")
                    (build / "partition_table/partition-table.bin").write_bytes(table.to_binary())
                    (build / "project_description.json").write_text(json.dumps({"target": "esp32s3",
                        "project_name": "keyferry_hil_endpoint", "project_version": "0.3.0-pointer.2"}))
                    (build / "flasher_args.json").write_text(json.dumps({"flash_settings": {"flash_size": f"{size}MB"},
                        "partition-table": {"offset": "0x8000"}, "flash_files": files}))
                    with patch.object(freeze.subprocess, "check_output", return_value=b"0" * 40), contextlib.redirect_stdout(io.StringIO()):
                        plan = freeze.freeze(build, root / f"frozen-{size}", IDF)
                    self.assertEqual(plan["flash_size_bytes"], size * 1024 * 1024)
                    self.assertEqual(plan["erase_before_first_install"][0]["offset"], 0x110000)
                    self.assertEqual(plan["artifact_role"], "DEVICE_PRIVATE_CANDIDATE")

@unittest.skipUnless((BUILD/"keyferry_hil_endpoint.bin").is_file() and IDF.is_dir(), "completed AtomS3 resource build required")
class FirstInstallFreezeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
    def tearDown(self): self.temp.cleanup()
    def test_real_build_freezes_as_non_authorized_resource_specimen(self):
        with contextlib.redirect_stdout(io.StringIO()):
            plan=freeze.freeze(BUILD,self.root/"frozen",IDF)
        self.assertEqual(plan["artifact_role"],"RESOURCE_ONLY_NEVER_FLASH")
        self.assertFalse(plan["hardware_authorized"])
        self.assertEqual(plan["application_slot_bytes"],3*1024*1024)
        self.assertEqual([w["offset"] for w in plan["writes"]],[0,0x8000,0x10000])
        self.assertEqual(plan["erase_before_first_install"][0]["offset"],0x310000)
        self.assertEqual(plan["erase_before_first_install"][0]["size_bytes"],0xb000)
        self.assertFalse((self.root/"frozen/private-config").exists())
        with self.assertRaises(ValueError): freeze.freeze(BUILD,self.root/"frozen",IDF)
    def test_wrong_flash_size_rejects_before_output(self):
        altered=self.root/"build"
        altered.mkdir()
        shutil.copyfile(BUILD/"project_description.json",altered/"project_description.json")
        flash=json.loads((BUILD/"flasher_args.json").read_text())
        flash["flash_settings"]["flash_size"]="32MB"
        (altered/"flasher_args.json").write_text(json.dumps(flash))
        with self.assertRaises(ValueError): freeze.freeze(altered,self.root/"frozen",IDF)
        self.assertFalse((self.root/"frozen").exists())

if __name__ == "__main__": unittest.main()
