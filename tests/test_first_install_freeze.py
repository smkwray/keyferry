import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDF = ROOT.parent.parent/".tools/esp-idf-v6.0.3"
BUILD = ROOT/"build/atoms3-resource"
SPEC = importlib.util.spec_from_file_location("freeze_first_install",ROOT/"scripts/freeze_first_install.py")
freeze = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(freeze)

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
        flash["flash_settings"]["flash_size"]="16MB"
        (altered/"flasher_args.json").write_text(json.dumps(flash))
        with self.assertRaises(ValueError): freeze.freeze(altered,self.root/"frozen",IDF)
        self.assertFalse((self.root/"frozen").exists())

if __name__ == "__main__": unittest.main()
