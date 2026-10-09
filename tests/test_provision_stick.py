import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch, Mock

from tests.provision_fakes import FakeTools

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("provision_stick", ROOT / "scripts/provision_stick.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name)
        self.profile = json.loads((ROOT / "firmware/esp32s3/boards/m5stack_atoms3_lite/board.json").read_text())
        self.tools = FakeTools(self.profile)
        self.approval = {"schema": "keyferry.provision-approval.v1", "board_profile": self.profile["id"],
                         "recovery_gate": "OWNER_RATIFIED_AUTOMATIC_ROM", "owner_source": "SYNTHETIC",
                         "write_scope": "NEW_DEVICE_FULL_INSTALL"}
        self.lines = []

    def run_flow(self):
        return p.execute(self.tools, self.private, self.profile, self.approval, True,
                         timeout=0.1, emit=self.lines.append)

    def test_all_steps_and_receipt_allowlist(self):
        state = self.run_flow()
        self.assertEqual(state["status"], "READY")
        self.assertEqual(self.tools.counts, {"mint": 1, "write": 1, "erase": 1, "verify": 2, "apply": 1})
        self.assertTrue(state["rom_reentry_verified"])
        self.assertNotIn("SECRET", json.dumps(state))
        self.assertNotIn("SECRET", "\n".join(self.lines))
        self.assertFalse(state["inventory"]["armed"])

    def test_resume_after_possible_write_does_not_mint_or_rewrite(self):
        self.tools.fail_after_write = True
        with self.assertRaises(p.Stop):
            self.run_flow()
        state = self.run_flow()
        self.assertEqual(state["status"], "READY")
        self.assertEqual(self.tools.counts["mint"], 1)
        self.assertEqual(self.tools.counts["write"], 1)
        self.assertEqual(self.tools.counts["apply"], 1)

    def test_uncertain_partial_write_mismatch_never_retries(self):
        self.tools.fail_after_write = True
        with self.assertRaises(p.Stop):
            self.run_flow()
        self.tools.flash.clear()
        with self.assertRaises(p.Stop):
            self.run_flow()
        self.assertEqual(self.tools.counts["write"], 1)

    def test_resume_wrong_chip_refused_before_write(self):
        self.tools.fail_after_write = True
        with self.assertRaises(p.Stop):
            self.run_flow()
        self.tools.mac = "02:00:00:00:00:02"
        with self.assertRaisesRegex(p.Stop, "RESUME_CHIP_MISMATCH"):
            self.run_flow()
        self.assertEqual(self.tools.counts["write"], 1)

    def test_changed_frozen_plan_cannot_replace_possible_write_receipt(self):
        self.tools.fail_after_write = True
        with self.assertRaises(p.Stop):
            self.run_flow()
        path = self.tools.run / "image/first-install-plan.json"
        plan = p.load(path)
        plan.pop("proposal_sha256")
        plan["version"] = "0.3.0-pointer.99"
        plan["proposal_sha256"] = p.digest(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode())
        p.save(path, plan)
        with self.assertRaisesRegex(p.Stop, "FROZEN_PLAN_CHANGED_BEFORE_RESUME"):
            self.run_flow()
        self.assertEqual(self.tools.counts["write"], 1)

    def test_security_and_each_missing_or_active_efuse(self):
        observation = self.tools.rom("COM42", "no-reset").observe()
        p.check_observation(observation, 8 * 1024 * 1024)
        for field in p.EFUSES:
            for value in (1, None, "False", [], False):
                with self.subTest(field=field, value=value):
                    altered = copy.deepcopy(observation)
                    altered["efuses"][field] = value
                    if value is False:
                        p.check_observation(altered, 8 * 1024 * 1024)
                    else:
                        with self.assertRaises(p.Stop):
                            p.check_observation(altered, 8 * 1024 * 1024)
        for field in ("secure_boot", "flash_encryption", "secure_download_mode"):
            altered = dict(observation, **{field: True})
            with self.assertRaises(p.Stop):
                p.check_observation(altered, 8 * 1024 * 1024)

    def test_lilygo_and_waveshare_profiles_use_the_same_flow(self):
        for name in ("lilygo_t_dongle_s3", "waveshare_geek_v1_1_reference"):
            with self.subTest(profile=name):
                profile = p.load(ROOT / "firmware/esp32s3/boards" / name / "board.json")
                tools = FakeTools(profile)
                approval = dict(self.approval, board_profile=name)
                result = p.execute(tools, self.private / name, profile, approval, True,
                                   timeout=0.1, emit=self.lines.append)
                self.assertEqual(result["identity"]["flash_size_bytes"], 16 * 1024 * 1024)
                self.assertEqual(result["inventory"]["board_compatibility_id"], profile["compatibility_id"])

    def test_new_port_selection_never_guesses(self):
        old = {"port": "COM1", "vid": 0x303A}
        new = {"port": "COM2", "vid": 0x303A}
        self.assertEqual(p.select_port([old], [old, new]), new)
        self.assertIsNone(p.select_port([old], [old, {"port": "COM3", "vid": 0x1234}]))
        with self.assertRaisesRegex(p.Stop, "AMBIGUOUS"):
            p.select_port([], [old, new])

    def test_manual_fallback_once_and_automatic_reentry(self):
        self.tools.fail_auto_entry = True
        self.run_flow()
        self.assertEqual(self.lines.count("ROM: hold the side button 2 s"), 1)

    def test_unratified_gate_prevents_prompt_or_write(self):
        self.approval["recovery_gate"] = "UNRATIFIED"
        with self.assertRaisesRegex(p.Stop, "RECOVERY_GATE_UNRATIFIED"):
            self.run_flow()
        self.assertEqual(self.tools.counts["mint"], 0)

    def test_live_pipeline_refuses_efuse_before_any_erase(self):
        original = self.tools.rom
        def unsafe_rom(port, mode):
            rom = original(port, mode)
            observe = rom.observe
            def unsafe_observation():
                result = observe()
                result["efuses"]["DIS_DOWNLOAD_MODE"] = 1
                return result
            rom.observe = unsafe_observation
            return rom
        self.tools.rom = unsafe_rom
        with self.assertRaisesRegex(p.Stop, "ACTIVE_OR_UNKNOWN_DOWNLOAD_EFUSE"):
            self.run_flow()
        self.assertEqual(self.tools.counts["erase"], 0)
        self.assertEqual(self.tools.counts["write"], 0)

    def test_hushrun_adapter_retains_request_id_without_raw_output(self):
        receipt = self.private / "receipt.json"
        p.save(receipt, {"status": "PREPARE_PENDING"})
        tools = p.Tools(ROOT, {"package_directory": str(self.private)})
        request_id = "00000000-0000-4000-8000-000000000001"
        tools.command([sys.executable, "-c", f"print('request {request_id} SYNTHETIC_SECRET')"],
                      hushrun_receipt=receipt)
        retained = p.load(receipt)
        self.assertEqual(retained["hushrun_request_id"], request_id)
        self.assertNotIn("SYNTHETIC_SECRET", receipt.read_text())

    def test_inventory_refuses_armed_wrong_elf_or_missing_pointer(self):
        self.run_flow()
        inventory = self.tools.inventory()
        for field, value in (("armed", True), ("active_command_id", "active"), ("link_path", "tailnet")):
            changed = copy.deepcopy(inventory)
            changed["devices"][0][field] = value
            with self.assertRaises(p.Stop):
                p.ready_inventory(changed, self.tools.device, self.tools.plan, self.profile)
        for field, value in (("elf_sha256", "f" * 64), ("device_capability_mask", 0)):
            changed = copy.deepcopy(inventory)
            changed["devices"][0]["firmware"][field] = value
            with self.assertRaises(p.Stop):
                p.ready_inventory(changed, self.tools.device, self.tools.plan, self.profile)

    def test_partial_preparation_not_replayed(self):
        def uncertain(run):
            self.tools.counts["mint"] += 1
            raise RuntimeError("possible mint")
        self.tools.prepare = uncertain
        for _ in range(2):
            with self.assertRaises(p.Stop):
                self.run_flow()
        self.assertEqual(self.tools.counts["mint"], 1)

    def test_production_rom_adapter_selects_real_backend_api_with_fakes(self):
        backend = Mock()
        with patch.object(p, "module", return_value=backend):
            rom = p.Rom(Path("."), "COM42", "default-reset")
        backend._open_rom.assert_called_once_with("COM42", "default-reset")
        self.run_flow()
        rom.write(self.tools.plan["writes"], self.tools.run / "image")
        self.assertEqual(backend._write_application.call_count, 3)
        for call, record in zip(backend._write_application.call_args_list, self.tools.plan["writes"]):
            self.assertEqual(call.args[1], record["offset"])
            self.assertEqual(call.args[2], (self.tools.run / "image" / record["file"]).read_bytes())
        rom.erase({"offset": 0x310000, "size_bytes": 0xB000})
        backend.cmds.erase_region.assert_called_once_with(rom.esp, 0x310000, 0xB000, force=False)
        rom.verify(self.tools.plan["writes"], self.tools.run / "image")
        backend.cmds.verify_flash.assert_called_once()
        rom.reset()
        backend.cmds.reset_chip.assert_called_once_with(rom.esp, "hard-reset")

    def test_known_chip_index_never_gets_a_second_identity(self):
        original = self.run_flow()
        first_id = original["device_id"]
        self.tools.port_reads = 0
        with self.assertRaisesRegex(p.Stop, "CHIP_ALREADY_HAS_IDENTITY"):
            p.execute(self.tools, self.private, self.profile, self.approval, True,
                      timeout=0.1, emit=self.lines.append, new_device=True)
        index = p.load(self.private / "provision-chip-020000000001.json")
        self.assertEqual(index["device_id"], first_id)
        self.assertEqual(self.tools.counts["write"], 1)

    def test_concurrent_runs_are_refused_and_lock_releases(self):
        with p.process_lock(self.private):
            with self.assertRaisesRegex(p.Stop, "ANOTHER_PROVISION_RUN_ACTIVE"):
                with p.process_lock(self.private):
                    self.fail("second lock admitted")
        with p.process_lock(self.private):
            pass

    def test_plan_rejects_image_tamper_and_security_burning_build(self):
        self.run_flow()
        image = self.tools.run / "image"
        (image / "app.bin").write_bytes(b"changed")
        with self.assertRaisesRegex(p.Stop, "ARTIFACT_HASH_MISMATCH"):
            p.check_plan(image, self.profile)

    def test_production_observation_uses_pinned_virtual_efuses(self):
        sites = list((ROOT / ".tools/idf-tools-v6.0.3/python_env").glob("*/Lib/site-packages"))
        if len(sites) != 1:
            self.skipTest("pinned IDF Python environment required for virtual eFuse contract")
        sys.path.insert(0, str(sites[0]))
        backend = p.module(ROOT / "tools/keyferry-firmware/esptool_backend.py", "provision_virtual_backend")
        backend.log.set_logger(backend._SilentLogger())
        commands = backend.init_commands(chip="esp32s3", virt=True)
        esp = Mock(secure_download_mode=False)
        esp.flash_id.return_value = 0x164020
        esp.read_mac.return_value = bytes.fromhex("020000000001")
        esp.get_major_chip_version.return_value = 0
        esp.get_minor_chip_version.return_value = 2
        esp.get_secure_boot_enabled.return_value = False
        esp.get_flash_encryption_enabled.return_value = False
        rom = p.Rom.__new__(p.Rom)
        rom.backend, rom.esp = backend, esp
        with patch.object(backend, "init_commands", return_value=commands), patch.object(
                backend.cmds, "detect_flash_size", return_value="8MB"):
            observation = rom.observe()
        p.check_observation(observation, 8 * 1024 * 1024)
        self.assertEqual(set(observation["efuses"]), set(p.EFUSES))


if __name__ == "__main__":
    unittest.main()
