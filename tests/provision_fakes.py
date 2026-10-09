"""Synthetic tool boundary for provision_stick -DryRun and regression tests."""
import hashlib
import json
from pathlib import Path
import uuid
import subprocess

EFUSES = ("SECURE_BOOT_EN", "SPI_BOOT_CRYPT_CNT", "DIS_DOWNLOAD_MODE",
          "ENABLE_SECURITY_DOWNLOAD", "DIS_USB_SERIAL_JTAG",
          "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE", "DIS_USB_OTG", "DIS_USB_OTG_DOWNLOAD_MODE")


class FakeTools:
    def __init__(self, profile):
        self.profile = profile
        self.calls = []
        self.counts = {"mint": 0, "write": 0, "erase": 0, "verify": 0, "apply": 0}
        self.port_reads = 0
        self.flash = {}
        self.fail_after_write = False
        self.fail_auto_entry = False
        self.mac = "02:00:00:00:00:01"
        self.device = None

    def preflight(self):
        self.calls.append("preflight")

    def protect(self, path):
        self.calls.append("protect")

    def prepare(self, run):
        self.calls.append("helper.prepare-stick(stdin-line)")
        self.counts["mint"] += 1
        directory = run / "prepare"
        directory.mkdir()
        (directory / "bootstrap").mkdir()
        (directory / "installation").mkdir()
        self.device = str(uuid.uuid4())
        (directory / "prepared.json").write_text(json.dumps({"device_id": self.device}))
        (directory / "bootstrap/keyferry_hil_private.h").write_text("synthetic, no credentials")

    def build(self, run, profile):
        self.calls.append("build_first_hil -PointerExtended; freeze_first_install")
        directory = run / "image"
        directory.mkdir()
        records = []
        artifacts = {}
        for offset, name in ((0, "bootloader.bin"), (0x8000, "partition-table.bin"), (0x10000, "app.bin")):
            data = b"synthetic " + name.encode()
            (directory / name).write_bytes(data)
            record = {"size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            artifacts[name] = record
            records.append(dict(record, file=name, offset=offset))
        (directory / "generated-board").mkdir()
        for name, data in (("app.elf", b"synthetic elf"),
                           ("generated-board/board_profile.h", f'"{profile["id"]}"'.encode()),
                           ("sdkconfig", b"# security disabled")):
            (directory / name).write_bytes(data)
            artifacts[name] = {"size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        plan = {"schema": "keyferry.first-install-plan.v1", "artifact_role": "DEVICE_PRIVATE_CANDIDATE",
                "flash_size_bytes": profile["flash"]["size_mb"] * 1024 * 1024,
                "application_headroom_bytes": 0x200000, "application_slot_bytes": 0x300000,
                "erase_before_first_install": [{"offset": 0x310000, "size_bytes": 0xB000}],
                "writes": records, "artifacts": artifacts, "version": "0.3.0-pointer.2",
                "producer_commit": subprocess.check_output(["git", "rev-parse", "HEAD"],
                    cwd=Path(__file__).resolve().parents[1]).decode().strip()}
        plan["proposal_sha256"] = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        (directory / "first-install-plan.json").write_text(json.dumps(plan))
        self.run, self.plan = run, plan

    def apply(self, run):
        self.calls.append("installer.Apply + start app")
        self.counts["apply"] += 1

    def ports(self):
        self.port_reads += 1
        return [] if self.port_reads == 1 else [{"port": "COM42", "vid": 0x303A, "serial": "SYNTHETIC"}]

    def rom(self, port, mode):
        self.calls.append("esptool." + mode)
        if self.fail_auto_entry and mode == "default-reset":
            self.fail_auto_entry = False
            raise RuntimeError("synthetic connect failure")
        return FakeRom(self)

    def bootstrap(self, run):
        self.calls.append("helper.bootstrap-roaming")

    def wait_bootstrap(self, run):
        self.calls.append("helper.bootstrap-status(read-only wait)")

    def inventory(self):
        self.calls.append("keyctl.devices")
        return {"devices": [{"id": self.device, "label": "SECRET SHOULD BE DROPPED",
                "transport": "tls", "link_path": "bluetooth", "link": "authenticated",
                "mode": "keyboard", "armed": False, "maintenance": False, "active_command_id": None,
                "firmware": {"board_compatibility_id": self.profile["compatibility_id"],
                             "device_capability_mask": 0x08000000, "elf_sha256": self.plan["artifacts"]["app.elf"]["sha256"],
                             "endpoint": self.plan["version"]}}]}


class FakeRom:
    def __init__(self, tools):
        self.tools = tools

    def observe(self):
        self.tools.calls.append("ROM.observe + efuse.summary(read-only)")
        return {"rom_mac": self.tools.mac, "chip": "esp32s3", "soc_revision": "v0.2",
                "flash_manufacturer_id": "0x20", "flash_device_id": "0x4017",
                "flash_size_bytes": self.tools.profile["flash"]["size_mb"] * 1024 * 1024,
                "efuse_sha256": "0" * 64, "efuses": dict.fromkeys(EFUSES, 0),
                "secure_boot": False, "flash_encryption": False, "secure_download_mode": False,
                "secret": "SECRET SHOULD BE DROPPED"}

    def erase(self, region):
        self.tools.counts["erase"] += 1

    def write(self, writes, directory):
        self.tools.counts["write"] += 1
        for w in writes:
            self.tools.flash[w["offset"]] = (directory / w["file"]).read_bytes()
        if self.tools.fail_after_write:
            self.tools.fail_after_write = False
            raise RuntimeError("uncertain write synthetic SECRET")

    def verify(self, writes, directory):
        self.tools.counts["verify"] += 1
        for w in writes:
            if self.tools.flash.get(w["offset"]) != (directory / w["file"]).read_bytes():
                raise RuntimeError("verify mismatch")

    def reset(self):
        self.tools.calls.append("esptool.after.hard-reset")

    def close(self):
        pass
