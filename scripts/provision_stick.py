#!/usr/bin/env python3
"""Owner-run first installation. Dry-run replaces tools, never the state machine.

Only paths enter argv. Child diagnostics and ROM logs are suppressed; receipts
are constructed from allowlisted metadata. There is no HID-input operation.
"""
import argparse
import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
EFUSES = ("SECURE_BOOT_EN", "SPI_BOOT_CRYPT_CNT", "DIS_DOWNLOAD_MODE",
          "ENABLE_SECURITY_DOWNLOAD", "DIS_USB_SERIAL_JTAG",
          "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE", "DIS_USB_OTG",
          "DIS_USB_OTG_DOWNLOAD_MODE")
IDENTITY = ("rom_mac", "chip", "soc_revision", "flash_manufacturer_id",
            "flash_device_id", "flash_size_bytes", "efuse_sha256")


class Stop(Exception):
    """Fixed local status, never a reflected tool/peer diagnostic."""


@contextlib.contextmanager
def process_lock(private):
    private.mkdir(parents=True, exist_ok=True)
    with (private / "provision.lock").open("a+b") as stream:
        stream.write(b"0")
        stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise Stop("ANOTHER_PROVISION_RUN_ACTIVE") from error
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Stop("DUPLICATE_JSON_FIELD")
            result[key] = value
        return result
    if path.stat().st_size > 128 * 1024:
        raise Stop("METADATA_TOO_LARGE")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    if os.name == "nt":
        # Match the pairing helper's durable Windows publication semantics.
        # A possible-write record must survive the rename before flash starts.
        import ctypes
        move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        move.restype = ctypes.c_int
        if not move(str(temporary.resolve()), str(path.resolve()), 0x1 | 0x8):
            raise Stop("STATE_PUBLISH_FAILED")
    else:
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def select_port(before, now):
    previous = {p["port"] for p in before}
    candidates = [p for p in now if p["vid"] == 0x303A and p["port"] not in previous]
    if len(candidates) > 1:
        raise Stop("AMBIGUOUS_NEW_303A_PORTS")
    return candidates[0] if candidates else None


def check_observation(observed, flash_bytes):
    if (observed.get("chip") != "esp32s3"
            or observed.get("flash_size_bytes") != flash_bytes
            or re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", observed.get("rom_mac", "")) is None):
        raise Stop("CHIP_IDENTITY_MISMATCH")
    for field in ("secure_boot", "flash_encryption", "secure_download_mode"):
        if observed.get(field) is not False:
            raise Stop("ACTIVE_OR_UNKNOWN_SECURITY")
    for field in EFUSES:
        value = observed.get("efuses", {}).get(field)
        if type(value) not in (bool, int) or value != 0:
            raise Stop("ACTIVE_OR_UNKNOWN_DOWNLOAD_EFUSE")
    for field in IDENTITY:
        if field not in observed:
            raise Stop("INCOMPLETE_ROM_IDENTITY")


def check_plan(directory, profile):
    plan = load(directory / "first-install-plan.json")
    unsigned = dict(plan)
    recorded = unsigned.pop("proposal_sha256", None)
    if digest(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()) != recorded:
        raise Stop("PLAN_DIGEST_MISMATCH")
    if (plan["schema"] != "keyferry.first-install-plan.v1"
            or plan["artifact_role"] != "DEVICE_PRIVATE_CANDIDATE"
            or plan["flash_size_bytes"] != profile["flash"]["size_mb"] * 1024 * 1024
            or plan["application_headroom_bytes"] < 32768):
        raise Stop("UNINSTALLABLE_PLAN")
    if (not {"sdkconfig", "generated-board/board_profile.h"}.issubset(plan["artifacts"])
            or sum(name.endswith(".elf") for name in plan["artifacts"]) != 1
            or re.fullmatch(r"[0-9a-f]{40}", plan.get("producer_commit", "")) is None):
        raise Stop("INCOMPLETE_FROZEN_PLAN")
    for relative, record in plan["artifacts"].items():
        path = directory / relative
        if not path.resolve().is_relative_to(directory.resolve()) or path.is_symlink():
            raise Stop("ARTIFACT_PATH_ESCAPE")
        data = path.read_bytes()
        if len(data) != record["size_bytes"] or digest(data) != record["sha256"]:
            raise Stop("ARTIFACT_HASH_MISMATCH")
    board = (directory / "generated-board/board_profile.h").read_text()
    if f'"{profile["id"]}"' not in board:
        raise Stop("BUILD_BOARD_MISMATCH")
    sdkconfig = (directory / "sdkconfig").read_text()
    if re.search(r"^CONFIG_SECURE_(?:BOOT|FLASH_ENC)[A-Z_]*=y$", sdkconfig, re.MULTILINE):
        raise Stop("IMAGE_COULD_ENABLE_SECURITY_EFUSES")
    writes = sorted(plan["writes"], key=lambda w: w["offset"])
    if [w["offset"] for w in writes] != [0, 0x8000, 0x10000]:
        raise Stop("UNEXPECTED_WRITE_SET")
    ends = [0x8000, 0x10000, 0x10000 + plan["application_slot_bytes"]]
    for w, end in zip(writes, ends):
        if (w["offset"] + w["size_bytes"] > end
                or plan["artifacts"].get(w["file"]) != {
                    "size_bytes": w["size_bytes"], "sha256": w["sha256"]}):
            raise Stop("WRITE_RANGE_MISMATCH")
    erases = plan["erase_before_first_install"]
    if len(erases) != 1:
        raise Stop("UNEXPECTED_ERASE_SET")
    erase = erases[0]
    if (erase["offset"] != ends[-1] or erase["size_bytes"] != 0xB000
            or erase["offset"] + erase["size_bytes"] > plan["flash_size_bytes"]):
        raise Stop("UNEXPECTED_ERASE_RANGE")
    return plan


def ready_inventory(inventory, device, plan, profile):
    matches = [v for v in inventory.get("devices", []) if v.get("id") == device]
    if len(matches) > 1:
        raise Stop("DUPLICATE_INVENTORY_DEVICE")
    if not matches or matches[0].get("link") != "authenticated":
        return None
    view = matches[0]
    firmware = view.get("firmware", {})
    elf = next((r["sha256"] for f, r in plan["artifacts"].items() if f.endswith(".elf")), None)
    if (view.get("armed") is not False or view.get("maintenance") is not False
            or "active_command_id" not in view or view["active_command_id"] is not None
            or view.get("mode") != "keyboard" or view.get("link_path") not in ("wifi", "bluetooth")
            or view.get("transport") != "tls"
            or firmware.get("board_compatibility_id") != profile["compatibility_id"]
            or firmware.get("elf_sha256") != elf
            or firmware.get("endpoint") != plan["version"]
            or type(firmware.get("device_capability_mask")) is not int
            or firmware["device_capability_mask"] & 0x08000000 == 0):
        raise Stop("AUTHENTICATED_INVENTORY_MISMATCH")
    return {"id": device, "link": "authenticated", "armed": False,
            "idle": True, "transport": view["link_path"],
            "board_compatibility_id": profile["compatibility_id"],
            "elf_sha256": elf, "device_capability_mask": firmware["device_capability_mask"]}


class Tools:
    """Real adapters only. Tests supply the same methods with synthetic tools."""
    def __init__(self, main, settings):
        self.main, self.settings = main, settings
        self.package = Path(settings["package_directory"])
        self.helper = self.package / "keyferry-pairing.exe"

    def command(self, args, timeout=600, json_output=False, hushrun_receipt=None):
        try:
            if hushrun_receipt is not None:
                # Hushrun suppresses child output. Retain only its request UUID,
                # as soon as emitted, so UNKNOWN can be inspected without replay.
                with subprocess.Popen([str(a) for a in args], cwd=ROOT,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
                    for line in process.stdout:
                        ids = re.findall(rb"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", line)
                        if ids:
                            state = load(hushrun_receipt)
                            if "hushrun_request_id" not in state:
                                state["hushrun_request_id"] = str(uuid.UUID(ids[0].decode("ascii")))
                                save(hushrun_receipt, state)
                    result = subprocess.CompletedProcess(args, process.wait(), b"")
            else:
                result = subprocess.run([str(a) for a in args], cwd=ROOT,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Stop("TOOL_COMPLETION_UNKNOWN") from error
        if result.returncode:
            raise Stop("TOOL_FAILED_INSPECT_STATE")
        return json.loads(result.stdout) if json_output else None

    def preflight(self):
        if os.name != "nt":
            raise Stop("WINDOWS_REQUIRED")
        import esptool
        if (esptool.__version__ != "5.4.0" or not Path(esptool.__file__).resolve().is_relative_to(
                (self.main / ".tools/idf-tools-v6.0.3/python_env").resolve())):
            raise Stop("PINNED_ESPTOOL_REQUIRED")
        for name in ("keyferry.exe", "keyferryd.exe", "keyctl.exe", "keyferry-pairing.exe"):
            if not (self.package / name).is_file():
                raise Stop("UPDATED_PROGRAM_PACKAGE_REQUIRED")
        self.hushrun = Path(os.environ["LOCALAPPDATA"]) / "Programs/Hushrun/hushrun.exe"
        for command in ("doctor", "capabilities"):
            result = self.command([self.hushrun, command, "--json"], json_output=True)
            if result.get("ready") is not True or (command == "capabilities"
                    and "stdin-line" not in result.get("delivery_modes", [])):
                raise Stop("HUSHRUN_NOT_READY")
        self.command([self.helper, "validate-installation", "--input", self.settings["installation_directory"]])
        expected = Path(os.environ["LOCALAPPDATA"]) / "keyferry/installation"
        if Path(self.settings["installation_directory"]).resolve() != expected.resolve():
            raise Stop("example-host_INSTALLED_IDENTITY_REQUIRED")
        # Version/help check is offline; no private input is read by help.
        result = subprocess.run([self.helper, "--help"], capture_output=True, timeout=10)
        if result.returncode or b"prepare-stick" not in result.stdout:
            raise Stop("REBUILT_PAIRING_PACKAGE_REQUIRED")

    def protect(self, path):
        path.mkdir(parents=True, exist_ok=True)
        sid = self.command(["pwsh", "-NoProfile", "-Command",
                            "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value | ConvertTo-Json"],
                           json_output=True)
        if not re.fullmatch(r"S-[0-9-]+", sid):
            raise Stop("PRIVATE_DIRECTORY_ACL_FAILED")
        self.command(["icacls", path, "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F", "/q"])

    def prepare(self, run):
        self.command([self.hushrun, "run", "--deliver", "stdin-line", "--label",
                      "owner-kit passphrase - mint new Keyferry stick and authorize example-host",
                      "--cwd", ROOT, "--", self.helper, "prepare-stick", "--owner-kit",
                      self.settings["owner_kit"], "--installation", self.settings["installation_directory"],
                      "--network-bundle", self.settings["network_bundle"], "--output", run / "prepare"],
                     timeout=None, hushrun_receipt=run / "receipt.json")

    def build(self, run, profile):
        build = "build/provision-" + run.name.split("-")[1]
        self.protect(ROOT / build)
        self.command(["pwsh", "-NoProfile", "-File", ROOT / "scripts/build_first_hil.ps1",
                      "-BuildDir", build, "-BoardProfile", profile["id"], "-PointerExtended",
                      "-PrivateHeader", run / "prepare/bootstrap/keyferry_hil_private.h",
                      "-ToolchainRoot", self.main, "-Jobs", "4"], timeout=1800)
        self.command([sys.executable, ROOT / "scripts/freeze_first_install.py", "--build", ROOT / build,
                      "--output", run / "image", "--idf-root", self.main / ".tools/esp-idf-v6.0.3"])

    def apply(self, run):
        self.command(["pwsh", "-NoProfile", "-File", ROOT / "scripts/provision_stick.ps1",
                      "-ApplyInstallation", run / "prepare/installation",
                      "-Settings", self.settings["settings_path"]])

    def ports(self):
        from serial.tools.list_ports import comports
        return [{"port": p.device, "vid": p.vid, "serial": p.serial_number} for p in comports()]

    def rom(self, port, mode):
        return Rom(self.main, port, mode)

    def bootstrap(self, run):
        self.command([self.helper, "bootstrap-roaming", "--private-header",
                      run / "prepare/bootstrap/keyferry_hil_private.h", "--installation",
                      run / "prepare/installation", "--network-bundle", self.settings["network_bundle"],
                      "--journal-dir", run / "bootstrap-journal"], timeout=120)

    def wait_bootstrap(self, run):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                self.command([self.helper, "bootstrap-status", "--private-header",
                              run / "prepare/bootstrap/keyferry_hil_private.h"], timeout=5)
                return
            except Stop:
                # This exact-device operation is read only. Policy writes below
                # are invoked once, journaled, and never replayed here.
                time.sleep(0.5)
        raise Stop("USB_BOOTSTRAP_INTERFACE_TIMEOUT")

    def inventory(self):
        cli = Path(os.environ["LOCALAPPDATA"]) / "Programs/Keyferry/keyctl.exe"
        return self.command([cli, "devices"], timeout=10, json_output=True)


class Rom:
    def __init__(self, main, port, mode):
        self.backend = module(ROOT / "tools/keyferry-firmware/esptool_backend.py", "provision_rom")
        self.backend.log.set_logger(self.backend._SilentLogger())
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.esp = self.backend._open_rom(port, mode)

    def observe(self):
        b, esp = self.backend, self.esp
        # Never serialize eFuse key blocks; hash the canonical summary in memory.
        commands = b.init_commands(esp=esp)
        values = {name: commands.efuses[name].get() if commands.efuses[name].is_readable() else None
                  for name in EFUSES}
        raw_id = esp.flash_id(cache=False)
        mac = esp.read_mac("BASE_MAC")
        return {"rom_mac": ":".join(f"{v:02x}" for v in mac), "chip": "esp32s3",
                "soc_revision": f"v{esp.get_major_chip_version()}.{esp.get_minor_chip_version()}",
                "flash_manufacturer_id": f"0x{raw_id & 255:02x}",
                "flash_device_id": f"0x{((raw_id >> 16) & 255) | (((raw_id >> 8) & 255) << 8):04x}",
                "flash_size_bytes": b.flash_size_bytes(b.cmds.detect_flash_size(esp)),
                "secure_boot": bool(esp.get_secure_boot_enabled()),
                "flash_encryption": bool(esp.get_flash_encryption_enabled()),
                "secure_download_mode": bool(esp.secure_download_mode), "efuses": values,
                "efuse_sha256": b._efuse_summary_sha256(commands)}

    def erase(self, region):
        self.backend.cmds.erase_region(self.esp, region["offset"], region["size_bytes"], force=False)

    def write(self, writes, directory):
        for offset, data in self.images(writes, directory):
            self.backend._write_application(self.esp, offset, data)

    @staticmethod
    def images(writes, directory):
        images = []
        for w in writes:
            data = (directory / w["file"]).read_bytes()
            if len(data) != w["size_bytes"] or digest(data) != w["sha256"]:
                raise Stop("FROZEN_IMAGE_CHANGED")
            images.append((w["offset"], data))
        return images

    def verify(self, writes, directory):
        self.backend.cmds.verify_flash(self.esp, self.images(writes, directory))

    def reset(self):
        self.backend.cmds.reset_chip(self.esp, "hard-reset")

    def close(self):
        self.esp.__exit__(None, None, None)


def execute(tools, private, profile, approval, dry_run=False, timeout=90, emit=print, new_device=False):
    """Shared production state machine. Write intent is durable before erase."""
    private.mkdir(parents=True, exist_ok=True)
    current = private / ("provision-current-" + profile["id"] + ".json")
    tools.preflight()
    if (approval.get("schema") != "keyferry.provision-approval.v1"
            or approval.get("board_profile") != profile["id"]
            or approval.get("recovery_gate") != "OWNER_RATIFIED_AUTOMATIC_ROM"
            or not approval.get("owner_source")):
        raise Stop("RECOVERY_GATE_UNRATIFIED")
    if current.exists():
        run = private / load(current)["run"]
        if not run.resolve().is_relative_to(private.resolve()):
            raise Stop("RUN_PATH_ESCAPE")
        if new_device:
            if load(run / "receipt.json").get("status") != "READY":
                raise Stop("PENDING_DEVICE_MUST_BE_RECONCILED_FIRST")
            current.unlink()
            return execute(tools, private, profile, approval, dry_run, timeout, emit)
    else:
        run = private / ("provision-" + uuid.uuid4().hex[:8] + "-" + datetime.date.today().isoformat())
        run.mkdir()
        save(current, {"run": run.name})
    tools.protect(run)
    state_path = run / "receipt.json"
    state = load(state_path) if state_path.exists() else {
        "schema": "keyferry.provision-receipt.v1", "board_profile": profile["id"],
        "dry_run": dry_run, "status": "PREPARE_PENDING"}
    approval_hash = digest(json.dumps(approval, sort_keys=True, separators=(",", ":")).encode())
    if state["dry_run"] is not dry_run or state["board_profile"] != profile["id"]:
        raise Stop("RUN_MODE_MISMATCH")
    def record(**fields):
        state.update(fields)
        save(state_path, state)
    rom = None
    try:
        record(approval_sha256=approval_hash)
        prepare = run / "prepare/prepared.json"
        if not prepare.exists():
            if state.get("prepare_possible"):
                raise Stop("PREPARATION_UNKNOWN_INSPECT_HUSHRUN_AND_STAGED_KIT")
            emit("PREPARE: one masked owner-kit prompt; mint identity and expand example-host grant")
            record(prepare_possible=True)
            tools.prepare(run)
            # The Hushrun adapter may have recorded its request while waiting.
            state.update(load(state_path))
        device = str(uuid.UUID(load(prepare)["device_id"]))
        if state.get("device_id") and state["device_id"] != device:
            raise Stop("PREPARED_IDENTITY_CHANGED")
        record(device_id=device, status="PREPARED")
        if not (run / "image/first-install-plan.json").exists():
            if state.get("build_possible"):
                raise Stop("BUILD_INCOMPLETE_INSPECT_FROZEN_ARTIFACTS")
            emit("BUILD: private pointer image and frozen full-install plan (stick unplugged)")
            record(build_possible=True)
            tools.build(run, profile)
        plan = check_plan(run / "image", profile)
        if state.get("plan_sha256") and state["plan_sha256"] != plan["proposal_sha256"]:
            raise Stop("FROZEN_PLAN_CHANGED_BEFORE_RESUME")
        record(plan_sha256=plan["proposal_sha256"], image_hashes={
            w["file"]: w["sha256"] for w in plan["writes"]}, producer_commit=plan["producer_commit"])
        # Invoking this owner-run command authorizes its narrow new-device full
        # install. Retain the exact hashes before writing, without another prompt.
        if approval.get("write_scope") != "NEW_DEVICE_FULL_INSTALL":
            raise Stop("NEW_DEVICE_WRITE_SCOPE_REQUIRED")
        if not state.get("controller_applied"):
            if state.get("apply_possible"):
                raise Stop("INSTALL_UNKNOWN_RECONCILE_INSTALLED_GENERATION")
            emit("CONTROLLER: Apply expanded credentials; example-host holder restarts once before flashing")
            record(apply_possible=True)
            tools.apply(run)
            record(controller_applied=True)
        baseline = tools.ports()
        emit("CONNECT: plug in the stick; waiting for one new VID 303A port")
        deadline = time.monotonic() + timeout
        selected = None
        # Resume may use only the recorded exact port+serial. Still re-read MAC.
        if state.get("identity"):
            saved = state["port"]
            candidates = [p for p in baseline if p == saved]
            if len(candidates) == 1:
                selected = candidates[0]
        while selected is None and time.monotonic() < deadline:
            selected = select_port(baseline, tools.ports())
            if selected is None:
                time.sleep(0.25)
        if selected is None:
            raise Stop("NEW_303A_PORT_TIMEOUT")
        try:
            rom = tools.rom(selected["port"], "default-reset")
        except Exception:
            emit("ROM: hold the side button 2 s" if profile["id"] == "m5stack_atoms3_lite"
                 else "ROM: use this board's BOOT/reset controls without unplugging")
            deadline = time.monotonic() + timeout
            while rom is None and time.monotonic() < deadline:
                # Never switch to an arbitrary port during re-enumeration.
                candidates = [p for p in tools.ports() if p == selected]
                if len(candidates) == 1:
                    try:
                        rom = tools.rom(selected["port"], "no-reset")
                    except Exception:
                        pass
                time.sleep(0.25)
            if rom is None:
                raise Stop("ROM_ENTRY_TIMEOUT")
        observation = rom.observe()
        check_observation(observation, plan["flash_size_bytes"])
        identity = {key: observation[key] for key in IDENTITY}
        if state.get("identity") and state["identity"] != identity:
            raise Stop("RESUME_CHIP_MISMATCH")
        index = private / ("provision-chip-" + observation["rom_mac"].replace(":", "") + ".json")
        if index.exists() and load(index) != {"run": run.name, "device_id": device}:
            raise Stop("CHIP_ALREADY_HAS_IDENTITY_RESUME_ITS_RUN")
        save(index, {"run": run.name, "device_id": device})
        record(identity=identity, port=selected, efuse_proof={k: observation["efuses"][k] for k in EFUSES})
        emit("IDENTITY: ESP32-S3, flash and all recovery/security eFuses checked")
        if state.get("write_possible"):
            emit("RESUME: possible prior write; verify only, never automatically rewrite")
        else:
            # A durable intent includes erase: interruption at any write boundary
            # always selects verify-only on rerun. Failed verify stops for review.
            record(write_possible=True, status="WRITE_POSSIBLE")
            emit("WRITE: erase planned state regions; write bootloader, table and app")
            for region in plan["erase_before_first_install"]:
                rom.erase(region)
            rom.write(plan["writes"], run / "image")
        rom.verify(plan["writes"], run / "image")
        record(verify_regions=[{"offset": w["offset"], "sha256": w["sha256"], "verified": True}
                               for w in plan["writes"]], status="WRITE_VERIFIED")
        emit("VERIFY: every written region matches; reset and automatically re-enter ROM")
        rom.close()
        rom = None
        # No button fallback here: this is specifically automatic re-entry proof.
        deadline = time.monotonic() + timeout
        while rom is None and time.monotonic() < deadline:
            try:
                rom = tools.rom(selected["port"], "default-reset")
            except Exception:
                time.sleep(0.25)
        if rom is None:
            raise Stop("AUTOMATIC_ROM_REENTRY_FAILED")
        repeated = rom.observe()
        check_observation(repeated, plan["flash_size_bytes"])
        if {key: repeated[key] for key in IDENTITY} != identity:
            raise Stop("ROM_REENTRY_IDENTITY_MISMATCH")
        rom.verify(plan["writes"], run / "image")
        record(rom_reentry_verified=True, rom_reentry_method="default-reset from ROM", second_verify=True)
        rom.reset()
        rom.close()
        rom = None
        emit("BOOT: hard-reset into app; authenticated bootstrap and disarmed inventory")
        if not state.get("bootstrap_complete"):
            if state.get("bootstrap_possible"):
                raise Stop("BOOTSTRAP_UNKNOWN_INSPECT_EXISTING_JOURNAL")
            tools.wait_bootstrap(run)
            record(bootstrap_possible=True)
            tools.bootstrap(run)
            record(bootstrap_complete=True)
        deadline = time.monotonic() + timeout
        inventory = None
        waiting = False
        while inventory is None and time.monotonic() < deadline:
            inventory = ready_inventory(tools.inventory(), device, plan, profile)
            if inventory is None:
                if not waiting:
                    emit("WAIT: authenticated disarmed stick ")
                    waiting = True
                emit(".")
                time.sleep(1)
        if waiting:
            emit("")
        if inventory is None:
            raise Stop("AUTHENTICATED_INVENTORY_TIMEOUT")
        record(inventory=inventory, status="READY", hardware_gate="OPEN")
        emit(f"READY: {device} on example-host (disarmed)" + (" [DRY RUN]" if dry_run else ""))
        return state
    except Exception as error:
        state.update(load(state_path))
        record(status="STOPPED", error= str(error) if isinstance(error, Stop) else "TOOL_OR_INPUT_FAILURE")
        raise Stop(state["error"]) from error
    finally:
        if rom is not None:
            rom.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--main-root", type=Path, required=True)
    parser.add_argument("--board-profile", default="m5stack_atoms3_lite")
    parser.add_argument("--settings", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--new-device", action="store_true")
    args = parser.parse_args()
    profile = load(ROOT / "firmware/esp32s3/boards" / args.board_profile / "board.json")
    private = args.main_root / "hardware/evidence/private"
    try:
        if args.dry_run:
            fake = module(ROOT / "tests/provision_fakes.py", "provision_fakes")
            tools = fake.FakeTools(profile)
            approval = {"schema": "keyferry.provision-approval.v1", "board_profile": profile["id"],
                        "recovery_gate": "OWNER_RATIFIED_AUTOMATIC_ROM", "owner_source": "SYNTHETIC",
                        "write_scope": "NEW_DEVICE_FULL_INSTALL"}
            private = private / "provision-dry-run" / uuid.uuid4().hex[:8]
        else:
            settings_path = args.settings or private / "provision-settings.json"
            settings = load(settings_path)
            settings["settings_path"] = str(settings_path.resolve())
            tools = Tools(args.main_root, settings)
            approval = load(Path(settings["approval_file"]))
        # Suppress all library/ROM output. Our emitter bypasses this redirect.
        console = sys.stdout
        def console_line(line):
            print(line, file=console, flush=True,
                  end="" if line == "." or line.startswith("WAIT:") else "\n")
        with process_lock(private), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            execute(tools, private, profile, approval, args.dry_run,
                    emit=console_line, new_device=args.new_device)
        return 0
    except Exception as error:
        print("STOP: " + (str(error) if isinstance(error, Stop) else "TOOL_OR_INPUT_FAILURE"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
