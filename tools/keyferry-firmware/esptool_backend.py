#!/usr/bin/env python3
"""Narrow exact-unit ROM probe and application-only firmware writer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from io import StringIO

import esptool
from esptool import cmds
from esptool.logger import TemplateLogger, log
from esptool.util import flash_size_bytes
from espefuse.efuse_interface import init_commands


PINNED_ESPTOOL_VERSION = "5.4.0"
MAX_PRESERVED_READ_BYTES = 65_536
APPLICATION_OFFSET = 0x10000
MAX_APPLICATION_BYTES = 1024 * 1024
CLONE_STATE_OFFSET = 0x110000
CLONE_STATE_BYTES = 0xB000
CLONE_SUFFIX_OFFSET = 0x11B000
CLONE_SUFFIX_BYTES = 0x1000
CLONE_REGIONS = {
    (APPLICATION_OFFSET, 0x1000),
    (APPLICATION_OFFSET + 0x1000, MAX_APPLICATION_BYTES - 0x1000),
    (CLONE_STATE_OFFSET, CLONE_STATE_BYTES),
}
LAYOUT_APP_OFFSET = 0x120000
LAYOUT_APP_LIMIT = 0x200000 - 0x8000
LAYOUT_TABLE_OFFSET = 0x8000
LAYOUT_SECTOR_BYTES = 0x1000
LAYOUT_AFTER_OFFSET = 0x9000
LAYOUT_AFTER_BYTES = LAYOUT_APP_OFFSET - LAYOUT_AFTER_OFFSET
LAYOUT_CONFIG_OFFSET = 0x110000
LAYOUT_CONFIG_BYTES = 0xB000
BACKUP_CHUNK_BYTES = 64 * 1024
MAX_BACKUP_BYTES = 16 * 1024 * 1024


class _ProbeError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _SilentLogger(TemplateLogger):
    def print(self, *args, **kwargs):
        pass

    def note(self, message):
        pass

    def warning(self, message):
        pass

    def error(self, message):
        pass

    def stage(self, finish=False):
        pass

    def progress_bar(self, cur_iter, total_iters, prefix="", suffix="", bar_length=30):
        pass

    def set_verbosity(self, verbosity):
        pass


def _bounded_positive(value: str) -> int:
    parsed = int(value, 10)
    if not 1 <= parsed <= MAX_PRESERVED_READ_BYTES:
        raise argparse.ArgumentTypeError("value outside the preserved-read bound")
    return parsed


def _bounded_offset(value: str) -> int:
    parsed = int(value, 10)
    if not 0 <= parsed < 16 * 1024 * 1024:
        raise argparse.ArgumentTypeError("offset outside flash")
    return parsed


def _local_port(value: str) -> str:
    if os.name == "nt":
        valid = re.fullmatch(r"COM[1-9][0-9]{0,2}", value) is not None
    else:
        valid = (
            len(value) <= 128
            and ".." not in value
            and (value.startswith("/dev/tty") or value.startswith("/dev/cu."))
        )
    if not valid:
        raise argparse.ArgumentTypeError("an exact local serial port is required")
    return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _SummarySink(StringIO):
    """In-memory target for espefuse's summary, which names and then closes its file."""

    name = "keyferry-efuse-summary"

    def close(self) -> None:
        pass

    def release(self) -> None:
        super().close()


def _efuse_summary_sha256(commands) -> str:
    """Digest of the JSON summary in the CRLF form that every qualified unit record binds.

    Qualification hashed `espefuse summary --format json --file` output saved on Windows, so the
    recorded digests cover CRLF line endings. Fixing that form keeps the digest platform-neutral.
    """
    sink = _SummarySink()
    try:
        commands.summary([], "json", sink, False)
        text = sink.getvalue().replace("\r\n", "\n").replace("\n", "\r\n")
        return _sha256(text.encode("utf-8"))
    finally:
        sink.release()


def _strict_json(line: bytes, duplicate_code: str):
    def object_no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise _ProbeError(duplicate_code)
            result[key] = value
        return result

    return json.loads(line, object_pairs_hook=object_no_duplicates)


def _open_rom(port: str):
    if esptool.__version__ != PINNED_ESPTOOL_VERSION:
        raise _ProbeError("firmware.rom_probe_tool")
    try:
        esp = cmds.detect_chip(
            port=port,
            baud=115_200,
            connect_mode="no-reset",
            trace_enabled=False,
            connect_attempts=1,
        )
    except Exception as error:
        raise _ProbeError("firmware.rom_probe_connect") from error
    try:
        if esp.IS_STUB or esp.CHIP_NAME != "ESP32-S3":
            raise _ProbeError("firmware.rom_probe_mode")
        try:
            # The ROM does not expose SPI flash until its volatile controller is
            # attached. This neither resets the SoC nor changes persistent flash.
            cmds.attach_flash(esp, spi_connection=None, flash_type="nor")
        except Exception as error:
            raise _ProbeError("firmware.rom_probe_flash_attach") from error
        return esp
    except Exception:
        try:
            esp.__exit__(None, None, None)
        except Exception:
            pass
        raise


def _observe_attached(esp, args: argparse.Namespace) -> dict[str, object]:
    if args.bootloader_offset + args.bootloader_size > args.partition_table_offset:
        raise _ProbeError("firmware.rom_probe_range")
    if args.partition_table_offset + args.partition_table_size > APPLICATION_OFFSET:
        raise _ProbeError("firmware.rom_probe_range")
    try:
        try:
            raw_flash_id = esp.flash_id(cache=False)
            manufacturer_id = raw_flash_id & 0xFF
            device_id = ((raw_flash_id >> 16) & 0xFF) | (
                ((raw_flash_id >> 8) & 0xFF) << 8
            )
            detected_size = flash_size_bytes(cmds.detect_flash_size(esp))
            mac = esp.read_mac("BASE_MAC")
            major_revision = esp.get_major_chip_version()
            minor_revision = esp.get_minor_chip_version()
            secure_boot = bool(esp.get_secure_boot_enabled())
            flash_encryption = bool(esp.get_flash_encryption_enabled())
            secure_download_mode = bool(esp.secure_download_mode)
        except Exception as error:
            raise _ProbeError("firmware.rom_probe_identity") from error
        if detected_size is None or mac is None or len(mac) != 6:
            raise _ProbeError("firmware.rom_probe_identity")

        try:
            efuse_sha256 = _efuse_summary_sha256(init_commands(esp=esp))
        except Exception as error:
            raise _ProbeError("firmware.rom_probe_efuse") from error

        try:
            bootloader = cmds.read_flash(
                esp,
                args.bootloader_offset,
                args.bootloader_size,
                output=None,
                flash_size="keep",
                no_progress=True,
            )
            partition_table = cmds.read_flash(
                esp,
                args.partition_table_offset,
                args.partition_table_size,
                output=None,
                flash_size="keep",
                no_progress=True,
            )
        except Exception as error:
            raise _ProbeError("firmware.rom_probe_preserved_read") from error
        if bootloader is None or partition_table is None:
            raise _ProbeError("firmware.rom_probe_preserved_read")
        return {
            "schema": "keyferry.rom-probe-result.v1",
            "mode": "READ_ONLY_PLAN",
            "port": args.port,
            "rom_mac": ":".join(f"{octet:02x}" for octet in mac),
            "chip": "esp32s3",
            "soc_revision": f"v{major_revision}.{minor_revision}",
            "flash_manufacturer_id": f"0x{manufacturer_id:02x}",
            "flash_device_id": f"0x{device_id:04x}",
            "flash_size_bytes": detected_size,
            "secure_boot": secure_boot,
            "flash_encryption": flash_encryption,
            "secure_download_mode": secure_download_mode,
            "efuse_sha256": efuse_sha256,
            "bootloader_sha256": _sha256(bootloader),
            "partition_table_sha256": _sha256(partition_table),
            "esptool_version": esptool.__version__,
        }
    except _ProbeError:
        raise
    except Exception as error:
        raise _ProbeError("firmware.rom_probe_identity") from error


def _probe(args: argparse.Namespace) -> dict[str, object]:
    esp = _open_rom(args.port)
    try:
        return _observe_attached(esp, args)
    finally:
        esp.__exit__(None, None, None)


def _read_apply_request() -> tuple[int, bytes, str]:
    line = sys.stdin.buffer.readline(4097)
    if not line or len(line) > 4096 or not line.endswith(b"\n"):
        raise _ProbeError("firmware.apply_protocol")
    try:
        request = _strict_json(line, "firmware.apply_protocol")
    except Exception as error:
        raise _ProbeError("firmware.apply_protocol") from error
    if not isinstance(request, dict) or set(request) != {
        "schema",
        "action",
        "offset",
        "size",
        "sha256",
    }:
        raise _ProbeError("firmware.apply_protocol")
    offset = request["offset"]
    size = request["size"]
    digest = request["sha256"]
    if (
        request["schema"] != "keyferry.apply-request.v1"
        or request["action"] != "write_application"
        or type(offset) is not int
        or offset != APPLICATION_OFFSET
        or type(size) is not int
        or not 1 <= size <= MAX_APPLICATION_BYTES
        or type(digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise _ProbeError("firmware.apply_protocol")
    image = sys.stdin.buffer.read(size + 1)
    if len(image) != size or _sha256(image) != digest:
        raise _ProbeError("firmware.apply_protocol")
    return offset, image, digest


def _write_application(esp, offset: int, image: bytes) -> None:
    cmds.write_flash(
        esp,
        [(offset, image)],
        flash_freq="keep",
        flash_mode="keep",
        flash_size="keep",
        flash_type="nor",
        erase_all=False,
        encrypt=False,
        encrypt_files=None,
        compress=False,
        no_compress=True,
        force=False,
        ignore_flash_enc_efuse=False,
        no_progress=True,
        diff_with=[],
        no_diff_verify=False,
        skip_flashed=False,
    )


def _apply_session(args: argparse.Namespace) -> dict[str, object]:
    esp = _open_rom(args.port)
    try:
        observation = _observe_attached(esp, args)
        sys.stdout.write(json.dumps(observation, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        offset, image, digest = _read_apply_request()
        try:
            _write_application(esp, offset, image)
            readback = cmds.read_flash(
                esp,
                offset,
                len(image),
                output=None,
                flash_size="keep",
                no_progress=True,
            )
        except Exception as error:
            raise _ProbeError("firmware.apply_unknown_write") from error
        if readback != image or _sha256(readback) != digest:
            raise _ProbeError("firmware.apply_unknown_write")
        return {
            "schema": "keyferry.apply-result.v1",
            "outcome": "WRITE_VERIFIED",
        }
    finally:
        esp.__exit__(None, None, None)


def _read_flash(esp, offset: int, length: int) -> bytes:
    try:
        data = cmds.read_flash(
            esp,
            offset,
            length,
            output=None,
            flash_size="keep",
            no_progress=True,
        )
    except Exception as error:
        raise _ProbeError("firmware.clone_split_read") from error
    if data is None or len(data) != length:
        raise _ProbeError("firmware.clone_split_read")
    return data


def _clone_observation_attached(esp, args: argparse.Namespace) -> dict[str, object]:
    basic = _observe_attached(esp, args)
    app = _read_flash(esp, APPLICATION_OFFSET, MAX_APPLICATION_BYTES)
    state = _read_flash(esp, CLONE_STATE_OFFSET, CLONE_STATE_BYTES)
    prefix = _read_flash(esp, 0, APPLICATION_OFFSET)
    suffix = _read_flash(esp, CLONE_SUFFIX_OFFSET, CLONE_SUFFIX_BYTES)
    return {
        "schema": "keyferry.clone-split-observation.v1",
        "port": args.port,
        "rom_mac": basic["rom_mac"],
        "chip": basic["chip"],
        "soc_revision": basic["soc_revision"],
        "flash_manufacturer_id": basic["flash_manufacturer_id"],
        "flash_device_id": basic["flash_device_id"],
        "flash_size_bytes": basic["flash_size_bytes"],
        "secure_boot": basic["secure_boot"],
        "flash_encryption": basic["flash_encryption"],
        "secure_download_mode": basic["secure_download_mode"],
        "efuse_sha256": basic["efuse_sha256"],
        "bootloader_sha256": basic["bootloader_sha256"],
        "partition_table_sha256": basic["partition_table_sha256"],
        "application_sha256": _sha256(app),
        "state_sha256": _sha256(state),
        "protected_prefix_sha256": _sha256(prefix),
        "protected_suffix_sha256": _sha256(suffix),
        "esptool_version": esptool.__version__,
    }


def _read_clone_request() -> tuple[dict[str, object], bytes | None]:
    line = sys.stdin.buffer.readline(4097)
    if not line or len(line) > 4096 or not line.endswith(b"\n"):
        raise _ProbeError("firmware.clone_split_protocol")
    try:
        request = _strict_json(line, "firmware.clone_split_protocol")
    except Exception as error:
        raise _ProbeError("firmware.clone_split_protocol") from error
    if not isinstance(request, dict) or request.get("schema") != "keyferry.clone-split-request.v1":
        raise _ProbeError("firmware.clone_split_protocol")
    action = request.get("action")
    image = None
    if action in {"erase", "verify_erased"}:
        if set(request) != {"schema", "action", "offset", "length"}:
            raise _ProbeError("firmware.clone_split_protocol")
        pair = (request.get("offset"), request.get("length"))
        if any(type(value) is not int for value in pair) or pair not in CLONE_REGIONS:
            raise _ProbeError("firmware.clone_split_protocol")
    elif action == "write_application":
        if set(request) != {"schema", "action", "offset", "size", "sha256"}:
            raise _ProbeError("firmware.clone_split_protocol")
        size = request.get("size")
        digest = request.get("sha256")
        if (
            request.get("offset") != APPLICATION_OFFSET
            or type(size) is not int
            or not 1 <= size <= MAX_APPLICATION_BYTES
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise _ProbeError("firmware.clone_split_protocol")
        image = sys.stdin.buffer.read(size)
        if len(image) != size or _sha256(image) != digest:
            raise _ProbeError("firmware.clone_split_protocol")
    elif action == "verify_application":
        if set(request) != {"schema", "action", "image_size", "image_sha256", "partition_size"}:
            raise _ProbeError("firmware.clone_split_protocol")
        if (
            type(request.get("image_size")) is not int
            or not 1 <= request["image_size"] <= MAX_APPLICATION_BYTES
            or request.get("partition_size") != MAX_APPLICATION_BYTES
            or not isinstance(request.get("image_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", request["image_sha256"]) is None
        ):
            raise _ProbeError("firmware.clone_split_protocol")
    elif action == "verify_protected":
        if set(request) != {"schema", "action", "prefix_sha256", "suffix_sha256"}:
            raise _ProbeError("firmware.clone_split_protocol")
        if any(
            not isinstance(request.get(field), str)
            or re.fullmatch(r"[0-9a-f]{64}", request[field]) is None
            for field in ("prefix_sha256", "suffix_sha256")
        ):
            raise _ProbeError("firmware.clone_split_protocol")
    else:
        raise _ProbeError("firmware.clone_split_protocol")
    return request, image


def _clone_result(ok: bool) -> None:
    sys.stdout.write(
        json.dumps(
            {"schema": "keyferry.clone-split-result.v1", "ok": ok},
            separators=(",", ":"),
        )
        + "\n"
    )
    sys.stdout.flush()


def _clone_probe(args: argparse.Namespace) -> dict[str, object]:
    esp = _open_rom(args.port)
    try:
        return _clone_observation_attached(esp, args)
    finally:
        esp.__exit__(None, None, None)


def _clone_split_session(args: argparse.Namespace) -> dict[str, object]:
    esp = _open_rom(args.port)
    written_image: bytes | None = None
    try:
        observation = _clone_observation_attached(esp, args)
        sys.stdout.write(json.dumps(observation, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        while True:
            request, image = _read_clone_request()
            action = request["action"]
            try:
                if action == "erase":
                    cmds.erase_region(
                        esp,
                        request["offset"],
                        request["length"],
                        force=False,
                        flash_type="nor",
                    )
                    ok = True
                elif action == "verify_erased":
                    data = _read_flash(esp, request["offset"], request["length"])
                    ok = data == b"\xff" * request["length"]
                elif action == "write_application":
                    if image is None:
                        raise _ProbeError("firmware.clone_split_protocol")
                    _write_application(esp, APPLICATION_OFFSET, image)
                    written_image = image
                    ok = True
                elif action == "verify_application":
                    data = _read_flash(esp, APPLICATION_OFFSET, MAX_APPLICATION_BYTES)
                    size = request["image_size"]
                    ok = (
                        written_image is not None
                        and len(written_image) == size
                        and _sha256(written_image) == request["image_sha256"]
                        and data[:size] == written_image
                        and data[size:] == b"\xff" * (MAX_APPLICATION_BYTES - size)
                    )
                elif action == "verify_protected":
                    prefix = _read_flash(esp, 0, APPLICATION_OFFSET)
                    suffix = _read_flash(esp, CLONE_SUFFIX_OFFSET, CLONE_SUFFIX_BYTES)
                    ok = (
                        _sha256(prefix) == request["prefix_sha256"]
                        and _sha256(suffix) == request["suffix_sha256"]
                    )
                else:
                    raise AssertionError("validated action missing")
            except _ProbeError:
                raise
            except Exception as error:
                raise _ProbeError("firmware.clone_split_interrupted") from error
            _clone_result(ok)
            if not ok:
                raise _ProbeError("firmware.clone_split_interrupted")
            if action == "verify_protected":
                return {
                    "schema": "keyferry.clone-split-session.v1",
                    "outcome": "COMPLETE",
                }
    finally:
        esp.__exit__(None, None, None)


def _read_backup_request(observed_size: int) -> int:
    line = sys.stdin.buffer.readline(4097)
    if not line or len(line) > 4096 or not line.endswith(b"\n"):
        raise _ProbeError("firmware.backup_protocol")
    try:
        request = _strict_json(line, "firmware.backup_protocol")
    except Exception as error:
        raise _ProbeError("firmware.backup_protocol") from error
    if (
        not isinstance(request, dict)
        or set(request) != {"schema", "action", "flash_size_bytes"}
        or request["schema"] != "keyferry.backup-request.v1"
        or request["action"] != "read_full_flash"
        or type(request["flash_size_bytes"]) is not int
        or request["flash_size_bytes"] != observed_size
        or not 1 <= observed_size <= MAX_BACKUP_BYTES
        or observed_size % BACKUP_CHUNK_BYTES != 0
    ):
        raise _ProbeError("firmware.backup_protocol")
    return observed_size


def _backup_session(args: argparse.Namespace) -> dict[str, object]:
    esp = _open_rom(args.port)
    try:
        before = _observe_attached(esp, args)
        sys.stdout.write(json.dumps(before, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        flash_size = _read_backup_request(before["flash_size_bytes"])
        temporary = Path(args.output) / "full-flash.partial"
        if temporary.exists() or (Path(args.output) / "full-flash.bin").exists():
            raise _ProbeError("firmware.backup_output")
        digest = hashlib.sha256()
        progress = Path(args.output) / "progress.json"

        def record_progress(phase: str, completed: int) -> None:
            next_file = Path(args.output) / "progress.tmp"
            next_file.write_text(json.dumps({
                "schema": "keyferry.backup-progress.v1", "phase": phase,
                "completed_bytes": completed, "total_bytes": flash_size,
            }, separators=(",", ":")), encoding="utf-8")
            next_file.replace(progress)

        try:
            with temporary.open("xb") as snapshot:
                for offset in range(0, flash_size, BACKUP_CHUNK_BYTES):
                    block = cmds.read_flash(
                        esp, offset, BACKUP_CHUNK_BYTES, output=None,
                        flash_size="keep", no_progress=True,
                    )
                    if block is None or len(block) != BACKUP_CHUNK_BYTES:
                        raise _ProbeError("firmware.backup_short_read")
                    snapshot.write(block)
                    digest.update(block)
                    if (offset + BACKUP_CHUNK_BYTES) % (1024 * 1024) == 0:
                        record_progress("first_read", offset + BACKUP_CHUNK_BYTES)
                snapshot.flush()
                os.fsync(snapshot.fileno())
            with temporary.open("rb") as snapshot:
                for offset in range(0, flash_size, BACKUP_CHUNK_BYTES):
                    expected = snapshot.read(BACKUP_CHUNK_BYTES)
                    repeated = cmds.read_flash(
                        esp, offset, BACKUP_CHUNK_BYTES, output=None,
                        flash_size="keep", no_progress=True,
                    )
                    if repeated is None or len(repeated) != BACKUP_CHUNK_BYTES:
                        raise _ProbeError("firmware.backup_short_read")
                    if repeated != expected:
                        raise _ProbeError("firmware.backup_difference")
                    if (offset + BACKUP_CHUNK_BYTES) % (1024 * 1024) == 0:
                        record_progress("second_read", offset + BACKUP_CHUNK_BYTES)
            after = _observe_attached(esp, args)
            if before != after:
                raise _ProbeError("firmware.backup_identity_changed")
            record_progress("host_validation", flash_size)
        except Exception as error:
            temporary.unlink(missing_ok=True)
            if isinstance(error, _ProbeError):
                raise
            raise _ProbeError("firmware.backup_read") from error
        return {
            "schema": "keyferry.backup-session-result.v1",
            "size_bytes": flash_size,
            "sha256": digest.hexdigest(),
            "second_pass_equal": True,
            "after": after,
        }
    finally:
        esp.__exit__(None, None, None)


def _layout_read_request() -> tuple[dict[str, object], bytes, bytes]:
    line = sys.stdin.buffer.readline(4097)
    try:
        if not line or len(line) > 4096 or not line.endswith(b"\n"):
            raise ValueError("request length")
        request = _strict_json(line, "firmware.layout_protocol")
        fields = {"schema", "action", "expected_unit", "boot_prefix_sha256",
                  "preserved_after_sha256", "stage_bytes", "stage_before_sha256",
                  "old_table_sector_sha256", "table_sha256", "image_sha256", "image_bytes"}
        if not isinstance(request, dict) or set(request) != fields:
            raise ValueError("request fields")
        if request["schema"] != "keyferry.layout-request.v1" or request["action"] not in {
            "stage_switch", "rollback"
        }:
            raise ValueError("request mode")
        size, image_size = request["stage_bytes"], request["image_bytes"]
        if (type(size) is not int or type(image_size) is not int
                or not LAYOUT_SECTOR_BYTES <= size <= 0x200000
                or size % LAYOUT_SECTOR_BYTES
                or not 1 <= image_size <= LAYOUT_APP_LIMIT
                or (image_size + LAYOUT_SECTOR_BYTES - 1) // LAYOUT_SECTOR_BYTES * LAYOUT_SECTOR_BYTES != size):
            raise ValueError("stage footprint")
        if request["action"] == "rollback" and image_size != size:
            raise ValueError("rollback footprint")
        for name in ("boot_prefix_sha256", "preserved_after_sha256",
                     "stage_before_sha256", "old_table_sector_sha256",
                     "table_sha256", "image_sha256"):
            if not isinstance(request[name], str) or re.fullmatch(r"[0-9a-f]{64}", request[name]) is None:
                raise ValueError("digest")
        unit = request["expected_unit"]
        unit_keys = {"rom_mac", "chip", "soc_revision", "flash_manufacturer_id",
                     "flash_device_id", "flash_size_bytes", "secure_boot", "flash_encryption",
                     "secure_download_mode", "efuse_sha256", "bootloader_sha256",
                     "partition_table_sha256"}
        if not isinstance(unit, dict) or set(unit) != unit_keys:
            raise ValueError("unit shape")
        payload_size = image_size if request["action"] == "stage_switch" else size
        payload = sys.stdin.buffer.read(payload_size + LAYOUT_SECTOR_BYTES + 1)
        if len(payload) != payload_size + LAYOUT_SECTOR_BYTES:
            raise ValueError("payload length")
        image, table = payload[:payload_size], payload[payload_size:]
        if _sha256(image) != request["image_sha256"] or _sha256(table) != request["table_sha256"]:
            raise ValueError("payload digest")
        return request, image, table
    except (KeyError, TypeError, ValueError) as error:
        raise _ProbeError("firmware.layout_protocol") from error


_LAYOUT_UNIT_FIELDS = ("rom_mac", "chip", "soc_revision", "flash_manufacturer_id",
                       "flash_device_id", "flash_size_bytes", "secure_boot",
                       "flash_encryption", "secure_download_mode", "efuse_sha256",
                       "bootloader_sha256", "partition_table_sha256")


def _layout_config_refresh(args: argparse.Namespace) -> dict[str, object]:
    line = sys.stdin.buffer.readline(4097)
    try:
        request = _strict_json(line, "firmware.layout_config_protocol")
        if (not isinstance(request, dict) or set(request) != {
                "schema", "expected_unit", "backup_receipt_sha256",
                "backup_snapshot_sha256"}
                or request["schema"] != "keyferry.layout-config-request.v1"
                or not isinstance(request["expected_unit"], dict)
                or set(request["expected_unit"]) != set(_LAYOUT_UNIT_FIELDS)
                or any(not isinstance(request[name], str) or
                       re.fullmatch(r"[0-9a-f]{64}", request[name]) is None
                       for name in ("backup_receipt_sha256", "backup_snapshot_sha256"))):
            raise ValueError("request")
    except (KeyError, TypeError, ValueError) as error:
        raise _ProbeError("firmware.layout_config_protocol") from error
    esp = _open_rom(args.port)
    try:
        observation = _observe_attached(esp, args)
        if (any(observation.get(field) != request["expected_unit"][field]
                for field in _LAYOUT_UNIT_FIELDS)
                or observation["flash_size_bytes"] != 0x1000000
                or observation["secure_boot"] or observation["flash_encryption"]
                or observation["secure_download_mode"]):
            raise _ProbeError("firmware.layout_unit_mismatch")
        first = _read_flash(esp, LAYOUT_CONFIG_OFFSET, LAYOUT_CONFIG_BYTES)
        second = _read_flash(esp, LAYOUT_CONFIG_OFFSET, LAYOUT_CONFIG_BYTES)
        if first != second:
            raise _ProbeError("firmware.layout_config_changed")
        output = Path(args.output)
        if not output.is_dir() or any(output.iterdir()):
            raise _ProbeError("firmware.layout_config_output")
        with (output / "config.bin").open("xb") as config_file:
            config_file.write(first)
        receipt = {
            "schema": "keyferry.layout-config-receipt.v1",
            "expected_unit": request["expected_unit"],
            "backup_receipt_sha256": request["backup_receipt_sha256"],
            "backup_snapshot_sha256": request["backup_snapshot_sha256"],
            "offset": LAYOUT_CONFIG_OFFSET, "size_bytes": LAYOUT_CONFIG_BYTES,
            "config_sha256": _sha256(first), "second_pass_equal": True,
        }
        with (output / "receipt.json").open("x", encoding="utf-8") as receipt_file:
            receipt_file.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        return {"schema": "keyferry.layout-config-result.v1",
                "outcome": "CAPTURED", "config_sha256": receipt["config_sha256"]}
    finally:
        esp.__exit__(None, None, None)


def _layout_regions(esp, stage_bytes: int, include_stage: bool = True) -> dict[str, str]:
    regions = {
        "boot_prefix_sha256": (0, LAYOUT_TABLE_OFFSET),
        "old_table_sector_sha256": (LAYOUT_TABLE_OFFSET, LAYOUT_SECTOR_BYTES),
        "preserved_after_sha256": (LAYOUT_AFTER_OFFSET, LAYOUT_AFTER_BYTES),
    }
    if include_stage:
        regions["stage_before_sha256"] = (LAYOUT_APP_OFFSET, stage_bytes)
    return {name: _sha256(_read_flash(esp, offset, length))
            for name, (offset, length) in regions.items()}


def _layout_write(esp, offset: int, image: bytes) -> None:
    if (offset == LAYOUT_APP_OFFSET and len(image) <= 0x200000
            and len(image) % LAYOUT_SECTOR_BYTES == 0) or (
            offset == LAYOUT_TABLE_OFFSET and len(image) == LAYOUT_SECTOR_BYTES):
        _write_application(esp, offset, image)
        return
    raise _ProbeError("firmware.layout_protocol")


def _layout_session(args: argparse.Namespace) -> dict[str, object]:
    request, image, table = _layout_read_request()
    esp = _open_rom(args.port)
    write_started = False
    try:
        observation = _observe_attached(esp, args)
        expected_unit = request["expected_unit"]
        checked_unit_fields = _LAYOUT_UNIT_FIELDS if request["action"] == "stage_switch" else (
            field for field in _LAYOUT_UNIT_FIELDS if field != "partition_table_sha256")
        if (any(observation.get(field) != expected_unit[field]
                for field in checked_unit_fields)
                or observation["flash_size_bytes"] != 0x1000000
                or observation["secure_boot"] or observation["flash_encryption"]
                or observation["secure_download_mode"]):
            raise _ProbeError("firmware.layout_unit_mismatch")
        regions = _layout_regions(esp, request["stage_bytes"],
                                  request["action"] == "stage_switch")
        for name in ("boot_prefix_sha256", "preserved_after_sha256"):
            if regions[name] != request[name]:
                raise _ProbeError("firmware.layout_preserved_mismatch")
        if request["action"] == "stage_switch":
            for name in ("old_table_sector_sha256", "stage_before_sha256"):
                if regions[name] != request[name]:
                    raise _ProbeError("firmware.layout_before_mismatch")
            padded = image.ljust(request["stage_bytes"], b"\xff")
            write_started = True
            _layout_write(esp, LAYOUT_APP_OFFSET, padded)
            if _read_flash(esp, LAYOUT_APP_OFFSET, len(padded)) != padded:
                raise _ProbeError("firmware.layout_unknown_write")
            after_stage = _layout_regions(esp, request["stage_bytes"], False)
            for name in ("boot_prefix_sha256", "preserved_after_sha256",
                         "old_table_sector_sha256"):
                if after_stage[name] != request[name]:
                    raise _ProbeError("firmware.layout_unknown_write")
            _layout_write(esp, LAYOUT_TABLE_OFFSET, table)
            if _read_flash(esp, LAYOUT_TABLE_OFFSET, LAYOUT_SECTOR_BYTES) != table:
                raise _ProbeError("firmware.layout_unknown_write")
            outcome = "SWITCH_VERIFIED"
        else:
            # ROM recovery accepts a torn current table and stage; the saved
            # old app/config and exact unit must still match before either write.
            write_started = True
            _layout_write(esp, LAYOUT_TABLE_OFFSET, table)
            if _read_flash(esp, LAYOUT_TABLE_OFFSET, LAYOUT_SECTOR_BYTES) != table:
                raise _ProbeError("firmware.layout_unknown_write")
            _layout_write(esp, LAYOUT_APP_OFFSET, image)
            if _read_flash(esp, LAYOUT_APP_OFFSET, len(image)) != image:
                raise _ProbeError("firmware.layout_unknown_write")
            outcome = "ROLLBACK_VERIFIED"
        if request["action"] == "rollback":
            final = _layout_regions(esp, request["stage_bytes"], False)
            if (final["boot_prefix_sha256"] != request["boot_prefix_sha256"]
                    or final["preserved_after_sha256"] != request["preserved_after_sha256"]):
                raise _ProbeError("firmware.layout_unknown_write")
        return {"schema": "keyferry.layout-result.v1", "outcome": outcome}
    except _ProbeError as error:
        if write_started and error.code != "firmware.layout_unknown_write":
            raise _ProbeError("firmware.layout_unknown_write") from error
        raise
    except Exception as error:
        raise _ProbeError("firmware.layout_unknown_write" if write_started
                          else "firmware.layout_unavailable") from error
    finally:
        esp.__exit__(None, None, None)


def _layout_update_session(args: argparse.Namespace) -> dict[str, object]:
    line = sys.stdin.buffer.readline(4097)
    try:
        request = _strict_json(line, "firmware.layout_update_protocol")
        if (not isinstance(request, dict) or set(request) != {
                "schema", "expected_unit", "boot_prefix_sha256",
                "table_sector_sha256", "installed_image_bytes",
                "installed_image_sha256", "image_bytes", "image_sha256"}
                or request["schema"] != "keyferry.layout-update-request.v1"
                or not isinstance(request["expected_unit"], dict)
                or set(request["expected_unit"]) != set(_LAYOUT_UNIT_FIELDS)
                or any(type(request[name]) is not int or
                       not 1 <= request[name] <= LAYOUT_APP_LIMIT
                       for name in ("installed_image_bytes", "image_bytes"))
                or any(not isinstance(request[name], str) or
                       re.fullmatch(r"[0-9a-f]{64}", request[name]) is None
                       for name in ("boot_prefix_sha256", "table_sector_sha256",
                                    "installed_image_sha256", "image_sha256"))):
            raise ValueError("request")
        image = sys.stdin.buffer.read(request["image_bytes"] + 1)
        if len(image) != request["image_bytes"] or _sha256(image) != request["image_sha256"]:
            raise ValueError("image")
    except (KeyError, TypeError, ValueError) as error:
        raise _ProbeError("firmware.layout_update_protocol") from error
    esp = _open_rom(args.port)
    write_started = False
    try:
        observation = _observe_attached(esp, args)
        if (any(observation.get(field) != request["expected_unit"][field]
                for field in _LAYOUT_UNIT_FIELDS)
                or observation["flash_size_bytes"] != 0x1000000
                or observation["secure_boot"] or observation["flash_encryption"]
                or observation["secure_download_mode"]):
            raise _ProbeError("firmware.layout_unit_mismatch")
        prefix = _read_flash(esp, 0, LAYOUT_TABLE_OFFSET)
        table = _read_flash(esp, LAYOUT_TABLE_OFFSET, LAYOUT_SECTOR_BYTES)
        protected = _read_flash(esp, LAYOUT_AFTER_OFFSET, LAYOUT_AFTER_BYTES)
        installed = _read_flash(esp, LAYOUT_APP_OFFSET, request["installed_image_bytes"])
        if (_sha256(prefix) != request["boot_prefix_sha256"]
                or _sha256(table) != request["table_sector_sha256"]
                or _sha256(installed) != request["installed_image_sha256"]):
            raise _ProbeError("firmware.layout_update_before_mismatch")
        padded = image.ljust((len(image) + LAYOUT_SECTOR_BYTES - 1) //
                             LAYOUT_SECTOR_BYTES * LAYOUT_SECTOR_BYTES, b"\xff")
        write_started = True
        _layout_write(esp, LAYOUT_APP_OFFSET, padded)
        if _read_flash(esp, LAYOUT_APP_OFFSET, len(padded)) != padded:
            raise _ProbeError("firmware.layout_unknown_write")
        if (_read_flash(esp, 0, LAYOUT_TABLE_OFFSET) != prefix
                or _read_flash(esp, LAYOUT_TABLE_OFFSET, LAYOUT_SECTOR_BYTES) != table
                or _read_flash(esp, LAYOUT_AFTER_OFFSET, LAYOUT_AFTER_BYTES) != protected):
            raise _ProbeError("firmware.layout_unknown_write")
        return {"schema": "keyferry.layout-result.v1", "outcome": "APP_UPDATE_VERIFIED"}
    except _ProbeError as error:
        if write_started and error.code != "firmware.layout_unknown_write":
            raise _ProbeError("firmware.layout_unknown_write") from error
        raise
    except Exception as error:
        raise _ProbeError("firmware.layout_unknown_write" if write_started
                          else "firmware.layout_unavailable") from error
    finally:
        esp.__exit__(None, None, None)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("probe", "apply-session", "clone-split-probe", "clone-split-session", "backup-session", "layout-session", "layout-config-refresh", "layout-update-session"):
        command = subparsers.add_parser(name, add_help=False, allow_abbrev=False)
        command.add_argument("--port", required=True, type=_local_port)
        command.add_argument("--bootloader-offset", required=True, type=_bounded_offset)
        command.add_argument("--bootloader-size", required=True, type=_bounded_positive)
        command.add_argument(
            "--partition-table-offset", required=True, type=_bounded_offset
        )
        command.add_argument(
            "--partition-table-size", required=True, type=_bounded_positive
        )
        if name == "backup-session":
            command.add_argument("--output", required=True)
        if name == "layout-config-refresh":
            command.add_argument("--output", required=True)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        log.set_logger(_SilentLogger())
        if args.command == "probe":
            result = _probe(args)
        elif args.command == "apply-session":
            result = _apply_session(args)
        elif args.command == "clone-split-probe":
            result = _clone_probe(args)
        elif args.command == "clone-split-session":
            result = _clone_split_session(args)
        elif args.command == "backup-session":
            result = _backup_session(args)
        elif args.command == "layout-session":
            result = _layout_session(args)
        elif args.command == "layout-config-refresh":
            result = _layout_config_refresh(args)
        elif args.command == "layout-update-session":
            result = _layout_update_session(args)
        else:
            raise RuntimeError("unsupported backend operation")
    except _ProbeError as error:
        result = {
            "schema": "keyferry.rom-probe-error.v1",
            "ready": False,
            "error": {"code": error.code},
        }
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
        return 20
    except (Exception, SystemExit):
        result = {
            "schema": "keyferry.rom-probe-error.v1",
            "ready": False,
            "error": {"code": "firmware.rom_probe_failed"},
        }
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
        return 20
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
