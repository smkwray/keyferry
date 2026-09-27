"""Inspect an unflashed ESP32-S3 MSC compile probe, not a release image."""

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys


APP_SLOT_BYTES = 0x100000
MIN_HEADROOM_BYTES = 0x8000
PROJECT = Path(__file__).resolve().parents[1]
IDF_PARTITION_PARSER = (
    PROJECT / ".tools/esp-idf-v6.0.3/components/partition_table/gen_esp32part.py"
)
OLD_CSV = PROJECT / "firmware/esp32s3/hil_endpoint/partitions.csv"
MEMORY_CSV = (
    PROJECT / "firmware/esp32s3/hil_endpoint/spikes/partitions.msc-memory.csv"
)
MEMORY_CONFIG_NAME = "spikes/partitions.msc-memory.csv"
HIL_CMAKE = PROJECT / "firmware/esp32s3/hil_endpoint/CMakeLists.txt"
OLD_LAYOUT = (
    ("factory", 0, 0, 0x10000, 0x100000),
    ("kf_cfg_a", 1, 0x40, 0x110000, 0x4000),
    ("kf_cfg_b", 1, 0x41, 0x114000, 0x4000),
    ("nvs", 1, 2, 0x118000, 0x3000),
)
MEMORY_LAYOUT = OLD_LAYOUT[1:] + (("factory", 0, 0, 0x120000, 0x200000),)


def bounded_file(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise SystemExit(f"absent, oversized or linked review artifact: {path.name}")
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    if not data or len(data) > maximum:
        raise SystemExit(f"invalid review artifact length: {path.name}")
    return data


def review_json(path: Path) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result
    try:
        value = json.loads(bounded_file(path, 65536), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as error:
        raise SystemExit(f"invalid review JSON: {path.name}") from error
    if not isinstance(value, dict):
        raise SystemExit(f"review JSON is not an object: {path.name}")
    return value


def retained_bootloader_compatible(installed: bytes, candidate: bytes) -> None:
    # Use the pinned image parser/checksum implementation, not a second ESP parser.
    environments = PROJECT / ".tools/idf-tools-v6.0.3/python_env"
    sites = list(environments.glob("*/Lib/site-packages")) + list(
        environments.glob("*/lib/python*/site-packages")
    )
    if len(sites) != 1:
        raise SystemExit("one pinned ESP-IDF Python environment is required")
    sys.path.insert(0, str(sites[0]))
    try:
        import esptool
        from esptool.bin_image import ESP32S3FirmwareImage
        if esptool.__version__ != "5.4.0" or not Path(esptool.__file__).resolve().is_relative_to(sites[0].resolve()):
            raise SystemExit("bootloader parser is not the pinned esptool")
        normalized = []
        for data in (installed, candidate):
            image = ESP32S3FirmwareImage(io.BytesIO(data))
            if (not image.append_digest or image.data_length is None
                    or image.data_length + 32 != len(data)
                    or image.stored_digest != image.calc_digest
                    or image.checksum != image.calculate_checksum()
                    or image.chip_id != image.ROM_LOADER.IMAGE_CHIP_ID
                    or data[2:4] != bytes([2, 0x4F])
                    or data[32] != 80):
                raise ValueError("invalid pinned S3 bootloader")
            # esp_bootloader_desc_t starts after the 24-byte image and 8-byte
            # segment headers. Only its idf_ver[32] field may differ. In these
            # builds export-script edits add '-dirty'; executable bytes may not.
            if data[40:72] not in (
                b"v6.0.3".ljust(32, b"\0"), b"v6.0.3-dirty".ljust(32, b"\0")
            ):
                raise ValueError("unrecognized bootloader IDF version")
            code = bytearray(data[:image.data_length - 1])
            code[40:72] = bytes(32)
            normalized.append(code)
        if normalized[0] != normalized[1]:
            raise ValueError("retained bootloader differs outside version metadata")
    except Exception as error:
        raise SystemExit("retained bootloader compatibility check failed") from error
    finally:
        sys.path.pop(0)


def inspect_backup(build: Path, backup: Path, package: Path, unit_record: Path) -> None:
    """Bind an existing verified private capture; this does not authorize a write."""
    receipt = review_json(backup / "receipt.json")
    manifest = review_json(package / "manifest.json")
    record = review_json(unit_record)
    try:
        if (receipt["schema"] != "keyferry.firmware-backup-result.v1"
                or receipt["outcome"] != "READ_VERIFIED"
                or receipt["unit_record_sha256"] != sha256(unit_record)
                or receipt["package_manifest_sha256"] != sha256(package / "manifest.json")
                or re.fullmatch(r"[0-9a-f]{64}", receipt["unit_binding_sha256"]) is None
                or receipt["efuse_sha256"] != record["efuse_sha256"]
                or record["schema"] != "keyferry.exact-unit-record.v1"
                or record["flash_size_bytes"] != 0x1000000
                or manifest["target"]["flash_size_bytes"] != 0x1000000
                or manifest["write"] != {"offset": 0x10000, "partition_size_bytes": APP_SLOT_BYTES}):
            raise ValueError("capture binding mismatch")
        profile = manifest["target"]["board_profile"]
        cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
        if not re.search(rf"^KEYFERRY_BOARD:STRING={re.escape(profile)}$", cache, re.MULTILINE):
            raise ValueError("capture belongs to a different board profile")
        image = manifest["image"]
        preserved = manifest["preserved"]
        assets = (
            ("board-manifest.toml", manifest["target"]["board_manifest_sha256"], 65536),
            ("partitions.csv", manifest["target"]["partition_map_sha256"], 65536),
            ("keyferry_hil_endpoint.bin", image["sha256"], APP_SLOT_BYTES),
            ("keyferry_hil_endpoint.elf", image["elf_sha256"], 32 * 1024 * 1024),
            ("bootloader.bin", preserved["bootloader_sha256"], 65536),
            ("partition-table.bin", preserved["partition_table_sha256"], 4096),
        )
        for name, expected, limit in assets:
            if hashlib.sha256(bounded_file(package / name, limit)).hexdigest() != expected:
                raise ValueError("rollback package artifact changed")
        if sha256(package / "partitions.csv") != sha256(OLD_CSV):
            raise ValueError("rollback package uses another partition map")
        snapshot = receipt["snapshot"]
        if (snapshot["file"] != "full-flash.bin" or snapshot["size_bytes"] != 0x1000000
                or snapshot["passes_equal"] is not True):
            raise ValueError("capture did not complete two full reads")
        data = bounded_file(backup / "full-flash.bin", 0x1000000)
        if len(data) != 0x1000000 or hashlib.sha256(data).hexdigest() != snapshot["sha256"]:
            raise ValueError("snapshot size or digest differs")
        old_app = bounded_file(package / "keyferry_hil_endpoint.bin", APP_SLOT_BYTES)
        old_boot = bounded_file(package / "bootloader.bin", 65536)
        old_table = bounded_file(package / "partition-table.bin", 4096)
        expected_app = {"offset": 0x10000, "size_bytes": len(old_app), "sha256": image["sha256"]}
        if (receipt["installed_application"] != expected_app
                or data[0x10000:0x10000 + len(old_app)] != old_app
                or data[:len(old_boot)] != old_boot
                or data[0x8000:0x8000 + len(old_table)] != old_table
                or receipt["bootloader_sha256"] != preserved["bootloader_sha256"]
                or receipt["partition_table_sha256"] != preserved["partition_table_sha256"]):
            raise ValueError("snapshot is not the bound installed image/table")
        new_boot = bounded_file(build / "bootloader/bootloader.bin", 65536)
        retained_bootloader_compatible(old_boot, new_boot)
        new_app = bounded_file(build / "keyferry_hil_endpoint.bin", 0x200000)
        if old_app[:24] != new_app[:24]:
            raise ValueError("candidate app header differs from the installed app")
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit("backup does not match the candidate and rollback inputs") from error
    factory = MEMORY_LAYOUT[-1]
    stage_start, stage_size = factory[3:5]
    footprint = (len(new_app) + 4095) // 4096 * 4096
    print("MSC_BACKUP_REVIEW non_authorizing=1 source_binding=PASS "
          "migration_gate=OPEN physical_boot_gate=OPEN "
          "retained_bootloader_code_equal=1 bootloader_write=0 "
          f"staging_offset={stage_start:#x} erase_footprint_bytes={footprint}")
    # Include the full old sector: a generated 3072-byte table is insufficient.
    for label, offset, length in (
        ("boot_prefix", 0, 0x8000), ("old_table_sector", 0x8000, 0x1000),
        ("preserved_after_table", 0x9000, stage_start - 0x9000),
        ("old_app_slot", 0x10000, APP_SLOT_BYTES),
        ("configuration_nvs", 0x110000, 0xB000),
        ("staging_slot", stage_start, stage_size),
    ):
        region = data[offset:offset + length]
        all_ff = int(region == bytes([255]) * length)
        print(f"MSC_BACKUP_REGION {label} offset={offset:#x} bytes={length} "
              f"sha256={hashlib.sha256(region).hexdigest()} "
              f"all_ff={all_ff}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def app_version(path: Path) -> bytes:
    image = path.read_bytes()
    if not image:
        raise SystemExit("firmware image is empty")
    magic = (0xABCD5432).to_bytes(4, "little")
    if image.count(magic) != 1:
        raise SystemExit("firmware image lacks a unique ESP app descriptor")
    offset = image.index(magic)
    if len(image) - offset < 256:
        raise SystemExit("firmware image has a truncated ESP app descriptor")
    project = image[offset + 48 : offset + 80].split(b"\x00", 1)[0]
    if project != b"keyferry_hil_endpoint":
        raise SystemExit("firmware image has a different app project")
    return image[offset + 16 : offset + 48].split(b"\x00", 1)[0]


def file_handoff_version(cmake: Path = HIL_CMAKE) -> bytes:
    source = cmake.read_text(encoding="utf-8")
    versions = re.findall(
        r'^if\(KEYFERRY_FILE_HANDOFF\)\s*\n'
        r'\s*set\(PROJECT_VER "([0-9]+\.[0-9]+\.[0-9]+-file\.[0-9]+)"\)\s*\n'
        r'endif\(\)$', source, re.MULTILINE,
    )
    if len(versions) != 1:
        raise SystemExit("USB file firmware version is not defined once in production CMake")
    return versions[0].encode("ascii")


def partition_parser():
    if not IDF_PARTITION_PARSER.is_file():
        raise SystemExit("pinned ESP-IDF partition parser is absent")
    spec = importlib.util.spec_from_file_location("keyferry_pinned_partitions", IDF_PARTITION_PARSER)
    if spec is None or spec.loader is None:
        raise SystemExit("pinned ESP-IDF partition parser cannot be loaded")
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    parser.offset_part_table = 0x8000
    return parser


def checked_table(parser, csv_path: Path, built_path: Path, expected: tuple):
    try:
        table = parser.PartitionTable.from_csv(csv_path.read_text(encoding="utf-8"))
        table.verify()
        table.verify_size_fits(0x1000000)
        rows = tuple(
            (part.name, part.type, part.subtype, part.offset, part.size)
            for part in table
        )
        if rows != expected or any(part.encrypted or part.readonly for part in table):
            raise SystemExit(f"partition layout differs from protected contract: {csv_path.name}")
        generated = table.to_binary()
        built = built_path.read_bytes()
        parsed = parser.PartitionTable.from_binary(built)
        parsed.verify()
    except (OSError, UnicodeError, parser.InputError, ValueError) as error:
        raise SystemExit(f"invalid partition artifact {csv_path.name}: {error}") from error
    if built != generated or parsed.to_binary() != generated:
        raise SystemExit(f"built partition table differs from source CSV: {csv_path.name}")
    return table


def check_flash_files(build: Path, app_offset: str) -> None:
    try:
        args = json.loads((build / "flasher_args.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"invalid flasher arguments: {error}") from error
    if not isinstance(args, dict):
        raise SystemExit("flasher arguments are not an object")
    expected = {
        "0x0": "bootloader/bootloader.bin",
        "0x8000": "partition_table/partition-table.bin",
        app_offset: "keyferry_hil_endpoint.bin",
    }
    app = args.get("app")
    partition = args.get("partition-table")
    bootloader = args.get("bootloader")
    settings = args.get("flash_settings")
    esptool = args.get("extra_esptool_args")
    if args.get("flash_files") != expected or not isinstance(app, dict) or app.get("offset") != app_offset:
        raise SystemExit("generated flash offsets differ from the reviewed layout")
    if (not isinstance(partition, dict) or partition.get("offset") != "0x8000"
            or not isinstance(bootloader, dict) or bootloader.get("offset") != "0x0"):
        raise SystemExit("generated bootloader or table offset differs from reviewed layout")
    if (not isinstance(settings, dict) or settings.get("flash_size") != "16MB"
            or not isinstance(esptool, dict) or esptool.get("chip") != "esp32s3"):
        raise SystemExit("generated flash size differs from declared 16 MiB boards")


def inspect_memory_layout(build: Path, baseline: Path, config: str, cache: str,
                          image_bytes: int) -> None:
    required = (
        baseline / "sdkconfig", baseline / "CMakeCache.txt",
        baseline / "keyferry_hil_endpoint.bin",
        baseline / "keyferry_hil_endpoint.map",
        baseline / "partition_table/partition-table.bin",
        baseline / "bootloader/bootloader.bin", baseline / "flasher_args.json",
        build / "partition_table/partition-table.bin",
        build / "bootloader/bootloader.bin", build / "flasher_args.json",
        build / "keyferry_hil_endpoint.elf",
    )
    for path in required:
        if not path.is_file():
            raise SystemExit(f"required memory-probe artifact is absent: {path}")
    if not re.search(r"^KEYFERRY_MSC_MEMORY_PROBE:BOOL=ON$", cache, re.MULTILINE):
        raise SystemExit("memory probe flag was not enabled")
    baseline_map = (baseline / "keyferry_hil_endpoint.map").read_text(
        encoding="utf-8", errors="replace"
    )
    if any(symbol in baseline_map for symbol in (
        "MscMemoryProbeTask", "MscMemoryProbeAllocate",
        "PublishMscProbeStatus", "CopyMscProbeStatus", "g_msc_probe_status",
    )):
        raise SystemExit("ordinary baseline links memory-probe code")
    map_text = (build / "keyferry_hil_endpoint.map").read_text(
        encoding="utf-8", errors="replace"
    )
    for symbol in ("MscMemoryProbeTask", "MscMemoryProbeAllocate"):
        if not re.search(
            rf"\.text\.[^\r\n]*{symbol}[^\r\n]*\r?\n"
            r"\s*0x[1-9a-fA-F][0-9a-fA-F]*\s+0x[1-9a-fA-F][0-9a-fA-F]*\s+"
            r"esp-idf/main/libmain\.a\(app_main\.cpp\.obj\)",
            map_text,
        ):
            raise SystemExit(f"linked memory probe {symbol} is absent")
    for key in ("CONFIG_PARTITION_TABLE_FILENAME", "CONFIG_PARTITION_TABLE_CUSTOM_FILENAME"):
        if not re.search(rf'^{key}="{re.escape(MEMORY_CONFIG_NAME)}"$', config, re.MULTILINE):
            raise SystemExit(f"memory probe selected a different partition CSV: {key}")
    baseline_config = (baseline / "sdkconfig").read_text(encoding="utf-8")
    if not re.search(r"^# CONFIG_TINYUSB_MSC_ENABLED is not set$", baseline_config, re.MULTILINE):
        raise SystemExit("baseline is not the non-MSC production configuration")
    if not re.search(r'^CONFIG_PARTITION_TABLE_FILENAME="partitions.csv"$', baseline_config, re.MULTILINE):
        raise SystemExit("baseline selected a different partition CSV")
    for resolved in (config, baseline_config):
        for required in (
            'CONFIG_IDF_TARGET="esp32s3"',
            'CONFIG_ESPTOOLPY_FLASHSIZE="16MB"',
            'CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y',
        ):
            if not re.search(rf"^{re.escape(required)}$", resolved, re.MULTILINE):
                raise SystemExit(f"build differs from ESP32-S3/16 MiB geometry: {required}")
    baseline_cache = (baseline / "CMakeCache.txt").read_text(encoding="utf-8")
    if re.search(r"^KEYFERRY_MSC_(SIZE|MEMORY)_PROBE:BOOL=ON$", baseline_cache, re.MULTILINE):
        raise SystemExit("baseline is another probe")
    board_pattern = r"^KEYFERRY_BOARD:STRING=([a-z0-9_]+)$"
    baseline_board = re.search(board_pattern, baseline_cache, re.MULTILINE)
    candidate_board = re.search(board_pattern, cache, re.MULTILINE)
    if (baseline_board is None or candidate_board is None
            or baseline_board.group(1) != candidate_board.group(1)
            or baseline_board.group(1) not in {
                "waveshare_geek_v1_1_reference", "lilygo_t_dongle_s3"
            }):
        raise SystemExit("baseline and candidate board profiles differ")
    parser = partition_parser()
    checked_table(parser, OLD_CSV, baseline / "partition_table/partition-table.bin", OLD_LAYOUT)
    candidate_table = checked_table(
        parser, MEMORY_CSV, build / "partition_table/partition-table.bin", MEMORY_LAYOUT
    )
    table_bytes = (build / "partition_table/partition-table.bin").read_bytes()
    if len(table_bytes) != 0xC00:
        raise SystemExit("candidate partition table is not the pinned 0xC00-byte format")
    table_sector = table_bytes + b"\xff" * (0x1000 - len(table_bytes))
    check_flash_files(baseline, "0x10000")
    check_flash_files(build, "0x120000")
    old_boot = baseline / "bootloader/bootloader.bin"
    new_boot = build / "bootloader/bootloader.bin"
    if sha256(old_boot) != sha256(new_boot):
        raise SystemExit("candidate bootloader differs from baseline")
    baseline_image = baseline / "keyferry_hil_endpoint.bin"
    if app_version(baseline_image) != b"0.1.0":
        raise SystemExit("baseline is not the ordinary release app image")
    baseline_bytes = baseline_image.stat().st_size
    if baseline_bytes > APP_SLOT_BYTES - MIN_HEADROOM_BYTES:
        raise SystemExit("baseline fails the existing 32 KiB app reserve")
    factory = candidate_table.find_by_name("factory")
    slot = factory.size
    headroom = slot - image_bytes
    print(
        "MSC_MEMORY_LAYOUT_REVIEW non_authorizing=1 "
        f"factory_offset={factory.offset:#x} factory_bytes={slot} "
        f"factory_end={factory.offset + slot:#x} "
        "table_sector_offset=0x8000 table_sector_bytes=4096 "
        "preserve_range=0x9000..0x120000 old_live_sector_backup_required=1 "
        f"image_bytes={image_bytes} headroom_bytes={headroom} "
        f"reserved_bytes={MIN_HEADROOM_BYTES} "
        f"gate={'PASS' if headroom >= MIN_HEADROOM_BYTES else 'FAIL'}"
    )
    print(
        "MSC_MEMORY_ARTIFACT candidate_table_sector_padded "
        f"sha256={hashlib.sha256(table_sector).hexdigest()}"
    )
    for label, path in (
        ("baseline_image", baseline_image),
        ("baseline_map", baseline / "keyferry_hil_endpoint.map"),
        ("candidate_image", build / "keyferry_hil_endpoint.bin"),
        ("candidate_elf", build / "keyferry_hil_endpoint.elf"),
        ("candidate_map", build / "keyferry_hil_endpoint.map"),
        ("candidate_sdkconfig", build / "sdkconfig"),
        ("bootloader", new_boot),
        ("old_csv", OLD_CSV),
        ("old_table", baseline / "partition_table/partition-table.bin"),
        ("candidate_csv", MEMORY_CSV),
        ("candidate_table", build / "partition_table/partition-table.bin"),
    ):
        print(f"MSC_MEMORY_ARTIFACT {label} sha256={sha256(path)}")
    if headroom < MIN_HEADROOM_BYTES:
        raise SystemExit("memory probe exceeds the 32 KiB candidate app headroom gate")


def inspect_file_handoff(build: Path) -> None:
    config = (build / "sdkconfig").read_text(encoding="utf-8")
    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    if (not re.search(r"^KEYFERRY_FILE_HANDOFF:BOOL=ON$", cache, re.MULTILINE)
            or not re.search(r"^CONFIG_TINYUSB_MSC_ENABLED=y$", config, re.MULTILINE)
            or re.search(r"^KEYFERRY_MSC_(SIZE|MEMORY)_PROBE:BOOL=ON$", cache, re.MULTILINE)):
        raise SystemExit("build is not the USB file firmware")
    image = build / "keyferry_hil_endpoint.bin"
    if app_version(image) != file_handoff_version():
        raise SystemExit("USB file firmware has an unexpected version")
    parser = partition_parser()
    checked_table(parser, MEMORY_CSV, build / "partition_table/partition-table.bin", MEMORY_LAYOUT)
    check_flash_files(build, "0x120000")
    headroom = MEMORY_LAYOUT[-1][4] - image.stat().st_size
    if headroom < MIN_HEADROOM_BYTES:
        raise SystemExit("USB file firmware fails the app reserve")
    linked = (build / "keyferry_hil_endpoint.map").read_text(encoding="utf-8", errors="replace")
    if "msc_device.c.obj" not in linked or "file_handoff.cpp.obj" not in linked:
        raise SystemExit("USB file backend is not linked")
    if any(adapter in linked for adapter in (
        "tinyusb_msc.c.obj", "storage_spiflash.c.obj", "storage_sdmmc.c.obj"
    )):
        raise SystemExit("persistent MSC storage adapter linked")
    print(f"USB_FILE_BUILD image_bytes={image.stat().st_size} headroom_bytes={headroom} "
          f"sha256={sha256(image)} physical_gate=OPEN")


def inspect(build: Path, baseline: Path | None = None,
            backup: Path | None = None, package: Path | None = None,
            unit_record: Path | None = None) -> None:
    selected = (backup is not None, package is not None, unit_record is not None)
    if any(selected) and (not all(selected) or baseline is None):
        raise SystemExit("backup review needs matching baseline, backup, rollback package and unit record")
    config = (build / "sdkconfig").read_text(encoding="utf-8")
    if not re.search(r"^CONFIG_TINYUSB_MSC_ENABLED=y$", config, re.MULTILINE):
        raise SystemExit("MSC core was not enabled in this build")
    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    if not re.search(r"^KEYFERRY_MSC_SIZE_PROBE:BOOL=ON$", cache, re.MULTILINE):
        raise SystemExit("MSC size probe flag was not enabled")
    if baseline is None and re.search(
        r"^KEYFERRY_MSC_MEMORY_PROBE:BOOL=ON$", cache, re.MULTILINE
    ):
        raise SystemExit("memory probe requires baseline comparison")
    binary = build / "keyferry_hil_endpoint.bin"
    image_bytes = binary.stat().st_size
    if image_bytes == 0:
        raise SystemExit("MSC size probe binary is empty")
    version = app_version(binary)
    expected_version = b"0.0.0-probe.mem" if baseline is not None else b"msc-size-probe"
    if version != expected_version:
        raise SystemExit("probe image lacks the non-release app version marker")
    map_text = (build / "keyferry_hil_endpoint.map").read_text(
        encoding="utf-8", errors="replace"
    )
    if "msc_device.c.obj" not in map_text:
        raise SystemExit("TinyUSB MSC class was not linked")
    for symbol in ("mscd_open", "tud_msc_is_writable_cb", "tud_msc_test_unit_ready_cb"):
        if not re.search(rf"^\s*0x[0-9a-fA-F]+\s+{symbol}$", map_text, re.MULTILINE):
            raise SystemExit(f"live MSC symbol is missing: {symbol}")
    if not re.search(
        r"^tud_msc_is_writable_cb\s+esp-idf/main/libmain\.a\(app_main\.cpp\.obj\)$",
        map_text,
        re.MULTILINE,
    ):
        raise SystemExit("read-only callback does not come from application code")
    # The managed component's flash/SD adapter is unsuitable for a volatile
    # synthetic volume and would invalidate this size experiment.
    for unwanted in ("tinyusb_msc.c.obj", "storage_spiflash.c.obj", "storage_sdmmc.c.obj"):
        if unwanted in map_text:
            raise SystemExit(f"storage adapter unexpectedly linked: {unwanted}")
    if baseline is not None:
        inspect_memory_layout(build, baseline, config, cache, image_bytes)
        if backup is not None:
            inspect_backup(build, backup, package, unit_record)
        return
    headroom = APP_SLOT_BYTES - image_bytes
    print(
        f"MSC_SIZE_PROBE image_bytes={image_bytes} "
        f"app_slot_bytes={APP_SLOT_BYTES} headroom_bytes={headroom} "
        f"reserved_bytes={MIN_HEADROOM_BYTES} "
        f"gate={'PASS' if headroom >= MIN_HEADROOM_BYTES else 'FAIL'}"
    )
    if headroom < MIN_HEADROOM_BYTES:
        raise SystemExit("MSC size probe exceeds the 32 KiB app headroom gate")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--baseline-dir", type=Path)
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--rollback-package", type=Path)
    parser.add_argument("--unit-record", type=Path)
    parser.add_argument("--file-handoff", action="store_true")
    arguments = parser.parse_args()
    if arguments.file_handoff:
        inspect_file_handoff(arguments.build_dir)
    else:
        inspect(arguments.build_dir, arguments.baseline_dir, arguments.backup_dir,
                arguments.rollback_package, arguments.unit_record)
