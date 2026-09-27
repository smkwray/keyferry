import contextlib
import hashlib
import importlib.util
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_msc_size_probe.py"
SPEC = importlib.util.spec_from_file_location("check_msc_size_probe", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def synthetic_bootloader(version=b"v6.0.3", code_byte=0xA5):
    """One pinned-parser-readable S3 image, with a real checksum and digest."""
    header = bytes.fromhex("e901024f04893c40ee000000090000000063000000000001")
    segment = bytearray([code_byte] * 128)
    segment[0] = 80  # esp_bootloader_desc_t magic
    segment[8:40] = version.ljust(32, b"\0")
    image = bytearray(header + struct.pack("<II", 0x3FC90000, len(segment)) + segment)
    checksum = 0xEF
    for byte in segment:
        checksum ^= byte
    image.extend(bytes(15))
    image.append(checksum)
    image.extend(hashlib.sha256(image).digest())
    return bytes(image)


class MscSizeProbeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.build = Path(self.directory.name)
        (self.build / "sdkconfig").write_text("CONFIG_TINYUSB_MSC_ENABLED=y\n")
        (self.build / "CMakeCache.txt").write_text("KEYFERRY_MSC_SIZE_PROBE:BOOL=ON\n")
        self.map = self.build / "keyferry_hil_endpoint.map"
        self.valid_map = (
            "libtinyusb.a(msc_device.c.obj)\n"
            " 0x42000010 mscd_open\n"
            " 0x42000020 tud_msc_is_writable_cb\n"
            " 0x42000030 tud_msc_test_unit_ready_cb\n"
            "tud_msc_is_writable_cb esp-idf/main/libmain.a(app_main.cpp.obj)\n"
        )
        self.map.write_text(self.valid_map)
        self.binary = self.build / "keyferry_hil_endpoint.bin"
        image = bytearray(0x100000 - 0x8000)
        image[32:36] = (0xABCD5432).to_bytes(4, "little")
        image[48:62] = b"msc-size-probe"
        image[80:101] = b"keyferry_hil_endpoint"
        self.binary.write_bytes(image)
        self.output = io.StringIO()
        self.fixture_no = 0

    def inspect(self):
        with contextlib.redirect_stdout(self.output):
            MODULE.inspect(self.build)

    def test_exact_reserve_is_accepted(self):
        self.inspect()
        self.assertIn("headroom_bytes=32768", self.output.getvalue())
        self.assertIn("gate=PASS", self.output.getvalue())

    def test_one_byte_below_reserve_fails_even_though_image_fits(self):
        with self.binary.open("ab") as output:
            output.write(b"\0")
        with self.assertRaises(SystemExit):
            self.inspect()
        self.assertIn("gate=FAIL", self.output.getvalue())
        self.assertNotIn("gate=PASS", self.output.getvalue())

    def test_empty_binary_is_not_a_resource_pass(self):
        self.binary.write_bytes(b"")
        with self.assertRaises(SystemExit):
            self.inspect()
        self.assertNotIn("gate=PASS", self.output.getvalue())

    def test_unqualified_marker_must_be_the_app_version(self):
        image = bytearray(self.binary.read_bytes())
        image[48:80] = b"0.1.0".ljust(32, b"\0")
        image[1024:1038] = b"msc-size-probe"
        self.binary.write_bytes(image)
        with self.assertRaises(SystemExit):
            self.inspect()

    def test_file_handoff_version_follows_single_production_cmake_definition(self):
        cmake = self.build / "CMakeLists.txt"
        cmake.write_text('if(KEYFERRY_FILE_HANDOFF)\n    set(PROJECT_VER "0.2.0-file.9")\nendif()\n')
        self.assertEqual(MODULE.file_handoff_version(cmake), b"0.2.0-file.9")
        cmake.write_text(cmake.read_text() * 2)
        with self.assertRaisesRegex(SystemExit, "defined once"):
            MODULE.file_handoff_version(cmake)

    def test_file_handoff_inspection_rejects_previous_image_version(self):
        (self.build / "CMakeCache.txt").write_text("KEYFERRY_FILE_HANDOFF:BOOL=ON\n")
        self.assertNotEqual(MODULE.file_handoff_version(), b"0.2.0-file.1")
        image = bytearray(self.binary.read_bytes())
        image[48:80] = b"0.2.0-file.1".ljust(32, b"\0")
        self.binary.write_bytes(image)
        with self.assertRaisesRegex(SystemExit, "unexpected version"):
            MODULE.inspect_file_handoff(self.build)

    def test_storage_adapters_invalidate_synthetic_probe(self):
        for adapter in ("tinyusb_msc.c.obj", "storage_spiflash.c.obj", "storage_sdmmc.c.obj"):
            with self.subTest(adapter=adapter):
                self.map.write_text(f"{self.valid_map}{adapter}\n")
                with self.assertRaisesRegex(SystemExit, "storage adapter"):
                    self.inspect()

    def test_image_without_msc_cannot_claim_msc_cost(self):
        self.map.write_text("libtinyusb.a(hid_device.c.obj)\n")
        with self.assertRaises(SystemExit):
            self.inspect()

    def test_discarded_core_cannot_claim_msc_cost(self):
        self.map.write_text("Discarded input sections\nlibtinyusb.a(msc_device.c.obj)\n")
        with self.assertRaisesRegex(SystemExit, "live MSC symbol"):
            self.inspect()

    def test_weak_library_writable_callback_is_rejected(self):
        self.map.write_text(self.valid_map.replace(
            "esp-idf/main/libmain.a(app_main.cpp.obj)",
            "esp-idf/espressif__tinyusb/libespressif__tinyusb.a(msc_device.c.obj)"
        ))
        with self.assertRaisesRegex(SystemExit, "read-only callback"):
            self.inspect()

    def test_disabled_or_commented_msc_is_rejected(self):
        for value in ("# CONFIG_TINYUSB_MSC_ENABLED is not set\n",
                      "# CONFIG_TINYUSB_MSC_ENABLED=y\n"):
            with self.subTest(value=value):
                (self.build / "sdkconfig").write_text(value)
                with self.assertRaises(SystemExit):
                    self.inspect()

    def test_production_build_is_not_a_probe(self):
        (self.build / "CMakeCache.txt").write_text("KEYFERRY_MSC_SIZE_PROBE:BOOL=OFF\n")
        with self.assertRaises(SystemExit):
            self.inspect()

    def memory_fixture(self):
        if not MODULE.IDF_PARTITION_PARSER.is_file():
            self.skipTest("pinned ESP-IDF partition parser is absent")
        self.fixture_no += 1
        self.baseline = self.build / f"baseline-{self.fixture_no}"
        self.baseline.mkdir()
        memory = self.build / f"memory-{self.fixture_no}"
        memory.mkdir()
        for name in ("sdkconfig", "CMakeCache.txt", "keyferry_hil_endpoint.map",
                     "keyferry_hil_endpoint.bin"):
            (memory / name).write_bytes((self.build / name).read_bytes())
        (memory / "keyferry_hil_endpoint.elf").write_bytes(b"synthetic linked memory probe")
        with (memory / "keyferry_hil_endpoint.map").open("a") as output:
            output.write(
                " .text._ZN12_GLOBAL__N_1L18MscMemoryProbeTaskEPv\n"
                "                0x4200d4c4       0x15 "
                "esp-idf/main/libmain.a(app_main.cpp.obj)\n"
                " .text._ZN12_GLOBAL__N_1L22MscMemoryProbeAllocateEPv\n"
                "                0x4200d4e0       0x15 "
                "esp-idf/main/libmain.a(app_main.cpp.obj)\n"
            )
        (memory / "sdkconfig").write_text(
            "CONFIG_TINYUSB_MSC_ENABLED=y\n"
            'CONFIG_PARTITION_TABLE_FILENAME="spikes/partitions.msc-memory.csv"\n'
            'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="spikes/partitions.msc-memory.csv"\n'
            'CONFIG_IDF_TARGET="esp32s3"\n'
            'CONFIG_ESPTOOLPY_FLASHSIZE="16MB"\n'
            'CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y\n'
        )
        (memory / "CMakeCache.txt").write_text(
            "KEYFERRY_MSC_SIZE_PROBE:BOOL=ON\n"
            "KEYFERRY_MSC_MEMORY_PROBE:BOOL=ON\n"
            "KEYFERRY_BOARD:STRING=waveshare_geek_v1_1_reference\n"
        )
        image = bytearray((memory / "keyferry_hil_endpoint.bin").read_bytes())
        image[48:80] = b"0.0.0-probe.mem".ljust(32, b"\0")
        (memory / "keyferry_hil_endpoint.bin").write_bytes(image)
        (self.baseline / "sdkconfig").write_text(
            "# CONFIG_TINYUSB_MSC_ENABLED is not set\n"
            'CONFIG_PARTITION_TABLE_FILENAME="partitions.csv"\n'
            'CONFIG_IDF_TARGET="esp32s3"\n'
            'CONFIG_ESPTOOLPY_FLASHSIZE="16MB"\n'
            'CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y\n'
        )
        (self.baseline / "CMakeCache.txt").write_text(
            "KEYFERRY_MSC_SIZE_PROBE:BOOL=OFF\n"
            "KEYFERRY_MSC_MEMORY_PROBE:BOOL=OFF\n"
            "KEYFERRY_BOARD:STRING=waveshare_geek_v1_1_reference\n"
        )
        baseline_image = bytearray(self.binary.read_bytes())
        baseline_image[48:80] = b"0.1.0".ljust(32, b"\0")
        (self.baseline / "keyferry_hil_endpoint.bin").write_bytes(baseline_image)
        (self.baseline / "keyferry_hil_endpoint.map").write_text("ordinary baseline map\n")
        old_csv = self.build / f"partitions-{self.fixture_no}.csv"
        old_csv.write_text(
            "factory, app, factory, 0x10000, 1M,\n"
            "kf_cfg_a, data, 0x40, 0x110000, 0x4000,\n"
            "kf_cfg_b, data, 0x41, 0x114000, 0x4000,\n"
            "nvs, data, nvs, 0x118000, 0x3000,\n"
        )
        self.candidate_csv = self.build / f"partitions.msc-memory-{self.fixture_no}.csv"
        self.candidate_csv.write_text(
            "kf_cfg_a, data, 0x40, 0x110000, 0x4000,\n"
            "kf_cfg_b, data, 0x41, 0x114000, 0x4000,\n"
            "nvs, data, nvs, 0x118000, 0x3000,\n"
            "factory, app, factory, 0x120000, 2M,\n"
        )
        parser = MODULE.partition_parser()
        for directory, csv in ((self.baseline, old_csv), (memory, self.candidate_csv)):
            (directory / "partition_table").mkdir()
            (directory / "partition_table/partition-table.bin").write_bytes(
                parser.PartitionTable.from_csv(csv.read_text()).to_binary()
            )
            (directory / "bootloader").mkdir()
            (directory / "bootloader/bootloader.bin").write_bytes(b"same tested bootloader")
            app_offset = "0x10000" if directory == self.baseline else "0x120000"
            (directory / "flasher_args.json").write_text(json.dumps({
                "flash_files": {
                    "0x0": "bootloader/bootloader.bin",
                    "0x8000": "partition_table/partition-table.bin",
                    app_offset: "keyferry_hil_endpoint.bin",
                },
                "bootloader": {"offset": "0x0"},
                "partition-table": {"offset": "0x8000"},
                "app": {"offset": app_offset},
                "flash_settings": {"flash_size": "16MB"},
                "extra_esptool_args": {"chip": "esp32s3"},
            }))
        self.memory = memory
        self.old_csv_patch = mock.patch.object(MODULE, "OLD_CSV", old_csv)
        self.candidate_csv_patch = mock.patch.object(MODULE, "MEMORY_CSV", self.candidate_csv)
        self.old_csv_patch.start()
        self.candidate_csv_patch.start()
        self.addCleanup(self.old_csv_patch.stop)
        self.addCleanup(self.candidate_csv_patch.stop)

    def inspect_memory(self):
        with contextlib.redirect_stdout(self.output):
            MODULE.inspect(self.memory, self.baseline)

    def test_memory_layout_reports_bound_artifacts_without_authorization(self):
        self.memory_fixture()
        self.inspect_memory()
        report = self.output.getvalue()
        self.assertIn("non_authorizing=1", report)
        self.assertIn("factory_offset=0x120000", report)
        self.assertIn("table_sector_offset=0x8000 table_sector_bytes=4096", report)
        self.assertIn("old_live_sector_backup_required=1", report)
        table = (self.memory / "partition_table/partition-table.bin").read_bytes()
        self.assertEqual(len(table), 0xC00)
        padded_sector = table + b"\xff" * 0x400
        self.assertEqual(len(padded_sector), 0x1000)
        self.assertIn(
            "candidate_table_sector_padded sha256=" + hashlib.sha256(padded_sector).hexdigest(),
            report,
        )
        self.assertIn("candidate_table sha256=", report)
        self.assertIn("gate=PASS", report)

    def test_memory_probe_requires_baseline(self):
        self.memory_fixture()
        with self.assertRaises(SystemExit):
            MODULE.inspect(self.memory)

    def test_memory_layout_rejects_changed_config_and_nvs(self):
        for before, after in (("0x110000", "0x10f000"),
                              ("0x118000", "0x119000")):
            with self.subTest(after=after):
                self.memory_fixture()
                self.candidate_csv.write_text(
                    self.candidate_csv.read_text().replace(before, after)
                )
                with self.assertRaisesRegex(SystemExit, "partition"):
                    self.inspect_memory()

    def test_memory_layout_rejects_app_overlap_and_out_of_flash_range(self):
        for new_offset in ("0x110000", "0xf00000"):
            with self.subTest(offset=new_offset):
                self.memory_fixture()
                self.candidate_csv.write_text(
                    self.candidate_csv.read_text().replace("0x120000", new_offset)
                )
                with self.assertRaisesRegex(SystemExit, "partition"):
                    self.inspect_memory()

    def test_memory_layout_rejects_tampered_built_table(self):
        self.memory_fixture()
        table = self.memory / "partition_table/partition-table.bin"
        data = bytearray(table.read_bytes())
        data[8] ^= 1
        table.write_bytes(data)
        with self.assertRaisesRegex(SystemExit, "partition"):
            self.inspect_memory()

    def test_memory_layout_rejects_changed_bootloader_and_flash_offsets(self):
        self.memory_fixture()
        (self.memory / "bootloader/bootloader.bin").write_bytes(b"changed")
        with self.assertRaisesRegex(SystemExit, "bootloader"):
            self.inspect_memory()
        self.memory_fixture()
        args = self.memory / "flasher_args.json"
        text = args.read_text().replace("0x120000", "0x10000")
        args.write_text(text)
        with self.assertRaisesRegex(SystemExit, "offset"):
            self.inspect_memory()

    def test_memory_layout_rejects_malformed_flasher_arguments(self):
        self.memory_fixture()
        (self.memory / "flasher_args.json").write_text("[]")
        with self.assertRaisesRegex(SystemExit, "flasher arguments are not an object"):
            self.inspect_memory()

    def test_memory_layout_rejects_less_than_32k_reserve(self):
        self.memory_fixture()
        with (self.memory / "keyferry_hil_endpoint.bin").open("ab") as output:
            output.write(b"\0" * (0x200000 - 0x8000 + 1 - self.binary.stat().st_size))
        with self.assertRaisesRegex(SystemExit, "headroom"):
            self.inspect_memory()
        self.assertIn("gate=FAIL", self.output.getvalue())

    def test_memory_layout_rejects_swapped_board_baseline(self):
        self.memory_fixture()
        cache = self.baseline / "CMakeCache.txt"
        cache.write_text(cache.read_text().replace(
            "waveshare_geek_v1_1_reference", "lilygo_t_dongle_s3"
        ))
        with self.assertRaisesRegex(SystemExit, "board"):
            self.inspect_memory()

    def test_memory_layout_rejects_empty_or_probe_baseline(self):
        for replacement in (b"", b"msc-size-probe"):
            with self.subTest(replacement=replacement):
                self.memory_fixture()
                baseline = self.baseline / "keyferry_hil_endpoint.bin"
                if replacement:
                    image = bytearray(baseline.read_bytes())
                    image[48:80] = replacement.ljust(32, b"\0")
                    baseline.write_bytes(image)
                else:
                    baseline.write_bytes(b"")
                with self.assertRaises(SystemExit):
                    self.inspect_memory()

    def test_memory_layout_rejects_wrong_flash_geometry(self):
        self.memory_fixture()
        config = self.memory / "sdkconfig"
        config.write_text(config.read_text().replace(
            'CONFIG_ESPTOOLPY_FLASHSIZE="16MB"',
            'CONFIG_ESPTOOLPY_FLASHSIZE="32MB"',
        ))
        with self.assertRaisesRegex(SystemExit, "geometry"):
            self.inspect_memory()

    def test_memory_layout_rejects_missing_linked_allocation_task(self):
        for symbol in ("MscMemoryProbeTask", "MscMemoryProbeAllocate"):
            with self.subTest(symbol=symbol):
                self.memory_fixture()
                target = self.memory / "keyferry_hil_endpoint.map"
                target.write_text(target.read_text().replace(symbol, "OtherFunction"))
                with self.assertRaisesRegex(SystemExit, symbol):
                    self.inspect_memory()

    def test_memory_layout_rejects_probe_code_in_ordinary_baseline(self):
        self.memory_fixture()
        (self.baseline / "keyferry_hil_endpoint.map").write_text(
            "ordinary baseline map\ng_msc_probe_status\n"
        )
        with self.assertRaisesRegex(SystemExit, "ordinary baseline links"):
            self.inspect_memory()

    def pinned_esptool(self):
        environments = MODULE.PROJECT / ".tools/idf-tools-v6.0.3/python_env"
        sites = list(environments.glob("*/Lib/site-packages")) + list(
            environments.glob("*/lib/python*/site-packages")
        )
        if len(sites) != 1:
            self.skipTest("pinned esptool environment is absent")

    def backup_fixture(self, occupied_stage=False):
        self.memory_fixture()
        self.pinned_esptool()
        boot = synthetic_bootloader()
        candidate_boot = synthetic_bootloader(b"v6.0.3-dirty")
        (self.baseline / "bootloader/bootloader.bin").write_bytes(candidate_boot)
        (self.memory / "bootloader/bootloader.bin").write_bytes(candidate_boot)
        self.package = self.build / f"rollback-{self.fixture_no}"
        self.package.mkdir()
        old_app = (self.baseline / "keyferry_hil_endpoint.bin").read_bytes()
        old_table = (self.baseline / "partition_table/partition-table.bin").read_bytes()
        assets = {
            "board-manifest.toml": b"synthetic board fixture\n",
            "partitions.csv": MODULE.OLD_CSV.read_bytes(),
            "keyferry_hil_endpoint.bin": old_app,
            "keyferry_hil_endpoint.elf": b"synthetic installed elf",
            "bootloader.bin": boot,
            "partition-table.bin": old_table,
        }
        for name, data in assets.items():
            (self.package / name).write_bytes(data)
        digest = lambda data: hashlib.sha256(data).hexdigest()
        manifest = {
            "target": {
                "flash_size_bytes": 0x1000000,
                "board_profile": "waveshare_geek_v1_1_reference",
                "board_manifest_sha256": digest(assets["board-manifest.toml"]),
                "partition_map_sha256": digest(assets["partitions.csv"]),
            },
            "write": {"offset": 0x10000, "partition_size_bytes": 0x100000},
            "image": {"sha256": digest(old_app),
                      "elf_sha256": digest(assets["keyferry_hil_endpoint.elf"])},
            "preserved": {"bootloader_sha256": digest(boot),
                          "partition_table_sha256": digest(old_table)},
        }
        (self.package / "manifest.json").write_text(json.dumps(manifest))
        self.record = self.build / f"unit-{self.fixture_no}.json"
        self.record.write_text(json.dumps({
            "schema": "keyferry.exact-unit-record.v1",
            "flash_size_bytes": 0x1000000,
            "efuse_sha256": "1" * 64,
        }))
        self.backup = self.build / f"backup-{self.fixture_no}"
        self.backup.mkdir()
        flash = bytearray(b"\xff" * 0x1000000)
        flash[:len(boot)] = boot
        flash[0x8000:0x8000 + len(old_table)] = old_table
        flash[0x10000:0x10000 + len(old_app)] = old_app
        if occupied_stage:
            flash[0x120000:0x121000] = b"S" * 0x1000
        (self.backup / "full-flash.bin").write_bytes(flash)
        self.receipt = {
            "schema": "keyferry.firmware-backup-result.v1",
            "outcome": "READ_VERIFIED",
            "unit_record_sha256": MODULE.sha256(self.record),
            "package_manifest_sha256": MODULE.sha256(self.package / "manifest.json"),
            "unit_binding_sha256": "2" * 64,
            "efuse_sha256": "1" * 64,
            "snapshot": {"file": "full-flash.bin", "size_bytes": len(flash),
                         "passes_equal": True, "sha256": digest(flash)},
            "installed_application": {"offset": 0x10000,
                                      "size_bytes": len(old_app),
                                      "sha256": digest(old_app)},
            "bootloader_sha256": digest(boot),
            "partition_table_sha256": digest(old_table),
        }
        self.write_receipt()

    def write_receipt(self):
        (self.backup / "receipt.json").write_text(json.dumps(self.receipt))

    def inspect_bound_backup(self):
        with contextlib.redirect_stdout(self.output):
            MODULE.inspect(self.memory, self.baseline, self.backup,
                           self.package, self.record)

    def test_retained_bootloader_accepts_only_version_metadata_difference(self):
        self.pinned_esptool()
        MODULE.retained_bootloader_compatible(
            synthetic_bootloader(), synthetic_bootloader(b"v6.0.3-dirty")
        )

    def test_retained_bootloader_rejects_rehashed_code_change(self):
        self.pinned_esptool()
        with self.assertRaisesRegex(SystemExit, "compatibility"):
            MODULE.retained_bootloader_compatible(
                synthetic_bootloader(), synthetic_bootloader(b"v6.0.3-dirty", 0xA6)
            )

    def test_retained_bootloader_rejects_bad_digest_or_checksum(self):
        self.pinned_esptool()
        good = synthetic_bootloader()
        for offset in (-1, -33):
            with self.subTest(offset=offset):
                bad = bytearray(good)
                bad[offset] ^= 1
                with self.assertRaisesRegex(SystemExit, "compatibility"):
                    MODULE.retained_bootloader_compatible(good, bytes(bad))

    def test_complete_backup_is_bound_but_not_migration_authority(self):
        self.backup_fixture()
        self.inspect_bound_backup()
        report = self.output.getvalue()
        self.assertIn(
            "MSC_BACKUP_REVIEW non_authorizing=1 source_binding=PASS migration_gate=OPEN",
            report,
        )
        self.assertIn("physical_boot_gate=OPEN", report)
        self.assertIn("MSC_BACKUP_REGION staging_slot", report)
        self.assertIn("all_ff=1", report)

    def test_occupied_staging_is_reported_without_authorizing_migration(self):
        self.backup_fixture(occupied_stage=True)
        self.inspect_bound_backup()
        report = self.output.getvalue()
        self.assertIn("MSC_BACKUP_REGION staging_slot", report)
        self.assertIn("all_ff=0", report)
        self.assertIn("migration_gate=OPEN", report)
        self.assertIn("physical_boot_gate=OPEN", report)

    def test_incomplete_or_misbinding_backup_is_rejected(self):
        for field, value in (
            ("outcome", "PARTIAL"),
            ("unit_binding_sha256", "not-a-digest"),
            ("efuse_sha256", "3" * 64),
        ):
            with self.subTest(field=field):
                self.backup_fixture()
                self.receipt[field] = value
                self.write_receipt()
                with self.assertRaisesRegex(SystemExit, "backup does not match"):
                    self.inspect_bound_backup()

    def test_second_read_and_package_record_bindings_are_required(self):
        for mutation in ("passes_equal", "unit_record_hash", "manifest_hash", "profile"):
            with self.subTest(mutation=mutation):
                self.backup_fixture()
                if mutation == "passes_equal":
                    self.receipt["snapshot"]["passes_equal"] = False
                elif mutation == "unit_record_hash":
                    self.receipt["unit_record_sha256"] = "0" * 64
                elif mutation == "manifest_hash":
                    self.receipt["package_manifest_sha256"] = "0" * 64
                else:
                    cache = self.memory / "CMakeCache.txt"
                    cache.write_text(cache.read_text().replace(
                        "waveshare_geek_v1_1_reference", "lilygo_t_dongle_s3"
                    ))
                self.write_receipt()
                with self.assertRaises(SystemExit):
                    self.inspect_bound_backup()

    def test_tampered_backup_app_table_snapshot_or_package_is_rejected(self):
        for target, offset in (("snapshot", 0x10000), ("snapshot", 0x8000),
                               ("snapshot", 0x120000), ("package", 0)):
            with self.subTest(target=target, offset=offset):
                self.backup_fixture()
                path = (self.backup / "full-flash.bin" if target == "snapshot"
                        else self.package / "bootloader.bin")
                data = bytearray(path.read_bytes())
                data[offset] ^= 1
                path.write_bytes(data)
                with self.assertRaisesRegex(SystemExit, "backup does not match"):
                    self.inspect_bound_backup()

    def test_rehashed_snapshot_cannot_hide_different_installed_app_or_table(self):
        for offset in (0x10000, 0x8000):
            with self.subTest(offset=offset):
                self.backup_fixture()
                path = self.backup / "full-flash.bin"
                data = bytearray(path.read_bytes())
                data[offset] ^= 1
                path.write_bytes(data)
                self.receipt["snapshot"]["sha256"] = hashlib.sha256(data).hexdigest()
                self.write_receipt()
                with self.assertRaisesRegex(SystemExit, "backup does not match"):
                    self.inspect_bound_backup()


if __name__ == "__main__":
    unittest.main()
