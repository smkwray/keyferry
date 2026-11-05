#!/usr/bin/env python3
"""Cross-platform local check entry point."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import build_governor

ROOT = Path(__file__).resolve().parents[1]
CPU_PERCENT, BUILD_JOB_CEILING = build_governor.budget()
BUILD_JOBS = min(BUILD_JOB_CEILING,
                 max(1, int(os.environ.get("CARGO_BUILD_JOBS", str(BUILD_JOB_CEILING)))))


def run(
    command: list[str],
    *,
    required: bool = True,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
) -> bool:
    print("+", subprocess.list2cmdline(command), flush=True)
    try:
        subprocess.run(command, cwd=cwd, check=True, env=env)
        return True
    except FileNotFoundError:
        if required:
            print(f"ERROR: command not found: {command[0]}", file=sys.stderr)
            raise SystemExit(1)
        print(f"SKIP: command not found: {command[0]}")
        return False
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc


def run_cpp_check(compiler: str) -> None:
    with tempfile.TemporaryDirectory(prefix="keyferry-check-") as raw_tmp:
        tmp = Path(raw_tmp)
        checks = [
            (
                "wifi-attempt-diagnostics-test",
                [ROOT / "firmware/common/include",
                 ROOT / "firmware/esp32s3/components/kf_esp_transport/include"],
                [ROOT / "firmware/esp32s3/components/kf_esp_transport/test/wifi_attempt_diagnostics_test.cpp"],
            ),
            (
                "file-handoff-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_file_handoff/include",
                ],
                [
                    ROOT / "firmware/esp32s3/components/kf_file_handoff/src/file_handoff.cpp",
                    ROOT / "firmware/esp32s3/components/kf_file_handoff/test/file_handoff_test.cpp",
                ],
            ),
            (
                "gateway-handoff-test",
                [ROOT / "firmware/common/include"],
                [
                    ROOT / "firmware/common/src/gateway_handoff.cpp",
                    ROOT / "firmware/common/test/gateway_handoff_test.cpp",
                ],
            ),
            (
                "roaming-profile-test",
                [ROOT / "firmware/common/include"],
                [
                    ROOT / "firmware/common/src/roaming_profile.cpp",
                    ROOT / "firmware/common/test/roaming_profile_test.cpp",
                ],
            ),
            (
                "frame-codec-test",
                [ROOT / "firmware/common/include"],
                [
                    ROOT / "firmware/common/src/frame_codec.cpp",
                    ROOT / "firmware/common/test/frame_codec_test.cpp",
                ],
            ),
            (
                "hid-executor-test",
                [ROOT / "firmware/esp32s3/components/kf_hid_core/include"],
                [
                    ROOT / "firmware/esp32s3/components/kf_hid_core/src/hid_executor.cpp",
                    ROOT / "firmware/esp32s3/components/kf_hid_core/test/hid_executor_test.cpp",
                ],
            ),
            (
                "command-executor-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_hid_core/include",
                    ROOT / "firmware/esp32s3/components/kf_command_executor/include",
                ],
                [
                    ROOT / "firmware/esp32s3/components/kf_hid_core/src/hid_executor.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_command_executor/src/command_executor.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_command_executor/src/input_command.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_command_executor/test/command_executor_test.cpp",
                ],
            ),
            (
                "input-command-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_hid_core/include",
                    ROOT / "firmware/esp32s3/components/kf_command_executor/include",
                ],
                [
                    ROOT / "firmware/esp32s3/components/kf_hid_core/src/hid_executor.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_command_executor/src/input_command.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_command_executor/test/input_command_test.cpp",
                ],
            ),
            (
                "secure-endpoint-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_secure_endpoint/include",
                    ROOT / "firmware/esp32s3/components/kf_hid_core/include",
                    ROOT / "firmware/esp32s3/components/kf_command_executor/include",
                ],
                [
                    ROOT / "firmware/common/src/frame_codec.cpp",
                    ROOT / "firmware/common/src/gateway_handoff.cpp",
                    ROOT / "firmware/esp32s3/components/kf_secure_endpoint/src/secure_endpoint.cpp",
                    ROOT / "firmware/esp32s3/components/kf_hid_core/src/hid_executor.cpp",
                    ROOT / "firmware/esp32s3/components/kf_command_executor/src/command_executor.cpp",
                    ROOT / "firmware/esp32s3/components/kf_command_executor/src/input_command.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_secure_endpoint/test/secure_endpoint_test.cpp",
                ],
            ),
            (
                "transport-policy-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_secure_endpoint/include",
                    ROOT / "firmware/esp32s3/components/kf_esp_transport/include",
                    ROOT / "firmware/esp32s3/components/kf_config_store/include",
                ],
                [
                    ROOT / "firmware/common/src/frame_codec.cpp",
                    ROOT / "firmware/common/src/roaming_profile.cpp",
                    ROOT / "firmware/common/src/gateway_handoff.cpp",
                    ROOT / "firmware/esp32s3/components/kf_secure_endpoint/src/secure_endpoint.cpp",
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/config_store.cpp",
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/recovery_anchor.cpp",
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/roaming_config.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_esp_transport/src/transport_policy.cpp",
                    ROOT / "firmware/esp32s3/components/kf_esp_transport/src/transport_arbiter.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_esp_transport/test/transport_policy_test.cpp",
                ],
            ),
            (
                "transport-arbiter-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_esp_transport/include",
                ],
                [
                    ROOT
                    / "firmware/esp32s3/components/kf_esp_transport/src/transport_arbiter.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_esp_transport/test/transport_arbiter_test.cpp",
                ],
            ),
            (
                "gateway-handoff-manager-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_esp_transport/include",
                ],
                [
                    ROOT / "firmware/common/src/gateway_handoff.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_esp_transport/src/gateway_handoff.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_esp_transport/test/gateway_handoff_test.cpp",
                ],
            ),
            (
                "discovery-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_discovery/include",
                ],
                [
                    ROOT / "firmware/esp32s3/components/kf_discovery/src/discovery.cpp",
                    ROOT / "firmware/esp32s3/components/kf_discovery/test/discovery_test.cpp",
                ],
            ),
            (
                "ble-transport-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_ble_transport/include",
                ],
                [
                    ROOT
                    / "firmware/esp32s3/components/kf_ble_transport/src/ble_transport.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_ble_transport/test/ble_transport_test.cpp",
                ],
            ),
            (
                "ble-hid-release-test",
                [ROOT / "firmware/esp32s3/components/kf_ble_hid/include"],
                [
                    ROOT
                    / "firmware/esp32s3/components/kf_ble_hid/src/release_burst.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_ble_hid/test/release_burst_test.cpp",
                ],
            ),
            (
                "output-mode-test",
                [
                    ROOT / "firmware/esp32s3/components/kf_output_mode/include",
                    ROOT / "firmware/common/include",
                ],
                [
                    ROOT
                    / "firmware/esp32s3/components/kf_output_mode/src/output_mode.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_output_mode/test/output_mode_test.cpp",
                ],
            ),
            (
                "display-orientation-test",
                [
                    ROOT
                    / "firmware/esp32s3/components/kf_display_orientation/include",
                    ROOT / "firmware/common/include",
                ],
                [
                    ROOT
                    / "firmware/esp32s3/components/kf_display_orientation/src/display_orientation.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_display_orientation/test/display_orientation_test.cpp",
                ],
            ),
            (
                "config-store-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_config_store/include",
                ],
                [
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/config_store.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/src/config_storage.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/test/config_store_test.cpp",
                ],
            ),
            (
                "recovery-anchor-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_config_store/include",
                ],
                [
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/config_store.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/src/recovery_anchor.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/test/recovery_anchor_test.cpp",
                ],
            ),
            (
                "roaming-config-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_config_store/include",
                ],
                [
                    ROOT / "firmware/common/src/roaming_profile.cpp",
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/config_store.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/src/recovery_anchor.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/src/roaming_config.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/test/roaming_config_test.cpp",
                ],
            ),
            (
                "roaming-storage-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_config_store/include",
                ],
                [
                    ROOT / "firmware/common/src/roaming_profile.cpp",
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/config_store.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/src/config_storage.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/src/recovery_anchor.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/src/roaming_config.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/src/roaming_storage.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/test/roaming_storage_test.cpp",
                ],
            ),
            (
                "runtime-config-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_secure_endpoint/include",
                    ROOT / "firmware/esp32s3/components/kf_esp_transport/include",
                    ROOT / "firmware/esp32s3/components/kf_config_store/include",
                    ROOT / "firmware/esp32s3/components/kf_runtime_config/include",
                ],
                [
                    ROOT / "firmware/common/src/frame_codec.cpp",
                    ROOT / "firmware/common/src/roaming_profile.cpp",
                    ROOT / "firmware/common/src/gateway_handoff.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_secure_endpoint/src/secure_endpoint.cpp",
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/config_store.cpp",
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/recovery_anchor.cpp",
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/roaming_config.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/src/roaming_storage.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_config_store/src/config_storage.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_esp_transport/src/transport_policy.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_runtime_config/src/runtime_config.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_runtime_config/test/runtime_config_test.cpp",
                ],
            ),
            (
                "provisioning-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_config_store/include",
                    ROOT / "firmware/esp32s3/components/kf_provisioning/include",
                ],
                [
                    ROOT / "firmware/common/src/roaming_profile.cpp",
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/config_store.cpp",
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/config_storage.cpp",
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/recovery_anchor.cpp",
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/roaming_config.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_provisioning/src/local_management.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_provisioning/src/local_management_codec.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_provisioning/src/local_management_coordinator.cpp",
                    ROOT / "firmware/esp32s3/components/kf_provisioning/src/provisioning.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_provisioning/test/provisioning_test.cpp",
                ],
            ),
            (
                "local-management-receipts-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_config_store/include",
                    ROOT / "firmware/esp32s3/components/kf_provisioning/include",
                ],
                [
                    ROOT / "firmware/esp32s3/components/kf_config_store/src/config_store.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_provisioning/src/local_management_receipts.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_provisioning/test/local_management_receipts_test.cpp",
                ],
            ),
            (
                "local-management-status-test",
                [
                    ROOT / "firmware/common/include",
                    ROOT / "firmware/esp32s3/components/kf_config_store/include",
                    ROOT / "firmware/esp32s3/components/kf_provisioning/include",
                ],
                [
                    ROOT
                    / "firmware/esp32s3/components/kf_provisioning/src/local_management_status.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_provisioning/test/local_management_status_test.cpp",
                ],
            ),
            (
                "status-test",
                [
                    ROOT / "firmware/esp32s3/components/kf_status/include",
                    ROOT / "firmware/esp32s3/components/kf_esp_status_display/include",
                ],
                [
                    ROOT / "firmware/esp32s3/components/kf_status/src/status.cpp",
                    ROOT
                    / "firmware/esp32s3/components/kf_esp_status_display/src/status_display_layout.cpp",
                    ROOT / "firmware/esp32s3/components/kf_status/test/status_test.cpp",
                ],
            ),
        ]
        checks.append((
            "status-led-test",
            [ROOT / "firmware/esp32s3/components/kf_status/include",
             ROOT / "firmware/esp32s3/components/kf_esp_status_display/include"],
            [ROOT / "firmware/esp32s3/components/kf_status/test/status_led_test.cpp"],
        ))
        transport = ROOT / "firmware/esp32s3/components/kf_esp_transport"
        # Only platform/crypto headers are substituted. Compile the production
        # transport owner loop with its real endpoint and arbitration sources.
        shims = tmp / "idf-transport"
        for header in (
            "esp_event.h", "esp_log.h", "esp_netif.h", "esp_random.h",
            "esp_timer.h", "esp_tls.h", "esp_tls_errors.h", "esp_wifi.h",
            "freertos/FreeRTOS.h", "freertos/event_groups.h", "freertos/task.h",
            "mbedtls/md.h", "mbedtls/ssl.h", "mbedtls/x509_crt.h",
        ):
            path = shims / header
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#include "idf_transport_test_stubs.h"\n', encoding="utf-8")
        _, policy_includes, policy_sources = next(
            check for check in checks if check[0] == "transport-policy-test")
        checks.append((
            "esp-transport-test",
            [shims, transport / "test", *policy_includes,
             ROOT / "firmware/esp32s3/components/kf_ble_transport/include",
             ROOT / "firmware/esp32s3/components/kf_esp_discovery/include",
             ROOT / "firmware/esp32s3/components/kf_discovery/include"],
            [*policy_sources[:-1],
             transport / "src/gateway_handoff.cpp",
             ROOT / "firmware/esp32s3/components/kf_discovery/src/discovery.cpp",
             transport / "test/esp_transport_test.cpp"],
        ))
        msvc = Path(compiler).name.lower() in {"cl", "cl.exe"}
        # USB Drive: production drive.cpp on the pinned ESP-IDF's own FatFs (C sources, built
        # without warnings as errors); only the platform headers are substituted.
        idf = Path(os.environ.get("IDF_PATH") or ROOT / ".tools/esp-idf-v6.0.3")
        version = idf / "version.txt"
        if not version.is_file() or version.read_text(encoding="utf-8").strip() != "v6.0.3":
            print(f"ERROR: handheld-drive-test needs the pinned ESP-IDF v6.0.3 at {idf} "
                  "(run the project toolchain setup, or set IDF_PATH)", file=sys.stderr)
            raise SystemExit(1)
        fatfs = idf / "components/fatfs"
        handheld = ROOT / "firmware/esp32s3/handheld/kf_handheld"
        drive_shims = tmp / "idf-drive"
        headers = ["bsp/esp-bsp.h", "esp_err.h", "esp_heap_caps.h", "esp_log.h", "esp_timer.h",
                   "freertos/FreeRTOS.h", "freertos/semphr.h", "freertos/task.h",
                   "sd_protocol_types.h", "sdkconfig.h", "sdmmc_cmd.h", "tusb.h"]
        if sys.platform == "win32":
            headers.append("windows.h")  # ff.h takes its integer types from it there
        if msvc:
            headers += ["strings.h", "sys/param.h", "sys/time.h"]
        for header in headers:
            path = drive_shims / header
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#include "drive_test_stubs.h"\n', encoding="utf-8")
        checks.append((
            "handheld-drive-test",
            [drive_shims, handheld / "test", handheld / "src", fatfs / "diskio", fatfs / "src"],
            [fatfs / "src/ff.c", fatfs / "src/ffunicode.c", fatfs / "diskio/diskio.c",
             fatfs / "port/freertos/ffsystem.c", handheld / "src/drive.cpp",
             handheld / "test/drive_test.cpp"],
        ))
        # Messages: production messages.cpp over a simulated USB serial port.
        messages_shims = tmp / "idf-messages"
        for header in ("device/usbd_pvt.h", "esp_heap_caps.h", "esp_log.h", "esp_timer.h",
                       "freertos/FreeRTOS.h", "freertos/semphr.h", "tinyusb_cdc_acm.h", "tusb.h"):
            path = messages_shims / header
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#include "messages_test_stubs.h"\n', encoding="utf-8")
        checks.append((
            "handheld-messages-test",
            [messages_shims, handheld / "test", handheld / "src"],
            [handheld / "src/messages.cpp", handheld / "test/messages_test.cpp"],
        ))
        for name, includes, sources in checks:
            executable = tmp / (f"{name}.exe" if sys.platform == "win32" else name)
            if msvc:
                objects = []
                for index, source in enumerate(sources):
                    object_path = tmp / f"{name}-{index}-{source.stem}.obj"
                    flags = (["/std:c11", "/W1"] if source.suffix == ".c"
                             else ["/std:c++17", "/W4", "/WX", "/EHsc"])
                    run(
                        [
                            compiler,
                            "/nologo",
                            *flags,
                            *(f"/I{include}" for include in includes),
                            "/c",
                            str(source),
                            f"/Fo:{object_path}",
                        ],
                        cwd=tmp,
                    )
                    objects.append(object_path)
                command = [
                    compiler,
                    "/nologo",
                    *(str(path) for path in objects),
                    f"/Fe:{executable}",
                ]
            else:
                objects = []
                for index, source in enumerate(s for s in sources if s.suffix == ".c"):
                    object_path = tmp / f"{name}-{index}-{source.stem}.o"
                    run([compiler, "-x", "c", *(f"-I{include}" for include in includes),
                         "-c", str(source), "-o", str(object_path)], cwd=tmp)
                    objects.append(object_path)
                command = [
                    compiler,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pthread",
                    *(f"-I{include}" for include in includes),
                    *(str(source) for source in sources if source.suffix != ".c"),
                    *(str(path) for path in objects),
                    "-o",
                    str(executable),
                ]
            run(command, cwd=tmp)
            arguments = [str(executable)]
            if name == "local-management-status-test":
                arguments.append(str(ROOT / "protocol/vectors/local-wifi-diagnostic.hex"))
                arguments.append(str(ROOT / "protocol/vectors/local-endpoint-diagnostic.hex"))
            if name == "secure-endpoint-test":
                arguments.append(str(ROOT / "protocol/vectors/typing-stress.hex"))
                arguments.append(str(ROOT / "protocol/vectors/pointer-session.hex"))
            run(arguments, cwd=tmp)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true", help="require Rust and C++ toolchains")
    parser.add_argument("--firmware-only", action="store_true", help="run source, Python and native firmware gates without Rust builds")
    args = parser.parse_args()

    run([sys.executable, "scripts/check_process_spawns.py"])
    run([sys.executable, "-m", "unittest", "tests.test_process_spawns"])
    run([sys.executable, "scripts/check_public_tree.py",
         *([] if args.firmware_only else ["--history"])])
    run([sys.executable, "scripts/check_seed.py"])
    run([sys.executable, "scripts/check_usb_executor.py"])
    run([sys.executable, "scripts/check_secure_endpoint.py"])
    run([sys.executable, "scripts/check_esp_transport.py"])
    run([sys.executable, "-m", "unittest", "tests.test_board_profiles", "tests.test_ble_hid_partition_gate", "tests.test_handheld_msc_gate", "tests.test_flash_backup", "tests.test_first_install_freeze", "tests.test_hil_pointer"])
    run([sys.executable, "scripts/check_hil_mouse.py"])
    run([sys.executable, "scripts/check_hil_pointer.py"])
    run([sys.executable, "scripts/check_provisioning.py"])
    run([sys.executable, "scripts/check_local_management.py"])
    run([sys.executable, "scripts/check_qualification.py"])
    run([sys.executable, "-m", "unittest", "tests.test_package_controller_release"])
    run([sys.executable, "-m", "unittest", "tests.test_public_boundary"])
    run([sys.executable, "-m", "unittest", "tests.test_esptool_summary_contract"])

    cargo = shutil.which("cargo")
    if args.firmware_only:
        print("NOT APPLICABLE: Rust builds (firmware-only selection)")
    elif cargo:
        cargo_env = os.environ.copy()
        cargo_env["CARGO_INCREMENTAL"] = "0"
        print(f"build concurrency: {BUILD_JOBS} jobs ({CPU_PERCENT}% CPU ceiling from project.toml; CARGO_BUILD_JOBS honored)", flush=True)
        run([cargo, "fmt", "--all", "--", "--check"], env=cargo_env)
        run(
            [
                cargo,
                "test",
                "--workspace",
                "--locked",
                "--offline",
                "--jobs",
                str(BUILD_JOBS),
            ],
            env=cargo_env,
        )
        run(
            [
                cargo,
                "clippy",
                "--workspace",
                "--all-targets",
                "--locked",
                "--offline",
                "--jobs",
                str(BUILD_JOBS),
                "--",
                "-D",
                "warnings",
            ],
            env=cargo_env,
        )
    elif args.strict:
        print("ERROR: cargo is required in strict mode", file=sys.stderr)
        raise SystemExit(1)
    else:
        print("SKIP: cargo not found")

    compiler = shutil.which("g++") or shutil.which("clang++") or shutil.which("cl")
    if compiler:
        run_cpp_check(compiler)
    elif args.strict:
        print("ERROR: a C++17 compiler is required in strict mode", file=sys.stderr)
        raise SystemExit(1)
    else:
        print("SKIP: no C++ compiler found")

    print("check: ok")


if __name__ == "__main__":
    if os.name == "nt" and not build_governor.governed():
        raise SystemExit(build_governor.run([sys.executable, __file__, *sys.argv[1:]]))
    main()
