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

ROOT = Path(__file__).resolve().parents[1]
BUILD_JOBS = max(1, int((os.cpu_count() or 1) * 0.60))


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
                ],
                [
                    ROOT / "firmware/common/src/frame_codec.cpp",
                    ROOT / "firmware/common/src/gateway_handoff.cpp",
                    ROOT / "firmware/esp32s3/components/kf_secure_endpoint/src/secure_endpoint.cpp",
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
        for name, includes, sources in checks:
            executable = tmp / (f"{name}.exe" if sys.platform == "win32" else name)
            if Path(compiler).name.lower() in {"cl", "cl.exe"}:
                objects = []
                for index, source in enumerate(sources):
                    object_path = tmp / f"{name}-{index}-{source.stem}.obj"
                    run(
                        [
                            compiler,
                            "/nologo",
                            "/std:c++17",
                            "/W4",
                            "/WX",
                            "/EHsc",
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
                command = [
                    compiler,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    *(f"-I{include}" for include in includes),
                    *(str(source) for source in sources),
                    "-o",
                    str(executable),
                ]
            run(command, cwd=tmp)
            run([str(executable)], cwd=tmp)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true", help="require Rust and C++ toolchains")
    args = parser.parse_args()

    run([sys.executable, "scripts/check_public_tree.py", "--history"])
    run([sys.executable, "scripts/check_seed.py"])
    run([sys.executable, "scripts/check_usb_executor.py"])
    run([sys.executable, "scripts/check_secure_endpoint.py"])
    run([sys.executable, "scripts/check_esp_transport.py"])
    run([sys.executable, "scripts/check_hil_mouse.py"])
    run([sys.executable, "scripts/check_provisioning.py"])
    run([sys.executable, "scripts/check_local_management.py"])
    run([sys.executable, "scripts/check_qualification.py"])
    run([sys.executable, "-m", "unittest", "tests.test_package_controller_release"])
    run([sys.executable, "-m", "unittest", "tests.test_public_boundary"])
    run([sys.executable, "-m", "unittest", "tests.test_esptool_summary_contract"])

    cargo = shutil.which("cargo")
    if cargo:
        cargo_env = os.environ.copy()
        cargo_env["CARGO_INCREMENTAL"] = "0"
        print(f"build concurrency: {BUILD_JOBS} jobs (60% of logical CPUs)", flush=True)
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
    main()
