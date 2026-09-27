import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "package_controller_release.py"
SPEC = importlib.util.spec_from_file_location("package_controller_release", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ControllerReleaseTests(unittest.TestCase):
    @staticmethod
    def registry(root: Path) -> Path:
        path = root / "private-identifiers.txt"
        path.write_text("private-host-9z\n11111111-2222-4333-8444-555555555555\n")
        return path

    @staticmethod
    def mac_app(root: Path) -> Path:
        app = root / "Keyferry.app"
        files = {
            "Contents/Info.plist": b"plist",
            "Contents/Resources/keyferry.icns": b"icon",
            "Contents/_CodeSignature/CodeResources": b"signature",
            "Contents/MacOS/keyferry": b"controller",
            "Contents/MacOS/keyferryd": b"daemon",
            "Contents/MacOS/keyferry-pairing": b"pairing",
            "Contents/MacOS/keyctl": b"cli",
            "Contents/MacOS/keyferry-ble-bridge": b"ble",
        }
        for relative, data in files.items():
            path = app / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return app

    def test_windows_release_is_generic_and_contains_no_installation_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            scripts = project / "scripts"
            scripts.mkdir(parents=True)
            (scripts / "install_windows_controller.ps1").write_text("installer\n")
            controller = root / "controller.exe"
            daemon = root / "daemon.exe"
            pairing = root / "pairing.exe"
            cli = root / "keyctl.exe"
            controller.write_bytes(b"controller")
            daemon.write_bytes(b"daemon")
            pairing.write_bytes(b"pairing")
            cli.write_bytes(b"cli")
            output = root / "keyferry-windows-x64.zip"

            MODULE.package(
                "windows",
                controller,
                daemon,
                pairing,
                cli,
                output,
                "1.2.3",
                project,
                self.registry(root),
            )

            with zipfile.ZipFile(output) as archive:
                names = sorted(archive.namelist())
                manifest = archive.read("SHA256SUMS").decode()
                readme = archive.read("README.txt").decode()
                version = archive.read("VERSION").decode()
            self.assertEqual(
                names,
                [
                    "README.txt",
                    "SHA256SUMS",
                    "VERSION",
                    "install.ps1",
                    "keyctl.exe",
                    "keyferry-pairing.exe",
                    "keyferry.exe",
                    "keyferryd.exe",
                ],
            )
            self.assertIn("  keyferry.exe\n", manifest)
            self.assertIn("  keyferryd.exe\n", manifest)
            self.assertNotIn("installation/", manifest)
            self.assertNotIn("recovery", manifest)
            self.assertNotIn("owner-kit", manifest)
            self.assertIn("may be distributed separately from private credentials", readme)
            self.assertIn("separate private credential directory", readme)
            self.assertIn("-CliExecutable .\\keyctl.exe -Mode Plan", readme)
            self.assertIn("Authorize this computer", readme.replace("\n   ", " "))
            self.assertIn("keyctl stream DEVICE-UUID --input", readme)
            self.assertIn("& $keyctl --help", readme)
            self.assertIn("& $keyctl status DEVICE-UUID", readme)
            self.assertIn("& $keyctl capabilities", readme)
            self.assertIn("& $keyctl screen-power DEVICE-UUID off", readme)
            self.assertIn(
                "keyctl local-recover --owner-kit PATH --device DEVICE-UUID restart-network",
                readme,
            )
            self.assertIn("owner-kit password through stdin personally", readme.replace("\n", " "))
            self.assertIn("an UNKNOWN result may have acted", readme.replace("\n", " "))
            self.assertIn("exactly one device whose `link` is `authenticated`", readme)
            normalized_readme = readme.replace("\n   ", " ")
            self.assertIn("new computer cannot type until the owner approves it", normalized_readme)
            self.assertIn("do not substitute a distant computer", normalized_readme)
            self.assertIn("Do not retry an interrupted or uncertain stream", readme)
            self.assertIn("service runs only while Keyferry is open", readme)
            self.assertIn("closing the app stops it", readme)
            self.assertIn("keyctl opens Keyferry automatically", readme)
            self.assertEqual(version, "1.2.3\n")

    def test_macos_release_contains_programs_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            scripts = project / "scripts"
            scripts.mkdir(parents=True)
            (scripts / "install_unix_controller.sh").write_text("installer\n")
            app = self.mac_app(root)
            output = root / "keyferry-macos-arm64.zip"

            MODULE.package(
                "macos",
                app,
                None,
                None,
                None,
                output,
                "1.2.3",
                project,
                self.registry(root),
            )

            with zipfile.ZipFile(output) as archive:
                names = set(archive.namelist())
                readme = archive.read("README.txt").decode()
            self.assertIn("Keyferry.app/Contents/MacOS/keyferry", names)
            self.assertNotIn("installation", "\n".join(names))
            self.assertNotIn("gateway.json", names)
            self.assertIn("--controller ./Keyferry.app --mode Plan", readme)
            self.assertIn("keyctl stream DEVICE-UUID --input", readme)
            self.assertIn("keyctl --help", readme)
            self.assertIn("keyctl status DEVICE-UUID", readme)
            self.assertIn("keyctl screen-power DEVICE-UUID off", readme)
            self.assertIn("service runs only while Keyferry is open", readme)

    def test_platform_installers_supervise_the_same_installation_daemon(self):
        project = Path(__file__).resolve().parents[1]
        windows = (project / "scripts" / "install_windows_controller.ps1").read_text()
        macos = (project / "scripts" / "install_unix_controller.sh").read_text()
        self.assertIn("--installation", windows)
        self.assertIn("[string[]]$LanInterface", windows)
        self.assertIn("$expectedArguments += \" $lanArguments\"", windows)
        self.assertIn("New-ScheduledTaskAction", windows)
        self.assertIn("$installedCli", windows)
        self.assertIn("--installation", macos)
        self.assertIn("--lan-interface", macos)
        self.assertIn("lan_interfaces=${lan_interfaces:-none}", macos)
        self.assertIn("launchctl bootstrap", macos)
        self.assertIn("$installed_cli", macos)
        self.assertIn("apply_succeeded=false", macos)
        self.assertIn(".Keyferry.app.rollback.", macos)
        self.assertIn("launch_agent_backup", macos)
        self.assertIn("old_app_displaced", macos)
        self.assertIn("new_app_published", macos)
        self.assertIn("credential_stage", macos)
        self.assertIn("another Keyferry installation is already in progress", macos)
        self.assertIn("StandardOutPath", macos)
        self.assertIn("command -v lsof", macos)
        self.assertIn("\"$lsof_command\" -nP -a -p \"$daemon_pid\"", macos)
        self.assertIn("/opt/homebrew/bin/tailscale", macos)
        self.assertIn('-iTCP:18043', macos)
        self.assertIn('-iTCP:18044', macos)
        self.assertIn("refusing to replace a linked application", macos)
        self.assertNotIn('open -gj "$installed_app"', macos)
        self.assertNotIn('open "$installed_app"', macos)
        self.assertNotIn("GatewayCredential", windows)
        self.assertNotIn("gateway.json", macos)

    def test_windows_installer_retires_legacy_gateway_and_verifies_its_own_daemon(self):
        project = Path(__file__).resolve().parents[1]
        windows = (project / "scripts" / "install_windows_controller.ps1").read_text()
        self.assertIn("$legacyTaskName = 'Keyferry Gateway'", windows)
        self.assertIn("Stop-ScheduledTask -TaskName $legacyTaskName", windows)
        self.assertIn("Unregister-ScheduledTask -TaskName $legacyTaskName", windows)
        self.assertIn("$process.ExecutablePath -ine $installedDaemon", windows)
        self.assertIn("$process.CommandLine.Contains($expectedArguments)", windows)
        self.assertIn("Get-NetIPAddress -InterfaceAlias $name", windows)
        self.assertIn("-LocalPort 7443", windows)
        self.assertIn("Get-AccountSid $task.Principal.UserId", windows)
        self.assertIn("$programAccessSddlBefore", windows)
        self.assertIn("[IO.FileSystemAclExtensions]::SetAccessControl", windows)
        self.assertNotIn("Set-Acl", windows)
        self.assertIn("$_.LocalPort -eq 18043 -or $_.LocalPort -eq 18044", windows)
        self.assertIn("Start-ScheduledTask -TaskName $legacyTaskName", windows)

    def test_installers_define_a_service_that_runs_only_while_the_app_is_open(self):
        project = Path(__file__).resolve().parents[1]
        windows = (project / "scripts" / "install_windows_controller.ps1").read_text()
        macos = (project / "scripts" / "install_unix_controller.sh").read_text()
        self.assertNotIn("New-ScheduledTaskTrigger", windows)
        self.assertNotIn("-Trigger", windows)
        self.assertNotIn("-RestartCount", windows)
        self.assertIn("-MultipleInstances IgnoreNew", windows)
        self.assertIn("$task.Settings.RestartCount -ne 0", windows)
        self.assertIn("Get-InstalledDaemonCommandProcessId", windows)
        self.assertIn("$verificationStartedDaemon = $true", windows)
        self.assertIn("Stop-ScheduledTask -TaskName $taskName\n", windows)
        self.assertIn("plutil -insert RunAtLoad -bool false", macos)
        self.assertIn("plutil -insert KeepAlive -bool false", macos)
        self.assertNotIn("-bool true", macos)
        self.assertNotIn("kickstart -k", macos)
        self.assertIn('launchctl kickstart "$launch_domain/$launch_label"', macos)
        self.assertIn('launchctl kill TERM "$launch_domain/$launch_label"', macos)
        self.assertIn('[ "$verification_started" != true ] || stop_verification_daemon', macos)

    def test_macos_package_gate_is_bounded_and_checks_the_native_bundle(self):
        project = Path(__file__).resolve().parents[1]
        gate = (project / "scripts" / "check_macos_package.sh").read_text()
        self.assertIn("logical_cpus * 60 / 100", gate)
        self.assertIn('rustup show active-toolchain', gate)
        self.assertNotIn('rust_toolchain=1.92.0', gate)
        self.assertIn('rustup which --toolchain "$rust_toolchain" rustc', gate)
        self.assertIn('rustup which --toolchain "$rust_toolchain" rustdoc', gate)
        self.assertIn('rustup run "$rust_toolchain" cargo', gate)
        self.assertIn("run_cargo test --locked --release", gate)
        self.assertIn("-p keyferryd", gate)
        self.assertIn("-p keyferry-local-management", gate)
        self.assertIn("-p keyferry-pairing", gate)
        self.assertIn("run_cargo build --locked --release", gate)
        self.assertIn("-p keyctl", gate)
        self.assertIn("cargo_target_dir=${CARGO_TARGET_DIR:-target}", gate)
        self.assertIn("cleanup_status=$?", gate)
        self.assertIn("codesign --verify --deep --strict", gate)
        self.assertIn("NSBluetoothAlwaysUsageDescription", gate)
        self.assertIn("keyferry-ble-bridge", gate)
        self.assertIn("create-owner-kit --output", gate)
        self.assertIn("issue-installation", gate)
        self.assertIn("--mode Plan", gate)
        self.assertNotIn("--mode Apply", gate)

    def test_windows_package_gate_is_bounded_private_and_non_installing(self):
        project = Path(__file__).resolve().parents[1]
        gate = (project / "scripts" / "check_windows_package.ps1").read_text()
        self.assertIn("[Math]::Floor($logicalCpus * 0.60)", gate)
        self.assertIn("RandomNumberGenerator]::Create()", gate)
        self.assertNotIn("RandomNumberGenerator]::Fill", gate)
        self.assertIn("cargo test --locked --release -p keyferryd", gate)
        self.assertIn("AreAccessRulesProtected", gate)
        self.assertIn("package_controller_release.py", gate)
        self.assertIn("check_windows_icon.py", gate)
        self.assertIn("-CliExecutable $cli", gate)
        self.assertIn("-Mode Plan", gate)
        self.assertIn("-LanInterface 'Ethernet 2'", gate)
        self.assertNotIn("-Mode Apply", gate)

    def test_owner_installation_helper_keeps_passphrase_out_of_arguments(self):
        project = Path(__file__).resolve().parents[1]
        helper = (project / "scripts" / "issue_owner_installation.ps1").read_text()
        self.assertIn("Read-Host 'Create owner-kit passphrase' -AsSecureString", helper)
        self.assertIn("Read-Host 'Owner-kit passphrase' -AsSecureString", helper)
        self.assertIn("Invoke-PairingWithSecret", helper)
        self.assertIn("Assert-ValidOwnerPassphrase", helper)
        self.assertIn("$byteCount -eq 0 -or $byteCount -gt 1024", helper)
        self.assertIn("$inputText | & $pairing @Arguments", helper)
        self.assertIn('$inputText = $SecretLines -join "`n"', helper)
        self.assertNotIn('($SecretLines -join "`n") + "`n"', helper)
        self.assertIn("[Math]::Floor([Environment]::ProcessorCount * 0.60)", helper)
        self.assertNotIn("if (-not (Test-Path -LiteralPath $pairing", helper)
        self.assertNotIn("--passphrase", helper)
        self.assertNotIn("Write-Host $passphrase", helper)

    def test_firmware_build_runner_caps_and_allows_lower_concurrency(self):
        project = Path(__file__).resolve().parents[1]
        helper = (project / "scripts" / "build_first_hil.ps1").read_text()
        self.assertIn("[ValidateRange(0, 256)]", helper)
        self.assertIn("[int]$Jobs = 0", helper)
        self.assertIn("[Math]::Floor([Environment]::ProcessorCount * 0.60)", helper)
        self.assertIn("if ($Jobs -gt $buildJobCeiling)", helper)
        self.assertIn("if ($Jobs -eq 0) { $buildJobCeiling } else { $Jobs }", helper)
        self.assertIn("$env:IDF_PY_BUILD_JOBS = $buildJobs", helper)
        self.assertIn("--jobs $buildJobs", helper)

    def test_refuses_to_overwrite_an_existing_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            scripts = project / "scripts"
            scripts.mkdir(parents=True)
            (scripts / "install_windows_controller.ps1").write_text("installer\n")
            controller = root / "controller.exe"
            daemon = root / "daemon.exe"
            pairing = root / "pairing.exe"
            cli = root / "keyctl.exe"
            controller.write_bytes(b"controller")
            daemon.write_bytes(b"daemon")
            pairing.write_bytes(b"pairing")
            cli.write_bytes(b"cli")
            output = root / "keyferry-windows-x64.zip"
            output.write_bytes(b"existing")

            with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
                MODULE.package(
                    "windows",
                    controller,
                    daemon,
                    pairing,
                    cli,
                    output,
                    "1.2.3",
                    project,
                    self.registry(root),
                )
            self.assertEqual(output.read_bytes(), b"existing")


if __name__ == "__main__":
    unittest.main()
