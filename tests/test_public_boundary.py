import importlib.util
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    import sys

    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


SCAN = load("check_public_tree", ROOT / "scripts" / "check_public_tree.py")
PACKAGE = load("package_controller_release", ROOT / "scripts" / "package_controller_release.py")


class PublicBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        (self.project / "scripts").mkdir(parents=True)
        (self.project / "scripts" / "install_windows_controller.ps1").write_text("installer\n")
        (self.project / "scripts" / "install_unix_controller.sh").write_text("installer\n")
        self.registry = self.root / "private-identifiers.txt"
        self.uuid = "12345678-1234-4234-9234-123456789abc"
        self.mac_bytes = bytes((0x10, 0x20, 0x30, 0x40, 0x50, 0x60))
        self.mac = ":".join(f"{value:02x}" for value in self.mac_bytes)
        self.secret = bytes(range(32))
        self.der = b"\x30\x16\x02\x01\x01\x04\x11private-der-value"
        self.registry.write_text(f"private-machine-z9\n{self.uuid}\n{self.mac}\n{self.secret.hex()}\n")
        private_der = self.project / "secrets" / "private-cert.der"
        private_der.parent.mkdir()
        private_der.write_bytes(self.der)

    def tearDown(self):
        self.temporary.cleanup()

    def windows_inputs(self, contaminated: bytes | None = None):
        paths = []
        for index, name in enumerate(("controller.exe", "daemon.exe", "pairing.exe", "keyctl.exe")):
            path = self.root / name
            path.write_bytes(contaminated if index == 0 and contaminated else name.encode())
            paths.append(path)
        return paths

    def mac_app(self) -> Path:
        app = self.root / "Keyferry.app"
        for relative in SCAN.MACOS_MEMBERS:
            if not relative.startswith("Keyferry.app/"):
                continue
            path = app / relative.removeprefix("Keyferry.app/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(relative.encode())
        return app

    def test_packager_rejects_private_bytes_extra_grant_and_unsafe_names(self):
        inputs = self.windows_inputs(bytes.fromhex(self.uuid.replace("-", "")))
        with self.assertRaisesRegex(ValueError, "privacy scan failed"):
            PACKAGE.package("windows", *inputs, self.root / "keyferry-windows-x64.zip",
                            "1.2.3", self.project, self.registry)

        app = self.mac_app()
        (app / "Contents" / "Resources" / "device-grant.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "manifest mismatch"):
            PACKAGE.package("macos", app, None, None, None,
                            self.root / "keyferry-macos-arm64.zip", "1.2.3",
                            self.project, self.registry)

        clean = self.windows_inputs()
        with self.assertRaisesRegex(ValueError, "version must be"):
            PACKAGE.package("windows", *clean, self.root / "keyferry-windows-x64.zip",
                            "private-machine-z9", self.project, self.registry)
        with self.assertRaisesRegex(ValueError, "output filename must be exactly"):
            PACKAGE.package("windows", *clean, self.root / "private-machine-z9.zip",
                            "1.2.3", self.project, self.registry)

    def test_zip_scanner_rejects_links_traversal_duplicates_and_nested_archives(self):
        archive_path = self.root / "keyferry-windows-x64.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("../escape", b"x")
            archive.writestr("nested.zip", b"x")
            archive.writestr("duplicate", b"one")
            archive.writestr("duplicate", b"two")
            link = zipfile.ZipInfo("linked")
            link.create_system = 3
            link.external_attr = 0o120777 << 16
            archive.writestr(link, b"target")
        failures = SCAN.artifact_failures(
            archive_path, SCAN.private_patterns(self.project, self.registry)
        )
        joined = "\n".join(failures)
        self.assertIn("unsafe archive member path", joined)
        self.assertIn("nested archive", joined)
        self.assertIn("duplicate archive member", joined)
        self.assertIn("link is forbidden", joined)

    def test_deleted_binary_private_values_remain_history_failures(self):
        repo = self.root / "history"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        payload = (bytes.fromhex(self.uuid.replace("-", ""))
                   + self.mac_bytes + self.secret)
        hidden = repo / "innocent.bin"
        hidden.write_bytes(payload)
        subprocess.run(["git", "add", "innocent.bin"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "add fixture"], cwd=repo, check=True)
        hidden.unlink()
        subprocess.run(["git", "add", "-u"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "remove fixture"], cwd=repo, check=True)
        patterns = SCAN.private_patterns(repo, self.registry)
        failures = SCAN.history_failures(patterns, repo)
        self.assertTrue(any("reachable objects" in failure for failure in failures))

    def test_private_workflow_paths_fail_in_current_tree_and_history(self):
        repo = self.root / "workflow-history"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        private_paths = (
            "workorders/one.md", "docs/plan.md", ".claude/settings.json",
            ".codex/config.toml", ".cursor/rules.md", ".tools/task.md",
            ".worktrees/agent/private.md",
            "do/state.md", "AGENTS.md", "CLAUDE.md", "START_HERE.md",
            "SEED_VALIDATION.md",
        )
        public_path = "apps/agent/prompts/default.md"
        for relative in (*private_paths, public_path):
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("harmless fixture\n")
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        current = SCAN.current_tree_failures(repo, [])
        for relative in private_paths:
            self.assertTrue(any(relative in failure for failure in current), relative)
        self.assertFalse(any(public_path in failure for failure in current))
        subprocess.run(["git", "commit", "-qm", "add fixtures"], cwd=repo, check=True)
        for relative in private_paths:
            (repo / relative).unlink()
        subprocess.run(["git", "add", "-u"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "remove private fixtures"], cwd=repo, check=True)
        self.assertEqual(SCAN.current_tree_failures(repo, []), [])
        self.assertIn(
            "Git history contains a prohibited private path or filename",
            SCAN.history_failures([], repo),
        )

    def test_dot_prefixed_path_normalization_keeps_private_directory_name(self):
        self.assertEqual(SCAN._path_failure("./.claude/settings.json"), "private path")
        self.assertEqual(SCAN._path_failure(".\\.codex\\config.toml"), "private path")
        self.assertEqual(SCAN._path_failure("./.worktrees/agent/private.md"), "private path")
        self.assertIsNone(SCAN._path_failure("apps/agent/prompts/default.md"))
        self.assertIsNone(SCAN._path_failure("apps/agent/AGENTS.md"))

    def test_current_binary_blob_is_scanned_instead_of_skipped(self):
        repo = self.root / "current"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        path = repo / "innocent.bin"
        path.write_bytes(b"\0prefix" + self.secret)
        subprocess.run(["git", "add", "innocent.bin"], cwd=repo, check=True)
        failures = SCAN.current_tree_failures(repo, SCAN.private_patterns(repo, self.registry))
        self.assertTrue(any("private identity material" in failure for failure in failures))

    def test_private_der_and_root_name_are_scanned(self):
        patterns = SCAN.private_patterns(self.project, self.registry)
        self.assertEqual(
            SCAN._content_failure(b"prefix" + self.der + b"suffix", patterns),
            "matches local private identity material",
        )
        artifact = self.root / "owner-kit-candidate"
        artifact.mkdir()
        failures = SCAN.artifact_failures(artifact, patterns)
        self.assertIn("artifact root has a private-looking name", failures)

    def test_registered_names_are_found_in_utf16_binaries(self):
        patterns = SCAN.private_patterns(self.project, self.registry)
        wide = "PRIVATE-MACHINE-Z9".encode("utf-16-le")
        self.assertEqual(
            SCAN._content_failure(b"\x01\x02" + wide + b"\x03", patterns),
            "matches local private identity material",
        )

    def test_unregistered_home_paths_fail_but_placeholders_pass(self):
        # Assembled at runtime so this file does not itself contain a home path.
        account = b"builder7"
        leaked = [
            b"unreachable codeC:\\Users\\" + account + b"\\.cargo\\registry\\src\\x.rs",
            b"/Users/" + account + b"/.cargo/registry/src/x.rs",
            b"/home/" + account + b"/.cargo/registry/src/x.rs",
            ("C:\\Users\\" + account.decode() + "\\AppData").encode("utf-16-le"),
        ]
        for data in leaked:
            self.assertEqual(SCAN._content_failure(data, []), "contains an absolute user home path")
        for data in (b"/Users/" + b"owner/Library", b"/home/" + b"owner/.local",
                     b"C:" + b"/Users/" + b"USER/x"):
            self.assertIsNone(SCAN._content_failure(data, []))

    def test_packager_rejects_a_binary_built_without_path_remapping(self):
        inputs = self.windows_inputs(b"C:\\Users\\" + b"builder7\\.cargo\\registry\\src\\lib.rs")
        with self.assertRaisesRegex(ValueError, "privacy scan failed"):
            PACKAGE.package("windows", *inputs, self.root / "keyferry-windows-x64.zip",
                            "1.2.3", self.project, self.registry)


if __name__ == "__main__":
    unittest.main()
