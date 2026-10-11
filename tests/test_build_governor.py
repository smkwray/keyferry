"""Real Windows job/lease tests; no mocks of the safety boundary."""
import ctypes
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest

from scripts.build_governor import budget

ROOT = Path(__file__).resolve().parents[1]
GOVERNOR = ROOT / "scripts/build_governor.py"
PERCENT, CEILING = budget()


class BudgetTests(unittest.TestCase):
    BUILD = {"cpu_percent": 50, "hosts": {"buildhost": {"cpu_percent": 75}}}

    def test_default_and_host_override(self):
        self.assertEqual(budget(self.BUILD, "default-host", 20), (50, 10))
        self.assertEqual(budget(self.BUILD, "buildhost", 32), (75, 24))
        self.assertEqual(budget(self.BUILD, "buildhost.local", 32), (75, 24))
        self.assertEqual(budget({"cpu_percent": 50}, "buildhost", 1), (50, 1))

    def test_invalid_percent_fails_closed(self):
        for value in (0, 101, "75", 75.0, True):
            with self.assertRaises(ValueError):
                budget({"cpu_percent": 50, "hosts": {"buildhost": {"cpu_percent": value}}}, "buildhost", 32)
        with self.assertRaises(KeyError):
            budget({"cpu_percent": 50, "hosts": {"buildhost": {}}}, "buildhost", 32)

    def test_ignored_local_host_override_uses_production_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "project.toml").write_text("[build]\ncpu_percent = 50\n")
            local = root / "project.local.toml"
            local.write_text("[build.hosts.buildhost]\ncpu_percent = 75\n")
            self.assertEqual(budget(host="buildhost.local", cpus=32, root=root), (75, 24))
            self.assertEqual(budget(host="other-host", cpus=20, root=root), (50, 10))
            local.write_text("[build]\ncpu_percent = 100\n")
            with self.assertRaises(ValueError):
                budget(host="buildhost", cpus=32, root=root)

    def test_project_budget_has_one_reader(self):
        # Every build entry point asks the governor; none parses project.toml itself.
        self.assertEqual(budget(tomllib.loads((ROOT / "project.toml").read_text())["build"],
                                "NO-SUCH-HOST", 20), (50, 10))
        parse = re.compile(r"""cpu_percent(\\s|\[\[:space:\]\])|\[["']cpu_percent["']\]""")
        readers = [path.name for path in (ROOT / "scripts").iterdir()
                   if path.is_file() and parse.search(path.read_text(errors="ignore"))]
        self.assertEqual(readers, ["build_governor.py"])
        printed = subprocess.run([sys.executable, str(GOVERNOR), "--budget"], capture_output=True,
                                 text=True, check=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.assertEqual(printed.stdout.split(), [str(PERCENT), str(CEILING)])

    def test_remote_builder_is_governed_and_verifies_transfers(self):
        script = (ROOT / "scripts/remote_build.ps1").read_text()
        self.assertIn("python scripts/build_governor.py --receipt", script)
        self.assertIn("SHA256 mismatch after transfer", script)
        self.assertIn("ls-files -- '*.lock'", script)
        self.assertIn("if ($code) { throw", script)


@unittest.skipUnless(os.name == "nt", "Windows Job Objects")
class GovernorTests(unittest.TestCase):
    def launch(self, receipt, code, jobs=None):
        env = os.environ.copy()
        env["CARGO_BUILD_JOBS"] = str(CEILING if jobs is None else jobs)
        return subprocess.Popen([sys.executable, str(GOVERNOR), "--receipt", str(receipt),
                                 "--", sys.executable, "-c", code],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                creationflags=subprocess.CREATE_NO_WINDOW)

    def finish(self, child):
        out, err = child.communicate(timeout=30)
        self.assertEqual(child.returncode, 0, (out, err))

    def test_shared_slots_cpu_cap_and_headless_tree(self):
        if CEILING < 2:
            self.skipTest("Concurrent admission needs at least two slots")
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as tmp:
            directory = Path(tmp)
            code = """
import ctypes, os, subprocess, sys, time
assert not ctypes.windll.kernel32.GetConsoleWindow()
print(os.environ['CARGO_BUILD_JOBS'], flush=True)
children = [subprocess.Popen([sys.executable, '-c',
    'import ctypes,time; assert not ctypes.windll.kernel32.GetConsoleWindow(); end=time.monotonic()+3; exec("while time.monotonic()<end: pass")']) for _ in range(12)]
assert all(p.wait() == 0 for p in children)
"""
            first = max(1, CEILING * 3 // 5)
            a = self.launch(directory / "a.json", code, first)
            # A concurrent lane may take only the remaining shared budget.
            self.assertIn(f"{first}/{CEILING} slots".encode(), a.stdout.readline())
            b = self.launch(directory / "b.json", code)
            self.finish(a)
            self.finish(b)
            ra = json.loads((directory / "a.json").read_text())
            rb = json.loads((directory / "b.json").read_text())
            self.assertEqual(ra["slots"] + rb["slots"], CEILING)
            # Twelve busy workers per lane cannot escape the shared Job cap.
            machine_seconds = max(ra["wall_seconds"], rb["wall_seconds"]) * os.cpu_count()
            self.assertLess((ra["cpu_seconds"] + rb["cpu_seconds"]) / machine_seconds, PERCENT / 100 + 0.10)
            self.assertGreater(ra["cpu_seconds"] + rb["cpu_seconds"], 1)

    def test_crash_kills_grandchild_and_releases_leases(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as tmp:
            directory = Path(tmp)
            pid = directory / "pid"
            code = ("import subprocess,sys,time; from pathlib import Path; "
                    "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
                    f"Path({str(pid)!r}).write_text(str(p.pid)); time.sleep(60)")
            child = self.launch(directory / "crash.json", code)
            # The host may be busy: the PID deadline starts after admission.
            self.assertIn(f"{CEILING}/{CEILING} slots".encode(), child.stdout.readline())
            deadline = time.monotonic() + 10
            while not pid.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(pid.exists())
            descendant = int(pid.read_text())
            child.kill()
            child.communicate(timeout=10)
            time.sleep(0.3)
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.OpenProcess.restype = ctypes.c_void_p
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
            handle = kernel.OpenProcess(0x1000, False, descendant)
            if handle:
                status = ctypes.c_ulong()
                self.assertTrue(kernel.GetExitCodeProcess(handle, ctypes.byref(status)))
                kernel.CloseHandle(handle)
                self.assertNotEqual(status.value, 259, "grandchild survived governor crash")
            followup = self.launch(directory / "after.json", "pass")
            self.finish(followup)
            self.assertEqual(json.loads((directory / "after.json").read_text())["slots"], CEILING)

    def test_invalid_job_assignment_never_runs_child(self):
        # A missing executable must fail and immediately release all leases.
        failed = subprocess.run([sys.executable, str(GOVERNOR), "--", "keyferry-nonexistent-build"],
                                capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertNotEqual(failed.returncode, 0)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as tmp:
            receipt = Path(tmp) / "after.json"
            followup = self.launch(receipt, "pass")
            self.finish(followup)
            self.assertEqual(json.loads(receipt.read_text())["slots"], CEILING)


if __name__ == "__main__":
    unittest.main()
