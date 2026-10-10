"""Real Windows job/lease tests; no mocks of the safety boundary."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from scripts.build_governor import budget

ROOT = Path(__file__).resolve().parents[1]
GOVERNOR = ROOT / "scripts/build_governor.py"
PERCENT, CEILING = budget()


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
