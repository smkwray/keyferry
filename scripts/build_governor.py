#!/usr/bin/env python3
"""Headless Windows build tree, shared CPU ceiling and crash-safe slot leases.

Other hosts pass through. Nested entry points verify job membership rather than
trusting an environment flag. Windows handles release leases on process death.
budget() is the only reader of project.toml [build]; scripts use --budget.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
JOB_NAME = "Global\\KeyferryBuildCpuV1"


def budget(build: dict | None = None, host: str | None = None,
           cpus: int | None = None, *, root: Path = ROOT) -> tuple[int, int]:
    """(cpu_percent, job ceiling), with optional ignored project.local.toml host overrides."""
    if build is None:
        build = tomllib.loads((root / "project.toml").read_text())["build"]
        local = root / "project.local.toml"
        if local.exists():
            override = tomllib.loads(local.read_text())["build"]
            if set(override) != {"hosts"}:
                raise ValueError("project.local.toml [build] requires only a hosts table")
            build["hosts"] = {**build.get("hosts", {}), **override["hosts"]}
    host = (host or socket.gethostname()).split(".")[0].upper()
    hosts = {name.upper(): value for name, value in build.get("hosts", {}).items()}
    percent = hosts.get(host, build)["cpu_percent"]
    if type(percent) is not int or not 1 <= percent <= 100:
        raise ValueError("build cpu_percent must be an integer in 1..100")
    return percent, max(1, (cpus or os.cpu_count() or 1) * percent // 100)


if os.name == "nt":
    import msvcrt
    K = C.WinDLL("kernel32", use_last_error=True)

    class Accounting(C.Structure):
        _fields_ = [("user", C.c_int64), ("kernel", C.c_int64),
                    ("period_user", C.c_int64), ("period_kernel", C.c_int64),
                    ("faults", W.DWORD), ("total", W.DWORD),
                    ("active", W.DWORD), ("terminated", W.DWORD)]

    class Limits(C.Structure):
        _fields_ = [("process_time", C.c_int64), ("job_time", C.c_int64),
                    ("flags", W.DWORD), ("min_ws", C.c_size_t),
                    ("max_ws", C.c_size_t), ("active", W.DWORD),
                    ("affinity", C.c_size_t), ("priority", W.DWORD),
                    ("scheduling", W.DWORD)]

    class Extended(C.Structure):
        _fields_ = [("limits", Limits), ("io", C.c_uint64 * 6),
                    ("process_memory", C.c_size_t), ("job_memory", C.c_size_t),
                    ("peak_process", C.c_size_t), ("peak_job", C.c_size_t)]

    class Cpu(C.Structure):
        _fields_ = [("flags", W.DWORD), ("rate", W.DWORD)]

    class Startup(C.Structure):
        _fields_ = [("cb", W.DWORD), ("reserved", W.LPWSTR), ("desktop", W.LPWSTR),
                    ("title", W.LPWSTR), ("x", W.DWORD), ("y", W.DWORD),
                    ("x_size", W.DWORD), ("y_size", W.DWORD),
                    ("x_chars", W.DWORD), ("y_chars", W.DWORD),
                    ("fill", W.DWORD), ("flags", W.DWORD),
                    ("show", W.WORD), ("reserved_size", W.WORD),
                    ("reserved_bytes", C.c_void_p), ("stdin", W.HANDLE),
                    ("stdout", W.HANDLE), ("stderr", W.HANDLE)]

    class StartupEx(C.Structure):
        _fields_ = [("startup", Startup), ("attributes", C.c_void_p)]

    class ProcessInfo(C.Structure):
        _fields_ = [("process", W.HANDLE), ("thread", W.HANDLE),
                    ("pid", W.DWORD), ("tid", W.DWORD)]

    for name, args, result in [
        ("CreateJobObjectW", [C.c_void_p, W.LPCWSTR], W.HANDLE),
        ("OpenJobObjectW", [W.DWORD, W.BOOL, W.LPCWSTR], W.HANDLE),
        ("GetCurrentProcess", [], W.HANDLE),
        ("IsProcessInJob", [W.HANDLE, W.HANDLE, C.POINTER(W.BOOL)], W.BOOL),
        ("SetInformationJobObject", [W.HANDLE, C.c_int, C.c_void_p, W.DWORD], W.BOOL),
        ("QueryInformationJobObject", [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p], W.BOOL),
        ("InitializeProcThreadAttributeList", [C.c_void_p, W.DWORD, W.DWORD, C.POINTER(C.c_size_t)], W.BOOL),
        ("UpdateProcThreadAttribute", [C.c_void_p, W.DWORD, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p], W.BOOL),
        ("DeleteProcThreadAttributeList", [C.c_void_p], None),
        ("CreateProcessW", [W.LPCWSTR, W.LPWSTR, C.c_void_p, C.c_void_p, W.BOOL,
                            W.DWORD, C.c_void_p, W.LPCWSTR, C.c_void_p, C.POINTER(ProcessInfo)], W.BOOL),
        ("WaitForSingleObject", [W.HANDLE, W.DWORD], W.DWORD),
        ("GetExitCodeProcess", [W.HANDLE, C.POINTER(W.DWORD)], W.BOOL),
        ("TerminateProcess", [W.HANDLE, W.UINT], W.BOOL),
        ("CloseHandle", [W.HANDLE], W.BOOL),
    ]:
        fn = getattr(K, name)
        fn.argtypes, fn.restype = args, result

    def checked(ok):
        if not ok:
            raise C.WinError(C.get_last_error())
        return ok


def governed() -> bool:
    if os.name != "nt":
        return True
    handle = K.OpenJobObjectW(4, False, JOB_NAME)
    if not handle:
        return False
    try:
        inside = W.BOOL()
        checked(K.IsProcessInJob(K.GetCurrentProcess(), handle, C.byref(inside)))
        return bool(inside.value)
    finally:
        K.CloseHandle(handle)


def run(command: list[str], receipt: Path | None = None) -> int:
    if os.name != "nt" or governed():
        return subprocess.call(command)
    percent, ceiling = budget()
    requested = min(ceiling, max(1, int(os.environ.get("CARGO_BUILD_JOBS", ceiling))))
    directory = Path("C:/tools/keyferry-build-slots")
    directory.mkdir(exist_ok=True)
    leases = []
    handles = []
    process = thread_handle = None
    start = time.perf_counter()
    try:
        # Grant available slots immediately, at least one. Never hold a partial
        # budget while waiting for more slots, which would deadlock other lanes.
        while not leases:
            for slot in range(ceiling):
                file = (directory / f"slot-{slot}.lock").open("a+b")
                file.seek(0)
                try:
                    msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
                    leases.append(file)
                except OSError:
                    file.close()
                if len(leases) == requested:
                    break
            if not leases:
                time.sleep(0.2)
        queue_seconds = time.perf_counter() - start
        start = time.perf_counter()
        shared = checked(K.CreateJobObjectW(None, JOB_NAME))
        handles.append(shared)
        cpu = Cpu(5, percent * 100)  # ENABLE | HARD_CAP, aggregate across lanes
        checked(K.SetInformationJobObject(shared, 15, C.byref(cpu), C.sizeof(cpu)))
        job = checked(K.CreateJobObjectW(None, None))
        handles.append(job)
        limits = Extended()
        limits.limits.flags = 0x2000  # KILL_ON_JOB_CLOSE, includes grandchildren
        checked(K.SetInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits)))
        env = os.environ.copy()
        env.update(CARGO_BUILD_JOBS=str(len(leases)), CTEST_PARALLEL_LEVEL=str(len(leases)),
                   IDF_PY_BUILD_JOBS=str(len(leases)), KEYFERRY_BUILD_SLOTS=str(len(leases)))
        info = StartupEx()
        info.startup.cb = C.sizeof(info)
        info.startup.flags = 0x100  # STARTF_USESTDHANDLES
        info.startup.stdin = msvcrt.get_osfhandle(sys.stdin.fileno())
        info.startup.stdout = msvcrt.get_osfhandle(sys.stdout.fileno())
        info.startup.stderr = msvcrt.get_osfhandle(sys.stderr.fileno())
        executable = __import__("shutil").which(command[0])
        if not executable:
            raise FileNotFoundError(command[0])
        size = C.c_size_t()
        K.InitializeProcThreadAttributeList(None, 1, 0, C.byref(size))
        attributes = C.create_string_buffer(size.value)
        checked(K.InitializeProcThreadAttributeList(attributes, 1, 0, C.byref(size)))
        info.attributes = C.cast(attributes, C.c_void_p)
        jobs = (W.HANDLE * 2)(shared, job)
        try:
            # Atomic assignment eliminates the crash window between a suspended
            # CreateProcess and AssignProcessToJobObject. Windows 10+ JOB_LIST.
            checked(K.UpdateProcThreadAttribute(attributes, 0, 0x2000D,
                                                jobs, C.sizeof(jobs), None, None))
            environment = C.create_unicode_buffer("\0".join(f"{k}={v}" for k, v in sorted(env.items())) + "\0\0")
            result = ProcessInfo()
            # BELOW_NORMAL priority keeps interactive KVM/capture work responsive.
            # BREAKAWAY avoids nesting the shared host job under a caller's
            # temporary job (e.g. an agent tool). Denial fails closed.
            checked(K.CreateProcessW(executable, C.create_unicode_buffer(subprocess.list2cmdline(command)),
                                     None, None, True, 0x09084400, environment, None,
                                     C.byref(info), C.byref(result)))
            process, thread_handle = result.process, result.thread
        finally:
            K.DeleteProcThreadAttributeList(attributes)
        print(f"build governor: {len(leases)}/{ceiling} slots, host CPU cap {percent}%", flush=True)
        while True:
            wait = K.WaitForSingleObject(process, 200)
            if wait == 0:
                break
            if wait != 258:
                raise C.WinError(C.get_last_error())
        # A completed/crashed build launcher must not leave detached work behind.
        # Closing the private job below kills any remaining descendants.
        accounting = Accounting()
        checked(K.QueryInformationJobObject(job, 1, C.byref(accounting), C.sizeof(accounting), None))
        memory = Extended()
        checked(K.QueryInformationJobObject(job, 9, C.byref(memory), C.sizeof(memory), None))
        code = W.DWORD()
        checked(K.GetExitCodeProcess(process, C.byref(code)))
        data = dict(command=command, host=socket.gethostname(), slots=len(leases),
                    cpu_percent=percent, queue_seconds=round(queue_seconds, 3),
                    wall_seconds=round(time.perf_counter() - start, 3),
                    cpu_seconds=round((accounting.user + accounting.kernel) / 10_000_000, 3),
                    peak_memory_mib=memory.peak_job // 2**20, exit_code=code.value)
        print("build measurement: " + json.dumps(data), flush=True)
        if receipt:
            receipt.parent.mkdir(parents=True, exist_ok=True)
            receipt.write_text(json.dumps(data, indent=2) + "\n")
        return code.value
    finally:
        if process:
            K.TerminateProcess(process, 1)  # harmless if already exited
        for handle in reversed(handles):
            K.CloseHandle(handle)
        for handle in (thread_handle, process):
            if handle:
                K.CloseHandle(handle)
        for file in leases:
            file.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--budget", action="store_true",
                        help="print this host's cpu_percent and job ceiling")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.probe:
        raise SystemExit(0 if governed() else 1)
    if args.budget:
        print(*budget())
        raise SystemExit(0)
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a command is required")
    raise SystemExit(run(command, args.receipt))


if __name__ == "__main__":
    main()
