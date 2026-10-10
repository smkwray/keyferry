"""Bounded typing probe: random alphanumeric text, no Enter, metadata-only evidence.

With --shift-taps N it instead sends N single Shift taps (no text, no focus change, no Mac
access), each right after an exact-device status read, waiting --reverify-gap seconds before
every --reverify-every'th tap so the status read re-proves an aged holder first."""
import argparse
from datetime import datetime, timezone
import json
import secrets
import string
import subprocess
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keyctl", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--focus-host", help="Authorized Mac hosting the USB target")
    parser.add_argument("--shift-taps", type=int, default=0)
    parser.add_argument("--reverify-every", type=int, default=3)
    parser.add_argument("--reverify-gap", type=float, default=31.0)
    args = parser.parse_args()
    if not args.shift_taps and not args.focus_host:
        parser.error("--focus-host is required for the typing probe")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    output_lock = threading.Lock()

    def emit(**metadata):
        with output_lock:
            print(json.dumps(dict(utc=datetime.now(timezone.utc).isoformat(), **metadata)), flush=True)

    def run(command, text=None, timeout=75):
        return subprocess.run(command, input=text, capture_output=True, text=True,
                              timeout=timeout, creationflags=flags)

    def device():
        result = run([args.keyctl, "devices"], timeout=15)
        if result.returncode:
            raise RuntimeError("device status unavailable")
        value = json.loads(result.stdout)
        rows = value if isinstance(value, list) else value["devices"]
        return next(row for row in rows if row["id"] == args.device)

    def focus():
        script = ("osascript -e 'tell application \"iTerm\" to activate'\n"
                  "osascript -e 'tell application \"System Events\" to get name of first "
                  "application process whose frontmost is true'")
        result = run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                      args.focus_host, script], timeout=20)
        if result.returncode or result.stdout.strip() != "iTerm2":
            raise RuntimeError("iTerm focus could not be verified")

    def ready():
        result = run([args.keyctl, "status", args.device], timeout=15)
        if result.returncode:
            raise RuntimeError("exact-device status unavailable")
        row = json.loads(result.stdout)
        if (row["link"] != "authenticated" or row["armed"] or row.get("active_command_id")
                or row.get("firmware", {}).get("board_compatibility_id") != 1):
            raise RuntimeError("requires authenticated, disarmed, idle Waveshare")
        if row.get("link_path") != "tailnet":
            raise RuntimeError("probe requires a forwarded tailnet route")
        return row

    def command(index, operation, text):
        started = time.perf_counter()
        result = run([args.keyctl, operation, args.device], text)
        value = json.loads(result.stdout)
        receipt = {key: value.get(key) for key in (
            "command_id", "outcome", "terminal", "possible_start", "terminal_zero_confirmed",
            "terminal_release_completed", "output_transport", "diagnostic_code")}
        emit(sample=index, operation=operation, elapsed_seconds=round(time.perf_counter()-started, 3),
             exit_code=result.returncode, **receipt)
        if value.get("outcome") != "EMITTED" or not value.get("terminal_release_completed"):
            raise RuntimeError("probe stopped at failed or uncertain command; never replayed")

    stop = threading.Event()

    def observe():
        previous = None
        while not stop.is_set():
            try:
                row = device()
                state = {key: row.get(key) for key in ("link", "link_path", "via")}
            except (RuntimeError, ValueError, KeyError, StopIteration, subprocess.TimeoutExpired):
                state = dict(status="unavailable")
            if state != previous:
                emit(link=state)
                previous = state
            stop.wait(1)

    clear = json.dumps(dict(schema="keyferry.keyboard-sequence.v1", profile="windows-us",
                           arm="command-scoped", start_within_ms=5000,
                           actions=[dict(type="chord", keys=["LEFT_CONTROL", "U"])]))
    observer = threading.Thread(target=observe, daemon=True)
    if args.shift_taps:
        shift = json.dumps(dict(schema="keyferry.keyboard-sequence.v1", profile="windows-us",
                                arm="command-scoped", start_within_ms=5000,
                                actions=[dict(type="tap", key="LEFT_SHIFT")]))
        observer.start()
        try:
            for index in range(1, args.shift_taps + 1):
                if index % args.reverify_every == 0:
                    time.sleep(args.reverify_gap)
                ready()
                command(index, "sequence", shift)
            emit(completed=args.shift_taps, operation="shift_tap")
        finally:
            stop.set()
            observer.join(timeout=16)
        return
    ready()
    focus()
    observer.start()
    try:
        command(0, "sequence", clear)
        for index in range(1, 11):
            ready()
            focus()
            text = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(300))
            command(index, "type", text)
            focus()
            command(index, "sequence", clear)
        ready()
        emit(completed=10, characters_per_command=300)
    finally:
        stop.set()
        observer.join(timeout=16)


if __name__ == "__main__":
    main()
