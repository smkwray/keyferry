#!/usr/bin/env python3
"""Read-only MCP capture/OCR smoke. Never controls a device or retains screen content."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keyctl", type=Path, required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    requests = [
        {"id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "keyferry-readonly-smoke", "version": "1"}}},
        {"method": "notifications/initialized"},
        {"id": 2, "method": "tools/call", "params": {"name": "screenshot", "arguments": {}}},
        {"id": 3, "method": "tools/call", "params": {
            "name": "wait_for_stable", "arguments": {"timeout_ms": 3000}}},
        {"id": 4, "method": "tools/call", "params": {"name": "find_text", "arguments": {}}},
        {"id": 5, "method": "tools/call", "params": {"name": "status", "arguments": {}}},
    ]
    encoded = "".join(json.dumps({"jsonrpc": "2.0", **r}) + "\n" for r in requests)
    # Port 9 and a nonexistent token make real daemon/device contact impossible.
    with tempfile.TemporaryDirectory(prefix="kf-mcp-readonly-") as temporary:
        process = subprocess.Popen([
            str(args.keyctl), "--url", "http://127.0.0.1:9", "--token-file",
            str(Path(temporary) / "missing-token"), "mcp", "--device",
            "00000000-0000-0000-0000-000000000000", "--source", args.source,
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Content stays in process memory. Never write stdout/stderr or OCR strings to evidence.
        try:
            output, diagnostic = process.communicate(encoded.encode(), timeout=90)
        except subprocess.TimeoutExpired:
            # End only this smoke's process tree, including capture launchers.
            import os
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            process.kill()
            process.communicate()
            print(json.dumps({"producer": "scripts/smoke_agent_kvm.py", "error": "smoke.timeout"}))
            raise SystemExit(1) from None
    responses = {r.get("id"): r for r in map(json.loads, output.splitlines())}
    summary = {
        "producer": "scripts/smoke_agent_kvm.py",
        "keyctl_sha256": hashlib.sha256(args.keyctl.read_bytes()).hexdigest(),
        "exit": process.returncode, "stderr_present": bool(diagnostic),
        "response_count": len(responses), "results": {},
    }
    for index, name in [(2, "screenshot"), (3, "wait_for_stable"), (4, "find_text"), (5, "status")]:
        response = responses.get(index, {})
        result = response.get("result", {})
        structured = result.get("structuredContent", {})
        item = {"isError": result.get("isError", True)}
        if result.get("isError"):
            item["error_code"] = structured.get("error", {}).get("code")
        elif name == "screenshot":
            item.update({k: structured.get(k) for k in (
                "width", "height", "native_width", "native_height", "capture_generation")})
            item["png_image_present"] = any(c.get("type") == "image" and c.get("mimeType") == "image/png"
                                            for c in result.get("content", []))
        elif name == "wait_for_stable":
            item.update({k: structured.get(k) for k in ("matched", "timed_out", "frames", "elapsed_ms")})
        elif name == "find_text":
            item["box_count"] = len(structured.get("boxes", []))
        elif name == "status":
            item["capture"] = {k: structured.get("capture", {}).get(k)
                               for k in ("generation", "restarts", "error", "last_failure")}
            item["device_error_code"] = (structured.get("device_error") or {}).get("code")
        summary["results"][name] = item
    print(json.dumps(summary, indent=2))
    success = process.returncode == 0 and len(responses) == 5 and all(
        not r["isError"] for r in summary["results"].values())
    raise SystemExit(0 if success else 1)


if __name__ == "__main__":
    main()
