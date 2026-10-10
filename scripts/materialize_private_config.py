#!/usr/bin/env python3
"""Refresh a private firmware header only when its validated inputs change."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid


def inputs(root: Path, bundle: Path) -> list[Path]:
    device = json.loads((bundle / "firmware/device.json").read_text())
    device_id = uuid.UUID(device["device_id"]).hex
    names = ["firmware/device.json", "firmware/wifi.json", "firmware/host-cert.der",
             "firmware/host-spki.der", "keyferryd/runtime.json", "recovery/secret.bin",
             "keyferryd/secrets/host-id", "keyferryd/secrets/host-key.der",
             "keyferryd/secrets/host-cert.der", f"keyferryd/secrets/pairings/{device_id}.link"]
    paths = [bundle / name for name in names]
    paths += [root / "Cargo.lock", root / "Cargo.toml", root / "rust-toolchain.toml",
              Path(__file__).resolve()]
    for package in ["tools/keyferry-pairing", "crates/keyferry-core", "crates/keyferry-gateway",
                    "crates/keyferry-local-management", "crates/keyferry-protocol"]:
        paths.append(root / package / "Cargo.toml")
        paths.extend(sorted((root / package / "src").rglob("*.rs")))
    return paths


def materialize(root: Path, bundle: Path, output: Path) -> bool:
    paths = inputs(root, bundle)
    digest = hashlib.sha256()
    for path in paths:
        data = path.read_bytes()  # Missing inputs always fail, even with a stamp.
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("Materialization input exceeds its size ceiling")
        digest.update(str(path).encode())
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    identity = digest.hexdigest()
    stamp = output / "materialize.stamp"
    header = output / "keyferry_hil_private.h"
    if stamp.is_file() and header.is_file():
        recorded = json.loads(stamp.read_text())
        if (recorded["inputs"] == identity and
                recorded["output"] == hashlib.sha256(header.read_bytes()).hexdigest()):
            stamp.touch()  # Also settle unchanged-but-touched Ninja dependencies.
            return False
    env = os.environ.copy()
    env["KEYFERRY_PAIRING_OUTPUT_DIR"] = str(output)
    subprocess.run([env.get("KEYFERRY_CARGO_EXECUTABLE", "cargo"), "run", "--locked", "--offline",
                    "--quiet", "-p", "keyferry-pairing", "--", "--bundle", str(bundle), "materialize"],
                   cwd=root, env=env, check=True,
                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    result = {"inputs": identity, "output": hashlib.sha256(header.read_bytes()).hexdigest()}
    temp = stamp.with_suffix(".tmp")
    temp.write_text(json.dumps(result) + "\n")
    temp.replace(stamp)
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bundle = Path(os.environ.get("KEYFERRY_PAIRING_BUNDLE", args.root / "secrets/first-hil"))
    materialize(args.root.resolve(), bundle.resolve(), args.output.resolve())
