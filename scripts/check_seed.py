#!/usr/bin/env python3
"""Dependency-free structural and golden-vector checks."""

from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_PATHS = [
    "README.md",
    "SECURITY.md",
    "protocol/protocol-v1.md",
    "protocol/keyboard-key-registry-v1.csv",
    "protocol/keyboard-sequence-v1.schema.json",
    "protocol/input-sequence-v1.schema.json",
    "protocol/messages.yaml",
    "scripts/gen_protocol.py",
    "crates/keyferry-protocol/src/lib.rs",
    "crates/keyferry-protocol/src/registry.rs",
    "firmware/common/include/keyferry_protocol_generated.h",
    "firmware/esp32s3/CMakeLists.txt",
    "firmware/esp32s3/IDF_VERSION",
    "firmware/esp32s3/dependencies.lock",
    "firmware/esp32s3/main/app_main.cpp",
    "scripts/check_qualification.py",
]

FORBIDDEN_SOURCE_TOKENS = {
    "setInsecure(": "TLS verification must never be disabled",
    "ESP8266WebServer": "the endpoint must not host a normal web server",
    "ESP8266HTTPUpdateServer": "version 1 must not expose OTA",
    "WiFiServer": "the dongle must not expose a generic inbound command listener",
    "runlivepayload": "stock ESPloit live-payload endpoints must not return",
    "ArduinoOTA": "version 1 must not expose OTA",
}

SOURCE_ROOTS = [
    ROOT / "apps",
    ROOT / "crates",
    ROOT / "firmware" / "esp32s3" / "main",
    ROOT / "firmware" / "esp32s3" / "components",
]

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)?$")
ID_RE = re.compile(r"^\s+(?:id|tag|bit):\s+(0x[0-9A-Fa-f]+|\d+)\s*$")
SECTION_RE = re.compile(r"^([a-z_]+):\s*$")
ITEM_NAME_RE = re.compile(r"^\s+- name:\s+([A-Z0-9_]+)\s*$")
KEY_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def cobs_encode(data: bytes) -> bytes:
    output = bytearray([0])
    code_index = 0
    code = 1
    for value in data:
        if value == 0:
            output[code_index] = code
            code_index = len(output)
            output.append(0)
            code = 1
        else:
            output.append(value)
            code += 1
            if code == 0xFF:
                output[code_index] = code
                code_index = len(output)
                output.append(0)
                code = 1
    output[code_index] = code
    return bytes(output)



def validate_generated_registry() -> None:
    try:
        subprocess.run(
            [sys.executable, str(ROOT / "scripts/gen_protocol.py"), "--check"],
            cwd=ROOT,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        fail(f"generated protocol constants are stale (exit {exc.returncode})")


def validate_shape() -> None:
    missing = [path for path in REQUIRED_PATHS if not (ROOT / path).is_file()]
    if missing:
        fail("missing required files: " + ", ".join(missing))


def validate_name() -> None:
    data = tomllib.loads((ROOT / "project.toml").read_text(encoding="utf-8"))
    name = data["working_name"]
    policy = data["name_policy"]
    if not NAME_RE.fullmatch(name):
        fail(f"working name violates lowercase name syntax: {name!r}")
    if not policy["minimum_length"] <= len(name) <= policy["maximum_length"]:
        fail(f"working name length is outside policy: {name!r}")
    if len(name) >= 10:
        fail(f"working name must be fewer than ten characters: {name!r}")


def validate_registry() -> None:
    lines = (ROOT / "protocol/messages.yaml").read_text(encoding="utf-8").splitlines()
    section = None
    item = None
    seen: dict[str, dict[int, str]] = {}
    count = 0
    for line in lines:
        section_match = SECTION_RE.match(line)
        if section_match:
            section = section_match.group(1)
            item = None
            continue
        item_match = ITEM_NAME_RE.match(line)
        if item_match:
            item = item_match.group(1)
            continue
        id_match = ID_RE.match(line)
        if id_match and section and item:
            value = int(id_match.group(1), 0)
            bucket = seen.setdefault(section, {})
            if value in bucket:
                fail(
                    f"duplicate numeric value in {section}: {item} and {bucket[value]} "
                    f"both use 0x{value:X}"
                )
            bucket[value] = item
            count += 1
    if count < 20:
        fail(f"protocol registry parsed too few numeric entries: {count}")


def validate_keyboard_sequence_contract() -> None:
    registry_path = ROOT / "protocol/keyboard-key-registry-v1.csv"
    registry_lines = [
        line for line in registry_path.read_text(encoding="utf-8").splitlines()
        if not line.startswith("#")
    ]
    rows = list(csv.DictReader(registry_lines))
    if len(rows) != 211:
        fail(f"keyboard key registry must contain 211 entries, found {len(rows)}")

    names: set[str] = set()
    usages: set[int] = set()
    modifiers: dict[str, int] = {}
    for row in rows:
        if set(row) != {"name", "class", "code", "portability"}:
            fail("keyboard key registry has an unexpected column set")
        name = row["name"]
        if not KEY_NAME_RE.fullmatch(name):
            fail(f"invalid canonical keyboard key name: {name!r}")
        if name in names:
            fail(f"duplicate canonical keyboard key name: {name}")
        names.add(name)
        try:
            code = int(row["code"], 0)
        except ValueError:
            fail(f"invalid keyboard key code for {name}")
        if row["portability"] not in {"boot-common", "report-extended"}:
            fail(f"invalid keyboard portability class for {name}")
        if row["class"] == "modifier":
            modifiers[name] = code
            if row["portability"] != "boot-common":
                fail(f"modifier must be boot-common: {name}")
        elif row["class"] == "non-modifier":
            allowed = (
                0x04 <= code <= 0x65
                or 0x67 <= code <= 0x7E
                or 0x82 <= code <= 0xA4
                or 0xB0 <= code <= 0xDD
            )
            if not allowed:
                fail(f"out-of-scope Keyboard/Keypad usage for {name}: 0x{code:02X}")
            if code in usages:
                fail(f"duplicate non-modifier usage: 0x{code:02X}")
            usages.add(code)
        else:
            fail(f"invalid keyboard key class for {name}")

    expected_modifiers = {
        "LEFT_CONTROL": 0x01,
        "LEFT_SHIFT": 0x02,
        "LEFT_ALT": 0x04,
        "LEFT_GUI": 0x08,
        "RIGHT_CONTROL": 0x10,
        "RIGHT_SHIFT": 0x20,
        "RIGHT_ALT": 0x40,
        "RIGHT_GUI": 0x80,
    }
    if modifiers != expected_modifiers:
        fail("keyboard modifier registry does not match the eight report bits")
    required = {
        "A", "Z", "DIGIT_0", "DIGIT_9", "ENTER", "ESCAPE", "TAB", "SPACE",
        "F1", "F12", "F13", "F24", "HOME", "DELETE", "RIGHT_ARROW",
        "KEYPAD_ENTER", "KEYPAD_0", "KEYPAD_9", "APPLICATION",
        "INTERNATIONAL_1", "INTERNATIONAL_9", "LANG_1", "LANG_9",
    }
    if missing := sorted(required - names):
        fail("keyboard key registry is missing required names: " + ", ".join(missing))
    forbidden_names = {
        "CTRL", "WIN", "CMD", "META", "RETURN", "POWER", "MUTE", "VOLUME_UP",
        "VOLUME_DOWN", "FN",
    }
    if present := sorted(forbidden_names & names):
        fail("keyboard key registry contains legacy or out-of-scope names: " + ", ".join(present))

    schema = json.loads(
        (ROOT / "protocol/keyboard-sequence-v1.schema.json").read_text(encoding="utf-8")
    )
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("keyboard sequence schema must use JSON Schema 2020-12")
    if schema.get("additionalProperties") is not False:
        fail("keyboard sequence envelope must reject unknown fields")
    required_envelope = {"schema", "command_id", "profile", "arm", "start_within_ms", "actions"}
    if set(schema.get("required", [])) != required_envelope:
        fail("keyboard sequence schema has the wrong required envelope fields")
    definitions = schema.get("$defs", {})
    for name in ("text_action", "tap_action", "chord_action", "wait_action", "repeat_action"):
        if definitions.get(name, {}).get("additionalProperties") is not False:
            fail(f"keyboard sequence {name} must reject variant-inapplicable fields")
    repeat_items = definitions["repeat_action"]["properties"]["actions"]["items"]
    if repeat_items != {"$ref": "#/$defs/non_repeat_action"}:
        fail("keyboard sequence repeat must reject nested repeats")


def validate_input_sequence_contract() -> None:
    schema = json.loads(
        (ROOT / "protocol/input-sequence-v1.schema.json").read_text(encoding="utf-8")
    )
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("input sequence schema must use JSON Schema 2020-12")
    if schema.get("additionalProperties") is not False:
        fail("input sequence envelope must reject unknown fields")
    required = {"schema", "command_id", "arm", "start_within_ms", "actions"}
    if set(schema.get("required", [])) != required:
        fail("input sequence schema has the wrong required envelope fields")
    definitions = schema.get("$defs", {})
    variants = (
        "text_action", "tap_action", "chord_action", "wait_action",
        "move_relative_action", "click_action", "repeat_action",
    )
    for name in variants:
        if definitions.get(name, {}).get("additionalProperties") is not False:
            fail(f"input sequence {name} must reject variant-inapplicable fields")
    repeat_items = definitions["repeat_action"]["properties"]["actions"]["items"]
    if repeat_items != {"$ref": "#/$defs/non_repeat_action"}:
        fail("input sequence repeat must reject nested repeats")
    buttons = definitions["click_action"]["properties"]["button"].get("enum")
    if buttons != ["button_1", "button_2"]:
        fail("input sequence exposes an unexpected mouse button set")
    movement = definitions["move_relative_action"]["properties"]
    for axis in ("dx_counts", "dy_counts"):
        if movement[axis].get("minimum") != -4096 or movement[axis].get("maximum") != 4096:
            fail(f"input sequence {axis} has the wrong bounds")


def validate_vectors() -> None:
    vector_files = sorted((ROOT / "protocol/vectors").glob("*.json"))
    if not vector_files:
        fail("no golden vectors found")
    for path in vector_files:
        data = json.loads(path.read_text(encoding="utf-8"))
        frame = data["frame"]
        payload = bytes.fromhex(frame["payload_hex"])
        message_type = int(frame["message_type"], 0)
        flags = int(frame["flags"], 0)
        sequence = int(frame["sequence"])
        header = (
            (0x4248).to_bytes(2, "little")
            + bytes([frame["major"], frame["minor"], message_type, flags])
            + sequence.to_bytes(4, "little")
            + len(payload).to_bytes(2, "little")
        )
        before_crc = header + payload
        decoded = before_crc + crc16_ccitt_false(before_crc).to_bytes(2, "little")
        wire = cobs_encode(decoded) + b"\x00"
        if decoded.hex() != data["decoded_hex"].lower():
            fail(f"decoded golden vector mismatch: {path.name}")
        if wire.hex() != data["wire_hex"].lower():
            fail(f"wire golden vector mismatch: {path.name}")
        if len(decoded) > 256:
            fail(f"golden vector exceeds decoded frame limit: {path.name}")


def iter_source_files():
    for base in SOURCE_ROOTS:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".rs", ".c", ".cc", ".cpp", ".h", ".hpp"}:
                yield path


def validate_forbidden_tokens() -> None:
    for path in iter_source_files():
        text = path.read_text(encoding="utf-8")
        for token, reason in FORBIDDEN_SOURCE_TOKENS.items():
            if token in text:
                fail(f"{path.relative_to(ROOT)} contains forbidden token {token!r}: {reason}")


def validate_firmware_guards() -> None:
    rel = "firmware/esp32s3/main/app_main.cpp"
    text = (ROOT / rel).read_text(encoding="utf-8")
    if "KEYFERRY_QUALIFICATION_IMAGE" not in text or "#error" not in text:
        fail(f"qualification image source guard missing from {rel}")


def main() -> None:
    validate_shape()
    validate_name()
    validate_registry()
    validate_keyboard_sequence_contract()
    validate_input_sequence_contract()
    validate_generated_registry()
    validate_vectors()
    validate_forbidden_tokens()
    validate_firmware_guards()
    print("check_seed: ok")


if __name__ == "__main__":
    main()
