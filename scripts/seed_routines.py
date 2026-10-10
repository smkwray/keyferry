#!/usr/bin/env python3
"""Install initial recipes and concise discovery wiring into a named synced keyferry skill.

Existing routines are preserved. Agents grow the shared library with routine_save, not this script.
"""
import argparse
import json
from pathlib import Path


def seeds():
    def text(name, description, max_chars=128, **extra):
        return {"name": name, "type": "text", "description": description,
                "max_chars": max_chars, **extra}

    def integer(name, description, minimum, maximum):
        return {"name": name, "type": "integer", "description": description,
                "minimum": minimum, "maximum": maximum}

    def key(*keys):
        return {"type": "key", "keys": list(keys)}

    def typing(value):
        return {"type": "type_text", "text": value}

    def wait(ms):
        return {"type": "wait", "ms": ms}

    def change():
        return {"type": "wait_for_change", "timeout_ms": 10000, "on_fail": "stop"}

    def recipe(name, description, os, parameters, steps, tags):
        return {"schema": "keyferry.recipe.v1", "name": name, "description": description,
                "target_os": os, "parameters": parameters, "tags": tags,
                "verified": False, "author": "Initial construction; live verification pending",
                "steps": steps}

    return [
        recipe("macos-open-app", "Open a named app through Spotlight; inspect the resulting screen.",
               "macos", [text("app", "Application name")],
               [key("CMD", "SPACE"), wait(400), typing("{app}"), key("ENTER"), change()],
               ["navigation", "app"]),
        recipe("macos-settings-search", "Open System Settings and search for a pane; inspect results.",
               "macos", [text("pane", "Settings search phrase")],
               [key("CMD", "SPACE"), wait(400), typing("System Settings"), key("ENTER"), change(),
                {"type": "wait_for_stable", "timeout_ms": 10000}, key("CMD", "F"),
                typing("{pane}"), change()], ["navigation", "settings"]),
        recipe("macos-lock-screen", "Lock the target session with Control-Command-Q.", "macos", [],
               [key("CTRL", "CMD", "Q"), change()], ["session", "lock"]),
        recipe("windows-settings-page", "Open a documented ms-settings URI page through Run.",
               "windows", [text("page", "ms-settings page suffix", pattern="[a-z0-9-]+")],
               [key("LEFT_GUI", "R"), wait(300), typing("ms-settings:{page}"), key("ENTER"), change()],
               ["navigation", "settings"]),
        recipe("windows-run-command", "Run an ordinary non-secret command through the Run dialog.",
               "windows", [text("command", "Reviewed Run dialog command", 256)],
               [key("LEFT_GUI", "R"), wait(300), typing("{command}"), key("ENTER"), change()],
               ["navigation", "app"]),
        recipe("clear-stacked-dialogs", "Dismiss up to 32 stacked prompts with Escape and a bounded delay.",
               "any", [integer("count", "Number of Escape taps", 1, 32),
                       integer("delay_ms", "Delay between taps in milliseconds", 0, 1000)],
               [{"type": "repeat", "count": "{count}", "delay_ms": "{delay_ms}",
                 "steps": [key("ESCAPE")]}], ["dialogs", "batch"]),
        recipe("select-all-copy", "Select all and copy in the focused control (Windows/Linux shortcuts).",
               "windows", [], [key("CTRL", "A"), key("CTRL", "C")], ["clipboard"]),
        recipe("linux-select-all-copy", "Select all and copy in the focused Linux control.",
               "linux", [], [key("CTRL", "A"), key("CTRL", "C")], ["clipboard"]),
        recipe("macos-select-all-copy", "Select all and copy in the focused macOS control.",
               "macos", [], [key("CMD", "A"), key("CMD", "C")], ["clipboard"]),
        recipe("unlock-secure-text", "Click the password field and request owner text; optional desktop marker.",
               "any", [integer("field_x", "Password field screenshot x", 0, 1279),
                       integer("field_y", "Password field screenshot y", 0, 1279),
                       text("desktop_marker", "Optional visible desktop marker after owner unlock", optional=True)],
               [{"type": "click", "x": "{field_x}", "y": "{field_y}"}, {"type": "secure_text"},
                {"type": "expect_text", "query": "{desktop_marker}", "timeout_ms": 30000,
                 "optional": True, "on_fail": "stop"}], ["session", "secure-text"]),
    ]


ROUTINES_SECTION = """## Routines

Check MCP `routines` before improvising a known task (search by query, target OS or tag).
`routine_run(name, params)` merges contiguous input into one bounded command, checks the screen
between stretches, stops on failure/UNKNOWN, and returns receipts plus one final screenshot.
Seeds are `verified:false` until observed live; OS scope describes the target, not the controller.
After a new manual flow succeeds, use `routine_save(definition)` to generalize its parameters and
add checkpoints. Exclusive create is the default; `replace:true` deliberately updates an entry.
Shared `routines/*.json` sync with this skill; private `keyctl recipe import` entries override by name.
CLI parity: `keyctl routine list|run|save|validate`; format/bounds: README's recipe protocol link.
For ad-hoc repetitions use `batch` with per-action `repeat`, `delay_ms`, and optional `settle`.
Passwords only via a routine `secure_text` step / the owner-only dialog, never saved literals or
ordinary params. REQUESTED/awaiting_owner means inspect and wait for the owner, never replay input.

"""


def install(skill):
    library = skill / "routines"
    library.mkdir(exist_ok=True)
    for definition in seeds():
        path = library / (definition["name"] + ".json")
        try:
            with path.open("x", encoding="utf-8", newline="\n") as output:
                json.dump(definition, output, indent=2)
                output.write("\n")
        except FileExistsError:
            continue
    doc = skill / "SKILL.md"
    content = doc.read_text(encoding="utf-8")
    if "## Routines\n" not in content:
        content = content.replace("## Secure text", ROUTINES_SECTION + "## Secure text", 1)
        doc.write_text(content, encoding="utf-8", newline="\n")
    for name in ["keyferry-mcp", "keyferry-mcp.cmd"]:
        launcher = skill / "bin" / name
        content = launcher.read_text(encoding="utf-8")
        if "KEYFERRY_ROUTINE_DIR" not in content:
            if name.endswith(".cmd"):
                content = content.replace("setlocal\n", 'setlocal\nif not defined KEYFERRY_ROUTINE_DIR set "KEYFERRY_ROUTINE_DIR=%~dp0..\\routines"\n', 1)
            else:
                content = content.replace('exec "$keyferry_keyctl"',
                    'keyferry_skill_dir=$(CDPATH= cd "$(dirname "$0")/.." && pwd) || exit 1\n'
                    'export KEYFERRY_ROUTINE_DIR=${KEYFERRY_ROUTINE_DIR:-"$keyferry_skill_dir/routines"}\n'
                    'exec "$keyferry_keyctl"', 1)
            launcher.write_text(content, encoding="utf-8", newline="\n")
    print(f"Routine seeds installed/preserved: {len(seeds())}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill-dir", type=Path, required=True)
    install(parser.parse_args().skill_dir)
