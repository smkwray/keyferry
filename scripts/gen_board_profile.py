#!/usr/bin/env python3
"""Validate one declarative ESP32-S3 board profile and emit its C++ view."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA = "keyferry.board-profile.v1"
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_]*$")
CONTROLLERS = {"st7735", "st7789"}
PRESENTATIONS = {"compact", "normal"}


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate field: {key}")
        result[key] = value
    return result


def exact_fields(value: Any, fields: set[str], location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{location} must be an object")
    actual = set(value)
    if actual != fields:
        missing = sorted(fields - actual)
        unknown = sorted(actual - fields)
        raise ValueError(
            f"{location} fields differ; missing={missing!r} unknown={unknown!r}"
        )
    return value


def integer(value: Any, minimum: int, maximum: int, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{location} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{location} must be in {minimum}..{maximum}")
    return value


def boolean(value: Any, location: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{location} must be boolean")
    return value


def load_profile(path: Path) -> dict[str, Any]:
    profile = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    exact_fields(
        profile,
        {
            "schema",
            "id",
            "compatibility_id",
            "qualified",
            "flash",
            "display",
            "capabilities",
            "pins",
        },
        "profile",
    )
    if profile["schema"] != SCHEMA:
        raise ValueError(f"schema must be {SCHEMA}")
    if not isinstance(profile["id"], str) or not IDENTIFIER.fullmatch(profile["id"]):
        raise ValueError("id must be a lowercase underscore identifier")
    integer(profile["compatibility_id"], 1, 0xFFFF_FFFF, "compatibility_id")
    boolean(profile["qualified"], "qualified")

    flash = exact_fields(profile["flash"], {"size_mb"}, "flash")
    integer(flash["size_mb"], 2, 32, "flash.size_mb")

    display = exact_fields(
        profile["display"],
        {
            "present",
            "controller",
            "presentation",
            "dc_gpio",
            "cs_gpio",
            "clk_gpio",
            "mosi_gpio",
            "reset_gpio",
            "backlight_gpio",
            "width",
            "height",
            "x_gap",
            "y_gap",
            "madctl",
            "invert_colors",
            "swap_color_bytes",
            "backlight_active_high",
            "backlight_percent",
            "pixel_clock_hz",
        },
        "display",
    )
    boolean(display["present"], "display.present")
    if display["controller"] not in CONTROLLERS:
        raise ValueError(f"display.controller must be one of {sorted(CONTROLLERS)!r}")
    if display["presentation"] not in PRESENTATIONS:
        raise ValueError(
            f"display.presentation must be one of {sorted(PRESENTATIONS)!r}"
        )
    for field in ("dc_gpio", "cs_gpio", "clk_gpio", "mosi_gpio", "reset_gpio", "backlight_gpio"):
        integer(display[field], 0, 48, f"display.{field}")
    integer(display["width"], 1, 320, "display.width")
    integer(display["height"], 1, 320, "display.height")
    integer(display["x_gap"], 0, 320, "display.x_gap")
    integer(display["y_gap"], 0, 320, "display.y_gap")
    integer(display["madctl"], 0, 255, "display.madctl")
    boolean(display["invert_colors"], "display.invert_colors")
    boolean(display["swap_color_bytes"], "display.swap_color_bytes")
    boolean(display["backlight_active_high"], "display.backlight_active_high")
    integer(display["backlight_percent"], 1, 100, "display.backlight_percent")
    integer(display["pixel_clock_hz"], 1_000_000, 40_000_000, "display.pixel_clock_hz")

    capabilities = exact_fields(
        profile["capabilities"],
        {"display", "touch", "button", "led", "removable_storage", "uart0_header"},
        "capabilities",
    )
    for field, value in capabilities.items():
        boolean(value, f"capabilities.{field}")
    if capabilities["display"] != display["present"]:
        raise ValueError("capabilities.display must equal display.present")

    pins = exact_fields(
        profile["pins"],
        {"usb_dm_gpio", "usb_dp_gpio", "boot_gpio", "uart0_rx_gpio", "uart0_tx_gpio"},
        "pins",
    )
    for field, value in pins.items():
        integer(value, 0, 48, f"pins.{field}")
    return profile


def cpp_bool(value: bool) -> str:
    return "true" if value else "false"


def render(profile: dict[str, Any], source: Path) -> str:
    display = profile["display"]
    capabilities = profile["capabilities"]
    pins = profile["pins"]
    controller = "kSt7735" if display["controller"] == "st7735" else "kSt7789"
    presentation = "kCompact" if display["presentation"] == "compact" else "kNormal"
    values = ",\n    ".join(
        [
            f"{cpp_bool(display['present'])}",
            f"DisplayController::{controller}",
            f"DisplayPresentation::{presentation}",
            f"{display['dc_gpio']}, {display['cs_gpio']}, {display['clk_gpio']}, {display['mosi_gpio']}",
            f"{display['reset_gpio']}, {display['backlight_gpio']}",
            f"{display['width']}, {display['height']}, {display['x_gap']}, {display['y_gap']}",
            f"0x{display['madctl']:02X}",
            f"{cpp_bool(display['invert_colors'])}, {cpp_bool(display['swap_color_bytes'])}",
            f"{cpp_bool(display['backlight_active_high'])}",
            f"{display['backlight_percent']}, {display['pixel_clock_hz']}U",
        ]
    )
    return f"""// Generated from {source.name}; do not edit.
#pragma once

#include <cstdint>

namespace keyferry::board {{

enum class DisplayController : std::uint8_t {{ kSt7735, kSt7789 }};
enum class DisplayPresentation : std::uint8_t {{ kNormal, kCompact }};

struct DisplayProfile {{
  bool present;
  DisplayController controller;
  DisplayPresentation presentation;
  std::int32_t dc_gpio;
  std::int32_t cs_gpio;
  std::int32_t clk_gpio;
  std::int32_t mosi_gpio;
  std::int32_t reset_gpio;
  std::int32_t backlight_gpio;
  std::int32_t width;
  std::int32_t height;
  std::int32_t x_gap;
  std::int32_t y_gap;
  std::uint8_t madctl;
  bool invert_colors;
  bool swap_color_bytes;
  bool backlight_active_high;
  std::uint32_t backlight_percent;
  std::uint32_t pixel_clock_hz;
}};

struct Capabilities {{
  bool display;
  bool touch;
  bool button;
  bool led;
  bool removable_storage;
  bool uart0_header;
}};

inline constexpr char id[] = "{profile['id']}";
inline constexpr std::uint32_t compatibility_id = {profile['compatibility_id']}U;
inline constexpr bool qualified = {cpp_bool(profile['qualified'])};
inline constexpr std::uint32_t flash_size_mb = {profile['flash']['size_mb']}U;
inline constexpr DisplayProfile display{{
    {values},
}};
inline constexpr Capabilities capabilities{{
    {cpp_bool(capabilities['display'])},
    {cpp_bool(capabilities['touch'])},
    {cpp_bool(capabilities['button'])},
    {cpp_bool(capabilities['led'])},
    {cpp_bool(capabilities['removable_storage'])},
    {cpp_bool(capabilities['uart0_header'])},
}};
inline constexpr std::int32_t usb_dm_gpio = {pins['usb_dm_gpio']};
inline constexpr std::int32_t usb_dp_gpio = {pins['usb_dp_gpio']};
inline constexpr std::int32_t boot_gpio = {pins['boot_gpio']};
inline constexpr std::int32_t uart0_rx_gpio = {pins['uart0_rx_gpio']};
inline constexpr std::int32_t uart0_tx_gpio = {pins['uart0_tx_gpio']};

}}  // namespace keyferry::board
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    profile = load_profile(args.input)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(render(profile, args.input), encoding="utf-8", newline="\n")
    print(f"board profile ok: {profile['id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
