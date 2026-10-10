"""Check the opt-in report-ID pointer personalities; legacy checker stays separate.

Two IF2 personalities exist. Relative+absolute (reports 1 and 4, pointer.9 bytes) is the
Windows image. Absolute-only (report 4 alone, bcdDevice 0105) is the macOS image: Apple's
DriverKit IOUserHIDEventDriver gives Button elements to the relative pointer whenever the
interface declares relative X/Y, so absolute events carry no buttons and every absolute move
releases a drag (pointer.6); a Digitizer collection is dispatched as digitizer events that
never move the cursor (pointer.9).
"""
import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
STYLUS = (0x0D, 0x20, 2)  # Digitizer page, Stylus usage, Logical collection
SOURCE = ROOT / "firmware/esp32s3/hil_endpoint/main/app_main.cpp"
ARRAYS = {False: "kPointerReportDescriptor", True: "kAbsolutePointerReportDescriptor"}
REVISIONS = {False: 0x0104, True: 0x0105}


def require(condition, message):
    if not condition:
        raise SystemExit("pointer check: " + message)


def source_descriptor(source, absolute_only):
    body = re.search(ARRAYS[absolute_only] + r"\[\]\s*=\s*\{(.*?)\};", source, re.S)
    require(body is not None, "missing closed pointer descriptor")
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", body[1]))


def parse(data):
    """Parse HID short items, preserving globals across collections/report IDs."""
    report_id = 0
    size = count = page = minimum = maximum = 0
    usage = []
    usage_minimum = usage_maximum = None
    collections = []
    fields = {}
    bits = {}
    axes = {}
    nested = {}
    offset = 0
    while offset < len(data):
        prefix = data[offset]
        offset += 1
        n = (0, 1, 2, 4)[prefix & 3]
        require(prefix != 0xFE and offset + n <= len(data), "malformed HID item")
        raw = data[offset:offset+n]
        value = int.from_bytes(raw, "little")
        offset += n
        tag = prefix & 0xFC
        if tag == 0x84: report_id = value
        elif tag == 0x74: size = value
        elif tag == 0x94: count = value
        elif tag == 0x04: page = value
        elif tag == 0x14: minimum = int.from_bytes(raw, "little", signed=True)
        elif tag == 0x24: maximum = int.from_bytes(raw, "little", signed=minimum < 0)
        elif tag == 0x08: usage.append((page, value))
        elif tag == 0x18: usage_minimum = value
        elif tag == 0x28: usage_maximum = value
        elif tag == 0x80:
            require(collections[:2] == [(1, 2, 1), (1, 1, 0)],
                    "each report must be Pointer physical inside Mouse application")
            require(collections[2:] in ([], [STYLUS]), "unexpected nested collection")
            fields.setdefault(report_id, []).append((
                bits.get(report_id, 0), page, size, count, minimum, maximum,
                value, usage_minimum, usage_maximum))
            nested.setdefault(report_id, []).append(collections[2:] == [STYLUS])
            bits[report_id] = bits.get(report_id, 0) + size * count
            for p, u in usage:
                if (p == 1 and u in (0x30, 0x31, 0x38)) or (p == 0x0C and u == 0x0238):
                    axes[(report_id, p, u)] = (minimum, maximum, size, value,
                                               bits[report_id] - size * count, count)
            usage.clear()
            usage_minimum = usage_maximum = None
        elif tag == 0xA0:
            require(len(usage) == 1, "collection must have one usage")
            collections.append((*usage[0], value))
            usage.clear()
            usage_minimum = usage_maximum = None
        elif tag == 0xC0:
            require(bool(collections), "unbalanced collection")
            collections.pop()
            usage.clear()
            usage_minimum = usage_maximum = None
        elif tag in (0x90, 0xB0): require(False, "unexpected output or feature report")
    require(not collections, "unclosed collection")
    return fields, bits, axes, nested


def check_report4(fields, axes, wheel_offset, wheel_count):
    for report_id in sorted(fields):
        require(fields[report_id][0] == (0, 9, 1, 5, 0, 1, 2, 1, 5),
                f"report {report_id} must start with five 0..1 button bits")
        require(fields[report_id][1] == (5, 9, 3, 1, 0, 1, 3, None, None),
                f"report {report_id} must pad the button byte with three constant bits")
    for axis in (0x30, 0x31):
        require(axes.get((4, 1, axis)) == (0, 32767, 16, 2, 8, 2), "absolute Generic Desktop axis differs")
    require(axes.get((4, 1, 0x38)) == (-127, 127, 8, 6, wheel_offset, wheel_count),
            "report 4 relative wheel differs")
    require(axes.get((4, 0x0C, 0x0238)) == (-127, 127, 8, 6, 48, 1),
            "report 4 relative Consumer AC Pan differs")


def check_relative_absolute(data):
    fields, bits, axes, nested = parse(data)
    require(bits == {1: 40, 4: 56}, "reports must be exactly 6 and 8 bytes with IDs 1 and 4 only")
    check_report4(fields, axes, 40, 1)
    require(axes.get((1, 1, 0x30)) == (-127, 127, 8, 6, 8, 3), "relative X differs")
    require(axes.get((1, 1, 0x31)) == (-127, 127, 8, 6, 8, 3), "relative Y differs")
    require(axes.get((1, 1, 0x38)) == (-127, 127, 8, 6, 8, 3), "report 1 relative wheel differs")
    require(axes.get((1, 0x0C, 0x0238)) == (-127, 127, 8, 6, 32, 1),
            "report 1 relative Consumer AC Pan differs")
    # The proven Windows bytes: report 4's buttons, padding and X/Y in one Stylus collection,
    # wheel and pan outside it.
    require(nested[1] == [False] * len(fields[1]), "report 1 must not be a digitizer transducer")
    require(nested[4] == [True, True, True, False, False],
            "report 4 buttons and absolute X/Y must share the Stylus collection, wheel/pan outside")


def check_absolute_only(data):
    fields, bits, axes, nested = parse(data)
    # A second report with relative X/Y takes every button from the absolute pointer (pointer.6).
    require(bits == {4: 56}, "absolute-only pointer must declare report 4 alone, 8 bytes")
    # Any Digitizer collection is dispatched as digitizer events that never move the cursor.
    require(nested[4] == [False] * len(fields[4]), "absolute-only report 4 must not be a digitizer")
    check_report4(fields, axes, 40, 1)


def descriptor(data=None, absolute_only=False):
    source = SOURCE.read_text()
    from check_hil_mouse import check_usb_identity
    check_usb_identity(source)
    if data is None:
        data = source_descriptor(source, absolute_only)
    (check_absolute_only if absolute_only else check_relative_absolute)(data)
    require(bytes([0x05,9,0x19,1,0x29,5]) in data, "five pointer buttons missing")
    require(bytes([0x05,0x0C,0x0A,0x38,0x02]) in data, "relative AC Pan missing")
    for token in (
        "constexpr auto kMouseProtocol = HID_ITF_PROTOCOL_NONE;",
        "kSelectedMouseReportDescriptorSize, kMouseEndpoint",
        f"constexpr std::uint16_t kInputDeviceRevision = 0x{REVISIONS[absolute_only]:04X};",
        "static_assert(kConfigurationDescriptor[72] == HID_SUBCLASS_NONE);",
        "static_assert(kConfigurationDescriptor[73] == HID_ITF_PROTOCOL_NONE);",
        "usb_transfer_generation_ != usb_attachment_generation_",
        "usb_transfer_epoch_ != authenticated_epoch_",
        "std::memcmp(report_bytes, expected_report, expected_length)",
        "usb_transfer_pointer_bytes_.data()",
        "keyferry::hid::SerializePointerReport(report, &usb_transfer_pointer_bytes_)",
        "!usb_mounted_ || usb_transfer_in_flight_ || !hid_.report_needed()",
        "identity.pointer_extended_v1 =",
        "hid_.enable_absolute_pointer()" if absolute_only else "hid_.enable_extended_pointer()",
        "wire.data() + 1",
    ):
        require(token in source, "missing dispatch/identity invariant: " + token)
    return data


def device_descriptor(pid, absolute_only):
    return (bytes.fromhex("12010002000000403a30") + pid.to_bytes(2, "little") +
            REVISIONS[absolute_only].to_bytes(2, "little") + bytes.fromhex("01020301"))


def no_msc_usb_descriptors(image, report, absolute_only=False):
    # Exact three-interface USB personality, including unchanged IF0/IF1.
    config = bytes.fromhex(
        "09025b000301008032"
        "0904000001030101040921110100012241000705810308000a"
        "0904010002030000050921110100012222000705020340000a0705820340000a"
        "09040200010300000609211101000122"
    ) + len(report).to_bytes(2, "little") + bytes.fromhex("0705830308000a")
    require(config in image, "HID IF0/IF1/IF2 descriptor differs or MSC is present")
    require(device_descriptor(0x4004, absolute_only) in image,
            f"HID VID/PID or bcdDevice {REVISIONS[absolute_only]:04x} differs")


def inspect_build(build, data, absolute_only):
    cache = (build / "CMakeCache.txt").read_text()
    require("KEYFERRY_POINTER_EXTENDED:BOOL=ON" in cache, "extended pointer disabled")
    match = re.search(r"^KEYFERRY_BOARD:STRING=([a-z0-9_]+)$", cache, re.M)
    require(match is not None, "missing board selection")
    board = match[1]
    config = (build / "sdkconfig").read_text()
    require("CONFIG_TINYUSB_HID_COUNT=3" in config, "USB HID count differs")
    image = (build / "keyferry_hil_endpoint.bin").read_bytes()
    from check_hil_mouse import check_usb_identity
    check_usb_identity(SOURCE.read_text(), image)
    require(data in image, "exact pointer descriptor is absent from image")
    if absolute_only:
        relative = source_descriptor(SOURCE.read_text(), False)
        require(relative not in image, "relative+absolute descriptor is present in an absolute-only image")
    flash = json.loads((build / "flasher_args.json").read_text())["flash_files"]
    if board == "waveshare_geek_v1_1_reference":
        require(device_descriptor(0x4008, absolute_only) in image,
                f"Waveshare VID/PID or bcdDevice {REVISIONS[absolute_only]:04x} differs")
        require("KEYFERRY_FILE_HANDOFF:BOOL=ON" in cache, "Waveshare file handoff disabled")
        require("CONFIG_TINYUSB_MSC_ENABLED=y" in config, "Waveshare MSC disabled")
        from check_msc_size_probe import inspect_file_handoff
        inspect_file_handoff(build)
        require(flash.get("0x120000") == "keyferry_hil_endpoint.bin", "app-only offset differs")
    elif board in ("m5stack_atoms3_lite", "lilygo_t_dongle_s3"):
        for token in ("KEYFERRY_FILE_HANDOFF:BOOL=OFF", "KEYFERRY_MSC_SIZE_PROBE:BOOL=OFF"):
            require(token in cache, "Unqualified storage build enabled")
        for token in ("# CONFIG_TINYUSB_MSC_ENABLED is not set", "# CONFIG_SPIRAM is not set",
                      "# CONFIG_TINYUSB_CDC_ENABLED is not set"):
            require(token in config, "No-MSC storage/PSRAM/CDC differs")
        no_msc_usb_descriptors(image, data, absolute_only)
        require(flash.get("0x10000") == "keyferry_hil_endpoint.bin", "Factory app offset differs")
        if board == "m5stack_atoms3_lite":
            from check_esp_transport import build_checks
            build_checks(build)
    else:
        require(False, "unsupported extended-pointer board: " + board)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    for absolute_only in (False, True):
        descriptor(absolute_only=absolute_only)
    personality = "relative+absolute"
    if args.build_dir:
        cache = (args.build_dir / "CMakeCache.txt").read_text()
        absolute_only = "KEYFERRY_POINTER_ABSOLUTE_ONLY:BOOL=ON" in cache
        personality = "absolute-only" if absolute_only else personality
        inspect_build(args.build_dir, descriptor(absolute_only=absolute_only), absolute_only)

    print(f"check_hil_pointer: ok; IF2={personality}; USB=Generic / USB Input Device; serial=unchanged device-ID uppercase hex; physical_gate=OPEN")


if __name__ == "__main__":
    main()
