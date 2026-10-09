"""Check the opt-in report-ID pointer personality; legacy checker stays separate."""
import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise SystemExit("pointer check: " + message)


def descriptor():
    source = (ROOT / "firmware/esp32s3/hil_endpoint/main/app_main.cpp").read_text()
    body = re.search(r"kPointerReportDescriptor\[\]\s*=\s*\{(.*?)\};", source, re.S)
    require(body is not None, "missing closed pointer descriptor")
    data = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", body[1]))
    # Parse HID short items, preserving globals across collections/report IDs.
    report_id = 0
    size = count = page = minimum = maximum = 0
    usage = []
    bits = {}
    axes = {}
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
        elif tag == 0x80:
            bits[report_id] = bits.get(report_id, 0) + size * count
            for p, u in usage:
                if p == 1 and u in (0x30, 0x31):
                    axes[(report_id, u)] = (minimum, maximum, size, value)
            usage.clear()
        elif tag in (0xA0, 0xC0): usage.clear()
        elif tag in (0x90, 0xB0): require(False, "unexpected output or feature report")
    require(bits == {1: 40, 4: 48}, "reports must be exactly 6 and 7 bytes with IDs 1 and 4 only")
    require(axes.get((1, 0x30)) == (-127, 127, 8, 6), "relative X differs")
    require(axes.get((1, 0x31)) == (-127, 127, 8, 6), "relative Y differs")
    for axis in (0x30, 0x31):
        require(axes.get((4, axis)) == (0, 32767, 16, 2), "absolute Generic Desktop axis differs")
    require(bytes([0x05,9,0x19,1,0x29,5]) in data, "five pointer buttons missing")
    require(bytes([0x05,0x0C,0x0A,0x38,0x02]) in data, "relative AC Pan missing")
    for token in (
        "constexpr auto kMouseProtocol = HID_ITF_PROTOCOL_NONE;",
        "kSelectedMouseReportDescriptorSize, kMouseEndpoint",
        "constexpr std::uint16_t kInputDeviceRevision = 0x0102;",
        "static_assert(kConfigurationDescriptor[72] == HID_SUBCLASS_NONE);",
        "static_assert(kConfigurationDescriptor[73] == HID_ITF_PROTOCOL_NONE);",
        "usb_transfer_generation_ != usb_attachment_generation_",
        "usb_transfer_epoch_ != authenticated_epoch_",
        "std::memcmp(report_bytes, expected_report, expected_length)",
        "usb_transfer_pointer_bytes_.data()",
        "identity.pointer_extended_v1 =",
        "hid_.enable_extended_pointer()",
        "wire.data() + 1",
    ):
        require(token in source, "missing dispatch/identity invariant: " + token)
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    data = descriptor()
    if args.build_dir:
        build = args.build_dir
        cache = (build / "CMakeCache.txt").read_text()
        for token in ("KEYFERRY_POINTER_EXTENDED:BOOL=ON", "KEYFERRY_FILE_HANDOFF:BOOL=ON", "KEYFERRY_BOARD:STRING=waveshare_geek_v1_1_reference"):
            require(token in cache, "candidate build differs: " + token)
        config = (build / "sdkconfig").read_text()
        for token in ("CONFIG_TINYUSB_HID_COUNT=3", "CONFIG_TINYUSB_MSC_ENABLED=y"):
            require(token in config, "USB classes differ")
        image = (build / "keyferry_hil_endpoint.bin").read_bytes()
        require(data in image, "exact pointer descriptor is absent from image")
        from check_msc_size_probe import inspect_file_handoff
        inspect_file_handoff(build)
        require(json.loads((build / "flasher_args.json").read_text())["flash_files"].get("0x120000") == "keyferry_hil_endpoint.bin", "app-only offset differs")
    print("check_hil_pointer: ok; physical_gate=OPEN")


if __name__ == "__main__":
    main()
