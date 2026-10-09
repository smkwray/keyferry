#!/usr/bin/env python3
"""Compare validated ESP32-S3 images and ELF allocated sections off-device.

Only the app descriptor's dependent ELF SHA256 may differ in loadable data.
Debug-only ELF differences are reported separately, never treated as code.
Uses the pinned IDF environment's esptool and pyelftools.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from esptool.bin_image import ESP32S3FirmwareImage


def digest(data):
    return hashlib.sha256(data).hexdigest()


def appdesc(data):
    if len(data) >= 256 and data[:4] == bytes.fromhex("3254cdab"):
        return data[:144] + bytes(32) + data[176:]
    return data


def image(path):
    data = path.read_bytes()
    parsed = ESP32S3FirmwareImage(io.BytesIO(data))
    if (not parsed.append_digest or parsed.data_length + 32 != len(data)
            or parsed.stored_digest != parsed.calc_digest
            or parsed.checksum != parsed.calculate_checksum()
            or parsed.chip_id != parsed.ROM_LOADER.IMAGE_CHIP_ID):
        raise ValueError("invalid S3 checksum/digest/chip: " + str(path))
    return data, [(s.addr, len(s.data), appdesc(s.data)) for s in parsed.segments]


def elf(path):
    with path.open("rb") as stream:
        parsed = ELFFile(stream)
        return {s.name: (s["sh_addr"], s["sh_size"], s["sh_type"],
                         s["sh_flags"], s.data()) for s in parsed.iter_sections()}


def compare(reference, candidate):
    name = "keyferry_hil_endpoint"
    left, left_segments = image(reference / (name + ".bin"))
    right, right_segments = image(candidate / (name + ".bin"))
    a, b = elf(reference / (name + ".elf")), elf(candidate / (name + ".elf"))
    differences = []
    for section in sorted(a.keys() | b.keys()):
        if section not in a or section not in b:
            if (a.get(section) or b.get(section))[3] & 2:
                differences.append(section)
            continue
        x, y = a[section], b[section]
        if (x[3] | y[3]) & 2:
            xd = appdesc(x[4]) if section == ".flash.appdesc" else x[4]
            yd = appdesc(y[4]) if section == ".flash.appdesc" else y[4]
            if x[:4] != y[:4] or xd != yd:
                differences.append(section)
    offsets = [i for i, (x, y) in enumerate(zip(left, right)) if x != y]
    ranges = []
    for offset in offsets:
        if ranges and ranges[-1][1] + 1 == offset:
            ranges[-1][1] = offset
        else:
            ranges.append([offset, offset])
    result = dict(
        schema="keyferry.idf-image-comparison.v1",
        reference=str(reference), candidate=str(candidate),
        bin_bytes=[len(left), len(right)], bin_sha256=[digest(left), digest(right)],
        bin_byte_equal=left == right, bin_difference_ranges_inclusive=ranges,
        bin_header_equal=left[:24] == right[:24],
        image_segments_equal_except_appdesc_elf_sha256=left_segments == right_segments,
        elf_sha256=[digest((reference / (name + ".elf")).read_bytes()),
                    digest((candidate / (name + ".elf")).read_bytes())],
        elf_allocated_differences=differences,
        elf_nonallocated_differences=[s for s in sorted(a.keys() | b.keys())
                                     if a.get(s) != b.get(s) and not ((a.get(s) or b.get(s))[3] & 2)],
        allowed_loadable_difference="app descriptor ELF SHA256 only; dependent image checksum/SHA256 validated",
    )
    result["status"] = "PASS" if (left[:24] == right[:24]
                                         and left_segments == right_segments
                                         and not differences) else "FAIL"
    return result


def main():
    parser = argparse.ArgumentParser()
    for field in ("reference", "candidate", "output"):
        parser.add_argument("--" + field, required=True, type=Path)
    args = parser.parse_args()
    result = compare(args.reference.resolve(), args.candidate.resolve())
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    raise SystemExit(result["status"] != "PASS")


if __name__ == "__main__":
    main()
