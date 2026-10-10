#!/usr/bin/env python3
"""Verify the source-only HIL mouse personality and callback safety contract."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "firmware/esp32s3/hil_endpoint/main/app_main.cpp"
ADAPTER = ROOT / "firmware/esp32s3/hil_endpoint/main/provisioning_adapter.h"
DEFAULTS = ROOT / "firmware/esp32s3/hil_endpoint/sdkconfig.defaults"
SECURE_HEADER = ROOT / "firmware/esp32s3/components/kf_secure_endpoint/include/keyferry/secure_endpoint.h"
SECURE_SOURCE = ROOT / "firmware/esp32s3/components/kf_secure_endpoint/src/secure_endpoint.cpp"
USB_IDENTITY = ROOT / "firmware/common/include/keyferry/usb_identity.h"


def check_usb_identity(app: str, image: bytes | None = None) -> None:
    identity = USB_IDENTITY.read_text(encoding="utf-8")
    names = {
        "kManufacturer": "Generic", "kProduct": "USB Input Device",
        "kKeyboard": "Keyboard", "kManagement": "USB Interface",
        "kMouse": "Mouse", "kDrive": "USB Drive",
        "kInquiryVendor": "Generic ", "kInquiryProduct": "USB Drive       ",
        "kVolumeLabel": "USB DRIVE  ", "kFatOem": "Generic ",
    }
    for name, value in names.items():
        require(identity, (f'inline constexpr char {name}[] = "{value}";',), "USB names")
    ble_hid = (ROOT / "firmware/esp32s3/components/kf_ble_hid/src/idf_ble_hid_peripheral.cpp").read_text()
    require(ble_hid, ("ble_svc_gap_device_name_set(keyferry::usb_identity::kProduct);",),
            "target BLE HID name")
    table = re.search(r"kStringDescriptors\[\]\s*=\s*\{(.*?)\};", app, re.S)
    if table is None:
        fail("USB string table missing")
    entries = re.sub(r"^#.*$", "", table[1], flags=re.M).split(",")
    if [entry.strip() for entry in entries if entry.strip()] != [
        "kEnglishLanguage", "keyferry::usb_identity::kManufacturer",
        "keyferry::usb_identity::kProduct", "kSerialDescriptor.data()",
        "keyferry::usb_identity::kKeyboard", "keyferry::usb_identity::kManagement",
        "keyferry::usb_identity::kMouse", "keyferry::usb_identity::kDrive",
    ]:
        fail("USB string indices/names or serial selection changed")
    serial = re.search(r"void BuildSerialDescriptor\(.*?\n\}", app, re.S)
    expected = r'''void BuildSerialDescriptor(const std::array<std::uint8_t, 16>& device_id) {
      constexpr char kHex[] = "0123456789ABCDEF";
      for (std::size_t index = 0; index < device_id.size(); ++index) {
        kSerialDescriptor[index * 2] = kHex[device_id[index] >> 4];
        kSerialDescriptor[index * 2 + 1] = kHex[device_id[index] & 0x0F];
      }
      kSerialDescriptor.back() = '\0';
    }'''
    if serial is None or re.sub(r"\s+", "", serial[0]) != re.sub(r"\s+", "", expected):
        fail("USB serial must remain the 32 uppercase hex digits of the device ID")
    require(app, (
        "static std::array<char, 33> kSerialDescriptor{};",
        "BuildSerialDescriptor(keyferry::hil_private::kDeviceId);",
        "constexpr std::uint16_t kInputDeviceRevision = 0x0101;",
        "std::memcpy(vendor, keyferry::usb_identity::kInquiryVendor, 8);",
        "std::memcpy(product, keyferry::usb_identity::kInquiryProduct, 16);",
    ), "USB identity")
    if image is not None:
        for name in ("kManufacturer", "kProduct", "kKeyboard", "kManagement", "kMouse"):
            if names[name].encode() + b"\0" not in image:
                fail(f"compiled generic USB string absent: {name}")
        for old in (b"keyferry owner device\0", b"KEYFERRY file handoff\0"):
            if old in image:
                fail("compiled image retains a branded USB name")


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(text: str, tokens: tuple[str, ...], surface: str) -> None:
    for token in tokens:
        if token not in text:
            fail(f"{surface} is missing {token!r}")


def main() -> int:
    app = APP.read_text(encoding="utf-8")
    check_usb_identity(app)
    adapter = ADAPTER.read_text(encoding="utf-8")
    defaults = DEFAULTS.read_text(encoding="utf-8")
    secure_header = SECURE_HEADER.read_text(encoding="utf-8")
    secure_source = SECURE_SOURCE.read_text(encoding="utf-8")

    require(
        app,
        (
            "constexpr std::uint8_t kKeyboardInterface = 0;",
            "constexpr std::uint8_t kProvisioningInterface = 1;",
            "constexpr std::uint8_t kMouseInterface = 2;",
            "constexpr std::uint8_t kKeyboardEndpoint = 0x81;",
            "constexpr std::uint8_t kProvisioningOutEndpoint = 0x02;",
            "constexpr std::uint8_t kProvisioningInEndpoint = 0x82;",
            "constexpr std::uint8_t kMouseEndpoint = 0x83;",
            "constexpr std::uint8_t kMscInterface = 3;",
            "constexpr std::uint8_t kMscOutEndpoint = 0x04;",
            "constexpr std::uint8_t kMscInEndpoint = 0x84;",
            "TUD_CONFIG_DESCRIPTOR(1, 4, 0, kConfigurationLength",
            "TUD_CONFIG_DESCRIPTOR(1, 3, 0, kConfigurationLength",
            "TUD_HID_REPORT_DESC_KEYBOARD()",
            "TUD_HID_INOUT_DESCRIPTOR(",
            "TUD_HID_REPORT_DESC_GENERIC_INOUT(kProvisioningEndpointSize)",
            "TUD_HID_DESCRIPTOR(kMouseInterface, kMouseString,",
            "HID_ITF_PROTOCOL_MOUSE",
            "static_assert(sizeof(kMouseReportDescriptor) == 50);",
            "TUD_MSC_DESCRIPTOR(kMscInterface, kMscString, kMscOutEndpoint,",
            "static_assert(kConfigurationDescriptor[4] == 4);",
            "static_assert(kConfigurationDescriptor[4] == 3);",
            "static_assert(kBleControlConfigurationDescriptor[4] == 2);",
            "static_assert(kBleControlConfigurationDescriptor[4] == 1);",
            "static_assert(kDeviceDescriptor.idProduct == 0x4008);",
            "static_assert(kDeviceDescriptor.idProduct == 0x4004);",
            "static_assert(kBleControlDeviceDescriptor.idProduct == 0x4009);",
            "static_assert(kBleControlDeviceDescriptor.idProduct == 0x4005);",
            "kBleControlConfigurationDescriptor[]",
            "TUD_CONFIG_DESCRIPTOR(1, 1, 0, kBleControlConfigurationLength",
            "TUD_CONFIG_DESCRIPTOR(1, 2, 0, kBleControlConfigurationLength",
            "g_ble_control_usb.store(ble_control_usb",
        ),
        "HIL descriptors",
    )
    descriptor = re.search(
        r"kMouseReportDescriptor\[\]\s*=\s*\{(?P<body>.*?)\};",
        app,
        re.DOTALL,
    )
    if descriptor is None:
        fail("mouse report descriptor is not a closed byte array")
    descriptor_body = descriptor.group("body")
    expected = (
        "0x05", "0x01", "0x09", "0x02", "0xA1", "0x01", "0x09", "0x01",
        "0xA1", "0x00", "0x05", "0x09", "0x19", "0x01", "0x29", "0x03",
        "0x15", "0x00", "0x25", "0x01", "0x95", "0x03", "0x75", "0x01",
        "0x81", "0x02", "0x95", "0x01", "0x75", "0x05", "0x81", "0x03",
        "0x05", "0x01", "0x09", "0x30", "0x09", "0x31", "0x15", "0x81",
        "0x25", "0x7F", "0x75", "0x08", "0x95", "0x02", "0x81", "0x06",
        "0xC0", "0xC0",
    )
    actual = tuple(re.findall(r"0x[0-9A-Fa-f]{2}", descriptor_body))
    if actual != expected:
        fail("mouse report descriptor differs from the exact three-byte boot contract")
    if "TUD_HID_REPORT_DESC_MOUSE" in app:
        fail("HIL uses the wheel/pan mouse convenience descriptor")
    control_descriptor = re.search(
        r"kBleControlConfigurationDescriptor\[\]\s*=\s*\{(?P<body>.*?)\};",
        app,
        re.DOTALL,
    )
    if control_descriptor is None:
        fail("BLE-output USB control descriptor is not a closed byte array")
    control_body = control_descriptor.group("body")
    require(
        control_body,
        (
            "TUD_CONFIG_DESCRIPTOR(1, 1",
            "TUD_CONFIG_DESCRIPTOR(1, 2",
            "TUD_HID_INOUT_DESCRIPTOR(",
            "kProvisioningReportDescriptor",
            "TUD_MSC_DESCRIPTOR(1, kMscString, kMscOutEndpoint, kMscInEndpoint, 64)",
        ),
        "BLE-output USB control descriptor",
    )
    for forbidden in (
        "kKeyboardInterface",
        "kKeyboardReportDescriptor",
        "kMouseInterface",
        "kMouseReportDescriptor",
        "HID_ITF_PROTOCOL_KEYBOARD",
        "HID_ITF_PROTOCOL_MOUSE",
    ):
        if forbidden in control_body:
            fail(f"BLE-output USB control descriptor exposes {forbidden}")

    require(
        app,
        (
            "hid_.enable_mouse_interface()",
            "hid_.desired_interface()",
            "hid_.desired_mouse_logical_token()",
            "tud_hid_n_ready(instance)",
            "tud_hid_n_report(instance, 0, &report, sizeof(report))",
            "usb_transfer_generation_ != usb_attachment_generation_",
            "usb_transfer_epoch_ != authenticated_epoch_",
            "std::memcmp(report_bytes, expected_report, expected_length)",
            "command_.UsbMouseReportAccepted(",
            "hid_.pointer_snapshot(absolute)",
            "identity.mouse_relative_v1 =",
            "output_mode == keyferry::protocol::OutputMode::kUsbHid;",
            "Capability::kMouseRelativeV1)) != 0;",
            "command_.BeginSession(epoch, peer_input_v1_, peer_input_v2_);",
        ),
        "HIL mouse dispatch",
    )
    require(
        adapter,
        (
            "kKeyboardHidInstance = 0",
            "kProvisioningHidInstance = 1",
            "kMouseHidInstance = 2",
            "kBleControlProvisioningHidInstance = 0",
        ),
        "HID instance registry",
    )
    require(defaults, ("CONFIG_TINYUSB_HID_COUNT=3",), "HIL sdkconfig")
    require(secure_header, ("bool mouse_relative_v1{};",), "firmware identity")
    require(
        secure_source,
        (
            "Capability::kMouseRelativeV1",
            "identity.mouse_relative_v1",
            "FirmwareCapabilityMask(firmware_identity_)",
        ),
        "identity encoder",
    )
    print("check_hil_mouse: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
