#pragma once

// Target-visible USB and direct BLE HID names. Identity remains the existing serial.
namespace keyferry::usb_identity {
inline constexpr char kManufacturer[] = "Generic";
inline constexpr char kProduct[] = "USB Input Device";
inline constexpr char kKeyboard[] = "Keyboard";
inline constexpr char kManagement[] = "USB Interface";
inline constexpr char kMouse[] = "Mouse";
inline constexpr char kDrive[] = "USB Drive";
inline constexpr char kInquiryVendor[] = "Generic ";
inline constexpr char kInquiryProduct[] = "USB Drive       ";
inline constexpr char kVolumeLabel[] = "USB DRIVE  ";
inline constexpr char kFatOem[] = "Generic ";
static_assert(sizeof(kInquiryVendor) == 9);
static_assert(sizeof(kInquiryProduct) == 17);
static_assert(sizeof(kVolumeLabel) == 12);
static_assert(sizeof(kFatOem) == 9);
}  // namespace keyferry::usb_identity
