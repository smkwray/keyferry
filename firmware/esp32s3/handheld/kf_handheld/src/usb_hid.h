#pragma once
#include <cstdint>

namespace keyferry::handheld {

// One USB personality per boot (ADR 0018 rule 5): each has its own PID and report descriptor.
enum class UsbPersonality : std::uint8_t {
  kKeepAwakeMouse,  // 303A:4010, relative mouse without report IDs
  kMacroPad,        // 303A:4011, keyboard + mouse + media keys in one interface
};

// Macro pad report IDs.
constexpr std::uint8_t kReportKeyboard = 1;
constexpr std::uint8_t kReportMouse = 2;
constexpr std::uint8_t kReportMedia = 3;

// Installs TinyUSB with that personality, after claiming the HID callbacks.
bool UsbHidStart(UsbPersonality personality);
// Sends one report and waits for the host to take it (500 ms). False: refused or unconfirmed.
// One sending task per boot.
bool UsbHidSend(std::uint8_t report_id, const void* report, std::uint16_t length);
bool UsbHidMounted();
bool UsbHidSuspended();
bool UsbHidReady();

}  // namespace keyferry::handheld
