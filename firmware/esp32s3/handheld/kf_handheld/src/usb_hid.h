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
// One sending task per boot. A press (anything that is not an all-released report) is refused
// once UsbHidClosePresses() has returned; releases are always allowed.
bool UsbHidSend(std::uint8_t report_id, const void* report, std::uint16_t length, bool press = false);
// From any task; after it returns no further press is submitted this boot.
void UsbHidClosePresses();
// Changes whenever the host configures or drops the device: a new session holds nothing from an
// earlier one.
std::uint32_t UsbHidSession();
// The session of the most recently submitted report.
std::uint32_t UsbHidLastSubmittedSession();
bool UsbHidMounted();
bool UsbHidSuspended();
bool UsbHidReady();

}  // namespace keyferry::handheld
