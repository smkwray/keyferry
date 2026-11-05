#pragma once
#include <cstddef>
#include <cstdint>

namespace keyferry::handheld {

// Runs Home or a handheld-only function and never returns, unless this boot was launched into
// Keyferry; then it returns at once and the caller starts the bridge.
void RunShellUnlessKeyferry();

struct KeyferryHooks {
  void* context = nullptr;
  // Writes bounded, metadata-only status text for the Keyferry screen.
  void (*status)(void* context, char* text, std::size_t size) = nullptr;
  // Non-blocking: closes admission for this boot and starts the release barrier. False when the
  // bridge is busy (provisioning or maintenance) and nothing changed.
  bool (*begin_leave)(void* context) = nullptr;
  // True once every key and button is confirmed released after begin_leave.
  bool (*neutral_confirmed)(void* context) = nullptr;
};

// Starts the Keyferry screen (status and Home) plus the BOOT long-hold exit. Leaving runs on a
// worker created here (no allocation, no UI lock before admission closes) and restarts to Home
// only after a confirmed release; otherwise the screen says so and nothing resumes.
void StartKeyferryShell(const KeyferryHooks& hooks);

// TinyUSB HID callbacks have one owner per image. The bridge owns them and forwards here while a
// handheld function (Keep Awake) owns the port; the check image's own callbacks do the same.
bool UsbOwnedByHandheld();
const std::uint8_t* HandheldHidReportDescriptor(std::uint8_t instance);
void HandheldHidReportComplete(std::uint8_t instance);
void HandheldHidReportFailed(std::uint8_t instance, bool input_report);

}  // namespace keyferry::handheld
