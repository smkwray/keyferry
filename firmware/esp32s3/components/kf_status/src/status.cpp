#include "keyferry/status.h"

#include <cstdio>

namespace keyferry::status {

Activity ActivityPresentationFilter::Update(
    const Activity observed, const std::uint64_t now_ms) noexcept {
  if (observed == Activity::kActive) {
    last_active_ms_ = now_ms;
    saw_active_ = true;
    return Activity::kActive;
  }
  if (observed == Activity::kReady && saw_active_ &&
      now_ms >= last_active_ms_ &&
      now_ms - last_active_ms_ < kActivePresentationHoldMs) {
    return Activity::kActive;
  }
  saw_active_ = false;
  return observed;
}

void ActivityPresentationFilter::Reset() noexcept {
  last_active_ms_ = 0;
  saw_active_ = false;
}

bool operator==(const Presentation& left,
                const Presentation& right) noexcept {
  if (left.page_ != right.page_ || left.activity_ != right.activity_ ||
      left.line_count_ != right.line_count_) {
    return false;
  }
  for (std::size_t index = 0; index < left.line_count_; ++index) {
    if (left.lines_[index].role != right.lines_[index].role ||
        left.lines_[index].tone != right.lines_[index].tone ||
        left.lines_[index].text != right.lines_[index].text) {
      return false;
    }
  }
  return true;
}

bool operator!=(const Presentation& left,
                const Presentation& right) noexcept {
  return !(left == right);
}

const char* UsbLabel(const bool mounted, const bool suspended) noexcept {
  if (suspended) {
    return "USB SLEEP";
  }
  return mounted ? "USB READY" : "USB OFF";
}

const char* LinkLabel(const LinkPath path) noexcept {
  switch (path) {
    case LinkPath::kWifi:
      return "WIFI";
    case LinkPath::kBluetooth:
      return "BLUETOOTH";
    case LinkPath::kOffline:
      return "NO LINK";
  }
  return "NO LINK";
}

const char* ActivityLabel(const Activity activity) noexcept {
  switch (activity) {
    case Activity::kLocked:
      return "LOCKED";
    case Activity::kConnecting:
      return "CONNECTING";
    case Activity::kReady:
      return "CONNECTED";
    case Activity::kActive:
      return "ACTIVE";
    case Activity::kProvisioning:
      return "SETUP";
    case Activity::kFault:
      return "FAULT";
  }
  return "FAULT";
}

const char* ConnectionLabel(const ConnectionProgress progress) noexcept {
  switch (progress) {
    case ConnectionProgress::kWifiJoining:
      return "WIFI JOINING";
    case ConnectionProgress::kWifiAuthenticating:
      return "WIFI AUTHENTICATING";
    case ConnectionProgress::kBluetoothAdvertising:
      return "BLUETOOTH ADVERTISING";
    case ConnectionProgress::kBluetoothAuthenticating:
      return "BLUETOOTH AUTHENTICATING";
    case ConnectionProgress::kSearching:
      return "SEARCHING FOR HOST";
  }
  return "SEARCHING FOR HOST";
}

const char* DetailLabel(const Snapshot& snapshot) noexcept {
  switch (snapshot.activity) {
    case Activity::kLocked:
      return "CONFIG LOCKED";
    case Activity::kConnecting:
      return ConnectionLabel(snapshot.connection);
    case Activity::kReady:
      return "HOST AUTHENTICATED";
    case Activity::kActive:
      return "SENDING KEYS";
    case Activity::kProvisioning:
      return "USB PROVISIONING";
    case Activity::kFault:
      return "STATUS UNAVAILABLE";
  }
  return "STATUS UNAVAILABLE";
}

Page SelectPage(const Snapshot& snapshot,
                const std::uint64_t elapsed_ms) noexcept {
  if (snapshot.ble_hid_mode || snapshot.activity == Activity::kReady ||
      snapshot.activity == Activity::kActive ||
      snapshot.activity == Activity::kProvisioning) {
    return Page::kSummary;
  }
  constexpr std::uint64_t kSummaryMs = 8000;
  constexpr std::uint64_t kCycleMs = 12000;
  return elapsed_ms % kCycleMs < kSummaryMs ? Page::kSummary
                                            : Page::kDiagnostics;
}

Presentation BuildPresentation(const Snapshot& snapshot,
                               const Page page,
                               const PresentationDensity density) noexcept {
  Presentation output;
  output.page_ = page;
  output.activity_ = snapshot.activity;
  const auto add = [&output](const LineRole role, const Tone tone,
                             const char* format, const auto... values) {
    if (output.line_count_ >= output.lines_.size()) {
      return;
    }
    Line& line = output.lines_[output.line_count_++];
    line.role = role;
    line.tone = tone;
    if constexpr (sizeof...(values) == 0) {
      std::snprintf(line.text.data(), line.text.size(), "%s", format);
    } else {
      std::snprintf(line.text.data(), line.text.size(), format, values...);
    }
  };

  if (page == Page::kDiagnostics) {
    if (density == PresentationDensity::kCompact) {
      add(LineRole::kDiagnosticHeader, Tone::kAccent, "D %.8s G%08lX",
          snapshot.build_id.data(),
          static_cast<unsigned long>(snapshot.config_generation &
                                     0xFFFF'FFFFULL));
      add(LineRole::kTransport,
          snapshot.transport_running ? Tone::kPrimary : Tone::kAccent,
          "TR %s N%08lX", snapshot.transport_running ? "RUN" : "OFF",
          static_cast<unsigned long>(
              static_cast<std::uint32_t>(snapshot.nvs_error)));
      add(LineRole::kWifi, Tone::kPrimary, "W S%u %s E%08lX",
          static_cast<unsigned>(snapshot.wifi_stage),
          snapshot.wifi_available ? "OK" : "OFF",
          static_cast<unsigned long>(
              static_cast<std::uint32_t>(snapshot.wifi_error)));
      add(LineRole::kBluetooth, Tone::kPrimary, "B S%u E%08lX Y%u A%u",
          static_cast<unsigned>(snapshot.ble_stage),
          static_cast<unsigned long>(
              static_cast<std::uint32_t>(snapshot.ble_error)),
          snapshot.ble_synchronized ? 1U : 0U,
          snapshot.ble_advertising ? 1U : 0U);
      add(LineRole::kHeap, Tone::kSecondary, "H %05lX/%05lX/%05lXK",
          static_cast<unsigned long>(snapshot.free_internal_heap / 1024U),
          static_cast<unsigned long>(snapshot.largest_internal_block / 1024U),
          static_cast<unsigned long>(snapshot.minimum_internal_heap / 1024U));
      return output;
    }
    add(LineRole::kDiagnosticHeader, Tone::kAccent, "DIAG FW %.8s G%llu",
        snapshot.build_id.data(),
        static_cast<unsigned long long>(snapshot.config_generation));
    add(LineRole::kTransport,
        snapshot.transport_running ? Tone::kPrimary : Tone::kAccent,
        "TRANSPORT %s NVS %ld", snapshot.transport_running ? "RUN" : "EXIT",
        static_cast<long>(snapshot.nvs_error));
    add(LineRole::kWifi, Tone::kPrimary, "WIFI ST%u %s E%ld",
        static_cast<unsigned>(snapshot.wifi_stage),
        snapshot.wifi_available ? "OK" : "OFF",
        static_cast<long>(snapshot.wifi_error));
    add(LineRole::kBluetooth, Tone::kPrimary,
        "BL ST%u %s E%ld SY%u AD%u",
        static_cast<unsigned>(snapshot.ble_stage),
        snapshot.ble_available ? "OK" : "OFF",
        static_cast<long>(snapshot.ble_error),
        snapshot.ble_synchronized ? 1U : 0U,
        snapshot.ble_advertising ? 1U : 0U);
    add(LineRole::kHeap, Tone::kSecondary, "HEAP %lu/%lu/%luK",
        static_cast<unsigned long>(snapshot.free_internal_heap / 1024U),
        static_cast<unsigned long>(snapshot.largest_internal_block / 1024U),
        static_cast<unsigned long>(snapshot.minimum_internal_heap / 1024U));
    return output;
  }

  if (snapshot.ble_hid_mode) {
    add(LineRole::kActivity, Tone::kAccent, "BT KEYBOARD");
    if (!snapshot.ble_hid_ready) {
      add(LineRole::kDetail, Tone::kPrimary, "PAIR CODE %06lu",
          static_cast<unsigned long>(snapshot.ble_hid_passkey));
    } else {
      add(LineRole::kDetail, Tone::kPrimary, "PAIRED");
    }
    add(LineRole::kUsb,
        snapshot.ble_hid_ready ? Tone::kPrimary : Tone::kSecondary,
        "%s", snapshot.ble_hid_ready ? "READY" : "ADD IN WINDOWS");
    add(LineRole::kLink,
        snapshot.link == LinkPath::kOffline ? Tone::kSecondary
                                            : Tone::kPrimary,
        "CONTROL %s", LinkLabel(snapshot.link));
  } else {
    add(LineRole::kActivity, Tone::kAccent, "%s",
        ActivityLabel(snapshot.activity));
    add(LineRole::kDetail, Tone::kPrimary, "%s", DetailLabel(snapshot));
    add(LineRole::kUsb,
        snapshot.usb_mounted && !snapshot.usb_suspended ? Tone::kPrimary
                                                        : Tone::kSecondary,
        "%s", UsbLabel(snapshot.usb_mounted, snapshot.usb_suspended));
    add(LineRole::kLink,
        snapshot.link == LinkPath::kOffline ? Tone::kSecondary
                                            : Tone::kPrimary,
        "%s", LinkLabel(snapshot.link));
  }
  add(LineRole::kBuild, Tone::kSecondary, "KEYFERRY FW %.8s",
      snapshot.build_id.data());
  return output;
}

}  // namespace keyferry::status
