#pragma once
#include <cstdint>
#include "keyferry/status.h"

namespace keyferry::status {
struct LedColor {
  std::uint8_t red{}, green{}, blue{};
};
// One public safety state, with a short transport marker every two seconds.
// No payload, credential, passkey, device name or diagnostic text is accepted.
constexpr LedColor StatusLedColor(const Snapshot& snapshot, std::uint64_t now_ms,
                                  std::uint8_t dim, bool armed) noexcept {
  const auto tick = now_ms / 250U;
  if (snapshot.activity == Activity::kFault) return tick % 2 ? LedColor{} : LedColor{dim, 0, 0};
  if (snapshot.activity == Activity::kProvisioning) return tick % 2 ? LedColor{} : LedColor{dim, 0, dim};
  if (snapshot.activity == Activity::kActive) return tick % 2 ? LedColor{} : LedColor{dim, dim, 0};
  if (armed) return {dim, dim, 0};
  if (snapshot.activity == Activity::kConnecting) {
    if (tick % 4 >= 2) return {};
    const bool wifi = snapshot.connection == ConnectionProgress::kWifiJoining ||
                      snapshot.connection == ConnectionProgress::kWifiAuthenticating;
    const bool ble = snapshot.connection == ConnectionProgress::kBluetoothAdvertising ||
                     snapshot.connection == ConnectionProgress::kBluetoothAuthenticating;
    return wifi ? LedColor{0, dim, dim} : ble ? LedColor{0, 0, dim} : LedColor{dim, static_cast<std::uint8_t>(dim / 2U), 0};
  }
  if (snapshot.activity == Activity::kReady) {
    if (tick % 8 == 0 && snapshot.link != LinkPath::kOffline) {
      return snapshot.link == LinkPath::kWifi ? LedColor{0, dim, dim} : LedColor{0, 0, dim};
    }
    return {0, dim, 0};
  }
  return {dim, static_cast<std::uint8_t>(dim / 2U), 0};  // Locked/unprovisioned, always disarmed.
}
}  // namespace keyferry::status
