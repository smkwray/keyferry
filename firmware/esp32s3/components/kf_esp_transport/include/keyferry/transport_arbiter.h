#pragma once

#include <cstdint>

namespace keyferry::transport {

enum class Path : std::uint8_t {
  kNone = 0,
  kWifi,
  kBluetooth,
};

struct ArbitrationActions {
  bool start_wifi = false;
  bool cancel_wifi = false;
  bool start_ble_advertising = false;
  bool stop_ble = false;
  bool start_ble_authentication = false;
  bool fail_closed = false;
};

struct TransportAvailability {
  bool wifi = true;
  bool bluetooth = true;
};

// Allocation-free policy for one EndpointSession shared by Wi-Fi and BLE.
// The caller performs returned actions and is solely responsible for network,
// radio, TLS, and fail-close effects.
class TransportArbiter final {
 public:
  ArbitrationActions Boot(std::uint64_t now_ms,
                          TransportAvailability availability = {});
  ArbitrationActions Disable(Path path, std::uint64_t now_ms);
  ArbitrationActions Poll(std::uint64_t now_ms);
  ArbitrationActions WifiAttemptFinished(bool authenticated,
                                         std::uint64_t now_ms);
  ArbitrationActions BleConnected(std::uint64_t now_ms);
  ArbitrationActions BleAuthenticated(std::uint64_t now_ms);
  ArbitrationActions BleCandidateFailed(std::uint64_t now_ms);
  ArbitrationActions ActiveTransportLost(std::uint64_t now_ms);
  void QuiesceForTargetedHandoff();
  bool InstallTargetedOwner(Path path);

  [[nodiscard]] Path active_path() const { return active_path_; }
  [[nodiscard]] bool wifi_candidate_active() const {
    return wifi_candidate_active_;
  }
  [[nodiscard]] bool ble_advertising() const { return ble_advertising_; }
  [[nodiscard]] bool ble_connected() const { return ble_connected_; }
  [[nodiscard]] bool ble_authentication_permitted() const {
    return ble_authentication_permitted_;
  }
  [[nodiscard]] std::uint32_t generation() const { return generation_; }

 private:
  ArbitrationActions BeginSelection(std::uint64_t now_ms, bool fail_closed);
  ArbitrationActions StartBleAdvertisingIfAllowed(std::uint64_t now_ms);
  void ClearBleCandidate();

  Path active_path_ = Path::kNone;
  std::uint64_t selection_started_ms_ = 0;
  std::uint64_t wifi_retry_started_ms_ = 0;
  std::uint32_t generation_ = 0;
  std::uint8_t consecutive_ble_failures_ = 0;
  TransportAvailability availability_{};
  bool wifi_candidate_active_ = false;
  bool ble_advertising_ = false;
  bool ble_connected_ = false;
  bool ble_authentication_permitted_ = false;
  bool wifi_retry_required_ = false;
};

}  // namespace keyferry::transport
