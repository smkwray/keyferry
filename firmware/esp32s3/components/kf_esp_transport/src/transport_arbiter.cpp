#include "keyferry/transport_arbiter.h"

#include <algorithm>
#include <array>
#include <limits>

#include "keyferry_protocol_generated.h"

namespace keyferry::transport {
namespace {

bool DeadlineReached(std::uint64_t now_ms, std::uint64_t start_ms,
                     std::uint64_t duration_ms) {
  return now_ms >= start_ms && now_ms - start_ms >= duration_ms;
}

}  // namespace

std::uint32_t ReconnectDelayMs(std::uint32_t consecutive_failures) {
  constexpr std::array<std::uint32_t, 6> kDelays{250, 500, 1000, 2000, 4000, 5000};
  return kDelays[consecutive_failures == 0 ? 0 :
      std::min<std::size_t>(consecutive_failures - 1, kDelays.size() - 1)];
}

ArbitrationActions TransportArbiter::Boot(
    std::uint64_t now_ms, TransportAvailability availability) {
  availability_ = availability;
  generation_ = generation_ == std::numeric_limits<std::uint32_t>::max()
                    ? 1
                    : generation_ + 1;
  consecutive_ble_failures_ = 0;
  consecutive_wifi_failures_ = 0;
  wifi_retry_required_ = false;
  return BeginSelection(now_ms, false);
}

ArbitrationActions TransportArbiter::BeginSelection(std::uint64_t now_ms,
                                                    bool fail_closed) {
  active_path_ = Path::kNone;
  selection_started_ms_ = now_ms;
  wifi_candidate_active_ = availability_.wifi;
  wifi_tls_verified_ = false;
  ClearBleCandidate();
  ArbitrationActions actions{};
  actions.fail_closed = fail_closed;
  if (availability_.wifi) {
    actions.start_wifi = true;
  } else if (availability_.bluetooth) {
    ble_advertising_ = true;
    actions.start_ble_advertising = true;
  }
  return actions;
}

ArbitrationActions TransportArbiter::Disable(const Path path,
                                             const std::uint64_t now_ms) {
  const bool wifi_was_candidate = wifi_candidate_active_;
  const bool ble_was_available = availability_.bluetooth;
  if (path == Path::kWifi) {
    if (!availability_.wifi) return {};
    availability_.wifi = false;
    wifi_candidate_active_ = false;
  } else if (path == Path::kBluetooth) {
    if (!availability_.bluetooth) return {};
    availability_.bluetooth = false;
    ClearBleCandidate();
  } else {
    return {};
  }
  // Losing an unused carrier cannot revoke the authenticated holder. Repeated
  // BLE host-sync faults used to restart selection here and overwrite live TLS.
  if (active_path_ != Path::kNone && active_path_ != path) {
    return {};
  }
  ArbitrationActions actions{};
  actions.fail_closed = true;
  if (active_path_ == Path::kNone && path == Path::kBluetooth &&
      ble_was_available && wifi_was_candidate && availability_.wifi) {
    wifi_candidate_active_ = true;
    actions.fail_closed = false;
    return actions;
  }
  if (active_path_ == Path::kNone && path == Path::kWifi &&
      availability_.bluetooth && (ble_advertising_ || ble_connected_)) {
    if (ble_connected_) {
      ble_authentication_permitted_ = true;
      actions.fail_closed = false;
      actions.start_ble_authentication = true;
    }
    return actions;
  }
  if (active_path_ == path) {
    generation_ = generation_ == std::numeric_limits<std::uint32_t>::max()
                      ? 1
                      : generation_ + 1;
  }
  return BeginSelection(now_ms, true);
}

ArbitrationActions TransportArbiter::StartBleAdvertisingIfAllowed(
    std::uint64_t now_ms) {
  ArbitrationActions actions{};
  if (availability_.bluetooth && active_path_ == Path::kNone &&
      !ble_advertising_ && !ble_connected_ &&
      DeadlineReached(now_ms, selection_started_ms_,
                      protocol::kBleAdvertisingDelayMs)) {
    ble_advertising_ = true;
    actions.start_ble_advertising = true;
  }
  return actions;
}

ArbitrationActions TransportArbiter::Poll(std::uint64_t now_ms) {
  if (active_path_ != Path::kNone) {
    return {};
  }
  auto actions = StartBleAdvertisingIfAllowed(now_ms);
  if (availability_.wifi && !ble_connected_ &&
      !wifi_candidate_active_ && wifi_retry_required_ &&
      DeadlineReached(now_ms, wifi_retry_started_ms_,
                      ReconnectDelayMs(consecutive_wifi_failures_))) {
    wifi_retry_required_ = false;
    wifi_candidate_active_ = true;
    wifi_tls_verified_ = false;
    selection_started_ms_ = now_ms;
    actions.start_wifi = true;
  }
  if (wifi_candidate_active_ &&
      DeadlineReached(now_ms, selection_started_ms_,
                      wifi_tls_verified_ ? protocol::kBleAuthenticationTimeoutMs
                                         : protocol::kBleWifiPreferenceMs)) {
    wifi_candidate_active_ = false;
    wifi_tls_verified_ = false;
    wifi_retry_required_ = availability_.wifi;
    wifi_retry_started_ms_ = now_ms;
    if (consecutive_wifi_failures_ < std::numeric_limits<std::uint32_t>::max()) {
      ++consecutive_wifi_failures_;
    }
    actions.cancel_wifi = true;
    if (ble_connected_) {
      ble_authentication_permitted_ = true;
      actions.start_ble_authentication = true;
    }
  }
  return actions;
}

void TransportArbiter::WifiTlsVerified(const std::uint64_t now_ms) {
  if (active_path_ == Path::kNone && wifi_candidate_active_) {
    // The endpoint authentication budget starts after verified TLS, never at
    // station association or before a blocking TLS handshake.
    wifi_tls_verified_ = true;
    selection_started_ms_ = now_ms;
  }
}

ArbitrationActions TransportArbiter::WifiAttemptFinished(
    bool authenticated, std::uint64_t now_ms) {
  if (active_path_ != Path::kNone || !wifi_candidate_active_) {
    return {};
  }
  wifi_candidate_active_ = false;
  wifi_tls_verified_ = false;
  if (authenticated) {
    active_path_ = Path::kWifi;
    ArbitrationActions actions{};
    actions.stop_ble = ble_advertising_ || ble_connected_;
    ClearBleCandidate();
    consecutive_ble_failures_ = 0;
    consecutive_wifi_failures_ = 0;
    wifi_retry_required_ = false;
    return actions;
  }

  ArbitrationActions actions{};
  actions.fail_closed = true;
  if (consecutive_wifi_failures_ < std::numeric_limits<std::uint32_t>::max()) {
    ++consecutive_wifi_failures_;
  }
  wifi_retry_required_ = availability_.wifi;
  wifi_retry_started_ms_ = now_ms;
  if (!availability_.bluetooth) {
    return actions;
  }
  if (consecutive_ble_failures_ >= protocol::kBleFailedCandidatesBeforeWifiRetry) {
    consecutive_ble_failures_ = 0;
    ble_advertising_ = true;
    actions.start_ble_advertising = true;
    return actions;
  }
  const auto advertise = StartBleAdvertisingIfAllowed(now_ms);
  actions.start_ble_advertising = advertise.start_ble_advertising;
  if (ble_connected_) {
    ble_authentication_permitted_ = true;
    actions.start_ble_authentication = true;
  }
  return actions;
}

ArbitrationActions TransportArbiter::BleConnected(std::uint64_t now_ms) {
  if (active_path_ != Path::kNone || !ble_advertising_ || ble_connected_) {
    return {};
  }
  ble_advertising_ = false;
  ble_connected_ = true;
  ArbitrationActions actions{};
  if (!wifi_candidate_active_ ||
      (!wifi_tls_verified_ && DeadlineReached(now_ms, selection_started_ms_,
                      protocol::kBleWifiPreferenceMs))) {
    ble_authentication_permitted_ = true;
    actions.start_ble_authentication = true;
  }
  return actions;
}

ArbitrationActions TransportArbiter::BleAuthenticated(std::uint64_t) {
  if (active_path_ != Path::kNone || !ble_connected_ ||
      !ble_authentication_permitted_) {
    return {};
  }
  active_path_ = Path::kBluetooth;
  ArbitrationActions actions{};
  actions.cancel_wifi = wifi_candidate_active_;
  wifi_candidate_active_ = false;
  wifi_tls_verified_ = false;
  consecutive_ble_failures_ = 0;
  consecutive_wifi_failures_ = 0;
  wifi_retry_required_ = false;
  return actions;
}

ArbitrationActions TransportArbiter::BleCandidateFailed(
    std::uint64_t now_ms) {
  if (active_path_ != Path::kNone || (!ble_connected_ && !ble_advertising_)) {
    return {};
  }
  ClearBleCandidate();
  ArbitrationActions actions{};
  actions.fail_closed = true;
  if (consecutive_ble_failures_ <
      std::numeric_limits<std::uint8_t>::max()) {
    ++consecutive_ble_failures_;
  }
  if (availability_.wifi && consecutive_ble_failures_ >=
      protocol::kBleFailedCandidatesBeforeWifiRetry) {
    wifi_retry_required_ = true;
    if (!wifi_candidate_active_) {
      wifi_candidate_active_ = true;
      selection_started_ms_ = now_ms;
      actions.start_wifi = true;
    }
    return actions;
  }
  if (availability_.bluetooth) {
    if (!availability_.wifi) {
      ble_advertising_ = true;
      actions.start_ble_advertising = true;
    } else {
      const auto advertise = StartBleAdvertisingIfAllowed(now_ms);
      actions.start_ble_advertising = advertise.start_ble_advertising;
    }
  }
  return actions;
}

ArbitrationActions TransportArbiter::ActiveTransportLost(
    std::uint64_t now_ms) {
  if (active_path_ == Path::kNone) {
    return {};
  }
  generation_ = generation_ == std::numeric_limits<std::uint32_t>::max()
                    ? 1
                    : generation_ + 1;
  consecutive_ble_failures_ = 0;
  wifi_retry_required_ = false;
  return BeginSelection(now_ms, true);
}

void TransportArbiter::QuiesceForTargetedHandoff() {
  active_path_ = Path::kNone;
  wifi_candidate_active_ = false;
  wifi_tls_verified_ = false;
  wifi_retry_required_ = false;
  ClearBleCandidate();
}

bool TransportArbiter::InstallTargetedOwner(const Path path) {
  if (active_path_ != Path::kNone || path == Path::kNone ||
      (path == Path::kWifi && !availability_.wifi) ||
      (path == Path::kBluetooth && !availability_.bluetooth)) {
    return false;
  }
  active_path_ = path;
  wifi_candidate_active_ = false;
  wifi_tls_verified_ = false;
  wifi_retry_required_ = false;
  ClearBleCandidate();
  return true;
}

void TransportArbiter::ClearBleCandidate() {
  ble_advertising_ = false;
  ble_connected_ = false;
  ble_authentication_permitted_ = false;
}

}  // namespace keyferry::transport
