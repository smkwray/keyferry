#include "keyferry/transport_arbiter.h"

#include <limits>

#include "keyferry_protocol_generated.h"

namespace keyferry::transport {
namespace {

bool DeadlineReached(std::uint64_t now_ms, std::uint64_t start_ms,
                     std::uint64_t duration_ms) {
  return now_ms >= start_ms && now_ms - start_ms >= duration_ms;
}

}  // namespace

ArbitrationActions TransportArbiter::Boot(
    std::uint64_t now_ms, TransportAvailability availability) {
  availability_ = availability;
  generation_ = generation_ == std::numeric_limits<std::uint32_t>::max()
                    ? 1
                    : generation_ + 1;
  consecutive_ble_failures_ = 0;
  wifi_retry_required_ = false;
  return BeginSelection(now_ms, false);
}

ArbitrationActions TransportArbiter::BeginSelection(std::uint64_t now_ms,
                                                    bool fail_closed) {
  active_path_ = Path::kNone;
  selection_started_ms_ = now_ms;
  wifi_candidate_active_ = availability_.wifi;
  ClearBleCandidate();
  ArbitrationActions actions{};
  actions.fail_closed = fail_closed;
  if (availability_.wifi) {
    actions.start_wifi = true;
  } else if (availability_.bluetooth) {
    ble_advertising_ = true;
    wifi_retry_started_ms_ = now_ms;
    actions.start_ble_advertising = true;
  }
  return actions;
}

ArbitrationActions TransportArbiter::Disable(const Path path,
                                             const std::uint64_t now_ms) {
  const bool wifi_was_candidate = wifi_candidate_active_;
  const bool ble_was_available = availability_.bluetooth;
  if (path == Path::kWifi) {
    availability_.wifi = false;
    wifi_candidate_active_ = false;
  } else if (path == Path::kBluetooth) {
    availability_.bluetooth = false;
    ClearBleCandidate();
  } else {
    return {};
  }
  ArbitrationActions actions{};
  actions.fail_closed = true;
  if (active_path_ == Path::kNone && path == Path::kBluetooth &&
      ble_was_available && wifi_was_candidate && availability_.wifi) {
    wifi_candidate_active_ = true;
    return actions;
  }
  if (active_path_ == Path::kNone && path == Path::kWifi &&
      availability_.bluetooth && (ble_advertising_ || ble_connected_)) {
    if (ble_connected_) {
      ble_authentication_permitted_ = true;
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
      !wifi_retry_required_ &&
      DeadlineReached(now_ms, selection_started_ms_,
                      protocol::kBleAdvertisingDelayMs)) {
    ble_advertising_ = true;
    wifi_retry_started_ms_ = now_ms;
    actions.start_ble_advertising = true;
  }
  return actions;
}

ArbitrationActions TransportArbiter::Poll(std::uint64_t now_ms) {
  if (active_path_ != Path::kNone) {
    return {};
  }
  auto actions = StartBleAdvertisingIfAllowed(now_ms);
  if (availability_.wifi && !availability_.bluetooth &&
      !wifi_candidate_active_ && wifi_retry_required_ &&
      DeadlineReached(now_ms, wifi_retry_started_ms_,
                      protocol::kBleWifiRetryIntervalMs)) {
    wifi_retry_required_ = false;
    wifi_candidate_active_ = true;
    selection_started_ms_ = now_ms;
    actions.start_wifi = true;
  }
  if (wifi_candidate_active_ &&
      DeadlineReached(now_ms, selection_started_ms_,
                      protocol::kBleWifiPreferenceMs)) {
    wifi_candidate_active_ = false;
    actions.cancel_wifi = true;
    if (ble_connected_) {
      ble_authentication_permitted_ = true;
      actions.start_ble_authentication = true;
    }
  }
  if (availability_.wifi && !wifi_candidate_active_ && ble_advertising_ &&
      !ble_connected_ &&
      DeadlineReached(now_ms, wifi_retry_started_ms_,
                      protocol::kBleWifiRetryIntervalMs)) {
    ClearBleCandidate();
    wifi_candidate_active_ = true;
    selection_started_ms_ = now_ms;
    actions.stop_ble = true;
    actions.start_wifi = true;
  }
  return actions;
}

ArbitrationActions TransportArbiter::WifiAttemptFinished(
    bool authenticated, std::uint64_t now_ms) {
  if (active_path_ != Path::kNone || !wifi_candidate_active_) {
    return {};
  }
  wifi_candidate_active_ = false;
  if (authenticated) {
    active_path_ = Path::kWifi;
    ArbitrationActions actions{};
    actions.stop_ble = ble_advertising_ || ble_connected_;
    ClearBleCandidate();
    consecutive_ble_failures_ = 0;
    wifi_retry_required_ = false;
    return actions;
  }

  ArbitrationActions actions{};
  actions.fail_closed = true;
  if (!availability_.bluetooth) {
    if (availability_.wifi) {
      wifi_retry_required_ = true;
      wifi_retry_started_ms_ = now_ms;
    }
    return actions;
  }
  if (wifi_retry_required_) {
    wifi_retry_required_ = false;
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
      DeadlineReached(now_ms, selection_started_ms_,
                      protocol::kBleWifiPreferenceMs)) {
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
  consecutive_ble_failures_ = 0;
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
      wifi_retry_started_ms_ = now_ms;
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
  wifi_retry_required_ = false;
  ClearBleCandidate();
}

bool TransportArbiter::InstallTargetedOwner(const Path path) {
  if (path == Path::kNone ||
      (path == Path::kWifi && !availability_.wifi) ||
      (path == Path::kBluetooth && !availability_.bluetooth)) {
    return false;
  }
  active_path_ = path;
  wifi_candidate_active_ = false;
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
