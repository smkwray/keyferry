#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>

#include "keyferry_protocol_generated.h"

namespace keyferry::transport {

// Metadata only. The sole transport task owns the in-flight state; callers
// synchronize copying completed() with Close(). No identity or secret is kept.
struct WifiAttemptStatus {
  protocol::WifiRejectReason last_wifi_reject_reason{protocol::WifiRejectReason::kNone};
  bool beacon_tls_identity_equal{};
  bool identity_checked{};
  bool tls_verified{};
  std::uint32_t attempt_count{};
  std::uint32_t elapsed_to_tls_ms{};
  std::uint32_t elapsed_to_close_ms{};
  std::uint8_t endpoint_reject_site{};
  std::uint8_t endpoint_message_type{};
  std::uint32_t endpoint_sequence{};
};

class WifiAttemptDiagnostics {
 public:
  void Start(std::uint64_t now_ms) {
    if (attempt_count_ != std::numeric_limits<std::uint32_t>::max()) ++attempt_count_;
    started_ms_ = now_ms;
    current_ = {};
    current_.attempt_count = attempt_count_;
    open_ = true;
  }
  void TlsVerified(std::uint64_t now_ms) {
    if (!open_) return;
    current_.tls_verified = true;
    current_.elapsed_to_tls_ms = Elapsed(now_ms);
  }
  void IdentityCompared(bool equal) {
    if (!open_) return;
    current_.identity_checked = true;
    current_.beacon_tls_identity_equal = equal;
  }
  void Reject(protocol::WifiRejectReason reason) {
    if (open_ && current_.last_wifi_reject_reason == protocol::WifiRejectReason::kNone)
      current_.last_wifi_reject_reason = reason;
  }
  void Close(std::uint64_t now_ms) {
    if (!open_) return;
    current_.elapsed_to_close_ms = Elapsed(now_ms);
    completed_ = current_;
    open_ = false;
  }
  void EndpointRejected(std::uint8_t site, std::uint8_t type, std::uint32_t sequence) {
    if (!open_) return;
    current_.endpoint_reject_site = site;
    current_.endpoint_message_type = type;
    current_.endpoint_sequence = sequence;
  }
  [[nodiscard]] WifiAttemptStatus completed() const { return completed_; }

 private:
  std::uint32_t Elapsed(std::uint64_t now_ms) const {
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(
        now_ms >= started_ms_ ? now_ms - started_ms_ : 0,
        std::numeric_limits<std::uint32_t>::max()));
  }
  WifiAttemptStatus current_{};
  WifiAttemptStatus completed_{};
  std::uint64_t started_ms_{};
  std::uint32_t attempt_count_{};
  bool open_{};
};

}  // namespace keyferry::transport
