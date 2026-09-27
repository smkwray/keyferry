#pragma once

#include <array>
#include <cstdint>

#include "gateway_handoff_protocol.h"

namespace keyferry::transport {

enum class GatewayHandoffStartResult : std::uint8_t {
  kStarted = 0,
  kDuplicate,
  kBusy,
  kInvalid,
};

class GatewayHandoffManager {
 public:
  void Boot();

  GatewayHandoffStartResult Start(
      const protocol::GatewayHandoffRequest& request,
      const std::array<std::uint8_t, 16>& previous_installation_id,
      const std::array<std::uint8_t, 16>& device_boot_nonce,
      const std::array<std::uint8_t, 16>& current_endpoint_session,
      std::uint64_t now_ms);

  bool ReleaseCompleted(std::uint64_t now_ms);
  bool ReleaseFailed(std::uint64_t now_ms);
  void Poll(std::uint64_t now_ms);

  [[nodiscard]] bool CandidateAllowed(
      const std::array<std::uint8_t, 16>& installation_id) const;
  bool TargetAuthenticated(
      const std::array<std::uint8_t, 16>& installation_id,
      const std::array<std::uint8_t, 16>& endpoint_session_id,
      std::uint64_t now_ms);
  bool InstallTarget(
      const protocol::GatewayHandoffRequest& request,
      const std::array<std::uint8_t, 32>& verified_proof_digest,
      std::uint64_t now_ms);
  bool TargetFailed(protocol::GatewayHandoffReason reason,
                    std::uint64_t now_ms);
  bool PreviousAuthenticated(
      const std::array<std::uint8_t, 16>& installation_id,
      const std::array<std::uint8_t, 16>& endpoint_session_id,
      std::uint64_t now_ms);
  bool RecoveryFailed(std::uint64_t now_ms);

  [[nodiscard]] bool active() const;
  [[nodiscard]] bool targeting() const;
  [[nodiscard]] bool restoring() const;
  [[nodiscard]] bool terminal() const;
  [[nodiscard]] bool MatchesTransaction(
      const std::array<std::uint8_t, 16>& transaction_id) const;
  bool ForgetTerminalIfExpired(std::uint64_t now_ms);
  [[nodiscard]] protocol::GatewayHandoffStatusPayload Status(
      protocol::GatewayHandoffOperation reply_operation,
      std::uint64_t now_ms) const;

 private:
  bool SameStart(const protocol::GatewayHandoffRequest& request) const;
  void EnterRestoring(protocol::GatewayHandoffReason reason,
                      std::uint64_t now_ms);
  void EnterTerminal(protocol::GatewayHandoffPhase phase,
                     protocol::GatewayHandoffReason reason,
                     std::uint64_t now_ms);
  static std::uint32_t Remaining(std::uint64_t deadline_ms,
                                 std::uint64_t now_ms);

  protocol::GatewayHandoffRequest start_{};
  protocol::GatewayHandoffPhase phase_{protocol::GatewayHandoffPhase::kUnknown};
  protocol::GatewayHandoffReason reason_{protocol::GatewayHandoffReason::kNone};
  std::array<std::uint8_t, 16> previous_installation_id_{};
  std::array<std::uint8_t, 16> device_boot_nonce_{};
  std::array<std::uint8_t, 16> current_endpoint_session_{};
  std::uint64_t release_deadline_ms_{};
  std::uint64_t phase_deadline_ms_{};
  std::uint64_t terminal_since_ms_{};
};

}  // namespace keyferry::transport
