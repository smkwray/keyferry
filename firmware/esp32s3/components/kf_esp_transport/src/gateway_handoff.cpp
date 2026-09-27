#include "keyferry/gateway_handoff.h"

#include <algorithm>

namespace keyferry::transport {
namespace {

constexpr std::uint64_t kReleaseDeadlineMs = 1000;
constexpr std::uint64_t kTerminalRetentionMs = 60000;

template <std::size_t Size>
bool Nonzero(const std::array<std::uint8_t, Size>& value) {
  return std::any_of(value.begin(), value.end(),
                     [](const std::uint8_t byte) { return byte != 0; });
}

}  // namespace

void GatewayHandoffManager::Boot() { *this = {}; }

GatewayHandoffStartResult GatewayHandoffManager::Start(
    const protocol::GatewayHandoffRequest& request,
    const std::array<std::uint8_t, 16>& previous_installation_id,
    const std::array<std::uint8_t, 16>& device_boot_nonce,
    const std::array<std::uint8_t, 16>& current_endpoint_session,
    const std::uint64_t now_ms) {
  if (request.operation != protocol::GatewayHandoffOperation::kStart ||
      !Nonzero(request.transaction_id) || !Nonzero(request.target_installation_id) ||
      !Nonzero(previous_installation_id) || !Nonzero(device_boot_nonce) ||
      !Nonzero(current_endpoint_session) ||
      request.target_installation_id == previous_installation_id ||
      request.target_valid_ms != protocol::kRoamingGatewayHandoffTargetValidMs ||
      request.recovery_ms != protocol::kRoamingGatewayHandoffRecoveryMs) {
    return GatewayHandoffStartResult::kInvalid;
  }
  if (active() || terminal()) {
    return SameStart(request) ? GatewayHandoffStartResult::kDuplicate
                              : GatewayHandoffStartResult::kBusy;
  }
  start_ = request;
  previous_installation_id_ = previous_installation_id;
  device_boot_nonce_ = device_boot_nonce;
  current_endpoint_session_ = current_endpoint_session;
  phase_ = protocol::GatewayHandoffPhase::kReleasing;
  reason_ = protocol::GatewayHandoffReason::kNone;
  release_deadline_ms_ = now_ms + kReleaseDeadlineMs;
  phase_deadline_ms_ = 0;
  terminal_since_ms_ = 0;
  return GatewayHandoffStartResult::kStarted;
}

bool GatewayHandoffManager::ReleaseCompleted(const std::uint64_t now_ms) {
  if (phase_ != protocol::GatewayHandoffPhase::kReleasing ||
      now_ms > release_deadline_ms_) {
    return false;
  }
  phase_ = protocol::GatewayHandoffPhase::kTargeting;
  reason_ = protocol::GatewayHandoffReason::kNone;
  release_deadline_ms_ = 0;
  phase_deadline_ms_ = now_ms + start_.target_valid_ms;
  return true;
}

bool GatewayHandoffManager::ReleaseFailed(const std::uint64_t now_ms) {
  if (phase_ != protocol::GatewayHandoffPhase::kReleasing) {
    return false;
  }
  EnterTerminal(protocol::GatewayHandoffPhase::kNotStarted,
                protocol::GatewayHandoffReason::kReleaseFailed, now_ms);
  return true;
}

void GatewayHandoffManager::Poll(const std::uint64_t now_ms) {
  if (phase_ == protocol::GatewayHandoffPhase::kReleasing &&
      now_ms > release_deadline_ms_) {
    ReleaseFailed(now_ms);
  } else if ((phase_ == protocol::GatewayHandoffPhase::kTargeting ||
              phase_ == protocol::GatewayHandoffPhase::kTargetProvisional) &&
             now_ms >= phase_deadline_ms_) {
    EnterRestoring(protocol::GatewayHandoffReason::kAcceptanceTimeout, now_ms);
  } else if (phase_ == protocol::GatewayHandoffPhase::kRestoring &&
             now_ms >= phase_deadline_ms_) {
    EnterTerminal(protocol::GatewayHandoffPhase::kRecoveryUnavailable,
                  protocol::GatewayHandoffReason::kPreviousGatewayUnavailable,
                  now_ms);
  }
}

bool GatewayHandoffManager::CandidateAllowed(
    const std::array<std::uint8_t, 16>& installation_id) const {
  if (targeting()) {
    return installation_id == start_.target_installation_id;
  }
  if (restoring()) {
    return installation_id == previous_installation_id_;
  }
  return false;
}

bool GatewayHandoffManager::TargetAuthenticated(
    const std::array<std::uint8_t, 16>& installation_id,
    const std::array<std::uint8_t, 16>& endpoint_session_id,
    const std::uint64_t now_ms) {
  Poll(now_ms);
  if (phase_ != protocol::GatewayHandoffPhase::kTargeting ||
      installation_id != start_.target_installation_id ||
      !Nonzero(endpoint_session_id)) {
    return false;
  }
  current_endpoint_session_ = endpoint_session_id;
  phase_ = protocol::GatewayHandoffPhase::kTargetProvisional;
  return true;
}

bool GatewayHandoffManager::InstallTarget(
    const protocol::GatewayHandoffRequest& request,
    const std::array<std::uint8_t, 32>& verified_proof_digest,
    const std::uint64_t now_ms) {
  Poll(now_ms);
  if (phase_ != protocol::GatewayHandoffPhase::kTargetProvisional ||
      request.operation != protocol::GatewayHandoffOperation::kAccept ||
      request.transaction_id != start_.transaction_id ||
      request.readiness_nonce != start_.readiness_nonce ||
      request.proof_digest != verified_proof_digest ||
      !Nonzero(verified_proof_digest)) {
    return false;
  }
  EnterTerminal(protocol::GatewayHandoffPhase::kTransferred,
                protocol::GatewayHandoffReason::kNone, now_ms);
  return true;
}

bool GatewayHandoffManager::TargetFailed(
    const protocol::GatewayHandoffReason reason, const std::uint64_t now_ms) {
  Poll(now_ms);
  if (!targeting()) {
    return false;
  }
  EnterRestoring(reason, now_ms);
  return true;
}

bool GatewayHandoffManager::PreviousAuthenticated(
    const std::array<std::uint8_t, 16>& installation_id,
    const std::array<std::uint8_t, 16>& endpoint_session_id,
    const std::uint64_t now_ms) {
  Poll(now_ms);
  if (phase_ != protocol::GatewayHandoffPhase::kRestoring ||
      installation_id != previous_installation_id_ ||
      !Nonzero(endpoint_session_id)) {
    return false;
  }
  current_endpoint_session_ = endpoint_session_id;
  EnterTerminal(protocol::GatewayHandoffPhase::kRestored,
                protocol::GatewayHandoffReason::kNone, now_ms);
  return true;
}

bool GatewayHandoffManager::RecoveryFailed(const std::uint64_t now_ms) {
  Poll(now_ms);
  if (phase_ != protocol::GatewayHandoffPhase::kRestoring) {
    return false;
  }
  EnterTerminal(protocol::GatewayHandoffPhase::kRecoveryUnavailable,
                protocol::GatewayHandoffReason::kPreviousGatewayUnavailable,
                now_ms);
  return true;
}

bool GatewayHandoffManager::active() const {
  return phase_ == protocol::GatewayHandoffPhase::kReleasing || targeting() ||
         restoring();
}

bool GatewayHandoffManager::targeting() const {
  return phase_ == protocol::GatewayHandoffPhase::kTargeting ||
         phase_ == protocol::GatewayHandoffPhase::kTargetProvisional;
}

bool GatewayHandoffManager::restoring() const {
  return phase_ == protocol::GatewayHandoffPhase::kRestoring;
}

bool GatewayHandoffManager::terminal() const {
  return phase_ == protocol::GatewayHandoffPhase::kTransferred ||
         phase_ == protocol::GatewayHandoffPhase::kRestored ||
         phase_ == protocol::GatewayHandoffPhase::kNotStarted ||
         phase_ == protocol::GatewayHandoffPhase::kRecoveryUnavailable;
}

bool GatewayHandoffManager::MatchesTransaction(
    const std::array<std::uint8_t, 16>& transaction_id) const {
  return phase_ != protocol::GatewayHandoffPhase::kUnknown &&
         transaction_id == start_.transaction_id;
}

bool GatewayHandoffManager::ForgetTerminalIfExpired(
    const std::uint64_t now_ms) {
  if (!terminal() || now_ms < terminal_since_ms_ ||
      now_ms - terminal_since_ms_ < kTerminalRetentionMs) {
    return false;
  }
  Boot();
  return true;
}

protocol::GatewayHandoffStatusPayload GatewayHandoffManager::Status(
    const protocol::GatewayHandoffOperation reply_operation,
    const std::uint64_t now_ms) const {
  protocol::GatewayHandoffStatusPayload output{};
  output.reply_operation = reply_operation;
  output.status = protocol::GatewayHandoffStatus::kOk;
  output.transaction_id = start_.transaction_id;
  output.phase = phase_;
  output.reason = reason_;
  if (phase_ == protocol::GatewayHandoffPhase::kReleasing) {
    output.remaining_phase_ms = Remaining(release_deadline_ms_, now_ms);
  } else if (targeting()) {
    output.remaining_phase_ms = Remaining(phase_deadline_ms_, now_ms);
    output.remaining_recovery_ms = start_.recovery_ms;
  } else if (restoring()) {
    output.remaining_recovery_ms = Remaining(phase_deadline_ms_, now_ms);
  }
  output.target_installation_id = start_.target_installation_id;
  output.previous_installation_id = previous_installation_id_;
  output.device_boot_nonce = device_boot_nonce_;
  output.current_endpoint_session = current_endpoint_session_;
  return output;
}

bool GatewayHandoffManager::SameStart(
    const protocol::GatewayHandoffRequest& request) const {
  return request.operation == protocol::GatewayHandoffOperation::kStart &&
         request.transaction_id == start_.transaction_id &&
         request.target_installation_id == start_.target_installation_id &&
         request.readiness_nonce == start_.readiness_nonce &&
         request.proof_digest == start_.proof_digest &&
         request.target_ipv4 == start_.target_ipv4 &&
         request.target_port == start_.target_port &&
         request.target_valid_ms == start_.target_valid_ms &&
         request.recovery_ms == start_.recovery_ms;
}

void GatewayHandoffManager::EnterRestoring(
    const protocol::GatewayHandoffReason reason, const std::uint64_t now_ms) {
  phase_ = protocol::GatewayHandoffPhase::kRestoring;
  reason_ = reason;
  phase_deadline_ms_ = now_ms + start_.recovery_ms;
  current_endpoint_session_.fill(0);
}

void GatewayHandoffManager::EnterTerminal(
    const protocol::GatewayHandoffPhase phase,
    const protocol::GatewayHandoffReason reason, const std::uint64_t now_ms) {
  phase_ = phase;
  reason_ = reason;
  release_deadline_ms_ = 0;
  phase_deadline_ms_ = 0;
  terminal_since_ms_ = now_ms;
}

std::uint32_t GatewayHandoffManager::Remaining(
    const std::uint64_t deadline_ms, const std::uint64_t now_ms) {
  if (now_ms >= deadline_ms) {
    return 0;
  }
  const std::uint64_t remaining = deadline_ms - now_ms;
  return remaining > UINT32_MAX ? UINT32_MAX
                                : static_cast<std::uint32_t>(remaining);
}

}  // namespace keyferry::transport
