#include "keyferry/gateway_handoff.h"

#include <array>
#include <cassert>

namespace {

using keyferry::protocol::GatewayHandoffOperation;
using keyferry::protocol::GatewayHandoffPhase;
using keyferry::protocol::GatewayHandoffReason;
using keyferry::protocol::GatewayHandoffRequest;
using keyferry::transport::GatewayHandoffManager;
using keyferry::transport::GatewayHandoffStartResult;

GatewayHandoffRequest Start() {
  GatewayHandoffRequest output{};
  output.operation = GatewayHandoffOperation::kStart;
  output.transaction_id.fill(0x11);
  output.target_installation_id.fill(0x22);
  output.readiness_nonce.fill(0x33);
  output.proof_digest.fill(0x44);
  output.target_ipv4 = {192, 168, 30, 120};
  output.target_port = keyferry::protocol::kRoamingDeviceTlsPort;
  output.target_valid_ms =
      keyferry::protocol::kRoamingGatewayHandoffTargetValidMs;
  output.recovery_ms = keyferry::protocol::kRoamingGatewayHandoffRecoveryMs;
  return output;
}

void TestSuccessAndNoTimerExtension() {
  GatewayHandoffManager manager;
  manager.Boot();
  auto start = Start();
  std::array<std::uint8_t, 16> previous{};
  std::array<std::uint8_t, 16> boot{};
  std::array<std::uint8_t, 16> old_session{};
  previous.fill(0x66);
  boot.fill(0x77);
  old_session.fill(0x88);
  assert(manager.Start(start, previous, boot, old_session, 1000) ==
         GatewayHandoffStartResult::kStarted);
  assert(manager.Start(start, previous, boot, old_session, 1500) ==
         GatewayHandoffStartResult::kDuplicate);
  assert(manager.Status(GatewayHandoffOperation::kQuery, 1500)
             .remaining_phase_ms == 500);
  assert(manager.ReleaseCompleted(1800));
  assert(manager.CandidateAllowed(start.target_installation_id));
  assert(!manager.CandidateAllowed(previous));
  std::array<std::uint8_t, 16> target_session{};
  target_session.fill(0x99);
  assert(manager.TargetAuthenticated(start.target_installation_id, target_session,
                                     2500));
  GatewayHandoffRequest accept{};
  accept.operation = GatewayHandoffOperation::kAccept;
  accept.transaction_id = start.transaction_id;
  accept.readiness_nonce = start.readiness_nonce;
  accept.proof_digest.fill(0x55);
  assert(manager.InstallTarget(accept, accept.proof_digest, 2600));
  assert(manager.Status(GatewayHandoffOperation::kQuery, 2600).phase ==
         GatewayHandoffPhase::kTransferred);
  auto next = start;
  next.transaction_id.fill(0x12);
  assert(manager.Start(next, previous, boot, target_session, 62599) ==
         GatewayHandoffStartResult::kBusy);
  assert(!manager.ForgetTerminalIfExpired(62599));
  assert(manager.ForgetTerminalIfExpired(62600));
  assert(manager.Status(GatewayHandoffOperation::kQuery, 62600).phase ==
         GatewayHandoffPhase::kUnknown);
  assert(manager.Start(next, previous, boot, target_session, 62600) ==
         GatewayHandoffStartResult::kStarted);
}

void TestExactRollbackAndExpiry() {
  GatewayHandoffManager manager;
  manager.Boot();
  auto start = Start();
  std::array<std::uint8_t, 16> previous{};
  std::array<std::uint8_t, 16> boot{};
  std::array<std::uint8_t, 16> old_session{};
  previous.fill(0x66);
  boot.fill(0x77);
  old_session.fill(0x88);
  assert(manager.Start(start, previous, boot, old_session, 0) ==
         GatewayHandoffStartResult::kStarted);
  assert(manager.ReleaseCompleted(500));
  manager.Poll(6500);
  assert(manager.restoring());
  assert(manager.CandidateAllowed(previous));
  assert(!manager.CandidateAllowed(start.target_installation_id));
  std::array<std::uint8_t, 16> restored_session{};
  restored_session.fill(0xAA);
  assert(manager.PreviousAuthenticated(previous, restored_session, 7000));
  assert(manager.Status(GatewayHandoffOperation::kQuery, 7000).phase ==
         GatewayHandoffPhase::kRestored);

  manager.Boot();
  assert(manager.Start(start, previous, boot, old_session, 0) ==
         GatewayHandoffStartResult::kStarted);
  assert(manager.ReleaseCompleted(500));
  assert(manager.TargetFailed(GatewayHandoffReason::kTransportFailed, 1000));
  manager.Poll(7000);
  assert(manager.Status(GatewayHandoffOperation::kQuery, 7000).phase ==
         GatewayHandoffPhase::kRecoveryUnavailable);
}

void TestReleaseFailureNeverTargets() {
  GatewayHandoffManager manager;
  manager.Boot();
  auto start = Start();
  std::array<std::uint8_t, 16> previous{};
  std::array<std::uint8_t, 16> boot{};
  std::array<std::uint8_t, 16> session{};
  previous.fill(0x66);
  boot.fill(0x77);
  session.fill(0x88);
  assert(manager.Start(start, previous, boot, session, 0) ==
         GatewayHandoffStartResult::kStarted);
  manager.Poll(1001);
  assert(manager.Status(GatewayHandoffOperation::kQuery, 1001).phase ==
         GatewayHandoffPhase::kNotStarted);
  assert(!manager.CandidateAllowed(start.target_installation_id));
}

}  // namespace

int main() {
  TestSuccessAndNoTimerExtension();
  TestExactRollbackAndExpiry();
  TestReleaseFailureNeverTargets();
  return 0;
}
