#include "keyferry/recovery_anchor.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>

namespace {

template <std::size_t Size>
std::array<std::uint8_t, Size> Filled(const std::uint8_t value) {
  std::array<std::uint8_t, Size> output{};
  output.fill(value);
  return output;
}

keyferry::config::AuthenticatedPolicyIdentity InitialPolicy() {
  return {
      Filled<16>(0x11), Filled<16>(0x22), Filled<32>(0x33), 1, 1,
      Filled<32>(0x44), 0, {},
  };
}

keyferry::config::RecoveryAnchor PendingAnchor() {
  keyferry::config::RecoveryAnchor anchor{};
  assert(keyferry::config::PrepareMigrationAnchor(
      InitialPolicy(), Filled<32>(0x55), Filled<16>(0x66), &anchor));
  return anchor;
}

keyferry::config::RecoveryAnchor ActiveAnchor() {
  const auto pending = PendingAnchor();
  keyferry::config::RecoveryAnchor active{};
  assert(keyferry::config::ActivateMigration(pending, &active));
  return active;
}

keyferry::config::RecoveryAnchorInspection Inspection(
    const keyferry::config::RecoveryAnchor& anchor) {
  std::array<std::uint8_t, keyferry::config::kRecoveryAnchorBytes> bytes{};
  assert(keyferry::config::EncodeRecoveryAnchor(anchor, &bytes));
  return keyferry::config::InspectRecoveryAnchor(bytes.data(), bytes.size());
}

void TestAnchorCodecAndCorruption() {
  using namespace keyferry::config;
  const auto anchor = PendingAnchor();
  std::array<std::uint8_t, kRecoveryAnchorBytes> bytes{};
  assert(EncodeRecoveryAnchor(anchor, &bytes));
  const auto decoded = InspectRecoveryAnchor(bytes.data(), bytes.size());
  assert(decoded.condition == RecoveryAnchorCondition::kValid);
  assert(decoded.anchor.device_recovery_secret == anchor.device_recovery_secret);
  assert(decoded.anchor.policy_hash == anchor.policy_hash);

  auto corrupt = bytes;
  corrupt[79] ^= 1;
  assert(InspectRecoveryAnchor(corrupt.data(), corrupt.size()).condition ==
         RecoveryAnchorCondition::kMalformed);
  for (std::size_t written = 0; written < bytes.size(); ++written) {
    std::array<std::uint8_t, kRecoveryAnchorBytes> torn{};
    torn.fill(0xFF);
    std::copy_n(bytes.begin(), written, torn.begin());
    assert(InspectRecoveryAnchor(torn.data(), torn.size()).condition !=
           RecoveryAnchorCondition::kValid);
  }
  bytes.fill(0xFF);
  assert(InspectRecoveryAnchor(bytes.data(), bytes.size()).condition ==
         RecoveryAnchorCondition::kErased);
  assert(InspectRecoveryAnchor(nullptr, 0).condition ==
         RecoveryAnchorCondition::kMalformed);
}

void TestMissingAndPendingAnchorsNeverRunOperationalTrust() {
  using namespace keyferry::config;
  RecoveryAnchorInspection missing{RecoveryAnchorCondition::kErased, {}};
  auto policy = InitialPolicy();
  assert(ReconcilePolicy(missing, &policy) == PolicyReconciliation::kLockedRecovery);
  assert(ReconcilePolicy(Inspection(PendingAnchor()), &policy) ==
         PolicyReconciliation::kLockedMigration);
  assert(ReconcilePolicy(Inspection(ActiveAnchor()), nullptr) ==
         PolicyReconciliation::kLockedPolicy);
}

void TestMigrationNeedsTwoMatchingV2Slots() {
  using namespace keyferry::config;
  const auto pending = PendingAnchor();
  const auto policy = InitialPolicy();
  assert(CanActivateMigration(pending, policy, policy));
  auto mismatch = policy;
  mismatch.hash[0] ^= 1;
  assert(!CanActivateMigration(pending, policy, mismatch));
  RecoveryAnchor active{};
  assert(ActivateMigration(pending, &active));
  assert(active.phase == RecoveryAnchorPhase::kActive);
  assert(!CanActivateMigration(active, policy, policy));
}

void TestPolicyFloorAllowsCurrentAndOnlyOneAuthenticatedSuccessor() {
  using namespace keyferry::config;
  const auto active = ActiveAnchor();
  const auto current = InitialPolicy();
  assert(ReconcilePolicy(Inspection(active), &current) == PolicyReconciliation::kReady);

  auto next = current;
  next.sequence = 2;
  next.previous_sequence = 1;
  next.previous_hash = current.hash;
  next.hash = Filled<32>(0x77);
  assert(ReconcilePolicy(Inspection(active), &next) ==
         PolicyReconciliation::kAdvanceFloor);

  auto wrong_previous = next;
  wrong_previous.previous_hash[0] ^= 1;
  assert(ReconcilePolicy(Inspection(active), &wrong_previous) ==
         PolicyReconciliation::kLockedRollback);
  auto skipped = next;
  skipped.sequence = 3;
  skipped.previous_sequence = 2;
  assert(ReconcilePolicy(Inspection(active), &skipped) ==
         PolicyReconciliation::kLockedRollback);
  auto wrong_owner = next;
  wrong_owner.owner_id[0] ^= 1;
  assert(ReconcilePolicy(Inspection(active), &wrong_owner) ==
         PolicyReconciliation::kLockedRollback);

  RecoveryAnchor advanced{};
  assert(AdvancePolicyFloor(active, next, Filled<16>(0x78), &advanced));
  assert(advanced.policy_sequence == 2 && advanced.policy_hash == next.hash);
  assert(ReconcilePolicy(Inspection(advanced), &current) ==
         PolicyReconciliation::kLockedRollback);
  assert(ReconcilePolicy(Inspection(advanced), &next) == PolicyReconciliation::kReady);
}

void TestEpochRotationIsExactlyOneStep() {
  using namespace keyferry::config;
  const auto active = ActiveAnchor();
  auto rotated = InitialPolicy();
  rotated.epoch = 2;
  rotated.sequence = 2;
  rotated.previous_sequence = 1;
  rotated.previous_hash = active.policy_hash;
  rotated.hash = Filled<32>(0x79);
  assert(ReconcilePolicy(Inspection(active), &rotated) ==
         PolicyReconciliation::kAdvanceFloor);
  rotated.epoch = 3;
  assert(ReconcilePolicy(Inspection(active), &rotated) ==
         PolicyReconciliation::kLockedRollback);
}

void TestInvalidInputsClearOutputs() {
  using namespace keyferry::config;
  auto invalid = InitialPolicy();
  invalid.owner_ca_sha256.fill(0);
  RecoveryAnchor anchor = ActiveAnchor();
  assert(!PrepareMigrationAnchor(invalid, Filled<32>(1), Filled<16>(2), &anchor));

  auto active = ActiveAnchor();
  std::array<std::uint8_t, kRecoveryAnchorBytes> encoded{};
  active.transaction_id.fill(0);
  encoded.fill(0xA5);
  assert(!EncodeRecoveryAnchor(active, &encoded));
  assert(std::all_of(encoded.begin(), encoded.end(),
                     [](const std::uint8_t byte) { return byte == 0; }));
}

}  // namespace

int main() {
  static_assert(keyferry::config::kRecoveryAnchorBytes == 180);
  TestAnchorCodecAndCorruption();
  TestMissingAndPendingAnchorsNeverRunOperationalTrust();
  TestMigrationNeedsTwoMatchingV2Slots();
  TestPolicyFloorAllowsCurrentAndOnlyOneAuthenticatedSuccessor();
  TestEpochRotationIsExactlyOneStep();
  TestInvalidInputsClearOutputs();
  std::puts("recovery_anchor_test: ok");
  return 0;
}
