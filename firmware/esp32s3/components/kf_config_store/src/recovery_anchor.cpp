#include "keyferry/recovery_anchor.h"

#include <algorithm>
#include <limits>

#include "keyferry/config_store.h"

namespace keyferry::config {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{'K', 'F', 'R', '2'};
constexpr std::uint16_t kFormatVersion = 1;
constexpr std::size_t kCrcOffset = kRecoveryAnchorBytes - 4;

template <std::size_t Size>
bool AnyNonzero(const std::array<std::uint8_t, Size>& value) {
  return std::any_of(value.begin(), value.end(),
                     [](const std::uint8_t byte) { return byte != 0; });
}

template <std::size_t Size>
bool AllZero(const std::array<std::uint8_t, Size>& value) {
  return !AnyNonzero(value);
}

void PutU16(std::uint8_t* output, const std::uint16_t value) {
  output[0] = static_cast<std::uint8_t>(value >> 8);
  output[1] = static_cast<std::uint8_t>(value);
}

void PutU32(std::uint8_t* output, const std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    *output++ = static_cast<std::uint8_t>(value >> shift);
  }
}

void PutU64(std::uint8_t* output, const std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    *output++ = static_cast<std::uint8_t>(value >> shift);
  }
}

std::uint16_t GetU16(const std::uint8_t* input) {
  return static_cast<std::uint16_t>(input[0]) << 8 |
         static_cast<std::uint16_t>(input[1]);
}

std::uint32_t GetU32(const std::uint8_t* input) {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value = (value << 8) | input[index];
  }
  return value;
}

std::uint64_t GetU64(const std::uint8_t* input) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value = (value << 8) | input[index];
  }
  return value;
}

template <std::size_t Size>
void Append(std::array<std::uint8_t, kRecoveryAnchorBytes>* output,
            std::size_t* offset, const std::array<std::uint8_t, Size>& value) {
  std::copy(value.begin(), value.end(), output->begin() + *offset);
  *offset += value.size();
}

template <std::size_t Size>
std::array<std::uint8_t, Size> Take(const std::uint8_t* input,
                                   std::size_t* offset) {
  std::array<std::uint8_t, Size> value{};
  std::copy_n(input + *offset, Size, value.begin());
  *offset += Size;
  return value;
}

bool SameAuthority(const RecoveryAnchor& anchor,
                   const AuthenticatedPolicyIdentity& policy) {
  return anchor.device_id == policy.device_id && anchor.owner_id == policy.owner_id &&
         anchor.owner_ca_sha256 == policy.owner_ca_sha256;
}

bool IsCurrentPolicy(const RecoveryAnchor& anchor,
                     const AuthenticatedPolicyIdentity& policy) {
  return SameAuthority(anchor, policy) && anchor.epoch == policy.epoch &&
         anchor.policy_sequence == policy.sequence && anchor.policy_hash == policy.hash;
}

bool IsNextPolicy(const RecoveryAnchor& anchor,
                  const AuthenticatedPolicyIdentity& policy) {
  if (!SameAuthority(anchor, policy) ||
      anchor.policy_sequence == std::numeric_limits<std::uint64_t>::max() ||
      policy.sequence != anchor.policy_sequence + 1 ||
      policy.previous_sequence != anchor.policy_sequence ||
      policy.previous_hash != anchor.policy_hash) {
    return false;
  }
  return policy.epoch == anchor.epoch ||
         (anchor.epoch != std::numeric_limits<std::uint64_t>::max() &&
          policy.epoch == anchor.epoch + 1);
}

}  // namespace

bool ValidateAuthenticatedPolicyIdentity(const AuthenticatedPolicyIdentity& policy) {
  if (!AnyNonzero(policy.device_id) || !AnyNonzero(policy.owner_id) ||
      !AnyNonzero(policy.owner_ca_sha256) || policy.epoch == 0 || policy.sequence == 0 ||
      !AnyNonzero(policy.hash)) {
    return false;
  }
  if (policy.sequence == 1) {
    return policy.previous_sequence == 0 && AllZero(policy.previous_hash);
  }
  return policy.previous_sequence == policy.sequence - 1 &&
         AnyNonzero(policy.previous_hash);
}

bool ValidateRecoveryAnchor(const RecoveryAnchor& anchor) {
  const bool valid_phase = anchor.phase == RecoveryAnchorPhase::kMigrationPending ||
                           anchor.phase == RecoveryAnchorPhase::kActive;
  return valid_phase && AnyNonzero(anchor.device_id) && AnyNonzero(anchor.owner_id) &&
         AnyNonzero(anchor.owner_ca_sha256) &&
         AnyNonzero(anchor.device_recovery_secret) && anchor.epoch != 0 &&
         anchor.policy_sequence != 0 && AnyNonzero(anchor.policy_hash) &&
         AnyNonzero(anchor.transaction_id);
}

bool EncodeRecoveryAnchor(
    const RecoveryAnchor& anchor,
    std::array<std::uint8_t, kRecoveryAnchorBytes>* output) {
  if (output == nullptr) {
    return false;
  }
  output->fill(0);
  if (!ValidateRecoveryAnchor(anchor)) {
    return false;
  }
  std::size_t offset = 0;
  Append(output, &offset, kMagic);
  PutU16(output->data() + offset, kFormatVersion);
  offset += 2;
  PutU16(output->data() + offset, static_cast<std::uint16_t>(kRecoveryAnchorBytes));
  offset += 2;
  (*output)[offset++] = static_cast<std::uint8_t>(anchor.phase);
  offset += 7;
  PutU64(output->data() + offset, anchor.epoch);
  offset += 8;
  PutU64(output->data() + offset, anchor.policy_sequence);
  offset += 8;
  Append(output, &offset, anchor.device_id);
  Append(output, &offset, anchor.owner_id);
  Append(output, &offset, anchor.owner_ca_sha256);
  Append(output, &offset, anchor.device_recovery_secret);
  Append(output, &offset, anchor.policy_hash);
  Append(output, &offset, anchor.transaction_id);
  if (offset != kCrcOffset) {
    output->fill(0);
    return false;
  }
  PutU32(output->data() + offset, Crc32(output->data(), kCrcOffset));
  return true;
}

RecoveryAnchorInspection InspectRecoveryAnchor(const std::uint8_t* bytes,
                                               const std::size_t length) {
  RecoveryAnchorInspection inspection{};
  if (bytes == nullptr || length != kRecoveryAnchorBytes) {
    return inspection;
  }
  if (std::all_of(bytes, bytes + length,
                  [](const std::uint8_t byte) { return byte == 0xFF; })) {
    inspection.condition = RecoveryAnchorCondition::kErased;
    return inspection;
  }
  if (!std::equal(kMagic.begin(), kMagic.end(), bytes) || GetU16(bytes + 4) != kFormatVersion ||
      GetU16(bytes + 6) != kRecoveryAnchorBytes ||
      !std::all_of(bytes + 9, bytes + 16,
                   [](const std::uint8_t byte) { return byte == 0; }) ||
      GetU32(bytes + kCrcOffset) != Crc32(bytes, kCrcOffset)) {
    return inspection;
  }
  RecoveryAnchor anchor{};
  anchor.phase = static_cast<RecoveryAnchorPhase>(bytes[8]);
  std::size_t offset = 16;
  anchor.epoch = GetU64(bytes + offset);
  offset += 8;
  anchor.policy_sequence = GetU64(bytes + offset);
  offset += 8;
  anchor.device_id = Take<16>(bytes, &offset);
  anchor.owner_id = Take<16>(bytes, &offset);
  anchor.owner_ca_sha256 = Take<32>(bytes, &offset);
  anchor.device_recovery_secret = Take<32>(bytes, &offset);
  anchor.policy_hash = Take<32>(bytes, &offset);
  anchor.transaction_id = Take<16>(bytes, &offset);
  if (offset != kCrcOffset || !ValidateRecoveryAnchor(anchor)) {
    return inspection;
  }
  inspection.condition = RecoveryAnchorCondition::kValid;
  inspection.anchor = anchor;
  return inspection;
}

PolicyReconciliation ReconcilePolicy(
    const RecoveryAnchorInspection& inspection,
    const AuthenticatedPolicyIdentity* selected_policy) {
  if (inspection.condition != RecoveryAnchorCondition::kValid ||
      !ValidateRecoveryAnchor(inspection.anchor)) {
    return PolicyReconciliation::kLockedRecovery;
  }
  if (inspection.anchor.phase == RecoveryAnchorPhase::kMigrationPending) {
    return PolicyReconciliation::kLockedMigration;
  }
  if (selected_policy == nullptr || !ValidateAuthenticatedPolicyIdentity(*selected_policy)) {
    return PolicyReconciliation::kLockedPolicy;
  }
  if (IsCurrentPolicy(inspection.anchor, *selected_policy)) {
    return PolicyReconciliation::kReady;
  }
  if (IsNextPolicy(inspection.anchor, *selected_policy)) {
    return PolicyReconciliation::kAdvanceFloor;
  }
  return PolicyReconciliation::kLockedRollback;
}

bool PrepareMigrationAnchor(const AuthenticatedPolicyIdentity& initial_policy,
                            const RecoverySecret& recovery_secret,
                            const RecoveryTransactionId& transaction_id,
                            RecoveryAnchor* output) {
  if (output == nullptr) {
    return false;
  }
  *output = {};
  if (!ValidateAuthenticatedPolicyIdentity(initial_policy) ||
      initial_policy.sequence != 1 || initial_policy.previous_sequence != 0 ||
      !AllZero(initial_policy.previous_hash) || !AnyNonzero(recovery_secret) ||
      !AnyNonzero(transaction_id)) {
    return false;
  }
  *output = {
      RecoveryAnchorPhase::kMigrationPending,
      initial_policy.device_id,
      initial_policy.owner_id,
      initial_policy.owner_ca_sha256,
      recovery_secret,
      initial_policy.epoch,
      initial_policy.sequence,
      initial_policy.hash,
      transaction_id,
  };
  return ValidateRecoveryAnchor(*output);
}

bool CanActivateMigration(const RecoveryAnchor& pending,
                          const AuthenticatedPolicyIdentity& slot_a,
                          const AuthenticatedPolicyIdentity& slot_b) {
  return ValidateRecoveryAnchor(pending) &&
         pending.phase == RecoveryAnchorPhase::kMigrationPending &&
         ValidateAuthenticatedPolicyIdentity(slot_a) &&
         ValidateAuthenticatedPolicyIdentity(slot_b) && IsCurrentPolicy(pending, slot_a) &&
         IsCurrentPolicy(pending, slot_b);
}

bool ActivateMigration(const RecoveryAnchor& pending, RecoveryAnchor* output) {
  if (output == nullptr) {
    return false;
  }
  *output = {};
  if (!ValidateRecoveryAnchor(pending) ||
      pending.phase != RecoveryAnchorPhase::kMigrationPending) {
    return false;
  }
  *output = pending;
  output->phase = RecoveryAnchorPhase::kActive;
  return true;
}

bool AdvancePolicyFloor(const RecoveryAnchor& active,
                        const AuthenticatedPolicyIdentity& next_policy,
                        const RecoveryTransactionId& transaction_id,
                        RecoveryAnchor* output) {
  if (output == nullptr) {
    return false;
  }
  *output = {};
  if (!ValidateRecoveryAnchor(active) ||
      active.phase != RecoveryAnchorPhase::kActive || !AnyNonzero(transaction_id)) {
    return false;
  }
  RecoveryAnchorInspection inspection{RecoveryAnchorCondition::kValid, active};
  if (ReconcilePolicy(inspection, &next_policy) != PolicyReconciliation::kAdvanceFloor) {
    return false;
  }
  *output = active;
  output->epoch = next_policy.epoch;
  output->policy_sequence = next_policy.sequence;
  output->policy_hash = next_policy.hash;
  output->transaction_id = transaction_id;
  return ValidateRecoveryAnchor(*output);
}

}  // namespace keyferry::config
