#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace keyferry::config {

constexpr std::size_t kRecoveryAnchorBytes = 180;

using RecoveryDeviceId = std::array<std::uint8_t, 16>;
using RecoveryOwnerId = std::array<std::uint8_t, 16>;
using RecoverySecret = std::array<std::uint8_t, 32>;
using PolicyHash = std::array<std::uint8_t, 32>;
using OwnerCaHash = std::array<std::uint8_t, 32>;
using RecoveryTransactionId = std::array<std::uint8_t, 16>;

enum class RecoveryAnchorPhase : std::uint8_t {
  kMigrationPending = 1,
  kActive = 2,
};

// This record is independent of the operational A/B configuration. It contains
// no command, HID, arm, or retry state. Its sequence/hash is the minimum
// authority policy that an operational slot may activate.
struct RecoveryAnchor {
  RecoveryAnchorPhase phase{RecoveryAnchorPhase::kMigrationPending};
  RecoveryDeviceId device_id{};
  RecoveryOwnerId owner_id{};
  OwnerCaHash owner_ca_sha256{};
  RecoverySecret device_recovery_secret{};
  std::uint64_t epoch{0};
  std::uint64_t policy_sequence{0};
  PolicyHash policy_hash{};
  RecoveryTransactionId transaction_id{};
};

// The caller must construct this only after validating the complete v2 policy,
// including its recovery authentication and canonical revocation set.
struct AuthenticatedPolicyIdentity {
  RecoveryDeviceId device_id{};
  RecoveryOwnerId owner_id{};
  OwnerCaHash owner_ca_sha256{};
  std::uint64_t epoch{0};
  std::uint64_t sequence{0};
  PolicyHash hash{};
  std::uint64_t previous_sequence{0};
  PolicyHash previous_hash{};
};

enum class RecoveryAnchorCondition : std::uint8_t {
  kErased,
  kMalformed,
  kValid,
};

struct RecoveryAnchorInspection {
  RecoveryAnchorCondition condition{RecoveryAnchorCondition::kMalformed};
  RecoveryAnchor anchor{};
};

enum class PolicyReconciliation : std::uint8_t {
  kLockedRecovery,
  kLockedMigration,
  kLockedPolicy,
  kLockedRollback,
  kReady,
  kAdvanceFloor,
};

bool ValidateAuthenticatedPolicyIdentity(const AuthenticatedPolicyIdentity& policy);
bool ValidateRecoveryAnchor(const RecoveryAnchor& anchor);
bool EncodeRecoveryAnchor(
    const RecoveryAnchor& anchor,
    std::array<std::uint8_t, kRecoveryAnchorBytes>* output);
RecoveryAnchorInspection InspectRecoveryAnchor(const std::uint8_t* bytes,
                                               std::size_t length);

// A missing or malformed anchor never enables compiled or legacy operational
// trust. A pending migration remains maintenance-only. A policy one step ahead
// of the active floor may advance it only when its predecessor matches exactly.
PolicyReconciliation ReconcilePolicy(
    const RecoveryAnchorInspection& inspection,
    const AuthenticatedPolicyIdentity* selected_policy);

bool PrepareMigrationAnchor(const AuthenticatedPolicyIdentity& initial_policy,
                            const RecoverySecret& recovery_secret,
                            const RecoveryTransactionId& transaction_id,
                            RecoveryAnchor* output);
bool CanActivateMigration(const RecoveryAnchor& pending,
                          const AuthenticatedPolicyIdentity& slot_a,
                          const AuthenticatedPolicyIdentity& slot_b);
bool ActivateMigration(const RecoveryAnchor& pending, RecoveryAnchor* output);
bool AdvancePolicyFloor(const RecoveryAnchor& active,
                        const AuthenticatedPolicyIdentity& next_policy,
                        const RecoveryTransactionId& transaction_id,
                        RecoveryAnchor* output);

}  // namespace keyferry::config
