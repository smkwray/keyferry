#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry/config_storage.h"
#include "keyferry/roaming_config.h"

namespace keyferry::config {

struct RoamingStorageWorkspace {
  std::array<std::uint8_t, kRoamingConfigSlotBytes> slot_a{};
  std::array<std::uint8_t, kRoamingConfigSlotBytes> slot_b{};
};

StorageStatus LoadRoamingConfig(SlotStorage& storage,
                                RoamingStorageWorkspace* workspace,
                                RoamingEndpointConfig* config,
                                Selection* selection);
StorageStatus CommitRoamingConfig(SlotStorage& storage,
                                  RoamingStorageWorkspace* workspace,
                                  const RoamingEndpointConfig& config,
                                  Selection* selection);

enum class AnchorReadStatus : std::uint8_t {
  kOk,
  kNotFound,
  kIoError,
};

class RecoveryAnchorStorage {
 public:
  virtual ~RecoveryAnchorStorage() = default;
  virtual AnchorReadStatus Read(std::uint8_t* output, std::size_t length) = 0;
  virtual bool Write(const std::uint8_t* data, std::size_t length) = 0;
};

// The caller may construct this only after checking the recovery transaction
// authentication, canonical policy hash/tag, and owner CA hash.
struct AuthenticatedMigrationRequest {
  RoamingEndpointConfig config{};
  RecoverySecret recovery_secret{};
  RecoveryTransactionId transaction_id{};
};

struct MigrationWorkspace {
  RoamingStorageWorkspace roaming{};
  // MigrateToRoaming performs nested authenticated-policy verification. Keep
  // the decoded policy out of the caller's task stack while that verifier is
  // active.
  RoamingEndpointConfig policy{};
  std::array<std::uint8_t, kRecoveryAnchorBytes> anchor{};
  std::array<std::uint8_t, kRecoveryAnchorBytes> verification{};
};

enum class MigrationStatus : std::uint8_t {
  kReady,
  kLockedRecovery,
  kLockedMigration,
  kLockedPolicy,
  kConflict,
  kInvalidRequest,
  kIoError,
  kVerificationFailed,
};

// This is restart-safe for both first migration and active-policy updates. The
// first migration commits a pending recovery anchor before either operational
// slot changes; while pending, every boot remains maintenance-only. Once the
// anchor is active, a successor policy is committed to the inactive slot before
// the monotonic anchor floor advances. Repeating the exact authenticated request
// reconciles either interrupted sequence without creating another successor.
MigrationStatus MigrateToRoaming(
    SlotStorage& slots, RecoveryAnchorStorage& anchors,
    RoamingPolicyCrypto& crypto, MigrationWorkspace* workspace,
    const AuthenticatedMigrationRequest* request);

}  // namespace keyferry::config
