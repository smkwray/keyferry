#pragma once

#include <array>
#include <cstdint>

#include "keyferry/config_storage.h"
#include "keyferry/roaming_storage.h"
#include "keyferry/roaming_config.h"
#include "keyferry/transport_runtime_config.h"

namespace keyferry::runtime_config {

enum class BootSource : std::uint8_t {
  kLocked,
  kPrivateBootstrap,
  kStored,
};

enum class BindStatus : std::uint8_t {
  kOk,
  kInvalidConfig,
  kIdentityMismatch,
  kUnsupportedProfileSet,
};

enum class BootStatus : std::uint8_t {
  kStored,
  kRoaming,
  kPrivateBootstrap,
  kLockedStorageIo,
  kLockedMalformedSlots,
  kLockedAmbiguousSlots,
  kLockedStorageState,
  kLockedBootstrapInvalid,
  kLockedStoredInvalid,
  kLockedIdentityMismatch,
  kLockedUnsupportedProfileSet,
  kLockedRecoveryIo,
  kLockedRecoveryMalformed,
  kLockedMigration,
  kLockedRoamingStorage,
  kLockedRoamingPolicy,
};

// Owns every byte referenced by runtime. Keep this object alive for the full
// lifetime of EspTransport.
struct StoredRuntime {
  config::EndpointConfig persisted{};
  std::array<char, transport::kIpv4TextCapacity> host_ipv4{};
  std::array<char, config::kMaxServerNameBytes + 1> server_name{};
  transport::RuntimeConfig runtime{};
};

struct StoredRoamingRuntime {
  config::RoamingEndpointConfig persisted{};
  config::RecoveryAnchor anchor{};
  config::RoamingPolicyVerificationWorkspace verification_workspace{};
  roaming::DeviceGatewayName server_name{};
  transport::RuntimeConfig runtime{};
};

// Static boot-owned storage. Every pointer published through RuntimeConfig
// remains valid for the lifetime of the application. Keeping this off task
// stacks also makes the additional v2 memory visible in the linker map.
struct OperationalBootContext {
  config::StorageWorkspace legacy_workspace{};
  config::MigrationWorkspace migration_workspace{};
  std::array<std::uint8_t, config::kRecoveryAnchorBytes> anchor_bytes{};
  StoredRuntime legacy{};
  StoredRoamingRuntime roaming{};
};

BootSource SelectBootSource(config::StorageStatus status);
BindStatus BindStoredRuntime(const std::array<std::uint8_t, 16>& expected_device_id,
                             StoredRuntime* output);
BindStatus BindRoamingRuntime(
    const std::array<std::uint8_t, 16>& expected_device_id,
    config::RoamingPolicyCrypto& crypto, StoredRoamingRuntime* output);
BootStatus ResolveBootConfig(
    config::SlotStorage& storage,
    const std::array<std::uint8_t, 16>& expected_device_id,
    const transport::RuntimeConfig& private_bootstrap,
    config::StorageWorkspace* workspace, StoredRuntime* stored,
    transport::RuntimeConfig* output, config::Selection* selection);

// An absent recovery anchor is the only state allowed to consult the legacy
// slots or private bootstrap. Once an anchor exists, malformed, pending, or
// mismatched v2 state stays maintenance-only and can never resurrect legacy
// operational trust.
BootStatus ResolveOperationalBoot(
    config::SlotStorage& slots, config::RecoveryAnchorStorage& anchors,
    const std::array<std::uint8_t, 16>& expected_device_id,
    const transport::RuntimeConfig& private_bootstrap,
    config::RoamingPolicyCrypto& crypto, OperationalBootContext* context,
    transport::RuntimeConfig* output, config::Selection* selection);

}  // namespace keyferry::runtime_config
