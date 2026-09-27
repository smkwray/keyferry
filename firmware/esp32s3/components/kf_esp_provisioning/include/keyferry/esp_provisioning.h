#pragma once

#include "keyferry/config_storage.h"
#include "keyferry/idf_config_storage.h"
#include "keyferry/idf_recovery_anchor_storage.h"
#include "keyferry/idf_roaming_policy_crypto.h"
#include "keyferry/provisioning.h"
namespace keyferry::provisioning {

// ESP-IDF effects for the portable provisioning state machine. The caller owns
// all objects and keeps the large storage workspace out of task stacks.
class IdfProvisioningEffects final : public Effects {
 public:
  IdfProvisioningEffects(config::IdfConfigStorage& storage,
                         config::StorageWorkspace& workspace,
                         config::IdfRecoveryAnchorStorage& anchor_storage,
                         config::IdfRoamingPolicyCrypto& roaming_crypto,
                         config::MigrationWorkspace& migration_workspace);
  ~IdfProvisioningEffects() override;

  IdfProvisioningEffects(const IdfProvisioningEffects&) = delete;
  IdfProvisioningEffects& operator=(const IdfProvisioningEffects&) = delete;

  // Must run during early app_main, before Wi-Fi or BLE starts using the RF/ADC
  // entropy sources. FillRandom fails closed until this succeeds.
  bool InitializeRandom();

  bool FillRandom(std::uint8_t* output, std::size_t length) override;
  bool HmacSha256(const std::array<std::uint8_t, 32>& key,
                  const ByteSpan* parts, std::size_t part_count,
                  std::array<std::uint8_t, 32>* output) override;
  std::uint64_t MonotonicMilliseconds() override;
  config::StorageStatus Commit(const config::EndpointConfig& config,
                               config::Selection* selection) override;
  config::MigrationStatus MigrateToRoaming(
      const config::RoamingEndpointConfig& config,
      const config::RecoverySecret& recovery_secret,
      const config::RecoveryTransactionId& transaction_id) override;

 private:
  config::IdfConfigStorage& storage_;
  config::StorageWorkspace& workspace_;
  config::IdfRecoveryAnchorStorage& anchor_storage_;
  config::IdfRoamingPolicyCrypto& roaming_crypto_;
  config::MigrationWorkspace& migration_workspace_;
  // This object has static lifetime in app_main. Keep the 3 KiB migration
  // request off the provisioning worker's FreeRTOS stack.
  config::AuthenticatedMigrationRequest migration_request_{};
  // Provisioning is intentionally bounded. Capture enough true entropy before
  // either radio starts, then consume each byte at most once. Exhaustion fails
  // closed and is recovered by rebooting, which refills this pool.
  std::array<std::uint8_t, 512> random_pool_{};
  std::size_t random_offset_{0};
  bool random_ready_{false};
};

}  // namespace keyferry::provisioning
