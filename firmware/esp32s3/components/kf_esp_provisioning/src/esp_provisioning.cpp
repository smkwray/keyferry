#include "keyferry/esp_provisioning.h"

#include <algorithm>

#include "bootloader_random.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "psa/crypto.h"

namespace keyferry::provisioning {
namespace {

void SecureClear(void* data, std::size_t length) {
  volatile auto* output = static_cast<volatile std::uint8_t*>(data);
  while (length-- != 0) {
    *output++ = 0;
  }
}

}  // namespace

IdfProvisioningEffects::IdfProvisioningEffects(
    config::IdfConfigStorage& storage, config::StorageWorkspace& workspace,
    config::IdfRecoveryAnchorStorage& anchor_storage,
    config::IdfRoamingPolicyCrypto& roaming_crypto,
    config::MigrationWorkspace& migration_workspace)
    : storage_(storage),
      workspace_(workspace),
      anchor_storage_(anchor_storage),
      roaming_crypto_(roaming_crypto),
      migration_workspace_(migration_workspace) {}

IdfProvisioningEffects::~IdfProvisioningEffects() {
  SecureClear(random_pool_.data(), random_pool_.size());
  SecureClear(&migration_request_, sizeof(migration_request_));
}

bool IdfProvisioningEffects::InitializeRandom() {
  if (random_ready_) {
    return true;
  }
  bootloader_random_enable();
  esp_fill_random(random_pool_.data(), random_pool_.size());
  bootloader_random_disable();
  random_offset_ = 0;
  random_ready_ = true;
  return true;
}

bool IdfProvisioningEffects::FillRandom(std::uint8_t* output,
                                        const std::size_t length) {
  if (!random_ready_ || output == nullptr || length == 0 ||
      length > random_pool_.size() - random_offset_) {
    return false;
  }
  std::copy_n(random_pool_.data() + random_offset_, length, output);
  SecureClear(random_pool_.data() + random_offset_, length);
  random_offset_ += length;
  return true;
}

bool IdfProvisioningEffects::HmacSha256(
    const std::array<std::uint8_t, 32>& key, const ByteSpan* parts,
    const std::size_t part_count, std::array<std::uint8_t, 32>* output) {
  if (parts == nullptr || part_count == 0 || output == nullptr) {
    return false;
  }
  output->fill(0);
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
  psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
  psa_set_key_bits(&attributes, key.size() * 8U);
  mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
  psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
  bool ok = psa_import_key(&attributes, key.data(), key.size(), &key_id) ==
                PSA_SUCCESS &&
            psa_mac_sign_setup(&operation, key_id,
                               PSA_ALG_HMAC(PSA_ALG_SHA_256)) == PSA_SUCCESS;
  psa_reset_key_attributes(&attributes);
  for (std::size_t index = 0; ok && index < part_count; ++index) {
    if (parts[index].data == nullptr && parts[index].size != 0) {
      ok = false;
    } else if (parts[index].size != 0) {
      ok = psa_mac_update(&operation, parts[index].data, parts[index].size) ==
           PSA_SUCCESS;
    }
  }
  if (ok) {
    std::size_t output_length = 0;
    ok = psa_mac_sign_finish(&operation, output->data(), output->size(),
                             &output_length) == PSA_SUCCESS &&
         output_length == output->size();
  }
  psa_mac_abort(&operation);
  if (MBEDTLS_SVC_KEY_ID_GET_KEY_ID(key_id) != 0) {
    psa_destroy_key(key_id);
  }
  if (!ok) {
    SecureClear(output->data(), output->size());
  }
  return ok;
}

std::uint64_t IdfProvisioningEffects::MonotonicMilliseconds() {
  const std::int64_t microseconds = esp_timer_get_time();
  return microseconds > 0 ? static_cast<std::uint64_t>(microseconds / 1000) : 0;
}

config::StorageStatus IdfProvisioningEffects::Commit(
    const config::EndpointConfig& config, config::Selection* selection) {
  if (!storage_.ready()) {
    if (selection != nullptr) {
      *selection = {};
    }
    return config::StorageStatus::kIoError;
  }
  return config::CommitConfig(storage_, &workspace_, config, selection);
}

config::MigrationStatus IdfProvisioningEffects::MigrateToRoaming(
    const config::RoamingEndpointConfig& roaming_config,
    const config::RecoverySecret& recovery_secret,
    const config::RecoveryTransactionId& transaction_id) {
  if (!storage_.ready()) {
    return config::MigrationStatus::kIoError;
  }
  // Assign the persistent request in place. Aggregate assignment materializes
  // a roughly 3 KiB temporary in this call frame on Xtensa GCC.
  migration_request_.config = roaming_config;
  migration_request_.recovery_secret = recovery_secret;
  migration_request_.transaction_id = transaction_id;
  const config::MigrationStatus status = config::MigrateToRoaming(
      storage_, anchor_storage_, roaming_crypto_, &migration_workspace_,
      &migration_request_);
  SecureClear(&migration_request_, sizeof(migration_request_));
  return status;
}

}  // namespace keyferry::provisioning
