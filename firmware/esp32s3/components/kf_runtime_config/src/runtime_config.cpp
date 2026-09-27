#include "keyferry/runtime_config.h"

#include <algorithm>
#include <cstdio>

namespace keyferry::runtime_config {

BootSource SelectBootSource(config::StorageStatus status) {
  if (status == config::StorageStatus::kOk) {
    return BootSource::kStored;
  }
  if (status == config::StorageStatus::kErasedUnprovisioned) {
    return BootSource::kPrivateBootstrap;
  }
  return BootSource::kLocked;
}

BindStatus BindStoredRuntime(const std::array<std::uint8_t, 16>& expected_device_id,
                             StoredRuntime* output) {
  if (output == nullptr || !config::ValidateConfig(output->persisted)) {
    return BindStatus::kInvalidConfig;
  }
  if (output->persisted.device_id != expected_device_id) {
    return BindStatus::kIdentityMismatch;
  }
  if (output->persisted.wifi_profile_count > 1 ||
      output->persisted.paired_host_count != 1) {
    return BindStatus::kUnsupportedProfileSet;
  }
  const auto& host = output->persisted.paired_hosts[0];
  if (output->persisted.wifi_profile_count == 1) {
    const auto& wifi = output->persisted.wifi_profiles[0];
    if (wifi.security != config::WifiSecurity::kWpa2Personal ||
        wifi.open_network_approved) {
      return BindStatus::kUnsupportedProfileSet;
    }
  }

  output->host_ipv4.fill(0);
  const int address_length = std::snprintf(
      output->host_ipv4.data(), output->host_ipv4.size(), "%u.%u.%u.%u",
      static_cast<unsigned>(host.ipv4[0]), static_cast<unsigned>(host.ipv4[1]),
      static_cast<unsigned>(host.ipv4[2]), static_cast<unsigned>(host.ipv4[3]));
  if (address_length < 0 ||
      static_cast<std::size_t>(address_length) >= output->host_ipv4.size()) {
    return BindStatus::kInvalidConfig;
  }
  output->server_name.fill(0);
  std::copy_n(host.server_name.begin(), host.server_name_length,
              output->server_name.begin());

  output->runtime = {};
  output->runtime.wifi_configured = output->persisted.wifi_profile_count == 1;
  if (output->runtime.wifi_configured) {
    const auto& wifi = output->persisted.wifi_profiles[0];
    output->runtime.wifi = {
        wifi.ssid.data(),       wifi.ssid_length,
        wifi.credential.data(), wifi.credential_length,
        endpoint::WifiAuth::kWpa2Personal,
        false,
    };
  }
  output->runtime.host_ipv4 = output->host_ipv4.data();
  output->runtime.host_ipv4_length = static_cast<std::size_t>(address_length);
  output->runtime.tls = {output->server_name.data(), host.server_name_length,
                         host.port, host.peer_spki_sha256};
  output->runtime.ca_certificate_der = host.ca_certificate_der.data();
  output->runtime.ca_certificate_der_length = host.ca_certificate_length;
  output->runtime.device_id = output->persisted.device_id;
  output->runtime.host_id = host.host_id;
  output->runtime.link_secret = host.link_secret;
  output->runtime.wifi_connect_timeout_ms = 15000;
  output->runtime.discovery_timeout_ms = 1500;
  output->runtime.tls_connect_timeout_ms = 10000;
  return transport::ValidateRuntimeConfig(output->runtime) ? BindStatus::kOk
                                                            : BindStatus::kInvalidConfig;
}

BindStatus BindRoamingRuntime(
    const std::array<std::uint8_t, 16>& expected_device_id,
    config::RoamingPolicyCrypto& crypto, StoredRoamingRuntime* output) {
  if (output == nullptr) {
    return BindStatus::kInvalidConfig;
  }
  output->runtime = {};
  output->server_name.fill(0);
  if (!config::ValidateRecoveryAnchor(output->anchor) ||
      output->anchor.phase != config::RecoveryAnchorPhase::kActive ||
      output->persisted.device_id != expected_device_id) {
    return BindStatus::kInvalidConfig;
  }
  config::AuthenticatedPolicyIdentity authenticated{};
  if (!config::VerifyAuthenticatedRoamingPolicy(
          output->persisted, output->anchor.device_recovery_secret, crypto,
          &authenticated)) {
    return BindStatus::kInvalidConfig;
  }
  const config::RecoveryAnchorInspection anchor{
      config::RecoveryAnchorCondition::kValid, output->anchor};
  if (config::ReconcilePolicy(anchor, &authenticated) !=
      config::PolicyReconciliation::kReady) {
    return BindStatus::kIdentityMismatch;
  }
  if (!roaming::BuildDeviceGatewayName(output->persisted.device_id,
                                       &output->server_name)) {
    return BindStatus::kInvalidConfig;
  }

  output->runtime.authority_mode = transport::AuthorityMode::kOwnerRoaming;
  output->runtime.wifi_configured =
      output->persisted.wifi_profile_count != 0;
  if (output->runtime.wifi_configured) {
    const config::WifiProfile* selected = &output->persisted.wifi_profiles[0];
    for (std::size_t index = 1;
         index < output->persisted.wifi_profile_count; ++index) {
      if (output->persisted.wifi_profiles[index].priority >
          selected->priority) {
        selected = &output->persisted.wifi_profiles[index];
      }
    }
    output->runtime.wifi = {
        selected->ssid.data(),       selected->ssid_length,
        selected->credential.data(), selected->credential_length,
        endpoint::WifiAuth::kWpa2Personal,
        false,
    };
  }
  output->runtime.tls = {
      output->server_name.data(), roaming::kDeviceGatewayNameBytes,
      protocol::kRoamingDeviceTlsPort, {}};
  output->runtime.ca_certificate_der = output->persisted.owner_ca_der.data();
  output->runtime.ca_certificate_der_length =
      output->persisted.owner_ca_length;
  output->runtime.device_id = output->persisted.device_id;
  output->runtime.roaming_policy = &output->persisted;
  output->runtime.roaming_recovery_secret =
      &output->anchor.device_recovery_secret;
  output->runtime.roaming_crypto = &crypto;
  output->runtime.roaming_verification_workspace =
      &output->verification_workspace;
  output->runtime.wifi_connect_timeout_ms = 15000;
  output->runtime.discovery_timeout_ms = 1500;
  output->runtime.tls_connect_timeout_ms = 10000;
  return transport::ValidateRuntimeConfig(output->runtime)
             ? BindStatus::kOk
             : BindStatus::kInvalidConfig;
}

BootStatus ResolveBootConfig(
    config::SlotStorage& storage,
    const std::array<std::uint8_t, 16>& expected_device_id,
    const transport::RuntimeConfig& private_bootstrap,
    config::StorageWorkspace* workspace, StoredRuntime* stored,
    transport::RuntimeConfig* output, config::Selection* selection) {
  if (workspace == nullptr || stored == nullptr || output == nullptr ||
      selection == nullptr) {
    return BootStatus::kLockedStorageIo;
  }
  *output = {};
  const config::StorageStatus storage_status =
      config::LoadConfig(storage, workspace, &stored->persisted, selection);
  switch (SelectBootSource(storage_status)) {
    case BootSource::kPrivateBootstrap:
      if (!transport::ValidateRuntimeConfig(private_bootstrap)) {
        return BootStatus::kLockedBootstrapInvalid;
      }
      *output = private_bootstrap;
      return BootStatus::kPrivateBootstrap;
    case BootSource::kStored:
      break;
    case BootSource::kLocked:
      if (storage_status == config::StorageStatus::kIoError) {
        return BootStatus::kLockedStorageIo;
      }
      if (storage_status == config::StorageStatus::kMalformedSlots) {
        return BootStatus::kLockedMalformedSlots;
      }
      if (storage_status == config::StorageStatus::kAmbiguousSlots) {
        return BootStatus::kLockedAmbiguousSlots;
      }
      return BootStatus::kLockedStorageState;
  }

  switch (BindStoredRuntime(expected_device_id, stored)) {
    case BindStatus::kOk:
      *output = stored->runtime;
      return BootStatus::kStored;
    case BindStatus::kInvalidConfig:
      return BootStatus::kLockedStoredInvalid;
    case BindStatus::kIdentityMismatch:
      return BootStatus::kLockedIdentityMismatch;
    case BindStatus::kUnsupportedProfileSet:
      return BootStatus::kLockedUnsupportedProfileSet;
  }
  return BootStatus::kLockedStoredInvalid;
}

BootStatus ResolveOperationalBoot(
    config::SlotStorage& slots, config::RecoveryAnchorStorage& anchors,
    const std::array<std::uint8_t, 16>& expected_device_id,
    const transport::RuntimeConfig& private_bootstrap,
    config::RoamingPolicyCrypto& crypto, OperationalBootContext* context,
    transport::RuntimeConfig* output, config::Selection* selection) {
  if (context == nullptr || output == nullptr || selection == nullptr) {
    return BootStatus::kLockedRecoveryIo;
  }
  *output = {};
  *selection = {config::ConfigState::kLockedUnprovisioned,
                config::SlotId::kNone, 0};
  context->anchor_bytes.fill(0);
  const auto anchor_read =
      anchors.Read(context->anchor_bytes.data(), context->anchor_bytes.size());
  if (anchor_read == config::AnchorReadStatus::kNotFound) {
    return ResolveBootConfig(slots, expected_device_id, private_bootstrap,
                             &context->legacy_workspace, &context->legacy,
                             output, selection);
  }
  if (anchor_read != config::AnchorReadStatus::kOk) {
    return BootStatus::kLockedRecoveryIo;
  }

  const auto inspection = config::InspectRecoveryAnchor(
      context->anchor_bytes.data(), context->anchor_bytes.size());
  context->anchor_bytes.fill(0);
  if (inspection.condition != config::RecoveryAnchorCondition::kValid) {
    return BootStatus::kLockedRecoveryMalformed;
  }
  context->roaming.anchor = inspection.anchor;
  if (inspection.anchor.phase != config::RecoveryAnchorPhase::kActive) {
    return BootStatus::kLockedMigration;
  }

  const auto storage_status = config::LoadRoamingConfig(
      slots, &context->migration_workspace.roaming, &context->roaming.persisted,
      selection);
  if (storage_status == config::StorageStatus::kIoError) {
    return BootStatus::kLockedRecoveryIo;
  }
  if (storage_status != config::StorageStatus::kOk) {
    return BootStatus::kLockedRoamingStorage;
  }
  const auto bind = BindRoamingRuntime(expected_device_id, crypto,
                                       &context->roaming);
  if (bind != BindStatus::kOk) {
    *selection = {config::ConfigState::kLockedUnprovisioned,
                  config::SlotId::kNone, 0};
    return BootStatus::kLockedRoamingPolicy;
  }
  *output = context->roaming.runtime;
  return BootStatus::kRoaming;
}

}  // namespace keyferry::runtime_config
