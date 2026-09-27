#include "keyferry/runtime_config.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>

namespace {

using keyferry::config::StorageStatus;
using keyferry::runtime_config::BindStatus;
using keyferry::runtime_config::BootSource;
using keyferry::runtime_config::BootStatus;
using keyferry::runtime_config::StoredRuntime;
using keyferry::runtime_config::StoredRoamingRuntime;

class AcceptingRoamingCrypto final
    : public keyferry::config::RoamingPolicyCrypto {
 public:
  bool Sha256(const std::uint8_t*, const std::size_t length,
              std::uint8_t output[32]) override {
    if (output == nullptr) {
      return false;
    }
    if (length == 64) {
      std::fill_n(output, 32, static_cast<std::uint8_t>(0x30));
    } else if (length == keyferry::config::kPolicyHashInputBytes) {
      std::fill_n(output, 32, static_cast<std::uint8_t>(0x40));
    } else if (length == keyferry::roaming::kLinkSaltInputBytes) {
      std::fill_n(output, 32, static_cast<std::uint8_t>(0x50));
    } else {
      return false;
    }
    return true;
  }

  bool HkdfSha256(const std::uint8_t*, std::size_t,
                  const std::uint8_t*, std::size_t, const std::uint8_t*,
                  std::size_t, std::uint8_t output[32]) override {
    if (output == nullptr) {
      return false;
    }
    std::fill_n(output, 32, static_cast<std::uint8_t>(0x60));
    return true;
  }

  bool HmacSha256(const std::uint8_t[32], const std::uint8_t*, std::size_t,
                  std::uint8_t output[32]) override {
    if (output == nullptr) {
      return false;
    }
    std::fill_n(output, 32, static_cast<std::uint8_t>(0x70));
    return true;
  }
};

class FakeStorage final : public keyferry::config::SlotStorage {
 public:
  FakeStorage() {
    a.fill(0xFF);
    b.fill(0xFF);
  }

  bool Read(keyferry::config::SlotId slot, std::uint8_t* output,
            std::size_t length) override {
    if (fail_read || output == nullptr ||
        length != keyferry::config::kSlotBytes) {
      return false;
    }
    const auto& source = slot == keyferry::config::SlotId::kA ? a : b;
    std::copy(source.begin(), source.end(), output);
    return true;
  }

  bool Erase(keyferry::config::SlotId) override {
    ++write_attempts;
    return false;
  }

  bool Write(keyferry::config::SlotId, std::size_t, const std::uint8_t*,
             std::size_t) override {
    ++write_attempts;
    return false;
  }

  std::array<std::uint8_t, keyferry::config::kSlotBytes> a{};
  std::array<std::uint8_t, keyferry::config::kSlotBytes> b{};
  bool fail_read{false};
  std::size_t write_attempts{0};
};

class DualFormatStorage final : public keyferry::config::SlotStorage {
 public:
  DualFormatStorage() {
    a.fill(0xFF);
    b.fill(0xFF);
  }

  bool Read(keyferry::config::SlotId slot, std::uint8_t* output,
            std::size_t length) override {
    ++read_attempts;
    if (fail_read || output == nullptr || length > a.size()) {
      return false;
    }
    const auto& source = slot == keyferry::config::SlotId::kA ? a : b;
    std::copy_n(source.begin(), length, output);
    return true;
  }

  bool Erase(keyferry::config::SlotId) override {
    ++write_attempts;
    return false;
  }

  bool Write(keyferry::config::SlotId, std::size_t, const std::uint8_t*,
             std::size_t) override {
    ++write_attempts;
    return false;
  }

  std::array<std::uint8_t, 0x4000> a{};
  std::array<std::uint8_t, 0x4000> b{};
  bool fail_read{false};
  std::size_t read_attempts{0};
  std::size_t write_attempts{0};
};

class FakeAnchorStorage final
    : public keyferry::config::RecoveryAnchorStorage {
 public:
  keyferry::config::AnchorReadStatus Read(std::uint8_t* output,
                                           std::size_t length) override {
    ++read_attempts;
    if (status != keyferry::config::AnchorReadStatus::kOk) {
      return status;
    }
    if (output == nullptr || length != bytes.size()) {
      return keyferry::config::AnchorReadStatus::kIoError;
    }
    std::copy(bytes.begin(), bytes.end(), output);
    return keyferry::config::AnchorReadStatus::kOk;
  }

  bool Write(const std::uint8_t*, std::size_t) override {
    ++write_attempts;
    return false;
  }

  keyferry::config::AnchorReadStatus status{
      keyferry::config::AnchorReadStatus::kNotFound};
  std::array<std::uint8_t, keyferry::config::kRecoveryAnchorBytes> bytes{};
  std::size_t read_attempts{0};
  std::size_t write_attempts{0};
};

StoredRuntime ValidStoredRuntime() {
  StoredRuntime stored{};
  auto& config = stored.persisted;
  config.device_id.fill(0x11);
  config.provisioning_key.fill(0x22);
  config.wifi_profile_count = 1;
  config.paired_host_count = 1;
  auto& wifi = config.wifi_profiles[0];
  constexpr char kSsid[] = "network";
  constexpr char kPassword[] = "password123";
  wifi.ssid_length = sizeof(kSsid) - 1;
  wifi.credential_length = sizeof(kPassword) - 1;
  std::copy_n(reinterpret_cast<const std::uint8_t*>(kSsid), wifi.ssid_length,
              wifi.ssid.begin());
  std::copy_n(reinterpret_cast<const std::uint8_t*>(kPassword),
              wifi.credential_length, wifi.credential.begin());
  auto& host = config.paired_hosts[0];
  host.host_id.fill(0x33);
  host.ipv4 = {192, 168, 30, 137};
  host.port = 7443;
  constexpr char kServerName[] = "keyferry-controller.invalid";
  host.server_name_length = sizeof(kServerName) - 1;
  std::copy_n(kServerName, host.server_name_length, host.server_name.begin());
  host.peer_spki_sha256.fill(0x44);
  host.link_secret.fill(0x55);
  host.ca_certificate_length = 64;
  host.ca_certificate_der.fill(0);
  host.ca_certificate_der[0] = 0x30;
  std::fill_n(host.ca_certificate_der.begin() + 1,
              static_cast<std::size_t>(host.ca_certificate_length - 1),
              std::uint8_t{0x66});
  return stored;
}

StoredRoamingRuntime ValidStoredRoamingRuntime() {
  StoredRoamingRuntime stored{};
  auto& policy = stored.persisted;
  policy.device_id.fill(0x11);
  policy.owner_id.fill(0x22);
  policy.owner_ca_sha256.fill(0x30);
  policy.epoch = 1;
  policy.policy_sequence = 1;
  policy.policy_hash.fill(0x40);
  policy.policy_auth_tag.fill(0x70);
  policy.owner_ca_length = 64;
  policy.owner_ca_der[0] = 0x30;
  std::fill(policy.owner_ca_der.begin() + 1,
            policy.owner_ca_der.begin() + policy.owner_ca_length,
            static_cast<std::uint8_t>(0x33));
  stored.anchor.phase = keyferry::config::RecoveryAnchorPhase::kActive;
  stored.anchor.device_id = policy.device_id;
  stored.anchor.owner_id = policy.owner_id;
  stored.anchor.owner_ca_sha256 = policy.owner_ca_sha256;
  stored.anchor.device_recovery_secret.fill(0x44);
  stored.anchor.epoch = policy.epoch;
  stored.anchor.policy_sequence = policy.policy_sequence;
  stored.anchor.policy_hash = policy.policy_hash;
  stored.anchor.transaction_id.fill(0x55);
  return stored;
}

void TestBootSourceIsFailClosed() {
  assert(keyferry::runtime_config::SelectBootSource(StorageStatus::kOk) ==
         BootSource::kStored);
  assert(keyferry::runtime_config::SelectBootSource(
             StorageStatus::kErasedUnprovisioned) ==
         BootSource::kPrivateBootstrap);
  for (const auto status : {
           StorageStatus::kMalformedSlots,
           StorageStatus::kInvalidConfig,
           StorageStatus::kIoError,
           StorageStatus::kVerificationFailed,
           StorageStatus::kAmbiguousSlots,
           StorageStatus::kGenerationExhausted,
       }) {
    assert(keyferry::runtime_config::SelectBootSource(status) == BootSource::kLocked);
  }
}

void TestStoredRuntimeOwnsExactViews() {
  auto stored = ValidStoredRuntime();
  const auto expected_device_id = stored.persisted.device_id;
  const auto expected_host_id = stored.persisted.paired_hosts[0].host_id;
  const auto expected_pin = stored.persisted.paired_hosts[0].peer_spki_sha256;
  const auto expected_link = stored.persisted.paired_hosts[0].link_secret;
  assert(keyferry::runtime_config::BindStoredRuntime(expected_device_id, &stored) ==
         BindStatus::kOk);
  assert(stored.runtime.wifi_configured);
  assert(std::strcmp(stored.runtime.host_ipv4, "192.168.30.137") == 0);
  assert(stored.runtime.host_ipv4 == stored.host_ipv4.data());
  assert(stored.runtime.tls.server_name == stored.server_name.data());
  assert(stored.runtime.wifi.ssid == stored.persisted.wifi_profiles[0].ssid.data());
  assert(stored.runtime.wifi.credential ==
         stored.persisted.wifi_profiles[0].credential.data());
  assert(stored.runtime.ca_certificate_der ==
         stored.persisted.paired_hosts[0].ca_certificate_der.data());
  assert(stored.runtime.device_id == expected_device_id);
  assert(stored.runtime.host_id == expected_host_id);
  assert(stored.runtime.tls.peer_spki_sha256 == expected_pin);
  assert(stored.runtime.link_secret == expected_link);
}

void TestStoredRuntimeAllowsBleOnlyConfiguration() {
  auto stored = ValidStoredRuntime();
  stored.persisted.wifi_profile_count = 0;
  stored.persisted.wifi_profiles[0] = {};
  const auto expected_device_id = stored.persisted.device_id;
  assert(keyferry::runtime_config::BindStoredRuntime(expected_device_id, &stored) ==
         BindStatus::kOk);
  assert(!stored.runtime.wifi_configured);
  assert(stored.runtime.wifi.ssid == nullptr);
  assert(stored.runtime.wifi.ssid_length == 0);
  assert(stored.runtime.wifi.credential == nullptr);
  assert(stored.runtime.wifi.credential_length == 0);
  assert(std::strcmp(stored.runtime.host_ipv4, "192.168.30.137") == 0);
}

void TestOwnerRoamingRuntimeNeedsNoPinnedHostOrWifi() {
  AcceptingRoamingCrypto crypto;
  auto stored = ValidStoredRoamingRuntime();
  assert(keyferry::runtime_config::BindRoamingRuntime(
             stored.persisted.device_id, crypto, &stored) == BindStatus::kOk);
  assert(stored.runtime.authority_mode ==
         keyferry::transport::AuthorityMode::kOwnerRoaming);
  assert(!stored.runtime.wifi_configured);
  assert(stored.runtime.host_ipv4 == nullptr);
  assert(std::all_of(stored.runtime.host_id.begin(),
                     stored.runtime.host_id.end(),
                     [](std::uint8_t byte) { return byte == 0; }));
  assert(std::all_of(stored.runtime.link_secret.begin(),
                     stored.runtime.link_secret.end(),
                     [](std::uint8_t byte) { return byte == 0; }));
  assert(std::strcmp(
             stored.runtime.tls.server_name,
             "d-11111111111111111111111111111111.gateway.keyferry.invalid") ==
         0);

  stored = ValidStoredRoamingRuntime();
  stored.persisted.wifi_profile_count = 2;
  auto set_wifi = [](keyferry::config::WifiProfile* wifi,
                     const char* ssid, const std::uint8_t priority) {
    wifi->security = keyferry::config::WifiSecurity::kWpa2Personal;
    wifi->priority = priority;
    wifi->ssid_length = static_cast<std::uint8_t>(std::strlen(ssid));
    wifi->credential_length = 8;
    std::copy_n(reinterpret_cast<const std::uint8_t*>(ssid),
                wifi->ssid_length, wifi->ssid.begin());
    std::copy_n(reinterpret_cast<const std::uint8_t*>("password"), 8,
                wifi->credential.begin());
  };
  set_wifi(&stored.persisted.wifi_profiles[0], "lower", 1);
  set_wifi(&stored.persisted.wifi_profiles[1], "higher", 9);
  assert(keyferry::runtime_config::BindRoamingRuntime(
             stored.persisted.device_id, crypto, &stored) == BindStatus::kOk);
  assert(stored.runtime.wifi_configured);
  assert(stored.runtime.wifi.ssid_length == 6);
  assert(std::equal(stored.runtime.wifi.ssid,
                    stored.runtime.wifi.ssid + 6,
                    reinterpret_cast<const std::uint8_t*>("higher")));

  stored.anchor.policy_hash[0] ^= 1;
  assert(keyferry::runtime_config::BindRoamingRuntime(
             stored.persisted.device_id, crypto, &stored) ==
         BindStatus::kIdentityMismatch);
}

void TestUnsupportedOrMismatchedConfigLocks() {
  auto stored = ValidStoredRuntime();
  auto expected = stored.persisted.device_id;
  expected[0] ^= 1;
  assert(keyferry::runtime_config::BindStoredRuntime(expected, &stored) ==
         BindStatus::kIdentityMismatch);

  stored = ValidStoredRuntime();
  stored.persisted.wifi_profile_count = 2;
  stored.persisted.wifi_profiles[1] = stored.persisted.wifi_profiles[0];
  stored.persisted.wifi_profiles[1].ssid[0] = 'x';
  assert(keyferry::runtime_config::BindStoredRuntime(stored.persisted.device_id,
                                                     &stored) ==
         BindStatus::kUnsupportedProfileSet);

  stored = ValidStoredRuntime();
  stored.persisted.wifi_profiles[0].security =
      keyferry::config::WifiSecurity::kOpenExplicit;
  stored.persisted.wifi_profiles[0].open_network_approved = true;
  stored.persisted.wifi_profiles[0].credential.fill(0);
  stored.persisted.wifi_profiles[0].credential_length = 0;
  assert(keyferry::runtime_config::BindStoredRuntime(stored.persisted.device_id,
                                                     &stored) ==
         BindStatus::kUnsupportedProfileSet);
}

keyferry::transport::RuntimeConfig ValidBootstrapConfig() {
  static StoredRuntime bootstrap = ValidStoredRuntime();
  const auto expected = bootstrap.persisted.device_id;
  assert(keyferry::runtime_config::BindStoredRuntime(expected, &bootstrap) ==
         BindStatus::kOk);
  return bootstrap.runtime;
}

BootStatus Resolve(FakeStorage& storage,
                   const std::array<std::uint8_t, 16>& expected_device_id,
                   keyferry::transport::RuntimeConfig* output,
                   keyferry::config::Selection* selection) {
  keyferry::config::StorageWorkspace workspace{};
  static StoredRuntime stored;
  return keyferry::runtime_config::ResolveBootConfig(
      storage, expected_device_id, ValidBootstrapConfig(), &workspace, &stored,
      output, selection);
}

void TestCompleteBootResolutionMatrix() {
  const auto valid = ValidStoredRuntime().persisted;
  const auto expected = valid.device_id;
  keyferry::transport::RuntimeConfig output{};
  keyferry::config::Selection selection{};

  FakeStorage erased;
  assert(Resolve(erased, expected, &output, &selection) ==
         BootStatus::kPrivateBootstrap);
  assert(std::strcmp(output.host_ipv4, "192.168.30.137") == 0);
  assert(erased.write_attempts == 0);

  FakeStorage malformed;
  malformed.a[0] = 0;
  output = ValidBootstrapConfig();
  assert(Resolve(malformed, expected, &output, &selection) ==
         BootStatus::kLockedMalformedSlots);
  assert(output.host_ipv4 == nullptr && malformed.write_attempts == 0);

  FakeStorage unreadable;
  unreadable.fail_read = true;
  assert(Resolve(unreadable, expected, &output, &selection) ==
         BootStatus::kLockedStorageIo);
  assert(output.host_ipv4 == nullptr && unreadable.write_attempts == 0);

  FakeStorage ambiguous;
  assert(keyferry::config::EncodeSlot(7, ValidStoredRuntime().persisted,
                                      &ambiguous.a));
  auto conflicting = ValidStoredRuntime().persisted;
  conflicting.wifi_profiles[0].ssid[0] = 'x';
  assert(keyferry::config::EncodeSlot(7, conflicting, &ambiguous.b));
  assert(Resolve(ambiguous, expected, &output, &selection) ==
         BootStatus::kLockedAmbiguousSlots);
  assert(output.host_ipv4 == nullptr && ambiguous.write_attempts == 0);

  FakeStorage valid_with_malformed_peer;
  assert(keyferry::config::EncodeSlot(9, valid, &valid_with_malformed_peer.a));
  valid_with_malformed_peer.b[0] = 0;
  assert(Resolve(valid_with_malformed_peer, expected, &output, &selection) ==
         BootStatus::kStored);
  assert(selection.slot == keyferry::config::SlotId::kA &&
         selection.generation == 9);
  assert(std::strcmp(output.host_ipv4, "192.168.30.137") == 0);
  assert(valid_with_malformed_peer.write_attempts == 0);

  auto wrong_identity = expected;
  wrong_identity[0] ^= 1;
  assert(Resolve(valid_with_malformed_peer, wrong_identity, &output, &selection) ==
         BootStatus::kLockedIdentityMismatch);
  assert(output.host_ipv4 == nullptr);

  FakeStorage unsupported;
  auto multiple = valid;
  multiple.wifi_profile_count = 2;
  multiple.wifi_profiles[1] = multiple.wifi_profiles[0];
  multiple.wifi_profiles[1].ssid[0] = 'y';
  assert(keyferry::config::EncodeSlot(1, multiple, &unsupported.a));
  assert(Resolve(unsupported, expected, &output, &selection) ==
         BootStatus::kLockedUnsupportedProfileSet);
  assert(output.host_ipv4 == nullptr && unsupported.write_attempts == 0);
}

BootStatus ResolveOperational(
    DualFormatStorage& storage, FakeAnchorStorage& anchor,
    AcceptingRoamingCrypto& crypto,
    keyferry::runtime_config::OperationalBootContext* context,
    keyferry::transport::RuntimeConfig* output,
    keyferry::config::Selection* selection) {
  return keyferry::runtime_config::ResolveOperationalBoot(
      storage, anchor, ValidStoredRuntime().persisted.device_id,
      ValidBootstrapConfig(), crypto, context, output, selection);
}

void PutLegacySlot(
    const keyferry::config::EndpointConfig& config,
    std::array<std::uint8_t, 0x4000>* destination) {
  std::array<std::uint8_t, keyferry::config::kSlotBytes> encoded{};
  assert(keyferry::config::EncodeSlot(1, config, &encoded));
  std::copy(encoded.begin(), encoded.end(), destination->begin());
}

void PutRoamingSlot(
    const keyferry::config::RoamingEndpointConfig& config,
    std::array<std::uint8_t, 0x4000>* destination) {
  std::array<std::uint8_t, keyferry::config::kRoamingConfigSlotBytes> encoded{};
  assert(keyferry::config::EncodeRoamingSlot(1, config, &encoded));
  std::copy(encoded.begin(), encoded.end(), destination->begin());
}

void PutAnchor(const keyferry::config::RecoveryAnchor& value,
               FakeAnchorStorage* storage) {
  assert(keyferry::config::EncodeRecoveryAnchor(value, &storage->bytes));
  storage->status = keyferry::config::AnchorReadStatus::kOk;
}

void TestOperationalBootNeverFallsBackAfterAnchorExists() {
  AcceptingRoamingCrypto crypto;
  keyferry::runtime_config::OperationalBootContext context{};
  keyferry::transport::RuntimeConfig output{};
  keyferry::config::Selection selection{};

  DualFormatStorage legacy;
  FakeAnchorStorage absent;
  PutLegacySlot(ValidStoredRuntime().persisted, &legacy.a);
  assert(ResolveOperational(legacy, absent, crypto, &context, &output,
                            &selection) == BootStatus::kStored);
  assert(output.authority_mode ==
         keyferry::transport::AuthorityMode::kPinnedPeer);

  DualFormatStorage ignored_legacy;
  PutLegacySlot(ValidStoredRuntime().persisted, &ignored_legacy.a);
  FakeAnchorStorage malformed;
  malformed.status = keyferry::config::AnchorReadStatus::kOk;
  malformed.bytes.fill(0);
  output = ValidBootstrapConfig();
  assert(ResolveOperational(ignored_legacy, malformed, crypto, &context,
                            &output, &selection) ==
         BootStatus::kLockedRecoveryMalformed);
  assert(ignored_legacy.read_attempts == 0 && output.host_ipv4 == nullptr);

  auto roaming = ValidStoredRoamingRuntime();
  roaming.anchor.phase =
      keyferry::config::RecoveryAnchorPhase::kMigrationPending;
  FakeAnchorStorage pending;
  PutAnchor(roaming.anchor, &pending);
  assert(ResolveOperational(ignored_legacy, pending, crypto, &context, &output,
                            &selection) == BootStatus::kLockedMigration);
  assert(ignored_legacy.read_attempts == 0);

  roaming = ValidStoredRoamingRuntime();
  DualFormatStorage ready;
  PutRoamingSlot(roaming.persisted, &ready.a);
  FakeAnchorStorage active;
  PutAnchor(roaming.anchor, &active);
  assert(ResolveOperational(ready, active, crypto, &context, &output,
                            &selection) == BootStatus::kRoaming);
  assert(output.authority_mode ==
             keyferry::transport::AuthorityMode::kOwnerRoaming &&
         selection.generation == 1);

  auto wrong_floor = roaming.anchor;
  wrong_floor.policy_hash[0] ^= 1;
  PutAnchor(wrong_floor, &active);
  assert(ResolveOperational(ready, active, crypto, &context, &output,
                            &selection) ==
         BootStatus::kLockedRoamingPolicy);
  assert(output.host_ipv4 == nullptr &&
         selection.state == keyferry::config::ConfigState::kLockedUnprovisioned);

  FakeAnchorStorage unreadable;
  unreadable.status = keyferry::config::AnchorReadStatus::kIoError;
  assert(ResolveOperational(ready, unreadable, crypto, &context, &output,
                            &selection) == BootStatus::kLockedRecoveryIo);
  assert(ready.write_attempts == 0 && unreadable.write_attempts == 0);
}

}  // namespace

int main() {
  TestBootSourceIsFailClosed();
  TestStoredRuntimeOwnsExactViews();
  TestStoredRuntimeAllowsBleOnlyConfiguration();
  TestOwnerRoamingRuntimeNeedsNoPinnedHostOrWifi();
  TestUnsupportedOrMismatchedConfigLocks();
  TestCompleteBootResolutionMatrix();
  TestOperationalBootNeverFallsBackAfterAnchorExists();
  std::puts("runtime_config_test: ok");
  return 0;
}
