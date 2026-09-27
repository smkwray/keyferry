#include "keyferry/roaming_config.h"
#include "roaming_profile.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <cstdio>
#include <limits>

namespace {

using keyferry::config::ConfigState;
using keyferry::config::RoamingEndpointConfig;
using keyferry::config::SlotCondition;
using keyferry::config::SlotId;
using keyferry::config::SlotView;

template <std::size_t Size>
std::array<std::uint8_t, Size> Filled(const std::uint8_t value) {
  std::array<std::uint8_t, Size> output{};
  output.fill(value);
  return output;
}

class ExpectedCrypto final : public keyferry::config::RoamingPolicyCrypto {
 public:
  bool Sha256(const std::uint8_t* input, const std::size_t length,
              std::uint8_t output[32]) override {
    if (input == nullptr || output == nullptr) {
      return false;
    }
    if (length == ca_der_length &&
        std::equal(input, input + length, ca_der.begin())) {
      std::copy(ca_hash.begin(), ca_hash.end(), output);
      return true;
    }
    if (length == policy_input.size() &&
        std::equal(input, input + length, policy_input.begin())) {
      std::copy(policy_hash.begin(), policy_hash.end(), output);
      return true;
    }
    if (length == salt_input.size() &&
        std::equal(input, input + length, salt_input.begin())) {
      std::copy(salt.begin(), salt.end(), output);
      return true;
    }
    if (length == installation_input.size() &&
        std::equal(input, input + length, installation_input.begin())) {
      std::copy(installation_hash.begin(), installation_hash.end(), output);
      return true;
    }
    return false;
  }

  bool HkdfSha256(const std::uint8_t* input_key,
                  const std::size_t input_key_length,
                  const std::uint8_t* input_salt,
                  const std::size_t salt_length, const std::uint8_t* info,
                  const std::size_t info_length,
                  std::uint8_t output[32]) override {
    if (input_key_length != recovery_secret.size() ||
        salt_length != salt.size() ||
        !std::equal(input_key, input_key + input_key_length,
                    recovery_secret.begin()) ||
        !std::equal(input_salt, input_salt + salt_length, salt.begin())) {
      return false;
    }
    if (info_length == keyferry::protocol::kRoamingPolicyAuthKeyDomain.size() &&
        std::equal(info, info + info_length,
                   keyferry::protocol::kRoamingPolicyAuthKeyDomain.begin())) {
      std::copy(auth_key.begin(), auth_key.end(), output);
      return true;
    }
    if (info_length == link_info.size() &&
        std::equal(info, info + info_length, link_info.begin())) {
      std::copy(link_secret.begin(), link_secret.end(), output);
      return true;
    }
    if (info_length == route_info.size() &&
        std::equal(info, info + info_length, route_info.begin())) {
      std::copy(route_secret.begin(), route_secret.end(), output);
      return true;
    }
    return false;
  }

  bool HmacSha256(const std::uint8_t key[32], const std::uint8_t* input,
                  const std::size_t input_length,
                  std::uint8_t output[32]) override {
    if (std::equal(key, key + auth_key.size(), auth_key.begin()) &&
        input_length == auth_input.size() &&
        std::equal(input, input + input_length, auth_input.begin())) {
      std::copy(auth_tag.begin(), auth_tag.end(), output);
      return true;
    }
    if (std::equal(key, key + route_secret.size(), route_secret.begin()) &&
        input_length == route_body.size() &&
        std::equal(input, input + input_length, route_body.begin())) {
      std::copy(route_tag.begin(), route_tag.end(), output);
      return true;
    }
    return false;
  }

  std::array<std::uint8_t, 4> ca_der{0x30, 0x02, 0x01, 0x00};
  std::size_t ca_der_length{ca_der.size()};
  std::array<std::uint8_t, 32> ca_hash{Filled<32>(0x33)};
  keyferry::config::PolicyHashInput policy_input{};
  std::array<std::uint8_t, 32> policy_hash{Filled<32>(0x44)};
  keyferry::roaming::LinkSaltInput salt_input{};
  std::array<std::uint8_t, 32> salt{Filled<32>(0x70)};
  std::array<std::uint8_t, 32> recovery_secret{Filled<32>(0x55)};
  std::array<std::uint8_t, 32> auth_key{Filled<32>(0x71)};
  keyferry::config::PolicyAuthInput auth_input{};
  std::array<std::uint8_t, 32> auth_tag{Filled<32>(0x45)};
  keyferry::roaming::InstallationHashInput installation_input{};
  std::array<std::uint8_t, 32> installation_hash{Filled<32>(0x72)};
  keyferry::roaming::DeviceLinkInfo link_info{};
  std::array<std::uint8_t, 32> link_secret{Filled<32>(0x73)};
  keyferry::roaming::RouteProofKeyInfo route_info{};
  std::array<std::uint8_t, 32> route_secret{Filled<32>(0x74)};
  keyferry::roaming::RouteProofBody route_body{};
  keyferry::roaming::RouteProofTag route_tag{Filled<32>(0x75)};
};

template <typename Slot>
SlotView View(const Slot& slot) {
  return {slot.data(), slot.size()};
}

void SetWifi(keyferry::config::WifiProfile* profile, const std::uint8_t marker) {
  assert(profile != nullptr);
  *profile = {};
  profile->security = keyferry::config::WifiSecurity::kWpa2Personal;
  profile->priority = marker;
  constexpr char kSsid[] = "roaming-network";
  constexpr char kCredential[] = "roaming-password";
  profile->ssid_length = sizeof(kSsid) - 1;
  profile->credential_length = sizeof(kCredential) - 1;
  std::copy_n(reinterpret_cast<const std::uint8_t*>(kSsid),
              profile->ssid_length, profile->ssid.begin());
  std::copy_n(reinterpret_cast<const std::uint8_t*>(kCredential),
              profile->credential_length, profile->credential.begin());
}

RoamingEndpointConfig ValidConfig(const std::uint8_t marker = 1) {
  RoamingEndpointConfig config{};
  config.device_id = Filled<16>(marker);
  config.owner_id = Filled<16>(static_cast<std::uint8_t>(marker + 1));
  config.owner_ca_sha256 = Filled<32>(static_cast<std::uint8_t>(marker + 2));
  config.epoch = 1;
  config.policy_sequence = 1;
  config.policy_hash = Filled<32>(static_cast<std::uint8_t>(marker + 3));
  config.policy_auth_tag = Filled<32>(static_cast<std::uint8_t>(marker + 4));
  config.owner_ca_length = 4;
  config.owner_ca_der[0] = 0x30;
  config.owner_ca_der[1] = 0x02;
  config.owner_ca_der[2] = marker;
  config.owner_ca_der[3] = static_cast<std::uint8_t>(marker + 5);
  return config;
}

void TestPayloadAndSlotRoundTrip() {
  using namespace keyferry::config;
  auto input = ValidConfig();
  input.wifi_profile_count = 1;
  SetWifi(&input.wifi_profiles[0], 7);
  input.revoked_installation_count = 2;
  input.revoked_installation_ids[0] = Filled<16>(0x20);
  input.revoked_installation_ids[1] = Filled<16>(0x30);

  std::array<std::uint8_t, kRoamingConfigPayloadBytes> payload{};
  assert(EncodeRoamingConfigPayload(input, &payload));
  RoamingEndpointConfig decoded{};
  assert(DecodeRoamingConfigPayload(payload.data(), payload.size(), &decoded));
  assert(decoded.device_id == input.device_id);
  assert(decoded.owner_ca_der == input.owner_ca_der);
  assert(decoded.revoked_installation_ids == input.revoked_installation_ids);
  assert(decoded.wifi_profiles[0].ssid == input.wifi_profiles[0].ssid);

  std::array<std::uint8_t, kRoamingConfigSlotBytes> slot{};
  assert(EncodeRoamingSlot(9, input, &slot));
  const auto inspection = InspectRoamingSlot(View(slot));
  assert(inspection.condition == SlotCondition::kValid);
  assert(inspection.generation == 9);
  RoamingEndpointConfig selected{};
  const auto selection = SelectNewestRoaming(View(slot), {nullptr, 0}, &selected);
  assert(selection.state == ConfigState::kReady);
  assert(selection.slot == SlotId::kA);
  assert(selection.generation == 9);
  assert(selected.policy_hash == input.policy_hash);
}

void TestZeroAndEightWifiProfilesAreValid() {
  using namespace keyferry::config;
  auto config = ValidConfig();
  assert(ValidateRoamingConfig(config));
  config.wifi_profile_count = static_cast<std::uint8_t>(config.wifi_profiles.size());
  for (std::size_t index = 0; index < config.wifi_profiles.size(); ++index) {
    SetWifi(&config.wifi_profiles[index], static_cast<std::uint8_t>(index));
  }
  assert(ValidateRoamingConfig(config));
  config.wifi_profile_count++;
  assert(!ValidateRoamingConfig(config));
}

void TestRevocationsMustBeSortedUniqueAndBounded() {
  using namespace keyferry::config;
  auto config = ValidConfig();
  config.revoked_installation_count = 2;
  config.revoked_installation_ids[0] = Filled<16>(0x10);
  config.revoked_installation_ids[1] = Filled<16>(0x20);
  assert(ValidateRoamingConfig(config));

  auto duplicate = config;
  duplicate.revoked_installation_ids[1] = duplicate.revoked_installation_ids[0];
  assert(!ValidateRoamingConfig(duplicate));
  auto unsorted = config;
  std::swap(unsorted.revoked_installation_ids[0],
            unsorted.revoked_installation_ids[1]);
  assert(!ValidateRoamingConfig(unsorted));
  auto zero = config;
  zero.revoked_installation_ids[0].fill(0);
  assert(!ValidateRoamingConfig(zero));
  auto dirty_tail = config;
  dirty_tail.revoked_installation_ids[2] = Filled<16>(0x30);
  assert(!ValidateRoamingConfig(dirty_tail));
}

void TestPolicyIdentityIsExact() {
  using namespace keyferry::config;
  auto config = ValidConfig();
  config.epoch = 4;
  config.policy_sequence = 7;
  config.previous_policy_sequence = 6;
  config.previous_policy_hash = Filled<32>(0xA1);
  const auto identity = RoamingPolicyIdentity(config);
  assert(identity.device_id == config.device_id);
  assert(identity.owner_id == config.owner_id);
  assert(identity.owner_ca_sha256 == config.owner_ca_sha256);
  assert(identity.epoch == config.epoch);
  assert(identity.sequence == config.policy_sequence);
  assert(identity.hash == config.policy_hash);
  assert(identity.previous_sequence == config.previous_policy_sequence);
  assert(identity.previous_hash == config.previous_policy_hash);
}

void TestSelectionAndCorruptionRules() {
  using namespace keyferry::config;
  std::array<std::uint8_t, kRoamingConfigSlotBytes> old_slot{};
  std::array<std::uint8_t, kRoamingConfigSlotBytes> new_slot{};
  assert(EncodeRoamingSlot(3, ValidConfig(1), &old_slot));
  assert(EncodeRoamingSlot(4, ValidConfig(9), &new_slot));
  RoamingEndpointConfig output{};
  auto selection = SelectNewestRoaming(View(old_slot), View(new_slot), &output);
  assert(selection.state == ConfigState::kReady && selection.slot == SlotId::kB);

  new_slot.back() ^= 1;
  selection = SelectNewestRoaming(View(old_slot), View(new_slot), &output);
  assert(selection.state == ConfigState::kReady && selection.slot == SlotId::kA);
  assert(selection.generation == 3);

  assert(EncodeRoamingSlot(3, ValidConfig(9), &new_slot));
  selection = SelectNewestRoaming(View(old_slot), View(new_slot), &output);
  assert(selection.state == ConfigState::kLockedUnprovisioned);
  assert(selection.slot == SlotId::kNone);
}

void TestLegacyAndRoamingSlotsDoNotCrossDecode() {
  using namespace keyferry::config;
  EndpointConfig legacy{};
  legacy.device_id = Filled<16>(1);
  legacy.provisioning_key = Filled<32>(2);
  legacy.wifi_profile_count = 1;
  legacy.paired_host_count = 1;
  SetWifi(&legacy.wifi_profiles[0], 1);
  auto& host = legacy.paired_hosts[0];
  host.host_id = Filled<16>(3);
  host.ipv4 = {192, 0, 2, 1};
  host.port = 7443;
  constexpr char kName[] = "legacy.invalid";
  host.server_name_length = sizeof(kName) - 1;
  std::copy_n(kName, host.server_name_length, host.server_name.begin());
  host.peer_spki_sha256 = Filled<32>(4);
  host.link_secret = Filled<32>(5);
  host.ca_certificate_length = 2;
  host.ca_certificate_der[0] = 0x30;
  host.ca_certificate_der[1] = 0;
  std::array<std::uint8_t, kSlotBytes> legacy_slot{};
  assert(EncodeSlot(1, legacy, &legacy_slot));
  assert(InspectRoamingSlot(View(legacy_slot)).condition == SlotCondition::kMalformed);

  std::array<std::uint8_t, kRoamingConfigSlotBytes> roaming_slot{};
  assert(EncodeRoamingSlot(1, ValidConfig(), &roaming_slot));
  assert(InspectSlot(View(roaming_slot)).condition == SlotCondition::kMalformed);
}

void TestUpdatePlanAndInvalidOutputClearing() {
  using namespace keyferry::config;
  std::array<std::uint8_t, kRoamingConfigSlotBytes> erased{};
  erased.fill(0xFF);
  auto plan = PlanRoamingUpdate(View(erased), View(erased));
  assert(plan.writable && plan.target == SlotId::kA && plan.generation == 1);

  std::array<std::uint8_t, kRoamingConfigSlotBytes> max_slot{};
  assert(EncodeRoamingSlot(std::numeric_limits<std::uint64_t>::max(),
                           ValidConfig(), &max_slot));
  plan = PlanRoamingUpdate(View(max_slot), View(erased));
  assert(!plan.writable);

  auto output = ValidConfig();
  std::array<std::uint8_t, kRoamingConfigPayloadBytes> malformed{};
  assert(!DecodeRoamingConfigPayload(malformed.data(), malformed.size(), &output));
  assert(output.epoch == 0 && output.wifi_profile_count == 0);
}

void TestPolicyAuthenticationCoversCaPolicyAndRecoverySecret() {
  using namespace keyferry::config;
  auto config = ValidConfig();
  config.owner_ca_sha256 = Filled<32>(0x33);
  config.policy_hash = Filled<32>(0x44);
  config.policy_auth_tag = Filled<32>(0x45);
  config.wifi_profile_count = 1;
  SetWifi(&config.wifi_profiles[0], 7);

  ExpectedCrypto crypto{};
  std::copy_n(config.owner_ca_der.begin(), config.owner_ca_length,
              crypto.ca_der.begin());
  assert(BuildRoamingPolicyHashInput(config, &crypto.policy_input));
  assert(keyferry::roaming::BuildLinkSaltInput(
      config.owner_id, config.device_id, config.epoch, &crypto.salt_input));
  assert(BuildRoamingPolicyAuthInput(config.policy_hash, &crypto.auth_input));

  AuthenticatedPolicyIdentity identity{};
  RoamingPolicyVerificationWorkspace workspace{};
  auto* mutable_workspace_bytes = reinterpret_cast<std::uint8_t*>(&workspace);
  std::fill_n(mutable_workspace_bytes, sizeof(workspace),
              std::uint8_t{0xa5});
  assert(VerifyAuthenticatedRoamingPolicy(config, crypto.recovery_secret,
                                           crypto, &identity, &workspace));
  assert(identity.hash == config.policy_hash && identity.sequence == 1);
  const auto* workspace_bytes =
      reinterpret_cast<const std::uint8_t*>(&workspace);
  assert(std::all_of(workspace_bytes, workspace_bytes + sizeof(workspace),
                     [](const std::uint8_t byte) { return byte == 0; }));

  auto altered = config;
  altered.wifi_profiles[0].priority++;
  identity = RoamingPolicyIdentity(config);
  assert(!VerifyAuthenticatedRoamingPolicy(altered, crypto.recovery_secret,
                                           crypto, &identity));
  assert(identity.sequence == 0);

  altered = config;
  altered.owner_ca_der[2] ^= 1;
  assert(!VerifyAuthenticatedRoamingPolicy(altered, crypto.recovery_secret,
                                           crypto, &identity));
  altered = config;
  altered.policy_auth_tag[0] ^= 1;
  assert(!VerifyAuthenticatedRoamingPolicy(altered, crypto.recovery_secret,
                                           crypto, &identity));
  auto wrong_secret = crypto.recovery_secret;
  wrong_secret[0] ^= 1;
  assert(!VerifyAuthenticatedRoamingPolicy(config, wrong_secret, crypto,
                                           &identity));
}

void TestCanonicalPolicyHashVector() {
  using namespace keyferry::config;
  auto config = ValidConfig();
  config.device_id = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
  config.owner_id = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  config.owner_ca_sha256 = {
      0x3f, 0x6e, 0x6c, 0xc2, 0x51, 0x61, 0x13, 0x8d, 0x90, 0x67, 0xff,
      0xad, 0x9e, 0x9e, 0xaa, 0xf5, 0x7b, 0xbb, 0x82, 0xfb, 0xa3, 0xcf,
      0x83, 0xc4, 0xec, 0x37, 0xef, 0xa9, 0x6c, 0xf3, 0x18, 0xba};
  config.owner_ca_der.fill(0);
  config.owner_ca_length = 5;
  config.owner_ca_der[0] = 0x30;
  config.owner_ca_der[1] = 0x03;
  config.owner_ca_der[2] = 0x01;
  config.owner_ca_der[3] = 0x02;
  config.owner_ca_der[4] = 0x03;
  config.policy_hash.fill(0x44);
  config.policy_auth_tag.fill(0x45);
  PolicyHashInput input{};
  assert(BuildRoamingPolicyHashInput(config, &input));
  assert(Crc32(input.data(), input.size()) == 0xCD23C1F3U);
  assert(std::equal(keyferry::protocol::kRoamingPolicyHashDomain.begin(),
                    keyferry::protocol::kRoamingPolicyHashDomain.end(),
                    input.begin()));
}

void TestRoamingPeerAuthorizationAndRevocation() {
  using namespace keyferry::config;
  auto config = ValidConfig();
  config.owner_ca_sha256 = Filled<32>(0x33);
  config.policy_hash = Filled<32>(0x44);
  config.policy_auth_tag = Filled<32>(0x45);
  ExpectedCrypto crypto{};
  std::copy_n(config.owner_ca_der.begin(), config.owner_ca_length,
              crypto.ca_der.begin());
  assert(BuildRoamingPolicyHashInput(config, &crypto.policy_input));
  assert(keyferry::roaming::BuildLinkSaltInput(
      config.owner_id, config.device_id, config.epoch, &crypto.salt_input));
  assert(BuildRoamingPolicyAuthInput(config.policy_hash, &crypto.auth_input));

  keyferry::roaming::P256Spki peer{};
  const std::array<std::uint8_t, 26> prefix{
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
      0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
      0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};
  std::copy(prefix.begin(), prefix.end(), peer.begin());
  peer[prefix.size()] = 0x04;
  std::fill(peer.begin() + prefix.size() + 1, peer.end(),
            static_cast<std::uint8_t>(0x51));
  assert(keyferry::roaming::BuildInstallationHashInput(
      peer, &crypto.installation_input));
  keyferry::roaming::InstallationId expected_id{};
  std::copy_n(crypto.installation_hash.begin(), expected_id.size(),
              expected_id.begin());
  assert(keyferry::roaming::BuildDeviceLinkInfo(expected_id, peer,
                                                &crypto.link_info));

  RoamingPeerAuthorization authorization{};
  RoamingPolicyVerificationWorkspace workspace{};
  assert(AuthorizeRoamingPeer(config, crypto.recovery_secret, peer, crypto,
                               &authorization, &workspace));
  assert(authorization.installation_id == expected_id);
  assert(authorization.peer_spki == peer);
  assert(authorization.link_secret == crypto.link_secret);

  config.revoked_installation_count = 1;
  config.revoked_installation_ids[0] = expected_id;
  assert(BuildRoamingPolicyHashInput(config, &crypto.policy_input));
  authorization.link_secret.fill(0x99);
  assert(!AuthorizeRoamingPeer(config, crypto.recovery_secret, peer, crypto,
                               &authorization));
  assert(std::all_of(authorization.link_secret.begin(),
                     authorization.link_secret.end(),
                     [](std::uint8_t byte) { return byte == 0; }));
}

void TestAuthenticatedRouteProofIsFixedAndPolicyBound() {
  using namespace keyferry::config;
  auto config = ValidConfig();
  config.owner_ca_sha256 = Filled<32>(0x33);
  config.policy_hash = Filled<32>(0x44);
  config.policy_auth_tag = Filled<32>(0x45);
  ExpectedCrypto crypto{};
  std::copy_n(config.owner_ca_der.begin(), config.owner_ca_length,
              crypto.ca_der.begin());
  assert(BuildRoamingPolicyHashInput(config, &crypto.policy_input));
  assert(keyferry::roaming::BuildLinkSaltInput(
      config.owner_id, config.device_id, config.epoch, &crypto.salt_input));
  assert(BuildRoamingPolicyAuthInput(config.policy_hash, &crypto.auth_input));

  keyferry::roaming::RouteProofFields fields{};
  fields.owner_id = config.owner_id;
  fields.device_id = config.device_id;
  fields.epoch = config.epoch;
  fields.policy_sequence = config.policy_sequence;
  fields.policy_hash = config.policy_hash;
  fields.gateway_installation_id = Filled<16>(0x70);
  fields.controller_installation_id = Filled<16>(0x60);
  fields.controller_nonce = Filled<32>(0xa0);
  fields.device_boot_nonce = Filled<16>(0xc0);
  fields.endpoint_session_id = Filled<16>(0xd0);
  fields.link_path = 2;
  fields.usb_ready = true;
  assert(keyferry::roaming::BuildRouteProofKeyInfo(
      fields.controller_installation_id, &crypto.route_info));
  assert(keyferry::roaming::BuildRouteProofBody(fields, &crypto.route_body));

  keyferry::roaming::RouteProofResponse response{};
  RoamingPolicyVerificationWorkspace workspace{};
  assert(BuildAuthenticatedRouteProof(config, crypto.recovery_secret, fields,
                                       crypto, &response, &workspace));
  keyferry::roaming::RouteProofResponse expected{};
  assert(keyferry::roaming::BuildRouteProofResponse(
      fields, crypto.route_tag, &expected));
  assert(response == expected);

  auto wrong_fields = fields;
  wrong_fields.policy_sequence++;
  assert(!BuildAuthenticatedRouteProof(config, crypto.recovery_secret,
                                       wrong_fields, crypto, &response));
  assert(std::all_of(response.begin(), response.end(),
                     [](const std::uint8_t byte) { return byte == 0; }));

  config.revoked_installation_count = 1;
  config.revoked_installation_ids[0] = fields.controller_installation_id;
  assert(BuildRoamingPolicyHashInput(config, &crypto.policy_input));
  assert(!BuildAuthenticatedRouteProof(config, crypto.recovery_secret, fields,
                                       crypto, &response));
}

}  // namespace

int main() {
  static_assert(keyferry::config::kRoamingConfigFixedHeaderBytes == 192);
  static_assert(keyferry::config::kRoamingConfigPayloadBytes == 3064);
  static_assert(keyferry::config::kRoamingConfigSlotBytes == 3092);
  TestPayloadAndSlotRoundTrip();
  TestZeroAndEightWifiProfilesAreValid();
  TestRevocationsMustBeSortedUniqueAndBounded();
  TestPolicyIdentityIsExact();
  TestSelectionAndCorruptionRules();
  TestLegacyAndRoamingSlotsDoNotCrossDecode();
  TestUpdatePlanAndInvalidOutputClearing();
  TestPolicyAuthenticationCoversCaPolicyAndRecoverySecret();
  TestCanonicalPolicyHashVector();
  TestRoamingPeerAuthorizationAndRevocation();
  TestAuthenticatedRouteProofIsFixedAndPolicyBound();
  std::puts("roaming_config_test: ok");
  return 0;
}
