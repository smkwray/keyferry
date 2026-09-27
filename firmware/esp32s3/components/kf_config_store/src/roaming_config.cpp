#include "keyferry/roaming_config.h"

#include <algorithm>
#include <limits>

#include "roaming_profile.h"

namespace keyferry::config {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{'K', 'F', 'C', '2'};
constexpr std::uint16_t kFormatVersion = 2;
constexpr std::size_t kCrcOffset = 20;
constexpr std::size_t kPolicyHashOffset = 88;
constexpr std::size_t kPreviousPolicyHashOffset = 120;
constexpr std::size_t kPolicyAuthTagOffset = 152;
constexpr std::size_t kPolicyTailOffset = 184;

bool AnyNonzero(const std::uint8_t* data, const std::size_t length) {
  std::uint8_t combined = 0;
  for (std::size_t index = 0; index < length; ++index) {
    combined |= data[index];
  }
  return combined != 0;
}

bool AllZero(const std::uint8_t* data, const std::size_t length) {
  return !AnyNonzero(data, length);
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

std::uint32_t ExtendCrc32(std::uint32_t crc, const std::uint8_t* data,
                          const std::size_t length) {
  for (std::size_t index = 0; index < length; ++index) {
    crc ^= data[index];
    for (int bit = 0; bit < 8; ++bit) {
      const std::uint32_t mask = 0U - (crc & 1U);
      crc = (crc >> 1) ^ (0xEDB88320U & mask);
    }
  }
  return crc;
}

std::uint32_t SlotCrc32(const std::uint8_t* slot) {
  std::uint32_t crc = ExtendCrc32(0xFFFFFFFFU, slot, kCrcOffset);
  crc = ExtendCrc32(crc, slot + kCommitOffset,
                    kRoamingConfigSlotBytes - kCommitOffset);
  return crc ^ 0xFFFFFFFFU;
}

bool StrictlySortedRevocations(const RoamingEndpointConfig& config) {
  for (std::size_t index = 0; index < config.revoked_installation_ids.size(); ++index) {
    const auto& value = config.revoked_installation_ids[index];
    if (index < config.revoked_installation_count) {
      if (!AnyNonzero(value.data(), value.size()) ||
          (index != 0 && !(config.revoked_installation_ids[index - 1] < value))) {
        return false;
      }
    } else if (!AllZero(value.data(), value.size())) {
      return false;
    }
  }
  return true;
}

void EncodeWifi(const WifiProfile& profile, std::uint8_t* output) {
  output[0] = static_cast<std::uint8_t>(profile.security);
  output[1] = profile.open_network_approved ? 1 : 0;
  output[2] = profile.priority;
  output[3] = profile.ssid_length;
  output[4] = profile.credential_length;
  std::copy(profile.ssid.begin(), profile.ssid.end(), output + 8);
  std::copy(profile.credential.begin(), profile.credential.end(),
            output + 8 + profile.ssid.size());
}

bool DecodeWifi(const std::uint8_t* input, WifiProfile* output) {
  if (output == nullptr || input[1] > 1 || input[5] != 0 || input[6] != 0 ||
      input[7] != 0) {
    return false;
  }
  WifiProfile profile{};
  profile.security = static_cast<WifiSecurity>(input[0]);
  profile.open_network_approved = input[1] != 0;
  profile.priority = input[2];
  profile.ssid_length = input[3];
  profile.credential_length = input[4];
  std::copy_n(input + 8, profile.ssid.size(), profile.ssid.begin());
  std::copy_n(input + 8 + profile.ssid.size(), profile.credential.size(),
              profile.credential.begin());
  if (!ValidateWifiProfile(profile)) {
    return false;
  }
  *output = profile;
  return true;
}

void EncodePayload(const RoamingEndpointConfig& config, std::uint8_t* output) {
  std::size_t offset = 0;
  auto append = [&](const auto& value) {
    std::copy(value.begin(), value.end(), output + offset);
    offset += value.size();
  };
  append(config.device_id);
  append(config.owner_id);
  append(config.owner_ca_sha256);
  PutU64(output + offset, config.epoch);
  offset += 8;
  PutU64(output + offset, config.policy_sequence);
  offset += 8;
  PutU64(output + offset, config.previous_policy_sequence);
  offset += 8;
  append(config.policy_hash);
  append(config.previous_policy_hash);
  append(config.policy_auth_tag);
  PutU16(output + offset, config.owner_ca_length);
  offset += 2;
  output[offset++] = config.wifi_profile_count;
  output[offset++] = config.revoked_installation_count;
  offset += 4;
  append(config.owner_ca_der);
  for (const auto& revoked : config.revoked_installation_ids) {
    append(revoked);
  }
  for (std::size_t index = 0; index < config.wifi_profiles.size(); ++index) {
    if (index < config.wifi_profile_count) {
      EncodeWifi(config.wifi_profiles[index], output + offset);
    }
    offset += kWifiRecordBytes;
  }
}

bool DecodePayload(const std::uint8_t* input, RoamingEndpointConfig* output) {
  RoamingEndpointConfig config{};
  std::size_t offset = 0;
  auto take = [&](auto* value) {
    std::copy_n(input + offset, value->size(), value->begin());
    offset += value->size();
  };
  take(&config.device_id);
  take(&config.owner_id);
  take(&config.owner_ca_sha256);
  config.epoch = GetU64(input + offset);
  offset += 8;
  config.policy_sequence = GetU64(input + offset);
  offset += 8;
  config.previous_policy_sequence = GetU64(input + offset);
  offset += 8;
  take(&config.policy_hash);
  take(&config.previous_policy_hash);
  take(&config.policy_auth_tag);
  config.owner_ca_length = GetU16(input + offset);
  offset += 2;
  config.wifi_profile_count = input[offset++];
  config.revoked_installation_count = input[offset++];
  if (!AllZero(input + offset, 4)) {
    return false;
  }
  offset += 4;
  take(&config.owner_ca_der);
  for (auto& revoked : config.revoked_installation_ids) {
    take(&revoked);
  }
  for (std::size_t index = 0; index < config.wifi_profiles.size(); ++index) {
    if (index < config.wifi_profile_count) {
      if (!DecodeWifi(input + offset, &config.wifi_profiles[index])) {
        return false;
      }
    } else if (!AllZero(input + offset, kWifiRecordBytes)) {
      return false;
    }
    offset += kWifiRecordBytes;
  }
  if (offset != kRoamingConfigPayloadBytes || !ValidateRoamingConfig(config)) {
    return false;
  }
  *output = config;
  return true;
}

bool ConstantTimeEqual(const std::uint8_t* left, const std::uint8_t* right,
                       const std::size_t length) {
  std::uint8_t difference = 0;
  for (std::size_t index = 0; index < length; ++index) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

void SecureClear(void* data, std::size_t length) {
  volatile auto* output = static_cast<volatile std::uint8_t*>(data);
  while (length-- != 0) {
    *output++ = 0;
  }
}

}  // namespace

AuthenticatedPolicyIdentity RoamingPolicyIdentity(
    const RoamingEndpointConfig& config) {
  return {
      config.device_id,
      config.owner_id,
      config.owner_ca_sha256,
      config.epoch,
      config.policy_sequence,
      config.policy_hash,
      config.previous_policy_sequence,
      config.previous_policy_hash,
  };
}

bool ValidateRoamingConfig(const RoamingEndpointConfig& config) {
  if (!ValidateAuthenticatedPolicyIdentity(RoamingPolicyIdentity(config)) ||
      config.owner_ca_length == 0 ||
      config.owner_ca_length > config.owner_ca_der.size() ||
      config.owner_ca_der[0] != 0x30 ||
      !AllZero(config.owner_ca_der.data() + config.owner_ca_length,
               config.owner_ca_der.size() - config.owner_ca_length) ||
      !AnyNonzero(config.policy_auth_tag.data(), config.policy_auth_tag.size()) ||
      config.wifi_profile_count > config.wifi_profiles.size() ||
      config.revoked_installation_count > config.revoked_installation_ids.size() ||
      !StrictlySortedRevocations(config)) {
    return false;
  }
  for (std::size_t index = 0; index < config.wifi_profile_count; ++index) {
    if (!ValidateWifiProfile(config.wifi_profiles[index])) {
      return false;
    }
  }
  return true;
}

bool BuildRoamingPolicyHashInput(const RoamingEndpointConfig& config,
                                 PolicyHashInput* output) {
  RoamingPolicyVerificationWorkspace workspace{};
  return BuildRoamingPolicyHashInput(config, output, &workspace);
}

bool BuildRoamingPolicyHashInput(
    const RoamingEndpointConfig& config, PolicyHashInput* output,
    RoamingPolicyVerificationWorkspace* workspace) {
  if (output == nullptr || workspace == nullptr) {
    return false;
  }
  output->fill(0);
  workspace->structurally_valid = config;
  workspace->structurally_valid.policy_hash.fill(1);
  workspace->structurally_valid.policy_auth_tag.fill(1);
  if (!ValidateRoamingConfig(workspace->structurally_valid)) {
    SecureClear(&workspace->structurally_valid,
                sizeof(workspace->structurally_valid));
    return false;
  }
  workspace->payload.fill(0);
  EncodePayload(config, workspace->payload.data());
  std::size_t offset = 0;
  std::copy(protocol::kRoamingPolicyHashDomain.begin(),
            protocol::kRoamingPolicyHashDomain.end(), output->begin());
  offset += protocol::kRoamingPolicyHashDomain.size();
  std::copy_n(workspace->payload.begin(), kPolicyHashOffset,
              output->begin() + offset);
  offset += kPolicyHashOffset;
  std::copy(workspace->payload.begin() + kPreviousPolicyHashOffset,
            workspace->payload.begin() + kPolicyAuthTagOffset,
            output->begin() + offset);
  offset += kPolicyAuthTagOffset - kPreviousPolicyHashOffset;
  std::copy(workspace->payload.begin() + kPolicyTailOffset,
            workspace->payload.end(),
            output->begin() + offset);
  offset += workspace->payload.size() - kPolicyTailOffset;
  SecureClear(&workspace->structurally_valid,
              sizeof(workspace->structurally_valid));
  SecureClear(workspace->payload.data(), workspace->payload.size());
  return offset == output->size();
}

bool BuildRoamingPolicyAuthInput(const PolicyHash& policy_hash,
                                 PolicyAuthInput* output) {
  if (output == nullptr || !AnyNonzero(policy_hash.data(), policy_hash.size())) {
    return false;
  }
  output->fill(0);
  std::copy(protocol::kRoamingPolicyAuthDomain.begin(),
            protocol::kRoamingPolicyAuthDomain.end(), output->begin());
  std::copy(policy_hash.begin(), policy_hash.end(),
            output->begin() + protocol::kRoamingPolicyAuthDomain.size());
  return true;
}

bool VerifyAuthenticatedRoamingPolicy(
    const RoamingEndpointConfig& config, const RecoverySecret& recovery_secret,
    RoamingPolicyCrypto& crypto, AuthenticatedPolicyIdentity* output) {
  RoamingPolicyVerificationWorkspace workspace{};
  return VerifyAuthenticatedRoamingPolicy(config, recovery_secret, crypto,
                                           output, &workspace);
}

bool VerifyAuthenticatedRoamingPolicy(
    const RoamingEndpointConfig& config, const RecoverySecret& recovery_secret,
    RoamingPolicyCrypto& crypto, AuthenticatedPolicyIdentity* output,
    RoamingPolicyVerificationWorkspace* workspace) {
  if (output == nullptr || workspace == nullptr) {
    return false;
  }
  *output = {};
  if (!ValidateRoamingConfig(config) ||
      !AnyNonzero(recovery_secret.data(), recovery_secret.size())) {
    return false;
  }
  const bool valid =
      BuildRoamingPolicyHashInput(config, &workspace->hash_input, workspace) &&
      crypto.Sha256(config.owner_ca_der.data(), config.owner_ca_length,
                    workspace->ca_hash.data()) &&
      ConstantTimeEqual(workspace->ca_hash.data(),
                        config.owner_ca_sha256.data(),
                        workspace->ca_hash.size()) &&
      crypto.Sha256(workspace->hash_input.data(), workspace->hash_input.size(),
                    workspace->calculated_hash.data()) &&
      ConstantTimeEqual(workspace->calculated_hash.data(),
                        config.policy_hash.data(),
                        workspace->calculated_hash.size()) &&
      roaming::BuildLinkSaltInput(config.owner_id, config.device_id,
                                  config.epoch, &workspace->salt_input) &&
      crypto.Sha256(workspace->salt_input.data(), workspace->salt_input.size(),
                    workspace->salt.data()) &&
      crypto.HkdfSha256(
          recovery_secret.data(), recovery_secret.size(),
          workspace->salt.data(), workspace->salt.size(),
          protocol::kRoamingPolicyAuthKeyDomain.data(),
          protocol::kRoamingPolicyAuthKeyDomain.size(),
          workspace->auth_key.data()) &&
      BuildRoamingPolicyAuthInput(config.policy_hash,
                                  &workspace->auth_input) &&
      crypto.HmacSha256(workspace->auth_key.data(),
                        workspace->auth_input.data(),
                        workspace->auth_input.size(),
                        workspace->calculated_tag.data()) &&
      ConstantTimeEqual(workspace->calculated_tag.data(),
                        config.policy_auth_tag.data(),
                        workspace->calculated_tag.size());
  SecureClear(workspace, sizeof(*workspace));
  if (!valid) {
    return false;
  }
  *output = RoamingPolicyIdentity(config);
  return true;
}

bool AuthorizeRoamingPeer(const RoamingEndpointConfig& config,
                          const RecoverySecret& recovery_secret,
                          const roaming::P256Spki& peer_spki,
                          RoamingPolicyCrypto& crypto,
                          RoamingPeerAuthorization* output) {
  RoamingPolicyVerificationWorkspace workspace{};
  return AuthorizeRoamingPeer(config, recovery_secret, peer_spki, crypto,
                              output, &workspace);
}

bool AuthorizeRoamingPeer(
    const RoamingEndpointConfig& config,
    const RecoverySecret& recovery_secret,
    const roaming::P256Spki& peer_spki, RoamingPolicyCrypto& crypto,
    RoamingPeerAuthorization* output,
    RoamingPolicyVerificationWorkspace* workspace) {
  if (output == nullptr || workspace == nullptr) {
    return false;
  }
  *output = {};
  AuthenticatedPolicyIdentity policy{};
  roaming::InstallationHashInput installation_input{};
  roaming::LinkSaltInput salt_input{};
  roaming::DeviceLinkInfo link_info{};
  std::array<std::uint8_t, 32> installation_hash{};
  std::array<std::uint8_t, 32> link_salt{};
  RoamingPeerAuthorization candidate{};
  const bool authorized =
      VerifyAuthenticatedRoamingPolicy(config, recovery_secret, crypto,
                                       &policy, workspace) &&
      roaming::BuildInstallationHashInput(peer_spki, &installation_input) &&
      crypto.Sha256(installation_input.data(), installation_input.size(),
                    installation_hash.data());
  if (!authorized) {
    SecureClear(installation_input.data(), installation_input.size());
    SecureClear(installation_hash.data(), installation_hash.size());
    return false;
  }
  std::copy_n(installation_hash.begin(), candidate.installation_id.size(),
              candidate.installation_id.begin());
  const auto revoked_end = config.revoked_installation_ids.begin() +
                           config.revoked_installation_count;
  if (!AnyNonzero(candidate.installation_id.data(),
                  candidate.installation_id.size()) ||
      std::binary_search(config.revoked_installation_ids.begin(), revoked_end,
                         candidate.installation_id) ||
      !roaming::BuildLinkSaltInput(config.owner_id, config.device_id,
                                   config.epoch, &salt_input) ||
      !crypto.Sha256(salt_input.data(), salt_input.size(), link_salt.data()) ||
      !roaming::BuildDeviceLinkInfo(candidate.installation_id, peer_spki,
                                    &link_info) ||
      !crypto.HkdfSha256(recovery_secret.data(), recovery_secret.size(),
                         link_salt.data(), link_salt.size(), link_info.data(),
                         link_info.size(), candidate.link_secret.data()) ||
      !AnyNonzero(candidate.link_secret.data(), candidate.link_secret.size())) {
    SecureClear(&candidate, sizeof(candidate));
    SecureClear(installation_input.data(), installation_input.size());
    SecureClear(installation_hash.data(), installation_hash.size());
    SecureClear(salt_input.data(), salt_input.size());
    SecureClear(link_salt.data(), link_salt.size());
    SecureClear(link_info.data(), link_info.size());
    return false;
  }
  candidate.peer_spki = peer_spki;
  *output = candidate;
  SecureClear(&candidate, sizeof(candidate));
  SecureClear(installation_input.data(), installation_input.size());
  SecureClear(installation_hash.data(), installation_hash.size());
  SecureClear(salt_input.data(), salt_input.size());
  SecureClear(link_salt.data(), link_salt.size());
  SecureClear(link_info.data(), link_info.size());
  return true;
}

bool BuildAuthenticatedRouteProof(
    const RoamingEndpointConfig& config,
    const RecoverySecret& recovery_secret,
    const roaming::RouteProofFields& fields, RoamingPolicyCrypto& crypto,
    roaming::RouteProofResponse* output) {
  RoamingPolicyVerificationWorkspace workspace{};
  return BuildAuthenticatedRouteProof(config, recovery_secret, fields, crypto,
                                      output, &workspace);
}

bool BuildAuthenticatedRouteProof(
    const RoamingEndpointConfig& config,
    const RecoverySecret& recovery_secret,
    const roaming::RouteProofFields& fields, RoamingPolicyCrypto& crypto,
    roaming::RouteProofResponse* output,
    RoamingPolicyVerificationWorkspace* workspace) {
  if (output == nullptr || workspace == nullptr) {
    return false;
  }
  output->fill(0);
  AuthenticatedPolicyIdentity policy{};
  roaming::LinkSaltInput salt_input{};
  roaming::RouteProofKeyInfo key_info{};
  roaming::RouteProofBody body{};
  roaming::RouteProofTag tag{};
  std::array<std::uint8_t, 32> salt{};
  std::array<std::uint8_t, 32> route_secret{};
  const auto revoked_end = config.revoked_installation_ids.begin() +
                           config.revoked_installation_count;
  const bool valid =
      VerifyAuthenticatedRoamingPolicy(config, recovery_secret, crypto,
                                       &policy, workspace) &&
      fields.owner_id == config.owner_id &&
      fields.device_id == config.device_id && fields.epoch == config.epoch &&
      fields.policy_sequence == config.policy_sequence &&
      fields.policy_hash == config.policy_hash &&
      !std::binary_search(config.revoked_installation_ids.begin(), revoked_end,
                          fields.controller_installation_id) &&
      roaming::BuildLinkSaltInput(config.owner_id, config.device_id,
                                  config.epoch, &salt_input) &&
      crypto.Sha256(salt_input.data(), salt_input.size(), salt.data()) &&
      roaming::BuildRouteProofKeyInfo(fields.controller_installation_id,
                                      &key_info) &&
      crypto.HkdfSha256(recovery_secret.data(), recovery_secret.size(),
                        salt.data(), salt.size(), key_info.data(),
                        key_info.size(), route_secret.data()) &&
      roaming::BuildRouteProofBody(fields, &body) &&
      crypto.HmacSha256(route_secret.data(), body.data(), body.size(),
                        tag.data()) &&
      roaming::BuildRouteProofResponse(fields, tag, output);
  SecureClear(salt_input.data(), salt_input.size());
  SecureClear(key_info.data(), key_info.size());
  SecureClear(body.data(), body.size());
  SecureClear(tag.data(), tag.size());
  SecureClear(salt.data(), salt.size());
  SecureClear(route_secret.data(), route_secret.size());
  if (!valid) {
    output->fill(0);
  }
  return valid;
}

bool EncodeRoamingConfigPayload(
    const RoamingEndpointConfig& config,
    std::array<std::uint8_t, kRoamingConfigPayloadBytes>* output) {
  if (output == nullptr) {
    return false;
  }
  output->fill(0);
  if (!ValidateRoamingConfig(config)) {
    return false;
  }
  EncodePayload(config, output->data());
  return true;
}

bool DecodeRoamingConfigPayload(const std::uint8_t* payload,
                                const std::size_t length,
                                RoamingEndpointConfig* output) {
  if (output != nullptr) {
    *output = {};
  }
  return payload != nullptr && length == kRoamingConfigPayloadBytes && output != nullptr &&
         DecodePayload(payload, output);
}

bool EncodeRoamingSlot(
    const std::uint64_t generation, const RoamingEndpointConfig& config,
    std::array<std::uint8_t, kRoamingConfigSlotBytes>* output) {
  if (output == nullptr) {
    return false;
  }
  output->fill(0);
  if (generation == 0 || !ValidateRoamingConfig(config)) {
    return false;
  }
  std::copy(kMagic.begin(), kMagic.end(), output->begin());
  PutU16(output->data() + 4, kFormatVersion);
  PutU16(output->data() + 6, static_cast<std::uint16_t>(kSlotHeaderBytes));
  PutU64(output->data() + 8, generation);
  PutU32(output->data() + 16,
         static_cast<std::uint32_t>(kRoamingConfigPayloadBytes));
  std::copy(kCommitMarker.begin(), kCommitMarker.end(),
            output->begin() + kCommitOffset);
  EncodePayload(config, output->data() + kSlotHeaderBytes);
  PutU32(output->data() + kCrcOffset, SlotCrc32(output->data()));
  return true;
}

SlotInspection InspectRoamingSlot(const SlotView slot) {
  if (slot.data == nullptr || slot.size != kRoamingConfigSlotBytes) {
    return {SlotCondition::kMalformed, 0};
  }
  if (std::all_of(slot.data, slot.data + slot.size,
                  [](const std::uint8_t byte) { return byte == 0xFF; })) {
    return {SlotCondition::kErased, 0};
  }
  const std::uint64_t generation = GetU64(slot.data + 8);
  RoamingEndpointConfig decoded{};
  if (!std::equal(kMagic.begin(), kMagic.end(), slot.data) ||
      GetU16(slot.data + 4) != kFormatVersion ||
      GetU16(slot.data + 6) != kSlotHeaderBytes || generation == 0 ||
      GetU32(slot.data + 16) != kRoamingConfigPayloadBytes ||
      !std::equal(kCommitMarker.begin(), kCommitMarker.end(),
                  slot.data + kCommitOffset) ||
      GetU32(slot.data + kCrcOffset) != SlotCrc32(slot.data) ||
      !DecodePayload(slot.data + kSlotHeaderBytes, &decoded)) {
    return {SlotCondition::kMalformed, 0};
  }
  return {SlotCondition::kValid, generation};
}

Selection SelectNewestRoaming(const SlotView slot_a, const SlotView slot_b,
                              RoamingEndpointConfig* output) {
  if (output == nullptr) {
    return {ConfigState::kLockedUnprovisioned, SlotId::kNone, 0};
  }
  *output = {};
  const SlotInspection a = InspectRoamingSlot(slot_a);
  const SlotInspection b = InspectRoamingSlot(slot_b);
  const bool a_valid = a.condition == SlotCondition::kValid;
  const bool b_valid = b.condition == SlotCondition::kValid;
  if (a_valid && b_valid && a.generation == b.generation &&
      !std::equal(slot_a.data, slot_a.data + slot_a.size, slot_b.data)) {
    return {ConfigState::kLockedUnprovisioned, SlotId::kNone, 0};
  }
  const SlotView selected = a_valid && (!b_valid || a.generation >= b.generation)
                                ? slot_a
                            : b_valid ? slot_b
                                      : SlotView{nullptr, 0};
  const SlotId id = selected.data == slot_a.data && selected.data != nullptr
                        ? SlotId::kA
                    : selected.data != nullptr ? SlotId::kB
                                               : SlotId::kNone;
  const std::uint64_t generation = id == SlotId::kA ? a.generation : b.generation;
  if (id == SlotId::kNone ||
      !DecodePayload(selected.data + kSlotHeaderBytes, output)) {
    *output = {};
    return {ConfigState::kLockedUnprovisioned, SlotId::kNone, 0};
  }
  return {ConfigState::kReady, id, generation};
}

UpdatePlan PlanRoamingUpdate(const SlotView slot_a, const SlotView slot_b) {
  const SlotInspection a = InspectRoamingSlot(slot_a);
  const SlotInspection b = InspectRoamingSlot(slot_b);
  const bool a_valid = a.condition == SlotCondition::kValid;
  const bool b_valid = b.condition == SlotCondition::kValid;
  if (a_valid && b_valid && a.generation == b.generation &&
      !std::equal(slot_a.data, slot_a.data + slot_a.size, slot_b.data)) {
    return {false, SlotId::kNone, 0};
  }
  if (a.condition == SlotCondition::kErased &&
      b.condition == SlotCondition::kErased) {
    return {true, SlotId::kA, 1};
  }
  if (!a_valid && a.condition != SlotCondition::kErased && !b_valid &&
      b.condition != SlotCondition::kErased) {
    return {false, SlotId::kNone, 0};
  }
  const std::uint64_t newest = a_valid && (!b_valid || a.generation >= b.generation)
                                   ? a.generation
                                   : b_valid ? b.generation : 0;
  if (newest == std::numeric_limits<std::uint64_t>::max()) {
    return {false, SlotId::kNone, 0};
  }
  if (!a_valid) {
    return {true, SlotId::kA, newest + 1};
  }
  if (!b_valid) {
    return {true, SlotId::kB, newest + 1};
  }
  return {true, a.generation <= b.generation ? SlotId::kA : SlotId::kB,
          newest + 1};
}

}  // namespace keyferry::config
