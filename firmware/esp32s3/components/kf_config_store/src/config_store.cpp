#include "keyferry/config_store.h"

#include <algorithm>
#include <limits>

namespace keyferry::config {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{'K', 'F', 'C', 'F'};
constexpr std::uint16_t kFormatVersion = 1;
constexpr std::size_t kCrcOffset = 20;

bool AnyNonzero(const std::uint8_t* data, std::size_t length) {
  std::uint8_t combined = 0;
  for (std::size_t index = 0; index < length; ++index) {
    combined |= data[index];
  }
  return combined != 0;
}

bool AllZero(const std::uint8_t* data, std::size_t length) {
  return !AnyNonzero(data, length);
}

void PutU16(std::uint8_t* output, std::uint16_t value) {
  output[0] = static_cast<std::uint8_t>(value);
  output[1] = static_cast<std::uint8_t>(value >> 8);
}

void PutU32(std::uint8_t* output, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    output[index] = static_cast<std::uint8_t>(value >> (index * 8));
  }
}

void PutU64(std::uint8_t* output, std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    output[index] = static_cast<std::uint8_t>(value >> (index * 8));
  }
}

std::uint16_t GetU16(const std::uint8_t* input) {
  return static_cast<std::uint16_t>(input[0]) |
         static_cast<std::uint16_t>(input[1] << 8);
}

std::uint32_t GetU32(const std::uint8_t* input) {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(input[index]) << (index * 8);
  }
  return value;
}

std::uint64_t GetU64(const std::uint8_t* input) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(input[index]) << (index * 8);
  }
  return value;
}

std::uint32_t ExtendCrc32(std::uint32_t crc, const std::uint8_t* data,
                          std::size_t length) {
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
  crc = ExtendCrc32(crc, slot + kCommitOffset, kSlotBytes - kCommitOffset);
  return crc ^ 0xFFFFFFFFU;
}

bool ValidWifi(const WifiProfile& profile) {
  if (profile.ssid_length == 0 || profile.ssid_length > kMaxSsidBytes ||
      profile.credential_length > kMaxWifiCredentialBytes ||
      !AllZero(profile.ssid.data() + profile.ssid_length,
               profile.ssid.size() - profile.ssid_length) ||
      !AllZero(profile.credential.data() + profile.credential_length,
               profile.credential.size() - profile.credential_length)) {
    return false;
  }
  if (profile.security == WifiSecurity::kWpa2Personal) {
    return !profile.open_network_approved && profile.credential_length >= 8;
  }
  return profile.security == WifiSecurity::kOpenExplicit &&
         profile.open_network_approved && profile.credential_length == 0;
}

bool ValidHost(const PairedHost& host) {
  const bool address_valid = host.ipv4[0] != 0 && host.ipv4[0] < 224 &&
                             AnyNonzero(host.ipv4.data(), host.ipv4.size());
  if (!AnyNonzero(host.host_id.data(), host.host_id.size()) || !address_valid ||
      host.port == 0 || host.server_name_length == 0 ||
      host.server_name_length > kMaxServerNameBytes ||
      host.ca_certificate_length == 0 ||
      host.ca_certificate_length > kMaxCaCertificateBytes ||
      !AnyNonzero(host.peer_spki_sha256.data(), host.peer_spki_sha256.size()) ||
      !AnyNonzero(host.link_secret.data(), host.link_secret.size()) ||
      host.ca_certificate_der[0] != 0x30) {
    return false;
  }
  for (std::size_t index = 0; index < host.server_name_length; ++index) {
    if (host.server_name[index] == '\0') {
      return false;
    }
  }
  const auto* name_tail = reinterpret_cast<const std::uint8_t*>(host.server_name.data()) +
                          host.server_name_length;
  return AllZero(name_tail, host.server_name.size() - host.server_name_length) &&
         AllZero(host.ca_certificate_der.data() + host.ca_certificate_length,
                 host.ca_certificate_der.size() - host.ca_certificate_length);
}

bool DecodePayload(const std::uint8_t* payload, EndpointConfig* output) {
  if (output != nullptr) {
    *output = {};
  }
  std::size_t offset = 0;
  if (!AnyNonzero(payload + offset, 16)) {
    return false;
  }
  if (output != nullptr) {
    std::copy_n(payload + offset, output->device_id.size(), output->device_id.begin());
  }
  offset += 16;
  const std::uint8_t* provisioning_key = payload + offset;
  if (!AnyNonzero(payload + offset, 32)) {
    return false;
  }
  if (output != nullptr) {
    std::copy_n(payload + offset, output->provisioning_key.size(),
                output->provisioning_key.begin());
  }
  offset += 32;
  const std::uint8_t wifi_profile_count = payload[offset++];
  const std::uint8_t paired_host_count = payload[offset++];
  if (payload[offset++] != 0 || payload[offset++] != 0 ||
      wifi_profile_count > kMaxWifiProfiles ||
      paired_host_count == 0 || paired_host_count > kMaxPairedHosts) {
    return false;
  }
  if (output != nullptr) {
    output->wifi_profile_count = wifi_profile_count;
    output->paired_host_count = paired_host_count;
  }

  for (std::size_t index = 0; index < kMaxWifiProfiles; ++index) {
    const std::size_t record_start = offset;
    const auto security = static_cast<WifiSecurity>(payload[offset++]);
    const std::uint8_t approved = payload[offset++];
    const std::uint8_t priority = payload[offset++];
    const std::uint8_t ssid_length = payload[offset++];
    const std::uint8_t credential_length = payload[offset++];
    const bool reserved_zero =
        payload[offset] == 0 && payload[offset + 1] == 0 && payload[offset + 2] == 0;
    offset += 3;
    const std::uint8_t* ssid = payload + offset;
    offset += kMaxSsidBytes;
    const std::uint8_t* credential = payload + offset;
    offset += kMaxWifiCredentialBytes;
    if (index < wifi_profile_count) {
      const bool common_valid = approved <= 1 && reserved_zero && ssid_length != 0 &&
                                ssid_length <= kMaxSsidBytes &&
                                credential_length <= kMaxWifiCredentialBytes &&
                                AllZero(ssid + ssid_length,
                                        kMaxSsidBytes - ssid_length) &&
                                AllZero(credential + credential_length,
                                        kMaxWifiCredentialBytes - credential_length);
      const bool security_valid =
          (security == WifiSecurity::kWpa2Personal && approved == 0 &&
           credential_length >= 8) ||
          (security == WifiSecurity::kOpenExplicit && approved == 1 &&
           credential_length == 0);
      if (!common_valid || !security_valid) {
        return false;
      }
      if (output != nullptr) {
        auto& profile = output->wifi_profiles[index];
        profile.security = security;
        profile.open_network_approved = approved != 0;
        profile.priority = priority;
        profile.ssid_length = ssid_length;
        profile.credential_length = credential_length;
        std::copy_n(ssid, profile.ssid.size(), profile.ssid.begin());
        std::copy_n(credential, profile.credential.size(), profile.credential.begin());
      }
    } else if (!AllZero(payload + record_start, kWifiRecordBytes)) {
      return false;
    }
  }

  for (std::size_t index = 0; index < kMaxPairedHosts; ++index) {
    const std::size_t record_start = offset;
    const std::uint8_t* host_id = payload + offset;
    offset += 16;
    const std::uint8_t* ipv4 = payload + offset;
    offset += 4;
    const std::uint16_t port = GetU16(payload + offset);
    offset += 2;
    const bool reserved_zero = payload[offset] == 0 && payload[offset + 1] == 0;
    offset += 2;
    const std::uint16_t server_name_length = GetU16(payload + offset);
    offset += 2;
    const std::uint16_t ca_certificate_length = GetU16(payload + offset);
    offset += 2;
    const std::uint8_t* server_name = payload + offset;
    offset += kMaxServerNameBytes;
    const std::uint8_t* peer_spki_sha256 = payload + offset;
    offset += 32;
    const std::uint8_t* link_secret = payload + offset;
    offset += 32;
    const std::uint8_t* ca_certificate_der = payload + offset;
    offset += kMaxCaCertificateBytes;
    if (index < paired_host_count) {
      bool name_valid = server_name_length != 0 &&
                        server_name_length <= kMaxServerNameBytes;
      for (std::size_t character = 0;
           name_valid && character < server_name_length; ++character) {
        name_valid = server_name[character] != 0;
      }
      const bool address_valid =
          ipv4[0] != 0 && ipv4[0] < 224 && AnyNonzero(ipv4, 4);
      if (!reserved_zero || !AnyNonzero(host_id, 16) || !address_valid || port == 0 ||
          !name_valid || ca_certificate_length == 0 ||
          ca_certificate_length > kMaxCaCertificateBytes ||
          !AllZero(server_name + server_name_length,
                   kMaxServerNameBytes - server_name_length) ||
          !AnyNonzero(peer_spki_sha256, 32) || !AnyNonzero(link_secret, 32) ||
          std::equal(provisioning_key, provisioning_key + 32, link_secret) ||
          ca_certificate_der[0] != 0x30 ||
          !AllZero(ca_certificate_der + ca_certificate_length,
                   kMaxCaCertificateBytes - ca_certificate_length)) {
        return false;
      }
      if (output != nullptr) {
        auto& host = output->paired_hosts[index];
        std::copy_n(host_id, host.host_id.size(), host.host_id.begin());
        std::copy_n(ipv4, host.ipv4.size(), host.ipv4.begin());
        host.port = port;
        host.server_name_length = server_name_length;
        host.ca_certificate_length = ca_certificate_length;
        std::copy_n(server_name, host.server_name.size(), host.server_name.begin());
        std::copy_n(peer_spki_sha256, host.peer_spki_sha256.size(),
                    host.peer_spki_sha256.begin());
        std::copy_n(link_secret, host.link_secret.size(), host.link_secret.begin());
        std::copy_n(ca_certificate_der, host.ca_certificate_der.size(),
                    host.ca_certificate_der.begin());
      }
    } else if (!AllZero(payload + record_start, kHostRecordBytes)) {
      return false;
    }
  }

  return offset == kPayloadBytes;
}

void EncodePayload(const EndpointConfig& config, std::uint8_t* payload) {
  std::size_t offset = 0;
  std::copy(config.device_id.begin(), config.device_id.end(), payload + offset);
  offset += config.device_id.size();
  std::copy(config.provisioning_key.begin(), config.provisioning_key.end(), payload + offset);
  offset += config.provisioning_key.size();
  payload[offset++] = config.wifi_profile_count;
  payload[offset++] = config.paired_host_count;
  offset += 2;

  for (std::size_t index = 0; index < kMaxWifiProfiles; ++index) {
    const auto& profile = config.wifi_profiles[index];
    if (index < config.wifi_profile_count) {
      payload[offset] = static_cast<std::uint8_t>(profile.security);
      payload[offset + 1] = profile.open_network_approved ? 1 : 0;
      payload[offset + 2] = profile.priority;
      payload[offset + 3] = profile.ssid_length;
      payload[offset + 4] = profile.credential_length;
      std::copy(profile.ssid.begin(), profile.ssid.end(), payload + offset + 8);
      std::copy(profile.credential.begin(), profile.credential.end(),
                payload + offset + 8 + profile.ssid.size());
    }
    offset += kWifiRecordBytes;
  }

  for (std::size_t index = 0; index < kMaxPairedHosts; ++index) {
    const auto& host = config.paired_hosts[index];
    if (index < config.paired_host_count) {
      std::copy(host.host_id.begin(), host.host_id.end(), payload + offset);
      offset += host.host_id.size();
      std::copy(host.ipv4.begin(), host.ipv4.end(), payload + offset);
      offset += host.ipv4.size();
      PutU16(payload + offset, host.port);
      offset += 4;
      PutU16(payload + offset, host.server_name_length);
      offset += 2;
      PutU16(payload + offset, host.ca_certificate_length);
      offset += 2;
      std::copy(host.server_name.begin(), host.server_name.end(), payload + offset);
      offset += host.server_name.size();
      std::copy(host.peer_spki_sha256.begin(), host.peer_spki_sha256.end(), payload + offset);
      offset += host.peer_spki_sha256.size();
      std::copy(host.link_secret.begin(), host.link_secret.end(), payload + offset);
      offset += host.link_secret.size();
      std::copy(host.ca_certificate_der.begin(), host.ca_certificate_der.end(),
                payload + offset);
      offset += host.ca_certificate_der.size();
    } else {
      offset += kHostRecordBytes;
    }
  }
}

}  // namespace

std::uint32_t Crc32(const std::uint8_t* data, std::size_t length) {
  if (data == nullptr && length != 0) {
    return 0;
  }
  return ExtendCrc32(0xFFFFFFFFU, data, length) ^ 0xFFFFFFFFU;
}

bool ValidateWifiProfile(const WifiProfile& profile) { return ValidWifi(profile); }

bool ValidateConfig(const EndpointConfig& config) {
  if (!AnyNonzero(config.device_id.data(), config.device_id.size()) ||
      !AnyNonzero(config.provisioning_key.data(), config.provisioning_key.size()) ||
      config.wifi_profile_count > kMaxWifiProfiles ||
      config.paired_host_count == 0 || config.paired_host_count > kMaxPairedHosts) {
    return false;
  }
  for (std::size_t index = 0; index < config.wifi_profiles.size(); ++index) {
    if (index < config.wifi_profile_count) {
      if (!ValidWifi(config.wifi_profiles[index])) {
        return false;
      }
    }
  }
  for (std::size_t index = 0; index < config.paired_hosts.size(); ++index) {
    if (index < config.paired_host_count) {
      if (!ValidHost(config.paired_hosts[index]) ||
          config.paired_hosts[index].link_secret == config.provisioning_key) {
        return false;
      }
    }
  }
  return true;
}

bool EncodeConfigPayload(const EndpointConfig& config,
                         std::array<std::uint8_t, kPayloadBytes>* output) {
  if (output == nullptr) {
    return false;
  }
  output->fill(0);
  if (!ValidateConfig(config)) {
    return false;
  }
  EncodePayload(config, output->data());
  return true;
}

bool DecodeConfigPayload(const std::uint8_t* payload, const std::size_t length,
                         EndpointConfig* output) {
  if (output != nullptr) {
    *output = {};
  }
  return payload != nullptr && length == kPayloadBytes && output != nullptr &&
         DecodePayload(payload, output);
}

bool EncodeSlot(std::uint64_t generation, const EndpointConfig& config,
                std::array<std::uint8_t, kSlotBytes>* output) {
  if (generation == 0 || output == nullptr || !ValidateConfig(config)) {
    return false;
  }
  output->fill(0);
  std::copy(kMagic.begin(), kMagic.end(), output->begin());
  PutU16(output->data() + 4, kFormatVersion);
  PutU16(output->data() + 6, static_cast<std::uint16_t>(kSlotHeaderBytes));
  PutU64(output->data() + 8, generation);
  PutU32(output->data() + 16, static_cast<std::uint32_t>(kPayloadBytes));
  std::copy(kCommitMarker.begin(), kCommitMarker.end(), output->begin() + kCommitOffset);
  EncodePayload(config, output->data() + kSlotHeaderBytes);
  PutU32(output->data() + kCrcOffset, SlotCrc32(output->data()));
  return true;
}

SlotInspection InspectSlot(SlotView slot) {
  if (slot.data == nullptr || slot.size != kSlotBytes) {
    return {SlotCondition::kMalformed, 0};
  }
  if (std::all_of(slot.data, slot.data + slot.size,
                  [](std::uint8_t byte) { return byte == 0xFF; })) {
    return {SlotCondition::kErased, 0};
  }
  if (
      !std::equal(kMagic.begin(), kMagic.end(), slot.data) ||
      GetU16(slot.data + 4) != kFormatVersion ||
      GetU16(slot.data + 6) != kSlotHeaderBytes ||
      GetU32(slot.data + 16) != kPayloadBytes ||
      !std::equal(kCommitMarker.begin(), kCommitMarker.end(),
                  slot.data + kCommitOffset)) {
    return {SlotCondition::kMalformed, 0};
  }
  const std::uint64_t generation = GetU64(slot.data + 8);
  if (generation == 0 || GetU32(slot.data + kCrcOffset) != SlotCrc32(slot.data) ||
      !DecodePayload(slot.data + kSlotHeaderBytes, nullptr)) {
    return {SlotCondition::kMalformed, 0};
  }
  return {SlotCondition::kValid, generation};
}

Selection SelectNewest(SlotView slot_a, SlotView slot_b, EndpointConfig* output) {
  if (output == nullptr) {
    return {ConfigState::kLockedUnprovisioned, SlotId::kNone, 0};
  }
  *output = {};
  const SlotInspection a = InspectSlot(slot_a);
  const SlotInspection b = InspectSlot(slot_b);
  const bool a_valid = a.condition == SlotCondition::kValid;
  const bool b_valid = b.condition == SlotCondition::kValid;
  if (a_valid && b_valid && a.generation == b.generation &&
      !std::equal(slot_a.data, slot_a.data + slot_a.size, slot_b.data)) {
    return {ConfigState::kLockedUnprovisioned, SlotId::kNone, 0};
  }
  SlotId selected = SlotId::kNone;
  SlotView view{nullptr, 0};
  std::uint64_t generation = 0;
  if (a_valid && (!b_valid || a.generation >= b.generation)) {
    selected = SlotId::kA;
    view = slot_a;
    generation = a.generation;
  } else if (b_valid) {
    selected = SlotId::kB;
    view = slot_b;
    generation = b.generation;
  }
  if (selected == SlotId::kNone ||
      !DecodePayload(view.data + kSlotHeaderBytes, output)) {
    *output = {};
    return {ConfigState::kLockedUnprovisioned, SlotId::kNone, 0};
  }
  return {ConfigState::kReady, selected, generation};
}

UpdatePlan PlanUpdate(SlotView slot_a, SlotView slot_b) {
  const SlotInspection a = InspectSlot(slot_a);
  const SlotInspection b = InspectSlot(slot_b);
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
  if (!a_valid && !b_valid) {
    return {false, SlotId::kNone, 0};
  }
  const std::uint64_t newest = a_valid && (!b_valid || a.generation >= b.generation)
                                   ? a.generation
                                   : b.generation;
  if (newest == std::numeric_limits<std::uint64_t>::max()) {
    return {false, SlotId::kNone, 0};
  }
  if (!a_valid) {
    return {true, SlotId::kA, newest + 1};
  }
  if (!b_valid) {
    return {true, SlotId::kB, newest + 1};
  }
  return {true, a.generation <= b.generation ? SlotId::kA : SlotId::kB, newest + 1};
}

}  // namespace keyferry::config
