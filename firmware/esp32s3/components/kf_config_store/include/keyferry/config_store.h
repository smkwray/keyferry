#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry_protocol_generated.h"

namespace keyferry::config {

constexpr std::size_t kMaxWifiProfiles = protocol::kConfigMaxWifiProfiles;
constexpr std::size_t kMaxPairedHosts = protocol::kConfigMaxPairedHosts;
constexpr std::size_t kMaxSsidBytes = protocol::kConfigMaxSsidBytes;
constexpr std::size_t kMaxWifiCredentialBytes =
    protocol::kConfigMaxWifiCredentialBytes;
constexpr std::size_t kMaxServerNameBytes = protocol::kConfigMaxServerNameBytes;
constexpr std::size_t kMaxCaCertificateBytes =
    protocol::kConfigMaxCaCertificateBytes;

constexpr std::size_t kSlotHeaderBytes = 28;
constexpr std::size_t kCommitOffset = 24;
constexpr std::array<std::uint8_t, 4> kCommitMarker{'C', 'M', 'I', 'T'};
constexpr std::size_t kWifiRecordBytes = protocol::kConfigWifiRecordBytes;
constexpr std::size_t kHostRecordBytes = protocol::kConfigHostRecordBytes;
constexpr std::size_t kPayloadBytes = protocol::kConfigPayloadBytes;
static_assert(kPayloadBytes == protocol::kConfigFixedHeaderBytes +
                                   kMaxWifiProfiles * kWifiRecordBytes +
                                   kMaxPairedHosts * kHostRecordBytes);
constexpr std::size_t kSlotBytes = kSlotHeaderBytes + kPayloadBytes;
static_assert(kSlotBytes < 16 * 1024);

enum class WifiSecurity : std::uint8_t {
  kWpa2Personal = 1,
  kOpenExplicit = 2,
};

struct WifiProfile {
  WifiSecurity security{WifiSecurity::kWpa2Personal};
  bool open_network_approved{false};
  std::uint8_t priority{0};
  std::uint8_t ssid_length{0};
  std::uint8_t credential_length{0};
  std::array<std::uint8_t, kMaxSsidBytes> ssid{};
  std::array<std::uint8_t, kMaxWifiCredentialBytes> credential{};
};

struct PairedHost {
  std::array<std::uint8_t, 16> host_id{};
  std::array<std::uint8_t, 4> ipv4{};
  std::uint16_t port{0};
  std::uint16_t server_name_length{0};
  std::uint16_t ca_certificate_length{0};
  std::array<char, kMaxServerNameBytes> server_name{};
  std::array<std::uint8_t, 32> peer_spki_sha256{};
  std::array<std::uint8_t, 32> link_secret{};
  std::array<std::uint8_t, kMaxCaCertificateBytes> ca_certificate_der{};
};

// Configuration only. Commands, HID reports, queues, payloads, and transcripts have no persistent
// representation in this schema.
struct EndpointConfig {
  std::array<std::uint8_t, 16> device_id{};
  std::array<std::uint8_t, 32> provisioning_key{};
  std::uint8_t wifi_profile_count{0};
  std::uint8_t paired_host_count{0};
  std::array<WifiProfile, kMaxWifiProfiles> wifi_profiles{};
  std::array<PairedHost, kMaxPairedHosts> paired_hosts{};
};

struct SlotView {
  const std::uint8_t* data;
  std::size_t size;
};

enum class SlotCondition : std::uint8_t {
  kErased,
  kMalformed,
  kValid,
};

struct SlotInspection {
  SlotCondition condition;
  std::uint64_t generation;
};

enum class SlotId : std::uint8_t {
  kNone,
  kA,
  kB,
};

enum class ConfigState : std::uint8_t {
  kLockedUnprovisioned,
  kReady,
};

struct Selection {
  ConfigState state;
  SlotId slot;
  std::uint64_t generation;
};

struct UpdatePlan {
  bool writable;
  SlotId target;
  std::uint64_t generation;
};

std::uint32_t Crc32(const std::uint8_t* data, std::size_t length);
bool ValidateWifiProfile(const WifiProfile& profile);
bool ValidateConfig(const EndpointConfig& config);
bool EncodeConfigPayload(const EndpointConfig& config,
                         std::array<std::uint8_t, kPayloadBytes>* output);
bool DecodeConfigPayload(const std::uint8_t* payload, std::size_t length,
                         EndpointConfig* output);
bool EncodeSlot(std::uint64_t generation, const EndpointConfig& config,
                std::array<std::uint8_t, kSlotBytes>* output);
SlotInspection InspectSlot(SlotView slot);
Selection SelectNewest(SlotView slot_a, SlotView slot_b, EndpointConfig* output);
UpdatePlan PlanUpdate(SlotView slot_a, SlotView slot_b);

}  // namespace keyferry::config
