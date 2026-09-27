#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry/config_store.h"
#include "keyferry/recovery_anchor.h"
#include "roaming_profile.h"

namespace keyferry::config {

constexpr std::size_t kRoamingConfigFixedHeaderBytes =
    protocol::kRoamingRoamingConfigFixedHeaderBytes;
constexpr std::size_t kRoamingConfigPayloadBytes =
    protocol::kRoamingRoamingConfigPayloadBytes;
constexpr std::size_t kMaxRevokedInstallations =
    protocol::kRoamingMaximumRevokedInstallations;
constexpr std::size_t kRoamingConfigSlotBytes =
    kSlotHeaderBytes + kRoamingConfigPayloadBytes;
constexpr std::size_t kPolicyHashInputBytes =
    protocol::kRoamingPolicyHashInputBytes;
constexpr std::size_t kPolicyAuthInputBytes =
    protocol::kRoamingPolicyAuthInputBytes;
static_assert(kRoamingConfigPayloadBytes ==
              kRoamingConfigFixedHeaderBytes + kMaxCaCertificateBytes +
                  kMaxRevokedInstallations * protocol::kRoamingRevocationEntryBytes +
                  kMaxWifiProfiles * kWifiRecordBytes);
static_assert(kRoamingConfigSlotBytes < 16 * 1024);

struct RoamingEndpointConfig {
  RecoveryDeviceId device_id{};
  RecoveryOwnerId owner_id{};
  OwnerCaHash owner_ca_sha256{};
  std::uint64_t epoch{0};
  std::uint64_t policy_sequence{0};
  std::uint64_t previous_policy_sequence{0};
  PolicyHash policy_hash{};
  PolicyHash previous_policy_hash{};
  std::array<std::uint8_t, protocol::kRoamingPolicyAuthTagBytes> policy_auth_tag{};
  std::uint16_t owner_ca_length{0};
  std::uint8_t wifi_profile_count{0};
  std::uint8_t revoked_installation_count{0};
  std::array<std::uint8_t, kMaxCaCertificateBytes> owner_ca_der{};
  std::array<RecoveryTransactionId, kMaxRevokedInstallations>
      revoked_installation_ids{};
  std::array<WifiProfile, kMaxWifiProfiles> wifi_profiles{};
};

using PolicyHashInput = std::array<std::uint8_t, kPolicyHashInputBytes>;
using PolicyAuthInput = std::array<std::uint8_t, kPolicyAuthInputBytes>;

// Single-owner scratch storage for authenticating a roaming policy. Firmware
// keeps this off FreeRTOS task stacks; callers must not share one workspace
// across concurrent operations.
struct RoamingPolicyVerificationWorkspace {
  RoamingEndpointConfig structurally_valid{};
  std::array<std::uint8_t, kRoamingConfigPayloadBytes> payload{};
  PolicyHashInput hash_input{};
  PolicyAuthInput auth_input{};
  roaming::LinkSaltInput salt_input{};
  std::array<std::uint8_t, 32> ca_hash{};
  std::array<std::uint8_t, 32> calculated_hash{};
  std::array<std::uint8_t, 32> salt{};
  std::array<std::uint8_t, 32> auth_key{};
  std::array<std::uint8_t, 32> calculated_tag{};
};

class RoamingPolicyCrypto {
 public:
  virtual ~RoamingPolicyCrypto() = default;
  virtual bool Sha256(const std::uint8_t* input, std::size_t length,
                      std::uint8_t output[32]) = 0;
  virtual bool HkdfSha256(const std::uint8_t* input_key,
                          std::size_t input_key_length,
                          const std::uint8_t* salt, std::size_t salt_length,
                          const std::uint8_t* info, std::size_t info_length,
                          std::uint8_t output[32]) = 0;
  virtual bool HmacSha256(const std::uint8_t key[32],
                          const std::uint8_t* input, std::size_t input_length,
                          std::uint8_t output[32]) = 0;
};

struct RoamingPeerAuthorization {
  roaming::InstallationId installation_id{};
  roaming::P256Spki peer_spki{};
  std::array<std::uint8_t, 32> link_secret{};
};

bool ValidateRoamingConfig(const RoamingEndpointConfig& config);
bool BuildRoamingPolicyHashInput(const RoamingEndpointConfig& config,
                                 PolicyHashInput* output);
bool BuildRoamingPolicyHashInput(
    const RoamingEndpointConfig& config, PolicyHashInput* output,
    RoamingPolicyVerificationWorkspace* workspace);
bool BuildRoamingPolicyAuthInput(const PolicyHash& policy_hash,
                                 PolicyAuthInput* output);
bool VerifyAuthenticatedRoamingPolicy(
    const RoamingEndpointConfig& config, const RecoverySecret& recovery_secret,
    RoamingPolicyCrypto& crypto, AuthenticatedPolicyIdentity* output);
bool VerifyAuthenticatedRoamingPolicy(
    const RoamingEndpointConfig& config, const RecoverySecret& recovery_secret,
    RoamingPolicyCrypto& crypto, AuthenticatedPolicyIdentity* output,
    RoamingPolicyVerificationWorkspace* workspace);
// Authenticates one TLS peer against an already provisioned owner policy. The
// TLS adapter remains responsible for chain, hostname, role, version, and
// cipher verification before passing the peer's canonical P-256 SPKI here.
bool AuthorizeRoamingPeer(const RoamingEndpointConfig& config,
                          const RecoverySecret& recovery_secret,
                          const roaming::P256Spki& peer_spki,
                          RoamingPolicyCrypto& crypto,
                          RoamingPeerAuthorization* output);
bool AuthorizeRoamingPeer(
    const RoamingEndpointConfig& config,
    const RecoverySecret& recovery_secret,
    const roaming::P256Spki& peer_spki, RoamingPolicyCrypto& crypto,
    RoamingPeerAuthorization* output,
    RoamingPolicyVerificationWorkspace* workspace);
// Produces only the fixed device route-proof statement defined by roaming-v2.
// The controller installation must still be authorized by the current policy.
bool BuildAuthenticatedRouteProof(
    const RoamingEndpointConfig& config,
    const RecoverySecret& recovery_secret,
    const roaming::RouteProofFields& fields, RoamingPolicyCrypto& crypto,
    roaming::RouteProofResponse* output);
bool BuildAuthenticatedRouteProof(
    const RoamingEndpointConfig& config,
    const RecoverySecret& recovery_secret,
    const roaming::RouteProofFields& fields, RoamingPolicyCrypto& crypto,
    roaming::RouteProofResponse* output,
    RoamingPolicyVerificationWorkspace* workspace);
AuthenticatedPolicyIdentity RoamingPolicyIdentity(
    const RoamingEndpointConfig& config);
bool EncodeRoamingConfigPayload(
    const RoamingEndpointConfig& config,
    std::array<std::uint8_t, kRoamingConfigPayloadBytes>* output);
bool DecodeRoamingConfigPayload(const std::uint8_t* payload, std::size_t length,
                                RoamingEndpointConfig* output);
bool EncodeRoamingSlot(
    std::uint64_t generation, const RoamingEndpointConfig& config,
    std::array<std::uint8_t, kRoamingConfigSlotBytes>* output);
SlotInspection InspectRoamingSlot(SlotView slot);
Selection SelectNewestRoaming(SlotView slot_a, SlotView slot_b,
                              RoamingEndpointConfig* output);
UpdatePlan PlanRoamingUpdate(SlotView slot_a, SlotView slot_b);

}  // namespace keyferry::config
