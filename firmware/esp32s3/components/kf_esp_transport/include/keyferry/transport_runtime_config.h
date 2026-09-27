#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry/secure_endpoint.h"

namespace keyferry::transport {

constexpr std::size_t kIpv4TextCapacity = 16;
constexpr std::size_t kMaxCaCertificateBytes = 8192;

enum class AuthorityMode : std::uint8_t {
  kPinnedPeer = 1,
  kOwnerRoaming = 2,
};

}  // namespace keyferry::transport

namespace keyferry::config {
struct RoamingEndpointConfig;
struct RoamingPeerAuthorization;
struct RoamingPolicyVerificationWorkspace;
class RoamingPolicyCrypto;
}  // namespace keyferry::config

namespace keyferry::transport {

struct RuntimeConfig {
  AuthorityMode authority_mode{AuthorityMode::kPinnedPeer};
  bool wifi_configured;
  endpoint::WifiStationView wifi;
  const char* host_ipv4;
  std::size_t host_ipv4_length;
  endpoint::TlsClientPolicy tls;
  const std::uint8_t* ca_certificate_der;
  std::size_t ca_certificate_der_length;
  std::array<std::uint8_t, 16> device_id;
  std::array<std::uint8_t, 16> host_id;
  std::array<std::uint8_t, 32> link_secret;
  const config::RoamingEndpointConfig* roaming_policy{nullptr};
  const std::array<std::uint8_t, 32>* roaming_recovery_secret{nullptr};
  config::RoamingPolicyCrypto* roaming_crypto{nullptr};
  config::RoamingPolicyVerificationWorkspace* roaming_verification_workspace{
      nullptr};
  std::uint32_t wifi_connect_timeout_ms;
  std::uint32_t discovery_timeout_ms;
  std::uint32_t tls_connect_timeout_ms;
  bool ble_gateway_allowed{true};
};

bool ParseIpv4Literal(const char* text, std::size_t length,
                      std::array<std::uint8_t, 4>* octets);
bool ValidateRuntimeConfig(const RuntimeConfig& config);
std::uint32_t ReconnectDelayMs(std::uint32_t consecutive_failures);

}  // namespace keyferry::transport
