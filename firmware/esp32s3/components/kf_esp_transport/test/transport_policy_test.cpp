#include "keyferry/transport_runtime_config.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>

#include "keyferry/roaming_config.h"
#include "roaming_profile.h"

namespace {

class RejectingCrypto final : public keyferry::config::RoamingPolicyCrypto {
 public:
  bool Sha256(const std::uint8_t*, std::size_t, std::uint8_t[32]) override {
    return false;
  }
  bool HkdfSha256(const std::uint8_t*, std::size_t, const std::uint8_t*,
                  std::size_t, const std::uint8_t*, std::size_t,
                  std::uint8_t[32]) override {
    return false;
  }
  bool HmacSha256(const std::uint8_t[32], const std::uint8_t*, std::size_t,
                  std::uint8_t[32]) override {
    return false;
  }
};

keyferry::transport::RuntimeConfig ValidConfig() {
  static constexpr std::array<std::uint8_t, 4> kSsid{'t', 'e', 's', 't'};
  static constexpr std::array<std::uint8_t, 8> kPassword{'1', '2', '3', '4', '5', '6', '7', '8'};
  static constexpr char kAddress[] = "192.0.2.1";
  static constexpr char kServerName[] = "controller.invalid";
  static constexpr std::array<std::uint8_t, 64> kFakeDer{};
  keyferry::transport::RuntimeConfig config{};
  config.wifi_configured = true;
  config.wifi = {kSsid.data(), kSsid.size(), kPassword.data(), kPassword.size(),
                 keyferry::endpoint::WifiAuth::kWpa2Personal, false};
  config.host_ipv4 = kAddress;
  config.host_ipv4_length = sizeof(kAddress) - 1;
  config.tls.server_name = kServerName;
  config.tls.server_name_length = sizeof(kServerName) - 1;
  config.tls.port = 4433;
  config.tls.peer_spki_sha256.fill(1);
  config.ca_certificate_der = kFakeDer.data();
  config.ca_certificate_der_length = kFakeDer.size();
  config.device_id.fill(2);
  config.host_id.fill(3);
  config.link_secret.fill(4);
  config.wifi_connect_timeout_ms = 15000;
  config.discovery_timeout_ms = 1500;
  config.tls_connect_timeout_ms = 10000;
  return config;
}

void TestIpv4Literal() {
  std::array<std::uint8_t, 4> output{};
  assert(keyferry::transport::ParseIpv4Literal("192.0.2.1", 9, &output));
  assert((output == std::array<std::uint8_t, 4>{192, 0, 2, 1}));
  assert(!keyferry::transport::ParseIpv4Literal("host.invalid", 12, &output));
  assert(!keyferry::transport::ParseIpv4Literal("192.168.001.1", 13, &output));
  assert(!keyferry::transport::ParseIpv4Literal("256.1.1.1", 9, &output));
  assert(!keyferry::transport::ParseIpv4Literal("1.2.3", 5, &output));
}

void TestRuntimePolicy() {
  auto config = ValidConfig();
  assert(keyferry::transport::ValidateRuntimeConfig(config));
  config.wifi.auth = keyferry::endpoint::WifiAuth::kOpenExplicit;
  config.wifi.credential = nullptr;
  config.wifi.credential_length = 0;
  config.wifi.open_network_approved = true;
  assert(!keyferry::transport::ValidateRuntimeConfig(config));

  config = ValidConfig();
  config.link_secret.fill(0);
  assert(!keyferry::transport::ValidateRuntimeConfig(config));
  config = ValidConfig();
  config.wifi_configured = false;
  config.wifi = {};
  assert(keyferry::transport::ValidateRuntimeConfig(config));
  config.wifi.ssid = reinterpret_cast<const std::uint8_t*>("latent");
  assert(!keyferry::transport::ValidateRuntimeConfig(config));
  config = ValidConfig();
  config.tls_connect_timeout_ms = 0;
  assert(!keyferry::transport::ValidateRuntimeConfig(config));
}

void TestRoamingRuntimeHasNoPinnedHostAuthority() {
  static keyferry::config::RoamingEndpointConfig policy;
  static keyferry::config::RecoverySecret recovery_secret;
  static keyferry::roaming::DeviceGatewayName server_name;
  static RejectingCrypto crypto;
  static keyferry::config::RoamingPolicyVerificationWorkspace
      verification_workspace;
  policy = {};
  policy.device_id.fill(0x20);
  policy.owner_id.fill(0x10);
  policy.owner_ca_sha256.fill(0x30);
  policy.epoch = 1;
  policy.policy_sequence = 1;
  policy.policy_hash.fill(0x40);
  policy.policy_auth_tag.fill(0x50);
  policy.owner_ca_length = 64;
  policy.owner_ca_der[0] = 0x30;
  std::fill(policy.owner_ca_der.begin() + 1,
            policy.owner_ca_der.begin() + policy.owner_ca_length,
            static_cast<std::uint8_t>(0x60));
  recovery_secret.fill(0x70);
  assert(keyferry::roaming::BuildDeviceGatewayName(policy.device_id,
                                                   &server_name));

  keyferry::transport::RuntimeConfig config{};
  config.authority_mode = keyferry::transport::AuthorityMode::kOwnerRoaming;
  config.wifi_configured = false;
  config.tls.server_name = server_name.data();
  config.tls.server_name_length = keyferry::roaming::kDeviceGatewayNameBytes;
  config.tls.port = keyferry::protocol::kRoamingDeviceTlsPort;
  config.ca_certificate_der = policy.owner_ca_der.data();
  config.ca_certificate_der_length = policy.owner_ca_length;
  config.device_id = policy.device_id;
  config.roaming_policy = &policy;
  config.roaming_recovery_secret = &recovery_secret;
  config.roaming_crypto = &crypto;
  config.roaming_verification_workspace = &verification_workspace;
  config.wifi_connect_timeout_ms = 15000;
  config.discovery_timeout_ms = 1500;
  config.tls_connect_timeout_ms = 10000;
  assert(keyferry::transport::ValidateRuntimeConfig(config));

  config.tls.peer_spki_sha256[0] = 1;
  assert(!keyferry::transport::ValidateRuntimeConfig(config));
  config.tls.peer_spki_sha256.fill(0);
  config.host_id[0] = 1;
  assert(!keyferry::transport::ValidateRuntimeConfig(config));
  config.host_id.fill(0);
  config.roaming_verification_workspace = nullptr;
  assert(!keyferry::transport::ValidateRuntimeConfig(config));
}

void TestReconnectBounds() {
  assert(keyferry::transport::ReconnectDelayMs(0) == 250);
  assert(keyferry::transport::ReconnectDelayMs(1) == 250);
  assert(keyferry::transport::ReconnectDelayMs(4) == 2000);
  assert(keyferry::transport::ReconnectDelayMs(1000000) == 5000);
}

}  // namespace

int main() {
  TestIpv4Literal();
  TestRuntimePolicy();
  TestRoamingRuntimeHasNoPinnedHostAuthority();
  TestReconnectBounds();
  std::puts("transport_policy_test: ok");
  return 0;
}
