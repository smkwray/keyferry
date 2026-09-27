#include "keyferry/transport_runtime_config.h"

#include <algorithm>
#include <cstring>

#include "keyferry/roaming_config.h"
#include "roaming_profile.h"

namespace keyferry::transport {
namespace {

bool AnyNonzero(const std::uint8_t* data, std::size_t length) {
  std::uint8_t combined = 0;
  for (std::size_t index = 0; index < length; ++index) {
    combined |= data[index];
  }
  return combined != 0;
}

}  // namespace

bool ParseIpv4Literal(const char* text, std::size_t length,
                      std::array<std::uint8_t, 4>* octets) {
  if (text == nullptr || octets == nullptr || length < 7 || length >= kIpv4TextCapacity) {
    return false;
  }
  std::array<std::uint8_t, 4> parsed{};
  std::size_t part = 0;
  std::uint16_t value = 0;
  std::size_t digits = 0;
  for (std::size_t index = 0; index <= length; ++index) {
    const char current = index == length ? '.' : text[index];
    if (current >= '0' && current <= '9') {
      if (digits == 0 && current == '0' && index + 1 < length && text[index + 1] != '.') {
        return false;
      }
      value = static_cast<std::uint16_t>(value * 10 + (current - '0'));
      if (++digits > 3 || value > 255) {
        return false;
      }
      continue;
    }
    if (current != '.' || digits == 0 || part >= parsed.size()) {
      return false;
    }
    parsed[part++] = static_cast<std::uint8_t>(value);
    value = 0;
    digits = 0;
  }
  if (part != parsed.size()) {
    return false;
  }
  *octets = parsed;
  return true;
}

bool ValidateRuntimeConfig(const RuntimeConfig& config) {
  std::array<std::uint8_t, 4> address{};
  const bool wifi_valid =
      config.wifi_configured
          ? config.wifi.auth == endpoint::WifiAuth::kWpa2Personal &&
                endpoint::ValidateWifiStation(config.wifi)
          : config.wifi.ssid == nullptr && config.wifi.ssid_length == 0 &&
                config.wifi.credential == nullptr &&
                config.wifi.credential_length == 0 &&
                !config.wifi.open_network_approved;
  const bool common_valid =
      wifi_valid && config.tls.server_name != nullptr &&
      config.tls.server_name_length != 0 &&
      config.tls.server_name_length <= 253 && config.tls.port != 0 &&
      config.tls.server_name[config.tls.server_name_length] == '\0' &&
         config.ca_certificate_der != nullptr && config.ca_certificate_der_length >= 64 &&
         config.ca_certificate_der_length <= kMaxCaCertificateBytes &&
         AnyNonzero(config.device_id.data(), config.device_id.size()) &&
         config.wifi_connect_timeout_ms >= 1000 && config.wifi_connect_timeout_ms <= 30000 &&
         config.discovery_timeout_ms >= 100 && config.discovery_timeout_ms <= 10000 &&
         config.tls_connect_timeout_ms >= 1000 && config.tls_connect_timeout_ms <= 30000;
  if (!common_valid) {
    return false;
  }
  if (config.authority_mode == AuthorityMode::kPinnedPeer) {
    return ParseIpv4Literal(config.host_ipv4, config.host_ipv4_length,
                            &address) &&
           config.host_ipv4[config.host_ipv4_length] == '\0' &&
           endpoint::ValidateTlsPolicy(config.tls) &&
           AnyNonzero(config.host_id.data(), config.host_id.size()) &&
           AnyNonzero(config.link_secret.data(), config.link_secret.size()) &&
           config.roaming_policy == nullptr &&
           config.roaming_recovery_secret == nullptr &&
           config.roaming_crypto == nullptr &&
           config.roaming_verification_workspace == nullptr;
  }
  if (config.authority_mode != AuthorityMode::kOwnerRoaming ||
      config.host_ipv4 != nullptr || config.host_ipv4_length != 0 ||
      AnyNonzero(config.host_id.data(), config.host_id.size()) ||
      AnyNonzero(config.link_secret.data(), config.link_secret.size()) ||
      AnyNonzero(config.tls.peer_spki_sha256.data(),
                 config.tls.peer_spki_sha256.size()) ||
      config.tls.port != protocol::kRoamingDeviceTlsPort ||
      config.roaming_policy == nullptr ||
      config.roaming_recovery_secret == nullptr ||
      config.roaming_crypto == nullptr ||
      config.roaming_verification_workspace == nullptr ||
      !config::ValidateRoamingConfig(*config.roaming_policy) ||
      config.roaming_policy->device_id != config.device_id ||
      config.ca_certificate_der != config.roaming_policy->owner_ca_der.data() ||
      config.ca_certificate_der_length !=
          config.roaming_policy->owner_ca_length ||
      !AnyNonzero(config.roaming_recovery_secret->data(),
                  config.roaming_recovery_secret->size())) {
    return false;
  }
  roaming::DeviceGatewayName expected_name{};
  return roaming::BuildDeviceGatewayName(config.device_id, &expected_name) &&
         config.tls.server_name_length == roaming::kDeviceGatewayNameBytes &&
         std::memcmp(config.tls.server_name, expected_name.data(),
                     expected_name.size()) == 0;
}

std::uint32_t ReconnectDelayMs(std::uint32_t consecutive_failures) {
  constexpr std::array<std::uint32_t, 6> kDelays{250, 500, 1000, 2000, 4000, 5000};
  if (consecutive_failures == 0) {
    return kDelays.front();
  }
  return kDelays[std::min<std::size_t>(consecutive_failures - 1, kDelays.size() - 1)];
}

}  // namespace keyferry::transport
