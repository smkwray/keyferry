// Off-device resource specimen only. Zero authority is rejected by provisioning.
// Installer rejects the probe prerelease. Never flash this specimen.
#pragma once
#include <array>
#include <cstdint>
namespace keyferry::hil_private {
inline constexpr bool kEnabled = false;
inline constexpr std::array<std::uint8_t, 16> kDeviceId{};
inline constexpr std::array<std::uint8_t, 16> kHostId{};
inline constexpr std::array<std::uint8_t, 32> kLinkSecret{};
inline constexpr std::array<std::uint8_t, 32> kProvisioningKey{};
inline constexpr std::array<std::uint8_t, 32> kSpkiSha256{};
inline constexpr std::array<std::uint8_t, 512> kCaCertificateDer{};
inline constexpr std::array<std::uint8_t, 8> kWifiSsid{};
inline constexpr std::array<std::uint8_t, 16> kWifiPassword{};
inline constexpr char kHostIpv4[] = "192.0.2.1";
inline constexpr char kTlsServerName[] = "resource.invalid";
inline constexpr std::uint16_t kHostPort = 7443;
}
