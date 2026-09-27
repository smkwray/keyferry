#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry_protocol_generated.h"

namespace keyferry::roaming {

constexpr std::size_t kInstallationHashInputBytes =
    protocol::kRoamingInstallationIdDomain.size() + protocol::kRoamingP256SpkiBytes;
constexpr std::size_t kLinkSaltInputBytes = protocol::kRoamingLinkSaltDomain.size() +
                                            protocol::kRoamingOwnerIdBytes +
                                            protocol::kRoamingDeviceIdBytes + 8;
constexpr std::size_t kDeviceLinkInfoBytes = protocol::kRoamingDeviceLinkDomain.size() +
                                             protocol::kRoamingInstallationIdBytes +
                                             protocol::kRoamingP256SpkiBytes;
constexpr std::size_t kRouteProofKeyInfoBytes =
    protocol::kRoamingRouteProofKeyDomain.size() + protocol::kRoamingInstallationIdBytes;
constexpr std::size_t kDeviceGatewayNameBytes =
    protocol::kRoamingDeviceGatewayDnsPrefix.size() + 32 +
    protocol::kRoamingDeviceGatewayDnsSuffix.size();
constexpr std::size_t kInstallationGatewayNameBytes =
    protocol::kRoamingInstallationGatewayDnsPrefix.size() + 32 +
    protocol::kRoamingInstallationGatewayDnsSuffix.size();

using InstallationId = std::array<std::uint8_t, protocol::kRoamingInstallationIdBytes>;
using OwnerId = std::array<std::uint8_t, protocol::kRoamingOwnerIdBytes>;
using DeviceId = std::array<std::uint8_t, protocol::kRoamingDeviceIdBytes>;
using P256Spki = std::array<std::uint8_t, protocol::kRoamingP256SpkiBytes>;
using InstallationHashInput = std::array<std::uint8_t, kInstallationHashInputBytes>;
using LinkSaltInput = std::array<std::uint8_t, kLinkSaltInputBytes>;
using DeviceLinkInfo = std::array<std::uint8_t, kDeviceLinkInfoBytes>;
using RouteProofKeyInfo = std::array<std::uint8_t, kRouteProofKeyInfoBytes>;
using RouteProofFieldsBytes =
    std::array<std::uint8_t, protocol::kRoamingRouteProofFieldsBytes>;
using RouteProofBody = std::array<std::uint8_t, protocol::kRoamingRouteProofBodyBytes>;
using RouteProofTag =
    std::array<std::uint8_t, protocol::kRoamingRouteProofTagBytes>;
using RouteProofResponse =
    std::array<std::uint8_t, protocol::kRoamingRouteProofResponseBytes>;
using DeviceGatewayName = std::array<char, kDeviceGatewayNameBytes + 1>;
using InstallationGatewayName =
    std::array<char, kInstallationGatewayNameBytes + 1>;

struct RouteProofFields {
  OwnerId owner_id;
  DeviceId device_id;
  std::uint64_t epoch;
  std::uint64_t policy_sequence;
  std::array<std::uint8_t, 32> policy_hash;
  InstallationId gateway_installation_id;
  InstallationId controller_installation_id;
  std::array<std::uint8_t, 32> controller_nonce;
  std::array<std::uint8_t, 16> device_boot_nonce;
  std::array<std::uint8_t, 16> endpoint_session_id;
  std::uint8_t link_path;
  bool usb_ready;
};

bool BuildInstallationHashInput(const P256Spki& spki, InstallationHashInput* output);
bool BuildLinkSaltInput(const OwnerId& owner_id, const DeviceId& device_id,
                        std::uint64_t epoch, LinkSaltInput* output);
bool BuildDeviceLinkInfo(const InstallationId& installation_id, const P256Spki& spki,
                         DeviceLinkInfo* output);
bool BuildRouteProofKeyInfo(const InstallationId& controller_installation_id,
                            RouteProofKeyInfo* output);
bool BuildRouteProofFields(const RouteProofFields& fields,
                           RouteProofFieldsBytes* output);
bool BuildRouteProofBody(const RouteProofFields& fields, RouteProofBody* output);
bool BuildRouteProofResponse(const RouteProofFields& fields,
                             const RouteProofTag& tag,
                             RouteProofResponse* output);
bool BuildDeviceGatewayName(const DeviceId& device_id,
                            DeviceGatewayName* output);
bool BuildInstallationGatewayName(const InstallationId& installation_id,
                                  InstallationGatewayName* output);

}  // namespace keyferry::roaming
