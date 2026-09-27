#include "roaming_profile.h"

#include <algorithm>

namespace keyferry::roaming {
namespace {

constexpr std::array<std::uint8_t, 26> kP256SpkiPrefix{
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};

template <std::size_t OutputSize, std::size_t InputSize>
void Append(std::array<std::uint8_t, OutputSize>* output, std::size_t* offset,
            const std::array<std::uint8_t, InputSize>& input) {
  std::copy(input.begin(), input.end(), output->begin() + *offset);
  *offset += input.size();
}

template <std::size_t Size>
bool AnyNonzero(const std::array<std::uint8_t, Size>& value) {
  return std::any_of(value.begin(), value.end(), [](const std::uint8_t byte) {
    return byte != 0;
  });
}

template <std::size_t Size>
void AppendU64(std::array<std::uint8_t, Size>* output, std::size_t* offset,
               const std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    (*output)[(*offset)++] = static_cast<std::uint8_t>(value >> shift);
  }
}

bool ValidSpki(const P256Spki& spki) {
  return std::equal(kP256SpkiPrefix.begin(), kP256SpkiPrefix.end(), spki.begin()) &&
         spki[kP256SpkiPrefix.size()] == 0x04;
}

template <std::size_t OutputSize, std::size_t PrefixSize,
          std::size_t IdSize, std::size_t SuffixSize>
bool BuildHexName(const std::array<std::uint8_t, PrefixSize>& prefix,
                  const std::array<std::uint8_t, IdSize>& id,
                  const std::array<std::uint8_t, SuffixSize>& suffix,
                  std::array<char, OutputSize>* output) {
  if (output == nullptr || !AnyNonzero(id) ||
      OutputSize != PrefixSize + IdSize * 2 + SuffixSize + 1) {
    return false;
  }
  constexpr char kHex[] = "0123456789abcdef";
  output->fill(0);
  std::size_t offset = 0;
  for (const auto byte : prefix) {
    (*output)[offset++] = static_cast<char>(byte);
  }
  for (const auto byte : id) {
    (*output)[offset++] = kHex[byte >> 4U];
    (*output)[offset++] = kHex[byte & 0x0fU];
  }
  for (const auto byte : suffix) {
    (*output)[offset++] = static_cast<char>(byte);
  }
  return offset + 1 == output->size() && (*output)[offset] == '\0';
}

}  // namespace

bool BuildInstallationHashInput(const P256Spki& spki, InstallationHashInput* output) {
  if (output == nullptr || !ValidSpki(spki)) {
    return false;
  }
  std::size_t offset = 0;
  Append(output, &offset, protocol::kRoamingInstallationIdDomain);
  Append(output, &offset, spki);
  return offset == output->size();
}

bool BuildLinkSaltInput(const OwnerId& owner_id, const DeviceId& device_id,
                        const std::uint64_t epoch, LinkSaltInput* output) {
  if (output == nullptr || !AnyNonzero(owner_id) || !AnyNonzero(device_id) || epoch == 0) {
    return false;
  }
  std::size_t offset = 0;
  Append(output, &offset, protocol::kRoamingLinkSaltDomain);
  Append(output, &offset, owner_id);
  Append(output, &offset, device_id);
  AppendU64(output, &offset, epoch);
  return offset == output->size();
}

bool BuildDeviceLinkInfo(const InstallationId& installation_id, const P256Spki& spki,
                         DeviceLinkInfo* output) {
  if (output == nullptr || !AnyNonzero(installation_id) || !ValidSpki(spki)) {
    return false;
  }
  std::size_t offset = 0;
  Append(output, &offset, protocol::kRoamingDeviceLinkDomain);
  Append(output, &offset, installation_id);
  Append(output, &offset, spki);
  return offset == output->size();
}

bool BuildRouteProofKeyInfo(const InstallationId& controller_installation_id,
                            RouteProofKeyInfo* output) {
  if (output == nullptr || !AnyNonzero(controller_installation_id)) {
    return false;
  }
  std::size_t offset = 0;
  Append(output, &offset, protocol::kRoamingRouteProofKeyDomain);
  Append(output, &offset, controller_installation_id);
  return offset == output->size();
}

bool BuildRouteProofFields(const RouteProofFields& fields,
                           RouteProofFieldsBytes* output) {
  if (output == nullptr || !AnyNonzero(fields.owner_id) || !AnyNonzero(fields.device_id) ||
      !AnyNonzero(fields.gateway_installation_id) ||
      !AnyNonzero(fields.controller_installation_id) ||
      !AnyNonzero(fields.policy_hash) || !AnyNonzero(fields.controller_nonce) ||
      !AnyNonzero(fields.device_boot_nonce) ||
      !AnyNonzero(fields.endpoint_session_id) || fields.epoch == 0 ||
      fields.policy_sequence == 0 || fields.link_path == 0 ||
      fields.link_path > 2) {
    return false;
  }
  std::size_t offset = 0;
  Append(output, &offset, fields.owner_id);
  Append(output, &offset, fields.device_id);
  AppendU64(output, &offset, fields.epoch);
  AppendU64(output, &offset, fields.policy_sequence);
  Append(output, &offset, fields.policy_hash);
  Append(output, &offset, fields.gateway_installation_id);
  Append(output, &offset, fields.controller_installation_id);
  Append(output, &offset, fields.controller_nonce);
  Append(output, &offset, fields.device_boot_nonce);
  Append(output, &offset, fields.endpoint_session_id);
  (*output)[offset++] = fields.link_path;
  (*output)[offset++] = fields.usb_ready ? 1 : 0;
  return offset == output->size();
}

bool BuildRouteProofBody(const RouteProofFields& fields, RouteProofBody* output) {
  if (output == nullptr) {
    return false;
  }
  RouteProofFieldsBytes encoded_fields{};
  if (!BuildRouteProofFields(fields, &encoded_fields)) {
    return false;
  }
  std::size_t offset = 0;
  Append(output, &offset, protocol::kRoamingRouteProofDomain);
  Append(output, &offset, encoded_fields);
  return offset == output->size();
}

bool BuildRouteProofResponse(const RouteProofFields& fields,
                             const RouteProofTag& tag,
                             RouteProofResponse* output) {
  if (output == nullptr || !AnyNonzero(tag)) {
    return false;
  }
  RouteProofFieldsBytes encoded_fields{};
  if (!BuildRouteProofFields(fields, &encoded_fields)) {
    return false;
  }
  std::size_t offset = 0;
  Append(output, &offset, encoded_fields);
  Append(output, &offset, tag);
  return offset == output->size();
}

bool BuildDeviceGatewayName(const DeviceId& device_id,
                            DeviceGatewayName* output) {
  return BuildHexName(protocol::kRoamingDeviceGatewayDnsPrefix, device_id,
                      protocol::kRoamingDeviceGatewayDnsSuffix, output);
}

bool BuildInstallationGatewayName(const InstallationId& installation_id,
                                  InstallationGatewayName* output) {
  return BuildHexName(protocol::kRoamingInstallationGatewayDnsPrefix,
                      installation_id,
                      protocol::kRoamingInstallationGatewayDnsSuffix, output);
}

}  // namespace keyferry::roaming
