#include "roaming_profile.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <string_view>

namespace {

keyferry::roaming::P256Spki VectorSpki() {
  keyferry::roaming::P256Spki spki{
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
      0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};
  spki[26] = 0x04;
  for (std::size_t index = 1; index <= 64; ++index) {
    spki[26 + index] = static_cast<std::uint8_t>(index);
  }
  return spki;
}

template <std::size_t Size>
std::array<std::uint8_t, Size> Sequence(const std::uint8_t first) {
  std::array<std::uint8_t, Size> output{};
  for (std::size_t index = 0; index < Size; ++index) {
    output[index] = static_cast<std::uint8_t>(first + index);
  }
  return output;
}

void TestDerivationInputs() {
  using namespace keyferry::roaming;
  const auto spki = VectorSpki();
  const InstallationId installation_id{0x04, 0x00, 0xbe, 0x80, 0xf1, 0xda, 0x22, 0xaa,
                                         0xaa, 0xc4, 0xc4, 0x38, 0x05, 0x4b, 0xf1, 0xa8};
  InstallationHashInput installation_input{};
  assert(BuildInstallationHashInput(spki, &installation_input));
  assert(std::equal(keyferry::protocol::kRoamingInstallationIdDomain.begin(),
                    keyferry::protocol::kRoamingInstallationIdDomain.end(),
                    installation_input.begin()));
  assert(std::equal(spki.begin(), spki.end(),
                    installation_input.end() - static_cast<std::ptrdiff_t>(spki.size())));

  LinkSaltInput salt_input{};
  assert(BuildLinkSaltInput(Sequence<16>(0x10), Sequence<16>(0x20), 1, &salt_input));
  assert(salt_input[salt_input.size() - 1] == 1);
  assert(std::all_of(salt_input.end() - 8, salt_input.end() - 1,
                     [](const std::uint8_t byte) { return byte == 0; }));

  DeviceLinkInfo link_info{};
  assert(BuildDeviceLinkInfo(installation_id, spki, &link_info));
  assert(std::equal(installation_id.begin(), installation_id.end(),
                    link_info.begin() + keyferry::protocol::kRoamingDeviceLinkDomain.size()));

  RouteProofKeyInfo route_info{};
  assert(BuildRouteProofKeyInfo(installation_id, &route_info));
  assert(std::equal(installation_id.begin(), installation_id.end(),
                    route_info.end() - static_cast<std::ptrdiff_t>(installation_id.size())));
}

void TestRouteProofBody() {
  using namespace keyferry::roaming;
  RouteProofFields fields{};
  fields.owner_id = Sequence<16>(0x10);
  fields.device_id = Sequence<16>(0x20);
  fields.epoch = 1;
  fields.policy_sequence = 7;
  fields.policy_hash = Sequence<32>(0x80);
  fields.gateway_installation_id = Sequence<16>(0x70);
  fields.controller_installation_id =
      {0x04, 0x00, 0xbe, 0x80, 0xf1, 0xda, 0x22, 0xaa,
       0xaa, 0xc4, 0xc4, 0x38, 0x05, 0x4b, 0xf1, 0xa8};
  fields.controller_nonce = Sequence<32>(0xa0);
  fields.device_boot_nonce = Sequence<16>(0xc0);
  fields.endpoint_session_id = Sequence<16>(0xd0);
  fields.link_path = 2;
  fields.usb_ready = true;
  RouteProofBody body{};
  assert(BuildRouteProofBody(fields, &body));
  assert(body.size() == keyferry::protocol::kRoamingRouteProofBodyBytes);
  assert(body[body.size() - 2] == 2);
  assert(body[body.size() - 1] == 1);

  RouteProofFieldsBytes encoded_fields{};
  assert(BuildRouteProofFields(fields, &encoded_fields));
  assert(std::equal(encoded_fields.begin(), encoded_fields.end(),
                    body.begin() + static_cast<std::ptrdiff_t>(
                                       keyferry::protocol::kRoamingRouteProofDomain.size())));
  const RouteProofTag tag = Sequence<32>(0xe0);
  RouteProofResponse response{};
  assert(BuildRouteProofResponse(fields, tag, &response));
  assert(std::equal(encoded_fields.begin(), encoded_fields.end(), response.begin()));
  assert(std::equal(tag.begin(), tag.end(),
                    response.end() - static_cast<std::ptrdiff_t>(tag.size())));

  fields.epoch = 0;
  assert(!BuildRouteProofBody(fields, &body));
  assert(!BuildRouteProofBody(fields, nullptr));
  fields.epoch = 1;
  fields.link_path = 0;
  assert(!BuildRouteProofFields(fields, &encoded_fields));
}

void TestSyntheticNamesMatchTheOwnerCredentialProfile() {
  using namespace keyferry::roaming;
  const auto device_id = Sequence<16>(0x20);
  DeviceGatewayName device_name{};
  assert(BuildDeviceGatewayName(device_id, &device_name));
  assert(std::string_view(device_name.data()) ==
         "d-202122232425262728292a2b2c2d2e2f.gateway.keyferry.invalid");

  const auto installation_id = Sequence<16>(0x70);
  InstallationGatewayName installation_name{};
  assert(BuildInstallationGatewayName(installation_id, &installation_name));
  assert(std::string_view(installation_name.data()) ==
         "i-707172737475767778797a7b7c7d7e7f.desktop.keyferry.invalid");
  DeviceId zero{};
  assert(!BuildDeviceGatewayName(zero, &device_name));
}

}  // namespace

int main() {
  static_assert(keyferry::protocol::kRoamingVersion == 2);
  static_assert(keyferry::roaming::kInstallationHashInputBytes == 118);
  static_assert(keyferry::roaming::kLinkSaltInputBytes == 61);
  static_assert(keyferry::roaming::kDeviceLinkInfoBytes == 130);
  static_assert(keyferry::roaming::kRouteProofKeyInfoBytes == 43);
  static_assert(keyferry::protocol::kRoamingRouteProofBodyBytes == 201);
  static_assert(keyferry::protocol::kRoamingRouteProofFieldsBytes == 178);
  static_assert(keyferry::protocol::kRoamingRouteProofResponseBytes == 210);
  TestDerivationInputs();
  TestRouteProofBody();
  TestSyntheticNamesMatchTheOwnerCredentialProfile();
  std::puts("roaming_profile_test: ok");
  return 0;
}
