#include "keyferry/discovery.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>

namespace {

using keyferry::discovery::AddressSource;
using keyferry::discovery::EncodedBeacon;
using keyferry::discovery::HostId;
using keyferry::discovery::HostSelection;
using keyferry::discovery::InterfaceView;
using keyferry::discovery::Ipv4Address;
using keyferry::discovery::PairedHostView;

HostId KnownHostId() {
  HostId id{};
  for (std::size_t index = 0; index < id.size(); ++index) {
    id[index] = static_cast<std::uint8_t>(index + 1);
  }
  return id;
}

InterfaceView SelectedInterface() {
  return {{192, 0, 2, 10}, {255, 255, 255, 0}};
}

PairedHostView KnownHost() {
  return {KnownHostId(), {192, 0, 2, 20}, 7443};
}

void TestFixedMetadataOnlyBeacon() {
  EncodedBeacon beacon{};
  assert(keyferry::discovery::EncodeBeacon(KnownHostId(), &beacon));
  assert(beacon.size() == 22);
  assert((std::array<std::uint8_t, 6>{beacon[0], beacon[1], beacon[2], beacon[3], beacon[4],
                                      beacon[5]} ==
          std::array<std::uint8_t, 6>{'K', 'F', 'H', 'B', 1, 0}));
  for (std::size_t index = 0; index < KnownHostId().size(); ++index) {
    assert(beacon[index + 6] == KnownHostId()[index]);
  }

  HostId empty{};
  const EncodedBeacon sentinel = beacon;
  assert(!keyferry::discovery::EncodeBeacon(empty, &beacon));
  assert(beacon == sentinel);
  assert(!keyferry::discovery::EncodeBeacon(KnownHostId(), nullptr));
}

void TestExplicitInterfaceSocketPlan() {
  keyferry::discovery::BeaconSocketPlan plan{};
  assert(keyferry::discovery::BuildBeaconSocketPlan(SelectedInterface(), &plan));
  assert((plan.bind_address == Ipv4Address{192, 0, 2, 10}));
  assert((plan.destination_address == Ipv4Address{192, 0, 2, 255}));
  assert(plan.port == keyferry::discovery::kBeaconPort);
  assert(plan.bind_address != Ipv4Address{});

  assert(!keyferry::discovery::BuildBeaconSocketPlan({{}, {255, 255, 255, 0}}, &plan));
  assert(!keyferry::discovery::BuildBeaconSocketPlan(
      {{127, 0, 0, 1}, {255, 0, 0, 0}}, &plan));
  assert(!keyferry::discovery::BuildBeaconSocketPlan(
      {{192, 0, 2, 10}, {0, 0, 0, 0}}, &plan));
  assert(!keyferry::discovery::BuildBeaconSocketPlan(
      {{192, 0, 2, 10}, {255, 255, 255, 255}}, &plan));
  assert(!keyferry::discovery::BuildBeaconSocketPlan(
      {{192, 0, 2, 10}, {255, 0, 255, 0}}, &plan));
}

void TestKnownHostFilterAndConfiguredTlsPort() {
  EncodedBeacon beacon{};
  const auto host = KnownHost();
  assert(keyferry::discovery::EncodeBeacon(host.host_id, &beacon));

  HostSelection selection{};
  assert(keyferry::discovery::SelectDiscoveredHost(
      beacon.data(), beacon.size(), {192, 0, 2, 44}, SelectedInterface(), &host, 1,
      &selection));
  assert(selection.host_id == host.host_id);
  assert((selection.address == Ipv4Address{192, 0, 2, 44}));
  assert(selection.tls_port == 7443);
  assert(selection.source == AddressSource::kBeacon);

  auto unknown_id = KnownHostId();
  unknown_id[0] ^= 0xff;
  assert(keyferry::discovery::EncodeBeacon(unknown_id, &beacon));
  const HostSelection sentinel = selection;
  assert(!keyferry::discovery::SelectDiscoveredHost(
      beacon.data(), beacon.size(), {192, 0, 2, 44}, SelectedInterface(), &host, 1,
      &selection));
  assert(selection.host_id == sentinel.host_id && selection.address == sentinel.address &&
         selection.tls_port == sentinel.tls_port && selection.source == sentinel.source);

  std::array<PairedHostView, 2> duplicate{host, host};
  assert(keyferry::discovery::EncodeBeacon(host.host_id, &beacon));
  assert(!keyferry::discovery::SelectDiscoveredHost(
      beacon.data(), beacon.size(), {192, 0, 2, 44}, SelectedInterface(), duplicate.data(),
      duplicate.size(), &selection));
}

void TestMalformedAndOffInterfaceBeaconsFailClosed() {
  EncodedBeacon beacon{};
  const auto host = KnownHost();
  assert(keyferry::discovery::EncodeBeacon(host.host_id, &beacon));
  HostSelection selection{};

  for (std::size_t length = 0; length < beacon.size(); ++length) {
    assert(!keyferry::discovery::SelectDiscoveredHost(
        beacon.data(), length, {192, 0, 2, 44}, SelectedInterface(), &host, 1, &selection));
  }
  std::array<std::uint8_t, keyferry::discovery::kBeaconSize + 1> trailing{};
  std::copy(beacon.begin(), beacon.end(), trailing.begin());
  assert(!keyferry::discovery::SelectDiscoveredHost(
      trailing.data(), trailing.size(), {192, 0, 2, 44}, SelectedInterface(), &host, 1,
      &selection));
  assert(!keyferry::discovery::SelectDiscoveredHost(
      beacon.data(), beacon.size(), {198, 51, 100, 44}, SelectedInterface(), &host, 1,
      &selection));
  assert(!keyferry::discovery::SelectDiscoveredHost(
      beacon.data(), beacon.size(), {224, 0, 0, 1}, SelectedInterface(), &host, 1,
      &selection));
  assert(!keyferry::discovery::SelectDiscoveredHost(
      beacon.data(), beacon.size(), SelectedInterface().address, SelectedInterface(), &host, 1,
      &selection));

  std::array<PairedHostView, keyferry::discovery::kMaxPairedHosts + 1> too_many{};
  too_many.fill(host);
  assert(!keyferry::discovery::SelectDiscoveredHost(
      beacon.data(), beacon.size(), {192, 0, 2, 44}, SelectedInterface(), too_many.data(),
      too_many.size(), &selection));
}

void TestManualAddressFallback() {
  const auto host = KnownHost();
  HostSelection selection{};
  assert(keyferry::discovery::SelectManualHost(host, &selection));
  assert(selection.host_id == host.host_id);
  assert(selection.address == host.manual_address);
  assert(selection.tls_port == host.tls_port);
  assert(selection.source == AddressSource::kManual);

  auto invalid = host;
  invalid.manual_address = {};
  assert(!keyferry::discovery::SelectManualHost(invalid, &selection));
  invalid = host;
  invalid.tls_port = 0;
  assert(!keyferry::discovery::SelectManualHost(invalid, &selection));
}

void TestRoamingCandidateIsOnlyAnUntrustedSameSubnetHint() {
  const auto installation_id = KnownHostId();
  EncodedBeacon beacon{};
  assert(keyferry::discovery::EncodeBeacon(installation_id, &beacon));
  HostSelection selected{};
  assert(keyferry::discovery::SelectRoamingCandidate(
      beacon.data(), beacon.size(), {192, 0, 2, 88}, SelectedInterface(),
      7443, &selected));
  assert(selected.host_id == installation_id);
  assert((selected.address == Ipv4Address{192, 0, 2, 88}));
  assert(selected.tls_port == 7443);
  assert(!keyferry::discovery::SelectRoamingCandidate(
      beacon.data(), beacon.size(), {198, 51, 100, 88},
      SelectedInterface(), 7443, &selected));
  assert(!keyferry::discovery::SelectRoamingCandidate(
      beacon.data(), beacon.size(), {192, 0, 2, 88}, SelectedInterface(), 0,
      &selected));
}

}  // namespace

int main() {
  TestFixedMetadataOnlyBeacon();
  TestExplicitInterfaceSocketPlan();
  TestKnownHostFilterAndConfiguredTlsPort();
  TestMalformedAndOffInterfaceBeaconsFailClosed();
  TestManualAddressFallback();
  TestRoamingCandidateIsOnlyAnUntrustedSameSubnetHint();
  std::puts("discovery_test: ok");
  return 0;
}
