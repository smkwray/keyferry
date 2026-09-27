#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry_protocol_generated.h"

namespace keyferry::discovery {

constexpr std::uint16_t kBeaconPort = protocol::kDiscoveryPort;
constexpr std::size_t kBeaconSize = protocol::kDiscoveryBeaconSize;
constexpr std::size_t kMaxPairedHosts = 8;

using Ipv4Address = std::array<std::uint8_t, 4>;
using HostId = std::array<std::uint8_t, 16>;
using EncodedBeacon = std::array<std::uint8_t, kBeaconSize>;

struct InterfaceView {
  Ipv4Address address;
  Ipv4Address netmask;
};

struct BeaconSocketPlan {
  Ipv4Address bind_address;
  Ipv4Address destination_address;
  std::uint16_t port;
};

struct PairedHostView {
  HostId host_id;
  Ipv4Address manual_address;
  std::uint16_t tls_port;
};

enum class AddressSource : std::uint8_t {
  kManual = 1,
  kBeacon = 2,
};

struct HostSelection {
  HostId host_id;
  Ipv4Address address;
  std::uint16_t tls_port;
  AddressSource source;
};

// Produces a fixed-size metadata-only announcement. Host IDs are identifiers,
// not authenticators; TLS pinning remains the authority for the selected peer.
bool EncodeBeacon(const HostId& host_id, EncodedBeacon* output);

// Derives an explicit-interface bind and directed-broadcast destination. A
// wildcard bind, multicast address, loopback address, /0, or /32 is rejected.
bool BuildBeaconSocketPlan(const InterfaceView& interface, BeaconSocketPlan* output);

// Accepts only a fixed-size beacon from the selected interface's subnet and a
// configured host ID. The source IP is only an address hint; the paired host's
// configured TLS port and pin are not supplied or changed by the beacon.
bool SelectDiscoveredHost(const std::uint8_t* packet, std::size_t packet_length,
                          const Ipv4Address& source_address,
                          const InterfaceView& interface,
                          const PairedHostView* paired_hosts,
                          std::size_t paired_host_count,
                          HostSelection* output);

// Roaming beacons are untrusted address hints. Their installation identity is
// accepted provisionally and must match the owner-CA-authenticated TLS peer
// before the candidate can be promoted.
bool SelectRoamingCandidate(const std::uint8_t* packet,
                            std::size_t packet_length,
                            const Ipv4Address& source_address,
                            const InterfaceView& interface,
                            std::uint16_t fixed_tls_port,
                            HostSelection* output);

// Manual addressing remains available when discovery is disabled, times out,
// or yields no accepted known-host beacon.
bool SelectManualHost(const PairedHostView& paired_host, HostSelection* output);

}  // namespace keyferry::discovery
