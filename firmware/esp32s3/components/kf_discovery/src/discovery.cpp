#include "keyferry/discovery.h"

#include <algorithm>

namespace keyferry::discovery {
namespace {

constexpr std::uint8_t kReserved = 0;
constexpr std::size_t kHostIdOffset = 6;

bool AnyNonzero(const std::uint8_t* data, std::size_t length) {
  std::uint8_t combined = 0;
  for (std::size_t index = 0; index < length; ++index) {
    combined |= data[index];
  }
  return combined != 0;
}

std::uint32_t ToUint32(const Ipv4Address& address) {
  return (static_cast<std::uint32_t>(address[0]) << 24U) |
         (static_cast<std::uint32_t>(address[1]) << 16U) |
         (static_cast<std::uint32_t>(address[2]) << 8U) |
         static_cast<std::uint32_t>(address[3]);
}

Ipv4Address FromUint32(std::uint32_t address) {
  return {static_cast<std::uint8_t>(address >> 24U),
          static_cast<std::uint8_t>(address >> 16U),
          static_cast<std::uint8_t>(address >> 8U),
          static_cast<std::uint8_t>(address)};
}

bool IsUnicast(const Ipv4Address& address) {
  return address[0] != 0 && address[0] != 127 && address[0] < 224 &&
         address != Ipv4Address{255, 255, 255, 255};
}

bool IsContiguousSubnetMask(std::uint32_t mask) {
  if (mask == 0 || mask == UINT32_MAX) {
    return false;
  }
  const std::uint32_t inverted = ~mask;
  return (inverted & (inverted + 1U)) == 0;
}

bool ValidateInterface(const InterfaceView& interface) {
  const std::uint32_t address = ToUint32(interface.address);
  const std::uint32_t mask = ToUint32(interface.netmask);
  if (!IsUnicast(interface.address) || !IsContiguousSubnetMask(mask)) {
    return false;
  }
  const std::uint32_t network = address & mask;
  const std::uint32_t broadcast = network | ~mask;
  return address != network && address != broadcast;
}

bool SameSubnet(const Ipv4Address& left, const Ipv4Address& right,
                const Ipv4Address& netmask) {
  const std::uint32_t mask = ToUint32(netmask);
  return (ToUint32(left) & mask) == (ToUint32(right) & mask);
}

bool DecodeBeacon(const std::uint8_t* packet, std::size_t packet_length,
                  HostId* host_id) {
  if (packet == nullptr || host_id == nullptr || packet_length != kBeaconSize ||
      !std::equal(protocol::kDiscoveryMagic.begin(), protocol::kDiscoveryMagic.end(), packet) ||
      packet[4] != protocol::kDiscoveryVersion ||
      packet[5] != kReserved) {
    return false;
  }
  std::copy_n(packet + kHostIdOffset, host_id->size(), host_id->begin());
  return AnyNonzero(host_id->data(), host_id->size());
}

bool ValidatePairedHost(const PairedHostView& host) {
  return AnyNonzero(host.host_id.data(), host.host_id.size()) &&
         IsUnicast(host.manual_address) && host.tls_port != 0;
}

}  // namespace

bool EncodeBeacon(const HostId& host_id, EncodedBeacon* output) {
  if (output == nullptr || !AnyNonzero(host_id.data(), host_id.size())) {
    return false;
  }
  EncodedBeacon encoded{};
  std::copy(protocol::kDiscoveryMagic.begin(), protocol::kDiscoveryMagic.end(), encoded.begin());
  encoded[4] = protocol::kDiscoveryVersion;
  encoded[5] = kReserved;
  std::copy(host_id.begin(), host_id.end(), encoded.begin() + kHostIdOffset);
  *output = encoded;
  return true;
}

bool BuildBeaconSocketPlan(const InterfaceView& interface, BeaconSocketPlan* output) {
  if (output == nullptr || !ValidateInterface(interface)) {
    return false;
  }
  const std::uint32_t address = ToUint32(interface.address);
  const std::uint32_t mask = ToUint32(interface.netmask);
  *output = BeaconSocketPlan{interface.address, FromUint32((address & mask) | ~mask),
                             kBeaconPort};
  return true;
}

bool SelectDiscoveredHost(const std::uint8_t* packet, std::size_t packet_length,
                          const Ipv4Address& source_address,
                          const InterfaceView& interface,
                          const PairedHostView* paired_hosts,
                          std::size_t paired_host_count,
                          HostSelection* output) {
  if (output == nullptr || paired_hosts == nullptr || paired_host_count == 0 ||
      paired_host_count > kMaxPairedHosts || !ValidateInterface(interface) ||
      !IsUnicast(source_address) || source_address == interface.address ||
      !SameSubnet(source_address, interface.address, interface.netmask)) {
    return false;
  }
  HostId advertised_host{};
  if (!DecodeBeacon(packet, packet_length, &advertised_host)) {
    return false;
  }
  const PairedHostView* match = nullptr;
  for (std::size_t index = 0; index < paired_host_count; ++index) {
    if (paired_hosts[index].host_id != advertised_host) {
      continue;
    }
    if (match != nullptr || !ValidatePairedHost(paired_hosts[index])) {
      return false;
    }
    match = &paired_hosts[index];
  }
  if (match == nullptr) {
    return false;
  }
  *output = HostSelection{match->host_id, source_address, match->tls_port,
                          AddressSource::kBeacon};
  return true;
}

bool SelectRoamingCandidate(const std::uint8_t* packet,
                            const std::size_t packet_length,
                            const Ipv4Address& source_address,
                            const InterfaceView& interface,
                            const std::uint16_t fixed_tls_port,
                            HostSelection* output) {
  if (output == nullptr || fixed_tls_port == 0 ||
      !ValidateInterface(interface) || !IsUnicast(source_address) ||
      source_address == interface.address ||
      !SameSubnet(source_address, interface.address, interface.netmask)) {
    return false;
  }
  HostId advertised_installation{};
  if (!DecodeBeacon(packet, packet_length, &advertised_installation)) {
    return false;
  }
  *output = {advertised_installation, source_address, fixed_tls_port,
             AddressSource::kBeacon};
  return true;
}

bool SelectManualHost(const PairedHostView& paired_host, HostSelection* output) {
  if (output == nullptr || !ValidatePairedHost(paired_host)) {
    return false;
  }
  *output = HostSelection{paired_host.host_id, paired_host.manual_address,
                          paired_host.tls_port, AddressSource::kManual};
  return true;
}

}  // namespace keyferry::discovery
