#include "keyferry/esp_discovery.h"

#include <algorithm>
#include <array>
#include <cerrno>

#include "esp_timer.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "unistd.h"

namespace keyferry::discovery {
namespace {

Ipv4Address ToAddress(const esp_ip4_addr_t& address) {
  return {esp_ip4_addr1(&address), esp_ip4_addr2(&address),
          esp_ip4_addr3(&address), esp_ip4_addr4(&address)};
}

Ipv4Address ToAddress(const in_addr& address) {
  const std::uint32_t host = ntohl(address.s_addr);
  return {static_cast<std::uint8_t>(host >> 24U),
          static_cast<std::uint8_t>(host >> 16U),
          static_cast<std::uint8_t>(host >> 8U),
          static_cast<std::uint8_t>(host)};
}

class Socket final {
 public:
  explicit Socket(int descriptor) : descriptor_(descriptor) {}
  ~Socket() {
    if (descriptor_ >= 0) {
      close(descriptor_);
    }
  }
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  int get() const { return descriptor_; }

 private:
  int descriptor_;
};

bool SetReceiveTimeout(int socket, std::int64_t remaining_us) {
  const std::int64_t bounded = std::max<std::int64_t>(1, remaining_us);
  timeval timeout{};
  timeout.tv_sec = static_cast<time_t>(bounded / 1000000LL);
  timeout.tv_usec = static_cast<suseconds_t>(bounded % 1000000LL);
  return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0;
}

bool ReceiveBeacon(esp_netif_t* station,
                   const PairedHostView* paired_hosts,
                   const std::size_t paired_host_count,
                   const std::uint16_t roaming_tls_port,
                   const std::uint32_t timeout_ms, HostSelection* output) {
  const bool roaming = roaming_tls_port != 0;
  if (station == nullptr || timeout_ms == 0 || output == nullptr ||
      (!roaming &&
       (paired_hosts == nullptr || paired_host_count == 0 ||
        paired_host_count > kMaxPairedHosts))) {
    return false;
  }
  *output = {};
  esp_netif_ip_info_t info{};
  if (esp_netif_get_ip_info(station, &info) != ESP_OK) {
    return false;
  }
  const InterfaceView interface{ToAddress(info.ip), ToAddress(info.netmask)};
  BeaconSocketPlan plan{};
  if (!BuildBeaconSocketPlan(interface, &plan)) {
    return false;
  }

  Socket socket(::socket(AF_INET, SOCK_DGRAM, IPPROTO_IP));
  if (socket.get() < 0) {
    return false;
  }
  sockaddr_in local{};
  local.sin_family = AF_INET;
  local.sin_port = htons(kBeaconPort);
  local.sin_addr.s_addr = info.ip.addr;
  if (bind(socket.get(), reinterpret_cast<const sockaddr*>(&local),
           sizeof(local)) != 0) {
    return false;
  }

  const std::int64_t deadline =
      esp_timer_get_time() + static_cast<std::int64_t>(timeout_ms) * 1000LL;
  while (true) {
    const std::int64_t remaining = deadline - esp_timer_get_time();
    if (remaining <= 0 || !SetReceiveTimeout(socket.get(), remaining)) {
      return false;
    }
    std::array<std::uint8_t, kBeaconSize + 1> packet{};
    sockaddr_in source{};
    socklen_t source_size = sizeof(source);
    const ssize_t received = recvfrom(
        socket.get(), packet.data(), packet.size(), 0,
        reinterpret_cast<sockaddr*>(&source), &source_size);
    if (received < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (source_size != sizeof(source) || source.sin_family != AF_INET) {
      continue;
    }
    const auto source_address = ToAddress(source.sin_addr);
    const bool selected =
        roaming ? SelectRoamingCandidate(
                      packet.data(), static_cast<std::size_t>(received),
                      source_address, interface, roaming_tls_port, output)
                : SelectDiscoveredHost(
                      packet.data(), static_cast<std::size_t>(received),
                      source_address, interface, paired_hosts,
                      paired_host_count, output);
    if (selected) {
      return true;
    }
  }
}

}  // namespace

bool ReceiveKnownHostBeacon(esp_netif_t* station,
                            const PairedHostView* paired_hosts,
                            std::size_t paired_host_count,
                            std::uint32_t timeout_ms,
                            HostSelection* output) {
  return ReceiveBeacon(station, paired_hosts, paired_host_count, 0, timeout_ms,
                       output);
}

bool ReceiveRoamingBeacon(esp_netif_t* station,
                          const std::uint16_t fixed_tls_port,
                          const std::uint32_t timeout_ms,
                          HostSelection* output) {
  return ReceiveBeacon(station, nullptr, 0, fixed_tls_port, timeout_ms,
                       output);
}

}  // namespace keyferry::discovery
