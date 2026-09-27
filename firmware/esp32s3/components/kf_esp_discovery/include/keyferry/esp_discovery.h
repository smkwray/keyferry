#pragma once

#include <cstddef>
#include <cstdint>

#include "esp_netif.h"
#include "keyferry/discovery.h"

namespace keyferry::discovery {

// Waits for a known-host beacon on the exact station IPv4 address. Malformed,
// oversized, unknown-host, and off-subnet datagrams are ignored until the
// bounded deadline. The caller retains an independently configured manual
// address for fallback and all TLS/HMAC authority.
bool ReceiveKnownHostBeacon(esp_netif_t* station,
                            const PairedHostView* paired_hosts,
                            std::size_t paired_host_count,
                            std::uint32_t timeout_ms,
                            HostSelection* output);

// Returns one untrusted same-subnet roaming address/installation hint. The
// caller must match the advertised installation ID to the owner-authenticated
// TLS peer before promoting the candidate.
bool ReceiveRoamingBeacon(esp_netif_t* station, std::uint16_t fixed_tls_port,
                          std::uint32_t timeout_ms, HostSelection* output);

}  // namespace keyferry::discovery
