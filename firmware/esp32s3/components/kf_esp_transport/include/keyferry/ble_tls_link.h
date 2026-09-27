#pragma once

#include <cstddef>
#include <cstdint>

#include "keyferry/idf_ble_transport.h"
#include "keyferry/transport_runtime_config.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

namespace keyferry::transport {

enum class BleTlsHandshake : std::uint8_t {
  kWantIo,
  kComplete,
  kFailed,
};

// Non-blocking TLS 1.2 client over the bounded GATT byte pipe. It owns no
// endpoint session or command state.
class BleTlsLink final {
 public:
  BleTlsLink(const RuntimeConfig& config, ble::IdfBlePeripheral& peripheral);
  ~BleTlsLink();

  BleTlsLink(const BleTlsLink&) = delete;
  BleTlsLink& operator=(const BleTlsLink&) = delete;

  bool Start(std::uint32_t generation, std::uint64_t now_ms);
  BleTlsHandshake HandshakeStep(std::uint64_t now_ms,
                                endpoint::TlsObservation* observation,
                                config::RoamingPeerAuthorization* authorization);
  int Read(std::uint8_t* output, std::size_t capacity);
  int Write(const std::uint8_t* data, std::size_t length);
  bool PollHealthy(std::uint64_t now_ms, bool authentication_complete = false);
  void Close();

  [[nodiscard]] bool established() const { return established_; }
  [[nodiscard]] std::uint32_t generation() const { return generation_; }

 private:
  static int BioSend(void* context, const unsigned char* data,
                     std::size_t length);
  static int BioReceive(void* context, unsigned char* output,
                        std::size_t capacity);
  void ResetContexts();
  bool DeadlineExpired(std::uint64_t now_ms) const;

  RuntimeConfig config_;
  ble::IdfBlePeripheral& peripheral_;
  mbedtls_ssl_context ssl_{};
  mbedtls_ssl_config ssl_config_{};
  mbedtls_x509_crt ca_certificate_{};
  std::uint32_t generation_{0};
  std::uint64_t started_ms_{0};
  std::uint64_t last_progress_ms_{0};
  bool contexts_initialized_{false};
  bool configured_{false};
  bool established_{false};
};

}  // namespace keyferry::transport
