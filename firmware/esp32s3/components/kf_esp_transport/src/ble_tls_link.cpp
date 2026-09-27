#include "keyferry/ble_tls_link.h"

#include <algorithm>
#include <array>

#include "esp_timer.h"
#include "keyferry/mbedtls_peer_policy.h"
#include "psa/crypto.h"

namespace keyferry::transport {
namespace {

constexpr std::array<int, 2> kCipherSuites{
    static_cast<int>(endpoint::kRequiredCipherSuite), 0};

std::uint64_t NowMs() {
  return static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
}

bool Reached(std::uint64_t now_ms, std::uint64_t start_ms,
             std::size_t timeout_ms) {
  return now_ms >= start_ms && now_ms - start_ms >= timeout_ms;
}

}  // namespace

BleTlsLink::BleTlsLink(const RuntimeConfig& config,
                       ble::IdfBlePeripheral& peripheral)
    : config_(config),
      peripheral_(peripheral) {
  mbedtls_ssl_init(&ssl_);
  mbedtls_ssl_config_init(&ssl_config_);
  mbedtls_x509_crt_init(&ca_certificate_);
  contexts_initialized_ = true;
}

BleTlsLink::~BleTlsLink() { ResetContexts(); }

bool BleTlsLink::Start(std::uint32_t generation, std::uint64_t now_ms) {
  ResetContexts();
  mbedtls_ssl_init(&ssl_);
  mbedtls_ssl_config_init(&ssl_config_);
  mbedtls_x509_crt_init(&ca_certificate_);
  contexts_initialized_ = true;
  if (generation == 0 || !ValidateRuntimeConfig(config_) ||
      psa_crypto_init() != PSA_SUCCESS ||
      !peripheral_.ready(generation) ||
      mbedtls_x509_crt_parse_der(&ca_certificate_,
                                 config_.ca_certificate_der,
                                 config_.ca_certificate_der_length) != 0 ||
      mbedtls_ssl_config_defaults(&ssl_config_, MBEDTLS_SSL_IS_CLIENT,
                                  MBEDTLS_SSL_TRANSPORT_STREAM,
                                  MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    ResetContexts();
    return false;
  }

  mbedtls_ssl_conf_authmode(&ssl_config_, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&ssl_config_, &ca_certificate_, nullptr);
  mbedtls_ssl_conf_min_tls_version(&ssl_config_,
                                   MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_max_tls_version(&ssl_config_,
                                   MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_ciphersuites(&ssl_config_, kCipherSuites.data());
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
  mbedtls_ssl_conf_session_tickets(&ssl_config_,
                                   MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#endif
  if (mbedtls_ssl_conf_max_frag_len(&ssl_config_,
                                    MBEDTLS_SSL_MAX_FRAG_LEN_512) != 0 ||
      mbedtls_ssl_setup(&ssl_, &ssl_config_) != 0 ||
      mbedtls_ssl_set_hostname(&ssl_, config_.tls.server_name) != 0) {
    ResetContexts();
    return false;
  }

  generation_ = generation;
  started_ms_ = now_ms;
  last_progress_ms_ = now_ms;
  configured_ = true;
  established_ = false;
  mbedtls_ssl_set_bio(&ssl_, this, BioSend, BioReceive, nullptr);
  return true;
}

BleTlsHandshake BleTlsLink::HandshakeStep(
    std::uint64_t now_ms, endpoint::TlsObservation* observation,
    config::RoamingPeerAuthorization* authorization) {
  if (authorization != nullptr) {
    *authorization = {};
  }
  if (!configured_ || established_ || observation == nullptr ||
      authorization == nullptr ||
      !PollHealthy(now_ms) || DeadlineExpired(now_ms)) {
    return BleTlsHandshake::kFailed;
  }
  const int result = mbedtls_ssl_handshake(&ssl_);
  if (result == MBEDTLS_ERR_SSL_WANT_READ ||
      result == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return BleTlsHandshake::kWantIo;
  }
  const bool peer_valid =
      result == 0 &&
      (config_.authority_mode == AuthorityMode::kPinnedPeer
           ? VerifyMbedTlsPeer(&ssl_, config_.tls, observation)
           : config_.roaming_policy != nullptr &&
                 config_.roaming_recovery_secret != nullptr &&
                 config_.roaming_crypto != nullptr &&
                 config_.roaming_verification_workspace != nullptr &&
                 VerifyMbedTlsRoamingPeer(
                     &ssl_, *config_.roaming_policy,
                     *config_.roaming_recovery_secret,
                     *config_.roaming_crypto, observation, authorization,
                     config_.roaming_verification_workspace));
  if (!peer_valid) {
    return BleTlsHandshake::kFailed;
  }
  established_ = true;
  return BleTlsHandshake::kComplete;
}

int BleTlsLink::Read(std::uint8_t* output, std::size_t capacity) {
  if (!established_ || output == nullptr || capacity == 0) {
    return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
  }
  return mbedtls_ssl_read(&ssl_, output, capacity);
}

int BleTlsLink::Write(const std::uint8_t* data, std::size_t length) {
  if (!established_ || data == nullptr || length == 0) {
    return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
  }
  return mbedtls_ssl_write(&ssl_, data, length);
}

bool BleTlsLink::PollHealthy(std::uint64_t now_ms,
                            bool authentication_complete) {
  return configured_ && peripheral_.ready(generation_) &&
         (authentication_complete || !DeadlineExpired(now_ms));
}

void BleTlsLink::Close() {
  if (configured_) {
    peripheral_.Disconnect();
  }
  ResetContexts();
}

int BleTlsLink::BioSend(void* context, const unsigned char* data,
                        std::size_t length) {
  auto* self = static_cast<BleTlsLink*>(context);
  if (self == nullptr || data == nullptr || length == 0 ||
      !self->peripheral_.ready(self->generation_)) {
    return MBEDTLS_ERR_SSL_CONN_EOF;
  }
  if (!self->peripheral_.can_send(self->generation_)) {
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  }
  const auto size = std::min(
      length, self->peripheral_.fragment_capacity(self->generation_));
  const auto now_ms = NowMs();
  if (size == 0 ||
      !self->peripheral_.Send(self->generation_, data, size, now_ms)) {
    return MBEDTLS_ERR_SSL_CONN_EOF;
  }
  self->last_progress_ms_ = now_ms;
  return static_cast<int>(size);
}

int BleTlsLink::BioReceive(void* context, unsigned char* output,
                           std::size_t capacity) {
  auto* self = static_cast<BleTlsLink*>(context);
  if (self == nullptr || output == nullptr || capacity == 0 ||
      !self->peripheral_.ready(self->generation_)) {
    return MBEDTLS_ERR_SSL_CONN_EOF;
  }
  const auto size = self->peripheral_.Read(output, capacity);
  if (size == 0) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  self->last_progress_ms_ = NowMs();
  return static_cast<int>(size);
}

void BleTlsLink::ResetContexts() {
  if (contexts_initialized_) {
    mbedtls_ssl_free(&ssl_);
    mbedtls_ssl_config_free(&ssl_config_);
    mbedtls_x509_crt_free(&ca_certificate_);
    contexts_initialized_ = false;
  }
  generation_ = 0;
  started_ms_ = 0;
  last_progress_ms_ = 0;
  configured_ = false;
  established_ = false;
}

bool BleTlsLink::DeadlineExpired(std::uint64_t now_ms) const {
  return Reached(now_ms, started_ms_, protocol::kBleAuthenticationTimeoutMs) ||
         Reached(now_ms, last_progress_ms_, protocol::kBleProgressTimeoutMs);
}

}  // namespace keyferry::transport
