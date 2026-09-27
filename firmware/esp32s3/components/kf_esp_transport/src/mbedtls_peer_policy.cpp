#include "keyferry/mbedtls_peer_policy.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "mbedtls/md.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
#error "Keyferry SPKI pinning requires MBEDTLS_SSL_KEEP_PEER_CERTIFICATE"
#endif

namespace keyferry::transport {
namespace {

constexpr std::array<std::uint8_t, 26> kP256SpkiPrefix{
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};

bool ConstantTimeEqual(const std::uint8_t* left, const std::uint8_t* right,
                       std::size_t length) {
  std::uint8_t difference = 0;
  for (std::size_t index = 0; index < length; ++index) {
    difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
  }
  return difference == 0;
}

bool IsP256Spki(const mbedtls_x509_crt& certificate) {
  return certificate.pk_raw.p != nullptr && certificate.pk_raw.len == 91 &&
         std::equal(kP256SpkiPrefix.begin(), kP256SpkiPrefix.end(),
                    certificate.pk_raw.p);
}

}  // namespace

bool VerifyMbedTlsPeer(mbedtls_ssl_context* ssl,
                       const endpoint::TlsClientPolicy& policy,
                       endpoint::TlsObservation* observation) {
  if (ssl == nullptr || observation == nullptr ||
      mbedtls_ssl_get_version_number(ssl) != MBEDTLS_SSL_VERSION_TLS1_2 ||
      mbedtls_ssl_get_ciphersuite_id_from_ssl(ssl) !=
          endpoint::kRequiredCipherSuite ||
      mbedtls_ssl_get_verify_result(ssl) != 0) {
    return false;
  }

  const mbedtls_x509_crt* peer = mbedtls_ssl_get_peer_cert(ssl);
  if (peer == nullptr || !IsP256Spki(*peer)) {
    return false;
  }

  observation->version = endpoint::kTls12Version;
  observation->cipher_suite = endpoint::kRequiredCipherSuite;
  observation->peer_key_algorithm = endpoint::PeerKeyAlgorithm::kEcdsaP256;
  const mbedtls_md_info_t* sha256 =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return sha256 != nullptr &&
         mbedtls_md(sha256, peer->pk_raw.p, peer->pk_raw.len,
                    observation->peer_spki_sha256.data()) == 0 &&
         ConstantTimeEqual(observation->peer_spki_sha256.data(),
                           policy.peer_spki_sha256.data(),
                           observation->peer_spki_sha256.size());
}

bool VerifyMbedTlsRoamingPeer(
    mbedtls_ssl_context* ssl, const config::RoamingEndpointConfig& policy,
    const config::RecoverySecret& recovery_secret,
    config::RoamingPolicyCrypto& crypto,
    endpoint::TlsObservation* observation,
    config::RoamingPeerAuthorization* authorization,
    config::RoamingPolicyVerificationWorkspace* workspace) {
  if (ssl == nullptr || observation == nullptr || authorization == nullptr ||
      workspace == nullptr ||
      mbedtls_ssl_get_version_number(ssl) != MBEDTLS_SSL_VERSION_TLS1_2 ||
      mbedtls_ssl_get_ciphersuite_id_from_ssl(ssl) !=
          endpoint::kRequiredCipherSuite ||
      mbedtls_ssl_get_verify_result(ssl) != 0) {
    return false;
  }

  const mbedtls_x509_crt* peer = mbedtls_ssl_get_peer_cert(ssl);
  if (peer == nullptr || !IsP256Spki(*peer)) {
    return false;
  }
  roaming::P256Spki peer_spki{};
  std::copy_n(peer->pk_raw.p, peer_spki.size(), peer_spki.begin());
  const mbedtls_md_info_t* sha256 =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (sha256 == nullptr ||
      mbedtls_md(sha256, peer_spki.data(), peer_spki.size(),
                 observation->peer_spki_sha256.data()) != 0 ||
      !config::AuthorizeRoamingPeer(policy, recovery_secret, peer_spki, crypto,
                                    authorization, workspace)) {
    return false;
  }
  observation->version = endpoint::kTls12Version;
  observation->cipher_suite = endpoint::kRequiredCipherSuite;
  observation->peer_key_algorithm = endpoint::PeerKeyAlgorithm::kEcdsaP256;
  return true;
}

}  // namespace keyferry::transport
