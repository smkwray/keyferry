#pragma once

#include "keyferry/roaming_config.h"
#include "keyferry/secure_endpoint.h"

struct mbedtls_ssl_context;

namespace keyferry::transport {

// Applies the shared post-handshake policy used by every physical transport.
// The peer certificate is consumed before another mbedtls_ssl_* call because
// Mbed TLS owns the returned pointer.
bool VerifyMbedTlsPeer(mbedtls_ssl_context* ssl,
                       const endpoint::TlsClientPolicy& policy,
                       endpoint::TlsObservation* observation);

// Verifies the owner-rooted TLS result, derives the peer installation identity
// and per-installation link secret, and rejects revoked peers. The TLS context
// must already be configured with the policy's owner CA and device DNS name.
bool VerifyMbedTlsRoamingPeer(
    mbedtls_ssl_context* ssl, const config::RoamingEndpointConfig& policy,
    const config::RecoverySecret& recovery_secret,
    config::RoamingPolicyCrypto& crypto,
    endpoint::TlsObservation* observation,
    config::RoamingPeerAuthorization* authorization,
    config::RoamingPolicyVerificationWorkspace* workspace);

}  // namespace keyferry::transport
