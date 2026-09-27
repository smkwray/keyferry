#pragma once

#include <array>
#include <cstdint>

#include "keyferry_protocol_generated.h"

namespace keyferry::local_management {

using Report = std::array<std::uint8_t, protocol::kLocalManagementReportSize>;
using SessionId =
    std::array<std::uint8_t, protocol::kLocalManagementSessionIdSize>;
using DeviceNonce =
    std::array<std::uint8_t, protocol::kLocalManagementDeviceNonceSize>;
using HostNonce =
    std::array<std::uint8_t, protocol::kLocalManagementHostNonceSize>;
using AuthenticationTag =
    std::array<std::uint8_t, protocol::kLocalManagementAuthenticationTagSize>;
using EnvelopeTag =
    std::array<std::uint8_t, protocol::kLocalManagementEnvelopeTagSize>;
using OperationId =
    std::array<std::uint8_t, protocol::kLocalManagementOperationIdSize>;
using RequestPayload =
    std::array<std::uint8_t, protocol::kLocalManagementRequestPayloadSize>;
using ResponsePayload =
    std::array<std::uint8_t, protocol::kLocalManagementResponsePayloadSize>;

enum class CodecStatus : std::uint8_t {
  kOk,
  kBadOperation,
  kBadVersion,
  kNonzeroReserved,
  kZeroSessionId,
  kZeroSequence,
  kMissingOperationId,
  kUnexpectedOperationId,
};

struct AuthenticateRequest {
  SessionId session_id{};
  HostNonce host_nonce{};
  AuthenticationTag proof{};
};

struct AuthenticatedRequest {
  protocol::LocalManagementOperation operation{};
  SessionId session_id{};
  std::uint32_t sequence{};
  OperationId operation_id{};
  RequestPayload payload{};
  EnvelopeTag tag{};
};

struct AuthenticatedResponse {
  protocol::LocalManagementOperation operation{};
  protocol::LocalManagementStatus status{};
  std::uint8_t flags{};
  SessionId session_id{};
  std::uint32_t sequence{};
  OperationId operation_id{};
  ResponsePayload payload{};
  EnvelopeTag tag{};
};

[[nodiscard]] bool IsAuthenticatedOperation(
    protocol::LocalManagementOperation operation);
[[nodiscard]] bool IsMutation(protocol::LocalManagementOperation operation);

CodecStatus DecodeAuthenticateRequest(const Report& report,
                                      AuthenticateRequest* output);
CodecStatus DecodeAuthenticatedRequest(const Report& report,
                                       AuthenticatedRequest* output);
CodecStatus EncodeChallengeResponse(
    protocol::LocalManagementStatus status, std::uint32_t capabilities,
    const std::array<std::uint8_t, 16>& device_id,
    const DeviceNonce& device_nonce, const SessionId& session_id,
    Report* output);
CodecStatus EncodeAuthenticateResponse(
    protocol::LocalManagementStatus status, const SessionId& session_id,
    const AuthenticationTag& proof, Report* output);
CodecStatus EncodeAuthenticatedResponse(const AuthenticatedResponse& response,
                                        Report* output);

// Returns bytes 0-47 with the envelope tag area zero. HMAC callers prepend the
// generated request/response domain and truncate SHA-256 to 16 bytes.
CodecStatus EncodeRequestSigningBytes(const AuthenticatedRequest& request,
                                      Report* output);
CodecStatus EncodeResponseSigningBytes(const AuthenticatedResponse& response,
                                       Report* output);

}  // namespace keyferry::local_management
