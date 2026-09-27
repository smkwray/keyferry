#include "keyferry/local_management_codec.h"

#include <algorithm>

namespace keyferry::local_management {
namespace {

constexpr std::uint8_t kResponseBit = 0x80;
constexpr std::size_t kEnvelopeTagOffset =
    protocol::kLocalManagementReportSize -
    protocol::kLocalManagementEnvelopeTagSize;

bool AnyNonzero(const std::uint8_t* data, const std::size_t length) {
  std::uint8_t combined = 0;
  for (std::size_t index = 0; index < length; ++index) {
    combined = static_cast<std::uint8_t>(combined | data[index]);
  }
  return combined != 0;
}

bool AllZero(const std::uint8_t* data, const std::size_t length) {
  return !AnyNonzero(data, length);
}

void PutU32(std::uint8_t* output, const std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    output[index] = static_cast<std::uint8_t>(value >> (index * 8));
  }
}

std::uint32_t GetU32(const std::uint8_t* input) {
  std::uint32_t output = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    output |= static_cast<std::uint32_t>(input[index]) << (index * 8);
  }
  return output;
}

CodecStatus ValidateIdentity(const SessionId& session_id,
                             const std::uint32_t sequence,
                             const OperationId& operation_id,
                             const protocol::LocalManagementOperation operation) {
  if (!AnyNonzero(session_id.data(), session_id.size())) {
    return CodecStatus::kZeroSessionId;
  }
  if (sequence == 0) {
    return CodecStatus::kZeroSequence;
  }
  const bool has_operation_id =
      AnyNonzero(operation_id.data(), operation_id.size());
  if (IsMutation(operation) && !has_operation_id) {
    return CodecStatus::kMissingOperationId;
  }
  if (!IsMutation(operation) && has_operation_id) {
    return CodecStatus::kUnexpectedOperationId;
  }
  return CodecStatus::kOk;
}

}  // namespace

bool IsAuthenticatedOperation(
    const protocol::LocalManagementOperation operation) {
  switch (operation) {
    case protocol::LocalManagementOperation::kGetStatus:
    case protocol::LocalManagementOperation::kOpenMaintenance:
    case protocol::LocalManagementOperation::kCloseMaintenance:
    case protocol::LocalManagementOperation::kRestartNetwork:
    case protocol::LocalManagementOperation::kClearBleBondAndEnroll:
    case protocol::LocalManagementOperation::kCancelEnrollment:
    case protocol::LocalManagementOperation::kSetOutputMode:
    case protocol::LocalManagementOperation::kReboot:
    case protocol::LocalManagementOperation::kGetReceipt:
      return true;
    case protocol::LocalManagementOperation::kChallenge:
    case protocol::LocalManagementOperation::kAuthenticate:
      return false;
  }
  return false;
}

bool IsMutation(const protocol::LocalManagementOperation operation) {
  switch (operation) {
    case protocol::LocalManagementOperation::kOpenMaintenance:
    case protocol::LocalManagementOperation::kCloseMaintenance:
    case protocol::LocalManagementOperation::kRestartNetwork:
    case protocol::LocalManagementOperation::kClearBleBondAndEnroll:
    case protocol::LocalManagementOperation::kCancelEnrollment:
    case protocol::LocalManagementOperation::kSetOutputMode:
    case protocol::LocalManagementOperation::kReboot:
      return true;
    case protocol::LocalManagementOperation::kChallenge:
    case protocol::LocalManagementOperation::kAuthenticate:
    case protocol::LocalManagementOperation::kGetStatus:
    case protocol::LocalManagementOperation::kGetReceipt:
      return false;
  }
  return false;
}

CodecStatus DecodeAuthenticateRequest(const Report& report,
                                      AuthenticateRequest* output) {
  if (output == nullptr ||
      report[0] !=
          static_cast<std::uint8_t>(
              protocol::LocalManagementOperation::kAuthenticate)) {
    return CodecStatus::kBadOperation;
  }
  if (report[1] != protocol::kLocalManagementVersion) {
    return CodecStatus::kBadVersion;
  }
  if (!AllZero(report.data() + 58, report.size() - 58)) {
    return CodecStatus::kNonzeroReserved;
  }
  std::copy_n(report.data() + 2, output->session_id.size(),
              output->session_id.begin());
  if (!AnyNonzero(output->session_id.data(), output->session_id.size())) {
    return CodecStatus::kZeroSessionId;
  }
  std::copy_n(report.data() + 10, output->host_nonce.size(),
              output->host_nonce.begin());
  std::copy_n(report.data() + 26, output->proof.size(), output->proof.begin());
  return CodecStatus::kOk;
}

CodecStatus DecodeAuthenticatedRequest(const Report& report,
                                       AuthenticatedRequest* output) {
  if (output == nullptr || (report[0] & kResponseBit) != 0) {
    return CodecStatus::kBadOperation;
  }
  const auto operation =
      static_cast<protocol::LocalManagementOperation>(report[0]);
  if (!IsAuthenticatedOperation(operation)) {
    return CodecStatus::kBadOperation;
  }
  if (report[1] != protocol::kLocalManagementVersion) {
    return CodecStatus::kBadVersion;
  }
  output->operation = operation;
  std::copy_n(report.data() + 2, output->session_id.size(),
              output->session_id.begin());
  output->sequence = GetU32(report.data() + 10);
  std::copy_n(report.data() + 14, output->operation_id.size(),
              output->operation_id.begin());
  const auto identity = ValidateIdentity(output->session_id, output->sequence,
                                         output->operation_id, operation);
  if (identity != CodecStatus::kOk) {
    return identity;
  }
  std::copy_n(report.data() + 30, output->payload.size(),
              output->payload.begin());
  std::copy_n(report.data() + kEnvelopeTagOffset, output->tag.size(),
              output->tag.begin());
  return CodecStatus::kOk;
}

CodecStatus EncodeChallengeResponse(
    const protocol::LocalManagementStatus status,
    const std::uint32_t capabilities,
    const std::array<std::uint8_t, 16>& device_id,
    const DeviceNonce& device_nonce, const SessionId& session_id,
    Report* output) {
  if (output == nullptr) {
    return CodecStatus::kBadOperation;
  }
  if (!AnyNonzero(session_id.data(), session_id.size())) {
    return CodecStatus::kZeroSessionId;
  }
  output->fill(0);
  (*output)[0] = static_cast<std::uint8_t>(
      static_cast<std::uint8_t>(protocol::LocalManagementOperation::kChallenge) |
      kResponseBit);
  (*output)[1] = static_cast<std::uint8_t>(status);
  (*output)[2] = protocol::kLocalManagementVersion;
  PutU32(output->data() + 3, capabilities);
  std::copy(device_id.begin(), device_id.end(), output->begin() + 7);
  std::copy(device_nonce.begin(), device_nonce.end(), output->begin() + 23);
  std::copy(session_id.begin(), session_id.end(), output->begin() + 55);
  return CodecStatus::kOk;
}

CodecStatus EncodeAuthenticateResponse(
    const protocol::LocalManagementStatus status, const SessionId& session_id,
    const AuthenticationTag& proof, Report* output) {
  if (output == nullptr) {
    return CodecStatus::kBadOperation;
  }
  if (!AnyNonzero(session_id.data(), session_id.size())) {
    return CodecStatus::kZeroSessionId;
  }
  output->fill(0);
  (*output)[0] = static_cast<std::uint8_t>(
      static_cast<std::uint8_t>(
          protocol::LocalManagementOperation::kAuthenticate) |
      kResponseBit);
  (*output)[1] = static_cast<std::uint8_t>(status);
  (*output)[2] = protocol::kLocalManagementVersion;
  std::copy(session_id.begin(), session_id.end(), output->begin() + 4);
  std::copy(proof.begin(), proof.end(), output->begin() + 12);
  return CodecStatus::kOk;
}

CodecStatus EncodeRequestSigningBytes(const AuthenticatedRequest& request,
                                      Report* output) {
  if (output == nullptr || !IsAuthenticatedOperation(request.operation)) {
    return CodecStatus::kBadOperation;
  }
  const auto identity = ValidateIdentity(request.session_id, request.sequence,
                                         request.operation_id,
                                         request.operation);
  if (identity != CodecStatus::kOk) {
    return identity;
  }
  output->fill(0);
  (*output)[0] = static_cast<std::uint8_t>(request.operation);
  (*output)[1] = protocol::kLocalManagementVersion;
  std::copy(request.session_id.begin(), request.session_id.end(),
            output->begin() + 2);
  PutU32(output->data() + 10, request.sequence);
  std::copy(request.operation_id.begin(), request.operation_id.end(),
            output->begin() + 14);
  std::copy(request.payload.begin(), request.payload.end(), output->begin() + 30);
  return CodecStatus::kOk;
}

CodecStatus EncodeResponseSigningBytes(const AuthenticatedResponse& response,
                                       Report* output) {
  if (output == nullptr || !IsAuthenticatedOperation(response.operation)) {
    return CodecStatus::kBadOperation;
  }
  const auto identity = ValidateIdentity(response.session_id, response.sequence,
                                         response.operation_id,
                                         response.operation);
  if (identity != CodecStatus::kOk) {
    return identity;
  }
  output->fill(0);
  (*output)[0] = static_cast<std::uint8_t>(
      static_cast<std::uint8_t>(response.operation) | kResponseBit);
  (*output)[1] = static_cast<std::uint8_t>(response.status);
  (*output)[2] = protocol::kLocalManagementVersion;
  (*output)[3] = response.flags;
  std::copy(response.session_id.begin(), response.session_id.end(),
            output->begin() + 4);
  PutU32(output->data() + 12, response.sequence);
  std::copy(response.operation_id.begin(), response.operation_id.end(),
            output->begin() + 16);
  std::copy(response.payload.begin(), response.payload.end(),
            output->begin() + 32);
  return CodecStatus::kOk;
}

CodecStatus EncodeAuthenticatedResponse(const AuthenticatedResponse& response,
                                        Report* output) {
  const auto status = EncodeResponseSigningBytes(response, output);
  if (status == CodecStatus::kOk) {
    std::copy(response.tag.begin(), response.tag.end(),
              output->begin() + kEnvelopeTagOffset);
  }
  return status;
}

}  // namespace keyferry::local_management
