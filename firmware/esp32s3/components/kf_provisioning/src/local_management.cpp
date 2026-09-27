#include "keyferry/local_management.h"

#include <algorithm>

namespace keyferry::local_management {
namespace {

constexpr std::uint8_t kResponseBit = 0x80;
constexpr std::size_t kSignedReportBytes = 48;

void SecureClear(void* data, std::size_t length) {
  volatile auto* output = static_cast<volatile std::uint8_t*>(data);
  while (length-- != 0) {
    *output++ = 0;
  }
}

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

bool EqualConstantTime(const std::uint8_t* left, const std::uint8_t* right,
                       const std::size_t length) {
  std::uint8_t difference = 0;
  for (std::size_t index = 0; index < length; ++index) {
    difference =
        static_cast<std::uint8_t>(difference | (left[index] ^ right[index]));
  }
  return difference == 0;
}

protocol::LocalManagementStatus CodecFailure(const CodecStatus status) {
  switch (status) {
    case CodecStatus::kOk:
      return protocol::LocalManagementStatus::kOk;
    case CodecStatus::kBadVersion:
    case CodecStatus::kBadOperation:
    case CodecStatus::kNonzeroReserved:
    case CodecStatus::kZeroSessionId:
    case CodecStatus::kZeroSequence:
    case CodecStatus::kMissingOperationId:
    case CodecStatus::kUnexpectedOperationId:
      return protocol::LocalManagementStatus::kBadReport;
  }
  return protocol::LocalManagementStatus::kBadReport;
}

}  // namespace

Session::Session(const std::array<std::uint8_t, 16>& device_id,
                 const std::array<std::uint8_t, 32>& recovery_secret,
                 const std::uint32_t capabilities,
                 provisioning::Effects& effects, Handler& handler)
    : device_id_(device_id),
      capabilities_(capabilities),
      effects_(effects),
      handler_(handler) {
  const std::array<provisioning::ByteSpan, 2> parts{{
      {protocol::kLocalManagementAdminKeyDomain.data(),
       protocol::kLocalManagementAdminKeyDomain.size()},
      {device_id_.data(), device_id_.size()},
  }};
  authority_valid_ =
      AnyNonzero(device_id_.data(), device_id_.size()) &&
      AnyNonzero(recovery_secret.data(), recovery_secret.size()) &&
      Calculate(recovery_secret, parts.data(), parts.size(), &admin_key_) &&
      AnyNonzero(admin_key_.data(), admin_key_.size());
}

Session::~Session() {
  ResetEphemeral();
  SecureClear(admin_key_.data(), admin_key_.size());
}

protocol::LocalManagementStatus Session::Handle(const Report& request,
                                                Report* response) {
  if (response == nullptr) {
    ResetEphemeral();
    return protocol::LocalManagementStatus::kBadReport;
  }
  response->fill(0);
  (*response)[0] = static_cast<std::uint8_t>(request[0] | kResponseBit);
  (*response)[2] = protocol::kLocalManagementVersion;
  const auto now_ms = effects_.MonotonicMilliseconds();
  Expire(now_ms);
  const auto operation =
      static_cast<protocol::LocalManagementOperation>(request[0]);
  protocol::LocalManagementStatus status{};
  if (operation == protocol::LocalManagementOperation::kChallenge) {
    status = Challenge(request, response, now_ms);
  } else if (operation == protocol::LocalManagementOperation::kAuthenticate) {
    status = Authenticate(request, response, now_ms);
  } else if (IsAuthenticatedOperation(operation)) {
    status = DispatchAuthenticated(request, response, now_ms);
  } else {
    status = protocol::LocalManagementStatus::kUnsupported;
  }
  (*response)[1] = static_cast<std::uint8_t>(status);
  return status;
}

protocol::LocalManagementStatus Session::Challenge(const Report& request,
                                                   Report* response,
                                                   const std::uint64_t now_ms) {
  ResetEphemeral();
  if (!authority_valid_) {
    return protocol::LocalManagementStatus::kBadState;
  }
  if (!AllZero(request.data() + 1, request.size() - 1)) {
    return protocol::LocalManagementStatus::kBadReport;
  }
  if (!effects_.FillRandom(device_nonce_.data(), device_nonce_.size()) ||
      !effects_.FillRandom(session_id_.data(), session_id_.size()) ||
      !AnyNonzero(device_nonce_.data(), device_nonce_.size()) ||
      !AnyNonzero(session_id_.data(), session_id_.size())) {
    ResetEphemeral();
    return protocol::LocalManagementStatus::kInternal;
  }
  challenge_active_ = true;
  started_ms_ = now_ms;
  last_activity_ms_ = now_ms;
  const auto encoded = EncodeChallengeResponse(
      protocol::LocalManagementStatus::kOk, capabilities_, device_id_,
      device_nonce_, session_id_, response);
  if (encoded != CodecStatus::kOk) {
    ResetEphemeral();
    return CodecFailure(encoded);
  }
  return protocol::LocalManagementStatus::kOk;
}

protocol::LocalManagementStatus Session::Authenticate(
    const Report& request, Report* response, const std::uint64_t now_ms) {
  AuthenticateRequest decoded{};
  const auto codec = DecodeAuthenticateRequest(request, &decoded);
  if (codec != CodecStatus::kOk) {
    ResetEphemeral();
    return CodecFailure(codec);
  }
  if (!challenge_active_ || authenticated_ ||
      !EqualConstantTime(decoded.session_id.data(), session_id_.data(),
                         session_id_.size())) {
    ResetEphemeral();
    return protocol::LocalManagementStatus::kBadState;
  }
  const std::uint8_t version = protocol::kLocalManagementVersion;
  const std::array<provisioning::ByteSpan, 6> transcript{{
      {protocol::kLocalManagementAuthenticationDomain.data(),
       protocol::kLocalManagementAuthenticationDomain.size()},
      {&version, 1},
      {device_id_.data(), device_id_.size()},
      {device_nonce_.data(), device_nonce_.size()},
      {session_id_.data(), session_id_.size()},
      {decoded.host_nonce.data(), decoded.host_nonce.size()},
  }};
  std::array<std::uint8_t, 32> expected{};
  if (!Calculate(admin_key_, transcript.data(), transcript.size(), &expected) ||
      !EqualConstantTime(expected.data(), decoded.proof.data(),
                         decoded.proof.size())) {
    SecureClear(expected.data(), expected.size());
    ResetEphemeral();
    return protocol::LocalManagementStatus::kAuthenticationFailed;
  }
  SecureClear(expected.data(), expected.size());

  const provisioning::ByteSpan session_domain{
      protocol::kLocalManagementSessionKeyDomain.data(),
      protocol::kLocalManagementSessionKeyDomain.size()};
  std::array<provisioning::ByteSpan, 7> session_parts{};
  session_parts[0] = session_domain;
  std::copy(transcript.begin(), transcript.end(), session_parts.begin() + 1);
  if (!Calculate(admin_key_, session_parts.data(), session_parts.size(),
                 &session_key_) ||
      !AnyNonzero(session_key_.data(), session_key_.size())) {
    ResetEphemeral();
    return protocol::LocalManagementStatus::kInternal;
  }

  const provisioning::ByteSpan proof_domain{
      protocol::kLocalManagementDeviceProofDomain.data(),
      protocol::kLocalManagementDeviceProofDomain.size()};
  std::array<provisioning::ByteSpan, 7> proof_parts{};
  proof_parts[0] = proof_domain;
  std::copy(transcript.begin(), transcript.end(), proof_parts.begin() + 1);
  AuthenticationTag proof{};
  if (!Calculate(session_key_, proof_parts.data(), proof_parts.size(), &proof) ||
      EncodeAuthenticateResponse(protocol::LocalManagementStatus::kOk,
                                 session_id_, proof, response) !=
          CodecStatus::kOk) {
    SecureClear(proof.data(), proof.size());
    ResetEphemeral();
    return protocol::LocalManagementStatus::kInternal;
  }
  SecureClear(proof.data(), proof.size());
  authenticated_ = true;
  challenge_active_ = false;
  last_activity_ms_ = now_ms;
  last_sequence_ = 0;
  return protocol::LocalManagementStatus::kOk;
}

protocol::LocalManagementStatus Session::DispatchAuthenticated(
    const Report& request, Report* response, const std::uint64_t now_ms) {
  AuthenticatedRequest decoded{};
  const auto codec = DecodeAuthenticatedRequest(request, &decoded);
  if (codec != CodecStatus::kOk) {
    ResetEphemeral();
    return CodecFailure(codec);
  }
  if (!authenticated_ ||
      !EqualConstantTime(decoded.session_id.data(), session_id_.data(),
                         session_id_.size())) {
    ResetEphemeral();
    return protocol::LocalManagementStatus::kBadState;
  }
  if (last_sequence_ == UINT32_MAX || decoded.sequence != last_sequence_ + 1) {
    ResetEphemeral();
    return protocol::LocalManagementStatus::kReplay;
  }
  Report signing{};
  if (EncodeRequestSigningBytes(decoded, &signing) != CodecStatus::kOk) {
    ResetEphemeral();
    return protocol::LocalManagementStatus::kBadReport;
  }
  const std::array<provisioning::ByteSpan, 2> request_parts{{
      {protocol::kLocalManagementRequestDomain.data(),
       protocol::kLocalManagementRequestDomain.size()},
      {signing.data(), kSignedReportBytes},
  }};
  std::array<std::uint8_t, 32> expected{};
  if (!Calculate(session_key_, request_parts.data(), request_parts.size(),
                 &expected) ||
      !EqualConstantTime(expected.data(), decoded.tag.data(),
                         decoded.tag.size())) {
    SecureClear(expected.data(), expected.size());
    ResetEphemeral();
    return protocol::LocalManagementStatus::kAuthenticationFailed;
  }
  SecureClear(expected.data(), expected.size());

  ResponsePayload payload{};
  std::uint8_t flags = 0;
  const auto status = handler_.Handle(decoded, &payload, &flags);
  AuthenticatedResponse outgoing{
      decoded.operation, status, flags, decoded.session_id, decoded.sequence,
      decoded.operation_id, payload, {}};
  if (EncodeResponseSigningBytes(outgoing, &signing) != CodecStatus::kOk) {
    ResetEphemeral();
    return protocol::LocalManagementStatus::kInternal;
  }
  const std::array<provisioning::ByteSpan, 2> response_parts{{
      {protocol::kLocalManagementResponseDomain.data(),
       protocol::kLocalManagementResponseDomain.size()},
      {signing.data(), kSignedReportBytes},
  }};
  std::array<std::uint8_t, 32> response_tag{};
  if (!Calculate(session_key_, response_parts.data(), response_parts.size(),
                 &response_tag)) {
    SecureClear(response_tag.data(), response_tag.size());
    ResetEphemeral();
    return protocol::LocalManagementStatus::kInternal;
  }
  std::copy_n(response_tag.begin(), outgoing.tag.size(), outgoing.tag.begin());
  SecureClear(response_tag.data(), response_tag.size());
  if (EncodeAuthenticatedResponse(outgoing, response) != CodecStatus::kOk) {
    ResetEphemeral();
    return protocol::LocalManagementStatus::kInternal;
  }
  last_sequence_ = decoded.sequence;
  last_activity_ms_ = now_ms;
  return status;
}

bool Session::Calculate(const std::array<std::uint8_t, 32>& key,
                        const provisioning::ByteSpan* parts,
                        const std::size_t part_count,
                        std::array<std::uint8_t, 32>* output) {
  return effects_.HmacSha256(key, parts, part_count, output);
}

bool Session::Expire(const std::uint64_t now_ms) {
  if (!challenge_active_ && !authenticated_) {
    return false;
  }
  if (now_ms - last_activity_ms_ < protocol::kLocalManagementIdleTimeoutMs &&
      now_ms - started_ms_ < protocol::kLocalManagementHardTimeoutMs) {
    return false;
  }
  ResetEphemeral();
  return true;
}

void Session::TransportLost() { ResetEphemeral(); }

void Session::ResetEphemeral() {
  SecureClear(session_key_.data(), session_key_.size());
  SecureClear(device_nonce_.data(), device_nonce_.size());
  SecureClear(session_id_.data(), session_id_.size());
  started_ms_ = 0;
  last_activity_ms_ = 0;
  last_sequence_ = 0;
  challenge_active_ = false;
  authenticated_ = false;
}

}  // namespace keyferry::local_management
