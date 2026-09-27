#include "keyferry/provisioning.h"

#include <algorithm>
#include <cstring>

namespace keyferry::provisioning {
namespace {

constexpr std::uint8_t kResponseBit = 0x80;

void SecureClear(void* data, std::size_t length) {
  volatile auto* output = static_cast<volatile std::uint8_t*>(data);
  while (length-- != 0) {
    *output++ = 0;
  }
}

bool AnyNonzero(const std::uint8_t* data, std::size_t length) {
  std::uint8_t combined = 0;
  for (std::size_t index = 0; index < length; ++index) {
    combined |= data[index];
  }
  return combined != 0;
}

bool AllZero(const std::uint8_t* data, std::size_t length) {
  return !AnyNonzero(data, length);
}

bool EqualConstantTime(const std::uint8_t* left, const std::uint8_t* right,
                       std::size_t length) {
  std::uint8_t difference = 0;
  for (std::size_t index = 0; index < length; ++index) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

std::uint16_t GetU16(const std::uint8_t* input) {
  return static_cast<std::uint16_t>(input[0]) |
         static_cast<std::uint16_t>(input[1] << 8);
}

void PutU16(std::uint8_t* output, std::uint16_t value) {
  output[0] = static_cast<std::uint8_t>(value);
  output[1] = static_cast<std::uint8_t>(value >> 8);
}

void PutU32(std::uint8_t* output, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    output[index] = static_cast<std::uint8_t>(value >> (index * 8));
  }
}

void PutU64(std::uint8_t* output, std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    output[index] = static_cast<std::uint8_t>(value >> (index * 8));
  }
}

bool TransactionMatches(const std::uint8_t* request_id,
                        const std::array<std::uint8_t, kTransactionIdBytes>& active) {
  return std::equal(active.begin(), active.end(), request_id);
}

}  // namespace

Session::Session(const std::array<std::uint8_t, 16>& device_id,
                 const std::array<std::uint8_t, 32>& provisioning_key,
                 const std::uint64_t current_generation,
                 Effects& effects, const PayloadFormat format,
                 const PolicyStatus policy_status)
    : device_id_(device_id),
      provisioning_key_(provisioning_key),
      current_generation_(current_generation),
      effects_(effects),
      format_(format),
      policy_status_(policy_status),
      payload_size_(format == PayloadFormat::kRoamingV2
                        ? config::kRoamingConfigPayloadBytes
                        : config::kPayloadBytes),
      authority_valid_(AnyNonzero(device_id_.data(), device_id_.size()) &&
                       AnyNonzero(provisioning_key_.data(),
                                  provisioning_key_.size())) {}

Session::~Session() {
  Reset();
  SecureClear(provisioning_key_.data(), provisioning_key_.size());
}

Status Session::Handle(const std::array<std::uint8_t, kReportBytes>& request,
                       std::array<std::uint8_t, kReportBytes>* response) {
  if (response == nullptr) {
    ClearTransaction(true);
    return Status::kBadReport;
  }
  const std::uint64_t now_ms = effects_.MonotonicMilliseconds();
  Expire(now_ms);
  response->fill(0);
  const auto operation = static_cast<Operation>(
      request[protocol::kProvisioningRequestOperationOffset]);
  (*response)[protocol::kProvisioningResponseOperationOffset] =
      static_cast<std::uint8_t>(
          request[protocol::kProvisioningRequestOperationOffset] | kResponseBit);
  Status status = Status::kBadReport;
  switch (operation) {
    case Operation::kChallenge:
      status = Challenge(request, response);
      if (status == Status::kOk) {
        MarkActivity(now_ms);
      }
      break;
    case Operation::kBegin:
      status = Begin(request);
      if (status == Status::kOk) {
        MarkActivity(now_ms);
      }
      break;
    case Operation::kData:
      status = Data(request);
      if (status == Status::kOk) {
        MarkActivity(now_ms);
      }
      break;
    case Operation::kCommit:
      status = Commit(request, response);
      break;
    case Operation::kAbort:
      if (AllZero(request.data() + protocol::kProvisioningRequestOperationOffset + 1,
                  request.size() -
                      protocol::kProvisioningRequestOperationOffset - 1)) {
        ClearTransaction(true);
        status = Status::kOk;
      }
      break;
    case Operation::kPolicyStatus:
      status = ReportPolicyStatus(request, response);
      break;
  }
  (*response)[protocol::kProvisioningResponseStatusOffset] =
      static_cast<std::uint8_t>(status);
  if (status != Status::kOk && operation != Operation::kChallenge) {
    ClearTransaction(true);
  }
  return status;
}

Status Session::Challenge(const std::array<std::uint8_t, kReportBytes>& request,
                          std::array<std::uint8_t, kReportBytes>* response) {
  ClearTransaction(true);
  if (!authority_valid_) {
    return Status::kBadState;
  }
  if (!AllZero(request.data() + protocol::kProvisioningRequestOperationOffset + 1,
               request.size() - protocol::kProvisioningRequestOperationOffset - 1)) {
    return Status::kBadReport;
  }
  if (!effects_.FillRandom(challenge_.data(), challenge_.size()) ||
      !AnyNonzero(challenge_.data(), challenge_.size())) {
    ClearTransaction(true);
    return Status::kRandomFailed;
  }
  challenge_active_ = true;
  (*response)[protocol::kProvisioningChallengeVersionOffset] =
      static_cast<std::uint8_t>(format_);
  PutU16(response->data() + protocol::kProvisioningChallengePayloadLengthOffset,
         static_cast<std::uint16_t>(payload_size_));
  std::copy(device_id_.begin(), device_id_.end(),
            response->begin() + protocol::kProvisioningChallengeDeviceIdOffset);
  std::copy(challenge_.begin(), challenge_.end(),
            response->begin() + protocol::kProvisioningChallengeNonceOffset);
  PutU64(response->data() + protocol::kProvisioningChallengeGenerationOffset,
         current_generation_);
  return Status::kOk;
}

Status Session::Begin(const std::array<std::uint8_t, kReportBytes>& request) {
  if (!challenge_active_ || transaction_active_) {
    return Status::kBadState;
  }
  constexpr std::size_t kBeginEnd =
      protocol::kProvisioningBeginTransactionIdOffset + kTransactionIdBytes;
  if (request[protocol::kProvisioningBeginVersionOffset] !=
          static_cast<std::uint8_t>(format_) ||
      GetU16(request.data() + protocol::kProvisioningBeginPayloadLengthOffset) !=
          payload_size_ ||
      !AnyNonzero(request.data() +
                      protocol::kProvisioningBeginTransactionIdOffset,
                  kTransactionIdBytes) ||
      !AllZero(request.data() + kBeginEnd, request.size() - kBeginEnd)) {
    return Status::kBadReport;
  }
  payload_.fill(0);
  std::copy_n(request.data() + protocol::kProvisioningBeginTransactionIdOffset,
              transaction_id_.size(), transaction_id_.begin());
  received_ = 0;
  transaction_active_ = true;
  return Status::kOk;
}

Status Session::Data(const std::array<std::uint8_t, kReportBytes>& request) {
  if (!challenge_active_ || !transaction_active_) {
    return Status::kBadState;
  }
  if (!TransactionMatches(
          request.data() + protocol::kProvisioningDataTransactionIdOffset,
          transaction_id_)) {
    return Status::kBadTransaction;
  }
  const std::size_t offset =
      GetU16(request.data() + protocol::kProvisioningDataOffsetOffset);
  const std::size_t length = request[protocol::kProvisioningDataLengthOffset];
  if (offset != received_ || length == 0 || length > kDataBytesPerReport ||
      received_ > payload_size_ || length > payload_size_ - received_ ||
      !AllZero(request.data() + protocol::kProvisioningDataBytesOffset + length,
               request.size() - protocol::kProvisioningDataBytesOffset - length)) {
    return offset != received_ ? Status::kBadOffset : Status::kBadReport;
  }
  std::copy_n(request.data() + protocol::kProvisioningDataBytesOffset, length,
              payload_.begin() + received_);
  received_ += length;
  return Status::kOk;
}

Status Session::Commit(const std::array<std::uint8_t, kReportBytes>& request,
                       std::array<std::uint8_t, kReportBytes>* response) {
  if (!challenge_active_ || !transaction_active_ || received_ != payload_size_) {
    return Status::kBadState;
  }
  if (!TransactionMatches(
          request.data() + protocol::kProvisioningCommitTransactionIdOffset,
          transaction_id_)) {
    return Status::kBadTransaction;
  }
  constexpr std::size_t kCommitEnd =
      protocol::kProvisioningCommitTagOffset + kAuthenticationTagBytes;
  if (!AllZero(request.data() + kCommitEnd, request.size() - kCommitEnd)) {
    return Status::kBadReport;
  }

  std::array<std::uint8_t, 8> generation{};
  std::array<std::uint8_t, 4> payload_length{};
  PutU64(generation.data(), current_generation_);
  PutU32(payload_length.data(), static_cast<std::uint32_t>(payload_size_));
  const ByteSpan authentication_domain =
      format_ == PayloadFormat::kRoamingV2
          ? ByteSpan{protocol::kRoamingMaintenanceAuthenticationDomain.data(),
                     protocol::kRoamingMaintenanceAuthenticationDomain.size()}
          : ByteSpan{kAuthenticationDomain.data(),
                     kAuthenticationDomain.size()};
  const std::array<ByteSpan, 7> authenticated_parts{{
      authentication_domain,
      {device_id_.data(), device_id_.size()},
      {challenge_.data(), challenge_.size()},
      {generation.data(), generation.size()},
      {transaction_id_.data(), transaction_id_.size()},
      {payload_length.data(), payload_length.size()},
      {payload_.data(), payload_size_},
  }};
  std::array<std::uint8_t, kAuthenticationTagBytes> expected{};
  if (!effects_.HmacSha256(provisioning_key_, authenticated_parts.data(),
                           authenticated_parts.size(), &expected) ||
      !EqualConstantTime(expected.data(),
                         request.data() + protocol::kProvisioningCommitTagOffset,
                         expected.size())) {
    SecureClear(expected.data(), expected.size());
    SecureClear(generation.data(), generation.size());
    SecureClear(payload_length.data(), payload_length.size());
    return Status::kAuthenticationFailed;
  }
  SecureClear(expected.data(), expected.size());
  SecureClear(generation.data(), generation.size());
  SecureClear(payload_length.data(), payload_length.size());
  config::Selection selection{};
  if (format_ == PayloadFormat::kRoamingV2) {
    if (!config::DecodeRoamingConfigPayload(payload_.data(), payload_size_,
                                            &roaming_candidate_)) {
      return Status::kInvalidConfig;
    }
    if (roaming_candidate_.device_id != device_id_) {
      return Status::kIdentityMismatch;
    }
    const auto migration = effects_.MigrateToRoaming(
        roaming_candidate_, provisioning_key_, transaction_id_);
    if (migration != config::MigrationStatus::kReady) {
      return Status::kCommitFailed;
    }
    selection = {config::ConfigState::kReady, config::SlotId::kNone,
                 roaming_candidate_.policy_sequence};
    policy_status_.state = PolicyState::kActive;
    policy_status_.epoch = roaming_candidate_.epoch;
    policy_status_.sequence = roaming_candidate_.policy_sequence;
    policy_status_.hash = roaming_candidate_.policy_hash;
  } else {
    if (!config::DecodeConfigPayload(payload_.data(), payload_size_,
                                     &candidate_)) {
      return Status::kInvalidConfig;
    }
    if (candidate_.device_id != device_id_) {
      return Status::kIdentityMismatch;
    }
    const config::StorageStatus storage_status =
        effects_.Commit(candidate_, &selection);
    if (storage_status != config::StorageStatus::kOk ||
        selection.state != config::ConfigState::kReady) {
      return Status::kCommitFailed;
    }
    provisioning_key_ = candidate_.provisioning_key;
  }
  current_generation_ = selection.generation;
  (*response)[protocol::kProvisioningCommitSlotOffset] =
      static_cast<std::uint8_t>(selection.slot);
  for (std::size_t index = 0; index < 8; ++index) {
    (*response)[protocol::kProvisioningCommitGenerationOffset + index] =
        static_cast<std::uint8_t>(selection.generation >> (index * 8));
  }
  ClearTransaction(true);
  return Status::kOk;
}

Status Session::ReportPolicyStatus(
    const std::array<std::uint8_t, kReportBytes>& request,
    std::array<std::uint8_t, kReportBytes>* response) {
  ClearTransaction(true);
  if (!AllZero(request.data() + protocol::kProvisioningRequestOperationOffset + 1,
               request.size() - protocol::kProvisioningRequestOperationOffset - 1)) {
    return Status::kBadReport;
  }
  (*response)[protocol::kProvisioningPolicyStatusStateOffset] =
      static_cast<std::uint8_t>(policy_status_.state);
  PutU64(response->data() + protocol::kProvisioningPolicyStatusEpochOffset,
         policy_status_.epoch);
  PutU64(response->data() + protocol::kProvisioningPolicyStatusSequenceOffset,
         policy_status_.sequence);
  std::copy(policy_status_.hash.begin(), policy_status_.hash.end(),
            response->begin() + protocol::kProvisioningPolicyStatusHashOffset);
  return Status::kOk;
}

void Session::ClearTransaction(const bool clear_challenge) {
  SecureClear(payload_.data(), payload_.size());
  SecureClear(&candidate_, sizeof(candidate_));
  SecureClear(&roaming_candidate_, sizeof(roaming_candidate_));
  SecureClear(transaction_id_.data(), transaction_id_.size());
  received_ = 0;
  transaction_active_ = false;
  if (clear_challenge) {
    SecureClear(challenge_.data(), challenge_.size());
    challenge_active_ = false;
    deadline_active_ = false;
    last_activity_ms_ = 0;
  }
}

bool Session::Expire(const std::uint64_t now_ms) {
  if (!deadline_active_ ||
      now_ms - last_activity_ms_ < kTransactionIdleTimeoutMs) {
    return false;
  }
  ClearTransaction(true);
  return true;
}

void Session::MarkActivity(const std::uint64_t now_ms) {
  last_activity_ms_ = now_ms;
  deadline_active_ = true;
}

void Session::TransportLost() { ClearTransaction(true); }

void Session::Reset() { ClearTransaction(true); }

}  // namespace keyferry::provisioning
