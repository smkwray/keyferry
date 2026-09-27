#include "gateway_handoff_protocol.h"

#include <algorithm>

namespace keyferry::protocol {
namespace {

bool AnyNonzero(const std::uint8_t* data, const std::size_t length) {
  std::uint8_t combined = 0;
  for (std::size_t index = 0; index < length; ++index) {
    combined |= data[index];
  }
  return combined != 0;
}

std::uint16_t ReadLe16(const std::uint8_t* input) {
  return static_cast<std::uint16_t>(input[0]) |
         (static_cast<std::uint16_t>(input[1]) << 8);
}

std::uint32_t ReadLe32(const std::uint8_t* input) {
  return static_cast<std::uint32_t>(input[0]) |
         (static_cast<std::uint32_t>(input[1]) << 8) |
         (static_cast<std::uint32_t>(input[2]) << 16) |
         (static_cast<std::uint32_t>(input[3]) << 24);
}

void WriteLe16(std::uint8_t* output, const std::uint16_t value) {
  output[0] = static_cast<std::uint8_t>(value);
  output[1] = static_cast<std::uint8_t>(value >> 8);
}

void WriteLe32(std::uint8_t* output, const std::uint32_t value) {
  output[0] = static_cast<std::uint8_t>(value);
  output[1] = static_cast<std::uint8_t>(value >> 8);
  output[2] = static_cast<std::uint8_t>(value >> 16);
  output[3] = static_cast<std::uint8_t>(value >> 24);
}

template <std::size_t Size>
void Copy(std::array<std::uint8_t, Size>* output, const std::uint8_t* input) {
  std::copy_n(input, Size, output->begin());
}

bool ValidTargetAddress(const std::array<std::uint8_t, 4>& value) {
  return value != std::array<std::uint8_t, 4>{255, 255, 255, 255} &&
         value[0] != 0 && value[0] != 127 && value[0] < 224;
}

}  // namespace

GatewayHandoffCodecError DecodeGatewayHandoffRequest(
    const std::uint8_t* payload, const std::size_t payload_length,
    GatewayHandoffRequest* output) {
  if (payload == nullptr || output == nullptr || payload_length < 2) {
    return GatewayHandoffCodecError::kWrongLength;
  }
  if (payload[0] != kGatewayHandoffSchema) {
    return GatewayHandoffCodecError::kUnsupportedSchema;
  }
  const auto operation = static_cast<GatewayHandoffOperation>(payload[1]);
  std::size_t expected = 0;
  switch (operation) {
    case GatewayHandoffOperation::kStart:
      expected = kRoamingGatewayHandoffStartPayloadBytes;
      break;
    case GatewayHandoffOperation::kAccept:
      expected = kRoamingGatewayHandoffAcceptPayloadBytes;
      break;
    case GatewayHandoffOperation::kQuery:
      expected = kRoamingGatewayHandoffQueryPayloadBytes;
      break;
    default:
      return GatewayHandoffCodecError::kUnsupportedOperation;
  }
  if (payload_length != expected) {
    return GatewayHandoffCodecError::kWrongLength;
  }

  GatewayHandoffRequest decoded{};
  decoded.operation = operation;
  Copy(&decoded.transaction_id, payload + 2);
  if (!AnyNonzero(decoded.transaction_id.data(), decoded.transaction_id.size())) {
    return GatewayHandoffCodecError::kZeroIdentifier;
  }
  if (operation == GatewayHandoffOperation::kQuery) {
    *output = decoded;
    return GatewayHandoffCodecError::kOk;
  }

  Copy(&decoded.readiness_nonce, payload + 18);
  if (!AnyNonzero(decoded.readiness_nonce.data(), decoded.readiness_nonce.size())) {
    return GatewayHandoffCodecError::kZeroIdentifier;
  }
  if (operation == GatewayHandoffOperation::kAccept) {
    Copy(&decoded.proof_digest, payload + 34);
    if (!AnyNonzero(decoded.proof_digest.data(), decoded.proof_digest.size())) {
      return GatewayHandoffCodecError::kZeroIdentifier;
    }
    *output = decoded;
    return GatewayHandoffCodecError::kOk;
  }

  Copy(&decoded.target_installation_id, payload + 18);
  Copy(&decoded.readiness_nonce, payload + 34);
  Copy(&decoded.proof_digest, payload + 50);
  Copy(&decoded.target_ipv4, payload + 82);
  decoded.target_port = ReadLe16(payload + 86);
  decoded.target_valid_ms = ReadLe32(payload + 88);
  decoded.recovery_ms = ReadLe32(payload + 92);
  if (!AnyNonzero(decoded.target_installation_id.data(),
                  decoded.target_installation_id.size()) ||
      !AnyNonzero(decoded.readiness_nonce.data(), decoded.readiness_nonce.size()) ||
      !AnyNonzero(decoded.proof_digest.data(), decoded.proof_digest.size())) {
    return GatewayHandoffCodecError::kZeroIdentifier;
  }
  if (!ValidTargetAddress(decoded.target_ipv4)) {
    return GatewayHandoffCodecError::kInvalidAddress;
  }
  if (decoded.target_port != kRoamingDeviceTlsPort) {
    return GatewayHandoffCodecError::kInvalidPort;
  }
  if (decoded.target_valid_ms != kRoamingGatewayHandoffTargetValidMs ||
      decoded.recovery_ms != kRoamingGatewayHandoffRecoveryMs) {
    return GatewayHandoffCodecError::kInvalidBudget;
  }
  *output = decoded;
  return GatewayHandoffCodecError::kOk;
}

GatewayHandoffCodecError EncodeGatewayHandoffStatus(
    const GatewayHandoffStatusPayload& input, std::uint8_t* output,
    const std::size_t output_capacity, std::size_t* output_length) {
  if (output == nullptr || output_length == nullptr ||
      output_capacity < kRoamingGatewayHandoffStatusPayloadBytes) {
    return GatewayHandoffCodecError::kWrongLength;
  }
  output[0] = kGatewayHandoffSchema;
  output[1] = static_cast<std::uint8_t>(input.reply_operation);
  WriteLe16(output + 2, static_cast<std::uint16_t>(input.status));
  std::copy(input.transaction_id.begin(), input.transaction_id.end(), output + 4);
  output[20] = static_cast<std::uint8_t>(input.phase);
  output[21] = static_cast<std::uint8_t>(input.reason);
  WriteLe32(output + 22, input.remaining_phase_ms);
  WriteLe32(output + 26, input.remaining_recovery_ms);
  std::copy(input.target_installation_id.begin(), input.target_installation_id.end(),
            output + 30);
  std::copy(input.previous_installation_id.begin(),
            input.previous_installation_id.end(), output + 46);
  std::copy(input.device_boot_nonce.begin(), input.device_boot_nonce.end(), output + 62);
  std::copy(input.current_endpoint_session.begin(),
            input.current_endpoint_session.end(), output + 78);
  *output_length = kRoamingGatewayHandoffStatusPayloadBytes;
  return GatewayHandoffCodecError::kOk;
}

}  // namespace keyferry::protocol
