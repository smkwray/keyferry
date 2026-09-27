#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry_protocol_generated.h"

namespace keyferry::protocol {

constexpr std::uint8_t kGatewayHandoffSchema = 1;

enum class GatewayHandoffCodecError : std::uint8_t {
  kOk = 0,
  kWrongLength,
  kUnsupportedSchema,
  kUnsupportedOperation,
  kZeroIdentifier,
  kInvalidAddress,
  kInvalidPort,
  kInvalidBudget,
};

struct GatewayHandoffRequest {
  GatewayHandoffOperation operation{GatewayHandoffOperation::kQuery};
  std::array<std::uint8_t, 16> transaction_id{};
  std::array<std::uint8_t, 16> target_installation_id{};
  std::array<std::uint8_t, 16> readiness_nonce{};
  std::array<std::uint8_t, 32> proof_digest{};
  std::array<std::uint8_t, 4> target_ipv4{};
  std::uint16_t target_port{};
  std::uint32_t target_valid_ms{};
  std::uint32_t recovery_ms{};
};

struct GatewayHandoffStatusPayload {
  GatewayHandoffOperation reply_operation{GatewayHandoffOperation::kQuery};
  GatewayHandoffStatus status{GatewayHandoffStatus::kOk};
  std::array<std::uint8_t, 16> transaction_id{};
  GatewayHandoffPhase phase{GatewayHandoffPhase::kUnknown};
  GatewayHandoffReason reason{GatewayHandoffReason::kNone};
  std::uint32_t remaining_phase_ms{};
  std::uint32_t remaining_recovery_ms{};
  std::array<std::uint8_t, 16> target_installation_id{};
  std::array<std::uint8_t, 16> previous_installation_id{};
  std::array<std::uint8_t, 16> device_boot_nonce{};
  std::array<std::uint8_t, 16> current_endpoint_session{};
};

GatewayHandoffCodecError DecodeGatewayHandoffRequest(
    const std::uint8_t* payload, std::size_t payload_length,
    GatewayHandoffRequest* output);

GatewayHandoffCodecError EncodeGatewayHandoffStatus(
    const GatewayHandoffStatusPayload& input, std::uint8_t* output,
    std::size_t output_capacity, std::size_t* output_length);

}  // namespace keyferry::protocol
