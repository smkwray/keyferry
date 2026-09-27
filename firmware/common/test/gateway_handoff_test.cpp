#include "gateway_handoff_protocol.h"

#include <array>
#include <cassert>
#include <cstdint>

namespace {

void WriteLe16(std::uint8_t* output, std::uint16_t value) {
  output[0] = static_cast<std::uint8_t>(value);
  output[1] = static_cast<std::uint8_t>(value >> 8);
}

void WriteLe32(std::uint8_t* output, std::uint32_t value) {
  output[0] = static_cast<std::uint8_t>(value);
  output[1] = static_cast<std::uint8_t>(value >> 8);
  output[2] = static_cast<std::uint8_t>(value >> 16);
  output[3] = static_cast<std::uint8_t>(value >> 24);
}

void TestStartAndStatus() {
  using namespace keyferry::protocol;
  std::array<std::uint8_t, kRoamingGatewayHandoffStartPayloadBytes> input{};
  input[0] = kGatewayHandoffSchema;
  input[1] = static_cast<std::uint8_t>(GatewayHandoffOperation::kStart);
  std::fill(input.begin() + 2, input.begin() + 18, std::uint8_t{0x11});
  std::fill(input.begin() + 18, input.begin() + 34, std::uint8_t{0x22});
  std::fill(input.begin() + 34, input.begin() + 50, std::uint8_t{0x33});
  std::fill(input.begin() + 50, input.begin() + 82, std::uint8_t{0x44});
  input[82] = 192;
  input[83] = 168;
  input[84] = 30;
  input[85] = 120;
  WriteLe16(input.data() + 86, kRoamingDeviceTlsPort);
  WriteLe32(input.data() + 88, kRoamingGatewayHandoffTargetValidMs);
  WriteLe32(input.data() + 92, kRoamingGatewayHandoffRecoveryMs);

  GatewayHandoffRequest decoded{};
  assert(DecodeGatewayHandoffRequest(input.data(), input.size(), &decoded) ==
         GatewayHandoffCodecError::kOk);
  assert(decoded.target_installation_id[0] == 0x22);
  const std::array<std::uint8_t, 4> expected_address{192, 168, 30, 120};
  assert(decoded.target_ipv4 == expected_address);

  GatewayHandoffStatusPayload status{};
  status.reply_operation = GatewayHandoffOperation::kStart;
  status.transaction_id = decoded.transaction_id;
  status.phase = GatewayHandoffPhase::kTargeting;
  status.remaining_phase_ms = 5500;
  std::array<std::uint8_t, kRoamingGatewayHandoffStatusPayloadBytes> encoded{};
  std::size_t length = 0;
  assert(EncodeGatewayHandoffStatus(status, encoded.data(), encoded.size(), &length) ==
         GatewayHandoffCodecError::kOk);
  assert(length == encoded.size());
  assert(encoded[0] == 1 && encoded[1] == 1 && encoded[20] == 2);
}

void TestInvalidSketchAndBudget() {
  using namespace keyferry::protocol;
  std::array<std::uint8_t, 20> sketch{};
  sketch[0] = 1;
  sketch[1] = 1;
  GatewayHandoffRequest output{};
  assert(DecodeGatewayHandoffRequest(sketch.data(), sketch.size(), &output) ==
         GatewayHandoffCodecError::kWrongLength);
}

}  // namespace

int main() {
  TestStartAndStatus();
  TestInvalidSketchAndBudget();
  return 0;
}
