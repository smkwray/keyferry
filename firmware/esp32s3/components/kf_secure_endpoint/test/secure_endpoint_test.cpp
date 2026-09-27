#include "keyferry/secure_endpoint.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace {

#undef assert
#define assert(condition)                                                          \
  do {                                                                             \
    if (!(condition)) {                                                            \
      std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,    \
                   #condition);                                                    \
      std::exit(1);                                                                \
    }                                                                              \
  } while (false)

using keyferry::endpoint::Effects;
using keyferry::endpoint::EndpointSession;
using keyferry::endpoint::FirmwareIdentity;
using keyferry::endpoint::PeerKeyAlgorithm;
using keyferry::endpoint::SessionReady;
using keyferry::endpoint::TlsClientPolicy;
using keyferry::endpoint::TlsObservation;
using keyferry::protocol::DecodedFrame;
using keyferry::protocol::MessageType;

void WriteLe32(std::uint8_t* output, std::uint32_t value) {
  output[0] = static_cast<std::uint8_t>(value);
  output[1] = static_cast<std::uint8_t>(value >> 8);
  output[2] = static_cast<std::uint8_t>(value >> 16);
  output[3] = static_cast<std::uint8_t>(value >> 24);
}

std::uint32_t ReadLe32(const std::uint8_t* input) {
  return static_cast<std::uint32_t>(input[0]) |
         (static_cast<std::uint32_t>(input[1]) << 8) |
         (static_cast<std::uint32_t>(input[2]) << 16) |
         (static_cast<std::uint32_t>(input[3]) << 24);
}

std::vector<std::uint8_t> Frame(MessageType type, std::uint32_t sequence,
                                const std::vector<std::uint8_t>& payload) {
  std::array<std::uint8_t, keyferry::endpoint::kMaxWireFrame> output{};
  std::size_t output_length = 0;
  assert(keyferry::protocol::EncodeWireFrame(
             keyferry::protocol::kMajor, keyferry::protocol::kMinor,
             static_cast<std::uint8_t>(type), 0, sequence, payload.data(), payload.size(),
             output.data(), output.size(), &output_length) ==
         keyferry::protocol::CodecError::kOk);
  return {output.begin(), output.begin() + static_cast<std::ptrdiff_t>(output_length)};
}

DecodedFrame Decode(const std::vector<std::uint8_t>& wire,
                    std::array<std::uint8_t, keyferry::protocol::kMaxDecodedFrame>& scratch) {
  DecodedFrame frame{};
  assert(keyferry::protocol::DecodeWireFrame(wire.data(), wire.size(), scratch.data(),
                                             scratch.size(), &frame) ==
         keyferry::protocol::CodecError::kOk);
  return frame;
}

class FakeEffects final : public Effects {
 public:
  void FailClosed(std::uint64_t epoch) override {
    ++fail_closed_count;
    last_epoch = epoch;
    armed = false;
  }

  bool FillRandom(std::uint8_t* output, std::size_t length) override {
    if (!random_ok) {
      return false;
    }
    for (std::size_t index = 0; index < length; ++index) {
      output[index] = static_cast<std::uint8_t>(0x80 + index);
    }
    return true;
  }

  bool HmacSha256(const std::uint8_t host_id[16], const std::uint8_t* input,
                  std::size_t input_length, std::uint8_t output[32]) override {
    if (!hmac_ok) {
      return false;
    }
    captured_host.assign(host_id, host_id + 16);
    captured_hmac_input.assign(input, input + input_length);
    for (std::size_t index = 0; index < 32; ++index) {
      output[index] = static_cast<std::uint8_t>(0x40 + index);
    }
    return true;
  }

  bool SendTls(const std::uint8_t* data, std::size_t length) override {
    if (!send_ok) {
      return false;
    }
    sent.assign(data, data + length);
    ++send_count;
    return true;
  }

  bool SessionAuthenticated(std::uint64_t epoch, const SessionReady& ready) override {
    ++authenticated_count;
    last_epoch = epoch;
    last_ready = ready;
    return authenticate_ok;
  }

  bool CommandScopedArm(std::uint64_t epoch,
                        std::uint32_t next_command_sequence) override {
    last_epoch = epoch;
    next_sequence = next_command_sequence;
    armed = true;
    ++arm_count;
    return arm_ok;
  }

  bool Disarm(std::uint64_t epoch) override {
    last_epoch = epoch;
    armed = false;
    ++disarm_count;
    return disarm_ok;
  }

  bool DisarmComplete(std::uint64_t epoch) override {
    last_epoch = epoch;
    return disarm_complete;
  }

  bool BuildRouteProof(
      std::uint64_t epoch, const std::uint8_t controller_id[16],
      const std::uint8_t controller_nonce[32],
      std::uint8_t output[keyferry::protocol::kRoamingRouteProofResponseBytes])
      override {
    last_epoch = epoch;
    captured_route_controller.assign(controller_id, controller_id + 16);
    captured_route_nonce.assign(controller_nonce, controller_nonce + 32);
    if (!route_proof_ok) {
      return false;
    }
    for (std::size_t index = 0;
         index < keyferry::protocol::kRoamingRouteProofResponseBytes; ++index) {
      output[index] = static_cast<std::uint8_t>(index + 1);
    }
    return true;
  }

  bool HandleGatewayHandoff(
      std::uint64_t epoch,
      const keyferry::protocol::GatewayHandoffRequest& request,
      keyferry::protocol::GatewayHandoffStatusPayload* status,
      bool* defer_reply) override {
    last_epoch = epoch;
    if (!gateway_handoff_ok || status == nullptr || defer_reply == nullptr) {
      return false;
    }
    captured_handoff = request;
    status->reply_operation = request.operation;
    status->status = keyferry::protocol::GatewayHandoffStatus::kOk;
    status->transaction_id = request.transaction_id;
    status->phase = keyferry::protocol::GatewayHandoffPhase::kTargeting;
    *defer_reply = gateway_handoff_deferred;
    return true;
  }

  bool ServiceGatewayHandoff(
      std::uint64_t epoch,
      keyferry::protocol::GatewayHandoffStatusPayload* status,
      bool* reply_ready) override {
    last_epoch = epoch;
    if (status == nullptr || reply_ready == nullptr) {
      return false;
    }
    status->reply_operation = captured_handoff.operation;
    status->status = keyferry::protocol::GatewayHandoffStatus::kOk;
    status->transaction_id = captured_handoff.transaction_id;
    status->phase = keyferry::protocol::GatewayHandoffPhase::kTargeting;
    *reply_ready = gateway_handoff_reply_ready;
    return true;
  }

  void GatewayHandoffReplySent(
      std::uint64_t epoch,
      keyferry::protocol::GatewayHandoffOperation operation) override {
    last_epoch = epoch;
    last_handoff_reply = operation;
    ++handoff_reply_count;
  }

  bool AuthenticatedFrame(std::uint64_t epoch, const DecodedFrame& frame) override {
    last_epoch = epoch;
    last_forwarded_type = frame.message_type;
    ++forwarded_count;
    return forward_ok;
  }

  bool random_ok{true};
  bool hmac_ok{true};
  bool send_ok{true};
  bool authenticate_ok{true};
  bool arm_ok{true};
  bool disarm_ok{true};
  bool disarm_complete{false};
  bool route_proof_ok{true};
  bool gateway_handoff_ok{true};
  bool gateway_handoff_deferred{false};
  bool gateway_handoff_reply_ready{false};
  bool forward_ok{true};
  bool armed{false};
  std::size_t fail_closed_count{0};
  std::size_t authenticated_count{0};
  std::size_t arm_count{0};
  std::size_t disarm_count{0};
  std::size_t forwarded_count{0};
  std::size_t send_count{0};
  std::size_t handoff_reply_count{0};
  std::uint64_t last_epoch{0};
  std::uint32_t next_sequence{0};
  std::uint8_t last_forwarded_type{0};
  keyferry::protocol::GatewayHandoffOperation last_handoff_reply{
      keyferry::protocol::GatewayHandoffOperation::kQuery};
  keyferry::protocol::GatewayHandoffRequest captured_handoff{};
  SessionReady last_ready{};
  std::vector<std::uint8_t> captured_host;
  std::vector<std::uint8_t> captured_hmac_input;
  std::vector<std::uint8_t> captured_route_controller;
  std::vector<std::uint8_t> captured_route_nonce;
  std::vector<std::uint8_t> sent;
};

void TestConfigurationValidation() {
  const std::array<std::uint8_t, 4> ssid{'t', 'e', 's', 't'};
  const std::array<std::uint8_t, 8> password{'1', '2', '3', '4', '5', '6', '7', '8'};
  assert(keyferry::endpoint::ValidateWifiStation(
      {ssid.data(), ssid.size(), password.data(), password.size(),
       keyferry::endpoint::WifiAuth::kWpa2Personal, false}));
  assert(!keyferry::endpoint::ValidateWifiStation(
      {ssid.data(), ssid.size(), password.data(), 7,
       keyferry::endpoint::WifiAuth::kWpa2Personal, false}));
  assert(keyferry::endpoint::ValidateWifiStation(
      {ssid.data(), ssid.size(), nullptr, 0,
       keyferry::endpoint::WifiAuth::kOpenExplicit, true}));
  assert(!keyferry::endpoint::ValidateWifiStation(
      {ssid.data(), ssid.size(), nullptr, 0,
       keyferry::endpoint::WifiAuth::kOpenExplicit, false}));

  FirmwareIdentity identity{};
  const std::array<std::uint8_t, 5> release{'0', '.', '1', '.', '0'};
  std::copy(release.begin(), release.end(), identity.release.begin());
  identity.board_compatibility_id =
      keyferry::endpoint::kWaveshareGeekV1_1CompatibilityId;
  identity.elf_sha256.fill(0xA5);
  assert(keyferry::endpoint::ValidateFirmwareIdentity(identity));
  const auto file_bit = static_cast<std::uint32_t>(
      keyferry::protocol::Capability::kUsbFileHandoffV1);
  assert((keyferry::endpoint::FirmwareCapabilityMask(identity) & file_bit) == 0);
  identity.usb_file_handoff_v1 = true;
  assert((keyferry::endpoint::FirmwareCapabilityMask(identity) & file_bit) != 0);
  const auto file_set_bit = static_cast<std::uint32_t>(
      keyferry::protocol::Capability::kUsbFileSetV2);
  assert((keyferry::endpoint::FirmwareCapabilityMask(identity) & file_set_bit) == 0);
  identity.usb_file_set_v2 = true;
  assert((keyferry::endpoint::FirmwareCapabilityMask(identity) & file_set_bit) != 0);
  const auto screen_bit = static_cast<std::uint32_t>(
      keyferry::protocol::Capability::kScreenPowerV1);
  assert((keyferry::endpoint::FirmwareCapabilityMask(identity) & screen_bit) == 0);
  identity.screen_power_v1 = true;
  assert((keyferry::endpoint::FirmwareCapabilityMask(identity) & screen_bit) != 0);
  identity.release[5] = '+';
  assert(!keyferry::endpoint::ValidateFirmwareIdentity(identity));
  identity.release[5] = 0;
  identity.board_compatibility_id =
      keyferry::endpoint::kLilygoTDongleS3CompatibilityId;
  assert(keyferry::endpoint::ValidateFirmwareIdentity(identity));
  identity.board_compatibility_id = 3;
  assert(!keyferry::endpoint::ValidateFirmwareIdentity(identity));
}

void TestHandshakeAndControlBoundary() {
  std::array<std::uint8_t, 16> device_id{};
  for (std::size_t index = 0; index < device_id.size(); ++index) {
    device_id[index] = static_cast<std::uint8_t>(0x20 + index);
  }
  TlsClientPolicy policy{};
  policy.server_name = "controller.invalid";
  policy.server_name_length = 18;
  policy.port = 4433;
  policy.peer_spki_sha256.fill(0xA5);
  assert(keyferry::endpoint::ValidateTlsPolicy(policy));

  FakeEffects effects;
  FirmwareIdentity identity{};
  const std::array<std::uint8_t, 5> release{'0', '.', '1', '.', '0'};
  std::copy(release.begin(), release.end(), identity.release.begin());
  identity.board_compatibility_id =
      keyferry::endpoint::kWaveshareGeekV1_1CompatibilityId;
  identity.mouse_relative_v1 = true;
  identity.ble_hid_output_v1 = true;
  identity.targeted_gateway_transfer_v1 = true;
  identity.local_management_v1 = true;
  for (std::size_t index = 0; index < identity.elf_sha256.size(); ++index) {
    identity.elf_sha256[index] = static_cast<std::uint8_t>(index + 1);
  }
  EndpointSession session(device_id, effects, identity);
  session.Boot();
  assert(session.epoch() == 1 && effects.fail_closed_count == 1 && !session.authenticated());

  TlsObservation tls{keyferry::endpoint::kTls12Version,
                     keyferry::endpoint::kRequiredCipherSuite,
                     PeerKeyAlgorithm::kEcdsaP256, policy.peer_spki_sha256};
  TlsObservation wrong = tls;
  wrong.cipher_suite = 0x1301;
  assert(!session.BeginTls(policy, wrong));
  assert(session.epoch() == 2 && effects.fail_closed_count == 2);
  assert(session.BeginTls(policy, tls));
  assert(session.epoch() == 3 && effects.fail_closed_count == 3);

  std::vector<std::uint8_t> challenge(66);
  for (std::size_t index = 0; index < 64; ++index) {
    challenge[index] = static_cast<std::uint8_t>(index + 1);
  }
  challenge[64] = keyferry::protocol::kMajor;
  challenge[65] = keyferry::protocol::kMinor;
  const std::vector<std::uint8_t> challenge_wire = Frame(MessageType::kAuthChallenge, 0, challenge);
  const std::size_t split = challenge_wire.size() / 2;
  assert(session.ConsumeTls(challenge_wire.data(), split));
  assert(session.ConsumeTls(challenge_wire.data() + split, challenge_wire.size() - split));

  assert(effects.captured_host == std::vector<std::uint8_t>(challenge.begin(),
                                                            challenge.begin() + 16));
  assert(effects.captured_hmac_input.size() == 131);
  const std::array<std::uint8_t, 17> domain{
      'h', 'i', 'd', 'b', 'r', 'i', 'd', 'g', 'e', '-', 'a', 'u', 't', 'h', '-', 'v', '1'};
  std::vector<std::uint8_t> expected_hmac_input;
  expected_hmac_input.insert(expected_hmac_input.end(), domain.begin(), domain.end());
  expected_hmac_input.insert(expected_hmac_input.end(), challenge.begin(), challenge.begin() + 16);
  expected_hmac_input.insert(expected_hmac_input.end(), device_id.begin(), device_id.end());
  expected_hmac_input.insert(expected_hmac_input.end(), challenge.begin() + 16,
                             challenge.begin() + 64);
  for (std::size_t index = 0; index < 32; ++index) {
    expected_hmac_input.push_back(static_cast<std::uint8_t>(0x80 + index));
  }
  expected_hmac_input.insert(expected_hmac_input.end(), challenge.begin() + 64, challenge.end());
  assert(effects.captured_hmac_input == expected_hmac_input);

  std::array<std::uint8_t, keyferry::protocol::kMaxDecodedFrame> scratch{};
  DecodedFrame response = Decode(effects.sent, scratch);
  assert(response.message_type == static_cast<std::uint8_t>(MessageType::kAuthResponse));
  assert(response.sequence == 0 && response.payload_length == 80);
  assert(std::equal(device_id.begin(), device_id.end(), response.payload));
  for (std::size_t index = 0; index < 32; ++index) {
    assert(response.payload[16 + index] == static_cast<std::uint8_t>(0x80 + index));
    assert(response.payload[48 + index] == static_cast<std::uint8_t>(0x40 + index));
  }

  std::vector<std::uint8_t> ready(34);
  for (std::size_t index = 0; index < 16; ++index) {
    ready[index] = static_cast<std::uint8_t>(0xC0 + index);
  }
  ready[16] = keyferry::protocol::kMajor;
  ready[17] = keyferry::protocol::kMinor;
  WriteLe32(ready.data() + 18,
            static_cast<std::uint32_t>(keyferry::protocol::Capability::kKeyboard) |
                static_cast<std::uint32_t>(
                    keyferry::protocol::Capability::kFirmwareIdentityV1));
  WriteLe32(ready.data() + 22, 45000);
  WriteLe32(ready.data() + 26, 10000);
  WriteLe32(ready.data() + 30, 500);
  const std::vector<std::uint8_t> ready_wire = Frame(MessageType::kSessionReady, 1, ready);
  assert(session.ConsumeTls(ready_wire.data(), ready_wire.size()));
  assert(session.authenticated() && effects.authenticated_count == 1 && !effects.armed);
  DecodedFrame identity_response = Decode(effects.sent, scratch);
  assert(identity_response.message_type ==
         static_cast<std::uint8_t>(MessageType::kCapabilities));
  assert(identity_response.sequence == 1 &&
         identity_response.payload_length ==
             keyferry::endpoint::kFirmwareIdentityPayloadBytes);
  assert(identity_response.payload[0] == 1);
  assert(ReadLe32(identity_response.payload + 1) ==
         (static_cast<std::uint32_t>(
              keyferry::protocol::Capability::kKeyboard) |
          static_cast<std::uint32_t>(
              keyferry::protocol::Capability::kFirmwareIdentityV1) |
          static_cast<std::uint32_t>(
              keyferry::protocol::Capability::kMouseRelativeV1) |
          static_cast<std::uint32_t>(
              keyferry::protocol::Capability::kBleHidOutputV1) |
          static_cast<std::uint32_t>(
              keyferry::protocol::Capability::kTargetedGatewayTransferV1) |
          static_cast<std::uint32_t>(
              keyferry::protocol::Capability::kLocalManagementV1)));
  assert(std::equal(release.begin(), release.end(), identity_response.payload + 8));
  assert(identity_response.payload[40] == 1 && identity_response.payload[44] == 1);
  assert(std::equal(identity.elf_sha256.begin(), identity.elf_sha256.end(),
                    identity_response.payload + 45));

  effects.sent.clear();
  std::vector<std::uint8_t> route_request(48);
  for (std::size_t index = 0; index < route_request.size(); ++index) {
    route_request[index] = static_cast<std::uint8_t>(0x30 + index);
  }
  const auto route_wire =
      Frame(MessageType::kRouteProofRequest, 2, route_request);
  assert(session.ConsumeTls(route_wire.data(), route_wire.size()));
  DecodedFrame route_response = Decode(effects.sent, scratch);
  assert(route_response.message_type ==
         static_cast<std::uint8_t>(MessageType::kRouteProofResponse));
  assert(route_response.sequence == 2 &&
         route_response.payload_length ==
             keyferry::protocol::kRoamingRouteProofResponseBytes);
  assert(effects.captured_route_controller ==
         std::vector<std::uint8_t>(route_request.begin(),
                                   route_request.begin() + 16));
  assert(effects.captured_route_nonce ==
         std::vector<std::uint8_t>(route_request.begin() + 16,
                                   route_request.end()));

  effects.sent.clear();
  const std::vector<std::uint8_t> bad_arm_payload{0x02, 1, 0, 0, 0};
  const std::vector<std::uint8_t> bad_arm = Frame(MessageType::kArm, 3, bad_arm_payload);
  assert(session.ConsumeTls(bad_arm.data(), bad_arm.size()));
  DecodedFrame error = Decode(effects.sent, scratch);
  assert(error.message_type == static_cast<std::uint8_t>(MessageType::kError));
  assert(error.sequence == 3 && error.payload_length == 2);
  assert(error.payload[0] == 0x09 && error.payload[1] == 0x00);
  assert(!effects.armed && effects.arm_count == 0);

  effects.sent.clear();
  const std::vector<std::uint8_t> arm_payload{0x01, 0, 0, 0, 0};
  const std::vector<std::uint8_t> arm = Frame(MessageType::kArm, 4, arm_payload);
  assert(session.ConsumeTls(arm.data(), arm.size()));
  DecodedFrame ack = Decode(effects.sent, scratch);
  assert(ack.message_type == static_cast<std::uint8_t>(MessageType::kAck));
  assert(ack.sequence == 4 && ack.payload_length == 3);
  assert(ack.payload[0] == static_cast<std::uint8_t>(MessageType::kArm));
  assert(ack.payload[1] == 0 && ack.payload[2] == 0);
  assert(effects.armed && effects.arm_count == 1);
  assert(effects.next_sequence == 5);

  effects.sent.clear();
  const std::vector<std::uint8_t> disarm = Frame(MessageType::kDisarm, 5, {});
  assert(session.ConsumeTls(disarm.data(), disarm.size()));
  assert(!effects.armed && effects.disarm_count == 1);
  assert(effects.sent.empty());
  assert(session.Service());
  assert(effects.sent.empty());
  effects.disarm_complete = true;
  assert(session.Service());
  ack = Decode(effects.sent, scratch);
  assert(ack.message_type == static_cast<std::uint8_t>(MessageType::kAck));
  assert(ack.sequence == 5 && ack.payload_length == 3);
  assert(ack.payload[0] == static_cast<std::uint8_t>(MessageType::kDisarm));

  effects.sent.clear();
  std::vector<std::uint8_t> handoff_query(
      keyferry::protocol::kRoamingGatewayHandoffQueryPayloadBytes);
  handoff_query[0] = keyferry::protocol::kGatewayHandoffSchema;
  handoff_query[1] = static_cast<std::uint8_t>(
      keyferry::protocol::GatewayHandoffOperation::kQuery);
  std::fill(handoff_query.begin() + 2, handoff_query.end(), std::uint8_t{0x19});
  const auto query_wire =
      Frame(MessageType::kGatewayHandoff, 6, handoff_query);
  assert(session.ConsumeTls(query_wire.data(), query_wire.size()));
  const auto query_response = Decode(effects.sent, scratch);
  assert(query_response.message_type ==
         static_cast<std::uint8_t>(MessageType::kGatewayHandoffStatus));
  assert(query_response.sequence == 6 &&
         query_response.payload_length ==
             keyferry::protocol::kRoamingGatewayHandoffStatusPayloadBytes);
  assert(effects.handoff_reply_count == 1 &&
         effects.last_handoff_reply ==
             keyferry::protocol::GatewayHandoffOperation::kQuery);

  effects.sent.clear();
  // The secure endpoint rejects malformed V2 shapes before the runtime can
  // dereference BEGIN fields or accept an overlong CHUNK.
  const auto short_begin = Frame(MessageType::kFileSetRequest, 7, {1, 0});
  assert(session.ConsumeTls(short_begin.data(), short_begin.size()));
  assert(Decode(effects.sent, scratch).message_type ==
         static_cast<std::uint8_t>(MessageType::kError));
  assert(effects.forwarded_count == 0);
  const auto long_chunk = Frame(MessageType::kFileSetRequest, 8,
                                std::vector<std::uint8_t>(206, 2));
  assert(session.ConsumeTls(long_chunk.data(), long_chunk.size()));
  assert(Decode(effects.sent, scratch).message_type ==
         static_cast<std::uint8_t>(MessageType::kError));
  assert(effects.forwarded_count == 0);
  const std::vector<std::uint8_t> command = Frame(MessageType::kCommand, 9, {});
  assert(session.ConsumeTls(command.data(), command.size()));
  assert(effects.forwarded_count == 1 &&
         effects.last_forwarded_type == static_cast<std::uint8_t>(MessageType::kCommand));

  const std::uint64_t authenticated_epoch = session.epoch();
  assert(!session.ConsumeTls(command.data(), command.size()));
  assert(!session.authenticated() && !effects.armed);
  assert(session.epoch() == authenticated_epoch + 1);
  const auto failed_epoch = session.epoch();
  const auto fail_closed_count = effects.fail_closed_count;
  session.TransportFault();
  session.TransportFault();
  assert(session.epoch() == failed_epoch);
  assert(effects.fail_closed_count == fail_closed_count);
}

void TestMalformedAndOversizeFailClosed() {
  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(1);
  TlsClientPolicy policy{"controller.invalid", 18, 4433, {}};
  policy.peer_spki_sha256.fill(2);
  FakeEffects effects;
  EndpointSession session(device_id, effects);
  TlsObservation tls{keyferry::endpoint::kTls12Version,
                     keyferry::endpoint::kRequiredCipherSuite,
                     PeerKeyAlgorithm::kEcdsaP256, policy.peer_spki_sha256};
  assert(session.BeginTls(policy, tls));
  const std::uint8_t empty_frame = 0;
  assert(!session.ConsumeTls(&empty_frame, 1));
  const std::uint64_t malformed_epoch = session.epoch();

  assert(session.BeginTls(policy, tls));
  std::array<std::uint8_t, keyferry::endpoint::kMaxWireFrame + 1> oversized{};
  oversized.fill(1);
  assert(!session.ConsumeTls(oversized.data(), oversized.size()));
  assert(session.epoch() == malformed_epoch + 2);
}

void TestHandshakeSequenceAndEpochOverflow() {
  std::uint64_t next = 0;
  assert(keyferry::endpoint::NextEpoch(0, &next) && next == 1);
  assert(keyferry::endpoint::NextEpoch(UINT64_MAX - 1, &next) && next == UINT64_MAX);
  assert(!keyferry::endpoint::NextEpoch(UINT64_MAX, &next));
  assert(!keyferry::endpoint::NextEpoch(0, nullptr));

  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(1);
  TlsClientPolicy policy{"controller.invalid", 18, 4433, {}};
  policy.peer_spki_sha256.fill(2);
  FakeEffects effects;
  EndpointSession session(device_id, effects);
  TlsObservation tls{keyferry::endpoint::kTls12Version,
                     keyferry::endpoint::kRequiredCipherSuite,
                     PeerKeyAlgorithm::kEcdsaP256, policy.peer_spki_sha256};
  assert(session.BeginTls(policy, tls));
  std::vector<std::uint8_t> challenge(66, 1);
  challenge[64] = keyferry::protocol::kMajor;
  challenge[65] = keyferry::protocol::kMinor;
  const std::vector<std::uint8_t> wrong_sequence =
      Frame(MessageType::kAuthChallenge, 7, challenge);
  assert(!session.ConsumeTls(wrong_sequence.data(), wrong_sequence.size()));
  assert(!session.authenticated());
}

}  // namespace

int main() {
  std::puts("test: configuration");
  std::fflush(stdout);
  TestConfigurationValidation();
  std::puts("test: handshake-control");
  std::fflush(stdout);
  TestHandshakeAndControlBoundary();
  std::puts("test: malformed-oversize");
  std::fflush(stdout);
  TestMalformedAndOversizeFailClosed();
  std::puts("test: sequence-epoch");
  std::fflush(stdout);
  TestHandshakeSequenceAndEpochOverflow();
  std::puts("secure_endpoint_test: ok");
  return 0;
}
