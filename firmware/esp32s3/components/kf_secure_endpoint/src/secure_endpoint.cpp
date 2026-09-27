#include "keyferry/secure_endpoint.h"

#include <algorithm>
#include <array>
#include <cstring>

#include "keyferry_protocol_generated.h"

namespace keyferry::endpoint {

std::uint32_t FirmwareCapabilityMask(const FirmwareIdentity& identity) {
  return static_cast<std::uint32_t>(protocol::Capability::kKeyboard) |
         static_cast<std::uint32_t>(protocol::Capability::kFirmwareIdentityV1) |
         (identity.mouse_relative_v1
              ? static_cast<std::uint32_t>(protocol::Capability::kMouseRelativeV1)
              : 0U) |
         (identity.ble_hid_output_v1
              ? static_cast<std::uint32_t>(protocol::Capability::kBleHidOutputV1)
              : 0U) |
         (identity.ble_hid_bond_reset_v1
              ? static_cast<std::uint32_t>(protocol::Capability::kBleHidBondResetV1)
              : 0U) |
         (identity.targeted_gateway_transfer_v1
              ? static_cast<std::uint32_t>(
                    protocol::Capability::kTargetedGatewayTransferV1)
              : 0U) |
         (identity.display_orientation_v1
              ? static_cast<std::uint32_t>(
                    protocol::Capability::kDisplayOrientationV1)
              : 0U) |
         (identity.screen_power_v1
              ? static_cast<std::uint32_t>(
                    protocol::Capability::kScreenPowerV1)
              : 0U) |
         (identity.local_management_v1
              ? static_cast<std::uint32_t>(
                    protocol::Capability::kLocalManagementV1)
              : 0U) |
         (identity.usb_file_handoff_v1
              ? static_cast<std::uint32_t>(
                    protocol::Capability::kUsbFileHandoffV1)
              : 0U) |
         (identity.usb_file_set_v2
              ? static_cast<std::uint32_t>(protocol::Capability::kUsbFileSetV2)
              : 0U);
}
namespace {

constexpr std::array<std::uint8_t, 17> kAuthDomain{
    'h', 'i', 'd', 'b', 'r', 'i', 'd', 'g', 'e', '-', 'a', 'u', 't', 'h', '-', 'v', '1'};
constexpr std::size_t kChallengeLength = 66;
constexpr std::size_t kResponseLength = 80;
constexpr std::size_t kSessionReadyLength = 34;
constexpr std::size_t kRouteProofRequestLength = 48;
constexpr std::uint8_t kCommandScopedPolicy = 0x01;
constexpr std::uint16_t kStatusOk = 0;
constexpr std::uint8_t kFirmwareIdentitySchema = 1;
constexpr std::uint8_t kEspAppElfSha256Digest = 1;

std::uint32_t ReadLe32(const std::uint8_t* input) {
  return static_cast<std::uint32_t>(input[0]) |
         (static_cast<std::uint32_t>(input[1]) << 8) |
         (static_cast<std::uint32_t>(input[2]) << 16) |
         (static_cast<std::uint32_t>(input[3]) << 24);
}

void WriteLe16(std::uint8_t* output, std::uint16_t value) {
  output[0] = static_cast<std::uint8_t>(value);
  output[1] = static_cast<std::uint8_t>(value >> 8);
}

bool ConstantTimeEqual(const std::uint8_t* left, const std::uint8_t* right,
                       std::size_t length) {
  std::uint8_t difference = 0;
  for (std::size_t index = 0; index < length; ++index) {
    difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
  }
  return difference == 0;
}

bool AnyNonzero(const std::uint8_t* data, std::size_t length) {
  std::uint8_t combined = 0;
  for (std::size_t index = 0; index < length; ++index) {
    combined |= data[index];
  }
  return combined != 0;
}

bool ValidFileRequest(const protocol::DecodedFrame& frame) {
  if (frame.payload == nullptr || frame.payload_length == 0) {
    return false;
  }
  switch (frame.payload[0]) {
    case 1: return frame.payload_length == 37;
    case 2: return frame.payload_length >= 6 && frame.payload_length <= 205;
    case 3: case 4: case 5: return frame.payload_length == 1;
    default: return false;
  }
}

bool ValidFileSetRequest(const protocol::DecodedFrame& frame) {
  if (frame.payload == nullptr || frame.payload_length == 0) return false;
  switch (frame.payload[0]) {
    case 1: return frame.payload_length == 37;
    case 2: return frame.payload_length >= 6 && frame.payload_length <= 205;
    case 3: case 4: return frame.payload_length == 1;
    case 5: return frame.payload_length == 2;
    default: return false;
  }
}

void SecureClear(std::uint8_t* data, std::size_t length) {
  volatile std::uint8_t* output = data;
  while (length-- != 0) {
    *output++ = 0;
  }
}

}  // namespace

bool ValidateWifiStation(const WifiStationView& wifi) {
  if (wifi.ssid == nullptr || wifi.ssid_length == 0 || wifi.ssid_length > 32) {
    return false;
  }
  if (wifi.auth == WifiAuth::kWpa2Personal) {
    return wifi.credential != nullptr && wifi.credential_length >= 8 &&
           wifi.credential_length <= 63 && !wifi.open_network_approved;
  }
  return wifi.auth == WifiAuth::kOpenExplicit && wifi.credential_length == 0 &&
         wifi.open_network_approved;
}

bool ValidateTlsPolicy(const TlsClientPolicy& policy) {
  if (policy.server_name == nullptr || policy.server_name_length == 0 ||
      policy.server_name_length > 253 || policy.port == 0 ||
      !AnyNonzero(policy.peer_spki_sha256.data(), policy.peer_spki_sha256.size())) {
    return false;
  }
  for (std::size_t index = 0; index < policy.server_name_length; ++index) {
    const unsigned char value = static_cast<unsigned char>(policy.server_name[index]);
    if (value <= 0x20 || value > 0x7e) {
      return false;
    }
  }
  return true;
}

bool ValidateFirmwareIdentity(const FirmwareIdentity& identity) {
  const auto terminator = std::find(identity.release.begin(), identity.release.end(), 0);
  const bool known_board =
      identity.board_compatibility_id == kWaveshareGeekV1_1CompatibilityId ||
      identity.board_compatibility_id == kLilygoTDongleS3CompatibilityId;
  if (terminator == identity.release.begin() || terminator == identity.release.end() ||
      !known_board ||
      !AnyNonzero(identity.elf_sha256.data(), identity.elf_sha256.size())) {
    return false;
  }
  for (auto cursor = identity.release.begin(); cursor != terminator; ++cursor) {
    if (*cursor < 0x21 || *cursor > 0x7e || *cursor == '+') {
      return false;
    }
  }
  return std::all_of(terminator, identity.release.end(),
                     [](const std::uint8_t value) { return value == 0; });
}

bool NextEpoch(std::uint64_t current, std::uint64_t* next) {
  if (next == nullptr || current == UINT64_MAX) {
    return false;
  }
  *next = current + 1;
  return *next != 0;
}

EndpointSession::EndpointSession(const std::array<std::uint8_t, 16>& device_id,
                                 Effects& effects,
                                 const FirmwareIdentity firmware_identity)
    : device_id_(device_id),
      effects_(effects),
      firmware_identity_(firmware_identity) {}

void EndpointSession::Boot() { Fail(); }

bool EndpointSession::BeginTls(const TlsClientPolicy& accepted_policy,
                               const TlsObservation& observation) {
  Fail();
  if (epoch_exhausted_ || !AnyNonzero(device_id_.data(), device_id_.size()) ||
      !ValidateTlsPolicy(accepted_policy) ||
      observation.version != kTls12Version ||
      observation.cipher_suite != kRequiredCipherSuite ||
      observation.peer_key_algorithm != PeerKeyAlgorithm::kEcdsaP256 ||
      !ConstantTimeEqual(observation.peer_spki_sha256.data(),
                         accepted_policy.peer_spki_sha256.data(),
                         kSha256Length)) {
    return false;
  }
  state_ = State::kAwaitChallenge;
  return true;
}

bool EndpointSession::ConsumeTls(const std::uint8_t* data, std::size_t length) {
  if (state_ == State::kOffline || (data == nullptr && length != 0)) {
    return Fail();
  }
  for (std::size_t index = 0; index < length; ++index) {
    if (wire_length_ == wire_.size()) {
      return Fail();
    }
    wire_[wire_length_++] = data[index];
    if (data[index] != 0) {
      continue;
    }

    protocol::DecodedFrame frame{};
    const protocol::CodecError result = protocol::DecodeWireFrame(
        wire_.data(), wire_length_, decoded_.data(), decoded_.size(), &frame);
    wire_length_ = 0;
    if (result != protocol::CodecError::kOk || frame.major != protocol::kMajor ||
        frame.minor != protocol::kMinor || !HandleFrame(frame)) {
      return Fail();
    }
  }
  return true;
}

void EndpointSession::TransportFault() {
  if (state_ != State::kOffline) {
    Fail();
  }
}

bool EndpointSession::Service() {
  if (disarm_ack_pending_) {
    if (state_ != State::kAuthenticated || !effects_.DisarmComplete(epoch_)) {
      return state_ == State::kAuthenticated;
    }
    std::array<std::uint8_t, 3> payload{
        static_cast<std::uint8_t>(protocol::MessageType::kDisarm), 0, 0};
    WriteLe16(payload.data() + 1, kStatusOk);
    if (!SendReply(static_cast<std::uint8_t>(protocol::MessageType::kAck),
                   disarm_sequence_, payload.data(), payload.size())) {
      return false;
    }
    disarm_ack_pending_ = false;
    disarm_sequence_ = 0;
  }
  if (handoff_reply_pending_) {
    if (state_ != State::kAuthenticated) {
      return false;
    }
    protocol::GatewayHandoffStatusPayload status{};
    bool ready = false;
    if (!effects_.ServiceGatewayHandoff(epoch_, &status, &ready)) {
      return false;
    }
    if (!ready) {
      return true;
    }
    std::array<std::uint8_t,
               protocol::kRoamingGatewayHandoffStatusPayloadBytes>
        payload{};
    std::size_t payload_length = 0;
    if (protocol::EncodeGatewayHandoffStatus(
            status, payload.data(), payload.size(), &payload_length) !=
            protocol::GatewayHandoffCodecError::kOk ||
        !SendReply(static_cast<std::uint8_t>(
                       protocol::MessageType::kGatewayHandoffStatus),
                   handoff_sequence_, payload.data(), payload_length)) {
      return false;
    }
    handoff_reply_pending_ = false;
    handoff_sequence_ = 0;
    effects_.GatewayHandoffReplySent(epoch_, handoff_operation_);
  }
  return true;
}

bool EndpointSession::authenticated() const { return state_ == State::kAuthenticated; }

std::uint64_t EndpointSession::epoch() const { return epoch_; }

bool EndpointSession::control_reply_pending() const {
  return disarm_ack_pending_ || handoff_reply_pending_;
}

bool EndpointSession::HandleFrame(const protocol::DecodedFrame& frame) {
  switch (state_) {
    case State::kAwaitChallenge:
      return HandleChallenge(frame);
    case State::kAwaitSessionReady:
      return HandleSessionReady(frame);
    case State::kAuthenticated:
      return HandleAuthenticated(frame);
    case State::kOffline:
      return false;
  }
  return false;
}

bool EndpointSession::HandleChallenge(const protocol::DecodedFrame& frame) {
  if (frame.message_type !=
          static_cast<std::uint8_t>(protocol::MessageType::kAuthChallenge) ||
      frame.payload_length != kChallengeLength ||
      frame.sequence != 0 ||
      frame.payload[64] != protocol::kMajor || frame.payload[65] != protocol::kMinor) {
    return false;
  }

  std::array<std::uint8_t, 32> device_nonce{};
  if (!effects_.FillRandom(device_nonce.data(), device_nonce.size()) ||
      !AnyNonzero(device_nonce.data(), device_nonce.size())) {
    SecureClear(device_nonce.data(), device_nonce.size());
    return false;
  }

  std::array<std::uint8_t, 131> hmac_input{};
  std::size_t cursor = 0;
  const auto append = [&hmac_input, &cursor](const std::uint8_t* source,
                                             std::size_t source_length) {
    std::copy_n(source, source_length, hmac_input.data() + cursor);
    cursor += source_length;
  };
  append(kAuthDomain.data(), kAuthDomain.size());
  append(frame.payload, 16);
  append(device_id_.data(), device_id_.size());
  append(frame.payload + 16, 16);
  append(frame.payload + 32, 32);
  append(device_nonce.data(), device_nonce.size());
  append(frame.payload + 64, 2);

  std::array<std::uint8_t, kSha256Length> hmac{};
  if (cursor != hmac_input.size() ||
      !effects_.HmacSha256(frame.payload, hmac_input.data(), hmac_input.size(),
                           hmac.data())) {
    SecureClear(hmac_input.data(), hmac_input.size());
    SecureClear(device_nonce.data(), device_nonce.size());
    SecureClear(hmac.data(), hmac.size());
    return false;
  }

  std::array<std::uint8_t, kResponseLength> response{};
  std::copy(device_id_.begin(), device_id_.end(), response.begin());
  std::copy(device_nonce.begin(), device_nonce.end(), response.begin() + 16);
  std::copy(hmac.begin(), hmac.end(), response.begin() + 48);
  const bool sent = SendReply(
      static_cast<std::uint8_t>(protocol::MessageType::kAuthResponse), frame.sequence,
      response.data(), response.size());

  SecureClear(hmac_input.data(), hmac_input.size());
  SecureClear(device_nonce.data(), device_nonce.size());
  SecureClear(hmac.data(), hmac.size());
  SecureClear(response.data(), response.size());
  if (!sent) {
    return false;
  }
  state_ = State::kAwaitSessionReady;
  return true;
}

bool EndpointSession::HandleSessionReady(const protocol::DecodedFrame& frame) {
  if (frame.message_type !=
          static_cast<std::uint8_t>(protocol::MessageType::kSessionReady) ||
      frame.payload_length != kSessionReadyLength ||
      frame.sequence != 1 ||
      frame.payload[16] != protocol::kMajor || frame.payload[17] != protocol::kMinor) {
    return false;
  }
  SessionReady ready{};
  std::copy_n(frame.payload, ready.session_id.size(), ready.session_id.begin());
  ready.major = frame.payload[16];
  ready.minor = frame.payload[17];
  ready.capability_mask = ReadLe32(frame.payload + 18);
  ready.host_lease_ms = ReadLe32(frame.payload + 22);
  ready.renew_every_ms = ReadLe32(frame.payload + 26);
  ready.command_max_ms = ReadLe32(frame.payload + 30);
  const bool identity_requested =
      (ready.capability_mask & static_cast<std::uint32_t>(
                                   protocol::Capability::kFirmwareIdentityV1)) != 0;
  if (!AnyNonzero(ready.session_id.data(), ready.session_id.size()) ||
      ready.host_lease_ms == 0 || ready.renew_every_ms == 0 ||
      ready.renew_every_ms >= ready.host_lease_ms || ready.command_max_ms == 0 ||
      ready.command_max_ms > 5000 ||
      (identity_requested && !ValidateFirmwareIdentity(firmware_identity_)) ||
      !effects_.SessionAuthenticated(epoch_, ready)) {
    return false;
  }
  if (identity_requested) {
    std::array<std::uint8_t, kFirmwareIdentityPayloadBytes> payload{};
    payload[0] = kFirmwareIdentitySchema;
    const std::uint32_t capabilities =
        FirmwareCapabilityMask(firmware_identity_);
    payload[1] = static_cast<std::uint8_t>(capabilities);
    payload[2] = static_cast<std::uint8_t>(capabilities >> 8);
    payload[3] = static_cast<std::uint8_t>(capabilities >> 16);
    payload[4] = static_cast<std::uint8_t>(capabilities >> 24);
    payload[5] = protocol::kMajor;
    payload[6] = protocol::kMinor;
    payload[7] = protocol::kMinor;
    std::copy(firmware_identity_.release.begin(), firmware_identity_.release.end(),
              payload.begin() + 8);
    const auto board = firmware_identity_.board_compatibility_id;
    payload[40] = static_cast<std::uint8_t>(board);
    payload[41] = static_cast<std::uint8_t>(board >> 8);
    payload[42] = static_cast<std::uint8_t>(board >> 16);
    payload[43] = static_cast<std::uint8_t>(board >> 24);
    payload[44] = kEspAppElfSha256Digest;
    std::copy(firmware_identity_.elf_sha256.begin(),
              firmware_identity_.elf_sha256.end(), payload.begin() + 45);
    if (!SendReply(static_cast<std::uint8_t>(protocol::MessageType::kCapabilities),
                   frame.sequence, payload.data(), payload.size())) {
      SecureClear(payload.data(), payload.size());
      return false;
    }
    SecureClear(payload.data(), payload.size());
  }
  state_ = State::kAuthenticated;
  expected_sequence_ = 2;
  return true;
}

bool EndpointSession::HandleAuthenticated(const protocol::DecodedFrame& frame) {
  // Reject before dispatch when increment would wrap. This is more conservative than executing the
  // final sequence and then closing with an uncertain result.
  if (disarm_ack_pending_ || handoff_reply_pending_ ||
      frame.sequence != expected_sequence_ ||
      expected_sequence_ == UINT32_MAX) {
    return false;
  }
  const auto type = static_cast<protocol::MessageType>(frame.message_type);
  bool handled = false;
  if (type == protocol::MessageType::kArm) {
    if (frame.payload_length != 5) {
      handled = SendError(frame, static_cast<std::uint16_t>(protocol::ErrorCode::kMalformed));
    } else {
      const std::uint32_t lease_ms = ReadLe32(frame.payload + 1);
      if (frame.payload[0] != kCommandScopedPolicy || lease_ms != 0) {
        handled =
            SendError(frame, static_cast<std::uint16_t>(protocol::ErrorCode::kInvalidMode));
      } else {
        handled = effects_.CommandScopedArm(epoch_, frame.sequence + 1U) && SendAck(frame);
      }
    }
  } else if (type == protocol::MessageType::kDisarm) {
    if (frame.payload_length != 0) {
      handled = SendError(frame, static_cast<std::uint16_t>(protocol::ErrorCode::kMalformed));
    } else {
      handled = !disarm_ack_pending_ && effects_.Disarm(epoch_);
      if (handled) {
        disarm_ack_pending_ = true;
        disarm_sequence_ = frame.sequence;
      }
    }
  } else if (type == protocol::MessageType::kLeaseRenew) {
    if (frame.payload_length != 4) {
      handled = SendError(frame, static_cast<std::uint16_t>(protocol::ErrorCode::kMalformed));
    } else {
      handled =
          SendError(frame, static_cast<std::uint16_t>(protocol::ErrorCode::kInvalidMode));
    }
  } else if (type == protocol::MessageType::kRouteProofRequest) {
    if (frame.payload_length != kRouteProofRequestLength) {
      handled = SendError(
          frame, static_cast<std::uint16_t>(protocol::ErrorCode::kMalformed));
    } else {
      std::array<std::uint8_t,
                 protocol::kRoamingRouteProofResponseBytes>
          response{};
      const bool built = effects_.BuildRouteProof(
          epoch_, frame.payload, frame.payload + 16, response.data());
      handled = built
                    ? SendReply(static_cast<std::uint8_t>(
                                    protocol::MessageType::kRouteProofResponse),
                                frame.sequence, response.data(), response.size())
                    : SendError(frame, static_cast<std::uint16_t>(
                                           protocol::ErrorCode::kBusy));
      SecureClear(response.data(), response.size());
    }
  } else if (type == protocol::MessageType::kGatewayHandoff) {
    protocol::GatewayHandoffRequest request{};
    if (protocol::DecodeGatewayHandoffRequest(
            frame.payload, frame.payload_length, &request) !=
        protocol::GatewayHandoffCodecError::kOk) {
      handled = SendError(
          frame, static_cast<std::uint16_t>(protocol::ErrorCode::kMalformed));
    } else {
      protocol::GatewayHandoffStatusPayload status{};
      bool defer_reply = false;
      if (!firmware_identity_.targeted_gateway_transfer_v1) {
        status.reply_operation = request.operation;
        status.status = protocol::GatewayHandoffStatus::kUnsupported;
        status.transaction_id = request.transaction_id;
        status.phase = protocol::GatewayHandoffPhase::kNotStarted;
      } else if (!effects_.HandleGatewayHandoff(epoch_, request, &status,
                                                 &defer_reply)) {
        return false;
      }
      if (defer_reply) {
        handoff_reply_pending_ = true;
        handoff_sequence_ = frame.sequence;
        handoff_operation_ = request.operation;
        handled = true;
      } else {
        std::array<std::uint8_t,
                   protocol::kRoamingGatewayHandoffStatusPayloadBytes>
            payload{};
        std::size_t payload_length = 0;
        handled = protocol::EncodeGatewayHandoffStatus(
                      status, payload.data(), payload.size(),
                      &payload_length) ==
                      protocol::GatewayHandoffCodecError::kOk &&
                  SendReply(static_cast<std::uint8_t>(
                                protocol::MessageType::kGatewayHandoffStatus),
                            frame.sequence, payload.data(), payload_length);
        if (handled) {
          effects_.GatewayHandoffReplySent(epoch_, request.operation);
        }
      }
    }
  } else if (type == protocol::MessageType::kFileRequest) {
    if (!ValidFileRequest(frame)) {
      handled = SendError(frame, static_cast<std::uint16_t>(protocol::ErrorCode::kMalformed));
    } else if (!firmware_identity_.usb_file_handoff_v1) {
      handled = SendError(frame, static_cast<std::uint16_t>(protocol::ErrorCode::kInvalidMode));
    } else {
      handled = effects_.AuthenticatedFrame(epoch_, frame);
    }
  } else if (type == protocol::MessageType::kFileSetRequest) {
    if (!ValidFileSetRequest(frame)) {
      handled = SendError(frame, static_cast<std::uint16_t>(protocol::ErrorCode::kMalformed));
    } else if (!firmware_identity_.usb_file_set_v2) {
      handled = SendError(frame, static_cast<std::uint16_t>(protocol::ErrorCode::kInvalidMode));
    } else {
      handled = effects_.AuthenticatedFrame(epoch_, frame);
    }
  } else {
    handled = effects_.AuthenticatedFrame(epoch_, frame);
  }
  if (handled) {
    ++expected_sequence_;
  }
  return handled;
}

bool EndpointSession::SendReply(std::uint8_t message_type, std::uint32_t sequence,
                                const std::uint8_t* payload,
                                std::size_t payload_length) {
  std::array<std::uint8_t, kMaxWireFrame> output{};
  std::size_t output_length = 0;
  const protocol::CodecError result = protocol::EncodeWireFrame(
      protocol::kMajor, protocol::kMinor, message_type, 0, sequence, payload,
      payload_length, output.data(), output.size(), &output_length);
  const bool sent = result == protocol::CodecError::kOk &&
                    effects_.SendTls(output.data(), output_length);
  SecureClear(output.data(), output.size());
  return sent;
}

bool EndpointSession::SendAck(const protocol::DecodedFrame& frame) {
  std::array<std::uint8_t, 3> payload{frame.message_type, 0, 0};
  WriteLe16(payload.data() + 1, kStatusOk);
  return SendReply(static_cast<std::uint8_t>(protocol::MessageType::kAck), frame.sequence,
                   payload.data(), payload.size());
}

bool EndpointSession::SendError(const protocol::DecodedFrame& frame,
                                std::uint16_t error_code) {
  std::array<std::uint8_t, 2> payload{};
  WriteLe16(payload.data(), error_code);
  return SendReply(static_cast<std::uint8_t>(protocol::MessageType::kError), frame.sequence,
                   payload.data(), payload.size());
}

bool EndpointSession::Fail() {
  state_ = State::kOffline;
  ResetReceive();
  expected_sequence_ = 0;
  disarm_ack_pending_ = false;
  disarm_sequence_ = 0;
  handoff_reply_pending_ = false;
  handoff_sequence_ = 0;
  handoff_operation_ = protocol::GatewayHandoffOperation::kQuery;
  std::uint64_t next = 0;
  if (NextEpoch(epoch_, &next)) {
    epoch_ = next;
  } else {
    epoch_exhausted_ = true;
  }
  effects_.FailClosed(epoch_);
  return false;
}

void EndpointSession::ResetReceive() {
  SecureClear(wire_.data(), wire_.size());
  SecureClear(decoded_.data(), decoded_.size());
  wire_length_ = 0;
}

}  // namespace keyferry::endpoint
