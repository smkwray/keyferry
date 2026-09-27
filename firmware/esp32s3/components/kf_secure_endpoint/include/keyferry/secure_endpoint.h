#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "frame_codec.h"
#include "gateway_handoff_protocol.h"
#include "keyferry_protocol_generated.h"

namespace keyferry::endpoint {

constexpr std::uint16_t kTls12Version = 0x0303;
constexpr std::uint16_t kRequiredCipherSuite = 0xCCA9;
constexpr std::size_t kSha256Length = 32;
constexpr std::size_t kMaxWireFrame = 259;
constexpr std::size_t kFirmwareIdentityReleaseBytes = 32;
constexpr std::size_t kFirmwareIdentityPayloadBytes = 77;
constexpr std::uint32_t kWaveshareGeekV1_1CompatibilityId = 1;
constexpr std::uint32_t kLilygoTDongleS3CompatibilityId = 2;

struct FirmwareIdentity {
  std::array<std::uint8_t, kFirmwareIdentityReleaseBytes> release{};
  std::uint32_t board_compatibility_id{};
  std::array<std::uint8_t, kSha256Length> elf_sha256{};
  bool mouse_relative_v1{};
  bool ble_hid_output_v1{};
  bool ble_hid_bond_reset_v1{};
  bool targeted_gateway_transfer_v1{};
  bool display_orientation_v1{};
  bool screen_power_v1{};
  bool local_management_v1{};
  bool usb_file_handoff_v1{};
  bool usb_file_set_v2{};
};

std::uint32_t FirmwareCapabilityMask(const FirmwareIdentity& identity);

enum class WifiAuth : std::uint8_t {
  kWpa2Personal,
  kOpenExplicit,
};

// Non-owning views. A provisioning adapter supplies these at runtime; firmware source never embeds
// credentials. The HIL skeleton intentionally supplies no usable profile.
struct WifiStationView {
  const std::uint8_t* ssid;
  std::size_t ssid_length;
  const std::uint8_t* credential;
  std::size_t credential_length;
  WifiAuth auth;
  bool open_network_approved;
};

struct TlsClientPolicy {
  const char* server_name;
  std::size_t server_name_length;
  std::uint16_t port;
  std::array<std::uint8_t, kSha256Length> peer_spki_sha256;
};

enum class PeerKeyAlgorithm : std::uint8_t {
  kUnknown,
  kEcdsaP256,
};

// Produced only after the TLS adapter has completed its handshake and hashed the authenticated
// SubjectPublicKeyInfo. No permissive or plaintext observation can satisfy this structure.
struct TlsObservation {
  std::uint16_t version;
  std::uint16_t cipher_suite;
  PeerKeyAlgorithm peer_key_algorithm;
  std::array<std::uint8_t, kSha256Length> peer_spki_sha256;
};

struct SessionReady {
  std::array<std::uint8_t, 16> session_id;
  std::uint8_t major;
  std::uint8_t minor;
  std::uint32_t capability_mask;
  std::uint32_t host_lease_ms;
  std::uint32_t renew_every_ms;
  std::uint32_t command_max_ms;
};

class Effects {
 public:
  virtual ~Effects() = default;

  // This callback owns the cross-component safety action: disarm, clear pending work, and request
  // the terminal all-zero USB report. It is invoked for every new or failed connection epoch.
  virtual void FailClosed(std::uint64_t epoch) = 0;
  virtual bool FillRandom(std::uint8_t* output, std::size_t length) = 0;
  virtual bool HmacSha256(const std::uint8_t host_id[16], const std::uint8_t* input,
                         std::size_t input_length,
                         std::uint8_t output[kSha256Length]) = 0;
  virtual bool SendTls(const std::uint8_t* data, std::size_t length) = 0;
  virtual bool SessionAuthenticated(std::uint64_t epoch, const SessionReady& ready) = 0;
  virtual bool CommandScopedArm(std::uint64_t epoch,
                                std::uint32_t next_command_sequence) = 0;
  virtual bool Disarm(std::uint64_t epoch) = 0;
  // A successful Disarm() starts the release. The ACK is withheld until this reports that the
  // all-zero USB report completed.
  virtual bool DisarmComplete(std::uint64_t epoch) = 0;
  // Produces only the fixed roaming-v2 route statement. The session layer
  // owns request validation, sequencing, framing, and the response type.
  virtual bool BuildRouteProof(
      std::uint64_t epoch,
      const std::uint8_t controller_installation_id[16],
      const std::uint8_t controller_nonce[32],
      std::uint8_t output[protocol::kRoamingRouteProofResponseBytes]) = 0;
  virtual bool HandleGatewayHandoff(
      std::uint64_t epoch,
      const protocol::GatewayHandoffRequest& request,
      protocol::GatewayHandoffStatusPayload* status,
      bool* defer_reply) = 0;
  virtual bool ServiceGatewayHandoff(
      std::uint64_t epoch,
      protocol::GatewayHandoffStatusPayload* status,
      bool* reply_ready) = 0;
  virtual void GatewayHandoffReplySent(
      std::uint64_t epoch,
      protocol::GatewayHandoffOperation operation) = 0;

  // Remote command/sequence/expiry handling is deliberately outside this component.
  // The frame and payload view are valid only for the duration of this call.
  virtual bool AuthenticatedFrame(std::uint64_t epoch,
                                  const protocol::DecodedFrame& frame) = 0;
};

bool ValidateWifiStation(const WifiStationView& wifi);
bool ValidateTlsPolicy(const TlsClientPolicy& policy);
bool ValidateFirmwareIdentity(const FirmwareIdentity& identity);
bool NextEpoch(std::uint64_t current, std::uint64_t* next);

class EndpointSession {
 public:
  EndpointSession(const std::array<std::uint8_t, 16>& device_id,
                  Effects& effects, FirmwareIdentity firmware_identity = {});

  void Boot();
  bool BeginTls(const TlsClientPolicy& accepted_policy,
                const TlsObservation& observation);
  bool ConsumeTls(const std::uint8_t* data, std::size_t length);
  bool Service();
  void TransportFault();

  bool authenticated() const;
  std::uint64_t epoch() const;
  bool control_reply_pending() const;

 private:
  enum class State : std::uint8_t {
    kOffline,
    kAwaitChallenge,
    kAwaitSessionReady,
    kAuthenticated,
  };

  bool HandleFrame(const protocol::DecodedFrame& frame);
  bool HandleChallenge(const protocol::DecodedFrame& frame);
  bool HandleSessionReady(const protocol::DecodedFrame& frame);
  bool HandleAuthenticated(const protocol::DecodedFrame& frame);
  bool SendReply(std::uint8_t message_type, std::uint32_t sequence,
                 const std::uint8_t* payload, std::size_t payload_length);
  bool SendAck(const protocol::DecodedFrame& frame);
  bool SendError(const protocol::DecodedFrame& frame, std::uint16_t error_code);
  bool Fail();
  void ResetReceive();

  std::array<std::uint8_t, 16> device_id_;
  Effects& effects_;
  FirmwareIdentity firmware_identity_;
  State state_{State::kOffline};
  std::uint64_t epoch_{0};
  bool epoch_exhausted_{false};
  std::uint32_t expected_sequence_{0};
  bool disarm_ack_pending_{false};
  std::uint32_t disarm_sequence_{0};
  bool handoff_reply_pending_{false};
  std::uint32_t handoff_sequence_{0};
  protocol::GatewayHandoffOperation handoff_operation_{
      protocol::GatewayHandoffOperation::kQuery};
  std::array<std::uint8_t, kMaxWireFrame> wire_{};
  std::size_t wire_length_{0};
  std::array<std::uint8_t, protocol::kMaxDecodedFrame> decoded_{};
};

}  // namespace keyferry::endpoint
