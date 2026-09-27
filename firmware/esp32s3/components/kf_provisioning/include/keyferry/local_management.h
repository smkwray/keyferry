#pragma once

#include <array>
#include <cstdint>

#include "keyferry/local_management_codec.h"
#include "keyferry/provisioning.h"

namespace keyferry::local_management {

class Handler {
 public:
  virtual ~Handler() = default;
  virtual protocol::LocalManagementStatus Handle(
      const AuthenticatedRequest& request, ResponsePayload* payload,
      std::uint8_t* flags) = 0;
};

// Portable authentication and replay state. It owns no USB, network, BLE,
// storage, or input implementation and dispatches only authenticated typed
// local-management requests to Handler.
class Session final {
 public:
  Session(const std::array<std::uint8_t, 16>& device_id,
          const std::array<std::uint8_t, 32>& recovery_secret,
          std::uint32_t capabilities, provisioning::Effects& effects,
          Handler& handler);
  ~Session();

  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  protocol::LocalManagementStatus Handle(const Report& request,
                                         Report* response);
  bool Expire(std::uint64_t now_ms);
  void TransportLost();

  [[nodiscard]] bool authenticated() const { return authenticated_; }
  [[nodiscard]] std::uint32_t last_sequence() const { return last_sequence_; }

 private:
  protocol::LocalManagementStatus Challenge(const Report& request,
                                            Report* response,
                                            std::uint64_t now_ms);
  protocol::LocalManagementStatus Authenticate(const Report& request,
                                               Report* response,
                                               std::uint64_t now_ms);
  protocol::LocalManagementStatus DispatchAuthenticated(
      const Report& request, Report* response, std::uint64_t now_ms);
  bool Calculate(const std::array<std::uint8_t, 32>& key,
                 const provisioning::ByteSpan* parts, std::size_t part_count,
                 std::array<std::uint8_t, 32>* output);
  void ResetEphemeral();

  std::array<std::uint8_t, 16> device_id_{};
  std::array<std::uint8_t, 32> admin_key_{};
  std::array<std::uint8_t, 32> session_key_{};
  DeviceNonce device_nonce_{};
  SessionId session_id_{};
  std::uint32_t capabilities_{};
  provisioning::Effects& effects_;
  Handler& handler_;
  std::uint64_t started_ms_{};
  std::uint64_t last_activity_ms_{};
  std::uint32_t last_sequence_{};
  bool authority_valid_{};
  bool challenge_active_{};
  bool authenticated_{};
};

}  // namespace keyferry::local_management
