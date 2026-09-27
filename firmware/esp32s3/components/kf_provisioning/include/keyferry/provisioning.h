#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry/config_storage.h"
#include "keyferry/roaming_storage.h"
#include "keyferry_protocol_generated.h"

namespace keyferry::provisioning {

constexpr std::size_t kReportBytes = protocol::kProvisioningReportSize;
constexpr std::size_t kChallengeBytes = protocol::kProvisioningChallengeSize;
constexpr std::size_t kTransactionIdBytes =
    protocol::kProvisioningTransactionIdSize;
constexpr std::size_t kAuthenticationTagBytes =
    protocol::kProvisioningAuthenticationTagSize;
constexpr std::size_t kDataBytesPerReport =
    protocol::kProvisioningDataBytesPerReport;
constexpr std::uint8_t kProtocolVersion = protocol::kProvisioningVersion;
constexpr std::uint64_t kTransactionIdleTimeoutMs =
    protocol::kProvisioningIdleTimeoutMs;
constexpr auto kAuthenticationDomain =
    protocol::kProvisioningAuthenticationDomain;

using Operation = protocol::ProvisioningOperation;
using PolicyState = protocol::ProvisioningPolicyState;
using Status = protocol::ProvisioningStatus;

struct PolicyStatus {
  PolicyState state{PolicyState::kLegacy};
  std::uint64_t epoch{0};
  std::uint64_t sequence{0};
  config::PolicyHash hash{};
};

enum class PayloadFormat : std::uint8_t {
  kLegacyV1 = 1,
  kRoamingV2 = protocol::kRoamingVersion,
};

struct ByteSpan {
  const std::uint8_t* data;
  std::size_t size;
};

class Effects {
 public:
  virtual ~Effects() = default;
  virtual bool FillRandom(std::uint8_t* output, std::size_t length) = 0;
  virtual bool HmacSha256(const std::array<std::uint8_t, 32>& key,
                          const ByteSpan* parts, std::size_t part_count,
                          std::array<std::uint8_t, 32>* output) = 0;
  virtual std::uint64_t MonotonicMilliseconds() = 0;
  virtual config::StorageStatus Commit(const config::EndpointConfig& config,
                                       config::Selection* selection) = 0;
  virtual config::MigrationStatus MigrateToRoaming(
      const config::RoamingEndpointConfig& config,
      const config::RecoverySecret& recovery_secret,
      const config::RecoveryTransactionId& transaction_id) = 0;
};

class Session {
 public:
  Session(const std::array<std::uint8_t, 16>& device_id,
          const std::array<std::uint8_t, 32>& provisioning_key,
          std::uint64_t current_generation,
          Effects& effects,
          PayloadFormat format = PayloadFormat::kLegacyV1,
          PolicyStatus policy_status = {});
  ~Session();

  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  // Handles one fixed-size vendor-HID output report and always returns a
  // fixed-size, zero-padded response. No operation can emit a keyboard report.
  Status Handle(const std::array<std::uint8_t, kReportBytes>& request,
                std::array<std::uint8_t, kReportBytes>* response);
  // Timer/task integration calls this even when the host sends no reports.
  bool Expire(std::uint64_t now_ms);
  // Must be called on USB unmount, suspend, or other transport loss.
  void TransportLost();
  void Reset();

 private:
  Status Challenge(const std::array<std::uint8_t, kReportBytes>& request,
                   std::array<std::uint8_t, kReportBytes>* response);
  Status Begin(const std::array<std::uint8_t, kReportBytes>& request);
  Status Data(const std::array<std::uint8_t, kReportBytes>& request);
  Status Commit(const std::array<std::uint8_t, kReportBytes>& request,
                std::array<std::uint8_t, kReportBytes>* response);
  Status ReportPolicyStatus(
      const std::array<std::uint8_t, kReportBytes>& request,
      std::array<std::uint8_t, kReportBytes>* response);
  void ClearTransaction(bool clear_challenge);
  void MarkActivity(std::uint64_t now_ms);

  std::array<std::uint8_t, 16> device_id_{};
  std::array<std::uint8_t, 32> provisioning_key_{};
  std::uint64_t current_generation_{0};
  Effects& effects_;
  std::array<std::uint8_t, kChallengeBytes> challenge_{};
  std::array<std::uint8_t, kTransactionIdBytes> transaction_id_{};
  std::array<std::uint8_t, config::kPayloadBytes> payload_{};
  config::EndpointConfig candidate_{};
  config::RoamingEndpointConfig roaming_candidate_{};
  PayloadFormat format_{PayloadFormat::kLegacyV1};
  PolicyStatus policy_status_{};
  std::size_t payload_size_{config::kPayloadBytes};
  std::size_t received_{0};
  std::uint64_t last_activity_ms_{0};
  bool authority_valid_{false};
  bool deadline_active_{false};
  bool challenge_active_{false};
  bool transaction_active_{false};
};

}  // namespace keyferry::provisioning
