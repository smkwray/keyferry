#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

#include "class/hid/hid_device.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "keyferry/local_management.h"
#include "keyferry/local_management_coordinator.h"
#include "keyferry/provisioning.h"

namespace keyferry::hil {

constexpr std::uint8_t kKeyboardHidInstance = 0;
constexpr std::uint8_t kProvisioningHidInstance = 1;
constexpr std::uint8_t kMouseHidInstance = 2;
constexpr std::uint8_t kBleControlProvisioningHidInstance = 0;

class ProvisioningPolicy {
 public:
  virtual ~ProvisioningPolicy() = default;
  virtual bool EnterProvisioning(bool local_maintenance_authorized) = 0;
  virtual bool ProvisioningActive() = 0;
  virtual bool CommitAllowed() = 0;
  virtual void LeaveProvisioning() = 0;
  virtual void ProvisioningFault() = 0;
  virtual void ProvisioningCommitResponseCompleted() = 0;
};

// Bridges TinyUSB callbacks to the portable provisioning session. Callback-side
// methods never authenticate, decode, erase, write flash, restart, or touch the
// keyboard executor. Service() is called only by the application loop.
class ProvisioningAdapter final {
 public:
  ProvisioningAdapter(provisioning::Session& session,
                      provisioning::Effects& effects,
                      ProvisioningPolicy& policy,
                      std::uint8_t hid_instance,
                      local_management::Session* local_session = nullptr,
                      local_management::Coordinator* local_coordinator = nullptr);

  bool Initialize();
  void SetReport(std::uint8_t instance, std::uint8_t report_id,
                 hid_report_type_t report_type, const std::uint8_t* buffer,
                 std::uint16_t length);
  void ReportCompleted(std::uint8_t instance, std::uint16_t length);
  void ReportFailed(std::uint8_t instance);
  void TransportLost();
  void Service();

 private:
  enum class ResponseKind : std::uint8_t {
    kNone,
    kProvisioning,
    kLocalManagement,
  };

  struct Request {
    std::array<std::uint8_t, provisioning::kReportBytes> bytes{};
  };

  static bool IsLocalManagementRequest(const Request& request);
  void ResetTransport(bool fault);
  void PrepareBadStateResponse(const Request& request);
  void PrepareUnsupportedLocalResponse(const Request& request);
  void ProcessRequest(const Request& request);
  void ProcessProvisioningRequest(const Request& request);
  void ProcessLocalManagementRequest(const Request& request);
  void ServiceResponse();

  provisioning::Session& session_;
  provisioning::Effects& effects_;
  ProvisioningPolicy& policy_;
  const std::uint8_t hid_instance_;
  local_management::Session* local_session_;
  local_management::Coordinator* local_coordinator_;
  StaticQueue_t request_queue_control_{};
  std::array<std::uint8_t, sizeof(Request)> request_queue_storage_{};
  QueueHandle_t request_queue_{nullptr};
  std::atomic_bool queue_fault_{false};
  std::atomic_bool transport_lost_{false};
  std::atomic_bool response_completed_{false};
  std::atomic_bool response_failed_{false};
  std::atomic_bool response_expected_{false};
  std::array<std::uint8_t, provisioning::kReportBytes> response_{};
  bool response_pending_{false};
  bool response_in_flight_{false};
  bool terminal_response_{false};
  bool commit_response_{false};
  ResponseKind response_kind_{ResponseKind::kNone};
  local_management::OperationId local_response_operation_id_{};
  bool local_response_has_operation_id_{false};
};

}  // namespace keyferry::hil
