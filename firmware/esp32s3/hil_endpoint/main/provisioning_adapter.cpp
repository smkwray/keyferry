#include "provisioning_adapter.h"

#include <algorithm>
#include <cstring>

namespace keyferry::hil {
namespace {

constexpr std::uint8_t kResponseBit = 0x80;

bool IsTerminalOperation(const provisioning::Operation operation) {
  return operation == provisioning::Operation::kAbort ||
         operation == provisioning::Operation::kCommit ||
         operation == provisioning::Operation::kPolicyStatus;
}

}  // namespace

ProvisioningAdapter::ProvisioningAdapter(provisioning::Session& session,
                                         provisioning::Effects& effects,
                                         ProvisioningPolicy& policy,
                                         const std::uint8_t hid_instance,
                                         local_management::Session* local_session,
                                         local_management::Coordinator* local_coordinator)
    : session_(session),
      effects_(effects),
      policy_(policy),
      hid_instance_(hid_instance),
      local_session_(local_session),
      local_coordinator_(local_coordinator) {}

bool ProvisioningAdapter::Initialize() {
  request_queue_ = xQueueCreateStatic(
      1, sizeof(Request), request_queue_storage_.data(), &request_queue_control_);
  return request_queue_ != nullptr;
}

void ProvisioningAdapter::SetReport(const std::uint8_t instance,
                                    const std::uint8_t report_id,
                                    const hid_report_type_t report_type,
                                    const std::uint8_t* buffer,
                                    const std::uint16_t length) {
  if (instance != hid_instance_ || report_id != 0 ||
      report_type != HID_REPORT_TYPE_OUTPUT || buffer == nullptr ||
      length != provisioning::kReportBytes || request_queue_ == nullptr) {
    queue_fault_.store(true, std::memory_order_release);
    return;
  }
  Request request{};
  std::memcpy(request.bytes.data(), buffer, request.bytes.size());
  if (xQueueSend(request_queue_, &request, 0) != pdTRUE) {
    queue_fault_.store(true, std::memory_order_release);
  }
}

void ProvisioningAdapter::ReportCompleted(const std::uint8_t instance,
                                          const std::uint16_t length) {
  if (instance != hid_instance_ ||
      length != provisioning::kReportBytes ||
      !response_expected_.exchange(false, std::memory_order_acq_rel)) {
    response_failed_.store(true, std::memory_order_release);
    return;
  }
  response_completed_.store(true, std::memory_order_release);
}

void ProvisioningAdapter::ReportFailed(const std::uint8_t instance) {
  if (instance == hid_instance_) {
    response_failed_.store(true, std::memory_order_release);
  }
}

void ProvisioningAdapter::TransportLost() {
  transport_lost_.store(true, std::memory_order_release);
}

bool ProvisioningAdapter::IsLocalManagementRequest(const Request& request) {
  const auto operation = request.bytes[0];
  return operation >= static_cast<std::uint8_t>(
                          protocol::LocalManagementOperation::kChallenge) &&
         operation <= static_cast<std::uint8_t>(
                          protocol::LocalManagementOperation::kGetReceipt);
}

void ProvisioningAdapter::ResetTransport(const bool fault) {
  session_.TransportLost();
  if (local_session_ != nullptr) {
    local_session_->TransportLost();
  }
  if (local_coordinator_ != nullptr) {
    local_coordinator_->TransportLost();
  }
  if (request_queue_ != nullptr) {
    xQueueReset(request_queue_);
  }
  response_.fill(0);
  response_pending_ = false;
  response_in_flight_ = false;
  terminal_response_ = false;
  commit_response_ = false;
  response_kind_ = ResponseKind::kNone;
  local_response_operation_id_.fill(0);
  local_response_has_operation_id_ = false;
  response_completed_.store(false, std::memory_order_release);
  response_failed_.store(false, std::memory_order_release);
  response_expected_.store(false, std::memory_order_release);
  queue_fault_.store(false, std::memory_order_release);
  transport_lost_.store(false, std::memory_order_release);
  if (fault) {
    policy_.ProvisioningFault();
  } else {
    policy_.LeaveProvisioning();
  }
}

void ProvisioningAdapter::PrepareBadStateResponse(const Request& request) {
  response_.fill(0);
  response_[protocol::kProvisioningResponseOperationOffset] =
      request.bytes[protocol::kProvisioningRequestOperationOffset] |
      kResponseBit;
  response_[protocol::kProvisioningResponseStatusOffset] =
      static_cast<std::uint8_t>(provisioning::Status::kBadState);
  response_pending_ = true;
  terminal_response_ = true;
  commit_response_ = false;
  response_kind_ = ResponseKind::kProvisioning;
}

void ProvisioningAdapter::PrepareUnsupportedLocalResponse(
    const Request& request) {
  response_.fill(0);
  response_[0] = static_cast<std::uint8_t>(request.bytes[0] | kResponseBit);
  response_[1] = static_cast<std::uint8_t>(
      protocol::LocalManagementStatus::kUnsupported);
  response_[2] = protocol::kLocalManagementVersion;
  response_pending_ = true;
  terminal_response_ = false;
  commit_response_ = false;
  response_kind_ = ResponseKind::kLocalManagement;
}

void ProvisioningAdapter::ProcessRequest(const Request& request) {
  if (IsLocalManagementRequest(request)) {
    ProcessLocalManagementRequest(request);
  } else {
    ProcessProvisioningRequest(request);
  }
}

void ProvisioningAdapter::ProcessProvisioningRequest(const Request& request) {
  const auto operation = static_cast<provisioning::Operation>(
      request.bytes[protocol::kProvisioningRequestOperationOffset]);
  if (operation == provisioning::Operation::kChallenge) {
    const bool local_maintenance_authorized =
        local_coordinator_ != nullptr && local_coordinator_->maintenance_active();
    if (!policy_.EnterProvisioning(local_maintenance_authorized)) {
      PrepareBadStateResponse(request);
      return;
    }
  } else if (operation != provisioning::Operation::kPolicyStatus &&
             !policy_.ProvisioningActive()) {
    PrepareBadStateResponse(request);
    return;
  }
  if (operation == provisioning::Operation::kCommit &&
      !policy_.CommitAllowed()) {
    session_.TransportLost();
    PrepareBadStateResponse(request);
    return;
  }

  const provisioning::Status status = session_.Handle(request.bytes, &response_);
  response_pending_ = true;
  terminal_response_ = status != provisioning::Status::kOk ||
                       IsTerminalOperation(operation);
  commit_response_ = operation == provisioning::Operation::kCommit &&
                     status == provisioning::Status::kOk;
  response_kind_ = ResponseKind::kProvisioning;
}

void ProvisioningAdapter::ProcessLocalManagementRequest(
    const Request& request) {
  if (local_session_ == nullptr || local_coordinator_ == nullptr) {
    PrepareUnsupportedLocalResponse(request);
    return;
  }

  local_management::AuthenticatedRequest decoded{};
  const bool authenticated_shape =
      local_management::DecodeAuthenticatedRequest(request.bytes, &decoded) ==
      local_management::CodecStatus::kOk;
  static_cast<void>(local_session_->Handle(request.bytes, &response_));
  response_pending_ = true;
  terminal_response_ = false;
  commit_response_ = false;
  response_kind_ = ResponseKind::kLocalManagement;
  local_response_operation_id_.fill(0);
  local_response_has_operation_id_ =
      authenticated_shape && local_management::IsMutation(decoded.operation) &&
      local_session_->authenticated() &&
      local_session_->last_sequence() == decoded.sequence &&
      std::equal(decoded.operation_id.begin(), decoded.operation_id.end(),
                 response_.begin() + 16);
  if (local_response_has_operation_id_) {
    local_response_operation_id_ = decoded.operation_id;
  }
}

void ProvisioningAdapter::ServiceResponse() {
  if (!response_pending_) {
    return;
  }
  if (response_in_flight_) {
    if (!response_completed_.exchange(false, std::memory_order_acq_rel)) {
      return;
    }
    response_in_flight_ = false;
    response_pending_ = false;
    response_.fill(0);
    if (response_kind_ == ResponseKind::kLocalManagement) {
      if (local_response_has_operation_id_ && local_coordinator_ != nullptr) {
        local_coordinator_->ResponseCompleted(local_response_operation_id_);
      }
    } else if (commit_response_) {
      commit_response_ = false;
      terminal_response_ = false;
      policy_.ProvisioningCommitResponseCompleted();
    } else if (terminal_response_) {
      terminal_response_ = false;
      policy_.LeaveProvisioning();
    }
    response_kind_ = ResponseKind::kNone;
    local_response_operation_id_.fill(0);
    local_response_has_operation_id_ = false;
    return;
  }
  if (tud_hid_n_ready(hid_instance_)) {
    response_expected_.store(true, std::memory_order_release);
    if (tud_hid_n_report(hid_instance_, 0, response_.data(),
                         response_.size())) {
      response_in_flight_ = true;
    } else {
      response_expected_.store(false, std::memory_order_release);
    }
  }
}

void ProvisioningAdapter::Service() {
  if (transport_lost_.load(std::memory_order_acquire)) {
    ResetTransport(false);
    return;
  }
  if (queue_fault_.load(std::memory_order_acquire) ||
      response_failed_.load(std::memory_order_acquire)) {
    ResetTransport(true);
    return;
  }
  const auto now_ms = effects_.MonotonicMilliseconds();
  if (local_coordinator_ != nullptr) {
    local_coordinator_->Poll();
  }
  const bool provisioning_expired = session_.Expire(now_ms);
  const bool local_expired =
      local_session_ != nullptr && local_session_->Expire(now_ms);
  if (provisioning_expired || local_expired) {
    ResetTransport(false);
    return;
  }
  ServiceResponse();
  if (response_pending_ || request_queue_ == nullptr) {
    return;
  }
  Request request{};
  if (xQueueReceive(request_queue_, &request, 0) == pdTRUE) {
    ProcessRequest(request);
    ServiceResponse();
  }
}

}  // namespace keyferry::hil
