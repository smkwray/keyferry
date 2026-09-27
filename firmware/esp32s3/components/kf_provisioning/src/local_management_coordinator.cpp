#include "keyferry/local_management_coordinator.h"

#include <algorithm>

namespace keyferry::local_management {

bool NeutralizationSatisfied(const bool stable_local_zero,
                             const std::uint8_t neutral_mask,
                             const std::uint8_t required_neutral_mask,
                             const bool output_transport_unavailable) {
  return stable_local_zero &&
         (output_transport_unavailable ||
          (neutral_mask & required_neutral_mask) == required_neutral_mask);
}

namespace {

using Operation = protocol::LocalManagementOperation;
using ReceiptState = protocol::LocalManagementReceiptState;
using Status = protocol::LocalManagementStatus;

bool EqualId(const OperationId& left, const OperationId& right) {
  return std::equal(left.begin(), left.end(), right.begin());
}

Status ReceiptStatus(const Receipt& receipt) {
  switch (receipt.state) {
    case ReceiptState::kInProgress:
      return Status::kInProgress;
    case ReceiptState::kCommitted:
    case ReceiptState::kFailed:
    case ReceiptState::kUnknown:
      return receipt.result;
    case ReceiptState::kNone:
      return Status::kOperationUnknown;
  }
  return Status::kInternal;
}

}  // namespace

Coordinator::Coordinator(Platform& platform, ReceiptStorage& storage)
    : platform_(platform), storage_(storage) {}

bool Coordinator::Initialize() {
  Receipt interrupted{};
  bool found = false;
  if (!storage_.FindInProgress(&interrupted, &found)) {
    return false;
  }
  if (found) {
    interrupted.state = ReceiptState::kUnknown;
    interrupted.result = Status::kInternal;
    interrupted.flags = 0;
    if (!storage_.Save(interrupted)) {
      return false;
    }
  }
  initialized_ = true;
  return true;
}

Status Coordinator::Handle(const AuthenticatedRequest& request,
                           ResponsePayload* payload, std::uint8_t* flags) {
  if (payload == nullptr || flags == nullptr || !initialized_) {
    return Status::kBadState;
  }
  payload->fill(0);
  *flags = maintenance_active_ ? kFlagMaintenanceActive : 0;
  switch (request.operation) {
    case Operation::kGetStatus:
      return ReadStatus(request, payload, flags);
    case Operation::kGetReceipt:
      return ReadReceipt(request, payload, flags);
    case Operation::kOpenMaintenance:
    case Operation::kCloseMaintenance:
    case Operation::kRestartNetwork:
    case Operation::kClearBleBondAndEnroll:
    case Operation::kCancelEnrollment:
    case Operation::kSetOutputMode:
    case Operation::kReboot:
      return Mutate(request, payload, flags);
    case Operation::kChallenge:
    case Operation::kAuthenticate:
      return Status::kBadReport;
  }
  return Status::kUnsupported;
}

Status Coordinator::ReadStatus(const AuthenticatedRequest& request,
                               ResponsePayload* payload,
                               std::uint8_t* flags) {
  std::uint16_t argument = 0;
  if (!Normalize(request, &argument) || !ValidStatusPage(request.payload[0])) {
    return Status::kBadReport;
  }
  const auto result = platform_.ReadStatus(
      static_cast<protocol::LocalManagementStatusPage>(request.payload[0]),
      payload);
  *flags = maintenance_active_ ? kFlagMaintenanceActive : 0;
  if (restart_pending_) {
    *flags |= kFlagRestartPending;
  }
  return result;
}

Status Coordinator::ReadReceipt(const AuthenticatedRequest& request,
                                ResponsePayload* payload,
                                std::uint8_t* flags) {
  std::uint16_t argument = 0;
  if (!Normalize(request, &argument)) {
    return Status::kBadReport;
  }
  OperationId target{};
  std::copy_n(request.payload.begin(), target.size(), target.begin());
  Receipt receipt{};
  bool found = false;
  if (!storage_.Find(target, &receipt, &found)) {
    return Status::kStorageError;
  }
  if (!found) {
    return Status::kOperationUnknown;
  }
  EncodeReceipt(receipt, payload, flags);
  return ReceiptStatus(receipt);
}

Status Coordinator::Mutate(const AuthenticatedRequest& request,
                           ResponsePayload* payload, std::uint8_t* flags) {
  std::uint16_t argument = 0;
  if (!Normalize(request, &argument)) {
    return Status::kBadReport;
  }
  bool handled = false;
  const auto existing =
      ExistingReceipt(request, argument, payload, flags, &handled);
  if (handled) {
    return existing;
  }
  if (opening_maintenance_ || restart_pending_) {
    return Status::kBusy;
  }
  if (request.operation == Operation::kOpenMaintenance) {
    if (maintenance_active_) {
      return Status::kBadState;
    }
    return BeginOpenMaintenance(request, payload, flags);
  }
  if (!maintenance_active_ || !platform_.NeutralConfirmed()) {
    return Status::kNotNeutral;
  }
  return ExecuteMutation(request, argument, payload, flags);
}

Status Coordinator::BeginOpenMaintenance(const AuthenticatedRequest& request,
                                         ResponsePayload* payload,
                                         std::uint8_t* flags) {
  Receipt receipt{};
  receipt.operation_id = request.operation_id;
  receipt.operation = request.operation;
  receipt.state = ReceiptState::kInProgress;
  receipt.result = Status::kInProgress;
  if (!storage_.Save(receipt)) {
    return Status::kStorageError;
  }
  platform_.SetMaintenanceActive(true);
  const auto neutralize = platform_.RequestNeutralization();
  if (neutralize != Status::kOk && neutralize != Status::kInProgress) {
    platform_.SetMaintenanceActive(false);
    return FinishReceipt(&receipt, neutralize, false, payload, flags);
  }
  if (platform_.NeutralConfirmed()) {
    maintenance_active_ = true;
    return FinishReceipt(&receipt, Status::kOk, false, payload, flags);
  }
  pending_open_ = receipt;
  opening_maintenance_ = true;
  neutralization_deadline_ms_ =
      platform_.MonotonicMilliseconds() + kNeutralizationDeadlineMs;
  EncodeReceipt(receipt, payload, flags);
  return Status::kInProgress;
}

Status Coordinator::ExecuteMutation(const AuthenticatedRequest& request,
                                    const std::uint16_t argument,
                                    ResponsePayload* payload,
                                    std::uint8_t* flags) {
  Receipt receipt{};
  receipt.operation_id = request.operation_id;
  receipt.operation = request.operation;
  receipt.state = ReceiptState::kInProgress;
  receipt.result = Status::kInProgress;
  receipt.argument = argument;
  if (!storage_.Save(receipt)) {
    return Status::kStorageError;
  }

  Status result = Status::kInternal;
  bool restart_required = false;
  switch (request.operation) {
    case Operation::kCloseMaintenance:
      maintenance_active_ = false;
      platform_.SetMaintenanceActive(false);
      result = Status::kOk;
      break;
    case Operation::kRestartNetwork:
      result = platform_.RestartNetwork();
      break;
    case Operation::kClearBleBondAndEnroll:
      result = platform_.ClearBleBondAndEnroll();
      break;
    case Operation::kCancelEnrollment:
      result = platform_.CancelEnrollment();
      break;
    case Operation::kSetOutputMode:
      result = platform_.SetOutputMode(
          static_cast<protocol::OutputMode>(argument), &restart_required);
      break;
    case Operation::kReboot:
      result = Status::kOk;
      restart_required = true;
      break;
    case Operation::kChallenge:
    case Operation::kAuthenticate:
    case Operation::kGetStatus:
    case Operation::kOpenMaintenance:
    case Operation::kGetReceipt:
      return FinishReceipt(&receipt, Status::kUnsupported, false, payload,
                           flags);
  }
  return FinishReceipt(&receipt, result, restart_required, payload, flags);
}

Status Coordinator::ExistingReceipt(const AuthenticatedRequest& request,
                                    const std::uint16_t argument,
                                    ResponsePayload* payload,
                                    std::uint8_t* flags, bool* handled) {
  *handled = false;
  Receipt receipt{};
  bool found = false;
  if (!storage_.Find(request.operation_id, &receipt, &found)) {
    *handled = true;
    return Status::kStorageError;
  }
  if (!found) {
    return Status::kOk;
  }
  *handled = true;
  if (receipt.operation != request.operation || receipt.argument != argument) {
    return Status::kOperationConflict;
  }
  EncodeReceipt(receipt, payload, flags);
  return ReceiptStatus(receipt);
}

Status Coordinator::FinishReceipt(Receipt* receipt, const Status result,
                                  const bool restart_required,
                                  ResponsePayload* payload,
                                  std::uint8_t* flags) {
  receipt->result = result;
  receipt->state = result == Status::kOk ? ReceiptState::kCommitted
                                         : ReceiptState::kFailed;
  receipt->flags = restart_required ? kFlagRestartPending : 0;
  if (!storage_.Save(*receipt)) {
    // The durable IN_PROGRESS intent remains authoritative. Never repeat the
    // possibly executed operation and never schedule a restart without a
    // committed receipt.
    restart_pending_ = false;
    restart_operation_id_.fill(0);
    return Status::kStorageError;
  }
  if (restart_required && result == Status::kOk) {
    restart_pending_ = true;
    restart_operation_id_ = receipt->operation_id;
  }
  EncodeReceipt(*receipt, payload, flags);
  return result;
}

void Coordinator::Poll() {
  if (!initialized_ || !opening_maintenance_) {
    return;
  }
  Status result = Status::kInProgress;
  if (platform_.NeutralConfirmed()) {
    maintenance_active_ = true;
    result = Status::kOk;
  } else if (platform_.MonotonicMilliseconds() >=
             neutralization_deadline_ms_) {
    result = Status::kNotNeutral;
  } else {
    return;
  }
  pending_open_.result = result;
  pending_open_.state = result == Status::kOk ? ReceiptState::kCommitted
                                              : ReceiptState::kFailed;
  if (!storage_.Save(pending_open_)) {
    maintenance_active_ = false;
  }
  if (!maintenance_active_) {
    platform_.SetMaintenanceActive(false);
  }
  opening_maintenance_ = false;
  pending_open_ = Receipt{};
}

void Coordinator::ResponseCompleted(const OperationId& operation_id) {
  if (!restart_pending_ || !EqualId(operation_id, restart_operation_id_)) {
    return;
  }
  restart_pending_ = false;
  restart_operation_id_.fill(0);
  maintenance_active_ = false;
  platform_.SetMaintenanceActive(false);
  platform_.RestartDevice();
}

void Coordinator::TransportLost() {
  if (opening_maintenance_) {
    pending_open_.state = ReceiptState::kUnknown;
    pending_open_.result = Status::kInternal;
    pending_open_.flags = 0;
    static_cast<void>(storage_.Save(pending_open_));
  }
  maintenance_active_ = false;
  opening_maintenance_ = false;
  restart_pending_ = false;
  platform_.SetMaintenanceActive(false);
  pending_open_ = Receipt{};
  restart_operation_id_.fill(0);
}

bool Coordinator::IsZero(const std::uint8_t* begin,
                         const std::uint8_t* end) {
  return std::all_of(begin, end,
                     [](const std::uint8_t value) { return value == 0; });
}

bool Coordinator::ValidStatusPage(const std::uint8_t page) {
  return page >=
             static_cast<std::uint8_t>(
                 protocol::LocalManagementStatusPage::kDevice) &&
         page <= static_cast<std::uint8_t>(
                     protocol::LocalManagementStatusPage::kProbeStack);
}

bool Coordinator::Normalize(const AuthenticatedRequest& request,
                            std::uint16_t* argument) {
  *argument = 0;
  switch (request.operation) {
    case Operation::kGetStatus:
      return IsZero(request.payload.data() + 1,
                    request.payload.data() + request.payload.size());
    case Operation::kGetReceipt:
      return !IsZero(request.payload.data(), request.payload.data() + 16) &&
             IsZero(request.payload.data() + 16,
                    request.payload.data() + request.payload.size());
    case Operation::kSetOutputMode:
      if (!IsZero(request.payload.data() + 1,
                  request.payload.data() + request.payload.size()) ||
          (request.payload[0] !=
               static_cast<std::uint8_t>(protocol::OutputMode::kUsbHid) &&
           request.payload[0] !=
               static_cast<std::uint8_t>(protocol::OutputMode::kBleHid))) {
        return false;
      }
      *argument = request.payload[0];
      return true;
    case Operation::kOpenMaintenance:
    case Operation::kCloseMaintenance:
    case Operation::kRestartNetwork:
    case Operation::kClearBleBondAndEnroll:
    case Operation::kCancelEnrollment:
    case Operation::kReboot:
      return IsZero(request.payload.data(),
                    request.payload.data() + request.payload.size());
    case Operation::kChallenge:
    case Operation::kAuthenticate:
      return false;
  }
  return false;
}

void Coordinator::EncodeReceipt(const Receipt& receipt,
                                ResponsePayload* payload,
                                std::uint8_t* flags) const {
  payload->fill(0);
  (*payload)[0] = static_cast<std::uint8_t>(receipt.state);
  (*payload)[1] = static_cast<std::uint8_t>(receipt.operation);
  (*payload)[2] = static_cast<std::uint8_t>(receipt.result);
  (*payload)[3] = receipt.flags;
  (*payload)[4] = static_cast<std::uint8_t>(receipt.argument & 0xFF);
  (*payload)[5] = static_cast<std::uint8_t>(receipt.argument >> 8);
  *flags = maintenance_active_ ? kFlagMaintenanceActive : 0;
  if (restart_pending_ ||
      (receipt.flags & kFlagRestartPending) != 0) {
    *flags |= kFlagRestartPending;
  }
}

}  // namespace keyferry::local_management
