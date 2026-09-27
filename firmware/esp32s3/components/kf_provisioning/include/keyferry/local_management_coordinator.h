#pragma once

#include <array>
#include <cstdint>

#include "keyferry/local_management.h"

namespace keyferry::local_management {

// An unavailable output transport cannot accept a nonzero report. Treat that
// state as neutral only when the runtime has also proved its complete local
// report state stable and zero; a later transport-ready transition begins by
// submitting a zero report.
[[nodiscard]] bool NeutralizationSatisfied(
    bool stable_local_zero, std::uint8_t neutral_mask,
    std::uint8_t required_neutral_mask, bool output_transport_unavailable);

// Durable metadata only. Receipts never contain request bodies, credentials,
// peer identities, or typed input.
struct Receipt {
  OperationId operation_id{};
  protocol::LocalManagementOperation operation{};
  protocol::LocalManagementReceiptState state{
      protocol::LocalManagementReceiptState::kNone};
  protocol::LocalManagementStatus result{
      protocol::LocalManagementStatus::kInternal};
  std::uint16_t argument{};
  std::uint8_t flags{};
};

class ReceiptStorage {
 public:
  virtual ~ReceiptStorage() = default;
  virtual bool Find(const OperationId& operation_id, Receipt* receipt,
                    bool* found) = 0;
  virtual bool Save(const Receipt& receipt) = 0;

  // There can be at most one in-progress mutation because the coordinator is
  // a single writer. Implementations must report it after restart.
  virtual bool FindInProgress(Receipt* receipt, bool* found) = 0;
};

class Platform {
 public:
  virtual ~Platform() = default;
  virtual std::uint64_t MonotonicMilliseconds() = 0;
  virtual protocol::LocalManagementStatus ReadStatus(
      protocol::LocalManagementStatusPage page,
      ResponsePayload* payload) = 0;

  // Blocks or releases all non-local command admission. The coordinator sets
  // this before neutralization begins and clears it on every failed, closed,
  // lost, or restart-completed maintenance path.
  virtual void SetMaintenanceActive(bool active) = 0;

  // This operation may only cancel, disarm, and request release-all. It must
  // never arm or submit a nonzero keyboard or mouse report.
  virtual protocol::LocalManagementStatus RequestNeutralization() = 0;
  virtual bool NeutralConfirmed() = 0;

  virtual protocol::LocalManagementStatus RestartNetwork() = 0;
  virtual protocol::LocalManagementStatus ClearBleBondAndEnroll() = 0;
  virtual protocol::LocalManagementStatus CancelEnrollment() = 0;
  virtual protocol::LocalManagementStatus SetOutputMode(
      protocol::OutputMode mode, bool* restart_required) = 0;
  virtual void RestartDevice() = 0;
};

class Coordinator final : public Handler {
 public:
  static constexpr std::uint64_t kNeutralizationDeadlineMs = 2000;
  static constexpr std::uint8_t kFlagMaintenanceActive = 0x01;
  static constexpr std::uint8_t kFlagRestartPending = 0x02;

  Coordinator(Platform& platform, ReceiptStorage& storage);

  // Reconciles a pre-restart in-progress receipt to UNKNOWN without executing
  // it. Must succeed before the coordinator is exposed to a Session.
  bool Initialize();

  protocol::LocalManagementStatus Handle(
      const AuthenticatedRequest& request, ResponsePayload* payload,
      std::uint8_t* flags) override;

  // Advances only the bounded neutralization wait for OPEN_MAINTENANCE.
  void Poll();

  // Called only after the matching authenticated response transfer completes.
  // A scheduled restart is never performed merely because it was enqueued.
  void ResponseCompleted(const OperationId& operation_id);

  // USB loss or session loss releases the lease and any volatile restart.
  void TransportLost();

  [[nodiscard]] bool maintenance_active() const {
    return maintenance_active_;
  }

 private:
  protocol::LocalManagementStatus ReadStatus(
      const AuthenticatedRequest& request, ResponsePayload* payload,
      std::uint8_t* flags);
  protocol::LocalManagementStatus ReadReceipt(
      const AuthenticatedRequest& request, ResponsePayload* payload,
      std::uint8_t* flags);
  protocol::LocalManagementStatus Mutate(
      const AuthenticatedRequest& request, ResponsePayload* payload,
      std::uint8_t* flags);
  protocol::LocalManagementStatus BeginOpenMaintenance(
      const AuthenticatedRequest& request, ResponsePayload* payload,
      std::uint8_t* flags);
  protocol::LocalManagementStatus ExecuteMutation(
      const AuthenticatedRequest& request, std::uint16_t argument,
      ResponsePayload* payload, std::uint8_t* flags);
  protocol::LocalManagementStatus ExistingReceipt(
      const AuthenticatedRequest& request, std::uint16_t argument,
      ResponsePayload* payload, std::uint8_t* flags, bool* handled);
  protocol::LocalManagementStatus FinishReceipt(
      Receipt* receipt, protocol::LocalManagementStatus result,
      bool restart_required, ResponsePayload* payload, std::uint8_t* flags);

  static bool IsZero(const std::uint8_t* begin, const std::uint8_t* end);
  static bool ValidStatusPage(std::uint8_t page);
  static bool Normalize(const AuthenticatedRequest& request,
                        std::uint16_t* argument);
  void EncodeReceipt(const Receipt& receipt, ResponsePayload* payload,
                     std::uint8_t* flags) const;

  Platform& platform_;
  ReceiptStorage& storage_;
  Receipt pending_open_{};
  OperationId restart_operation_id_{};
  std::uint64_t neutralization_deadline_ms_{};
  bool initialized_{};
  bool maintenance_active_{};
  bool opening_maintenance_{};
  bool restart_pending_{};
};

}  // namespace keyferry::local_management
