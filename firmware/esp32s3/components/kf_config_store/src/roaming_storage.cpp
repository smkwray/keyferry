#include "keyferry/roaming_storage.h"

#include <algorithm>
#include <limits>

namespace keyferry::config {
namespace {

void SecureClear(void* data, std::size_t length) {
  volatile auto* output = static_cast<volatile std::uint8_t*>(data);
  while (length-- != 0) {
    *output++ = 0;
  }
}

template <typename Workspace>
StorageStatus FinishStorage(const StorageStatus status, Workspace* workspace) {
  if (workspace != nullptr) {
    SecureClear(workspace, sizeof(*workspace));
  }
  return status;
}

MigrationStatus FinishMigration(const MigrationStatus status,
                                MigrationWorkspace* workspace) {
  if (workspace != nullptr) {
    SecureClear(workspace, sizeof(*workspace));
  }
  return status;
}

SlotView View(const std::array<std::uint8_t, kRoamingConfigSlotBytes>& slot) {
  return {slot.data(), slot.size()};
}

std::array<std::uint8_t, kRoamingConfigSlotBytes>* Buffer(
    RoamingStorageWorkspace* workspace, const SlotId slot) {
  if (workspace == nullptr) {
    return nullptr;
  }
  return slot == SlotId::kA ? &workspace->slot_a
         : slot == SlotId::kB ? &workspace->slot_b
                              : nullptr;
}

StorageStatus WriteSlot(SlotStorage& storage,
                        RoamingStorageWorkspace* workspace,
                        const SlotId target_id, const std::uint64_t generation,
                        const RoamingEndpointConfig& config) {
  auto* target = Buffer(workspace, target_id);
  auto* scratch = Buffer(workspace, target_id == SlotId::kA ? SlotId::kB
                                                            : SlotId::kA);
  if (target == nullptr || scratch == nullptr ||
      !EncodeRoamingSlot(generation, config, target)) {
    return StorageStatus::kInvalidConfig;
  }
  *scratch = *target;
  std::fill_n(scratch->begin() + kCommitOffset, kCommitMarker.size(),
              static_cast<std::uint8_t>(0xFF));
  if (!storage.Erase(target_id) ||
      !storage.Write(target_id, 0, scratch->data(), scratch->size())) {
    return StorageStatus::kIoError;
  }
  scratch->fill(0);
  if (!storage.Read(target_id, scratch->data(), scratch->size())) {
    return StorageStatus::kIoError;
  }
  const bool body_exact =
      std::equal(target->begin(), target->begin() + kCommitOffset,
                 scratch->begin()) &&
      std::all_of(scratch->begin() + kCommitOffset,
                  scratch->begin() + kCommitOffset + kCommitMarker.size(),
                  [](const std::uint8_t byte) { return byte == 0xFF; }) &&
      std::equal(target->begin() + kCommitOffset + kCommitMarker.size(),
                 target->end(),
                 scratch->begin() + kCommitOffset + kCommitMarker.size());
  if (!body_exact ||
      InspectRoamingSlot(View(*scratch)).condition == SlotCondition::kValid) {
    return StorageStatus::kVerificationFailed;
  }
  if (!storage.Write(target_id, kCommitOffset,
                     target->data() + kCommitOffset, kCommitMarker.size())) {
    return StorageStatus::kIoError;
  }
  scratch->fill(0);
  if (!storage.Read(target_id, scratch->data(), scratch->size())) {
    return StorageStatus::kIoError;
  }
  const auto committed = InspectRoamingSlot(View(*scratch));
  return committed.condition == SlotCondition::kValid &&
                 committed.generation == generation &&
                 std::equal(target->begin(), target->end(), scratch->begin())
             ? StorageStatus::kOk
             : StorageStatus::kVerificationFailed;
}

bool SamePendingPolicy(const RecoveryAnchor& pending,
                       const RoamingEndpointConfig& config) {
  const auto policy = RoamingPolicyIdentity(config);
  return pending.device_id == policy.device_id &&
         pending.owner_id == policy.owner_id &&
         pending.owner_ca_sha256 == policy.owner_ca_sha256 &&
         pending.epoch == policy.epoch &&
         pending.policy_sequence == policy.sequence &&
         pending.policy_hash == policy.hash;
}

bool SameRequest(const RecoveryAnchor& pending,
                 const AuthenticatedMigrationRequest& request) {
  return SamePendingPolicy(pending, request.config) &&
         pending.device_recovery_secret == request.recovery_secret &&
         pending.transaction_id == request.transaction_id;
}

bool SamePolicy(const AuthenticatedPolicyIdentity& left,
                const AuthenticatedPolicyIdentity& right) {
  return left.device_id == right.device_id && left.owner_id == right.owner_id &&
         left.owner_ca_sha256 == right.owner_ca_sha256 &&
         left.epoch == right.epoch && left.sequence == right.sequence &&
         left.hash == right.hash &&
         left.previous_sequence == right.previous_sequence &&
         left.previous_hash == right.previous_hash;
}

bool PersistAnchor(RecoveryAnchorStorage& storage,
                   const RecoveryAnchor& anchor,
                   MigrationWorkspace* workspace) {
  if (!EncodeRecoveryAnchor(anchor, &workspace->anchor) ||
      !storage.Write(workspace->anchor.data(), workspace->anchor.size())) {
    return false;
  }
  workspace->verification.fill(0);
  if (storage.Read(workspace->verification.data(),
                   workspace->verification.size()) != AnchorReadStatus::kOk ||
      workspace->anchor != workspace->verification) {
    return false;
  }
  const auto inspected = InspectRecoveryAnchor(
      workspace->verification.data(), workspace->verification.size());
  return inspected.condition == RecoveryAnchorCondition::kValid &&
         inspected.anchor.transaction_id == anchor.transaction_id &&
         inspected.anchor.phase == anchor.phase;
}

}  // namespace

StorageStatus LoadRoamingConfig(SlotStorage& storage,
                                RoamingStorageWorkspace* workspace,
                                RoamingEndpointConfig* config,
                                Selection* selection) {
  if (workspace == nullptr || config == nullptr || selection == nullptr) {
    return FinishStorage(StorageStatus::kIoError, workspace);
  }
  *config = {};
  *selection = {ConfigState::kLockedUnprovisioned, SlotId::kNone, 0};
  if (!storage.Read(SlotId::kA, workspace->slot_a.data(),
                    workspace->slot_a.size()) ||
      !storage.Read(SlotId::kB, workspace->slot_b.data(),
                    workspace->slot_b.size())) {
    return FinishStorage(StorageStatus::kIoError, workspace);
  }
  *selection = SelectNewestRoaming(View(workspace->slot_a),
                                   View(workspace->slot_b), config);
  if (selection->state == ConfigState::kReady) {
    return FinishStorage(StorageStatus::kOk, workspace);
  }
  const auto a = InspectRoamingSlot(View(workspace->slot_a));
  const auto b = InspectRoamingSlot(View(workspace->slot_b));
  if (a.condition == SlotCondition::kErased &&
      b.condition == SlotCondition::kErased) {
    return FinishStorage(StorageStatus::kErasedUnprovisioned, workspace);
  }
  const bool ambiguous =
      a.condition == SlotCondition::kValid &&
      b.condition == SlotCondition::kValid && a.generation == b.generation &&
      workspace->slot_a != workspace->slot_b;
  return FinishStorage(ambiguous ? StorageStatus::kAmbiguousSlots
                                 : StorageStatus::kMalformedSlots,
                       workspace);
}

StorageStatus CommitRoamingConfig(SlotStorage& storage,
                                  RoamingStorageWorkspace* workspace,
                                  const RoamingEndpointConfig& config,
                                  Selection* selection) {
  if (workspace == nullptr || selection == nullptr) {
    return FinishStorage(StorageStatus::kIoError, workspace);
  }
  *selection = {ConfigState::kLockedUnprovisioned, SlotId::kNone, 0};
  if (!ValidateRoamingConfig(config)) {
    return FinishStorage(StorageStatus::kInvalidConfig, workspace);
  }
  if (!storage.Read(SlotId::kA, workspace->slot_a.data(),
                    workspace->slot_a.size()) ||
      !storage.Read(SlotId::kB, workspace->slot_b.data(),
                    workspace->slot_b.size())) {
    return FinishStorage(StorageStatus::kIoError, workspace);
  }
  const auto plan = PlanRoamingUpdate(View(workspace->slot_a),
                                      View(workspace->slot_b));
  if (!plan.writable) {
    const auto a = InspectRoamingSlot(View(workspace->slot_a));
    const auto b = InspectRoamingSlot(View(workspace->slot_b));
    const bool ambiguous = a.condition == SlotCondition::kValid &&
                           b.condition == SlotCondition::kValid &&
                           a.generation == b.generation &&
                           workspace->slot_a != workspace->slot_b;
    const bool malformed =
        a.condition == SlotCondition::kMalformed &&
        b.condition == SlotCondition::kMalformed;
    return FinishStorage(ambiguous          ? StorageStatus::kAmbiguousSlots
                         : malformed        ? StorageStatus::kMalformedSlots
                                            : StorageStatus::kGenerationExhausted,
                         workspace);
  }
  const auto status = WriteSlot(storage, workspace, plan.target,
                                plan.generation, config);
  if (status == StorageStatus::kOk) {
    *selection = {ConfigState::kReady, plan.target, plan.generation};
  }
  return FinishStorage(status, workspace);
}

MigrationStatus MigrateToRoaming(
    SlotStorage& slots, RecoveryAnchorStorage& anchors,
    RoamingPolicyCrypto& crypto, MigrationWorkspace* workspace,
    const AuthenticatedMigrationRequest* request) {
  if (workspace == nullptr) {
    return MigrationStatus::kIoError;
  }
  workspace->anchor.fill(0);
  const auto read = anchors.Read(workspace->anchor.data(), workspace->anchor.size());
  RecoveryAnchorInspection inspection{};
  if (read == AnchorReadStatus::kOk) {
    inspection = InspectRecoveryAnchor(workspace->anchor.data(),
                                       workspace->anchor.size());
  } else if (read == AnchorReadStatus::kNotFound) {
    workspace->anchor.fill(0xFF);
    inspection = InspectRecoveryAnchor(workspace->anchor.data(),
                                       workspace->anchor.size());
  } else {
    return FinishMigration(MigrationStatus::kIoError, workspace);
  }

  if (inspection.condition == RecoveryAnchorCondition::kMalformed) {
    return FinishMigration(MigrationStatus::kLockedRecovery, workspace);
  }
  if (inspection.condition == RecoveryAnchorCondition::kErased) {
    AuthenticatedPolicyIdentity verified{};
    if (request == nullptr ||
        !VerifyAuthenticatedRoamingPolicy(request->config,
                                          request->recovery_secret, crypto,
                                          &verified)) {
      return FinishMigration(MigrationStatus::kInvalidRequest, workspace);
    }
    RecoveryAnchor pending{};
    if (!PrepareMigrationAnchor(verified, request->recovery_secret,
                                request->transaction_id, &pending)) {
      return FinishMigration(MigrationStatus::kInvalidRequest, workspace);
    }
    if (!PersistAnchor(anchors, pending, workspace)) {
      return FinishMigration(MigrationStatus::kVerificationFailed, workspace);
    }
    inspection = {RecoveryAnchorCondition::kValid, pending};
  }

  if (inspection.anchor.phase == RecoveryAnchorPhase::kActive) {
    workspace->policy = {};
    Selection selection{};
    const auto load = LoadRoamingConfig(slots, &workspace->roaming,
                                        &workspace->policy, &selection);
    if (load == StorageStatus::kIoError) {
      return FinishMigration(MigrationStatus::kIoError, workspace);
    }
    if (load != StorageStatus::kOk) {
      return FinishMigration(MigrationStatus::kLockedPolicy, workspace);
    }
    AuthenticatedPolicyIdentity active_policy{};
    if (!VerifyAuthenticatedRoamingPolicy(
            workspace->policy, inspection.anchor.device_recovery_secret, crypto,
            &active_policy)) {
      return FinishMigration(MigrationStatus::kLockedPolicy, workspace);
    }
    const auto active_reconciliation = ReconcilePolicy(inspection, &active_policy);
    if (request == nullptr) {
      return FinishMigration(
          active_reconciliation == PolicyReconciliation::kReady
              ? MigrationStatus::kReady
              : MigrationStatus::kLockedPolicy,
          workspace);
    }
    AuthenticatedPolicyIdentity requested_policy{};
    if (request->recovery_secret != inspection.anchor.device_recovery_secret ||
        !VerifyAuthenticatedRoamingPolicy(
            request->config, inspection.anchor.device_recovery_secret, crypto,
            &requested_policy)) {
      return FinishMigration(MigrationStatus::kInvalidRequest, workspace);
    }
    const auto requested_reconciliation =
        ReconcilePolicy(inspection, &requested_policy);
    if (requested_reconciliation == PolicyReconciliation::kReady) {
      return FinishMigration(
          active_reconciliation == PolicyReconciliation::kReady &&
                  SamePolicy(active_policy, requested_policy)
              ? MigrationStatus::kReady
              : MigrationStatus::kLockedPolicy,
          workspace);
    }
    if (requested_reconciliation != PolicyReconciliation::kAdvanceFloor) {
      return FinishMigration(MigrationStatus::kLockedPolicy, workspace);
    }
    if (active_reconciliation == PolicyReconciliation::kReady) {
      Selection committed{};
      const auto commit = CommitRoamingConfig(
          slots, &workspace->roaming, request->config, &committed);
      if (commit != StorageStatus::kOk) {
        return FinishMigration(
            commit == StorageStatus::kVerificationFailed
                ? MigrationStatus::kVerificationFailed
                : MigrationStatus::kIoError,
            workspace);
      }
      workspace->policy = {};
      if (LoadRoamingConfig(slots, &workspace->roaming, &workspace->policy,
                            &selection) !=
              StorageStatus::kOk ||
          !VerifyAuthenticatedRoamingPolicy(
              workspace->policy, inspection.anchor.device_recovery_secret,
              crypto,
              &active_policy)) {
        return FinishMigration(MigrationStatus::kVerificationFailed, workspace);
      }
    }
    if (ReconcilePolicy(inspection, &active_policy) !=
            PolicyReconciliation::kAdvanceFloor ||
        !SamePolicy(active_policy, requested_policy)) {
      return FinishMigration(MigrationStatus::kConflict, workspace);
    }
    RecoveryAnchor advanced{};
    if (!AdvancePolicyFloor(inspection.anchor, requested_policy,
                            request->transaction_id, &advanced) ||
        !PersistAnchor(anchors, advanced, workspace)) {
      return FinishMigration(MigrationStatus::kVerificationFailed, workspace);
    }
    return FinishMigration(MigrationStatus::kReady, workspace);
  }

  AuthenticatedPolicyIdentity verified{};
  if (request == nullptr ||
      !VerifyAuthenticatedRoamingPolicy(request->config,
                                        inspection.anchor.device_recovery_secret,
                                        crypto, &verified) ||
      !SameRequest(inspection.anchor, *request)) {
    return FinishMigration(MigrationStatus::kLockedMigration, workspace);
  }

  if (!slots.Read(SlotId::kA, workspace->roaming.slot_a.data(),
                  workspace->roaming.slot_a.size()) ||
      !slots.Read(SlotId::kB, workspace->roaming.slot_b.data(),
                  workspace->roaming.slot_b.size())) {
    return FinishMigration(MigrationStatus::kIoError, workspace);
  }
  const auto a = InspectRoamingSlot(View(workspace->roaming.slot_a));
  const auto b = InspectRoamingSlot(View(workspace->roaming.slot_b));
  bool existing_exact = true;
  if (a.condition == SlotCondition::kValid &&
      b.condition == SlotCondition::kValid) {
    existing_exact = a.generation == 1 && b.generation == 1 &&
                     workspace->roaming.slot_a == workspace->roaming.slot_b;
  } else if (a.condition == SlotCondition::kValid) {
    existing_exact =
        a.generation == 1 &&
        EncodeRoamingSlot(1, request->config, &workspace->roaming.slot_b) &&
        workspace->roaming.slot_a == workspace->roaming.slot_b;
  } else if (b.condition == SlotCondition::kValid) {
    existing_exact =
        b.generation == 1 &&
        EncodeRoamingSlot(1, request->config, &workspace->roaming.slot_a) &&
        workspace->roaming.slot_a == workspace->roaming.slot_b;
  }
  if (!existing_exact) {
    return FinishMigration(MigrationStatus::kConflict, workspace);
  }
  if (a.condition != SlotCondition::kValid) {
    const auto status = WriteSlot(slots, &workspace->roaming, SlotId::kA, 1,
                                  request->config);
    if (status != StorageStatus::kOk) {
      return FinishMigration(status == StorageStatus::kVerificationFailed
                                 ? MigrationStatus::kVerificationFailed
                                 : MigrationStatus::kIoError,
                             workspace);
    }
  }
  if (b.condition != SlotCondition::kValid) {
    const auto status = WriteSlot(slots, &workspace->roaming, SlotId::kB, 1,
                                  request->config);
    if (status != StorageStatus::kOk) {
      return FinishMigration(status == StorageStatus::kVerificationFailed
                                 ? MigrationStatus::kVerificationFailed
                                 : MigrationStatus::kIoError,
                             workspace);
    }
  }

  if (!slots.Read(SlotId::kA, workspace->roaming.slot_a.data(),
                  workspace->roaming.slot_a.size()) ||
      !slots.Read(SlotId::kB, workspace->roaming.slot_b.data(),
                  workspace->roaming.slot_b.size())) {
    return FinishMigration(MigrationStatus::kIoError, workspace);
  }
  const auto final_a = InspectRoamingSlot(View(workspace->roaming.slot_a));
  const auto final_b = InspectRoamingSlot(View(workspace->roaming.slot_b));
  if (final_a.condition != SlotCondition::kValid ||
      final_b.condition != SlotCondition::kValid || final_a.generation != 1 ||
      final_b.generation != 1 ||
      workspace->roaming.slot_a != workspace->roaming.slot_b ||
      !EncodeRoamingSlot(1, request->config, &workspace->roaming.slot_a) ||
      workspace->roaming.slot_a != workspace->roaming.slot_b) {
    return FinishMigration(MigrationStatus::kVerificationFailed, workspace);
  }
  const auto requested_policy = RoamingPolicyIdentity(request->config);
  if (!CanActivateMigration(inspection.anchor, requested_policy,
                            requested_policy)) {
    return FinishMigration(MigrationStatus::kVerificationFailed, workspace);
  }
  RecoveryAnchor active{};
  if (!ActivateMigration(inspection.anchor, &active) ||
      !PersistAnchor(anchors, active, workspace)) {
    return FinishMigration(MigrationStatus::kVerificationFailed, workspace);
  }
  return FinishMigration(MigrationStatus::kReady, workspace);
}

}  // namespace keyferry::config
