#include "keyferry/config_storage.h"

#include <algorithm>

namespace keyferry::config {
namespace {

void SecureClear(void* data, std::size_t length) {
  volatile auto* output = static_cast<volatile std::uint8_t*>(data);
  while (length-- != 0) {
    *output++ = 0;
  }
}

StorageStatus Finish(StorageStatus status, StorageWorkspace* workspace) {
  if (workspace != nullptr) {
    SecureClear(workspace, sizeof(*workspace));
  }
  return status;
}

SlotView View(const std::array<std::uint8_t, kSlotBytes>& slot) {
  return {slot.data(), slot.size()};
}

std::array<std::uint8_t, kSlotBytes>* Buffer(StorageWorkspace* workspace, SlotId slot) {
  if (workspace == nullptr) {
    return nullptr;
  }
  if (slot == SlotId::kA) {
    return &workspace->slot_a;
  }
  if (slot == SlotId::kB) {
    return &workspace->slot_b;
  }
  return nullptr;
}

}  // namespace

StorageStatus LoadConfig(SlotStorage& storage, StorageWorkspace* workspace,
                         EndpointConfig* config, Selection* selection) {
  if (workspace == nullptr || config == nullptr || selection == nullptr) {
    return Finish(StorageStatus::kIoError, workspace);
  }
  *config = {};
  *selection = {ConfigState::kLockedUnprovisioned, SlotId::kNone, 0};
  if (!storage.Read(SlotId::kA, workspace->slot_a.data(), workspace->slot_a.size()) ||
      !storage.Read(SlotId::kB, workspace->slot_b.data(), workspace->slot_b.size())) {
    return Finish(StorageStatus::kIoError, workspace);
  }
  *selection = SelectNewest(View(workspace->slot_a), View(workspace->slot_b), config);
  if (selection->state == ConfigState::kReady) {
    return Finish(StorageStatus::kOk, workspace);
  }
  const SlotInspection a = InspectSlot(View(workspace->slot_a));
  const SlotInspection b = InspectSlot(View(workspace->slot_b));
  if (a.condition == SlotCondition::kErased &&
      b.condition == SlotCondition::kErased) {
    return Finish(StorageStatus::kErasedUnprovisioned, workspace);
  }
  const bool ambiguous =
      a.condition == SlotCondition::kValid && b.condition == SlotCondition::kValid &&
      a.generation == b.generation &&
      !std::equal(workspace->slot_a.begin(), workspace->slot_a.end(),
                  workspace->slot_b.begin());
  return Finish(ambiguous ? StorageStatus::kAmbiguousSlots
                          : StorageStatus::kMalformedSlots,
                workspace);
}

StorageStatus CommitConfig(SlotStorage& storage, StorageWorkspace* workspace,
                           const EndpointConfig& config, Selection* selection) {
  if (workspace == nullptr || selection == nullptr) {
    return Finish(StorageStatus::kIoError, workspace);
  }
  *selection = {ConfigState::kLockedUnprovisioned, SlotId::kNone, 0};
  if (!ValidateConfig(config)) {
    return Finish(StorageStatus::kInvalidConfig, workspace);
  }
  if (!storage.Read(SlotId::kA, workspace->slot_a.data(), workspace->slot_a.size()) ||
      !storage.Read(SlotId::kB, workspace->slot_b.data(), workspace->slot_b.size())) {
    return Finish(StorageStatus::kIoError, workspace);
  }
  const UpdatePlan plan = PlanUpdate(View(workspace->slot_a), View(workspace->slot_b));
  if (!plan.writable) {
    const SlotInspection a = InspectSlot(View(workspace->slot_a));
    const SlotInspection b = InspectSlot(View(workspace->slot_b));
    const bool ambiguous =
        a.condition == SlotCondition::kValid && b.condition == SlotCondition::kValid &&
        a.generation == b.generation &&
        !std::equal(workspace->slot_a.begin(), workspace->slot_a.end(),
                    workspace->slot_b.begin());
    const bool malformed_only = a.condition != SlotCondition::kValid &&
                                b.condition != SlotCondition::kValid &&
                                (a.condition == SlotCondition::kMalformed ||
                                 b.condition == SlotCondition::kMalformed);
    return Finish(ambiguous          ? StorageStatus::kAmbiguousSlots
                  : malformed_only   ? StorageStatus::kMalformedSlots
                                     : StorageStatus::kGenerationExhausted,
                  workspace);
  }
  auto* target = Buffer(workspace, plan.target);
  auto* scratch = Buffer(workspace, plan.target == SlotId::kA ? SlotId::kB : SlotId::kA);
  if (target == nullptr || scratch == nullptr ||
      !EncodeSlot(plan.generation, config, target)) {
    return Finish(StorageStatus::kIoError, workspace);
  }
  *scratch = *target;
  std::fill_n(scratch->begin() + kCommitOffset, kCommitMarker.size(),
              static_cast<std::uint8_t>(0xFF));
  if (!storage.Erase(plan.target) ||
      !storage.Write(plan.target, 0, scratch->data(), scratch->size())) {
    return Finish(StorageStatus::kIoError, workspace);
  }
  scratch->fill(0);
  if (!storage.Read(plan.target, scratch->data(), scratch->size())) {
    return Finish(StorageStatus::kIoError, workspace);
  }
  const bool body_exact =
      std::equal(target->begin(), target->begin() + kCommitOffset, scratch->begin()) &&
      std::all_of(scratch->begin() + kCommitOffset,
                  scratch->begin() + kCommitOffset + kCommitMarker.size(),
                  [](std::uint8_t byte) { return byte == 0xFF; }) &&
      std::equal(target->begin() + kCommitOffset + kCommitMarker.size(), target->end(),
                 scratch->begin() + kCommitOffset + kCommitMarker.size());
  if (!body_exact ||
      InspectSlot(View(*scratch)).condition == SlotCondition::kValid) {
    return Finish(StorageStatus::kVerificationFailed, workspace);
  }
  if (!storage.Write(plan.target, kCommitOffset, target->data() + kCommitOffset,
                     kCommitMarker.size())) {
    return Finish(StorageStatus::kIoError, workspace);
  }
  scratch->fill(0);
  if (!storage.Read(plan.target, scratch->data(), scratch->size())) {
    return Finish(StorageStatus::kIoError, workspace);
  }
  const SlotInspection committed = InspectSlot(View(*scratch));
  const bool exact = std::equal(target->begin(), target->end(), scratch->begin());
  if (!exact || committed.condition != SlotCondition::kValid ||
      committed.generation != plan.generation) {
    return Finish(StorageStatus::kVerificationFailed, workspace);
  }
  *selection = {ConfigState::kReady, plan.target, plan.generation};
  return Finish(StorageStatus::kOk, workspace);
}

}  // namespace keyferry::config
