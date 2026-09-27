#include "keyferry/local_management_receipts.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace {

namespace local = keyferry::local_management;
using keyferry::protocol::LocalManagementOperation;
using keyferry::protocol::LocalManagementReceiptState;
using keyferry::protocol::LocalManagementStatus;

class FakeBlobs final : public local::ReceiptBlobStorage {
 public:
  local::ReceiptBlobReadStatus Read(
      const std::uint8_t slot, local::ReceiptJournalBlob* output) override {
    if (fail_read || slot > 1 || output == nullptr) {
      return local::ReceiptBlobReadStatus::kIoError;
    }
    if (!present[slot]) {
      return local::ReceiptBlobReadStatus::kNotFound;
    }
    *output = blobs[slot];
    return local::ReceiptBlobReadStatus::kOk;
  }

  bool Write(const std::uint8_t slot,
             const local::ReceiptJournalBlob& data) override {
    ++writes;
    if (fail_write || slot > 1) {
      return false;
    }
    blobs[slot] = data;
    present[slot] = true;
    if (corrupt_write) {
      blobs[slot][20] ^= 1;
    }
    return true;
  }

  std::array<local::ReceiptJournalBlob, 2> blobs{};
  std::array<bool, 2> present{};
  std::size_t writes{};
  bool fail_read{};
  bool fail_write{};
  bool corrupt_write{};
};

local::Receipt MakeReceipt(const std::uint8_t id,
                           const LocalManagementReceiptState state,
                           const LocalManagementOperation operation =
                               LocalManagementOperation::kRestartNetwork) {
  local::Receipt receipt{};
  receipt.operation_id.fill(id);
  receipt.operation = operation;
  receipt.state = state;
  switch (state) {
    case LocalManagementReceiptState::kInProgress:
      receipt.result = LocalManagementStatus::kInProgress;
      break;
    case LocalManagementReceiptState::kCommitted:
      receipt.result = LocalManagementStatus::kOk;
      break;
    case LocalManagementReceiptState::kFailed:
      receipt.result = LocalManagementStatus::kNotNeutral;
      break;
    case LocalManagementReceiptState::kUnknown:
      receipt.result = LocalManagementStatus::kInternal;
      break;
    case LocalManagementReceiptState::kNone:
      break;
  }
  return receipt;
}

void TestEmptyUpdateReloadAndExactLookup() {
  FakeBlobs blobs;
  local::ReceiptJournal journal(blobs);
  assert(journal.Initialize());
  assert(journal.size() == 0 && journal.generation() == 0);

  auto receipt =
      MakeReceipt(0x11, LocalManagementReceiptState::kInProgress);
  assert(journal.Save(receipt));
  assert(journal.size() == 1 && journal.generation() == 1);
  receipt.state = LocalManagementReceiptState::kCommitted;
  receipt.result = LocalManagementStatus::kOk;
  assert(journal.Save(receipt));
  assert(journal.size() == 1 && journal.generation() == 2);

  local::ReceiptJournal reloaded(blobs);
  assert(reloaded.Initialize());
  local::Receipt found{};
  bool exists = false;
  assert(reloaded.Find(receipt.operation_id, &found, &exists));
  assert(exists && found.state == LocalManagementReceiptState::kCommitted);
  assert(found.operation == LocalManagementOperation::kRestartNetwork);
  found = {};
  exists = false;
  assert(reloaded.Last(&found, &exists));
  assert(exists && found.operation_id == receipt.operation_id);
  assert(reloaded.generation() == 2);
}

void TestWriteAndReadbackFailurePreserveRuntimeState() {
  FakeBlobs blobs;
  local::ReceiptJournal journal(blobs);
  assert(journal.Initialize());
  const auto first =
      MakeReceipt(0x21, LocalManagementReceiptState::kCommitted);
  assert(journal.Save(first));

  blobs.fail_write = true;
  const auto second =
      MakeReceipt(0x22, LocalManagementReceiptState::kCommitted);
  assert(!journal.Save(second));
  assert(journal.size() == 1 && journal.generation() == 1);
  blobs.fail_write = false;
  blobs.corrupt_write = true;
  assert(!journal.Save(second));
  assert(journal.size() == 1 && journal.generation() == 1);
  local::Receipt ignored{};
  bool found = true;
  assert(journal.Find(second.operation_id, &ignored, &found) && !found);
}

void TestLatestCorruptionFallsBackToPriorGeneration() {
  FakeBlobs blobs;
  local::ReceiptJournal journal(blobs);
  assert(journal.Initialize());
  const auto first =
      MakeReceipt(0x31, LocalManagementReceiptState::kInProgress);
  assert(journal.Save(first));
  auto completed = first;
  completed.state = LocalManagementReceiptState::kCommitted;
  completed.result = LocalManagementStatus::kOk;
  assert(journal.Save(completed));

  // Generation 2 is in slot 1 after alternating from the initial slot 1.
  blobs.blobs[1][24] ^= 1;
  local::ReceiptJournal recovered(blobs);
  assert(recovered.Initialize());
  local::Receipt pending{};
  bool found = false;
  assert(recovered.FindInProgress(&pending, &found));
  assert(found && pending.operation_id == first.operation_id);
  assert(recovered.generation() == 1);
}

void TestCapacityIsBoundedAndOldestReceiptExpires() {
  FakeBlobs blobs;
  local::ReceiptJournal journal(blobs);
  assert(journal.Initialize());
  for (std::size_t index = 1; index <= local::kReceiptCapacity + 1; ++index) {
    assert(journal.Save(MakeReceipt(
        static_cast<std::uint8_t>(index),
        LocalManagementReceiptState::kCommitted)));
  }
  assert(journal.size() == local::kReceiptCapacity);
  local::Receipt found_receipt{};
  bool found = true;
  const auto oldest = MakeReceipt(1, LocalManagementReceiptState::kCommitted);
  assert(journal.Find(oldest.operation_id, &found_receipt, &found) && !found);
  const auto newest = MakeReceipt(
      static_cast<std::uint8_t>(local::kReceiptCapacity + 1),
      LocalManagementReceiptState::kCommitted);
  assert(journal.Find(newest.operation_id, &found_receipt, &found) && found);
  assert(journal.Last(&found_receipt, &found) && found);
  assert(found_receipt.operation_id == newest.operation_id);
}

void TestMalformedAmbiguousAndInvalidReceiptsFailClosed() {
  FakeBlobs blobs;
  blobs.present[0] = true;
  blobs.blobs[0].fill(0xA5);
  local::ReceiptJournal malformed(blobs);
  assert(!malformed.Initialize());

  FakeBlobs ambiguous_blobs;
  local::ReceiptJournal source(ambiguous_blobs);
  assert(source.Initialize());
  assert(source.Save(
      MakeReceipt(0x51, LocalManagementReceiptState::kCommitted)));
  const std::uint8_t active = ambiguous_blobs.present[0] ? 0 : 1;
  const std::uint8_t other = active == 0 ? 1 : 0;
  ambiguous_blobs.blobs[other] = ambiguous_blobs.blobs[active];
  ambiguous_blobs.present[other] = true;
  ambiguous_blobs.blobs[other][20] ^= 1;
  local::ReceiptJournal one_valid(ambiguous_blobs);
  assert(one_valid.Initialize());

  FakeBlobs validation_blobs;
  local::ReceiptJournal validation(validation_blobs);
  assert(validation.Initialize());
  auto invalid = MakeReceipt(
      0x61, LocalManagementReceiptState::kCommitted,
      LocalManagementOperation::kSetOutputMode);
  invalid.argument = 9;
  assert(!validation.Save(invalid));
  invalid = MakeReceipt(0x62, LocalManagementReceiptState::kInProgress);
  invalid.flags = local::Coordinator::kFlagRestartPending;
  assert(!validation.Save(invalid));
}

}  // namespace

int main() {
  TestEmptyUpdateReloadAndExactLookup();
  TestWriteAndReadbackFailurePreserveRuntimeState();
  TestLatestCorruptionFallsBackToPriorGeneration();
  TestCapacityIsBoundedAndOldestReceiptExpires();
  TestMalformedAmbiguousAndInvalidReceiptsFailClosed();
  std::puts("local_management_receipts_test: ok");
  return 0;
}
