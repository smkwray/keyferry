#include "keyferry/local_management_receipts.h"

#include <algorithm>
#include <limits>

#include "keyferry/config_store.h"

namespace keyferry::local_management {
namespace {

using Operation = protocol::LocalManagementOperation;
using ReceiptState = protocol::LocalManagementReceiptState;
using Status = protocol::LocalManagementStatus;

constexpr std::array<std::uint8_t, 4> kMagic{'K', 'F', 'M', 'R'};
constexpr std::uint8_t kVersion = 1;
constexpr std::size_t kHeaderBytes = 16;
constexpr std::size_t kCrcOffset = kReceiptJournalBytes - 4;

void Put16(std::uint8_t* output, const std::uint16_t value) {
  output[0] = static_cast<std::uint8_t>(value & 0xFF);
  output[1] = static_cast<std::uint8_t>(value >> 8);
}

void Put32(std::uint8_t* output, const std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    output[index] = static_cast<std::uint8_t>(value >> (8 * index));
  }
}

void Put64(std::uint8_t* output, const std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    output[index] = static_cast<std::uint8_t>(value >> (8 * index));
  }
}

std::uint16_t Get16(const std::uint8_t* input) {
  return static_cast<std::uint16_t>(input[0]) |
         (static_cast<std::uint16_t>(input[1]) << 8);
}

std::uint32_t Get32(const std::uint8_t* input) {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(input[index]) << (8 * index);
  }
  return value;
}

std::uint64_t Get64(const std::uint8_t* input) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(input[index]) << (8 * index);
  }
  return value;
}

bool IsMutation(const Operation operation) {
  return operation >= Operation::kOpenMaintenance &&
         operation <= Operation::kReboot;
}

bool ValidStatus(const Status status) {
  switch (status) {
    case Status::kOk:
    case Status::kBadReport:
    case Status::kBadState:
    case Status::kAuthenticationFailed:
    case Status::kReplay:
    case Status::kBusy:
    case Status::kUnsupported:
    case Status::kNotNeutral:
    case Status::kOperationUnknown:
    case Status::kOperationConflict:
    case Status::kStorageError:
    case Status::kInProgress:
    case Status::kInternal:
      return true;
  }
  return false;
}

bool ValidReceipt(const Receipt& receipt) {
  if (std::all_of(receipt.operation_id.begin(), receipt.operation_id.end(),
                  [](const std::uint8_t value) { return value == 0; }) ||
      !IsMutation(receipt.operation) || !ValidStatus(receipt.result) ||
      (receipt.flags & ~Coordinator::kFlagRestartPending) != 0) {
    return false;
  }
  if (receipt.operation == Operation::kSetOutputMode) {
    if (receipt.argument !=
            static_cast<std::uint16_t>(protocol::OutputMode::kUsbHid) &&
        receipt.argument !=
            static_cast<std::uint16_t>(protocol::OutputMode::kBleHid)) {
      return false;
    }
  } else if (receipt.argument != 0) {
    return false;
  }
  switch (receipt.state) {
    case ReceiptState::kInProgress:
      return receipt.result == Status::kInProgress && receipt.flags == 0;
    case ReceiptState::kCommitted:
      return receipt.result == Status::kOk;
    case ReceiptState::kFailed:
      return receipt.result != Status::kOk &&
             receipt.result != Status::kInProgress;
    case ReceiptState::kUnknown:
      return receipt.result == Status::kInternal && receipt.flags == 0;
    case ReceiptState::kNone:
      return false;
  }
  return false;
}

bool Encode(const std::array<Receipt, kReceiptCapacity>& receipts,
            const std::size_t count, const std::uint64_t generation,
            ReceiptJournalBlob* output) {
  if (output == nullptr || count > kReceiptCapacity || generation == 0) {
    return false;
  }
  output->fill(0);
  std::copy(kMagic.begin(), kMagic.end(), output->begin());
  (*output)[4] = kVersion;
  (*output)[5] = static_cast<std::uint8_t>(count);
  Put64(output->data() + 8, generation);
  for (std::size_t index = 0; index < count; ++index) {
    if (!ValidReceipt(receipts[index])) {
      return false;
    }
    auto* record = output->data() + kHeaderBytes + index * kReceiptRecordBytes;
    std::copy(receipts[index].operation_id.begin(),
              receipts[index].operation_id.end(), record);
    record[16] = static_cast<std::uint8_t>(receipts[index].operation);
    record[17] = static_cast<std::uint8_t>(receipts[index].state);
    record[18] = static_cast<std::uint8_t>(receipts[index].result);
    Put16(record + 19, receipts[index].argument);
    record[21] = receipts[index].flags;
  }
  Put32(output->data() + kCrcOffset,
        config::Crc32(output->data(), kCrcOffset));
  return true;
}

bool Decode(const ReceiptJournalBlob& input,
            std::array<Receipt, kReceiptCapacity>* receipts,
            std::size_t* count, std::uint64_t* generation) {
  if (receipts == nullptr || count == nullptr || generation == nullptr ||
      !std::equal(kMagic.begin(), kMagic.end(), input.begin()) ||
      input[4] != kVersion || input[6] != 0 || input[7] != 0 ||
      input[5] > kReceiptCapacity ||
      Get32(input.data() + kCrcOffset) !=
          config::Crc32(input.data(), kCrcOffset)) {
    return false;
  }
  const auto decoded_generation = Get64(input.data() + 8);
  if (decoded_generation == 0) {
    return false;
  }
  receipts->fill(Receipt{});
  std::size_t in_progress = 0;
  for (std::size_t index = 0; index < input[5]; ++index) {
    const auto* record =
        input.data() + kHeaderBytes + index * kReceiptRecordBytes;
    auto& receipt = (*receipts)[index];
    std::copy_n(record, receipt.operation_id.size(),
                receipt.operation_id.begin());
    receipt.operation = static_cast<Operation>(record[16]);
    receipt.state = static_cast<ReceiptState>(record[17]);
    receipt.result = static_cast<Status>(record[18]);
    receipt.argument = Get16(record + 19);
    receipt.flags = record[21];
    if (record[22] != 0 || record[23] != 0 || !ValidReceipt(receipt)) {
      return false;
    }
    in_progress += receipt.state == ReceiptState::kInProgress ? 1 : 0;
    for (std::size_t prior = 0; prior < index; ++prior) {
      if ((*receipts)[prior].operation_id == receipt.operation_id) {
        return false;
      }
    }
  }
  const auto used_end =
      kHeaderBytes + static_cast<std::size_t>(input[5]) * kReceiptRecordBytes;
  if (in_progress > 1 ||
      !std::all_of(input.begin() + used_end, input.begin() + kCrcOffset,
                   [](const std::uint8_t value) { return value == 0; })) {
    return false;
  }
  *count = input[5];
  *generation = decoded_generation;
  return true;
}

}  // namespace

ReceiptJournal::ReceiptJournal(ReceiptBlobStorage& storage)
    : storage_(storage) {}

bool ReceiptJournal::Initialize() {
  ReceiptJournalBlob blobs[2]{};
  std::array<Receipt, kReceiptCapacity> decoded[2]{};
  std::size_t counts[2]{};
  std::uint64_t generations[2]{};
  bool valid[2]{};
  bool absent[2]{};
  for (std::uint8_t slot = 0; slot < 2; ++slot) {
    const auto read = storage_.Read(slot, &blobs[slot]);
    if (read == ReceiptBlobReadStatus::kIoError) {
      return false;
    }
    absent[slot] = read == ReceiptBlobReadStatus::kNotFound;
    valid[slot] = read == ReceiptBlobReadStatus::kOk &&
                  Decode(blobs[slot], &decoded[slot], &counts[slot],
                         &generations[slot]);
  }
  if (!valid[0] && !valid[1]) {
    if (!absent[0] || !absent[1]) {
      return false;
    }
    receipts_.fill(Receipt{});
    count_ = 0;
    generation_ = 0;
    active_slot_ = 1;
    initialized_ = true;
    return true;
  }
  std::uint8_t selected = valid[1] ? 1 : 0;
  if (valid[0] && valid[1]) {
    if (generations[0] == generations[1]) {
      if (blobs[0] != blobs[1]) {
        return false;
      }
      selected = 1;
    } else {
      selected = generations[0] > generations[1] ? 0 : 1;
    }
  }
  receipts_ = decoded[selected];
  count_ = counts[selected];
  generation_ = generations[selected];
  active_slot_ = selected;
  initialized_ = true;
  return true;
}

bool ReceiptJournal::Find(const OperationId& operation_id, Receipt* receipt,
                          bool* found) {
  if (!initialized_ || receipt == nullptr || found == nullptr) {
    return false;
  }
  for (std::size_t index = 0; index < count_; ++index) {
    if (receipts_[index].operation_id == operation_id) {
      *receipt = receipts_[index];
      *found = true;
      return true;
    }
  }
  *found = false;
  return true;
}

bool ReceiptJournal::Save(const Receipt& receipt) {
  if (!initialized_ || !ValidReceipt(receipt) ||
      generation_ == std::numeric_limits<std::uint64_t>::max()) {
    return false;
  }
  auto next = receipts_;
  auto next_count = count_;
  for (std::size_t index = 0; index < count_; ++index) {
    if (next[index].operation_id == receipt.operation_id) {
      next[index] = receipt;
      return Commit(next, next_count);
    }
  }
  if (next_count == kReceiptCapacity) {
    std::move(next.begin() + 1, next.end(), next.begin());
    --next_count;
  }
  next[next_count++] = receipt;
  return Commit(next, next_count);
}

bool ReceiptJournal::FindInProgress(Receipt* receipt, bool* found) {
  if (!initialized_ || receipt == nullptr || found == nullptr) {
    return false;
  }
  *found = false;
  for (std::size_t index = 0; index < count_; ++index) {
    if (receipts_[index].state != ReceiptState::kInProgress) {
      continue;
    }
    if (*found) {
      return false;
    }
    *receipt = receipts_[index];
    *found = true;
  }
  return true;
}

bool ReceiptJournal::Last(Receipt* receipt, bool* found) const {
  if (!initialized_ || receipt == nullptr || found == nullptr) {
    return false;
  }
  *found = count_ != 0;
  if (*found) {
    *receipt = receipts_[count_ - 1];
  }
  return true;
}

bool ReceiptJournal::Commit(
    const std::array<Receipt, kReceiptCapacity>& receipts,
    const std::size_t count) {
  const auto next_generation = generation_ + 1;
  ReceiptJournalBlob encoded{};
  if (!Encode(receipts, count, next_generation, &encoded)) {
    return false;
  }
  const auto target = static_cast<std::uint8_t>(active_slot_ == 0 ? 1 : 0);
  if (!storage_.Write(target, encoded)) {
    return false;
  }
  ReceiptJournalBlob verified{};
  if (storage_.Read(target, &verified) != ReceiptBlobReadStatus::kOk ||
      verified != encoded) {
    return false;
  }
  receipts_ = receipts;
  count_ = count;
  generation_ = next_generation;
  active_slot_ = target;
  return true;
}

}  // namespace keyferry::local_management
