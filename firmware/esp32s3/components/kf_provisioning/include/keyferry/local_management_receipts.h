#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry/local_management_coordinator.h"

namespace keyferry::local_management {

constexpr std::size_t kReceiptCapacity = 16;
constexpr std::size_t kReceiptRecordBytes = 24;
constexpr std::size_t kReceiptJournalBytes =
    16 + kReceiptCapacity * kReceiptRecordBytes + 4;
using ReceiptJournalBlob = std::array<std::uint8_t, kReceiptJournalBytes>;

enum class ReceiptBlobReadStatus : std::uint8_t {
  kOk,
  kNotFound,
  kIoError,
};

class ReceiptBlobStorage {
 public:
  virtual ~ReceiptBlobStorage() = default;
  virtual ReceiptBlobReadStatus Read(std::uint8_t slot,
                                     ReceiptJournalBlob* output) = 0;
  virtual bool Write(std::uint8_t slot,
                     const ReceiptJournalBlob& data) = 0;
};

// Fixed-capacity, metadata-only A/B journal. The newest 16 operation receipts
// are retained; an evicted identifier is reported unknown and never causes an
// automatic retry. Each update is verified before becoming runtime state.
class ReceiptJournal final : public ReceiptStorage {
 public:
  explicit ReceiptJournal(ReceiptBlobStorage& storage);

  bool Initialize();
  bool Find(const OperationId& operation_id, Receipt* receipt,
            bool* found) override;
  bool Save(const Receipt& receipt) override;
  bool FindInProgress(Receipt* receipt, bool* found) override;
  bool Last(Receipt* receipt, bool* found) const;

  [[nodiscard]] std::size_t size() const { return count_; }
  [[nodiscard]] std::uint64_t generation() const { return generation_; }

 private:
  bool Commit(const std::array<Receipt, kReceiptCapacity>& receipts,
              std::size_t count);

  ReceiptBlobStorage& storage_;
  std::array<Receipt, kReceiptCapacity> receipts_{};
  std::size_t count_{};
  std::uint64_t generation_{};
  std::uint8_t active_slot_{1};
  bool initialized_{};
};

}  // namespace keyferry::local_management
