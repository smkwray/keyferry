#pragma once

#include "keyferry/local_management_receipts.h"

namespace keyferry::local_management {

// Uses two fixed blobs in the existing NVS partition. The application must
// initialize NVS first. This adapter never erases or reformats NVS.
class IdfReceiptBlobStorage final : public ReceiptBlobStorage {
 public:
  ReceiptBlobReadStatus Read(std::uint8_t slot,
                             ReceiptJournalBlob* output) override;
  bool Write(std::uint8_t slot,
             const ReceiptJournalBlob& data) override;
};

}  // namespace keyferry::local_management
