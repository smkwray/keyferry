#pragma once

#include <cstddef>
#include <cstdint>

#include "esp_partition.h"
#include "keyferry/config_storage.h"

namespace keyferry::config {

constexpr std::size_t kConfigPartitionBytes = 0x4000;

class IdfConfigStorage final : public SlotStorage {
 public:
  IdfConfigStorage();

  bool ready() const;
  bool Read(SlotId slot, std::uint8_t* output, std::size_t length) override;
  bool Erase(SlotId slot) override;
  bool Write(SlotId slot, std::size_t offset, const std::uint8_t* data,
             std::size_t length) override;

 private:
  const esp_partition_t* Partition(SlotId slot) const;

  const esp_partition_t* slot_a_;
  const esp_partition_t* slot_b_;
};

}  // namespace keyferry::config
