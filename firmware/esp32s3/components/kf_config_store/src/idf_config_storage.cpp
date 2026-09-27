#include "keyferry/idf_config_storage.h"

#include <cstring>

#include "esp_partition.h"
#include "keyferry/roaming_config.h"

namespace keyferry::config {
namespace {

constexpr esp_partition_subtype_t kSlotASubtype =
    static_cast<esp_partition_subtype_t>(0x40);
constexpr esp_partition_subtype_t kSlotBSubtype =
    static_cast<esp_partition_subtype_t>(0x41);

bool ValidPartition(const esp_partition_t* partition, esp_partition_subtype_t subtype,
                    const char* label) {
  return partition != nullptr && partition->type == ESP_PARTITION_TYPE_DATA &&
         partition->subtype == subtype && partition->size == kConfigPartitionBytes &&
         partition->encrypted == false && std::strcmp(partition->label, label) == 0;
}

}  // namespace

IdfConfigStorage::IdfConfigStorage()
    : slot_a_(esp_partition_find_first(ESP_PARTITION_TYPE_DATA, kSlotASubtype,
                                       "kf_cfg_a")),
      slot_b_(esp_partition_find_first(ESP_PARTITION_TYPE_DATA, kSlotBSubtype,
                                       "kf_cfg_b")) {}

bool IdfConfigStorage::ready() const {
  return ValidPartition(slot_a_, kSlotASubtype, "kf_cfg_a") &&
         ValidPartition(slot_b_, kSlotBSubtype, "kf_cfg_b") &&
         slot_a_->address != slot_b_->address;
}

const esp_partition_t* IdfConfigStorage::Partition(SlotId slot) const {
  if (slot == SlotId::kA) {
    return slot_a_;
  }
  if (slot == SlotId::kB) {
    return slot_b_;
  }
  return nullptr;
}

bool IdfConfigStorage::Read(SlotId slot, std::uint8_t* output, std::size_t length) {
  const esp_partition_t* partition = Partition(slot);
  const bool supported_length =
      length == kSlotBytes || length == kRoamingConfigSlotBytes;
  return ready() && partition != nullptr && output != nullptr && supported_length &&
         esp_partition_read(partition, 0, output, length) == ESP_OK;
}

bool IdfConfigStorage::Erase(SlotId slot) {
  const esp_partition_t* partition = Partition(slot);
  return ready() && partition != nullptr &&
         esp_partition_erase_range(partition, 0, partition->size) == ESP_OK;
}

bool IdfConfigStorage::Write(SlotId slot, std::size_t offset,
                             const std::uint8_t* data, std::size_t length) {
  const esp_partition_t* partition = Partition(slot);
  return ready() && partition != nullptr && data != nullptr &&
         offset <= kRoamingConfigSlotBytes &&
         length <= kRoamingConfigSlotBytes - offset &&
         esp_partition_write(partition, offset, data, length) == ESP_OK;
}

}  // namespace keyferry::config
