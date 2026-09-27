#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry/config_store.h"

namespace keyferry::config {

class SlotStorage {
 public:
  virtual ~SlotStorage() = default;
  virtual bool Read(SlotId slot, std::uint8_t* output, std::size_t length) = 0;
  virtual bool Erase(SlotId slot) = 0;
  virtual bool Write(SlotId slot, std::size_t offset, const std::uint8_t* data,
                     std::size_t length) = 0;
};

struct StorageWorkspace {
  std::array<std::uint8_t, kSlotBytes> slot_a{};
  std::array<std::uint8_t, kSlotBytes> slot_b{};
};

enum class StorageStatus : std::uint8_t {
  kOk,
  kErasedUnprovisioned,
  kMalformedSlots,
  kInvalidConfig,
  kIoError,
  kVerificationFailed,
  kAmbiguousSlots,
  kGenerationExhausted,
};

// Both slots must be readable. Malformed slots are handled by the A/B selector,
// while an actual storage I/O failure is never silently treated as an erased slot.
StorageStatus LoadConfig(SlotStorage& storage, StorageWorkspace* workspace,
                         EndpointConfig* config, Selection* selection);

// Erases and writes only the inactive/older slot. The full body is read back
// before the commit marker is written, then the committed slot is read back
// byte-for-byte. The caller must keep this large workspace out of task stacks.
StorageStatus CommitConfig(SlotStorage& storage, StorageWorkspace* workspace,
                           const EndpointConfig& config, Selection* selection);

}  // namespace keyferry::config
