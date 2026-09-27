#pragma once

#include <cstddef>
#include <cstdint>

#include "keyferry/roaming_storage.h"

namespace keyferry::config {

// Uses the existing partition named "nvs" and a dedicated namespace/key. The
// application must initialize NVS once before constructing or using this
// adapter. This class never erases or reformats NVS automatically.
class IdfRecoveryAnchorStorage final : public RecoveryAnchorStorage {
 public:
  AnchorReadStatus Read(std::uint8_t* output, std::size_t length) override;
  bool Write(const std::uint8_t* data, std::size_t length) override;
};

}  // namespace keyferry::config
