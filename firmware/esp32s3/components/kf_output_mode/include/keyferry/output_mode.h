#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry_protocol_generated.h"

namespace keyferry::output_mode {

constexpr std::size_t kRecordBytes = 8;
using Record = std::array<std::uint8_t, kRecordBytes>;

enum class ReadResult : std::uint8_t {
  kAbsent,
  kPresent,
  kError,
};

enum class LoadStatus : std::uint8_t {
  kStored,
  kDefaultAbsent,
  kDefaultMalformed,
  kDefaultStorageError,
};

struct LoadResult {
  protocol::OutputMode mode{protocol::OutputMode::kUsbHid};
  LoadStatus status{LoadStatus::kDefaultStorageError};
};

class Storage {
 public:
  virtual ~Storage() = default;
  virtual ReadResult Read(Record* output) = 0;
  virtual bool Write(const Record& record) = 0;
};

bool IsSupported(protocol::OutputMode mode) noexcept;
bool Encode(protocol::OutputMode mode, Record* output) noexcept;
bool Decode(const Record& record, protocol::OutputMode* output) noexcept;
LoadResult Load(Storage& storage) noexcept;
bool Save(Storage& storage, protocol::OutputMode mode) noexcept;
protocol::OutputMode EffectiveBootMode(protocol::OutputMode stored,
                                       bool usb_recovery_requested) noexcept;

}  // namespace keyferry::output_mode
