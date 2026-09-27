#include "keyferry/output_mode.h"

#include <algorithm>

namespace keyferry::output_mode {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{'K', 'F', 'O', 'M'};
constexpr std::uint8_t kVersion = 1;

}  // namespace

bool IsSupported(const protocol::OutputMode mode) noexcept {
  return mode == protocol::OutputMode::kUsbHid ||
         mode == protocol::OutputMode::kBleHid;
}

bool Encode(const protocol::OutputMode mode, Record* const output) noexcept {
  if (output == nullptr || !IsSupported(mode)) {
    return false;
  }
  output->fill(0);
  std::copy(kMagic.begin(), kMagic.end(), output->begin());
  (*output)[4] = kVersion;
  (*output)[5] = static_cast<std::uint8_t>(mode);
  return true;
}

bool Decode(const Record& record, protocol::OutputMode* const output) noexcept {
  if (output != nullptr) {
    *output = protocol::OutputMode::kUsbHid;
  }
  const auto mode = static_cast<protocol::OutputMode>(record[5]);
  if (output == nullptr ||
      !std::equal(kMagic.begin(), kMagic.end(), record.begin()) ||
      record[4] != kVersion || record[6] != 0 || record[7] != 0 ||
      !IsSupported(mode)) {
    return false;
  }
  *output = mode;
  return true;
}

LoadResult Load(Storage& storage) noexcept {
  Record record{};
  switch (storage.Read(&record)) {
    case ReadResult::kAbsent:
      return {protocol::OutputMode::kUsbHid, LoadStatus::kDefaultAbsent};
    case ReadResult::kError:
      return {protocol::OutputMode::kUsbHid,
              LoadStatus::kDefaultStorageError};
    case ReadResult::kPresent:
      break;
  }
  protocol::OutputMode mode{};
  return Decode(record, &mode)
             ? LoadResult{mode, LoadStatus::kStored}
             : LoadResult{protocol::OutputMode::kUsbHid,
                          LoadStatus::kDefaultMalformed};
}

bool Save(Storage& storage, const protocol::OutputMode mode) noexcept {
  Record record{};
  return Encode(mode, &record) && storage.Write(record);
}

protocol::OutputMode EffectiveBootMode(
    const protocol::OutputMode stored,
    const bool usb_recovery_requested) noexcept {
  if (!IsSupported(stored) || usb_recovery_requested) {
    return protocol::OutputMode::kUsbHid;
  }
  return stored;
}

}  // namespace keyferry::output_mode
