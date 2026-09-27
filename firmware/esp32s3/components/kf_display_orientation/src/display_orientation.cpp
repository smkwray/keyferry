#include "keyferry/display_orientation.h"

#include <algorithm>

namespace keyferry::display_orientation {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{'K', 'F', 'D', 'O'};
constexpr std::uint8_t kVersion = 1;

}  // namespace

bool IsSupported(const protocol::DisplayOrientation orientation) noexcept {
  return orientation == protocol::DisplayOrientation::kNormal ||
         orientation == protocol::DisplayOrientation::kRotated180;
}

bool Encode(const protocol::DisplayOrientation orientation,
            Record* const output) noexcept {
  if (output == nullptr || !IsSupported(orientation)) {
    return false;
  }
  output->fill(0);
  std::copy(kMagic.begin(), kMagic.end(), output->begin());
  (*output)[4] = kVersion;
  (*output)[5] = static_cast<std::uint8_t>(orientation);
  return true;
}

bool Decode(const Record& record,
            protocol::DisplayOrientation* const output) noexcept {
  if (output != nullptr) {
    *output = protocol::DisplayOrientation::kNormal;
  }
  const auto orientation =
      static_cast<protocol::DisplayOrientation>(record[5]);
  if (output == nullptr ||
      !std::equal(kMagic.begin(), kMagic.end(), record.begin()) ||
      record[4] != kVersion || record[6] != 0 || record[7] != 0 ||
      !IsSupported(orientation)) {
    return false;
  }
  *output = orientation;
  return true;
}

LoadResult Load(Storage& storage) noexcept {
  Record record{};
  switch (storage.Read(&record)) {
    case ReadResult::kAbsent:
      return {protocol::DisplayOrientation::kNormal,
              LoadStatus::kDefaultAbsent};
    case ReadResult::kError:
      return {protocol::DisplayOrientation::kNormal,
              LoadStatus::kDefaultStorageError};
    case ReadResult::kPresent:
      break;
  }
  protocol::DisplayOrientation orientation{};
  return Decode(record, &orientation)
             ? LoadResult{orientation, LoadStatus::kStored}
             : LoadResult{protocol::DisplayOrientation::kNormal,
                          LoadStatus::kDefaultMalformed};
}

bool Save(Storage& storage,
          const protocol::DisplayOrientation orientation) noexcept {
  Record record{};
  return Encode(orientation, &record) && storage.Write(record);
}

bool IsSupportedPower(const protocol::ScreenPower power) noexcept {
  return power == protocol::ScreenPower::kOff ||
         power == protocol::ScreenPower::kOn;
}

bool DecodeSetPowerRequest(const std::uint8_t* const payload,
                           const std::size_t length,
                           protocol::ScreenPower* const output) noexcept {
  if (payload == nullptr || output == nullptr || length != 1) return false;
  const auto power = static_cast<protocol::ScreenPower>(payload[0]);
  if (!IsSupportedPower(power)) return false;
  *output = power;
  return true;
}

bool CanSetPower(const PowerMutationInputs& inputs) noexcept {
  return inputs.display_available && !inputs.command_active && !inputs.armed &&
         inputs.keyboard_neutral && inputs.mouse_neutral &&
         !inputs.report_needed && !inputs.usb_transfer_in_flight &&
         !inputs.ble_release_in_flight;
}

PowerLoadResult LoadPower(Storage& storage) noexcept {
  std::uint8_t value = 0;
  switch (storage.ReadPower(&value)) {
    case ReadResult::kAbsent:
      return {protocol::ScreenPower::kOn, LoadStatus::kDefaultAbsent};
    case ReadResult::kError:
      return {protocol::ScreenPower::kOn, LoadStatus::kDefaultStorageError};
    case ReadResult::kPresent:
      break;
  }
  const auto power = static_cast<protocol::ScreenPower>(value);
  return IsSupportedPower(power)
             ? PowerLoadResult{power, LoadStatus::kStored}
             : PowerLoadResult{protocol::ScreenPower::kOn,
                               LoadStatus::kDefaultMalformed};
}

bool SavePower(Storage& storage, const protocol::ScreenPower power) noexcept {
  return IsSupportedPower(power) &&
         storage.WritePower(static_cast<std::uint8_t>(power));
}

}  // namespace keyferry::display_orientation
