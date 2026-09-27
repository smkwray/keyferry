#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry_protocol_generated.h"

namespace keyferry::display_orientation {

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
  protocol::DisplayOrientation orientation{
      protocol::DisplayOrientation::kNormal};
  LoadStatus status{LoadStatus::kDefaultStorageError};
};

struct PowerLoadResult {
  protocol::ScreenPower power{protocol::ScreenPower::kOn};
  LoadStatus status{LoadStatus::kDefaultStorageError};
};

// Stored preference and the last hardware-confirmed state are distinct. An
// accepted request can be pending until the display task applies it.
class PowerState final {
 public:
  explicit PowerState(protocol::ScreenPower stored) : stored_(stored) {}
  protocol::ScreenPower stored() const { return stored_; }
  protocol::ScreenPower active() const { return active_; }
  bool available() const { return available_; }
  void SetStored(protocol::ScreenPower power) { stored_ = power; }
  void Applied(protocol::ScreenPower power) {
    active_ = power;
    available_ = true;
  }
  void Unavailable() { available_ = false; }

 private:
  protocol::ScreenPower stored_;
  protocol::ScreenPower active_{protocol::ScreenPower::kOn};
  bool available_{false};
};

class Storage {
 public:
  virtual ~Storage() = default;
  virtual ReadResult Read(Record* output) = 0;
  virtual bool Write(const Record& record) = 0;
  virtual ReadResult ReadPower(std::uint8_t* output) = 0;
  virtual bool WritePower(std::uint8_t power) = 0;
};

bool IsSupported(protocol::DisplayOrientation orientation) noexcept;
bool Encode(protocol::DisplayOrientation orientation, Record* output) noexcept;
bool Decode(const Record& record,
            protocol::DisplayOrientation* output) noexcept;
LoadResult Load(Storage& storage) noexcept;
bool Save(Storage& storage,
          protocol::DisplayOrientation orientation) noexcept;
bool IsSupportedPower(protocol::ScreenPower power) noexcept;
bool DecodeSetPowerRequest(const std::uint8_t* payload, std::size_t length,
                           protocol::ScreenPower* output) noexcept;
struct PowerMutationInputs {
  bool display_available{};
  bool command_active{};
  bool armed{};
  bool keyboard_neutral{};
  bool mouse_neutral{};
  bool report_needed{};
  bool usb_transfer_in_flight{};
  bool ble_release_in_flight{};
};
bool CanSetPower(const PowerMutationInputs& inputs) noexcept;
PowerLoadResult LoadPower(Storage& storage) noexcept;
bool SavePower(Storage& storage, protocol::ScreenPower power) noexcept;

}  // namespace keyferry::display_orientation
