#include <cassert>

#include "keyferry/display_orientation.h"

namespace {

class MemoryStorage final : public keyferry::display_orientation::Storage {
 public:
  keyferry::display_orientation::ReadResult Read(
      keyferry::display_orientation::Record* output) override {
    if (result == keyferry::display_orientation::ReadResult::kPresent &&
        output != nullptr) {
      *output = record;
    }
    return result;
  }

  bool Write(const keyferry::display_orientation::Record& value) override {
    if (!write_ok) {
      return false;
    }
    record = value;
    result = keyferry::display_orientation::ReadResult::kPresent;
    return true;
  }

  keyferry::display_orientation::ReadResult ReadPower(
      std::uint8_t* output) override {
    if (power_result == keyferry::display_orientation::ReadResult::kPresent &&
        output != nullptr) {
      *output = power;
    }
    return power_result;
  }

  bool WritePower(const std::uint8_t value) override {
    if (!write_ok) return false;
    power = value;
    power_result = keyferry::display_orientation::ReadResult::kPresent;
    return true;
  }

  keyferry::display_orientation::ReadResult result{
      keyferry::display_orientation::ReadResult::kAbsent};
  keyferry::display_orientation::Record record{};
  bool write_ok{true};
  keyferry::display_orientation::ReadResult power_result{
      keyferry::display_orientation::ReadResult::kAbsent};
  std::uint8_t power{};
};

}  // namespace

int main() {
  using keyferry::display_orientation::LoadStatus;
  using keyferry::protocol::DisplayOrientation;

  MemoryStorage storage;
  auto loaded = keyferry::display_orientation::Load(storage);
  assert(loaded.orientation == DisplayOrientation::kNormal);
  assert(loaded.status == LoadStatus::kDefaultAbsent);

  assert(keyferry::display_orientation::Save(
      storage, DisplayOrientation::kRotated180));
  loaded = keyferry::display_orientation::Load(storage);
  assert(loaded.orientation == DisplayOrientation::kRotated180);
  assert(loaded.status == LoadStatus::kStored);

  storage.record[6] = 1;
  loaded = keyferry::display_orientation::Load(storage);
  assert(loaded.orientation == DisplayOrientation::kNormal);
  assert(loaded.status == LoadStatus::kDefaultMalformed);

  storage.write_ok = false;
  assert(!keyferry::display_orientation::Save(
      storage, DisplayOrientation::kNormal));
  assert(!keyferry::display_orientation::IsSupported(
      static_cast<DisplayOrientation>(0xff)));

  using keyferry::protocol::ScreenPower;
  auto power = keyferry::display_orientation::LoadPower(storage);
  assert(power.power == ScreenPower::kOn &&
         power.status == LoadStatus::kDefaultAbsent);
  keyferry::display_orientation::PowerState state(power.power);
  assert(!state.available() && state.stored() == ScreenPower::kOn);
  state.Applied(ScreenPower::kOn);
  assert(state.available() && state.active() == ScreenPower::kOn);
  storage.write_ok = true;
  assert(keyferry::display_orientation::SavePower(storage, ScreenPower::kOff));
  power = keyferry::display_orientation::LoadPower(storage);
  assert(power.power == ScreenPower::kOff && power.status == LoadStatus::kStored);
  state.SetStored(power.power);
  assert(state.available() && state.active() == ScreenPower::kOn &&
         state.stored() == ScreenPower::kOff);
  state.Applied(ScreenPower::kOff);
  assert(state.available() && state.active() == ScreenPower::kOff);
  state.Unavailable();
  assert(!state.available());
  storage.power = 0xff;
  power = keyferry::display_orientation::LoadPower(storage);
  assert(power.power == ScreenPower::kOn &&
         power.status == LoadStatus::kDefaultMalformed);
  storage.power_result = keyferry::display_orientation::ReadResult::kError;
  power = keyferry::display_orientation::LoadPower(storage);
  assert(power.power == ScreenPower::kOn &&
         power.status == LoadStatus::kDefaultStorageError);
  storage.write_ok = false;
  assert(!keyferry::display_orientation::SavePower(storage, ScreenPower::kOn));
  assert(!keyferry::display_orientation::SavePower(
      storage, static_cast<ScreenPower>(0xff)));
  ScreenPower decoded{};
  const std::uint8_t off_request[]{static_cast<std::uint8_t>(ScreenPower::kOff), 0};
  assert(keyferry::display_orientation::DecodeSetPowerRequest(
      off_request, 1, &decoded));
  assert(decoded == ScreenPower::kOff);
  assert(!keyferry::display_orientation::DecodeSetPowerRequest(
      off_request, 0, &decoded));
  assert(!keyferry::display_orientation::DecodeSetPowerRequest(
      off_request, 2, &decoded));
  assert(!keyferry::display_orientation::DecodeSetPowerRequest(
      nullptr, 1, &decoded));
  const std::uint8_t invalid_request[]{0xff};
  assert(!keyferry::display_orientation::DecodeSetPowerRequest(
      invalid_request, 1, &decoded));
  assert(decoded == ScreenPower::kOff);
  keyferry::display_orientation::PowerMutationInputs inputs{};
  inputs.display_available = true;
  inputs.keyboard_neutral = true;
  inputs.mouse_neutral = true;
  assert(keyferry::display_orientation::CanSetPower(inputs));
  inputs.armed = true;
  assert(!keyferry::display_orientation::CanSetPower(inputs));
  inputs.armed = false;
  inputs.command_active = true;
  assert(!keyferry::display_orientation::CanSetPower(inputs));
  inputs.command_active = false;
  inputs.report_needed = true;
  assert(!keyferry::display_orientation::CanSetPower(inputs));
  inputs.report_needed = false;
  inputs.keyboard_neutral = false;
  assert(!keyferry::display_orientation::CanSetPower(inputs));
  inputs.keyboard_neutral = true;
  inputs.mouse_neutral = false;
  assert(!keyferry::display_orientation::CanSetPower(inputs));
  inputs.mouse_neutral = true;
  inputs.usb_transfer_in_flight = true;
  assert(!keyferry::display_orientation::CanSetPower(inputs));
  inputs.usb_transfer_in_flight = false;
  inputs.ble_release_in_flight = true;
  assert(!keyferry::display_orientation::CanSetPower(inputs));
  inputs.ble_release_in_flight = false;
  inputs.display_available = false;
  assert(!keyferry::display_orientation::CanSetPower(inputs));
  return 0;
}
