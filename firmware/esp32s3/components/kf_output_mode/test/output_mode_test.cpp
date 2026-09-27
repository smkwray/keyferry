#include "keyferry/output_mode.h"

#include <cassert>
#include <cstdlib>
#include <iostream>

namespace {

using keyferry::output_mode::LoadStatus;
using keyferry::output_mode::ReadResult;
using keyferry::output_mode::Record;
using keyferry::protocol::OutputMode;

class FakeStorage final : public keyferry::output_mode::Storage {
 public:
  ReadResult Read(Record* output) override {
    if (read == ReadResult::kPresent && output != nullptr) {
      *output = record;
    }
    return read;
  }

  bool Write(const Record& value) override {
    ++writes;
    if (!write_ok) {
      return false;
    }
    record = value;
    read = ReadResult::kPresent;
    return true;
  }

  ReadResult read{ReadResult::kAbsent};
  Record record{};
  bool write_ok{true};
  int writes{0};
};

void Missing_and_failed_storage_default_only_to_usb() {
  FakeStorage storage;
  auto result = keyferry::output_mode::Load(storage);
  assert(result.mode == OutputMode::kUsbHid);
  assert(result.status == LoadStatus::kDefaultAbsent);

  storage.read = ReadResult::kError;
  result = keyferry::output_mode::Load(storage);
  assert(result.mode == OutputMode::kUsbHid);
  assert(result.status == LoadStatus::kDefaultStorageError);
}

void Round_trip_accepts_only_the_two_named_modes() {
  FakeStorage storage;
  assert(keyferry::output_mode::Save(storage, OutputMode::kBleHid));
  assert(storage.writes == 1);
  const auto result = keyferry::output_mode::Load(storage);
  assert(result.mode == OutputMode::kBleHid);
  assert(result.status == LoadStatus::kStored);

  assert(!keyferry::output_mode::Save(
      storage, static_cast<OutputMode>(0x7F)));
  assert(storage.writes == 1);
}

void Every_malformed_field_falls_back_to_usb() {
  FakeStorage storage;
  assert(keyferry::output_mode::Save(storage, OutputMode::kBleHid));
  const Record valid = storage.record;
  for (std::size_t index = 0; index < valid.size(); ++index) {
    storage.record = valid;
    storage.record[index] ^= 0x80;
    const auto result = keyferry::output_mode::Load(storage);
    assert(result.mode == OutputMode::kUsbHid);
    assert(result.status == LoadStatus::kDefaultMalformed);
  }
}

void Failed_write_never_changes_the_selected_record() {
  FakeStorage storage;
  assert(keyferry::output_mode::Save(storage, OutputMode::kUsbHid));
  const Record before = storage.record;
  storage.write_ok = false;
  assert(!keyferry::output_mode::Save(storage, OutputMode::kBleHid));
  assert(storage.record == before);
}

void Recovery_override_is_one_boot_and_never_enables_ble() {
  assert(keyferry::output_mode::EffectiveBootMode(OutputMode::kBleHid, false) ==
         OutputMode::kBleHid);
  assert(keyferry::output_mode::EffectiveBootMode(OutputMode::kBleHid, true) ==
         OutputMode::kUsbHid);
  assert(keyferry::output_mode::EffectiveBootMode(OutputMode::kUsbHid, true) ==
         OutputMode::kUsbHid);
  assert(keyferry::output_mode::EffectiveBootMode(
             static_cast<OutputMode>(0x7F), false) == OutputMode::kUsbHid);
}

}  // namespace

int main() {
  Missing_and_failed_storage_default_only_to_usb();
  Round_trip_accepts_only_the_two_named_modes();
  Every_malformed_field_falls_back_to_usb();
  Failed_write_never_changes_the_selected_record();
  Recovery_override_is_one_boot_and_never_enables_ble();
  std::cout << "output_mode_test: ok\n";
  return EXIT_SUCCESS;
}
