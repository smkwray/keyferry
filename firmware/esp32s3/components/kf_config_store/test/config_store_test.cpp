#include "keyferry/config_store.h"
#include "keyferry/config_storage.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

namespace {

using keyferry::config::ConfigState;
using keyferry::config::EndpointConfig;
using keyferry::config::SlotId;
using keyferry::config::SlotCondition;
using keyferry::config::SlotView;
using keyferry::config::StorageStatus;

class FakeStorage final : public keyferry::config::SlotStorage {
 public:
  FakeStorage() {
    a.fill(0xFF);
    b.fill(0xFF);
  }

  bool Read(SlotId slot, std::uint8_t* output, std::size_t length) override {
    if (fail_read || output == nullptr || length != keyferry::config::kSlotBytes) {
      return false;
    }
    const auto* source = Buffer(slot);
    if (source == nullptr) {
      return false;
    }
    std::copy(source->begin(), source->end(), output);
    return true;
  }

  bool Erase(SlotId slot) override {
    auto* target = Buffer(slot);
    ++erase_calls;
    if (fail_erase || target == nullptr) {
      return false;
    }
    target->fill(0xFF);
    return true;
  }

  bool Write(SlotId slot, std::size_t offset, const std::uint8_t* data,
             std::size_t length) override {
    auto* target = Buffer(slot);
    ++write_calls;
    if (target == nullptr || data == nullptr || offset > target->size() ||
        length > target->size() - offset ||
        (fail_on_write_call != 0 && write_calls == fail_on_write_call)) {
      return false;
    }
    const std::size_t written = std::min(write_limit, length);
    std::copy_n(data, written, target->begin() + offset);
    last_written = slot;
    return written == length;
  }

  std::array<std::uint8_t, keyferry::config::kSlotBytes> a{};
  std::array<std::uint8_t, keyferry::config::kSlotBytes> b{};
  bool fail_read{false};
  bool fail_erase{false};
  std::size_t write_limit{keyferry::config::kSlotBytes};
  std::size_t write_calls{0};
  std::size_t erase_calls{0};
  std::size_t fail_on_write_call{0};
  SlotId last_written{SlotId::kNone};

 private:
  std::array<std::uint8_t, keyferry::config::kSlotBytes>* Buffer(SlotId slot) {
    return slot == SlotId::kA ? &a : slot == SlotId::kB ? &b : nullptr;
  }

  const std::array<std::uint8_t, keyferry::config::kSlotBytes>* Buffer(
      SlotId slot) const {
    return slot == SlotId::kA ? &a : slot == SlotId::kB ? &b : nullptr;
  }
};

EndpointConfig ValidConfig(std::uint8_t marker = 1) {
  EndpointConfig config{};
  config.device_id.fill(marker);
  config.provisioning_key.fill(static_cast<std::uint8_t>(marker + 1));
  config.wifi_profile_count = 1;
  config.paired_host_count = 1;

  auto& wifi = config.wifi_profiles[0];
  constexpr char kSsid[] = "test-network";
  constexpr char kCredential[] = "test-password";
  wifi.security = keyferry::config::WifiSecurity::kWpa2Personal;
  wifi.priority = 7;
  wifi.ssid_length = sizeof(kSsid) - 1;
  wifi.credential_length = sizeof(kCredential) - 1;
  std::copy_n(reinterpret_cast<const std::uint8_t*>(kSsid), wifi.ssid_length,
              wifi.ssid.begin());
  std::copy_n(reinterpret_cast<const std::uint8_t*>(kCredential),
              wifi.credential_length, wifi.credential.begin());

  auto& host = config.paired_hosts[0];
  host.host_id.fill(static_cast<std::uint8_t>(marker + 2));
  host.ipv4 = {192, 0, 2, marker};
  host.port = 7443;
  constexpr char kServerName[] = "controller.invalid";
  host.server_name_length = sizeof(kServerName) - 1;
  std::copy_n(kServerName, host.server_name_length, host.server_name.begin());
  host.peer_spki_sha256.fill(static_cast<std::uint8_t>(marker + 3));
  host.link_secret.fill(static_cast<std::uint8_t>(marker + 4));
  host.ca_certificate_length = 4;
  host.ca_certificate_der[0] = 0x30;
  host.ca_certificate_der[1] = 0x02;
  host.ca_certificate_der[2] = marker;
  host.ca_certificate_der[3] = static_cast<std::uint8_t>(marker + 5);
  return config;
}

template <typename Slot>
SlotView View(const Slot& slot) {
  return {slot.data(), slot.size()};
}

bool WorkspaceIsZero(const keyferry::config::StorageWorkspace& workspace) {
  const auto* begin = reinterpret_cast<const std::uint8_t*>(&workspace);
  return std::all_of(begin, begin + sizeof(workspace),
                     [](std::uint8_t byte) { return byte == 0; });
}

void TestCrcKnownAnswer() {
  constexpr char kInput[] = "123456789";
  assert(keyferry::config::Crc32(reinterpret_cast<const std::uint8_t*>(kInput),
                                sizeof(kInput) - 1) == 0xCBF43926U);
}

void TestHighestValidGenerationWins() {
  std::array<std::uint8_t, keyferry::config::kSlotBytes> a{};
  std::array<std::uint8_t, keyferry::config::kSlotBytes> b{};
  const auto old_config = ValidConfig(1);
  const auto new_config = ValidConfig(9);
  assert(keyferry::config::EncodeSlot(41, old_config, &a));
  assert(keyferry::config::EncodeSlot(42, new_config, &b));
  EndpointConfig selected{};
  const auto result = keyferry::config::SelectNewest(View(a), View(b), &selected);
  assert(result.state == ConfigState::kReady);
  assert(result.slot == SlotId::kB);
  assert(result.generation == 42);
  assert(selected.device_id == new_config.device_id);
}

void TestNeitherValidLocksUnprovisioned() {
  std::array<std::uint8_t, keyferry::config::kSlotBytes> erased{};
  erased.fill(0xFF);
  EndpointConfig selected = ValidConfig();
  const auto result = keyferry::config::SelectNewest(View(erased), View(erased), &selected);
  assert(result.state == ConfigState::kLockedUnprovisioned);
  assert(result.slot == SlotId::kNone);
  assert(result.generation == 0);
  assert(selected.wifi_profile_count == 0);
  const auto plan = keyferry::config::PlanUpdate(View(erased), View(erased));
  assert(plan.writable && plan.target == SlotId::kA && plan.generation == 1);
}

void TestSlotInspectionDistinguishesErasedMalformedAndValid() {
  std::array<std::uint8_t, keyferry::config::kSlotBytes> slot{};
  slot.fill(0xFF);
  assert(keyferry::config::InspectSlot(View(slot)).condition ==
         SlotCondition::kErased);
  slot[0] = 0;
  assert(keyferry::config::InspectSlot(View(slot)).condition ==
         SlotCondition::kMalformed);
  assert(keyferry::config::EncodeSlot(1, ValidConfig(), &slot));
  const auto valid = keyferry::config::InspectSlot(View(slot));
  assert(valid.condition == SlotCondition::kValid && valid.generation == 1);
}

void TestConflictingEqualGenerationsLock() {
  std::array<std::uint8_t, keyferry::config::kSlotBytes> a{};
  std::array<std::uint8_t, keyferry::config::kSlotBytes> b{};
  assert(keyferry::config::EncodeSlot(7, ValidConfig(1), &a));
  assert(keyferry::config::EncodeSlot(7, ValidConfig(2), &b));
  EndpointConfig selected = ValidConfig();
  const auto result = keyferry::config::SelectNewest(View(a), View(b), &selected);
  assert(result.state == ConfigState::kLockedUnprovisioned);
  assert(result.slot == SlotId::kNone && result.generation == 0);
  assert(selected.wifi_profile_count == 0);
  const auto plan = keyferry::config::PlanUpdate(View(a), View(b));
  assert(!plan.writable && plan.target == SlotId::kNone);

  FakeStorage storage;
  storage.a = a;
  storage.b = b;
  keyferry::config::StorageWorkspace workspace{};
  keyferry::config::Selection selection{};
  assert(keyferry::config::CommitConfig(storage, &workspace, ValidConfig(3),
                                        &selection) ==
         StorageStatus::kAmbiguousSlots);
}

void TestTornWriteNeverSupplantsOldSlot() {
  std::array<std::uint8_t, keyferry::config::kSlotBytes> a{};
  std::array<std::uint8_t, keyferry::config::kSlotBytes> old_b{};
  std::array<std::uint8_t, keyferry::config::kSlotBytes> next_b{};
  assert(keyferry::config::EncodeSlot(7, ValidConfig(1), &a));
  assert(keyferry::config::EncodeSlot(6, ValidConfig(2), &old_b));
  assert(keyferry::config::EncodeSlot(8, ValidConfig(3), &next_b));

  const auto plan = keyferry::config::PlanUpdate(View(a), View(old_b));
  assert(plan.writable && plan.target == SlotId::kB && plan.generation == 8);
  for (std::size_t written = 0; written < next_b.size(); ++written) {
    std::array<std::uint8_t, keyferry::config::kSlotBytes> torn{};
    torn.fill(0xFF);
    std::copy_n(next_b.begin(), written, torn.begin());
    EndpointConfig selected{};
    const auto result = keyferry::config::SelectNewest(View(a), View(torn), &selected);
    assert(result.state == ConfigState::kReady);
    assert(result.slot == SlotId::kA);
    assert(result.generation == 7);
  }

  EndpointConfig selected{};
  const auto complete = keyferry::config::SelectNewest(View(a), View(next_b), &selected);
  assert(complete.state == ConfigState::kReady);
  assert(complete.slot == SlotId::kB && complete.generation == 8);
}

void TestHeaderAndPayloadCorruptionFallBack() {
  std::array<std::uint8_t, keyferry::config::kSlotBytes> a{};
  std::array<std::uint8_t, keyferry::config::kSlotBytes> b{};
  assert(keyferry::config::EncodeSlot(10, ValidConfig(1), &a));
  assert(keyferry::config::EncodeSlot(11, ValidConfig(2), &b));
  for (const std::size_t offset : {std::size_t{0}, std::size_t{8}, std::size_t{20},
                                   keyferry::config::kCommitOffset,
                                   keyferry::config::kSlotHeaderBytes + 17,
                                   keyferry::config::kSlotBytes - 1}) {
    auto corrupt = b;
    corrupt[offset] ^= 0x5A;
    EndpointConfig selected{};
    const auto result = keyferry::config::SelectNewest(View(a), View(corrupt), &selected);
    assert(result.state == ConfigState::kReady);
    assert(result.slot == SlotId::kA && result.generation == 10);
  }
}

void TestLimitsAndGenerationExhaustion() {
  auto config = ValidConfig();
  config.wifi_profile_count = keyferry::config::kMaxWifiProfiles + 1;
  std::array<std::uint8_t, keyferry::config::kSlotBytes> slot{};
  assert(!keyferry::config::EncodeSlot(1, config, &slot));
  config = ValidConfig();
  config.paired_host_count = keyferry::config::kMaxPairedHosts + 1;
  assert(!keyferry::config::EncodeSlot(1, config, &slot));

  std::array<std::uint8_t, keyferry::config::kSlotBytes> newest{};
  assert(keyferry::config::EncodeSlot(std::numeric_limits<std::uint64_t>::max(),
                                     ValidConfig(), &newest));
  std::array<std::uint8_t, keyferry::config::kSlotBytes> erased{};
  erased.fill(0xFF);
  const auto plan = keyferry::config::PlanUpdate(View(newest), View(erased));
  assert(!plan.writable && plan.target == SlotId::kNone && plan.generation == 0);
}

void TestFullProfileAndHostCapacity() {
  auto config = ValidConfig();
  config.wifi_profile_count = keyferry::config::kMaxWifiProfiles;
  config.paired_host_count = keyferry::config::kMaxPairedHosts;
  for (std::size_t index = 1; index < keyferry::config::kMaxWifiProfiles; ++index) {
    config.wifi_profiles[index] = config.wifi_profiles[0];
    config.wifi_profiles[index].priority = static_cast<std::uint8_t>(index);
  }
  for (std::size_t index = 1; index < keyferry::config::kMaxPairedHosts; ++index) {
    config.paired_hosts[index] = config.paired_hosts[0];
    config.paired_hosts[index].host_id[0] = static_cast<std::uint8_t>(index + 1);
    config.paired_hosts[index].ipv4[3] = static_cast<std::uint8_t>(index + 1);
  }
  std::array<std::uint8_t, keyferry::config::kSlotBytes> slot{};
  assert(keyferry::config::EncodeSlot(3, config, &slot));
  EndpointConfig selected{};
  const auto result = keyferry::config::SelectNewest(View(slot), {nullptr, 0}, &selected);
  assert(result.state == ConfigState::kReady && result.generation == 3);
  assert(selected.wifi_profile_count == keyferry::config::kMaxWifiProfiles);
  assert(selected.paired_host_count == keyferry::config::kMaxPairedHosts);
}

void TestZeroWifiConfigurationRoundTrips() {
  auto config = ValidConfig();
  config.wifi_profile_count = 0;
  config.wifi_profiles[0] = {};
  assert(keyferry::config::ValidateConfig(config));
  std::array<std::uint8_t, keyferry::config::kSlotBytes> slot{};
  assert(keyferry::config::EncodeSlot(4, config, &slot));
  EndpointConfig selected{};
  const auto result =
      keyferry::config::SelectNewest(View(slot), {nullptr, 0}, &selected);
  assert(result.state == ConfigState::kReady && result.generation == 4);
  assert(selected.wifi_profile_count == 0);
  assert(selected.paired_host_count == 1);
}

void TestPayloadEncodingClearsOutputOnInvalidInput() {
  auto invalid = ValidConfig();
  invalid.provisioning_key.fill(0);
  std::array<std::uint8_t, keyferry::config::kPayloadBytes> payload{};
  payload.fill(0xA5);
  assert(!keyferry::config::EncodeConfigPayload(invalid, &payload));
  assert(std::all_of(payload.begin(), payload.end(),
                     [](const std::uint8_t byte) { return byte == 0; }));

  auto collapsed_authority = ValidConfig();
  collapsed_authority.provisioning_key =
      collapsed_authority.paired_hosts[0].link_secret;
  payload.fill(0xA5);
  assert(!keyferry::config::ValidateConfig(collapsed_authority));
  assert(!keyferry::config::EncodeConfigPayload(collapsed_authority, &payload));
  assert(std::all_of(payload.begin(), payload.end(),
                     [](const std::uint8_t byte) { return byte == 0; }));
}

void TestStorageCommitLoadAndAlternation() {
  FakeStorage storage;
  keyferry::config::StorageWorkspace workspace{};
  keyferry::config::Selection selection{};
  const auto first = ValidConfig(1);
  assert(keyferry::config::CommitConfig(storage, &workspace, first, &selection) ==
         StorageStatus::kOk);
  assert(selection.slot == SlotId::kA && selection.generation == 1);
  assert(WorkspaceIsZero(workspace));

  EndpointConfig loaded{};
  assert(keyferry::config::LoadConfig(storage, &workspace, &loaded, &selection) ==
         StorageStatus::kOk);
  assert(selection.slot == SlotId::kA && loaded.device_id == first.device_id);

  const auto second = ValidConfig(9);
  assert(keyferry::config::CommitConfig(storage, &workspace, second, &selection) ==
         StorageStatus::kOk);
  assert(selection.slot == SlotId::kB && selection.generation == 2);
  assert(keyferry::config::LoadConfig(storage, &workspace, &loaded, &selection) ==
         StorageStatus::kOk);
  assert(loaded.device_id == second.device_id);
}

void TestStorageLoadDistinguishesEmptyInvalidAndAmbiguous() {
  FakeStorage storage;
  keyferry::config::StorageWorkspace workspace{};
  EndpointConfig loaded = ValidConfig();
  keyferry::config::Selection selection{};
  assert(keyferry::config::LoadConfig(storage, &workspace, &loaded, &selection) ==
         StorageStatus::kErasedUnprovisioned);
  assert(loaded.wifi_profile_count == 0 && selection.slot == SlotId::kNone);
  assert(WorkspaceIsZero(workspace));

  storage.a[0] = 0;
  assert(keyferry::config::LoadConfig(storage, &workspace, &loaded, &selection) ==
         StorageStatus::kMalformedSlots);
  assert(loaded.wifi_profile_count == 0 && selection.slot == SlotId::kNone);
  assert(WorkspaceIsZero(workspace));
  assert(keyferry::config::CommitConfig(storage, &workspace, ValidConfig(), &selection) ==
         StorageStatus::kMalformedSlots);
  assert(storage.erase_calls == 0 && storage.write_calls == 0);
  assert(WorkspaceIsZero(workspace));

  assert(keyferry::config::EncodeSlot(7, ValidConfig(1), &storage.a));
  assert(keyferry::config::EncodeSlot(7, ValidConfig(2), &storage.b));
  assert(keyferry::config::LoadConfig(storage, &workspace, &loaded, &selection) ==
         StorageStatus::kAmbiguousSlots);
  assert(loaded.wifi_profile_count == 0 && selection.slot == SlotId::kNone);
  assert(WorkspaceIsZero(workspace));
}

void TestStorageFailureKeepsPriorGeneration() {
  FakeStorage storage;
  keyferry::config::StorageWorkspace workspace{};
  keyferry::config::Selection selection{};
  const auto prior = ValidConfig(1);
  assert(keyferry::config::CommitConfig(storage, &workspace, prior, &selection) ==
         StorageStatus::kOk);

  storage.write_limit = 127;
  assert(keyferry::config::CommitConfig(storage, &workspace, ValidConfig(2), &selection) ==
         StorageStatus::kIoError);
  assert(WorkspaceIsZero(workspace));
  storage.write_limit = keyferry::config::kSlotBytes;
  EndpointConfig loaded{};
  assert(keyferry::config::LoadConfig(storage, &workspace, &loaded, &selection) ==
         StorageStatus::kOk);
  assert(selection.slot == SlotId::kA && selection.generation == 1 &&
         loaded.device_id == prior.device_id);

  storage.fail_on_write_call = storage.write_calls + 2;
  assert(keyferry::config::CommitConfig(storage, &workspace, ValidConfig(3), &selection) ==
         StorageStatus::kIoError);
  assert(WorkspaceIsZero(workspace));
  storage.fail_on_write_call = 0;
  assert(keyferry::config::LoadConfig(storage, &workspace, &loaded, &selection) ==
         StorageStatus::kOk);
  assert(selection.slot == SlotId::kA && selection.generation == 1 &&
         loaded.device_id == prior.device_id);

  storage.fail_read = true;
  loaded = prior;
  assert(keyferry::config::LoadConfig(storage, &workspace, &loaded, &selection) ==
         StorageStatus::kIoError);
  assert(loaded.wifi_profile_count == 0 && selection.slot == SlotId::kNone);
  assert(WorkspaceIsZero(workspace));
}

}  // namespace

int main() {
  TestCrcKnownAnswer();
  TestHighestValidGenerationWins();
  TestNeitherValidLocksUnprovisioned();
  TestSlotInspectionDistinguishesErasedMalformedAndValid();
  TestConflictingEqualGenerationsLock();
  TestTornWriteNeverSupplantsOldSlot();
  TestHeaderAndPayloadCorruptionFallBack();
  TestLimitsAndGenerationExhaustion();
  TestFullProfileAndHostCapacity();
  TestZeroWifiConfigurationRoundTrips();
  TestPayloadEncodingClearsOutputOnInvalidInput();
  TestStorageCommitLoadAndAlternation();
  TestStorageLoadDistinguishesEmptyInvalidAndAmbiguous();
  TestStorageFailureKeepsPriorGeneration();
  std::puts("config_store_test: ok");
  return 0;
}
