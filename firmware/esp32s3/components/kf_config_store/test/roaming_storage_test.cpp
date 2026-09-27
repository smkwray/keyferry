#include "keyferry/roaming_storage.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>

namespace {

using keyferry::config::AnchorReadStatus;
using keyferry::config::RecoveryAnchorStorage;
using keyferry::config::SlotId;
using keyferry::config::SlotStorage;

struct FaultClock {
  std::size_t mutation{0};
  std::size_t fail_at{0};

  bool Permit() {
    ++mutation;
    return fail_at == 0 || mutation != fail_at;
  }
};

class FakeSlots final : public SlotStorage {
 public:
  explicit FakeSlots(FaultClock* clock) : clock_(clock) {
    a.fill(0xFF);
    b.fill(0xFF);
  }

  bool Read(const SlotId slot, std::uint8_t* output,
            const std::size_t length) override {
    const auto* source = Buffer(slot);
    if (source == nullptr || output == nullptr || length > source->size()) {
      return false;
    }
    std::copy_n(source->begin(), length, output);
    return true;
  }

  bool Erase(const SlotId slot) override {
    auto* target = Buffer(slot);
    if (target == nullptr || !clock_->Permit()) {
      return false;
    }
    target->fill(0xFF);
    return true;
  }

  bool Write(const SlotId slot, const std::size_t offset,
             const std::uint8_t* data, const std::size_t length) override {
    auto* target = Buffer(slot);
    if (target == nullptr || data == nullptr || offset > target->size() ||
        length > target->size() - offset || !clock_->Permit()) {
      return false;
    }
    std::copy_n(data, length, target->begin() + offset);
    return true;
  }

  std::array<std::uint8_t, 0x4000> a{};
  std::array<std::uint8_t, 0x4000> b{};

 private:
  std::array<std::uint8_t, 0x4000>* Buffer(const SlotId slot) {
    return slot == SlotId::kA ? &a : slot == SlotId::kB ? &b : nullptr;
  }

  const std::array<std::uint8_t, 0x4000>* Buffer(const SlotId slot) const {
    return slot == SlotId::kA ? &a : slot == SlotId::kB ? &b : nullptr;
  }

  FaultClock* clock_;
};

class FakeAnchor final : public RecoveryAnchorStorage {
 public:
  explicit FakeAnchor(FaultClock* clock) : clock_(clock) { bytes.fill(0xFF); }

  AnchorReadStatus Read(std::uint8_t* output,
                        const std::size_t length) override {
    if (fail_read || output == nullptr ||
        length != keyferry::config::kRecoveryAnchorBytes) {
      return AnchorReadStatus::kIoError;
    }
    if (!exists) {
      return AnchorReadStatus::kNotFound;
    }
    std::copy(bytes.begin(), bytes.end(), output);
    return AnchorReadStatus::kOk;
  }

  bool Write(const std::uint8_t* data, const std::size_t length) override {
    if (data == nullptr || length != bytes.size() || !clock_->Permit()) {
      return false;
    }
    std::copy_n(data, length, bytes.begin());
    exists = true;
    return true;
  }

  keyferry::config::RecoveryAnchorInspection Inspect() const {
    return keyferry::config::InspectRecoveryAnchor(bytes.data(), bytes.size());
  }

  FaultClock* clock_;
  bool exists{false};
  bool fail_read{false};
  std::array<std::uint8_t, keyferry::config::kRecoveryAnchorBytes> bytes{};
};

template <std::size_t Size>
std::array<std::uint8_t, Size> Filled(const std::uint8_t value) {
  std::array<std::uint8_t, Size> output{};
  output.fill(value);
  return output;
}

keyferry::config::RoamingEndpointConfig ValidRoaming() {
  keyferry::config::RoamingEndpointConfig config{};
  config.device_id = Filled<16>(0x11);
  config.owner_id = Filled<16>(0x22);
  config.owner_ca_sha256 = Filled<32>(0x33);
  config.epoch = 1;
  config.policy_sequence = 1;
  config.policy_hash = Filled<32>(0x44);
  config.policy_auth_tag = Filled<32>(0x45);
  config.owner_ca_length = 4;
  config.owner_ca_der[0] = 0x30;
  config.owner_ca_der[1] = 0x02;
  config.owner_ca_der[2] = 0x01;
  config.owner_ca_der[3] = 0x00;
  return config;
}

keyferry::config::AuthenticatedMigrationRequest ValidRequest() {
  return {ValidRoaming(), Filled<32>(0x55), Filled<16>(0x66)};
}

keyferry::config::AuthenticatedMigrationRequest NextRequest() {
  auto request = ValidRequest();
  request.config.policy_sequence = 2;
  request.config.previous_policy_sequence = 1;
  request.config.previous_policy_hash = request.config.policy_hash;
  request.config.policy_hash = Filled<32>(0x46);
  request.config.policy_auth_tag = Filled<32>(0x47);
  request.config.revoked_installation_count = 1;
  request.config.revoked_installation_ids[0] = Filled<16>(0x77);
  request.transaction_id = Filled<16>(0x67);
  return request;
}

class FixtureCrypto final : public keyferry::config::RoamingPolicyCrypto {
 public:
  FixtureCrypto() {
    const auto request = ValidRequest();
    assert(keyferry::config::BuildRoamingPolicyHashInput(
        request.config, &policy_input));
    assert(keyferry::config::BuildRoamingPolicyAuthInput(
        request.config.policy_hash, &auth_input));
    const auto next = NextRequest();
    assert(keyferry::config::BuildRoamingPolicyHashInput(
        next.config, &next_policy_input));
    assert(keyferry::config::BuildRoamingPolicyAuthInput(
        next.config.policy_hash, &next_auth_input));
  }

  bool Sha256(const std::uint8_t* input, const std::size_t length,
              std::uint8_t output[32]) override {
    if (fail || input == nullptr || output == nullptr) {
      return false;
    }
    const auto request = ValidRequest();
    if (length == request.config.owner_ca_length &&
        std::equal(input, input + length,
                   request.config.owner_ca_der.begin())) {
      std::copy(request.config.owner_ca_sha256.begin(),
                request.config.owner_ca_sha256.end(), output);
      return true;
    }
    if (length == policy_input.size() &&
        std::equal(input, input + length, policy_input.begin())) {
      std::copy(request.config.policy_hash.begin(),
                request.config.policy_hash.end(), output);
      return true;
    }
    const auto next = NextRequest();
    if (length == next_policy_input.size() &&
        std::equal(input, input + length, next_policy_input.begin())) {
      std::copy(next.config.policy_hash.begin(), next.config.policy_hash.end(),
                output);
      return true;
    }
    if (length > 32 && length < 128) {
      std::fill_n(output, 32, static_cast<std::uint8_t>(0x70));
      return true;
    }
    return false;
  }

  bool HkdfSha256(const std::uint8_t* input_key,
                  const std::size_t input_key_length,
                  const std::uint8_t* salt, const std::size_t salt_length,
                  const std::uint8_t* info, const std::size_t info_length,
                  std::uint8_t output[32]) override {
    const auto request = ValidRequest();
    if (fail || input_key_length != request.recovery_secret.size() ||
        !std::equal(input_key, input_key + input_key_length,
                    request.recovery_secret.begin()) ||
        salt == nullptr || salt_length != 32 || info == nullptr ||
        info_length != keyferry::protocol::kRoamingPolicyAuthKeyDomain.size() ||
        !std::equal(info, info + info_length,
                    keyferry::protocol::kRoamingPolicyAuthKeyDomain.begin())) {
      return false;
    }
    std::fill_n(output, 32, static_cast<std::uint8_t>(0x71));
    return true;
  }

  bool HmacSha256(const std::uint8_t key[32], const std::uint8_t* input,
                  const std::size_t input_length,
                  std::uint8_t output[32]) override {
    const auto request = ValidRequest();
    if (fail || !std::all_of(key, key + 32,
                             [](const std::uint8_t byte) {
                               return byte == 0x71;
                             }) ||
        input_length != auth_input.size()) {
      return false;
    }
    if (std::equal(input, input + input_length, auth_input.begin())) {
      std::copy(request.config.policy_auth_tag.begin(),
                request.config.policy_auth_tag.end(), output);
      return true;
    }
    const auto next = NextRequest();
    if (std::equal(input, input + input_length, next_auth_input.begin())) {
      std::copy(next.config.policy_auth_tag.begin(),
                next.config.policy_auth_tag.end(), output);
      return true;
    }
    return false;
  }

  bool fail{false};
  keyferry::config::PolicyHashInput policy_input{};
  keyferry::config::PolicyAuthInput auth_input{};
  keyferry::config::PolicyHashInput next_policy_input{};
  keyferry::config::PolicyAuthInput next_auth_input{};
};

void SeedLegacySlots(FakeSlots* slots) {
  using namespace keyferry::config;
  EndpointConfig legacy{};
  legacy.device_id = Filled<16>(0x11);
  legacy.provisioning_key = Filled<32>(0x55);
  legacy.wifi_profile_count = 1;
  legacy.paired_host_count = 1;
  auto& wifi = legacy.wifi_profiles[0];
  wifi.security = WifiSecurity::kWpa2Personal;
  wifi.priority = 1;
  wifi.ssid_length = 1;
  wifi.credential_length = 8;
  wifi.ssid[0] = 'x';
  std::fill_n(wifi.credential.begin(), wifi.credential_length, 'p');
  auto& host = legacy.paired_hosts[0];
  host.host_id = Filled<16>(1);
  host.ipv4 = {192, 0, 2, 1};
  host.port = 7443;
  constexpr char kName[] = "legacy.invalid";
  host.server_name_length = sizeof(kName) - 1;
  std::copy_n(kName, host.server_name_length, host.server_name.begin());
  host.peer_spki_sha256 = Filled<32>(2);
  host.link_secret = Filled<32>(3);
  host.ca_certificate_length = 2;
  host.ca_certificate_der[0] = 0x30;
  host.ca_certificate_der[1] = 0;
  std::array<std::uint8_t, kSlotBytes> encoded{};
  assert(EncodeSlot(1, legacy, &encoded));
  std::copy(encoded.begin(), encoded.end(), slots->a.begin());
  assert(EncodeSlot(1, legacy, &encoded));
  std::copy(encoded.begin(), encoded.end(), slots->b.begin());
}

keyferry::config::MigrationStatus Run(
    FakeSlots* slots, FakeAnchor* anchor,
    const keyferry::config::AuthenticatedMigrationRequest* request) {
  keyferry::config::MigrationWorkspace workspace{};
  FixtureCrypto crypto{};
  return keyferry::config::MigrateToRoaming(*slots, *anchor, crypto,
                                            &workspace, request);
}

void TestMigrationNeedsAuthenticatedRequest() {
  using namespace keyferry::config;
  FaultClock clock{};
  FakeSlots slots(&clock);
  FakeAnchor anchor(&clock);
  SeedLegacySlots(&slots);
  assert(Run(&slots, &anchor, nullptr) == MigrationStatus::kInvalidRequest);
  assert(!anchor.exists);
  assert(InspectSlot({slots.a.data(), kSlotBytes}).condition ==
         SlotCondition::kValid);
}

void TestMigrationReplacesBothSlotsAndActivatesFloor() {
  using namespace keyferry::config;
  FaultClock clock{};
  FakeSlots slots(&clock);
  FakeAnchor anchor(&clock);
  SeedLegacySlots(&slots);
  const auto request = ValidRequest();
  assert(Run(&slots, &anchor, &request) == MigrationStatus::kReady);
  const auto inspection = anchor.Inspect();
  assert(inspection.condition == RecoveryAnchorCondition::kValid);
  assert(inspection.anchor.phase == RecoveryAnchorPhase::kActive);
  assert(InspectRoamingSlot({slots.a.data(), kRoamingConfigSlotBytes}).condition ==
         SlotCondition::kValid);
  assert(InspectRoamingSlot({slots.b.data(), kRoamingConfigSlotBytes}).condition ==
         SlotCondition::kValid);
  assert(Run(&slots, &anchor, nullptr) == MigrationStatus::kReady);
}

void TestEveryMutationCutResumesWithoutLegacyFallback() {
  using namespace keyferry::config;
  const auto request = ValidRequest();
  constexpr std::size_t kMutationCount = 8;
  for (std::size_t cut = 1; cut <= kMutationCount; ++cut) {
    FaultClock clock{0, cut};
    FakeSlots slots(&clock);
    FakeAnchor anchor(&clock);
    SeedLegacySlots(&slots);
    const auto interrupted = Run(&slots, &anchor, &request);
    assert(interrupted != MigrationStatus::kReady);
    if (anchor.exists) {
      const auto inspection = anchor.Inspect();
      assert(inspection.condition == RecoveryAnchorCondition::kValid);
      assert(inspection.anchor.phase == RecoveryAnchorPhase::kMigrationPending);
    }
    clock.fail_at = 0;
    assert(Run(&slots, &anchor, &request) == MigrationStatus::kReady);
    assert(anchor.Inspect().anchor.phase == RecoveryAnchorPhase::kActive);
  }
}

void TestPendingMigrationRejectsAnotherPolicyOrTransaction() {
  using namespace keyferry::config;
  FaultClock clock{0, 2};
  FakeSlots slots(&clock);
  FakeAnchor anchor(&clock);
  const auto request = ValidRequest();
  assert(Run(&slots, &anchor, &request) != MigrationStatus::kReady);
  assert(anchor.Inspect().anchor.phase == RecoveryAnchorPhase::kMigrationPending);
  clock.fail_at = 0;
  auto wrong = request;
  wrong.transaction_id[0] ^= 1;
  assert(Run(&slots, &anchor, &wrong) == MigrationStatus::kLockedMigration);
  wrong = request;
  wrong.config.policy_hash[0] ^= 1;
  assert(Run(&slots, &anchor, &wrong) == MigrationStatus::kLockedMigration);
}

void TestConflictingV2SlotLocksMigration() {
  using namespace keyferry::config;
  FaultClock clock{0, 2};
  FakeSlots slots(&clock);
  FakeAnchor anchor(&clock);
  const auto request = ValidRequest();
  assert(Run(&slots, &anchor, &request) != MigrationStatus::kReady);
  clock.fail_at = 0;
  auto wrong = ValidRoaming();
  wrong.policy_hash[0] ^= 1;
  std::array<std::uint8_t, kRoamingConfigSlotBytes> encoded{};
  assert(EncodeRoamingSlot(1, wrong, &encoded));
  slots.a.fill(0xFF);
  std::copy(encoded.begin(), encoded.end(), slots.a.begin());
  assert(Run(&slots, &anchor, &request) == MigrationStatus::kConflict);
}

void TestFailedPolicyAuthenticationNeverWrites() {
  using namespace keyferry::config;
  FaultClock clock{};
  FakeSlots slots(&clock);
  FakeAnchor anchor(&clock);
  const auto request = ValidRequest();
  FixtureCrypto crypto{};
  crypto.fail = true;
  MigrationWorkspace workspace{};
  assert(MigrateToRoaming(slots, anchor, crypto, &workspace, &request) ==
         MigrationStatus::kInvalidRequest);
  assert(clock.mutation == 0 && !anchor.exists);
}

void TestAuthenticatedSuccessorAdvancesOnceAndResumesEveryCut() {
  using namespace keyferry::config;
  constexpr std::size_t kUpdateMutationCount = 4;
  for (std::size_t cut = 1; cut <= kUpdateMutationCount; ++cut) {
    FaultClock clock{};
    FakeSlots slots(&clock);
    FakeAnchor anchor(&clock);
    const auto initial = ValidRequest();
    assert(Run(&slots, &anchor, &initial) == MigrationStatus::kReady);
    clock.mutation = 0;
    clock.fail_at = cut;
    const auto next = NextRequest();
    assert(Run(&slots, &anchor, &next) != MigrationStatus::kReady);
    assert(anchor.Inspect().anchor.policy_sequence == 1);
    clock.fail_at = 0;
    assert(Run(&slots, &anchor, &next) == MigrationStatus::kReady);
    assert(anchor.Inspect().anchor.policy_sequence == 2);
    assert(Run(&slots, &anchor, nullptr) == MigrationStatus::kReady);
    const auto mutations = clock.mutation;
    assert(Run(&slots, &anchor, &next) == MigrationStatus::kReady);
    assert(clock.mutation == mutations);
    assert(Run(&slots, &anchor, &initial) == MigrationStatus::kLockedPolicy);
  }
}

void TestSuccessorRequiresTheAnchoredRecoverySecret() {
  using namespace keyferry::config;
  FaultClock clock{};
  FakeSlots slots(&clock);
  FakeAnchor anchor(&clock);
  const auto initial = ValidRequest();
  assert(Run(&slots, &anchor, &initial) == MigrationStatus::kReady);
  clock.mutation = 0;
  auto next = NextRequest();
  next.recovery_secret[0] ^= 1;
  assert(Run(&slots, &anchor, &next) == MigrationStatus::kInvalidRequest);
  assert(clock.mutation == 0);
  assert(anchor.Inspect().anchor.policy_sequence == 1);
}

}  // namespace

int main() {
  TestMigrationNeedsAuthenticatedRequest();
  TestMigrationReplacesBothSlotsAndActivatesFloor();
  TestEveryMutationCutResumesWithoutLegacyFallback();
  TestPendingMigrationRejectsAnotherPolicyOrTransaction();
  TestConflictingV2SlotLocksMigration();
  TestFailedPolicyAuthenticationNeverWrites();
  TestAuthenticatedSuccessorAdvancesOnceAndResumesEveryCut();
  TestSuccessorRequiresTheAnchoredRecoverySecret();
  std::puts("roaming_storage_test: ok");
  return 0;
}
