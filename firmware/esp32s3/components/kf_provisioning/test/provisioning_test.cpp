#include "keyferry/provisioning.h"
#include "keyferry/local_management.h"
#include "keyferry/local_management_codec.h"
#include "keyferry/local_management_coordinator.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace {

using keyferry::config::EndpointConfig;
using keyferry::config::SlotId;
using keyferry::config::StorageStatus;
using keyferry::provisioning::Operation;
using keyferry::provisioning::Status;

class FakeStorage final : public keyferry::config::SlotStorage {
 public:
  FakeStorage() {
    a.fill(0xFF);
    b.fill(0xFF);
  }

  bool Read(SlotId slot, std::uint8_t* output, std::size_t length) override {
    const auto* source = Buffer(slot);
    if (fail || source == nullptr || output == nullptr || length != source->size()) {
      return false;
    }
    std::copy(source->begin(), source->end(), output);
    return true;
  }

  bool Erase(SlotId slot) override {
    auto* target = Buffer(slot);
    if (fail || target == nullptr) {
      return false;
    }
    ++erase_calls;
    target->fill(0xFF);
    return true;
  }

  bool Write(SlotId slot, std::size_t offset, const std::uint8_t* data,
             std::size_t length) override {
    auto* target = Buffer(slot);
    if (fail || target == nullptr || data == nullptr || offset > target->size() ||
        length > target->size() - offset) {
      return false;
    }
    ++write_calls;
    std::copy_n(data, length, target->begin() + offset);
    return true;
  }

  std::array<std::uint8_t, keyferry::config::kSlotBytes> a{};
  std::array<std::uint8_t, keyferry::config::kSlotBytes> b{};
  bool fail{false};
  std::size_t erase_calls{0};
  std::size_t write_calls{0};

 private:
  std::array<std::uint8_t, keyferry::config::kSlotBytes>* Buffer(SlotId slot) {
    return slot == SlotId::kA ? &a : slot == SlotId::kB ? &b : nullptr;
  }
  const std::array<std::uint8_t, keyferry::config::kSlotBytes>* Buffer(
      SlotId slot) const {
    return slot == SlotId::kA ? &a : slot == SlotId::kB ? &b : nullptr;
  }
};

std::array<std::uint8_t, 32> TestMac(
    const std::array<std::uint8_t, 32>& key,
    const std::vector<std::uint8_t>& transcript) {
  auto output = key;
  std::size_t cursor = 0;
  for (const auto byte : transcript) {
    const std::size_t index = cursor % output.size();
    output[index] = static_cast<std::uint8_t>(
        (output[index] << 1) | (output[index] >> 7));
    output[index] ^= static_cast<std::uint8_t>(byte + cursor);
    ++cursor;
  }
  return output;
}

class FakeEffects final : public keyferry::provisioning::Effects {
 public:
  bool FillRandom(std::uint8_t* output, std::size_t length) override {
    if (random_fails || output == nullptr) {
      return false;
    }
    for (std::size_t index = 0; index < length; ++index) {
      output[index] = static_cast<std::uint8_t>(0x80 + index);
    }
    return true;
  }

  bool HmacSha256(const std::array<std::uint8_t, 32>& key,
                  const keyferry::provisioning::ByteSpan* parts,
                  std::size_t part_count,
                  std::array<std::uint8_t, 32>* output) override {
    if (hmac_fails || parts == nullptr || output == nullptr) {
      return false;
    }
    transcript.clear();
    for (std::size_t index = 0; index < part_count; ++index) {
      transcript.insert(transcript.end(), parts[index].data,
                        parts[index].data + parts[index].size);
    }
    *output = TestMac(key, transcript);
    return true;
  }

  std::uint64_t MonotonicMilliseconds() override { return now_ms; }

  StorageStatus Commit(const EndpointConfig& config,
                       keyferry::config::Selection* selection) override {
    ++commit_calls;
    return keyferry::config::CommitConfig(storage, &workspace, config, selection);
  }

  keyferry::config::MigrationStatus MigrateToRoaming(
      const keyferry::config::RoamingEndpointConfig& config,
      const keyferry::config::RecoverySecret& recovery_secret,
      const keyferry::config::RecoveryTransactionId& transaction_id) override {
    ++migration_calls;
    migrated = config;
    migration_secret = recovery_secret;
    migration_transaction = transaction_id;
    return migration_result;
  }

  FakeStorage storage;
  keyferry::config::StorageWorkspace workspace{};
  std::vector<std::uint8_t> transcript;
  bool random_fails{false};
  bool hmac_fails{false};
  std::uint64_t now_ms{0};
  std::size_t commit_calls{0};
  std::size_t migration_calls{0};
  keyferry::config::MigrationStatus migration_result{
      keyferry::config::MigrationStatus::kReady};
  keyferry::config::RoamingEndpointConfig migrated{};
  keyferry::config::RecoverySecret migration_secret{};
  keyferry::config::RecoveryTransactionId migration_transaction{};
};

EndpointConfig ValidConfig(const std::array<std::uint8_t, 16>& device_id,
                           std::uint8_t marker) {
  EndpointConfig config{};
  config.device_id = device_id;
  config.provisioning_key.fill(static_cast<std::uint8_t>(marker + 1));
  config.wifi_profile_count = 1;
  auto& wifi = config.wifi_profiles[0];
  wifi.security = keyferry::config::WifiSecurity::kWpa2Personal;
  wifi.priority = 1;
  wifi.ssid_length = 4;
  wifi.credential_length = 8;
  std::copy_n("ssid", wifi.ssid_length, wifi.ssid.begin());
  std::copy_n("password", wifi.credential_length, wifi.credential.begin());
  config.paired_host_count = 1;
  auto& host = config.paired_hosts[0];
  host.host_id.fill(static_cast<std::uint8_t>(marker + 2));
  host.ipv4 = {192, 0, 2, marker};
  host.port = 7443;
  host.server_name_length = 14;
  std::copy_n("keyferry.local", host.server_name_length, host.server_name.begin());
  host.peer_spki_sha256.fill(static_cast<std::uint8_t>(marker + 3));
  host.link_secret.fill(static_cast<std::uint8_t>(marker + 4));
  host.ca_certificate_length = 4;
  host.ca_certificate_der[0] = 0x30;
  host.ca_certificate_der[1] = 0x02;
  host.ca_certificate_der[2] = marker;
  host.ca_certificate_der[3] = static_cast<std::uint8_t>(marker + 5);
  return config;
}

std::array<std::uint8_t, keyferry::provisioning::kReportBytes> Request(
    Operation operation) {
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> request{};
  request[0] = static_cast<std::uint8_t>(operation);
  return request;
}

void PutU16(std::uint8_t* output, std::uint16_t value) {
  output[0] = static_cast<std::uint8_t>(value);
  output[1] = static_cast<std::uint8_t>(value >> 8);
}

void PutU32(std::vector<std::uint8_t>* output, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    output->push_back(static_cast<std::uint8_t>(value >> (index * 8)));
  }
}

void PutU64(std::vector<std::uint8_t>* output, std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    output->push_back(static_cast<std::uint8_t>(value >> (index * 8)));
  }
}

std::uint64_t GetU64(const std::uint8_t* input) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(input[index]) << (index * 8);
  }
  return value;
}

struct PreparedTransaction {
  std::array<std::uint8_t, 16> transaction_id{};
  std::array<std::uint8_t, keyferry::config::kPayloadBytes> payload{};
  std::array<std::uint8_t, 32> challenge{};
};

PreparedTransaction StagePayload(
    keyferry::provisioning::Session* session,
    const std::array<std::uint8_t, keyferry::config::kPayloadBytes>& payload) {
  PreparedTransaction prepared{};
  prepared.payload = payload;
  prepared.transaction_id.fill(0x55);
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> response{};
  assert(session->Handle(Request(Operation::kChallenge), &response) == Status::kOk);
  assert(response[0] ==
         (static_cast<std::uint8_t>(Operation::kChallenge) | 0x80));
  assert(response[2] == keyferry::provisioning::kProtocolVersion);
  std::copy_n(response.begin() + 21, prepared.challenge.size(),
              prepared.challenge.begin());

  auto begin = Request(Operation::kBegin);
  begin[1] = keyferry::provisioning::kProtocolVersion;
  PutU16(begin.data() + 2,
         static_cast<std::uint16_t>(keyferry::config::kPayloadBytes));
  std::copy(prepared.transaction_id.begin(), prepared.transaction_id.end(),
            begin.begin() + 4);
  assert(session->Handle(begin, &response) == Status::kOk);
  for (std::size_t offset = 0; offset < prepared.payload.size();) {
    auto data = Request(Operation::kData);
    std::copy(prepared.transaction_id.begin(), prepared.transaction_id.end(),
              data.begin() + 1);
    PutU16(data.data() + 17, static_cast<std::uint16_t>(offset));
    const std::size_t length =
        std::min(keyferry::provisioning::kDataBytesPerReport,
                 prepared.payload.size() - offset);
    data[19] = static_cast<std::uint8_t>(length);
    std::copy_n(prepared.payload.begin() + offset, length, data.begin() + 20);
    assert(session->Handle(data, &response) == Status::kOk);
    offset += length;
  }
  return prepared;
}

PreparedTransaction Stage(keyferry::provisioning::Session* session,
                          const EndpointConfig& config) {
  std::array<std::uint8_t, keyferry::config::kPayloadBytes> payload{};
  assert(keyferry::config::EncodeConfigPayload(config, &payload));
  return StagePayload(session, payload);
}

std::array<std::uint8_t, 32> AuthenticationTag(
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 16>& device_id,
    const PreparedTransaction& prepared, std::uint64_t generation) {
  std::vector<std::uint8_t> transcript;
  transcript.insert(transcript.end(),
                    keyferry::provisioning::kAuthenticationDomain.begin(),
                    keyferry::provisioning::kAuthenticationDomain.end());
  transcript.insert(transcript.end(), device_id.begin(), device_id.end());
  transcript.insert(transcript.end(), prepared.challenge.begin(),
                    prepared.challenge.end());
  PutU64(&transcript, generation);
  transcript.insert(transcript.end(), prepared.transaction_id.begin(),
                    prepared.transaction_id.end());
  PutU32(&transcript,
         static_cast<std::uint32_t>(keyferry::config::kPayloadBytes));
  transcript.insert(transcript.end(), prepared.payload.begin(), prepared.payload.end());
  return TestMac(key, transcript);
}

std::array<std::uint8_t, keyferry::provisioning::kReportBytes> CommitRequest(
    const PreparedTransaction& prepared, const std::array<std::uint8_t, 32>& tag) {
  auto request = Request(Operation::kCommit);
  std::copy(prepared.transaction_id.begin(), prepared.transaction_id.end(),
            request.begin() + 1);
  std::copy(tag.begin(), tag.end(), request.begin() + 17);
  return request;
}

void BeginEmpty(
    keyferry::provisioning::Session* session,
    const std::array<std::uint8_t, keyferry::provisioning::kTransactionIdBytes>&
        transaction_id,
    std::array<std::uint8_t, keyferry::provisioning::kReportBytes>* response) {
  assert(session->Handle(Request(Operation::kChallenge), response) == Status::kOk);
  auto begin = Request(Operation::kBegin);
  begin[1] = keyferry::provisioning::kProtocolVersion;
  PutU16(begin.data() + 2,
         static_cast<std::uint16_t>(keyferry::config::kPayloadBytes));
  std::copy(transaction_id.begin(), transaction_id.end(), begin.begin() + 4);
  assert(session->Handle(begin, response) == Status::kOk);
}

void TestAuthenticatedCommitUsesCanonicalPayloadAndRealStorage() {
  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x11);
  std::array<std::uint8_t, 32> key{};
  key.fill(0x22);
  FakeEffects effects;
  keyferry::provisioning::Session session(device_id, key, 0, effects);
  const auto config = ValidConfig(device_id, 7);
  const auto prepared = Stage(&session, config);
  const auto tag = AuthenticationTag(key, device_id, prepared, 0);
  auto commit = CommitRequest(prepared, tag);
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> response{};
  assert(session.Handle(commit, &response) == Status::kOk);
  assert(effects.commit_calls == 1 && effects.storage.erase_calls == 1 &&
         effects.storage.write_calls == 2);
  assert(response[2] == static_cast<std::uint8_t>(SlotId::kA));
  assert(response[3] == 1);

  keyferry::config::StorageWorkspace workspace{};
  EndpointConfig loaded{};
  keyferry::config::Selection selection{};
  assert(keyferry::config::LoadConfig(effects.storage, &workspace, &loaded,
                                      &selection) == StorageStatus::kOk);
  assert(loaded.device_id == config.device_id);
  assert(loaded.provisioning_key == config.provisioning_key);
  assert(session.Handle(commit, &response) == Status::kBadState);
  assert(effects.commit_calls == 1);
}

void TestAuthenticationFailureConsumesNonceAndWritesNothing() {
  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x31);
  std::array<std::uint8_t, 32> key{};
  key.fill(0x32);
  FakeEffects effects;
  keyferry::provisioning::Session session(device_id, key, 0, effects);
  const auto prepared = Stage(&session, ValidConfig(device_id, 4));
  auto tag = AuthenticationTag(key, device_id, prepared, 0);
  tag[0] ^= 1;
  const auto commit = CommitRequest(prepared, tag);
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> response{};
  assert(session.Handle(commit, &response) == Status::kAuthenticationFailed);
  assert(effects.commit_calls == 0 && effects.storage.erase_calls == 0);
  assert(session.Handle(commit, &response) == Status::kBadState);
}

void TestMalformedOrderIdentityAndStorageFailuresFailClosed() {
  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x41);
  std::array<std::uint8_t, 32> key{};
  key.fill(0x42);
  FakeEffects effects;
  keyferry::provisioning::Session session(device_id, key, 0, effects);
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> response{};

  assert(session.Handle(Request(Operation::kData), &response) == Status::kBadState);
  auto prepared = Stage(&session, ValidConfig(device_id, 5));
  auto bad_data = Request(Operation::kData);
  std::copy(prepared.transaction_id.begin(), prepared.transaction_id.end(),
            bad_data.begin() + 1);
  PutU16(bad_data.data() + 17, 1);
  bad_data[19] = 1;
  bad_data[20] = 9;
  // Stage completed the transfer, so another data report is rejected and consumes state.
  assert(session.Handle(bad_data, &response) == Status::kBadOffset);

  auto wrong_identity = device_id;
  wrong_identity[0] ^= 1;
  prepared = Stage(&session, ValidConfig(wrong_identity, 6));
  auto tag = AuthenticationTag(key, device_id, prepared, 0);
  assert(session.Handle(CommitRequest(prepared, tag), &response) ==
         Status::kIdentityMismatch);
  assert(effects.commit_calls == 0);

  effects.storage.fail = true;
  prepared = Stage(&session, ValidConfig(device_id, 7));
  tag = AuthenticationTag(key, device_id, prepared, 0);
  assert(session.Handle(CommitRequest(prepared, tag), &response) ==
         Status::kCommitFailed);
  assert(effects.commit_calls == 1);
}

void TestKeyRotationAndAbort() {
  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x51);
  std::array<std::uint8_t, 32> original_key{};
  original_key.fill(0x52);
  FakeEffects effects;
  keyferry::provisioning::Session session(device_id, original_key, 0, effects);
  const auto first_config = ValidConfig(device_id, 8);
  auto prepared = Stage(&session, first_config);
  auto tag = AuthenticationTag(original_key, device_id, prepared, 0);
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> response{};
  assert(session.Handle(CommitRequest(prepared, tag), &response) == Status::kOk);

  const auto second_config = ValidConfig(device_id, 9);
  prepared = Stage(&session, second_config);
  tag = AuthenticationTag(original_key, device_id, prepared, 1);
  assert(session.Handle(CommitRequest(prepared, tag), &response) ==
         Status::kAuthenticationFailed);

  prepared = Stage(&session, second_config);
  tag = AuthenticationTag(first_config.provisioning_key, device_id, prepared, 1);
  assert(session.Handle(CommitRequest(prepared, tag), &response) == Status::kOk);
  assert(response[2] == static_cast<std::uint8_t>(SlotId::kB));
  assert(response[3] == 2);

  assert(session.Handle(Request(Operation::kChallenge), &response) == Status::kOk);
  assert(session.Handle(Request(Operation::kAbort), &response) == Status::kOk);
  auto begin = Request(Operation::kBegin);
  begin[1] = keyferry::provisioning::kProtocolVersion;
  PutU16(begin.data() + 2,
         static_cast<std::uint16_t>(keyferry::config::kPayloadBytes));
  std::fill_n(begin.begin() + 4, 16, static_cast<std::uint8_t>(1));
  assert(session.Handle(begin, &response) == Status::kBadState);
}

void TestRandomAndPaddingFailures() {
  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x61);
  std::array<std::uint8_t, 32> key{};
  key.fill(0x62);
  FakeEffects effects;
  keyferry::provisioning::Session session(device_id, key, 0, effects);
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> response{};
  effects.random_fails = true;
  assert(session.Handle(Request(Operation::kChallenge), &response) ==
         Status::kRandomFailed);
  effects.random_fails = false;
  auto challenge = Request(Operation::kChallenge);
  challenge.back() = 1;
  assert(session.Handle(challenge, &response) == Status::kBadReport);
}

void TestMalformedReportMatrix() {
  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x68);
  std::array<std::uint8_t, 32> key{};
  key.fill(0x69);
  FakeEffects effects;
  keyferry::provisioning::Session session(device_id, key, 0, effects);
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> response{};

  auto bad_begin = Request(Operation::kBegin);
  bad_begin[1] = keyferry::provisioning::kProtocolVersion + 1;
  PutU16(bad_begin.data() + 2,
         static_cast<std::uint16_t>(keyferry::config::kPayloadBytes));
  std::fill_n(bad_begin.begin() + 4, 16, static_cast<std::uint8_t>(1));
  assert(session.Handle(Request(Operation::kChallenge), &response) == Status::kOk);
  assert(session.Handle(bad_begin, &response) == Status::kBadReport);

  bad_begin[1] = keyferry::provisioning::kProtocolVersion;
  PutU16(bad_begin.data() + 2, 1);
  assert(session.Handle(Request(Operation::kChallenge), &response) == Status::kOk);
  assert(session.Handle(bad_begin, &response) == Status::kBadReport);

  PutU16(bad_begin.data() + 2,
         static_cast<std::uint16_t>(keyferry::config::kPayloadBytes));
  std::fill_n(bad_begin.begin() + 4, 16, static_cast<std::uint8_t>(0));
  assert(session.Handle(Request(Operation::kChallenge), &response) == Status::kOk);
  assert(session.Handle(bad_begin, &response) == Status::kBadReport);

  std::fill_n(bad_begin.begin() + 4, 16, static_cast<std::uint8_t>(1));
  bad_begin.back() = 1;
  assert(session.Handle(Request(Operation::kChallenge), &response) == Status::kOk);
  assert(session.Handle(bad_begin, &response) == Status::kBadReport);

  std::array<std::uint8_t, keyferry::provisioning::kTransactionIdBytes>
      transaction_id{};
  transaction_id.fill(0x44);
  BeginEmpty(&session, transaction_id, &response);
  auto bad_data = Request(Operation::kData);
  std::copy(transaction_id.begin(), transaction_id.end(), bad_data.begin() + 1);
  assert(session.Handle(bad_data, &response) == Status::kBadReport);

  BeginEmpty(&session, transaction_id, &response);
  bad_data[19] = keyferry::provisioning::kDataBytesPerReport + 1;
  assert(session.Handle(bad_data, &response) == Status::kBadReport);

  BeginEmpty(&session, transaction_id, &response);
  bad_data[19] = 1;
  bad_data[20] = 1;
  bad_data.back() = 1;
  assert(session.Handle(bad_data, &response) == Status::kBadReport);

  auto prepared = Stage(&session, ValidConfig(device_id, 13));
  auto bad_transaction = Request(Operation::kData);
  std::fill_n(bad_transaction.begin() + 1, 16, static_cast<std::uint8_t>(0x99));
  PutU16(bad_transaction.data() + 17,
         static_cast<std::uint16_t>(prepared.payload.size()));
  bad_transaction[19] = 1;
  bad_transaction[20] = 1;
  assert(session.Handle(bad_transaction, &response) == Status::kBadTransaction);

  prepared = Stage(&session, ValidConfig(device_id, 14));
  auto tag = AuthenticationTag(key, device_id, prepared, 0);
  auto wrong_commit_transaction = CommitRequest(prepared, tag);
  wrong_commit_transaction[1] ^= 1;
  assert(session.Handle(wrong_commit_transaction, &response) ==
         Status::kBadTransaction);

  prepared = Stage(&session, ValidConfig(device_id, 15));
  auto overrun = Request(Operation::kData);
  std::copy(prepared.transaction_id.begin(), prepared.transaction_id.end(),
            overrun.begin() + 1);
  PutU16(overrun.data() + 17,
         static_cast<std::uint16_t>(prepared.payload.size()));
  overrun[19] = 1;
  overrun[20] = 1;
  assert(session.Handle(overrun, &response) == Status::kBadReport);

  prepared = Stage(&session, ValidConfig(device_id, 16));
  tag = AuthenticationTag(key, device_id, prepared, 0);
  auto bad_commit = CommitRequest(prepared, tag);
  bad_commit.back() = 1;
  assert(session.Handle(bad_commit, &response) == Status::kBadReport);

  prepared = Stage(&session, ValidConfig(device_id, 17));
  tag = AuthenticationTag(key, device_id, prepared, 0);
  effects.hmac_fails = true;
  assert(session.Handle(CommitRequest(prepared, tag), &response) ==
         Status::kAuthenticationFailed);
  assert(effects.commit_calls == 0);
}

void TestCollapsedAuthorityIsRejectedBeforeStorage() {
  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x6A);
  std::array<std::uint8_t, 32> key{};
  key.fill(0x6B);
  FakeEffects effects;
  keyferry::provisioning::Session session(device_id, key, 0, effects);
  const auto config = ValidConfig(device_id, 17);
  std::array<std::uint8_t, keyferry::config::kPayloadBytes> payload{};
  assert(keyferry::config::EncodeConfigPayload(config, &payload));
  const auto link_secret = std::search(payload.begin() + 48, payload.end(),
                                       config.paired_hosts[0].link_secret.begin(),
                                       config.paired_hosts[0].link_secret.end());
  assert(link_secret != payload.end());
  std::copy_n(link_secret, config.provisioning_key.size(), payload.begin() + 16);
  const auto prepared = StagePayload(&session, payload);
  const auto tag = AuthenticationTag(key, device_id, prepared, 0);
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> response{};
  assert(session.Handle(CommitRequest(prepared, tag), &response) ==
         Status::kInvalidConfig);
  assert(effects.commit_calls == 0 && effects.storage.erase_calls == 0 &&
         effects.storage.write_calls == 0);
}

void TestBoundedMalformedReportsNeverWrite() {
  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x78);
  std::array<std::uint8_t, 32> key{};
  key.fill(0x79);
  FakeEffects effects;
  effects.hmac_fails = true;
  keyferry::provisioning::Session session(device_id, key, 0, effects);
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> request{};
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> response{};
  std::uint32_t state = 0xC0FFEE01;
  for (std::size_t iteration = 0; iteration < 100000; ++iteration) {
    for (auto& byte : request) {
      state = state * 1664525U + 1013904223U;
      byte = static_cast<std::uint8_t>(state >> 24);
    }
    session.Handle(request, &response);
  }
  assert(effects.commit_calls == 0 && effects.storage.erase_calls == 0 &&
         effects.storage.write_calls == 0);
}

void TestMissingAuthorityTimeoutAndTransportLossFailClosed() {
  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x71);
  std::array<std::uint8_t, 32> key{};
  key.fill(0x72);
  FakeEffects effects;
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> response{};

  std::array<std::uint8_t, 32> zero_key{};
  keyferry::provisioning::Session no_key(device_id, zero_key, 0, effects);
  assert(no_key.Handle(Request(Operation::kChallenge), &response) ==
         Status::kBadState);
  assert(effects.transcript.empty() && effects.commit_calls == 0);

  std::array<std::uint8_t, 16> zero_device_id{};
  keyferry::provisioning::Session no_identity(zero_device_id, key, 0, effects);
  assert(no_identity.Handle(Request(Operation::kChallenge), &response) ==
         Status::kBadState);

  keyferry::provisioning::Session timed(device_id, key, 0, effects);
  auto prepared = Stage(&timed, ValidConfig(device_id, 10));
  auto tag = AuthenticationTag(key, device_id, prepared, 0);
  effects.now_ms = keyferry::provisioning::kTransactionIdleTimeoutMs;
  assert(timed.Expire(effects.now_ms));
  assert(timed.Handle(CommitRequest(prepared, tag), &response) ==
         Status::kBadState);
  assert(effects.commit_calls == 0);

  effects.now_ms++;
  prepared = Stage(&timed, ValidConfig(device_id, 11));
  tag = AuthenticationTag(key, device_id, prepared, 0);
  timed.TransportLost();
  assert(timed.Handle(CommitRequest(prepared, tag), &response) ==
         Status::kBadState);
  assert(effects.commit_calls == 0);

  prepared = Stage(&timed, ValidConfig(device_id, 12));
  tag = AuthenticationTag(key, device_id, prepared, 0);
  assert(timed.Handle(CommitRequest(prepared, tag), nullptr) ==
         Status::kBadReport);
  assert(timed.Handle(CommitRequest(prepared, tag), &response) ==
         Status::kBadState);
}

void TestRoamingMigrationUsesDistinctAuthenticatedPayload() {
  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x21);
  std::array<std::uint8_t, 32> recovery_secret{};
  recovery_secret.fill(0x22);
  keyferry::config::RoamingEndpointConfig policy{};
  policy.device_id = device_id;
  policy.owner_id.fill(0x23);
  policy.owner_ca_sha256.fill(0x24);
  policy.epoch = 1;
  policy.policy_sequence = 1;
  policy.policy_hash.fill(0x25);
  policy.policy_auth_tag.fill(0x26);
  policy.owner_ca_length = 4;
  policy.owner_ca_der[0] = 0x30;
  policy.owner_ca_der[1] = 0x02;
  policy.owner_ca_der[2] = 0x01;
  policy.owner_ca_der[3] = 0;
  std::array<std::uint8_t, keyferry::config::kRoamingConfigPayloadBytes>
      payload{};
  assert(keyferry::config::EncodeRoamingConfigPayload(policy, &payload));

  FakeEffects effects;
  keyferry::provisioning::Session session(
      device_id, recovery_secret, 0, effects,
      keyferry::provisioning::PayloadFormat::kRoamingV2);
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> response{};
  assert(session.Handle(Request(Operation::kChallenge), &response) == Status::kOk);
  assert(response[2] == keyferry::protocol::kRoamingVersion);
  assert((static_cast<std::uint16_t>(response[3]) |
          (static_cast<std::uint16_t>(response[4]) << 8)) ==
         static_cast<std::uint16_t>(payload.size()));
  std::array<std::uint8_t, 32> challenge{};
  std::copy_n(response.begin() + 21, challenge.size(), challenge.begin());
  std::array<std::uint8_t, 16> transaction_id{};
  transaction_id.fill(0x27);
  auto begin = Request(Operation::kBegin);
  begin[1] = keyferry::protocol::kRoamingVersion;
  PutU16(begin.data() + 2, static_cast<std::uint16_t>(payload.size()));
  std::copy(transaction_id.begin(), transaction_id.end(), begin.begin() + 4);
  assert(session.Handle(begin, &response) == Status::kOk);
  for (std::size_t offset = 0; offset < payload.size();) {
    auto data = Request(Operation::kData);
    std::copy(transaction_id.begin(), transaction_id.end(), data.begin() + 1);
    PutU16(data.data() + 17, static_cast<std::uint16_t>(offset));
    const auto length = std::min(keyferry::provisioning::kDataBytesPerReport,
                                 payload.size() - offset);
    data[19] = static_cast<std::uint8_t>(length);
    std::copy_n(payload.begin() + offset, length, data.begin() + 20);
    assert(session.Handle(data, &response) == Status::kOk);
    offset += length;
  }
  std::vector<std::uint8_t> transcript;
  transcript.insert(
      transcript.end(),
      keyferry::protocol::kRoamingMaintenanceAuthenticationDomain.begin(),
      keyferry::protocol::kRoamingMaintenanceAuthenticationDomain.end());
  transcript.insert(transcript.end(), device_id.begin(), device_id.end());
  transcript.insert(transcript.end(), challenge.begin(), challenge.end());
  PutU64(&transcript, 0);
  transcript.insert(transcript.end(), transaction_id.begin(),
                    transaction_id.end());
  PutU32(&transcript, static_cast<std::uint32_t>(payload.size()));
  transcript.insert(transcript.end(), payload.begin(), payload.end());
  const auto tag = TestMac(recovery_secret, transcript);
  auto commit = Request(Operation::kCommit);
  std::copy(transaction_id.begin(), transaction_id.end(), commit.begin() + 1);
  std::copy(tag.begin(), tag.end(), commit.begin() + 17);
  assert(session.Handle(commit, &response) == Status::kOk);
  assert(effects.migration_calls == 1 && effects.commit_calls == 0);
  assert(effects.migrated.device_id == device_id);
  assert(effects.migration_secret == recovery_secret);
  assert(effects.migration_transaction == transaction_id);
  assert(response[2] == static_cast<std::uint8_t>(SlotId::kNone));
  assert(response[3] == 1);
  assert(session.Handle(Request(Operation::kPolicyStatus), &response) ==
         Status::kOk);
  assert(response[keyferry::protocol::kProvisioningPolicyStatusStateOffset] ==
         static_cast<std::uint8_t>(
             keyferry::provisioning::PolicyState::kActive));
  assert(GetU64(response.data() +
                keyferry::protocol::kProvisioningPolicyStatusEpochOffset) == 1);
  assert(GetU64(response.data() +
                keyferry::protocol::kProvisioningPolicyStatusSequenceOffset) ==
         policy.policy_sequence);
  assert(std::equal(
      policy.policy_hash.begin(), policy.policy_hash.end(),
      response.begin() + keyferry::protocol::kProvisioningPolicyStatusHashOffset));
}

void TestPolicyStatusIsBoundedAndAvailableWithoutOperationalAuthority() {
  std::array<std::uint8_t, 16> no_device{};
  std::array<std::uint8_t, 32> no_key{};
  keyferry::provisioning::PolicyStatus policy{};
  policy.state = keyferry::provisioning::PolicyState::kMigrationPending;
  policy.epoch = 7;
  policy.sequence = 11;
  policy.hash.fill(0xA5);
  FakeEffects effects;
  keyferry::provisioning::Session session(
      no_device, no_key, 11, effects,
      keyferry::provisioning::PayloadFormat::kRoamingV2, policy);
  std::array<std::uint8_t, keyferry::provisioning::kReportBytes> response{};
  assert(session.Handle(Request(Operation::kPolicyStatus), &response) ==
         Status::kOk);
  assert(response[0] ==
         (static_cast<std::uint8_t>(Operation::kPolicyStatus) | 0x80));
  assert(response[1] == static_cast<std::uint8_t>(Status::kOk));
  assert(response[2] == static_cast<std::uint8_t>(policy.state));
  assert(GetU64(response.data() + 3) == policy.epoch);
  assert(GetU64(response.data() + 11) == policy.sequence);
  assert(std::equal(policy.hash.begin(), policy.hash.end(), response.begin() + 19));
  assert(std::all_of(response.begin() + 51, response.end(),
                     [](std::uint8_t byte) { return byte == 0; }));

  auto malformed = Request(Operation::kPolicyStatus);
  malformed.back() = 1;
  assert(session.Handle(malformed, &response) == Status::kBadReport);
}

void TestLocalManagementCodecMatchesTheFixedReportContract() {
  namespace local = keyferry::local_management;
  using keyferry::protocol::LocalManagementOperation;
  using keyferry::protocol::LocalManagementStatus;

  local::SessionId session_id{};
  session_id.fill(0x21);
  local::DeviceNonce device_nonce{};
  device_nonce.fill(0x22);
  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x11);
  local::Report report{};
  assert(local::EncodeChallengeResponse(
             LocalManagementStatus::kOk, 0x00800000, device_id, device_nonce,
             session_id, &report) == local::CodecStatus::kOk);
  assert(report[0] ==
         (static_cast<std::uint8_t>(LocalManagementOperation::kChallenge) |
          0x80));
  assert(report[1] == static_cast<std::uint8_t>(LocalManagementStatus::kOk));
  assert(report[2] == keyferry::protocol::kLocalManagementVersion);
  assert(report[3] == 0 && report[4] == 0 && report[5] == 0x80 &&
         report[6] == 0);
  assert(std::equal(device_id.begin(), device_id.end(), report.begin() + 7));
  assert(std::equal(device_nonce.begin(), device_nonce.end(),
                    report.begin() + 23));
  assert(std::equal(session_id.begin(), session_id.end(), report.begin() + 55));
  assert(report[63] == 0);

  local::AuthenticateRequest authenticate{};
  report.fill(0);
  report[0] =
      static_cast<std::uint8_t>(LocalManagementOperation::kAuthenticate);
  report[1] = keyferry::protocol::kLocalManagementVersion;
  std::copy(session_id.begin(), session_id.end(), report.begin() + 2);
  std::fill(report.begin() + 10, report.begin() + 26, std::uint8_t{0x33});
  std::fill(report.begin() + 26, report.begin() + 58, std::uint8_t{0x44});
  assert(local::DecodeAuthenticateRequest(report, &authenticate) ==
         local::CodecStatus::kOk);
  assert(authenticate.session_id == session_id);
  assert(std::all_of(authenticate.host_nonce.begin(),
                     authenticate.host_nonce.end(),
                     [](const std::uint8_t value) { return value == 0x33; }));
  assert(std::all_of(authenticate.proof.begin(), authenticate.proof.end(),
                     [](const std::uint8_t value) { return value == 0x44; }));
  report[63] = 1;
  assert(local::DecodeAuthenticateRequest(report, &authenticate) ==
         local::CodecStatus::kNonzeroReserved);
}

void TestLocalManagementEnvelopeRejectsUnsafeIdentityShapes() {
  namespace local = keyferry::local_management;
  using keyferry::protocol::LocalManagementOperation;
  using keyferry::protocol::LocalManagementStatus;

  local::AuthenticatedRequest request{};
  request.operation = LocalManagementOperation::kClearBleBondAndEnroll;
  request.session_id.fill(0x21);
  request.sequence = 7;
  request.operation_id.fill(0x42);
  request.payload.fill(0x66);
  request.tag.fill(0x77);
  local::Report report{};
  assert(local::EncodeRequestSigningBytes(request, &report) ==
         local::CodecStatus::kOk);
  std::copy(request.tag.begin(), request.tag.end(), report.begin() + 48);

  local::AuthenticatedRequest decoded{};
  assert(local::DecodeAuthenticatedRequest(report, &decoded) ==
         local::CodecStatus::kOk);
  assert(decoded.operation == request.operation);
  assert(decoded.session_id == request.session_id);
  assert(decoded.sequence == request.sequence);
  assert(decoded.operation_id == request.operation_id);
  assert(decoded.payload == request.payload);
  assert(decoded.tag == request.tag);

  auto malformed = report;
  std::fill(malformed.begin() + 14, malformed.begin() + 30, std::uint8_t{0});
  assert(local::DecodeAuthenticatedRequest(malformed, &decoded) ==
         local::CodecStatus::kMissingOperationId);
  malformed = report;
  malformed[10] = malformed[11] = malformed[12] = malformed[13] = 0;
  assert(local::DecodeAuthenticatedRequest(malformed, &decoded) ==
         local::CodecStatus::kZeroSequence);

  request.operation = LocalManagementOperation::kGetStatus;
  assert(local::EncodeRequestSigningBytes(request, &report) ==
         local::CodecStatus::kUnexpectedOperationId);
  request.operation_id.fill(0);
  assert(local::EncodeRequestSigningBytes(request, &report) ==
         local::CodecStatus::kOk);

  local::AuthenticatedResponse response{};
  response.operation = LocalManagementOperation::kRestartNetwork;
  response.status = LocalManagementStatus::kInProgress;
  response.flags = 3;
  response.session_id.fill(0x21);
  response.sequence = 9;
  response.operation_id.fill(0x42);
  response.payload.fill(0x88);
  response.tag.fill(0x99);
  assert(local::EncodeAuthenticatedResponse(response, &report) ==
         local::CodecStatus::kOk);
  assert(report[0] ==
         (static_cast<std::uint8_t>(LocalManagementOperation::kRestartNetwork) |
          0x80));
  assert(report[1] ==
         static_cast<std::uint8_t>(LocalManagementStatus::kInProgress));
  assert(report[2] == keyferry::protocol::kLocalManagementVersion);
  assert(report[3] == 3 && report[12] == 9);
  assert(std::all_of(report.begin() + 48, report.end(),
                     [](const std::uint8_t value) { return value == 0x99; }));
}

class FakeLocalHandler final : public keyferry::local_management::Handler {
 public:
  keyferry::protocol::LocalManagementStatus Handle(
      const keyferry::local_management::AuthenticatedRequest& request,
      keyferry::local_management::ResponsePayload* payload,
      std::uint8_t* flags) override {
    ++calls;
    last = request;
    payload->fill(0x5A);
    *flags = 3;
    return result;
  }

  std::size_t calls{};
  keyferry::local_management::AuthenticatedRequest last{};
  keyferry::protocol::LocalManagementStatus result{
      keyferry::protocol::LocalManagementStatus::kOk};
};

struct LocalAuthentication {
  keyferry::local_management::SessionId session_id{};
  std::array<std::uint8_t, 32> session_key{};
};

LocalAuthentication AuthenticateLocal(
    keyferry::local_management::Session* session,
    const std::array<std::uint8_t, 16>& device_id,
    const std::array<std::uint8_t, 32>& recovery_secret) {
  namespace local = keyferry::local_management;
  using keyferry::protocol::LocalManagementOperation;
  using keyferry::protocol::LocalManagementStatus;

  local::Report request{};
  request[0] = static_cast<std::uint8_t>(LocalManagementOperation::kChallenge);
  local::Report response{};
  assert(session->Handle(request, &response) == LocalManagementStatus::kOk);
  local::DeviceNonce device_nonce{};
  std::copy_n(response.begin() + 23, device_nonce.size(), device_nonce.begin());
  LocalAuthentication authentication{};
  std::copy_n(response.begin() + 55, authentication.session_id.size(),
              authentication.session_id.begin());

  std::vector<std::uint8_t> admin_input(
      keyferry::protocol::kLocalManagementAdminKeyDomain.begin(),
      keyferry::protocol::kLocalManagementAdminKeyDomain.end());
  admin_input.insert(admin_input.end(), device_id.begin(), device_id.end());
  const auto admin_key = TestMac(recovery_secret, admin_input);

  local::HostNonce host_nonce{};
  host_nonce.fill(0x33);
  std::vector<std::uint8_t> transcript(
      keyferry::protocol::kLocalManagementAuthenticationDomain.begin(),
      keyferry::protocol::kLocalManagementAuthenticationDomain.end());
  transcript.push_back(keyferry::protocol::kLocalManagementVersion);
  transcript.insert(transcript.end(), device_id.begin(), device_id.end());
  transcript.insert(transcript.end(), device_nonce.begin(), device_nonce.end());
  transcript.insert(transcript.end(), authentication.session_id.begin(),
                    authentication.session_id.end());
  transcript.insert(transcript.end(), host_nonce.begin(), host_nonce.end());
  const auto host_proof = TestMac(admin_key, transcript);

  request.fill(0);
  request[0] =
      static_cast<std::uint8_t>(LocalManagementOperation::kAuthenticate);
  request[1] = keyferry::protocol::kLocalManagementVersion;
  std::copy(authentication.session_id.begin(), authentication.session_id.end(),
            request.begin() + 2);
  std::copy(host_nonce.begin(), host_nonce.end(), request.begin() + 10);
  std::copy(host_proof.begin(), host_proof.end(), request.begin() + 26);
  assert(session->Handle(request, &response) == LocalManagementStatus::kOk);
  assert(response[0] ==
         (static_cast<std::uint8_t>(LocalManagementOperation::kAuthenticate) |
          0x80));

  std::vector<std::uint8_t> session_input(
      keyferry::protocol::kLocalManagementSessionKeyDomain.begin(),
      keyferry::protocol::kLocalManagementSessionKeyDomain.end());
  session_input.insert(session_input.end(), transcript.begin(), transcript.end());
  authentication.session_key = TestMac(admin_key, session_input);
  std::vector<std::uint8_t> device_proof_input(
      keyferry::protocol::kLocalManagementDeviceProofDomain.begin(),
      keyferry::protocol::kLocalManagementDeviceProofDomain.end());
  device_proof_input.insert(device_proof_input.end(), transcript.begin(),
                            transcript.end());
  const auto device_proof =
      TestMac(authentication.session_key, device_proof_input);
  assert(std::equal(device_proof.begin(), device_proof.end(),
                    response.begin() + 12));
  return authentication;
}

keyferry::local_management::Report AuthenticatedLocalRequest(
    const LocalAuthentication& authentication, const std::uint32_t sequence,
    const bool valid_tag) {
  namespace local = keyferry::local_management;
  local::AuthenticatedRequest decoded{};
  decoded.operation =
      keyferry::protocol::LocalManagementOperation::kRestartNetwork;
  decoded.session_id = authentication.session_id;
  decoded.sequence = sequence;
  decoded.operation_id.fill(0x42);
  decoded.payload.fill(0x66);
  local::Report report{};
  assert(local::EncodeRequestSigningBytes(decoded, &report) ==
         local::CodecStatus::kOk);
  std::vector<std::uint8_t> tag_input(
      keyferry::protocol::kLocalManagementRequestDomain.begin(),
      keyferry::protocol::kLocalManagementRequestDomain.end());
  tag_input.insert(tag_input.end(), report.begin(), report.begin() + 48);
  auto tag = TestMac(authentication.session_key, tag_input);
  if (!valid_tag) {
    tag[0] ^= 1;
  }
  std::copy_n(tag.begin(), 16, report.begin() + 48);
  return report;
}

void TestLocalManagementMutualAuthenticationReplayAndExpiry() {
  namespace local = keyferry::local_management;
  using keyferry::protocol::LocalManagementStatus;

  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x11);
  std::array<std::uint8_t, 32> recovery_secret{};
  recovery_secret.fill(0x22);
  FakeEffects effects;
  FakeLocalHandler handler;
  local::Session session(device_id, recovery_secret, 0x00800000, effects,
                         handler);
  const auto authentication =
      AuthenticateLocal(&session, device_id, recovery_secret);
  assert(session.authenticated());

  auto request = AuthenticatedLocalRequest(authentication, 1, true);
  local::Report response{};
  assert(session.Handle(request, &response) == LocalManagementStatus::kOk);
  assert(handler.calls == 1);
  assert(session.last_sequence() == 1);
  assert(response[3] == 3);
  assert(std::all_of(response.begin() + 32, response.begin() + 48,
                     [](const std::uint8_t value) { return value == 0x5A; }));
  std::vector<std::uint8_t> response_tag_input(
      keyferry::protocol::kLocalManagementResponseDomain.begin(),
      keyferry::protocol::kLocalManagementResponseDomain.end());
  response_tag_input.insert(response_tag_input.end(), response.begin(),
                            response.begin() + 48);
  const auto response_tag =
      TestMac(authentication.session_key, response_tag_input);
  assert(std::equal(response_tag.begin(), response_tag.begin() + 16,
                    response.begin() + 48));

  assert(session.Handle(request, &response) ==
         LocalManagementStatus::kReplay);
  assert(handler.calls == 1);
  assert(!session.authenticated());
  const auto second_authentication =
      AuthenticateLocal(&session, device_id, recovery_secret);
  request = AuthenticatedLocalRequest(second_authentication, 1, false);
  assert(session.Handle(request, &response) ==
         LocalManagementStatus::kAuthenticationFailed);
  assert(!session.authenticated());
  assert(handler.calls == 1);

  const auto third_authentication =
      AuthenticateLocal(&session, device_id, recovery_secret);
  static_cast<void>(third_authentication);
  effects.now_ms = keyferry::protocol::kLocalManagementIdleTimeoutMs;
  assert(session.Expire(effects.now_ms));
  assert(!session.authenticated());
}

void TestLocalManagementRejectsBadProofBeforeDispatch() {
  namespace local = keyferry::local_management;
  using keyferry::protocol::LocalManagementOperation;
  using keyferry::protocol::LocalManagementStatus;

  std::array<std::uint8_t, 16> device_id{};
  device_id.fill(0x11);
  std::array<std::uint8_t, 32> recovery_secret{};
  recovery_secret.fill(0x22);
  FakeEffects effects;
  FakeLocalHandler handler;
  local::Session session(device_id, recovery_secret, 0x00800000, effects,
                         handler);
  local::Report request{};
  local::Report response{};
  request[0] = static_cast<std::uint8_t>(LocalManagementOperation::kChallenge);
  assert(session.Handle(request, &response) == LocalManagementStatus::kOk);
  local::SessionId session_id{};
  std::copy_n(response.begin() + 55, session_id.size(), session_id.begin());
  request.fill(0);
  request[0] =
      static_cast<std::uint8_t>(LocalManagementOperation::kAuthenticate);
  request[1] = keyferry::protocol::kLocalManagementVersion;
  std::copy(session_id.begin(), session_id.end(), request.begin() + 2);
  std::fill(request.begin() + 10, request.begin() + 26, std::uint8_t{0x33});
  std::fill(request.begin() + 26, request.begin() + 58, std::uint8_t{0xEE});
  assert(session.Handle(request, &response) ==
         LocalManagementStatus::kAuthenticationFailed);
  assert(!session.authenticated());
  assert(handler.calls == 0);
}

class FakeReceiptStorage final
    : public keyferry::local_management::ReceiptStorage {
 public:
  bool Find(const keyferry::local_management::OperationId& operation_id,
            keyferry::local_management::Receipt* receipt,
            bool* found) override {
    if (fail_find) {
      return false;
    }
    for (const auto& candidate : receipts) {
      if (candidate.operation_id == operation_id) {
        *receipt = candidate;
        *found = true;
        return true;
      }
    }
    *found = false;
    return true;
  }

  bool Save(const keyferry::local_management::Receipt& receipt) override {
    ++save_calls;
    events.push_back(10);
    if (fail_on_save_call != 0 && save_calls == fail_on_save_call) {
      return false;
    }
    for (auto& candidate : receipts) {
      if (candidate.operation_id == receipt.operation_id) {
        candidate = receipt;
        return true;
      }
    }
    receipts.push_back(receipt);
    return true;
  }

  bool FindInProgress(keyferry::local_management::Receipt* receipt,
                      bool* found) override {
    if (fail_find) {
      return false;
    }
    for (const auto& candidate : receipts) {
      if (candidate.state ==
          keyferry::protocol::LocalManagementReceiptState::kInProgress) {
        *receipt = candidate;
        *found = true;
        return true;
      }
    }
    *found = false;
    return true;
  }

  std::vector<keyferry::local_management::Receipt> receipts;
  std::vector<int> events;
  std::size_t save_calls{};
  std::size_t fail_on_save_call{};
  bool fail_find{};
};

class FakeManagementPlatform final
    : public keyferry::local_management::Platform {
 public:
  std::uint64_t MonotonicMilliseconds() override { return now_ms; }

  keyferry::protocol::LocalManagementStatus ReadStatus(
      keyferry::protocol::LocalManagementStatusPage page,
      keyferry::local_management::ResponsePayload* payload) override {
    ++status_reads;
    (*payload)[0] = static_cast<std::uint8_t>(page);
    return status_result;
  }

  void SetMaintenanceActive(const bool active) override {
    maintenance_blocked = active;
    ++maintenance_state_changes;
  }

  keyferry::protocol::LocalManagementStatus RequestNeutralization() override {
    events->push_back(20);
    ++neutralization_requests;
    return neutralization_result;
  }

  bool NeutralConfirmed() override { return neutral; }

  keyferry::protocol::LocalManagementStatus RestartNetwork() override {
    events->push_back(30);
    ++restart_network_calls;
    return mutation_result;
  }

  keyferry::protocol::LocalManagementStatus ClearBleBondAndEnroll() override {
    events->push_back(31);
    ++clear_bond_calls;
    return mutation_result;
  }

  keyferry::protocol::LocalManagementStatus CancelEnrollment() override {
    events->push_back(32);
    ++cancel_enrollment_calls;
    return mutation_result;
  }

  keyferry::protocol::LocalManagementStatus SetOutputMode(
      keyferry::protocol::OutputMode mode, bool* restart_required) override {
    events->push_back(33);
    ++set_mode_calls;
    last_mode = mode;
    *restart_required = mode_restart_required;
    return mutation_result;
  }

  void RestartDevice() override {
    events->push_back(40);
    ++restart_device_calls;
  }

  std::vector<int>* events{};
  std::uint64_t now_ms{};
  keyferry::protocol::LocalManagementStatus status_result{
      keyferry::protocol::LocalManagementStatus::kOk};
  keyferry::protocol::LocalManagementStatus neutralization_result{
      keyferry::protocol::LocalManagementStatus::kOk};
  keyferry::protocol::LocalManagementStatus mutation_result{
      keyferry::protocol::LocalManagementStatus::kOk};
  keyferry::protocol::OutputMode last_mode{
      keyferry::protocol::OutputMode::kUsbHid};
  std::size_t status_reads{};
  std::size_t neutralization_requests{};
  std::size_t restart_network_calls{};
  std::size_t clear_bond_calls{};
  std::size_t cancel_enrollment_calls{};
  std::size_t set_mode_calls{};
  std::size_t restart_device_calls{};
  std::size_t maintenance_state_changes{};
  bool neutral{};
  bool maintenance_blocked{};
  bool mode_restart_required{};
};

keyferry::local_management::AuthenticatedRequest ManagementRequest(
    keyferry::protocol::LocalManagementOperation operation,
    const std::uint8_t id_byte) {
  keyferry::local_management::AuthenticatedRequest request{};
  request.operation = operation;
  if (id_byte != 0) {
    request.operation_id.fill(id_byte);
  }
  return request;
}

keyferry::protocol::LocalManagementStatus HandleManagement(
    keyferry::local_management::Coordinator* coordinator,
    const keyferry::local_management::AuthenticatedRequest& request,
    keyferry::local_management::ResponsePayload* payload = nullptr,
    std::uint8_t* flags = nullptr) {
  keyferry::local_management::ResponsePayload local_payload{};
  std::uint8_t local_flags{};
  return coordinator->Handle(request,
                             payload == nullptr ? &local_payload : payload,
                             flags == nullptr ? &local_flags : flags);
}

void OpenMaintenance(keyferry::local_management::Coordinator* coordinator,
                     FakeManagementPlatform* platform,
                     const std::uint8_t id_byte) {
  platform->neutral = true;
  const auto request = ManagementRequest(
      keyferry::protocol::LocalManagementOperation::kOpenMaintenance,
      id_byte);
  assert(HandleManagement(coordinator, request) ==
         keyferry::protocol::LocalManagementStatus::kOk);
  assert(coordinator->maintenance_active());
  assert(platform->maintenance_blocked);
}

void TestLocalManagementCoordinatorStatusAndPayloadValidation() {
  using keyferry::protocol::LocalManagementOperation;
  using LocalStatus = keyferry::protocol::LocalManagementStatus;
  FakeReceiptStorage storage;
  FakeManagementPlatform platform;
  platform.events = &storage.events;
  keyferry::local_management::Coordinator coordinator(platform, storage);
  assert(coordinator.Initialize());

  auto request = ManagementRequest(LocalManagementOperation::kGetStatus, 0);
  request.payload[0] = static_cast<std::uint8_t>(
      keyferry::protocol::LocalManagementStatusPage::kBleHid);
  keyferry::local_management::ResponsePayload payload{};
  assert(HandleManagement(&coordinator, request, &payload) == LocalStatus::kOk);
  assert(platform.status_reads == 1);
  assert(payload[0] == request.payload[0]);

  // New probe pages are admitted by the coordinator, while an ordinary
  // platform without the opt-in probe reports them as unavailable.
  platform.status_result = LocalStatus::kUnsupported;
  for (const auto page : {
           keyferry::protocol::LocalManagementStatusPage::kProbeRun,
           keyferry::protocol::LocalManagementStatusPage::kProbeHeap,
           keyferry::protocol::LocalManagementStatusPage::kProbeStack,
       }) {
    request.payload[0] = static_cast<std::uint8_t>(page);
    assert(HandleManagement(&coordinator, request) == LocalStatus::kUnsupported);
  }
  assert(platform.status_reads == 4);
  platform.status_result = LocalStatus::kOk;

  request.payload[17] = 1;
  assert(HandleManagement(&coordinator, request) == LocalStatus::kBadReport);
  assert(platform.status_reads == 4);
  request.payload.fill(0);
  request.payload[0] = 0x7F;
  assert(HandleManagement(&coordinator, request) == LocalStatus::kBadReport);

  auto mutation =
      ManagementRequest(LocalManagementOperation::kRestartNetwork, 0x21);
  mutation.payload[0] = 1;
  assert(HandleManagement(&coordinator, mutation) == LocalStatus::kBadReport);
  assert(storage.receipts.empty());
  assert(platform.restart_network_calls == 0);

  FakeReceiptStorage failed_storage;
  failed_storage.fail_on_save_call = 1;
  FakeManagementPlatform failed_platform;
  failed_platform.events = &failed_storage.events;
  failed_platform.neutral = true;
  keyferry::local_management::Coordinator failed_coordinator(failed_platform,
                                                             failed_storage);
  assert(failed_coordinator.Initialize());
  auto open =
      ManagementRequest(LocalManagementOperation::kOpenMaintenance, 0x22);
  assert(HandleManagement(&failed_coordinator, open) ==
         LocalStatus::kStorageError);
  assert(failed_platform.neutralization_requests == 0);
  assert(!failed_platform.maintenance_blocked);
}

void TestLocalManagementCoordinatorPersistsBeforeEffectsAndDeduplicates() {
  using keyferry::protocol::LocalManagementOperation;
  using keyferry::protocol::LocalManagementReceiptState;
  using LocalStatus = keyferry::protocol::LocalManagementStatus;
  FakeReceiptStorage storage;
  FakeManagementPlatform platform;
  platform.events = &storage.events;
  keyferry::local_management::Coordinator coordinator(platform, storage);
  assert(coordinator.Initialize());

  auto restart =
      ManagementRequest(LocalManagementOperation::kRestartNetwork, 0x31);
  assert(HandleManagement(&coordinator, restart) == LocalStatus::kNotNeutral);
  assert(platform.restart_network_calls == 0);

  OpenMaintenance(&coordinator, &platform, 0x30);
  storage.events.clear();
  assert(HandleManagement(&coordinator, restart) == LocalStatus::kOk);
  assert((storage.events == std::vector<int>{10, 30, 10}));
  assert(storage.receipts.back().state ==
         LocalManagementReceiptState::kCommitted);
  assert(platform.restart_network_calls == 1);

  assert(HandleManagement(&coordinator, restart) == LocalStatus::kOk);
  assert(platform.restart_network_calls == 1);
  auto conflict = restart;
  conflict.operation = LocalManagementOperation::kCancelEnrollment;
  assert(HandleManagement(&coordinator, conflict) ==
         LocalStatus::kOperationConflict);
  assert(platform.cancel_enrollment_calls == 0);
}

void TestLocalManagementCoordinatorDrainsAndTimesOut() {
  using keyferry::protocol::LocalManagementOperation;
  using keyferry::protocol::LocalManagementReceiptState;
  using LocalStatus = keyferry::protocol::LocalManagementStatus;
  FakeReceiptStorage storage;
  FakeManagementPlatform platform;
  platform.events = &storage.events;
  keyferry::local_management::Coordinator coordinator(platform, storage);
  assert(coordinator.Initialize());
  platform.now_ms = 100;
  auto open =
      ManagementRequest(LocalManagementOperation::kOpenMaintenance, 0x41);
  assert(HandleManagement(&coordinator, open) == LocalStatus::kInProgress);
  assert((storage.events == std::vector<int>{10, 20}));
  assert(!coordinator.maintenance_active());
  assert(platform.maintenance_blocked);
  platform.now_ms = 2099;
  coordinator.Poll();
  assert(storage.receipts[0].state ==
         LocalManagementReceiptState::kInProgress);
  platform.neutral = true;
  coordinator.Poll();
  assert(coordinator.maintenance_active());
  assert(storage.receipts[0].state ==
         LocalManagementReceiptState::kCommitted);

  FakeReceiptStorage lost_storage;
  FakeManagementPlatform lost_platform;
  lost_platform.events = &lost_storage.events;
  keyferry::local_management::Coordinator lost_coordinator(lost_platform,
                                                           lost_storage);
  assert(lost_coordinator.Initialize());
  open.operation_id.fill(0x43);
  assert(HandleManagement(&lost_coordinator, open) ==
         LocalStatus::kInProgress);
  lost_coordinator.TransportLost();
  assert(!lost_coordinator.maintenance_active());
  assert(!lost_platform.maintenance_blocked);
  assert(lost_storage.receipts[0].state ==
         LocalManagementReceiptState::kUnknown);

  FakeReceiptStorage timeout_storage;
  FakeManagementPlatform timeout_platform;
  timeout_platform.events = &timeout_storage.events;
  keyferry::local_management::Coordinator timeout_coordinator(
      timeout_platform, timeout_storage);
  assert(timeout_coordinator.Initialize());
  open.operation_id.fill(0x42);
  assert(HandleManagement(&timeout_coordinator, open) ==
         LocalStatus::kInProgress);
  timeout_platform.now_ms =
      keyferry::local_management::Coordinator::kNeutralizationDeadlineMs;
  timeout_coordinator.Poll();
  assert(!timeout_coordinator.maintenance_active());
  assert(!timeout_platform.maintenance_blocked);
  assert(timeout_storage.receipts[0].state ==
         LocalManagementReceiptState::kFailed);
  assert(timeout_storage.receipts[0].result == LocalStatus::kNotNeutral);
}

void TestLocalManagementNeutralizationAcceptsOnlySafeUnavailableOutput() {
  constexpr std::uint8_t kKeyboardNeutral = 0x01;
  using keyferry::local_management::NeutralizationSatisfied;

  assert(NeutralizationSatisfied(true, kKeyboardNeutral,
                                 kKeyboardNeutral, false));
  assert(!NeutralizationSatisfied(true, 0, kKeyboardNeutral, false));
  assert(NeutralizationSatisfied(true, 0, kKeyboardNeutral, true));
  assert(!NeutralizationSatisfied(false, 0, kKeyboardNeutral, true));
}

void TestLocalManagementCoordinatorRestartWaitsForResponseCompletion() {
  using keyferry::protocol::LocalManagementOperation;
  using LocalStatus = keyferry::protocol::LocalManagementStatus;
  FakeReceiptStorage storage;
  FakeManagementPlatform platform;
  platform.events = &storage.events;
  keyferry::local_management::Coordinator coordinator(platform, storage);
  assert(coordinator.Initialize());
  OpenMaintenance(&coordinator, &platform, 0x50);

  auto set_mode =
      ManagementRequest(LocalManagementOperation::kSetOutputMode, 0x51);
  set_mode.payload[0] = static_cast<std::uint8_t>(
      keyferry::protocol::OutputMode::kBleHid);
  platform.mode_restart_required = true;
  std::uint8_t flags{};
  assert(HandleManagement(&coordinator, set_mode, nullptr, &flags) ==
         LocalStatus::kOk);
  assert(platform.set_mode_calls == 1);
  assert(platform.last_mode == keyferry::protocol::OutputMode::kBleHid);
  assert((flags & keyferry::local_management::Coordinator::
                      kFlagRestartPending) != 0);
  assert(platform.restart_device_calls == 0);
  auto wrong_id = set_mode.operation_id;
  wrong_id[0] ^= 1;
  coordinator.ResponseCompleted(wrong_id);
  assert(platform.restart_device_calls == 0);
  coordinator.ResponseCompleted(set_mode.operation_id);
  assert(platform.restart_device_calls == 1);
  assert(!coordinator.maintenance_active());
}

void TestLocalManagementCoordinatorEnrollmentStaysLiveWithoutRestart() {
  using keyferry::protocol::LocalManagementOperation;
  using LocalStatus = keyferry::protocol::LocalManagementStatus;
  FakeReceiptStorage storage;
  FakeManagementPlatform platform;
  platform.events = &storage.events;
  keyferry::local_management::Coordinator coordinator(platform, storage);
  assert(coordinator.Initialize());
  OpenMaintenance(&coordinator, &platform, 0x58);

  const auto enroll = ManagementRequest(
      LocalManagementOperation::kClearBleBondAndEnroll, 0x59);
  std::uint8_t flags{};
  assert(HandleManagement(&coordinator, enroll, nullptr, &flags) ==
         LocalStatus::kOk);
  assert(platform.clear_bond_calls == 1);
  assert((flags & keyferry::local_management::Coordinator::
                      kFlagRestartPending) == 0);
  coordinator.ResponseCompleted(enroll.operation_id);
  assert(platform.restart_device_calls == 0);
  assert(coordinator.maintenance_active());

  const auto cancel =
      ManagementRequest(LocalManagementOperation::kCancelEnrollment, 0x5A);
  assert(HandleManagement(&coordinator, cancel) == LocalStatus::kOk);
  assert(platform.cancel_enrollment_calls == 1);
  assert(platform.restart_device_calls == 0);
}

void TestLocalManagementCoordinatorStorageFailureAndBootRecovery() {
  using keyferry::protocol::LocalManagementOperation;
  using keyferry::protocol::LocalManagementReceiptState;
  using LocalStatus = keyferry::protocol::LocalManagementStatus;
  FakeReceiptStorage storage;
  FakeManagementPlatform platform;
  platform.events = &storage.events;
  keyferry::local_management::Coordinator coordinator(platform, storage);
  assert(coordinator.Initialize());
  OpenMaintenance(&coordinator, &platform, 0x60);

  const auto prior_saves = storage.save_calls;
  storage.fail_on_save_call = prior_saves + 2;
  auto restart =
      ManagementRequest(LocalManagementOperation::kRestartNetwork, 0x61);
  assert(HandleManagement(&coordinator, restart) == LocalStatus::kStorageError);
  assert(platform.restart_network_calls == 1);
  assert(storage.receipts.back().state ==
         LocalManagementReceiptState::kInProgress);
  assert(HandleManagement(&coordinator, restart) == LocalStatus::kInProgress);
  assert(platform.restart_network_calls == 1);

  storage.fail_on_save_call = 0;
  FakeManagementPlatform recovered_platform;
  recovered_platform.events = &storage.events;
  keyferry::local_management::Coordinator recovered(recovered_platform,
                                                     storage);
  assert(recovered.Initialize());
  assert(storage.receipts.back().state ==
         LocalManagementReceiptState::kUnknown);
  assert(recovered_platform.restart_network_calls == 0);

  auto read = ManagementRequest(LocalManagementOperation::kGetReceipt, 0);
  std::copy(restart.operation_id.begin(), restart.operation_id.end(),
            read.payload.begin());
  keyferry::local_management::ResponsePayload payload{};
  assert(HandleManagement(&recovered, read, &payload) == LocalStatus::kInternal);
  assert(payload[0] ==
         static_cast<std::uint8_t>(LocalManagementReceiptState::kUnknown));
}

}  // namespace

int main() {
  TestAuthenticatedCommitUsesCanonicalPayloadAndRealStorage();
  TestAuthenticationFailureConsumesNonceAndWritesNothing();
  TestMalformedOrderIdentityAndStorageFailuresFailClosed();
  TestKeyRotationAndAbort();
  TestRandomAndPaddingFailures();
  TestMalformedReportMatrix();
  TestCollapsedAuthorityIsRejectedBeforeStorage();
  TestBoundedMalformedReportsNeverWrite();
  TestMissingAuthorityTimeoutAndTransportLossFailClosed();
  TestRoamingMigrationUsesDistinctAuthenticatedPayload();
  TestPolicyStatusIsBoundedAndAvailableWithoutOperationalAuthority();
  TestLocalManagementCodecMatchesTheFixedReportContract();
  TestLocalManagementEnvelopeRejectsUnsafeIdentityShapes();
  TestLocalManagementMutualAuthenticationReplayAndExpiry();
  TestLocalManagementRejectsBadProofBeforeDispatch();
  TestLocalManagementCoordinatorStatusAndPayloadValidation();
  TestLocalManagementCoordinatorPersistsBeforeEffectsAndDeduplicates();
  TestLocalManagementCoordinatorDrainsAndTimesOut();
  TestLocalManagementNeutralizationAcceptsOnlySafeUnavailableOutput();
  TestLocalManagementCoordinatorRestartWaitsForResponseCompletion();
  TestLocalManagementCoordinatorEnrollmentStaysLiveWithoutRestart();
  TestLocalManagementCoordinatorStorageFailureAndBootRecovery();
  std::puts("provisioning_test: ok");
  return 0;
}
