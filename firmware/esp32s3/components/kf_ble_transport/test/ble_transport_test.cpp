#include "keyferry/ble_transport.h"
#include "keyferry/idf_ble_transport.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>

namespace {

using keyferry::ble::BytePipe;
using keyferry::ble::Fault;
using keyferry::ble::ReconcileAdvertisingStopState;

constexpr std::uint32_t kGeneration = 7;

BytePipe ReadyPipe(std::uint16_t mtu = 247) {
  BytePipe pipe;
  assert(pipe.Connect(kGeneration, mtu, 100));
  assert(pipe.SetIndications(kGeneration, true, 101));
  return pipe;
}

void TestMtu23AndIndicationAcknowledgement() {
  auto pipe = ReadyPipe(23);
  assert(pipe.fragment_capacity() == 20);
  assert(pipe.UpdateMtu(kGeneration, 247));
  assert(pipe.fragment_capacity() == 244);
  assert(!pipe.UpdateMtu(kGeneration - 1, 23));
  assert(pipe.fragment_capacity() == 244);
  std::array<std::uint8_t, 20> bytes{};
  bytes.fill(0xA5);
  assert(pipe.StageIndication(kGeneration, bytes.data(), bytes.size(), 200));
  const auto pending = pipe.PendingIndication();
  assert(pending.size == bytes.size());
  assert(pending.data != nullptr && pending.data[0] == 0xA5);
  assert(pipe.CompleteIndication(kGeneration, true, 201));
  assert(!pipe.indication_pending());
  assert(pipe.PendingIndication().size == 0);

  std::array<std::uint8_t, 245> oversized{};
  assert(!pipe.StageIndication(kGeneration, oversized.data(), oversized.size(),
                               202));
  assert(pipe.fault() == Fault::kBadFragment);
}

void TestReceiveRingWrapAndExactFull() {
  auto pipe = ReadyPipe();
  std::array<std::uint8_t, 1268> stream{};
  std::array<std::uint8_t, 768> output{};
  for (std::size_t index = 0; index < stream.size(); ++index) {
    stream[index] = static_cast<std::uint8_t>(index % 251);
  }

  for (int count = 0; count < 4; ++count) {
    assert(pipe.ReceiveWrite(kGeneration, stream.data() + count * 244, 244,
                             200 + count));
  }
  assert(pipe.Read(output.data(), 500) == 500);
  for (std::size_t index = 0; index < 500; ++index) {
    assert(output[index] == stream[index]);
  }
  assert(pipe.ReceiveWrite(kGeneration, stream.data() + 976, 244, 300));
  assert(pipe.ReceiveWrite(kGeneration, stream.data() + 1220, 48, 301));
  assert(pipe.received_size() == 768);
  assert(pipe.Read(output.data(), output.size()) == 768);
  for (std::size_t index = 0; index < output.size(); ++index) {
    assert(output[index] == stream[index + 500]);
  }
  assert(pipe.received_size() == 0);
}

void TestOverflowFailsClosedAndWipes() {
  auto pipe = ReadyPipe();
  std::array<std::uint8_t, 244> fragment{};
  for (int count = 0; count < 4; ++count) {
    assert(pipe.ReceiveWrite(kGeneration, fragment.data(), fragment.size(),
                             200 + count));
  }
  assert(!pipe.ReceiveWrite(kGeneration, fragment.data(), 49, 300));
  assert(pipe.fault() == Fault::kReceiveOverflow);
  assert(!pipe.connected());
  assert(pipe.received_size() == 0);
}

void TestStaleGenerationCannotAffectCurrentConnection() {
  auto pipe = ReadyPipe();
  std::array<std::uint8_t, 1> byte{0x11};
  assert(!pipe.ReceiveWrite(kGeneration - 1, byte.data(), byte.size(), 200));
  assert(pipe.ready());
  assert(pipe.fault() == Fault::kNone);
  assert(!pipe.Disconnect(kGeneration - 1));
  assert(pipe.ready());

  assert(pipe.StageIndication(kGeneration, byte.data(), byte.size(), 201));
  assert(!pipe.CompleteIndication(kGeneration - 1, false, 202));
  assert(pipe.ready());
  assert(pipe.indication_pending());
  assert(pipe.CompleteIndication(kGeneration, true, 203));
}

void TestDeadlinesAndFailuresCloseThePipe() {
  BytePipe setup;
  assert(setup.Connect(kGeneration, 247, 100));
  assert(setup.Poll(100 + keyferry::protocol::kBleCccdSetupTimeoutMs - 1));
  assert(!setup.Poll(100 + keyferry::protocol::kBleCccdSetupTimeoutMs));
  assert(setup.fault() == Fault::kCccdTimeout);

  auto indication = ReadyPipe();
  std::array<std::uint8_t, 1> byte{0x22};
  assert(indication.StageIndication(kGeneration, byte.data(), byte.size(), 300));
  assert(indication.Poll(300 + keyferry::protocol::kBleOperationTimeoutMs - 1));
  assert(!indication.Poll(300 + keyferry::protocol::kBleOperationTimeoutMs));
  assert(indication.fault() == Fault::kIndicationTimeout);

  auto failed = ReadyPipe();
  assert(failed.StageIndication(kGeneration, byte.data(), byte.size(), 400));
  assert(!failed.CompleteIndication(kGeneration, false, 401));
  assert(failed.fault() == Fault::kIndicationFailed);

  auto disabled = ReadyPipe();
  assert(!disabled.SetIndications(kGeneration, false, 500));
  assert(disabled.fault() == Fault::kCccdDisabled);
}

void TestInvalidStateFailsClosed() {
  BytePipe pipe;
  assert(!pipe.Connect(0, 247, 0));
  assert(pipe.fault() == Fault::kInvalidMtu);

  assert(pipe.Connect(kGeneration, 247, 10));
  std::array<std::uint8_t, 1> byte{0x33};
  assert(!pipe.ReceiveWrite(kGeneration, byte.data(), byte.size(), 11));
  assert(pipe.fault() == Fault::kBadState);

  BytePipe oversized_mtu;
  assert(!oversized_mtu.Connect(kGeneration, 518, 12));
  assert(oversized_mtu.fault() == Fault::kInvalidMtu);

  auto renegotiated_mtu = ReadyPipe();
  assert(!renegotiated_mtu.UpdateMtu(kGeneration, 518));
  assert(renegotiated_mtu.fault() == Fault::kInvalidMtu);
}

void TestAdvertisingStopReconcilesEverySuccessfulNimbleResult() {
  constexpr int kAlreadyStopped = 2;
  bool advertising = true;
  assert(ReconcileAdvertisingStopState(0, kAlreadyStopped, &advertising));
  assert(!advertising);

  advertising = true;
  assert(ReconcileAdvertisingStopState(kAlreadyStopped, kAlreadyStopped,
                                       &advertising));
  assert(!advertising);

  advertising = true;
  assert(!ReconcileAdvertisingStopState(7, kAlreadyStopped, &advertising));
  assert(advertising);
  assert(!ReconcileAdvertisingStopState(0, kAlreadyStopped, nullptr));
}

}  // namespace

int main() {
  TestMtu23AndIndicationAcknowledgement();
  TestReceiveRingWrapAndExactFull();
  TestOverflowFailsClosedAndWipes();
  TestStaleGenerationCannotAffectCurrentConnection();
  TestDeadlinesAndFailuresCloseThePipe();
  TestInvalidStateFailsClosed();
  TestAdvertisingStopReconcilesEverySuccessfulNimbleResult();
  std::cout << "ble_transport_test: ok\n";
  return 0;
}
