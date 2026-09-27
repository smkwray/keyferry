#include "keyferry/transport_arbiter.h"

#include <cassert>
#include <cstdint>
#include <cstdio>

#include "keyferry_protocol_generated.h"

namespace {

using keyferry::transport::Path;
using keyferry::transport::TransportAvailability;
using keyferry::transport::TransportArbiter;

void TestWifiWinsPreferenceWindow() {
  TransportArbiter arbiter;
  auto actions = arbiter.Boot(100);
  assert(actions.start_wifi && !actions.fail_closed);
  assert(arbiter.generation() == 1);

  actions = arbiter.Poll(100 + keyferry::protocol::kBleAdvertisingDelayMs);
  assert(actions.start_ble_advertising);
  actions = arbiter.BleConnected(6000);
  assert(!actions.start_ble_authentication);
  assert(!arbiter.ble_authentication_permitted());

  actions = arbiter.WifiAttemptFinished(true, 7000);
  assert(actions.stop_ble);
  assert(arbiter.active_path() == Path::kWifi);
  assert(!arbiter.ble_connected());
}

void TestBleStartsAfterPreferenceDeadline() {
  TransportArbiter arbiter;
  arbiter.Boot(1000);
  auto actions = arbiter.Poll(
      1000 + keyferry::protocol::kBleAdvertisingDelayMs);
  assert(actions.start_ble_advertising);
  actions = arbiter.BleConnected(7000);
  assert(!actions.start_ble_authentication);

  actions = arbiter.Poll(1000 + keyferry::protocol::kBleWifiPreferenceMs);
  assert(actions.cancel_wifi && actions.start_ble_authentication);
  assert(arbiter.ble_authentication_permitted());
  actions = arbiter.BleAuthenticated(17000);
  assert(arbiter.active_path() == Path::kBluetooth);
  assert(!arbiter.wifi_candidate_active());
}

void TestWifiFailureReleasesWaitingBleCandidate() {
  TransportArbiter arbiter;
  arbiter.Boot(0);
  arbiter.Poll(keyferry::protocol::kBleAdvertisingDelayMs);
  arbiter.BleConnected(6000);
  auto actions = arbiter.WifiAttemptFinished(false, 7000);
  assert(actions.fail_closed);
  assert(actions.start_ble_authentication);
  assert(arbiter.ble_authentication_permitted());
}

void TestThreeBleFailuresForceWifiAttempt() {
  TransportArbiter arbiter;
  arbiter.Boot(0);
  arbiter.WifiAttemptFinished(
      false, keyferry::protocol::kBleAdvertisingDelayMs);
  for (std::uint8_t failure = 1;
       failure <= keyferry::protocol::kBleFailedCandidatesBeforeWifiRetry;
       ++failure) {
    assert(arbiter.ble_advertising());
    arbiter.BleConnected(6000 + failure);
    auto actions = arbiter.BleCandidateFailed(7000 + failure);
    assert(actions.fail_closed);
    if (failure < keyferry::protocol::kBleFailedCandidatesBeforeWifiRetry) {
      assert(actions.start_ble_advertising);
    } else {
      assert(actions.start_wifi);
      assert(!actions.start_ble_advertising);
      assert(arbiter.wifi_candidate_active());
    }
  }
  auto actions = arbiter.WifiAttemptFinished(false, 3000);
  assert(actions.fail_closed && actions.start_ble_advertising);
}

void TestActiveLossStartsFreshDisarmedSelection() {
  TransportArbiter arbiter;
  arbiter.Boot(0);
  arbiter.WifiAttemptFinished(true, 100);
  const auto old_generation = arbiter.generation();
  const auto actions = arbiter.ActiveTransportLost(200);
  assert(actions.fail_closed && actions.start_wifi);
  assert(arbiter.active_path() == Path::kNone);
  assert(arbiter.wifi_candidate_active());
  assert(arbiter.generation() == old_generation + 1);
}

void TestInvalidOrLosingEventsCannotReplaceOwner() {
  TransportArbiter arbiter;
  arbiter.Boot(0);
  arbiter.WifiAttemptFinished(true, 100);
  auto actions = arbiter.BleConnected(200);
  assert(!actions.start_ble_authentication);
  actions = arbiter.BleAuthenticated(201);
  assert(!actions.cancel_wifi);
  assert(arbiter.active_path() == Path::kWifi);
}

void TestIdleBleAdvertisingPeriodicallyRetriesWifi() {
  TransportArbiter arbiter;
  arbiter.Boot(0);
  auto actions = arbiter.Poll(keyferry::protocol::kBleAdvertisingDelayMs);
  assert(actions.start_ble_advertising);
  actions = arbiter.Poll(keyferry::protocol::kBleWifiPreferenceMs);
  assert(actions.cancel_wifi);
  assert(!actions.start_wifi);
  actions = arbiter.Poll(keyferry::protocol::kBleAdvertisingDelayMs +
                         keyferry::protocol::kBleWifiRetryIntervalMs - 1);
  assert(!actions.start_wifi);
  actions = arbiter.Poll(keyferry::protocol::kBleAdvertisingDelayMs +
                         keyferry::protocol::kBleWifiRetryIntervalMs);
  assert(actions.stop_ble && actions.start_wifi);
  assert(arbiter.wifi_candidate_active());
  assert(!arbiter.ble_advertising());
}

void TestFastWifiRetryStillAllowsFullBleAdvertisingWindow() {
  TransportArbiter arbiter;
  arbiter.Boot(0);
  arbiter.Poll(keyferry::protocol::kBleAdvertisingDelayMs);
  arbiter.Poll(keyferry::protocol::kBleWifiPreferenceMs);
  auto actions = arbiter.Poll(keyferry::protocol::kBleAdvertisingDelayMs +
                              keyferry::protocol::kBleWifiRetryIntervalMs);
  assert(actions.stop_ble && actions.start_wifi);

  const auto wifi_failed_ms = keyferry::protocol::kBleAdvertisingDelayMs +
                              keyferry::protocol::kBleWifiRetryIntervalMs + 1;
  actions = arbiter.WifiAttemptFinished(false, wifi_failed_ms);
  assert(!actions.start_ble_advertising);
  const auto advertising_started_ms =
      wifi_failed_ms + keyferry::protocol::kBleAdvertisingDelayMs;
  actions = arbiter.Poll(advertising_started_ms);
  assert(actions.start_ble_advertising);
  actions = arbiter.Poll(advertising_started_ms +
                         keyferry::protocol::kBleWifiRetryIntervalMs - 1);
  assert(!actions.start_wifi);
  actions = arbiter.Poll(advertising_started_ms +
                         keyferry::protocol::kBleWifiRetryIntervalMs);
  assert(actions.stop_ble && actions.start_wifi);
}

void TestWifiOnlyNeverRequestsBle() {
  TransportArbiter arbiter;
  auto actions = arbiter.Boot(0, TransportAvailability{true, false});
  assert(actions.start_wifi && !actions.start_ble_advertising);
  actions = arbiter.WifiAttemptFinished(false, 100);
  assert(actions.fail_closed && !actions.start_wifi &&
         !actions.start_ble_advertising);
  actions = arbiter.Poll(100 +
                         keyferry::protocol::kBleWifiRetryIntervalMs - 1);
  assert(!actions.start_wifi && !actions.start_ble_advertising);
  actions = arbiter.Poll(100 +
                         keyferry::protocol::kBleWifiRetryIntervalMs);
  assert(actions.start_wifi && !actions.start_ble_advertising);
  actions = arbiter.Poll(100 +
                         keyferry::protocol::kBleWifiRetryIntervalMs + 1);
  assert(!actions.start_ble_advertising);
}

void TestBleOnlyStartsImmediatelyAndNeverRequestsWifi() {
  TransportArbiter arbiter;
  auto actions = arbiter.Boot(0, TransportAvailability{false, true});
  assert(!actions.start_wifi && actions.start_ble_advertising);
  actions = arbiter.BleConnected(1);
  assert(actions.start_ble_authentication);
  actions = arbiter.BleCandidateFailed(2);
  assert(actions.fail_closed && actions.start_ble_advertising);
  assert(!actions.start_wifi);
}

void TestBothUnavailableFailsClosedWithoutRadioAction() {
  TransportArbiter arbiter;
  auto actions = arbiter.Boot(0, TransportAvailability{false, false});
  assert(!actions.start_wifi && !actions.start_ble_advertising);
  actions = arbiter.Disable(Path::kBluetooth, 1);
  assert(actions.fail_closed && !actions.start_wifi &&
         !actions.start_ble_advertising);
}

void TestDisablingBleKeepsWifiSelectionAlive() {
  TransportArbiter arbiter;
  arbiter.Boot(0);
  auto actions = arbiter.Disable(Path::kBluetooth, 1);
  assert(actions.fail_closed && !actions.start_wifi &&
         !actions.start_ble_advertising);
  assert(arbiter.wifi_candidate_active());
}

void TestTargetedHandoffQuiescesOrdinarySelection() {
  TransportArbiter arbiter;
  arbiter.Boot(0, TransportAvailability{false, true});
  arbiter.BleConnected(1);
  arbiter.BleAuthenticated(2);
  assert(arbiter.active_path() == Path::kBluetooth);
  arbiter.QuiesceForTargetedHandoff();
  assert(arbiter.active_path() == Path::kNone);
  assert(!arbiter.wifi_candidate_active());
  assert(!arbiter.ble_advertising());
  assert(!arbiter.ble_connected());
  assert(!arbiter.ble_authentication_permitted());
  assert(arbiter.InstallTargetedOwner(Path::kBluetooth));
  assert(arbiter.active_path() == Path::kBluetooth);
  assert(!arbiter.InstallTargetedOwner(Path::kNone));
}

void TestFreshBootAfterAnActivePathRestartsSelection() {
  TransportArbiter arbiter;
  auto actions = arbiter.Boot(10);
  assert(actions.start_wifi);
  actions = arbiter.WifiAttemptFinished(true, 11);
  assert(arbiter.active_path() == Path::kWifi);
  const auto generation = arbiter.generation();

  actions = arbiter.Boot(20, TransportAvailability{true, true});
  assert(actions.start_wifi && !actions.start_ble_advertising);
  assert(arbiter.active_path() == Path::kNone);
  assert(arbiter.wifi_candidate_active());
  assert(arbiter.generation() > generation);
}

}  // namespace

int main() {
  TestWifiWinsPreferenceWindow();
  TestBleStartsAfterPreferenceDeadline();
  TestWifiFailureReleasesWaitingBleCandidate();
  TestThreeBleFailuresForceWifiAttempt();
  TestActiveLossStartsFreshDisarmedSelection();
  TestInvalidOrLosingEventsCannotReplaceOwner();
  TestIdleBleAdvertisingPeriodicallyRetriesWifi();
  TestFastWifiRetryStillAllowsFullBleAdvertisingWindow();
  TestWifiOnlyNeverRequestsBle();
  TestBleOnlyStartsImmediatelyAndNeverRequestsWifi();
  TestBothUnavailableFailsClosedWithoutRadioAction();
  TestDisablingBleKeepsWifiSelectionAlive();
  TestTargetedHandoffQuiescesOrdinarySelection();
  TestFreshBootAfterAnActivePathRestartsSelection();
  std::puts("transport_arbiter_test: ok");
  return 0;
}
