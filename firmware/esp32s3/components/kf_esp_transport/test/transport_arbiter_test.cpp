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
  actions = arbiter.Poll(keyferry::protocol::kBleWifiPreferenceMs + 249);
  assert(!actions.start_wifi);
  actions = arbiter.Poll(keyferry::protocol::kBleWifiPreferenceMs + 250);
  assert(!actions.stop_ble && actions.start_wifi);
  assert(arbiter.wifi_candidate_active());
  assert(arbiter.ble_advertising());
}

void TestFastWifiRetryStillAllowsFullBleAdvertisingWindow() {
  TransportArbiter arbiter;
  arbiter.Boot(0);
  arbiter.Poll(keyferry::protocol::kBleAdvertisingDelayMs);
  arbiter.Poll(keyferry::protocol::kBleWifiPreferenceMs);
  auto actions = arbiter.Poll(keyferry::protocol::kBleWifiPreferenceMs + 250);
  assert(!actions.stop_ble && actions.start_wifi);

  const auto wifi_failed_ms = keyferry::protocol::kBleWifiPreferenceMs + 251;
  actions = arbiter.WifiAttemptFinished(false, wifi_failed_ms);
  assert(!actions.start_ble_advertising);
  assert(arbiter.ble_advertising());
  actions = arbiter.Poll(wifi_failed_ms + 499);
  assert(!actions.start_wifi);
  actions = arbiter.Poll(wifi_failed_ms + 500);
  assert(!actions.stop_ble && actions.start_wifi);
}

void TestWifiOnlyNeverRequestsBle() {
  TransportArbiter arbiter;
  auto actions = arbiter.Boot(0, TransportAvailability{true, false});
  assert(actions.start_wifi && !actions.start_ble_advertising);
  actions = arbiter.WifiAttemptFinished(false, 100);
  assert(actions.fail_closed && !actions.start_wifi &&
         !actions.start_ble_advertising);
  actions = arbiter.Poll(349);
  assert(!actions.start_wifi && !actions.start_ble_advertising);
  actions = arbiter.Poll(350);
  assert(actions.start_wifi && !actions.start_ble_advertising);
  actions = arbiter.Poll(351);
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
  assert(!actions.fail_closed && !actions.start_wifi &&
         !actions.start_ble_advertising);
}

void TestDisablingBleKeepsWifiSelectionAlive() {
  TransportArbiter arbiter;
  arbiter.Boot(0);
  auto actions = arbiter.Disable(Path::kBluetooth, 1);
  assert(!actions.fail_closed && !actions.start_wifi &&
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

void AssertNoActions(const keyferry::transport::ArbitrationActions& actions) {
  assert(!actions.start_wifi && !actions.cancel_wifi &&
         !actions.start_ble_advertising && !actions.stop_ble &&
         !actions.start_ble_authentication && !actions.fail_closed);
}

void TestUnusedCarrierCannotRevokeEitherHolder() {
  for (const auto owner : {Path::kWifi, Path::kBluetooth}) {
    TransportArbiter arbiter;
    arbiter.Boot(0);
    arbiter.QuiesceForTargetedHandoff();
    assert(arbiter.InstallTargetedOwner(owner));
    const auto generation = arbiter.generation();
    const auto other = owner == Path::kWifi ? Path::kBluetooth : Path::kWifi;
    assert(!arbiter.InstallTargetedOwner(other));
    for (std::uint64_t now = 1; now < 180000; now += 1000) {
      AssertNoActions(arbiter.Disable(other, now));
      AssertNoActions(arbiter.Poll(now));
      AssertNoActions(arbiter.WifiAttemptFinished(true, now));
      AssertNoActions(arbiter.BleConnected(now));
      AssertNoActions(arbiter.BleAuthenticated(now));
      AssertNoActions(arbiter.BleCandidateFailed(now));
      assert(arbiter.active_path() == owner && arbiter.generation() == generation);
    }
    const auto actions = arbiter.ActiveTransportLost(180000);
    assert(actions.fail_closed && arbiter.active_path() == Path::kNone);
    assert(arbiter.generation() == generation + 1);
  }
}

void TestVerifiedWifiGetsItsFullAuthenticationBudget() {
  TransportArbiter arbiter;
  arbiter.Boot(0);
  arbiter.WifiTlsVerified(14990);
  auto actions = arbiter.Poll(15000);
  assert(!actions.cancel_wifi);
  actions = arbiter.Poll(34989);
  assert(!actions.cancel_wifi);
  actions = arbiter.Poll(34990);
  assert(actions.cancel_wifi);
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
  TestUnusedCarrierCannotRevokeEitherHolder();
  TestVerifiedWifiGetsItsFullAuthenticationBudget();
  std::puts("transport_arbiter_test: ok");
  return 0;
}
