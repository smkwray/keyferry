#include "keyferry/wifi_attempt_diagnostics.h"
#include <cassert>
#include <cstdio>

int main() {
  using keyferry::protocol::WifiRejectReason;
  keyferry::transport::WifiAttemptDiagnostics diagnostic;
  assert(diagnostic.completed().attempt_count == 0);
  diagnostic.Start(100);
  diagnostic.TlsVerified(5100);
  diagnostic.IdentityCompared(true);
  diagnostic.Reject(WifiRejectReason::kWifiPreferenceExpired);
  diagnostic.Reject(WifiRejectReason::kOther);
  diagnostic.Close(15100);
  const auto failed = diagnostic.completed();
  assert(failed.attempt_count == 1 && failed.elapsed_to_tls_ms == 5000);
  assert(failed.elapsed_to_close_ms == 15000 && failed.beacon_tls_identity_equal);
  assert(failed.last_wifi_reject_reason == WifiRejectReason::kWifiPreferenceExpired);
  diagnostic.Start(20000);
  assert(diagnostic.completed().attempt_count == 1); // reconnect retains last close
  diagnostic.TlsVerified(22000);
  diagnostic.IdentityCompared(false);
  diagnostic.Reject(WifiRejectReason::kBeaconTlsIdentityMismatch);
  diagnostic.Close(22001);
  assert(diagnostic.completed().attempt_count == 2);
  assert(!diagnostic.completed().beacon_tls_identity_equal);
  diagnostic.Close(23000); // duplicate cleanup cannot overwrite timing
  assert(diagnostic.completed().elapsed_to_close_ms == 2001);
  diagnostic.Start(30000);
  diagnostic.Reject(WifiRejectReason::kDiscoveryTimeout);
  diagnostic.Close(31000);
  assert(!diagnostic.completed().tls_verified && !diagnostic.completed().identity_checked);
  assert(diagnostic.completed().elapsed_to_tls_ms == 0);
  diagnostic.Start(0);
  diagnostic.Close(0x100000000ULL);
  assert(diagnostic.completed().elapsed_to_close_ms == 0xFFFFFFFFU);
  std::puts("wifi_attempt_diagnostics_test: ok");
}
