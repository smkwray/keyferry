#include "idf_transport_test_stubs.h"
#include <cassert>
#include <cstdio>

#include "keyferry/ble_tls_link.h"
#include "keyferry/gateway_handoff.h"
#include "keyferry/roaming_config.h"
#include "roaming_profile.h"
#include "keyferry/wifi_attempt_diagnostics.h"
// Observe private state without adding a test-only production API. All state
// transitions below execute the actual production Run/Poll/Service methods.
#define private public
#include "keyferry/esp_transport.h"
#undef private
#include "../src/esp_transport.cpp"

namespace idf_test {
inline keyferry::ble::PeripheralEvents ble_events{};
inline bool ble_synchronized = true;
inline bool wrong_tls_identity = false;

std::array<std::uint8_t, 16> Installation(unsigned controller) {
  std::array<std::uint8_t, 16> id{};
  id.fill(static_cast<std::uint8_t>(controller + 1));
  return id;
}

void Reset() {
  now = 0; stop_at = 200000; tls_elapsed = 0;
  advertised = discovery_reads = wifi_disconnects = ble_stops = ble_starts = 0;
  reachable = {true, true, true}; failed = {};
  connections.clear(); tick = {}; connected = {}; event_bits = 0;
  ble_events = {}; ble_synchronized = true; wrong_tls_identity = false;
}

std::vector<std::uint8_t> Wire(keyferry::protocol::MessageType type,
                              std::uint32_t sequence,
                              const std::vector<std::uint8_t>& payload) {
  std::array<std::uint8_t, keyferry::endpoint::kMaxWireFrame> wire{};
  std::size_t length = 0;
  assert(keyferry::protocol::EncodeWireFrame(1, 0, static_cast<std::uint8_t>(type),
      0, sequence, payload.data(), payload.size(), wire.data(), wire.size(),
      &length) == keyferry::protocol::CodecError::kOk);
  return {wire.begin(), wire.begin() + length};
}

void Queue(esp_tls_t* tls, keyferry::protocol::MessageType type,
           std::uint32_t sequence, const std::vector<std::uint8_t>& payload) {
  const auto wire = Wire(type, sequence, payload);
  tls->incoming.insert(tls->incoming.end(), wire.begin(), wire.end());
}

void Authenticate(esp_tls_t* tls) {
  std::vector<std::uint8_t> challenge(66, 0x66);
  const auto id = Installation(tls->ssl.controller);
  std::copy(id.begin(), id.end(), challenge.begin());
  challenge[64] = 1; challenge[65] = 0;
  Queue(tls, keyferry::protocol::MessageType::kAuthChallenge, 0, challenge);
  std::vector<std::uint8_t> ready(34, 0);
  std::fill_n(ready.begin(), 16, static_cast<std::uint8_t>(tls->ssl.controller + 10));
  ready[16] = 1; ready[18] = 1;
  ready[22] = 0xC8; ready[23] = 0xAF; // 45 s lease
  ready[26] = 0x10; ready[27] = 0x27; // 10 s renew
  ready[30] = 0xF4; ready[31] = 1; // 500 ms command bound
  Queue(tls, keyferry::protocol::MessageType::kSessionReady, 1, ready);
}
}

namespace keyferry::ble {
PeripheralInitialization IdfBlePeripheral::Initialize() { return {true, PeripheralStage::kHostSync, 0}; }
bool IdfBlePeripheral::StartAdvertising() { ++idf_test::ble_starts; return true; }
PeripheralEvents IdfBlePeripheral::Poll(std::uint64_t) { return idf_test::ble_events; }
void IdfBlePeripheral::Stop() { ++idf_test::ble_stops; }
void IdfBlePeripheral::Disconnect() {}
bool IdfBlePeripheral::ready(std::uint32_t) const { return true; }
bool IdfBlePeripheral::can_send(std::uint32_t) const { return true; }
PeripheralStatus IdfBlePeripheral::status() const {
  PeripheralStatus status{}; status.synchronized = idf_test::ble_synchronized; return status;
}
}

namespace keyferry::transport {
BleTlsLink::BleTlsLink(const RuntimeConfig& config, ble::IdfBlePeripheral& peripheral)
    : config_(config), peripheral_(peripheral) {}
BleTlsLink::~BleTlsLink() = default;
bool BleTlsLink::Start(std::uint32_t, std::uint64_t) { return true; }
BleTlsHandshake BleTlsLink::HandshakeStep(std::uint64_t, endpoint::TlsObservation*, config::RoamingPeerAuthorization*) { return BleTlsHandshake::kWantIo; }
int BleTlsLink::Read(std::uint8_t*, std::size_t) { return MBEDTLS_ERR_SSL_WANT_READ; }
int BleTlsLink::Write(const std::uint8_t*, std::size_t n) { return static_cast<int>(n); }
bool BleTlsLink::PollHealthy(std::uint64_t, bool) { return true; }
void BleTlsLink::Close() { established_ = false; }
bool VerifyMbedTlsPeer(mbedtls_ssl_context*, const endpoint::TlsClientPolicy&,
                       endpoint::TlsObservation*) { return false; }
bool VerifyMbedTlsRoamingPeer(mbedtls_ssl_context* ssl,
    const config::RoamingEndpointConfig&, const config::RecoverySecret&,
    config::RoamingPolicyCrypto&, endpoint::TlsObservation* observation,
    config::RoamingPeerAuthorization* authorization,
    config::RoamingPolicyVerificationWorkspace*) {
  *observation = {endpoint::kTls12Version, endpoint::kRequiredCipherSuite,
                 endpoint::PeerKeyAlgorithm::kEcdsaP256, {}};
  observation->peer_spki_sha256.fill(0x66);
  authorization->installation_id = idf_test::Installation(
      ssl->controller + (idf_test::wrong_tls_identity ? 1 : 0));
  authorization->link_secret.fill(0x66);
  return true;
}
}

namespace keyferry::discovery {
bool ReceiveRoamingBeacon(esp_netif_t*, std::uint16_t port, std::uint32_t, HostSelection* out) {
  ++idf_test::discovery_reads;
  for (unsigned offset = 0; offset < 3; ++offset) {
    const auto candidate = (idf_test::advertised + offset) % 3;
    if (!idf_test::reachable[candidate]) continue;
    *out = {idf_test::Installation(candidate), {192, 0, 2,
        static_cast<std::uint8_t>(candidate + 1)}, port, AddressSource::kBeacon};
    return true;
  }
  return false;
}
bool ReceiveKnownHostBeacon(esp_netif_t*, const PairedHostView*, std::size_t,
                            std::uint32_t, HostSelection*) { return false; }
}

namespace {
using keyferry::protocol::MessageType;
using keyferry::transport::EspTransport;
using keyferry::transport::Path;

class Crypto final : public keyferry::config::RoamingPolicyCrypto {
 public:
  bool Sha256(const std::uint8_t*, std::size_t, std::uint8_t out[32]) override { std::memset(out, 0x66, 32); return true; }
  bool HkdfSha256(const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t,
                  const std::uint8_t*, std::size_t, std::uint8_t out[32]) override { std::memset(out, 0x66, 32); return true; }
  bool HmacSha256(const std::uint8_t[32], const std::uint8_t*, std::size_t,
                  std::uint8_t out[32]) override { std::memset(out, 0x66, 32); return true; }
};

keyferry::transport::RuntimeConfig Config() {
  static keyferry::config::RoamingEndpointConfig policy;
  static keyferry::config::RecoverySecret secret;
  static keyferry::config::RoamingPolicyVerificationWorkspace workspace;
  static Crypto crypto;
  static std::array<char, 80> name{};
  static const std::uint8_t ssid[]{'t'}, password[]{'1','2','3','4','5','6','7','8'};
  policy = {}; policy.device_id.fill(0x20); policy.owner_id.fill(0x10);
  policy.owner_ca_sha256.fill(0x66); policy.epoch = policy.policy_sequence = 1;
  policy.policy_hash.fill(0x66); policy.policy_auth_tag.fill(0x66);
  policy.owner_ca_length = 64; policy.owner_ca_der[0] = 0x30; secret.fill(0x66);
  // Reuse the exact device-scoped server-name producer.
  keyferry::roaming::DeviceGatewayName gateway_name{};
  assert(keyferry::roaming::BuildDeviceGatewayName(policy.device_id, &gateway_name));
  std::copy(gateway_name.begin(), gateway_name.end(), name.begin());
  keyferry::transport::RuntimeConfig config{};
  config.authority_mode = keyferry::transport::AuthorityMode::kOwnerRoaming;
  config.wifi_configured = true;
  config.wifi = {ssid, sizeof(ssid), password, sizeof(password), keyferry::endpoint::WifiAuth::kWpa2Personal, false};
  config.tls.server_name = name.data(); config.tls.server_name_length = keyferry::roaming::kDeviceGatewayNameBytes;
  config.tls.port = keyferry::protocol::kRoamingDeviceTlsPort;
  config.ca_certificate_der = policy.owner_ca_der.data(); config.ca_certificate_der_length = policy.owner_ca_length;
  config.device_id = policy.device_id; config.roaming_policy = &policy;
  config.roaming_recovery_secret = &secret; config.roaming_crypto = &crypto;
  config.roaming_verification_workspace = &workspace;
  config.wifi_connect_timeout_ms = 15000; config.discovery_timeout_ms = 1500;
  config.tls_connect_timeout_ms = 15000;
  assert(keyferry::transport::ValidateRuntimeConfig(config));
  return config;
}

class Runtime final : public keyferry::transport::Delegate {
 public:
  unsigned faults = 0, authentications = 0, executions = 0, releases = 0;
  bool armed = false, in_flight = false;
  void FailClosed(std::uint64_t) override { ++faults; armed = in_flight = false; ++releases; }
  bool SessionAuthenticated(std::uint64_t, const keyferry::endpoint::SessionReady&) override { ++authentications; return true; }
  bool CommandScopedArm(std::uint64_t, std::uint32_t) override { armed = true; return true; }
  bool Disarm(std::uint64_t) override { armed = in_flight = false; ++releases; return true; }
  bool DisarmComplete(std::uint64_t) override { return true; }
  bool AuthenticatedFrame(std::uint64_t, const keyferry::protocol::DecodedFrame&) override { ++executions; in_flight = true; return true; }
  bool UsbReady() override { return true; }
  bool Service(std::uint64_t) override { return true; }
};

void Run(EspTransport& transport) {
  try { transport.Run(); assert(false); } catch (const idf_test::Stop&) {}
}

void TestHealthyHolderWithCompetingControllers(unsigned count) {
  idf_test::Reset(); idf_test::reachable[2] = count == 3;
  Runtime runtime; EspTransport transport(Config(), runtime, 0);
  idf_test::connected = idf_test::Authenticate;
  bool armed = false, started = false, checked = false;
  unsigned stable_faults = 0; std::uint64_t epoch = 0;
  idf_test::tick = [&] {
    if (transport.active_path() != Path::kWifi) return;
    if (!armed) {
      stable_faults = runtime.faults; epoch = transport.session_.epoch(); armed = true;
      idf_test::Queue(idf_test::connections[0].get(), MessageType::kArm, 2, {1,0,0,0,0});
      return;
    }
    if (runtime.armed && !started) {
      keyferry::protocol::GatewayHandoffRequest request{};
      request.operation = keyferry::protocol::GatewayHandoffOperation::kStart;
      keyferry::protocol::GatewayHandoffStatusPayload status{}; bool defer = true;
      assert(transport.HandleGatewayHandoff(epoch, request, &status, &defer));
      assert(status.status == keyferry::protocol::GatewayHandoffStatus::kBusy && !defer);
      started = true;
      idf_test::Queue(idf_test::connections[0].get(), MessageType::kCommand, 3, {1});
    }
    idf_test::advertised = (idf_test::advertised + 1) % count;
    // The exact original trigger, persistently reported by an unused carrier.
    if (runtime.in_flight) {
      idf_test::ble_synchronized = false;
      idf_test::ble_events.fault = keyferry::ble::Fault::kBadState;
    }
    // Another controller restarts; its connection availability is irrelevant.
    idf_test::reachable[1] = idf_test::now % 1000 < 500;
    if (runtime.in_flight) {
      assert(runtime.faults == stable_faults && runtime.armed);
      assert(transport.session_.epoch() == epoch && transport.session_.authenticated());
      assert(idf_test::connections.size() == 1 && !idf_test::connections[0]->closed);
      assert(idf_test::discovery_reads == 1 && idf_test::wifi_disconnects == 0);
      keyferry::protocol::GatewayHandoffRequest request{};
      request.operation = keyferry::protocol::GatewayHandoffOperation::kStart;
      keyferry::protocol::GatewayHandoffStatusPayload status{}; bool defer = true;
      assert(transport.HandleGatewayHandoff(epoch, request, &status, &defer));
      assert(status.status == keyferry::protocol::GatewayHandoffStatus::kBusy && !defer);
      assert(!transport.gateway_handoff_.active()); checked = true;
    }
  };
  Run(transport);
  assert(checked && runtime.executions == 1 && runtime.authentications == 1);
  assert(transport.active_path() == Path::kWifi);
  transport.CloseCurrentTls();
}

void TestRealFailureTriesLastGoodThenFailsOverWithoutReplay() {
  idf_test::Reset(); Runtime runtime; EspTransport transport(Config(), runtime, 0);
  idf_test::advertised = 1; idf_test::connected = idf_test::Authenticate;
  bool armed = false, started = false, lost = false, stable = false;
  idf_test::tick = [&] {
    if (!armed && transport.active_path() == Path::kWifi) {
      armed = true;
      idf_test::Queue(idf_test::connections[0].get(), MessageType::kArm, 2, {1,0,0,0,0});
    } else if (runtime.armed && !started) {
      started = true;
      idf_test::Queue(idf_test::connections[0].get(), MessageType::kCommand, 3, {1});
    } else if (!lost && runtime.in_flight) {
      lost = true; idf_test::advertised = 2;
      idf_test::failed[1] = true; idf_test::reachable[1] = false;
    } else if (lost && runtime.authentications == 2) {
      assert(!runtime.armed && !runtime.in_flight && runtime.executions == 1);
      assert(idf_test::connections.size() == 3);
      assert(idf_test::connections[1]->ssl.controller == 1); // retained holder
      assert(idf_test::connections[2]->ssl.controller == 2); // discovery fallback
      assert(transport.active_host_id_ == idf_test::Installation(2));
      stable = true; idf_test::stop_at = idf_test::now;
    }
  };
  Run(transport); assert(stable); transport.CloseCurrentTls();
}

void TestHandoffWaitsForCorrelatedNeutral() {
  idf_test::Reset(); Runtime runtime; EspTransport transport(Config(), runtime, 0);
  idf_test::connected = idf_test::Authenticate; idf_test::stop_at = 100;
  Run(transport);
  const auto epoch = transport.session_.epoch();
  assert(transport.CommandScopedArm(epoch, 3));
  std::vector<std::uint8_t> result(22, 0);
  result[16] = static_cast<std::uint8_t>(keyferry::protocol::ResultCode::kEmitted);
  result[17] = 3; // declared keyboard + pointer
  result[18] = 1; // keyboard only; pointer release is unconfirmed
  auto wire = idf_test::Wire(MessageType::kInputCommandResultV2, 3, result);
  assert(transport.SendTls(wire.data(), wire.size()));
  assert(transport.input_arm_sequence_ == 3);
  result[18] = 3;
  wire = idf_test::Wire(MessageType::kInputCommandResultV2, 2, result);
  assert(transport.SendTls(wire.data(), wire.size()));
  assert(transport.input_arm_sequence_ == 3);
  wire = idf_test::Wire(MessageType::kInputCommandResultV2, 3, result);
  assert(transport.SendTls(wire.data(), wire.size()));
  assert(transport.input_arm_sequence_ == 0);

  // The same production handoff entry point is still available after neutral
  // completion, with the existing fresh proof and exact target binding.
  std::array<std::uint8_t, 32> nonce{}; nonce.fill(0x77);
  std::array<std::uint8_t, keyferry::protocol::kRoamingRouteProofResponseBytes> proof{};
  const auto target = idf_test::Installation(1);
  assert(transport.BuildRouteProof(epoch, target.data(), nonce.data(), proof.data()));
  keyferry::protocol::GatewayHandoffRequest request{};
  request.operation = keyferry::protocol::GatewayHandoffOperation::kStart;
  request.transaction_id.fill(0x11); request.target_installation_id = target;
  request.readiness_nonce.fill(0x22); request.proof_digest = transport.route_proof_digest_;
  request.target_ipv4 = {192,0,2,2}; request.target_port = transport.config_.tls.port;
  request.target_valid_ms = keyferry::protocol::kRoamingGatewayHandoffTargetValidMs;
  request.recovery_ms = keyferry::protocol::kRoamingGatewayHandoffRecoveryMs;
  keyferry::protocol::GatewayHandoffStatusPayload status{}; bool defer = false;
  assert(transport.HandleGatewayHandoff(epoch, request, &status, &defer));
  assert(defer && transport.gateway_handoff_.active());
  assert(!idf_test::connections[0]->closed); // waits for correlated START reply
  transport.CloseCurrentTls();
}

void TestTlsDeadlineAndIdentityBinding() {
  idf_test::Reset(); idf_test::tls_elapsed = 14990;
  Runtime runtime; EspTransport transport(Config(), runtime, 0);
  idf_test::connected = idf_test::Authenticate;
  idf_test::stop_at = 45000;
  Run(transport);
  assert(runtime.authentications == 1 && transport.session_.authenticated());
  assert(idf_test::connections.size() == 1);
  transport.CloseCurrentTls();

  idf_test::Reset(); idf_test::wrong_tls_identity = true; idf_test::stop_at = 50;
  Runtime rejected; EspTransport mismatch(Config(), rejected, 0);
  Run(mismatch);
  assert(rejected.authentications == 0 && !mismatch.session_.authenticated());
  assert(mismatch.diagnostics().wifi_attempt.last_wifi_reject_reason ==
         keyferry::protocol::WifiRejectReason::kBeaconTlsIdentityMismatch);
  mismatch.CloseCurrentTls();
}
}

int main() {
  TestHealthyHolderWithCompetingControllers(2);
  TestHealthyHolderWithCompetingControllers(3);
  TestRealFailureTriesLastGoodThenFailsOverWithoutReplay();
  TestHandoffWaitsForCorrelatedNeutral();
  TestTlsDeadlineAndIdentityBinding();
  std::puts("esp_transport_test: ok (production Run; carriers/crypto simulated)");
}
