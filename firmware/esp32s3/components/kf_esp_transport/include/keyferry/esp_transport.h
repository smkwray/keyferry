#pragma once

#include <atomic>

#include "keyferry/ble_tls_link.h"
#include "keyferry/gateway_handoff.h"
#include "keyferry/idf_ble_transport.h"
#include "keyferry/transport_arbiter.h"
#include "keyferry/transport_runtime_config.h"

namespace keyferry::transport {

enum class WifiStage : std::uint8_t {
  kOff = 0,
  kNetif,
  kEventLoop,
  kStationNetif,
  kEventGroup,
  kEventHandlers,
  kDriver,
  kStorage,
  kMode,
  kConfig,
  kStarted,
  kConnecting,
  kGotIp,
  kTls,
  kAuthenticated,
  kDisconnected,
};

struct TransportDiagnostics {
  bool running = false;
  bool wifi_available = false;
  bool ble_available = false;
  WifiStage wifi_stage = WifiStage::kOff;
  std::int32_t wifi_error = 0;
  std::int32_t nvs_error = 0;
  ble::PeripheralStatus ble{};
};

class Delegate {
 public:
  virtual ~Delegate() = default;
  virtual void FailClosed(std::uint64_t epoch) = 0;
  virtual bool SessionAuthenticated(std::uint64_t epoch,
                                    const endpoint::SessionReady& ready) = 0;
  virtual bool CommandScopedArm(std::uint64_t epoch,
                                std::uint32_t next_command_sequence) = 0;
  virtual bool Disarm(std::uint64_t epoch) = 0;
  virtual bool DisarmComplete(std::uint64_t epoch) = 0;
  virtual bool AuthenticatedFrame(std::uint64_t epoch,
                                  const protocol::DecodedFrame& frame) = 0;
  virtual bool UsbReady() = 0;
  // Called from the sole TLS owner task between non-blocking reads. Implementations use it to
  // drain bounded command-result output without sharing the TLS context across tasks.
  virtual bool Service(std::uint64_t epoch) = 0;
};

// Sole endpoint-session owner. Wi-Fi and BLE are byte transports beneath this manager; neither
// transport owns command state or can replace an authenticated path.
class EspTransport final : public endpoint::Effects {
 public:
  EspTransport(const RuntimeConfig& config, Delegate& delegate,
               std::int32_t nvs_result,
               endpoint::FirmwareIdentity firmware_identity = {});

  void BootOffline();
  void Run();
  // Queues one restart for the sole transport-owner task. It never performs
  // Wi-Fi, BLE, TLS, or endpoint work on the caller's thread.
  bool RequestRestart();
  [[nodiscard]] Path active_path() const {
    return published_path_.load(std::memory_order_acquire);
  }
  [[nodiscard]] TransportDiagnostics diagnostics() const;

  void FailClosed(std::uint64_t epoch) override;
  bool FillRandom(std::uint8_t* output, std::size_t length) override;
  bool HmacSha256(const std::uint8_t host_id[16], const std::uint8_t* input,
                  std::size_t input_length, std::uint8_t output[32]) override;
  bool BuildRouteProof(
      std::uint64_t epoch,
      const std::uint8_t controller_installation_id[16],
      const std::uint8_t controller_nonce[32],
      std::uint8_t output[protocol::kRoamingRouteProofResponseBytes]) override;
  bool HandleGatewayHandoff(
      std::uint64_t epoch,
      const protocol::GatewayHandoffRequest& request,
      protocol::GatewayHandoffStatusPayload* status,
      bool* defer_reply) override;
  bool ServiceGatewayHandoff(
      std::uint64_t epoch,
      protocol::GatewayHandoffStatusPayload* status,
      bool* reply_ready) override;
  void GatewayHandoffReplySent(
      std::uint64_t epoch,
      protocol::GatewayHandoffOperation operation) override;
  bool SendTls(const std::uint8_t* data, std::size_t length) override;
  bool SessionAuthenticated(std::uint64_t epoch,
                            const endpoint::SessionReady& ready) override;
  bool CommandScopedArm(std::uint64_t epoch,
                        std::uint32_t next_command_sequence) override;
  bool Disarm(std::uint64_t epoch) override;
  bool DisarmComplete(std::uint64_t epoch) override;
  bool AuthenticatedFrame(std::uint64_t epoch,
                          const protocol::DecodedFrame& frame) override;

 private:
  bool InitializeStation();
  bool StationReadyForTls() const;
  bool StartWifiCandidate();
  bool PollWifiCandidate(std::uint64_t now_ms);
  bool ResolveHostAddress(std::uint32_t timeout_ms);
  bool StartGatewayHandoffCandidate(std::uint64_t now_ms);
  void ServiceGatewayHandoffTransport(std::uint64_t now_ms);
  void GatewayHandoffCandidateFailed(std::uint64_t now_ms,
                                     protocol::GatewayHandoffReason reason);
  void FailClosedGatewayHandoff();
  void BeginCommittedGatewayHandoff(std::uint64_t now_ms);
  bool ConnectAndVerifyWifiTls(std::uint32_t timeout_ms,
                               endpoint::TlsObservation* observation,
                               config::RoamingPeerAuthorization* authorization);
  bool BeginEndpointTls(
      const endpoint::TlsObservation& observation,
      const config::RoamingPeerAuthorization& authorization);
  bool StartBleTls(std::uint64_t now_ms);
  bool ServiceCurrentTls(std::uint64_t now_ms);
  bool ServiceEndpointRead(std::uint64_t now_ms);
  void PollBle(std::uint64_t now_ms);
  void ApplyActions(const ArbitrationActions& actions, std::uint64_t now_ms);
  void PromoteAuthenticatedCandidate(std::uint64_t now_ms);
  void CandidateFailed(std::uint64_t now_ms);
  void ActiveTransportLost(std::uint64_t now_ms);
  void RestartRuntime(std::uint64_t now_ms);
  void CloseCurrentTls();
  void ClearPeerAuthorization();
  std::uint32_t WifiPreferenceRemainingMs(std::uint64_t now_ms) const;
  void RecordWifi(WifiStage stage, std::int32_t error = 0);

  RuntimeConfig config_;
  Delegate& delegate_;
  endpoint::EndpointSession session_;
  ble::IdfBlePeripheral ble_peripheral_;
  BleTlsLink ble_tls_;
  TransportArbiter arbiter_;
  void* station_netif_{nullptr};
  void* wifi_events_{nullptr};
  void* tls_{nullptr};
  std::array<char, kIpv4TextCapacity> resolved_host_ipv4_{};
  std::size_t resolved_host_ipv4_length_{0};
  endpoint::TlsClientPolicy accepted_tls_policy_{};
  std::array<std::uint8_t, 16> active_host_id_{};
  std::array<std::uint8_t, 32> active_link_secret_{};
  std::array<std::uint8_t, 16> advertised_installation_id_{};
  std::array<std::uint8_t, 16> device_boot_nonce_{};
  std::array<std::uint8_t, 16> active_session_id_{};
  GatewayHandoffManager gateway_handoff_{};
  std::array<std::uint8_t, 16> route_proof_controller_id_{};
  std::array<std::uint8_t, 16> route_proof_session_id_{};
  std::array<std::uint8_t, 32> route_proof_digest_{};
  std::uint64_t route_proof_expires_ms_{0};
  std::array<std::uint8_t, 4> handoff_target_ipv4_{};
  std::uint16_t handoff_target_port_{0};
  std::array<std::uint8_t, 16> handoff_candidate_installation_id_{};
  std::array<char, kIpv4TextCapacity> handoff_previous_ipv4_{};
  std::size_t handoff_previous_ipv4_length_{0};
  std::uint16_t handoff_previous_port_{0};
  Path handoff_previous_path_{Path::kNone};
  std::uint64_t handoff_next_attempt_ms_{0};
  std::uint8_t handoff_attempts_{0};
  bool handoff_start_committed_{false};
  bool handoff_fail_closed_{false};
  std::uint64_t selection_started_ms_{0};
  std::uint64_t candidate_started_ms_{0};
  std::uint64_t last_route_proof_ms_{0};
  std::uint32_t ble_generation_{0};
  bool station_initialized_{false};
  bool wifi_connecting_{false};
  bool ble_authentication_requested_{false};
  bool ble_handshake_active_{false};
  bool endpoint_tls_started_{false};
  bool endpoint_authenticated_{false};
  std::int32_t nvs_result_{0};
  Path candidate_path_{Path::kNone};
  std::atomic<Path> published_path_{Path::kNone};
  std::atomic_bool running_{false};
  std::atomic_bool wifi_available_{false};
  std::atomic_bool ble_available_{false};
  std::atomic<WifiStage> wifi_stage_{WifiStage::kOff};
  std::atomic<std::int32_t> wifi_error_{0};
  std::atomic_bool restart_requested_{false};
};

}  // namespace keyferry::transport
