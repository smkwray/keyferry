#include "keyferry/esp_transport.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "esp_tls_errors.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "keyferry/esp_discovery.h"
#include "mbedtls/md.h"
#include "keyferry/mbedtls_peer_policy.h"
#include "mbedtls/ssl.h"

namespace keyferry::transport {
namespace {

constexpr char kTag[] = "kf_transport";
constexpr EventBits_t kStationGotIp = BIT0;
constexpr EventBits_t kStationDisconnected = BIT1;
constexpr std::array<int, 2> kCipherSuites{
    static_cast<int>(endpoint::kRequiredCipherSuite), 0};
constexpr int kTcpKeepAliveIdleSeconds = 10;
constexpr int kTcpKeepAliveIntervalSeconds = 3;
constexpr int kTcpKeepAliveProbeCount = 3;
constexpr std::int64_t kTlsResultWriteTimeoutUs = 250LL * 1000;
constexpr std::uint32_t kManagerPollMs = 10;
constexpr std::uint32_t kRouteProofMinimumIntervalMs = 100;
constexpr std::uint32_t kGatewayHandoffAttemptTimeoutMs = 2500;
constexpr std::uint32_t kGatewayHandoffRetryGapMs = 250;
constexpr std::uint8_t kGatewayHandoffMaximumAttempts = 2;

void SecureClear(void* data, std::size_t length) {
  volatile std::uint8_t* output = static_cast<volatile std::uint8_t*>(data);
  while (length-- != 0) {
    *output++ = 0;
  }
}

bool ConstantTimeEqual(const std::uint8_t* left, const std::uint8_t* right,
                       std::size_t length) {
  std::uint8_t difference = 0;
  for (std::size_t index = 0; index < length; ++index) {
    difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
  }
  return difference == 0;
}

bool AnyNonzero(const std::uint8_t* data, const std::size_t length) {
  std::uint8_t combined = 0;
  for (std::size_t index = 0; index < length; ++index) {
    combined |= data[index];
  }
  return combined != 0;
}

std::uint64_t NowMs() {
  return static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
}

}  // namespace

EspTransport::EspTransport(const RuntimeConfig& config, Delegate& delegate,
                           const std::int32_t nvs_result,
                           const endpoint::FirmwareIdentity firmware_identity)
    : config_(config),
      delegate_(delegate),
      session_(config.device_id, *this, firmware_identity),
      ble_tls_(config, ble_peripheral_),
      nvs_result_(nvs_result) {}

void EspTransport::BootOffline() { session_.Boot(); }

bool EspTransport::RequestRestart() {
  if (!running_.load(std::memory_order_acquire)) {
    return false;
  }
  bool expected = false;
  return restart_requested_.compare_exchange_strong(
      expected, true, std::memory_order_acq_rel);
}

void EspTransport::Run() {
  session_.Boot();
  gateway_handoff_.Boot();
  running_.store(true, std::memory_order_release);
  if (!ValidateRuntimeConfig(config_)) {
    delegate_.FailClosed(session_.epoch());
    running_.store(false, std::memory_order_release);
    ESP_LOGE(kTag, "transport runtime configuration rejected");
    return;
  }
  if (config_.authority_mode == AuthorityMode::kOwnerRoaming &&
      (!FillRandom(device_boot_nonce_.data(), device_boot_nonce_.size()) ||
       !AnyNonzero(device_boot_nonce_.data(), device_boot_nonce_.size()))) {
    delegate_.FailClosed(session_.epoch());
    running_.store(false, std::memory_order_release);
    ESP_LOGE(kTag, "roaming boot nonce generation failed");
    return;
  }

  const bool wifi_available = config_.wifi_configured && InitializeStation();
  wifi_available_.store(wifi_available, std::memory_order_release);
  ble::PeripheralInitialization ble_initialization{};
  if (config_.ble_gateway_allowed && nvs_result_ == ESP_OK) {
    ble_initialization = ble_peripheral_.Initialize();
  }
  ble_available_.store(ble_initialization.ok, std::memory_order_release);
  if (!wifi_available && !ble_initialization.ok) {
    delegate_.FailClosed(session_.epoch());
    running_.store(false, std::memory_order_release);
    ESP_LOGE(kTag,
             "both transports unavailable: wifi_stage=%u wifi_error=%ld "
             "ble_stage=%u ble_error=%ld nvs_error=%ld",
             static_cast<unsigned>(wifi_stage_.load()),
             static_cast<long>(wifi_error_.load()),
             static_cast<unsigned>(ble_initialization.stage),
             static_cast<long>(ble_initialization.error),
             static_cast<long>(nvs_result_));
    return;
  }

  auto now_ms = NowMs();
  selection_started_ms_ = now_ms;
  ApplyActions(arbiter_.Boot(
                   now_ms, {wifi_available, ble_initialization.ok}),
               now_ms);
  while (true) {
    now_ms = NowMs();
    if (restart_requested_.exchange(false, std::memory_order_acq_rel)) {
      RestartRuntime(now_ms);
    }
    PollBle(now_ms);
    gateway_handoff_.Poll(now_ms);
    if (!handoff_fail_closed_ &&
        gateway_handoff_
                .Status(protocol::GatewayHandoffOperation::kQuery, now_ms)
                .phase ==
            protocol::GatewayHandoffPhase::kRecoveryUnavailable) {
      FailClosedGatewayHandoff();
    }
    if (!handoff_fail_closed_) {
      (void)gateway_handoff_.ForgetTerminalIfExpired(now_ms);
    }
    if (handoff_start_committed_) {
      BeginCommittedGatewayHandoff(now_ms);
    }
    if (handoff_fail_closed_) {
      vTaskDelay(pdMS_TO_TICKS(kManagerPollMs));
      continue;
    }
    if (gateway_handoff_.targeting() || gateway_handoff_.restoring()) {
      ServiceGatewayHandoffTransport(now_ms);
      vTaskDelay(pdMS_TO_TICKS(kManagerPollMs));
      continue;
    }
    ApplyActions(arbiter_.Poll(now_ms), now_ms);
    if (wifi_connecting_ && !PollWifiCandidate(now_ms)) {
      CandidateFailed(now_ms);
    }
    if (ble_authentication_requested_ && !ble_handshake_active_ &&
        candidate_path_ == Path::kNone &&
        ble_peripheral_.ready(ble_generation_) && !StartBleTls(now_ms)) {
      CandidateFailed(now_ms);
    }
    if (!ServiceCurrentTls(now_ms)) {
      if (arbiter_.active_path() == Path::kNone) {
        CandidateFailed(now_ms);
      } else {
        ActiveTransportLost(now_ms);
      }
    }
    vTaskDelay(pdMS_TO_TICKS(kManagerPollMs));
  }
}

TransportDiagnostics EspTransport::diagnostics() const {
  return {running_.load(std::memory_order_acquire),
          wifi_available_.load(std::memory_order_acquire),
          ble_available_.load(std::memory_order_acquire),
          wifi_stage_.load(std::memory_order_acquire),
          wifi_error_.load(std::memory_order_acquire), nvs_result_,
          ble_peripheral_.status()};
}

void EspTransport::FailClosed(std::uint64_t epoch) { delegate_.FailClosed(epoch); }

bool EspTransport::FillRandom(std::uint8_t* output, std::size_t length) {
  if (output == nullptr || length == 0) {
    return false;
  }
  esp_fill_random(output, length);
  return true;
}

bool EspTransport::HmacSha256(const std::uint8_t host_id[16], const std::uint8_t* input,
                              std::size_t input_length, std::uint8_t output[32]) {
  if (host_id == nullptr || input == nullptr || output == nullptr || input_length == 0 ||
      !ConstantTimeEqual(host_id, active_host_id_.data(),
                         active_host_id_.size())) {
    return false;
  }
  const mbedtls_md_info_t* sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return sha256 != nullptr &&
         mbedtls_md_hmac(sha256, active_link_secret_.data(),
                         active_link_secret_.size(), input, input_length,
                         output) == 0;
}

bool EspTransport::BuildRouteProof(
    const std::uint64_t epoch,
    const std::uint8_t controller_installation_id[16],
    const std::uint8_t controller_nonce[32],
    std::uint8_t output[protocol::kRoamingRouteProofResponseBytes]) {
  if (output == nullptr) {
    return false;
  }
  std::fill_n(output, protocol::kRoamingRouteProofResponseBytes,
              static_cast<std::uint8_t>(0));
  const auto now_ms = NowMs();
  if (config_.authority_mode != AuthorityMode::kOwnerRoaming ||
      config_.roaming_policy == nullptr ||
      config_.roaming_recovery_secret == nullptr ||
      config_.roaming_crypto == nullptr || controller_installation_id == nullptr ||
      controller_nonce == nullptr || !session_.authenticated() ||
      epoch == 0 || epoch != session_.epoch() ||
      candidate_path_ == Path::kNone ||
      (last_route_proof_ms_ != 0 && now_ms >= last_route_proof_ms_ &&
       now_ms - last_route_proof_ms_ < kRouteProofMinimumIntervalMs)) {
    return false;
  }
  last_route_proof_ms_ = now_ms;
  roaming::RouteProofFields fields{};
  fields.owner_id = config_.roaming_policy->owner_id;
  fields.device_id = config_.device_id;
  fields.epoch = config_.roaming_policy->epoch;
  fields.policy_sequence = config_.roaming_policy->policy_sequence;
  fields.policy_hash = config_.roaming_policy->policy_hash;
  fields.gateway_installation_id = active_host_id_;
  std::copy_n(controller_installation_id,
              fields.controller_installation_id.size(),
              fields.controller_installation_id.begin());
  std::copy_n(controller_nonce, fields.controller_nonce.size(),
              fields.controller_nonce.begin());
  fields.device_boot_nonce = device_boot_nonce_;
  fields.endpoint_session_id = active_session_id_;
  fields.link_path = static_cast<std::uint8_t>(candidate_path_);
  fields.usb_ready = delegate_.UsbReady();
  roaming::RouteProofResponse response{};
  bool built = config::BuildAuthenticatedRouteProof(
      *config_.roaming_policy, *config_.roaming_recovery_secret, fields,
      *config_.roaming_crypto, &response,
      config_.roaming_verification_workspace);
  if (built) {
    std::copy(response.begin(), response.end(), output);
    std::array<std::uint8_t, 32> digest{};
    const mbedtls_md_info_t* sha256 =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (sha256 == nullptr ||
        mbedtls_md(sha256, output,
                   protocol::kRoamingRouteProofResponseBytes,
                   digest.data()) != 0) {
      SecureClear(output, protocol::kRoamingRouteProofResponseBytes);
      built = false;
    } else {
      std::copy_n(controller_installation_id,
                  route_proof_controller_id_.size(),
                  route_proof_controller_id_.begin());
      route_proof_session_id_ = active_session_id_;
      route_proof_digest_ = digest;
      route_proof_expires_ms_ =
          now_ms + protocol::kRoamingRouteProofTtlMs;
    }
    SecureClear(digest.data(), digest.size());
  }
  SecureClear(&fields, sizeof(fields));
  SecureClear(response.data(), response.size());
  return built;
}

bool EspTransport::HandleGatewayHandoff(
    const std::uint64_t epoch,
    const protocol::GatewayHandoffRequest& request,
    protocol::GatewayHandoffStatusPayload* status, bool* defer_reply) {
  if (status == nullptr || defer_reply == nullptr ||
      epoch == 0 || epoch != session_.epoch() || !session_.authenticated()) {
    return false;
  }
  *defer_reply = false;
  const auto now_ms = NowMs();
  gateway_handoff_.Poll(now_ms);
  const auto set_rejection = [&](const protocol::GatewayHandoffStatus code) {
    *status = {};
    status->reply_operation = request.operation;
    status->status = code;
    status->transaction_id = request.transaction_id;
    status->phase = protocol::GatewayHandoffPhase::kNotStarted;
    status->device_boot_nonce = device_boot_nonce_;
    status->current_endpoint_session = active_session_id_;
  };
  const bool proof_fresh = route_proof_expires_ms_ != 0 &&
                           now_ms <= route_proof_expires_ms_ &&
                           route_proof_session_id_ == active_session_id_;

  if (request.operation == protocol::GatewayHandoffOperation::kStart) {
    if (config_.authority_mode != AuthorityMode::kOwnerRoaming ||
        candidate_path_ == Path::kNone ||
        (candidate_path_ == Path::kWifi && resolved_host_ipv4_length_ == 0) ||
        request.target_port != config_.tls.port) {
      set_rejection(protocol::GatewayHandoffStatus::kUnsupported);
      return true;
    }
    if (!proof_fresh ||
        request.target_installation_id != route_proof_controller_id_ ||
        request.proof_digest != route_proof_digest_) {
      set_rejection(protocol::GatewayHandoffStatus::kStaleProof);
      return true;
    }
    const auto started = gateway_handoff_.Start(
        request, active_host_id_, device_boot_nonce_, active_session_id_, now_ms);
    if (started == GatewayHandoffStartResult::kBusy) {
      set_rejection(protocol::GatewayHandoffStatus::kBusy);
      return true;
    }
    if (started == GatewayHandoffStartResult::kInvalid) {
      set_rejection(protocol::GatewayHandoffStatus::kNotReady);
      return true;
    }
    *status = gateway_handoff_.Status(request.operation, now_ms);
    if (started == GatewayHandoffStartResult::kDuplicate) {
      return true;
    }
    handoff_target_ipv4_ = request.target_ipv4;
    handoff_target_port_ = request.target_port;
    handoff_previous_path_ = candidate_path_;
    if (candidate_path_ == Path::kWifi) {
      handoff_previous_ipv4_ = resolved_host_ipv4_;
      handoff_previous_ipv4_length_ = resolved_host_ipv4_length_;
    } else {
      handoff_previous_ipv4_.fill(0);
      handoff_previous_ipv4_length_ = 0;
    }
    handoff_previous_port_ = config_.tls.port;
    route_proof_expires_ms_ = 0;
    route_proof_controller_id_.fill(0);
    route_proof_session_id_.fill(0);
    SecureClear(route_proof_digest_.data(), route_proof_digest_.size());
    if (!delegate_.Disarm(epoch)) {
      gateway_handoff_.ReleaseFailed(now_ms);
      *status = gateway_handoff_.Status(request.operation, now_ms);
      status->status = protocol::GatewayHandoffStatus::kReleaseFailed;
      return true;
    }
    *defer_reply = true;
    return true;
  }

  if (!gateway_handoff_.MatchesTransaction(request.transaction_id)) {
    set_rejection(protocol::GatewayHandoffStatus::kUnknownTransaction);
    status->phase = protocol::GatewayHandoffPhase::kUnknown;
    return true;
  }
  if (request.operation == protocol::GatewayHandoffOperation::kAccept) {
    if (!proof_fresh || route_proof_controller_id_ != active_host_id_ ||
        request.proof_digest != route_proof_digest_ ||
        !gateway_handoff_.InstallTarget(request, route_proof_digest_, now_ms)) {
      *status = gateway_handoff_.Status(request.operation, now_ms);
      status->status = proof_fresh
                           ? protocol::GatewayHandoffStatus::kInvalidTransition
                           : protocol::GatewayHandoffStatus::kStaleProof;
      return true;
    }
    route_proof_expires_ms_ = 0;
    route_proof_controller_id_.fill(0);
    route_proof_session_id_.fill(0);
    SecureClear(route_proof_digest_.data(), route_proof_digest_.size());
    if (!arbiter_.InstallTargetedOwner(candidate_path_)) {
      *status = gateway_handoff_.Status(request.operation, now_ms);
      status->status = protocol::GatewayHandoffStatus::kInvalidTransition;
      return true;
    }
    *status = gateway_handoff_.Status(request.operation, now_ms);
    return true;
  }
  *status = gateway_handoff_.Status(request.operation, now_ms);
  return true;
}

bool EspTransport::ServiceGatewayHandoff(
    const std::uint64_t epoch,
    protocol::GatewayHandoffStatusPayload* status, bool* reply_ready) {
  if (status == nullptr || reply_ready == nullptr ||
      epoch != session_.epoch()) {
    return false;
  }
  const auto now_ms = NowMs();
  gateway_handoff_.Poll(now_ms);
  if (delegate_.DisarmComplete(epoch)) {
    (void)gateway_handoff_.ReleaseCompleted(now_ms);
  }
  *status = gateway_handoff_.Status(
      protocol::GatewayHandoffOperation::kStart, now_ms);
  if (status->phase == protocol::GatewayHandoffPhase::kNotStarted) {
    status->status = protocol::GatewayHandoffStatus::kReleaseFailed;
  }
  *reply_ready = status->phase != protocol::GatewayHandoffPhase::kReleasing;
  return true;
}

void EspTransport::GatewayHandoffReplySent(
    const std::uint64_t epoch,
    const protocol::GatewayHandoffOperation operation) {
  if (epoch == session_.epoch() &&
      operation == protocol::GatewayHandoffOperation::kStart &&
      gateway_handoff_.targeting()) {
    handoff_start_committed_ = true;
  }
}

bool EspTransport::SendTls(const std::uint8_t* data, std::size_t length) {
  if (data == nullptr || length == 0 || candidate_path_ == Path::kNone) {
    return false;
  }
  if (candidate_path_ == Path::kBluetooth) {
    std::size_t offset = 0;
    const auto deadline = NowMs() + protocol::kBleOperationTimeoutMs;
    while (offset < length) {
      const int result = ble_tls_.Write(data + offset, length - offset);
      if (result > 0) {
        offset += static_cast<std::size_t>(result);
      } else if (result == MBEDTLS_ERR_SSL_WANT_READ ||
                 result == MBEDTLS_ERR_SSL_WANT_WRITE) {
        if (NowMs() >= deadline) {
          return false;
        }
        vTaskDelay(pdMS_TO_TICKS(1));
      } else {
        return false;
      }
    }
    return true;
  }
  if (candidate_path_ != Path::kWifi || tls_ == nullptr) {
    return false;
  }
  std::size_t offset = 0;
  const std::int64_t deadline = esp_timer_get_time() + kTlsResultWriteTimeoutUs;
  while (offset < length) {
    const ssize_t result = esp_tls_conn_write(static_cast<esp_tls_t*>(tls_), data + offset,
                                              length - offset);
    if (result > 0) {
      offset += static_cast<std::size_t>(result);
    } else if (result == ESP_TLS_ERR_SSL_WANT_READ || result == ESP_TLS_ERR_SSL_WANT_WRITE) {
      if (esp_timer_get_time() >= deadline) {
        return false;
      }
      vTaskDelay(pdMS_TO_TICKS(1));
    } else {
      return false;
    }
  }
  return true;
}

bool EspTransport::SessionAuthenticated(std::uint64_t epoch,
                                        const endpoint::SessionReady& ready) {
  const bool handoff_candidate =
      gateway_handoff_.targeting() || gateway_handoff_.restoring();
  if (candidate_path_ == Path::kNone ||
      (!handoff_candidate && arbiter_.active_path() != Path::kNone) ||
      !delegate_.SessionAuthenticated(epoch, ready)) {
    return false;
  }
  active_session_id_ = ready.session_id;
  endpoint_authenticated_ = true;
  return true;
}

bool EspTransport::CommandScopedArm(std::uint64_t epoch,
                                    std::uint32_t next_command_sequence) {
  return delegate_.CommandScopedArm(epoch, next_command_sequence);
}

bool EspTransport::Disarm(std::uint64_t epoch) { return delegate_.Disarm(epoch); }

bool EspTransport::DisarmComplete(std::uint64_t epoch) {
  return delegate_.DisarmComplete(epoch);
}

bool EspTransport::AuthenticatedFrame(std::uint64_t epoch,
                                      const protocol::DecodedFrame& frame) {
  return delegate_.AuthenticatedFrame(epoch, frame);
}

bool EspTransport::InitializeStation() {
  if (station_initialized_) {
    return true;
  }
  RecordWifi(WifiStage::kNetif);
  esp_err_t result = esp_netif_init();
  if (result != ESP_OK) {
    RecordWifi(WifiStage::kNetif, result);
    return false;
  }
  RecordWifi(WifiStage::kEventLoop);
  result = esp_event_loop_create_default();
  if (result != ESP_OK) {
    RecordWifi(WifiStage::kEventLoop, result);
    return false;
  }
  RecordWifi(WifiStage::kStationNetif);
  station_netif_ = esp_netif_create_default_wifi_sta();
  if (station_netif_ == nullptr) {
    RecordWifi(WifiStage::kStationNetif, ESP_ERR_NO_MEM);
    return false;
  }

  RecordWifi(WifiStage::kEventGroup);
  wifi_events_ = xEventGroupCreate();
  if (wifi_events_ == nullptr) {
    RecordWifi(WifiStage::kEventGroup, ESP_ERR_NO_MEM);
    return false;
  }
  const auto event_handler = [](void* argument, esp_event_base_t base, std::int32_t event_id,
                                void* event_data) {
    auto* self = static_cast<EspTransport*>(argument);
    auto events = static_cast<EventGroupHandle_t>(self->wifi_events_);
    if (base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
      self->RecordWifi(WifiStage::kGotIp);
      xEventGroupSetBits(events, kStationGotIp);
    } else if ((base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) ||
               (base == IP_EVENT && event_id == IP_EVENT_STA_LOST_IP)) {
      std::int32_t reason = 0;
      if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED &&
          event_data != nullptr) {
        reason = static_cast<wifi_event_sta_disconnected_t*>(event_data)->reason;
      }
      self->RecordWifi(WifiStage::kDisconnected, reason);
      xEventGroupSetBits(events, kStationDisconnected);
    }
  };
  esp_event_handler_instance_t wifi_handler{};
  esp_event_handler_instance_t ip_handler{};
  RecordWifi(WifiStage::kEventHandlers);
  result = esp_event_handler_instance_register(
      WIFI_EVENT, ESP_EVENT_ANY_ID, event_handler, this, &wifi_handler);
  if (result == ESP_OK) {
    result = esp_event_handler_instance_register(
        IP_EVENT, ESP_EVENT_ANY_ID, event_handler, this, &ip_handler);
  }
  if (result != ESP_OK) {
    RecordWifi(WifiStage::kEventHandlers, result);
    return false;
  }

  wifi_init_config_t initialization = WIFI_INIT_CONFIG_DEFAULT();
  RecordWifi(WifiStage::kDriver);
  result = esp_wifi_init(&initialization);
  if (result != ESP_OK) {
    RecordWifi(WifiStage::kDriver, result);
    return false;
  }
  RecordWifi(WifiStage::kStorage);
  result = esp_wifi_set_storage(WIFI_STORAGE_RAM);
  if (result != ESP_OK) {
    RecordWifi(WifiStage::kStorage, result);
    return false;
  }
  RecordWifi(WifiStage::kMode);
  result = esp_wifi_set_mode(WIFI_MODE_STA);
  if (result != ESP_OK) {
    RecordWifi(WifiStage::kMode, result);
    return false;
  }

  wifi_config_t station{};
  std::copy_n(config_.wifi.ssid, config_.wifi.ssid_length, station.sta.ssid);
  std::copy_n(config_.wifi.credential, config_.wifi.credential_length, station.sta.password);
  station.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
  station.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
  station.sta.threshold.rssi = -127;
  station.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
  station.sta.pmf_cfg.capable = true;
  station.sta.pmf_cfg.required = false;
  RecordWifi(WifiStage::kConfig);
  result = esp_wifi_set_config(WIFI_IF_STA, &station);
  SecureClear(&station, sizeof(station));
  if (result != ESP_OK) {
    RecordWifi(WifiStage::kConfig, result);
    return false;
  }
  RecordWifi(WifiStage::kStarted);
  result = esp_wifi_start();
  if (result != ESP_OK) {
    RecordWifi(WifiStage::kStarted, result);
    return false;
  }
  station_initialized_ = true;
  return true;
}

bool EspTransport::StartWifiCandidate() {
  auto events = static_cast<EventGroupHandle_t>(wifi_events_);
  xEventGroupClearBits(events, kStationGotIp | kStationDisconnected);
  advertised_installation_id_.fill(0);
  candidate_path_ = Path::kWifi;
  candidate_started_ms_ = NowMs();
  selection_started_ms_ = candidate_started_ms_;
  endpoint_tls_started_ = false;
  endpoint_authenticated_ = false;
  if (StationReadyForTls()) {
    RecordWifi(WifiStage::kGotIp);
    xEventGroupSetBits(events, kStationGotIp);
    wifi_connecting_ = true;
    return true;
  }
  RecordWifi(WifiStage::kConnecting);
  const esp_err_t result = esp_wifi_connect();
  if (result != ESP_OK) {
    RecordWifi(WifiStage::kConnecting, result);
    candidate_path_ = Path::kNone;
    return false;
  }
  wifi_connecting_ = true;
  return true;
}

bool EspTransport::StationReadyForTls() const {
  if (station_netif_ == nullptr) {
    return false;
  }
  wifi_ap_record_t access_point{};
  esp_netif_ip_info_t ip{};
  return esp_wifi_sta_get_ap_info(&access_point) == ESP_OK &&
         (access_point.authmode == WIFI_AUTH_WPA2_PSK ||
          access_point.authmode == WIFI_AUTH_WPA2_WPA3_PSK) &&
         esp_netif_get_ip_info(static_cast<esp_netif_t*>(station_netif_),
                              &ip) == ESP_OK &&
         ip.ip.addr != 0;
}

bool EspTransport::PollWifiCandidate(std::uint64_t now_ms) {
  auto events = static_cast<EventGroupHandle_t>(wifi_events_);
  const EventBits_t result = xEventGroupGetBits(events);
  if ((result & kStationDisconnected) != 0) {
    xEventGroupClearBits(events, kStationDisconnected);
    wifi_connecting_ = false;
    return false;
  }
  if ((result & kStationGotIp) == 0) {
    if (now_ms >= candidate_started_ms_ &&
        now_ms - candidate_started_ms_ >= config_.wifi_connect_timeout_ms) {
      wifi_connecting_ = false;
      return false;
    }
    return true;
  }
  xEventGroupClearBits(events, kStationGotIp);
  wifi_connecting_ = false;
  wifi_ap_record_t access_point{};
  if (esp_wifi_sta_get_ap_info(&access_point) != ESP_OK ||
      (access_point.authmode != WIFI_AUTH_WPA2_PSK &&
       access_point.authmode != WIFI_AUTH_WPA2_WPA3_PSK)) {
    return false;
  }

  auto remaining_ms = WifiPreferenceRemainingMs(now_ms);
  if (remaining_ms == 0 ||
      !ResolveHostAddress(
          std::min(config_.discovery_timeout_ms, remaining_ms))) {
    return false;
  }
  now_ms = NowMs();
  remaining_ms = WifiPreferenceRemainingMs(now_ms);
  endpoint::TlsObservation observation{};
  config::RoamingPeerAuthorization authorization{};
  RecordWifi(WifiStage::kTls);
  if (remaining_ms == 0 ||
      !ConnectAndVerifyWifiTls(
          std::min(config_.tls_connect_timeout_ms, remaining_ms),
          &observation, &authorization) ||
      !BeginEndpointTls(observation, authorization)) {
    return false;
  }
  endpoint_tls_started_ = true;
  candidate_started_ms_ = now_ms;
  return true;
}

bool EspTransport::ResolveHostAddress(std::uint32_t timeout_ms) {
  discovery::HostSelection selection{};
  if (config_.authority_mode == AuthorityMode::kOwnerRoaming) {
    if (!discovery::ReceiveRoamingBeacon(
            static_cast<esp_netif_t*>(station_netif_), config_.tls.port,
            timeout_ms, &selection)) {
      return false;
    }
    advertised_installation_id_ = selection.host_id;
  } else {
    discovery::Ipv4Address manual_address{};
    if (!ParseIpv4Literal(config_.host_ipv4, config_.host_ipv4_length,
                          &manual_address)) {
      return false;
    }
    const discovery::PairedHostView paired_host{
        config_.host_id, manual_address, config_.tls.port};
    const bool discovered = discovery::ReceiveKnownHostBeacon(
        static_cast<esp_netif_t*>(station_netif_), &paired_host, 1,
        timeout_ms, &selection);
    if (!discovered && !discovery::SelectManualHost(paired_host, &selection)) {
      return false;
    }
  }
  const int length = std::snprintf(
      resolved_host_ipv4_.data(), resolved_host_ipv4_.size(), "%u.%u.%u.%u",
      static_cast<unsigned>(selection.address[0]),
      static_cast<unsigned>(selection.address[1]),
      static_cast<unsigned>(selection.address[2]),
      static_cast<unsigned>(selection.address[3]));
  if (length <= 0 || static_cast<std::size_t>(length) >= resolved_host_ipv4_.size() ||
      selection.tls_port != config_.tls.port) {
    resolved_host_ipv4_.fill(0);
    resolved_host_ipv4_length_ = 0;
    return false;
  }
  resolved_host_ipv4_length_ = static_cast<std::size_t>(length);
  return true;
}

bool EspTransport::StartGatewayHandoffCandidate(const std::uint64_t now_ms) {
  const auto status = gateway_handoff_.Status(
      protocol::GatewayHandoffOperation::kQuery, now_ms);
  const std::array<std::uint8_t, 16>* expected_installation = nullptr;
  std::uint32_t remaining_ms = 0;
  Path path = Path::kNone;
  if (gateway_handoff_.targeting()) {
    const int length = std::snprintf(
        resolved_host_ipv4_.data(), resolved_host_ipv4_.size(),
        "%u.%u.%u.%u", static_cast<unsigned>(handoff_target_ipv4_[0]),
        static_cast<unsigned>(handoff_target_ipv4_[1]),
        static_cast<unsigned>(handoff_target_ipv4_[2]),
        static_cast<unsigned>(handoff_target_ipv4_[3]));
    if (length <= 0 ||
        static_cast<std::size_t>(length) >= resolved_host_ipv4_.size() ||
        handoff_target_port_ != config_.tls.port) {
      return false;
    }
    resolved_host_ipv4_length_ = static_cast<std::size_t>(length);
    expected_installation = &status.target_installation_id;
    remaining_ms = status.remaining_phase_ms;
    path = Path::kWifi;
  } else if (gateway_handoff_.restoring()) {
    if (handoff_previous_path_ == Path::kWifi) {
      if (handoff_previous_ipv4_length_ == 0 ||
          handoff_previous_ipv4_length_ >= resolved_host_ipv4_.size() ||
          handoff_previous_port_ != config_.tls.port) {
        return false;
      }
      resolved_host_ipv4_ = handoff_previous_ipv4_;
      resolved_host_ipv4_length_ = handoff_previous_ipv4_length_;
      path = Path::kWifi;
    } else if (handoff_previous_path_ == Path::kBluetooth) {
      if (!ble_available_.load(std::memory_order_acquire)) {
        return false;
      }
      path = Path::kBluetooth;
    } else {
      return false;
    }
    expected_installation = &status.previous_installation_id;
    remaining_ms = status.remaining_recovery_ms;
  } else {
    return false;
  }
  if (remaining_ms == 0 || expected_installation == nullptr) {
    return false;
  }

  candidate_path_ = path;
  advertised_installation_id_ = *expected_installation;
  handoff_candidate_installation_id_ = *expected_installation;
  candidate_started_ms_ = now_ms;
  endpoint_tls_started_ = false;
  endpoint_authenticated_ = false;
  ble_authentication_requested_ = false;
  ble_handshake_active_ = false;
  if (path == Path::kBluetooth) {
    return ble_peripheral_.StartAdvertising();
  }
  if (!StationReadyForTls()) {
    auto events = static_cast<EventGroupHandle_t>(wifi_events_);
    xEventGroupClearBits(events, kStationGotIp | kStationDisconnected);
    RecordWifi(WifiStage::kConnecting);
    if (esp_wifi_connect() != ESP_OK) {
      return false;
    }
    wifi_connecting_ = true;
    return true;
  }
  endpoint::TlsObservation observation{};
  config::RoamingPeerAuthorization authorization{};
  RecordWifi(WifiStage::kTls);
  const auto timeout_ms =
      std::min(kGatewayHandoffAttemptTimeoutMs, remaining_ms);
  if (!ConnectAndVerifyWifiTls(timeout_ms, &observation, &authorization) ||
      authorization.installation_id != *expected_installation ||
      !BeginEndpointTls(observation, authorization)) {
    return false;
  }
  endpoint_tls_started_ = true;
  candidate_started_ms_ = NowMs();
  return true;
}

void EspTransport::ServiceGatewayHandoffTransport(
    const std::uint64_t now_ms) {
  gateway_handoff_.Poll(now_ms);
  if (!gateway_handoff_.targeting() && !gateway_handoff_.restoring()) {
    const auto status = gateway_handoff_.Status(
        protocol::GatewayHandoffOperation::kQuery, now_ms);
    if (status.phase ==
        protocol::GatewayHandoffPhase::kRecoveryUnavailable) {
      FailClosedGatewayHandoff();
    }
    return;
  }
  const auto handoff_status = gateway_handoff_.Status(
      protocol::GatewayHandoffOperation::kQuery, now_ms);
  const auto& expected_installation = gateway_handoff_.targeting()
                                          ? handoff_status.target_installation_id
                                          : handoff_status.previous_installation_id;
  if (candidate_path_ != Path::kNone &&
      handoff_candidate_installation_id_ != expected_installation) {
    session_.TransportFault();
    CloseCurrentTls();
    if (candidate_path_ == Path::kBluetooth) {
      ble_peripheral_.Disconnect();
    }
    candidate_path_ = Path::kNone;
    wifi_connecting_ = false;
    endpoint_authenticated_ = false;
    handoff_attempts_ = 0;
    handoff_next_attempt_ms_ = now_ms;
    handoff_candidate_installation_id_.fill(0);
  }
  if (candidate_path_ == Path::kNone) {
    if (now_ms < handoff_next_attempt_ms_) {
      return;
    }
    if (handoff_attempts_ >= kGatewayHandoffMaximumAttempts) {
      if (gateway_handoff_.targeting()) {
        (void)gateway_handoff_.TargetFailed(
            protocol::GatewayHandoffReason::kTargetAbsent, now_ms);
        handoff_attempts_ = 0;
        handoff_next_attempt_ms_ = now_ms;
      } else {
        (void)gateway_handoff_.RecoveryFailed(now_ms);
      }
      return;
    }
    ++handoff_attempts_;
    if (!StartGatewayHandoffCandidate(now_ms)) {
      GatewayHandoffCandidateFailed(
          NowMs(), protocol::GatewayHandoffReason::kTransportFailed);
    }
    return;
  }
  if (candidate_path_ == Path::kWifi && wifi_connecting_) {
    auto events = static_cast<EventGroupHandle_t>(wifi_events_);
    const EventBits_t result = xEventGroupGetBits(events);
    if ((result & kStationDisconnected) != 0) {
      xEventGroupClearBits(events, kStationDisconnected);
      wifi_connecting_ = false;
      GatewayHandoffCandidateFailed(
          now_ms, protocol::GatewayHandoffReason::kTransportFailed);
      return;
    }
    if ((result & kStationGotIp) == 0 && !StationReadyForTls()) {
      if (now_ms >= candidate_started_ms_ &&
          now_ms - candidate_started_ms_ >= kGatewayHandoffAttemptTimeoutMs) {
        wifi_connecting_ = false;
        GatewayHandoffCandidateFailed(
            now_ms, protocol::GatewayHandoffReason::kTransportFailed);
      }
      return;
    }
    xEventGroupClearBits(events, kStationGotIp);
    wifi_connecting_ = false;
    endpoint::TlsObservation observation{};
    config::RoamingPeerAuthorization authorization{};
    RecordWifi(WifiStage::kTls);
    const auto remaining_ms = gateway_handoff_.targeting()
                                  ? handoff_status.remaining_phase_ms
                                  : handoff_status.remaining_recovery_ms;
    if (remaining_ms == 0 ||
        !ConnectAndVerifyWifiTls(
            std::min(kGatewayHandoffAttemptTimeoutMs, remaining_ms),
            &observation, &authorization) ||
        authorization.installation_id != expected_installation ||
        !BeginEndpointTls(observation, authorization)) {
      GatewayHandoffCandidateFailed(
          NowMs(), protocol::GatewayHandoffReason::kTransportFailed);
      return;
    }
    endpoint_tls_started_ = true;
    candidate_started_ms_ = NowMs();
  }
  if (candidate_path_ == Path::kBluetooth && !ble_handshake_active_ &&
      !endpoint_tls_started_) {
    if (ble_peripheral_.ready(ble_generation_)) {
      ble_authentication_requested_ = true;
      if (!StartBleTls(now_ms)) {
        GatewayHandoffCandidateFailed(
            now_ms, protocol::GatewayHandoffReason::kTransportFailed);
        return;
      }
    } else if (now_ms >= candidate_started_ms_ &&
               now_ms - candidate_started_ms_ >=
                   kGatewayHandoffAttemptTimeoutMs) {
      GatewayHandoffCandidateFailed(
          now_ms, protocol::GatewayHandoffReason::kTransportFailed);
      return;
    } else {
      return;
    }
  }
  if (!ServiceCurrentTls(now_ms)) {
    GatewayHandoffCandidateFailed(
        now_ms, protocol::GatewayHandoffReason::kTransportFailed);
  }
}

void EspTransport::GatewayHandoffCandidateFailed(
    const std::uint64_t now_ms,
    const protocol::GatewayHandoffReason reason) {
  const Path failed_path = candidate_path_;
  session_.TransportFault();
  CloseCurrentTls();
  if (failed_path == Path::kBluetooth) {
    ble_peripheral_.Disconnect();
  }
  candidate_path_ = Path::kNone;
  handoff_candidate_installation_id_.fill(0);
  endpoint_tls_started_ = false;
  endpoint_authenticated_ = false;
  if (handoff_attempts_ >= kGatewayHandoffMaximumAttempts) {
    if (gateway_handoff_.targeting()) {
      (void)gateway_handoff_.TargetFailed(reason, now_ms);
      handoff_attempts_ = 0;
      handoff_next_attempt_ms_ = now_ms;
    } else {
      (void)gateway_handoff_.RecoveryFailed(now_ms);
    }
  } else {
    handoff_next_attempt_ms_ = now_ms + kGatewayHandoffRetryGapMs;
  }
}

void EspTransport::FailClosedGatewayHandoff() {
  session_.TransportFault();
  delegate_.FailClosed(session_.epoch());
  CloseCurrentTls();
  if (candidate_path_ == Path::kBluetooth) {
    ble_peripheral_.Stop();
  } else if (candidate_path_ == Path::kWifi) {
    (void)esp_wifi_disconnect();
  }
  arbiter_.QuiesceForTargetedHandoff();
  candidate_path_ = Path::kNone;
  handoff_candidate_installation_id_.fill(0);
  endpoint_tls_started_ = false;
  endpoint_authenticated_ = false;
  wifi_connecting_ = false;
  published_path_.store(Path::kNone, std::memory_order_release);
  handoff_fail_closed_ = true;
}

void EspTransport::BeginCommittedGatewayHandoff(
    const std::uint64_t now_ms) {
  handoff_start_committed_ = false;
  const Path previous_path = candidate_path_;
  session_.TransportFault();
  CloseCurrentTls();
  if (previous_path == Path::kBluetooth) {
    ble_peripheral_.Stop();
  }
  arbiter_.QuiesceForTargetedHandoff();
  candidate_path_ = Path::kNone;
  handoff_candidate_installation_id_.fill(0);
  endpoint_tls_started_ = false;
  endpoint_authenticated_ = false;
  wifi_connecting_ = false;
  published_path_.store(Path::kNone, std::memory_order_release);
  handoff_attempts_ = 0;
  handoff_next_attempt_ms_ = now_ms;
}

bool EspTransport::ConnectAndVerifyWifiTls(
    std::uint32_t timeout_ms, endpoint::TlsObservation* observation,
    config::RoamingPeerAuthorization* authorization) {
  if (observation == nullptr || authorization == nullptr || timeout_ms == 0) {
    return false;
  }
  *authorization = {};
  CloseCurrentTls();
  auto* tls = esp_tls_init();
  if (tls == nullptr) {
    return false;
  }
  tls_ = tls;

  tls_keep_alive_cfg_t keep_alive{true, kTcpKeepAliveIdleSeconds,
                                  kTcpKeepAliveIntervalSeconds,
                                  kTcpKeepAliveProbeCount};
  esp_tls_cfg_t tls_config{};
  tls_config.cacert_buf = config_.ca_certificate_der;
  tls_config.cacert_bytes = static_cast<unsigned int>(config_.ca_certificate_der_length);
  tls_config.timeout_ms = static_cast<int>(timeout_ms);
  tls_config.common_name = config_.tls.server_name;
  tls_config.skip_common_name = false;
  tls_config.keep_alive_cfg = &keep_alive;
  tls_config.addr_family = ESP_TLS_AF_INET;
  tls_config.ciphersuites_list = kCipherSuites.data();
  tls_config.tls_version = ESP_TLS_VER_TLS_1_2;
  tls_config.non_block = true;
  if (resolved_host_ipv4_length_ == 0 ||
      esp_tls_conn_new_sync(resolved_host_ipv4_.data(),
                            static_cast<int>(resolved_host_ipv4_length_), config_.tls.port,
                            &tls_config, tls) != 1) {
    return false;
  }

  auto* ssl =
      static_cast<mbedtls_ssl_context*>(esp_tls_get_ssl_context(tls));
  if (config_.authority_mode == AuthorityMode::kPinnedPeer) {
    return VerifyMbedTlsPeer(ssl, config_.tls, observation);
  }
  return config_.roaming_policy != nullptr &&
         config_.roaming_recovery_secret != nullptr &&
         config_.roaming_crypto != nullptr &&
         config_.roaming_verification_workspace != nullptr &&
         VerifyMbedTlsRoamingPeer(
             ssl, *config_.roaming_policy, *config_.roaming_recovery_secret,
             *config_.roaming_crypto, observation, authorization,
             config_.roaming_verification_workspace);
}

bool EspTransport::BeginEndpointTls(
    const endpoint::TlsObservation& observation,
    const config::RoamingPeerAuthorization& authorization) {
  ClearPeerAuthorization();
  accepted_tls_policy_ = config_.tls;
  if (config_.authority_mode == AuthorityMode::kPinnedPeer) {
    active_host_id_ = config_.host_id;
    active_link_secret_ = config_.link_secret;
  } else {
    const bool handoff_candidate = gateway_handoff_.targeting() ||
                                   gateway_handoff_.restoring();
    if (authorization.installation_id ==
            std::array<std::uint8_t, 16>{} ||
        authorization.link_secret == std::array<std::uint8_t, 32>{} ||
        (handoff_candidate &&
         authorization.installation_id !=
             handoff_candidate_installation_id_) ||
        (candidate_path_ == Path::kWifi &&
         authorization.installation_id != advertised_installation_id_)) {
      ClearPeerAuthorization();
      advertised_installation_id_.fill(0);
      return false;
    }
    active_host_id_ = authorization.installation_id;
    active_link_secret_ = authorization.link_secret;
    accepted_tls_policy_.peer_spki_sha256 = observation.peer_spki_sha256;
  }
  if (!session_.BeginTls(accepted_tls_policy_, observation)) {
    ClearPeerAuthorization();
    advertised_installation_id_.fill(0);
    return false;
  }
  advertised_installation_id_.fill(0);
  return true;
}

bool EspTransport::StartBleTls(std::uint64_t now_ms) {
  if (!ble_authentication_requested_ || ble_generation_ == 0 ||
      !ble_peripheral_.ready(ble_generation_)) {
    return false;
  }
  candidate_path_ = Path::kBluetooth;
  candidate_started_ms_ = now_ms;
  endpoint_tls_started_ = false;
  endpoint_authenticated_ = false;
  ble_authentication_requested_ = false;
  ble_handshake_active_ = ble_tls_.Start(ble_generation_, now_ms);
  return ble_handshake_active_;
}

bool EspTransport::ServiceCurrentTls(std::uint64_t now_ms) {
  if (candidate_path_ == Path::kNone) {
    return true;
  }
  if (candidate_path_ == Path::kBluetooth && ble_handshake_active_) {
    endpoint::TlsObservation observation{};
    config::RoamingPeerAuthorization authorization{};
    const auto result =
        ble_tls_.HandshakeStep(now_ms, &observation, &authorization);
    if (result == BleTlsHandshake::kFailed) {
      return false;
    }
    if (result == BleTlsHandshake::kWantIo) {
      return true;
    }
    ble_handshake_active_ = false;
    candidate_started_ms_ = now_ms;
    if (!BeginEndpointTls(observation, authorization)) {
      return false;
    }
    endpoint_tls_started_ = true;
  }
  if (!endpoint_tls_started_) {
    return true;
  }
  return ServiceEndpointRead(now_ms);
}

bool EspTransport::ServiceEndpointRead(std::uint64_t now_ms) {
  std::array<std::uint8_t, 512> input{};
  if (!session_.Service() ||
      (!session_.control_reply_pending() &&
       !delegate_.Service(session_.epoch()))) {
    return false;
  }
  int result = 0;
  if (candidate_path_ == Path::kWifi) {
    auto events = static_cast<EventGroupHandle_t>(wifi_events_);
    const EventBits_t wifi_state = xEventGroupGetBits(events);
    if ((wifi_state & kStationDisconnected) != 0) {
      xEventGroupClearBits(events, kStationDisconnected);
      return false;
    }
    if (tls_ == nullptr) {
      return false;
    }
    result = static_cast<int>(esp_tls_conn_read(
        static_cast<esp_tls_t*>(tls_), input.data(), input.size()));
  } else {
    if (!ble_tls_.PollHealthy(now_ms, session_.authenticated())) {
      return false;
    }
    result = ble_tls_.Read(input.data(), input.size());
  }
  if (result > 0) {
    const bool consumed =
        session_.ConsumeTls(input.data(), static_cast<std::size_t>(result));
    SecureClear(input.data(), input.size());
    if (!consumed) {
      return false;
    }
    if (endpoint_authenticated_) {
      PromoteAuthenticatedCandidate(now_ms);
    }
    return true;
  }
  SecureClear(input.data(), input.size());
  if (result == ESP_TLS_ERR_SSL_WANT_READ ||
      result == ESP_TLS_ERR_SSL_WANT_WRITE ||
      result == MBEDTLS_ERR_SSL_WANT_READ ||
      result == MBEDTLS_ERR_SSL_WANT_WRITE) {
    if (!session_.authenticated() && now_ms >= candidate_started_ms_ &&
        now_ms - candidate_started_ms_ >=
            protocol::kBleAuthenticationTimeoutMs) {
      return false;
    }
    return true;
  }
  return false;
}

void EspTransport::PollBle(std::uint64_t now_ms) {
  const auto events = ble_peripheral_.Poll(now_ms);
  const bool handoff_ble_candidate =
      (gateway_handoff_.targeting() || gateway_handoff_.restoring()) &&
      candidate_path_ == Path::kBluetooth;
  if (handoff_ble_candidate) {
    if (events.connected) {
      ble_generation_ = events.generation;
      ble_authentication_requested_ = true;
    }
    if (events.disconnected || events.fault != ble::Fault::kNone) {
      GatewayHandoffCandidateFailed(
          now_ms, protocol::GatewayHandoffReason::kTransportFailed);
    }
    return;
  }
  if (events.connected) {
    ble_generation_ = events.generation;
    ApplyActions(arbiter_.BleConnected(now_ms), now_ms);
  }
  if (events.fault != ble::Fault::kNone &&
      !ble_peripheral_.status().synchronized &&
      arbiter_.active_path() != Path::kBluetooth &&
      candidate_path_ != Path::kBluetooth) {
    ble_available_.store(false, std::memory_order_release);
    ble_peripheral_.Stop();
    ApplyActions(arbiter_.Disable(Path::kBluetooth, now_ms), now_ms);
    return;
  }
  if ((events.disconnected || events.fault != ble::Fault::kNone) &&
      (arbiter_.active_path() == Path::kBluetooth ||
       arbiter_.ble_connected() || arbiter_.ble_advertising() ||
       candidate_path_ == Path::kBluetooth)) {
    if (arbiter_.active_path() == Path::kBluetooth) {
      ActiveTransportLost(now_ms);
    } else {
      CandidateFailed(now_ms);
    }
  }
}

void EspTransport::ApplyActions(const ArbitrationActions& actions,
                                std::uint64_t now_ms) {
  if (actions.fail_closed) {
    session_.TransportFault();
    delegate_.FailClosed(session_.epoch());
  }
  if (actions.cancel_wifi) {
    wifi_connecting_ = false;
    (void)esp_wifi_disconnect();
    if (candidate_path_ == Path::kWifi &&
        arbiter_.active_path() != Path::kWifi) {
      session_.TransportFault();
      CloseCurrentTls();
      candidate_path_ = Path::kNone;
      endpoint_tls_started_ = false;
      endpoint_authenticated_ = false;
    }
  }
  if (actions.stop_ble) {
    if (candidate_path_ == Path::kBluetooth) {
      session_.TransportFault();
      ble_tls_.Close();
      candidate_path_ = Path::kNone;
      endpoint_tls_started_ = false;
      endpoint_authenticated_ = false;
    }
    ble_authentication_requested_ = false;
    ble_handshake_active_ = false;
    ble_peripheral_.Stop();
  }
  if (actions.start_wifi && !StartWifiCandidate()) {
    CandidateFailed(now_ms);
  }
  if (actions.start_ble_advertising &&
      !ble_peripheral_.StartAdvertising()) {
    ble_available_.store(false, std::memory_order_release);
    ApplyActions(arbiter_.Disable(Path::kBluetooth, now_ms), now_ms);
  }
  if (actions.start_ble_authentication) {
    ble_authentication_requested_ = true;
  }
}

void EspTransport::PromoteAuthenticatedCandidate(std::uint64_t now_ms) {
  if (gateway_handoff_.targeting()) {
    endpoint_authenticated_ = false;
    if (!gateway_handoff_.TargetAuthenticated(
            active_host_id_, active_session_id_, now_ms)) {
      GatewayHandoffCandidateFailed(
          now_ms, protocol::GatewayHandoffReason::kIdentityFailed);
      return;
    }
    published_path_.store(Path::kWifi, std::memory_order_release);
    RecordWifi(WifiStage::kAuthenticated);
    return;
  }
  if (gateway_handoff_.restoring()) {
    endpoint_authenticated_ = false;
    if (!gateway_handoff_.PreviousAuthenticated(
            active_host_id_, active_session_id_, now_ms)) {
      GatewayHandoffCandidateFailed(
          now_ms, protocol::GatewayHandoffReason::kIdentityFailed);
      return;
    }
    if (!arbiter_.InstallTargetedOwner(candidate_path_)) {
      GatewayHandoffCandidateFailed(
          now_ms, protocol::GatewayHandoffReason::kIdentityFailed);
      return;
    }
    published_path_.store(candidate_path_, std::memory_order_release);
    if (candidate_path_ == Path::kWifi) {
      RecordWifi(WifiStage::kAuthenticated);
    }
    return;
  }
  ArbitrationActions actions{};
  if (candidate_path_ == Path::kWifi) {
    actions = arbiter_.WifiAttemptFinished(true, now_ms);
  } else if (candidate_path_ == Path::kBluetooth) {
    actions = arbiter_.BleAuthenticated(now_ms);
  } else {
    endpoint_authenticated_ = false;
    return;
  }
  endpoint_authenticated_ = false;
  if (arbiter_.active_path() != candidate_path_) {
    CandidateFailed(now_ms);
    return;
  }
  published_path_.store(candidate_path_, std::memory_order_release);
  if (candidate_path_ == Path::kWifi) {
    RecordWifi(WifiStage::kAuthenticated);
  }
  ApplyActions(actions, now_ms);
}

void EspTransport::CandidateFailed(std::uint64_t now_ms) {
  const Path failed_path = candidate_path_;
  if (failed_path == Path::kBluetooth) {
    // BleTlsLink::Start can fail before it owns initialized TLS contexts. The
    // physical GATT candidate still must be evicted before advertising again.
    ble_peripheral_.Disconnect();
  }
  session_.TransportFault();
  CloseCurrentTls();
  if (failed_path == Path::kWifi) {
    (void)esp_wifi_disconnect();
  }
  candidate_path_ = Path::kNone;
  endpoint_tls_started_ = false;
  endpoint_authenticated_ = false;
  ble_authentication_requested_ = false;
  ble_handshake_active_ = false;
  ArbitrationActions actions{};
  if (failed_path == Path::kBluetooth || arbiter_.ble_connected()) {
    actions = arbiter_.BleCandidateFailed(now_ms);
  } else if (failed_path == Path::kWifi || arbiter_.wifi_candidate_active()) {
    actions = arbiter_.WifiAttemptFinished(false, now_ms);
  }
  ApplyActions(actions, now_ms);
}

void EspTransport::ActiveTransportLost(std::uint64_t now_ms) {
  session_.TransportFault();
  CloseCurrentTls();
  candidate_path_ = Path::kNone;
  endpoint_tls_started_ = false;
  endpoint_authenticated_ = false;
  wifi_connecting_ = false;
  ble_authentication_requested_ = false;
  ble_handshake_active_ = false;
  published_path_.store(Path::kNone, std::memory_order_release);
  ApplyActions(arbiter_.ActiveTransportLost(now_ms), now_ms);
}

void EspTransport::RestartRuntime(const std::uint64_t now_ms) {
  session_.TransportFault();
  CloseCurrentTls();
  wifi_connecting_ = false;
  (void)esp_wifi_disconnect();
  ble_authentication_requested_ = false;
  ble_handshake_active_ = false;
  ble_generation_ = 0;
  ble_peripheral_.Stop();
  candidate_path_ = Path::kNone;
  endpoint_tls_started_ = false;
  endpoint_authenticated_ = false;
  published_path_.store(Path::kNone, std::memory_order_release);

  gateway_handoff_.Boot();
  handoff_target_ipv4_.fill(0);
  handoff_target_port_ = 0;
  handoff_candidate_installation_id_.fill(0);
  handoff_previous_ipv4_.fill(0);
  handoff_previous_ipv4_length_ = 0;
  handoff_previous_port_ = 0;
  handoff_previous_path_ = Path::kNone;
  handoff_next_attempt_ms_ = 0;
  handoff_attempts_ = 0;
  handoff_start_committed_ = false;
  handoff_fail_closed_ = false;
  advertised_installation_id_.fill(0);

  selection_started_ms_ = now_ms;
  ApplyActions(
      arbiter_.Boot(now_ms,
                    {wifi_available_.load(std::memory_order_acquire),
                     ble_available_.load(std::memory_order_acquire)}),
      now_ms);
}

void EspTransport::CloseCurrentTls() {
  if (tls_ != nullptr) {
    esp_tls_conn_destroy(static_cast<esp_tls_t*>(tls_));
    tls_ = nullptr;
  }
  if (ble_handshake_active_ || ble_tls_.established()) {
    ble_tls_.Close();
  }
  ble_handshake_active_ = false;
  endpoint_tls_started_ = false;
  ClearPeerAuthorization();
}

void EspTransport::ClearPeerAuthorization() {
  accepted_tls_policy_ = {};
  active_host_id_.fill(0);
  SecureClear(active_link_secret_.data(), active_link_secret_.size());
  active_session_id_.fill(0);
  last_route_proof_ms_ = 0;
  route_proof_controller_id_.fill(0);
  route_proof_session_id_.fill(0);
  SecureClear(route_proof_digest_.data(), route_proof_digest_.size());
  route_proof_expires_ms_ = 0;
}

std::uint32_t EspTransport::WifiPreferenceRemainingMs(
    std::uint64_t now_ms) const {
  if (now_ms < selection_started_ms_) {
    return 0;
  }
  const auto elapsed = now_ms - selection_started_ms_;
  if (elapsed >= protocol::kBleWifiPreferenceMs) {
    return 0;
  }
  return static_cast<std::uint32_t>(protocol::kBleWifiPreferenceMs - elapsed);
}

void EspTransport::RecordWifi(const WifiStage stage,
                              const std::int32_t error) {
  wifi_stage_.store(stage, std::memory_order_release);
  wifi_error_.store(error, std::memory_order_release);
}

}  // namespace keyferry::transport
