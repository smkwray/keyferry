#include "keyferry/idf_ble_hid_peripheral.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstring>

#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_hs_mbuf.h"
#include "host/ble_store.h"
#include "host/util/util.h"
#include "keyferry/ble_hid_release.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "services/hid/ble_svc_hid.h"

namespace keyferry::ble_hid {
namespace {

constexpr std::uint16_t kNoConnection = BLE_HS_CONN_HANDLE_NONE;
constexpr std::uint8_t kKeyboardReportId = 1;
constexpr std::uint16_t kKeyboardAppearance = 0x03C1;
constexpr std::uint32_t kEventDisconnected = 1U << 0U;
constexpr std::uint32_t kEventReleaseComplete = 1U << 1U;
constexpr std::uint32_t kEventDisconnectRequired = 1U << 2U;
constexpr std::uint32_t kEventFault = 1U << 3U;

constexpr std::array<std::uint8_t, 67> kKeyboardReportMap{{
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01,
    0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00,
    0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02,
    0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x06,
    0x75, 0x08, 0x15, 0x00, 0x26, 0xDD, 0x00, 0x05, 0x07,
    0x19, 0x00, 0x2A, 0xDD, 0x00, 0x81, 0x00, 0x95, 0x05,
    0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05,
    0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01,
    0xC0,
}};

const ble_uuid16_t kHidServiceUuid = BLE_UUID16_INIT(BLE_SVC_HID_UUID16);
const ble_uuid16_t kBootKeyboardInputUuid =
    BLE_UUID16_INIT(BLE_SVC_HID_CHR_UUID16_BOOT_KBD_INP);
const ble_uuid16_t kReportUuid =
    BLE_UUID16_INIT(BLE_SVC_HID_CHR_UUID16_RPT);

struct State {
  portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
  std::atomic<std::uint32_t> events{0};
  ReleaseBurst release;
  std::uint16_t connection_handle{kNoConnection};
  std::uint16_t boot_input_handle{};
  std::uint16_t report_input_handle{};
  std::uint16_t connection_interval_units{24};
  std::uint32_t generation{};
  std::uint32_t passkey{};
  std::uint8_t address_type{};
  std::uint8_t protocol_mode{BLE_SVC_HID_PROTO_MODE_REPORT};
  bool initialized{};
  bool synchronized{};
  bool advertising{};
  bool authenticated{};
  bool boot_subscribed{};
  bool report_subscribed{};
  bool initial_release_complete{};
  bool release_for_report{};
  bool unbonded_advertising_allowed{};
  EnrollmentWindow enrollment{};
  PeripheralStage stage{PeripheralStage::kOff};
  std::int32_t error{};
};

State g_state;
IdfBleHidPeripheral* g_owner{};

void MarkEvent(const std::uint32_t event) {
  g_state.events.fetch_or(event, std::memory_order_release);
}

bool IsZero(const KeyboardReport& report) {
  std::uint8_t value = 0;
  for (const auto byte : report) {
    value = static_cast<std::uint8_t>(value | byte);
  }
  return value == 0;
}

void Terminate(const std::uint16_t reason = BLE_ERR_REM_USER_CONN_TERM) {
  std::uint16_t handle;
  portENTER_CRITICAL(&g_state.lock);
  handle = g_state.connection_handle;
  portEXIT_CRITICAL(&g_state.lock);
  if (handle != kNoConnection) {
    (void)ble_gap_terminate(handle, reason);
  }
}

bool IsSubscribedLocked() {
  return g_state.protocol_mode == BLE_SVC_HID_PROTO_MODE_BOOT
             ? g_state.boot_subscribed
             : g_state.report_subscribed;
}

struct BondInventory {
  BondStoreStatus status{};
  bool peer_matches{};
};

BondInventory ReadBondInventory(const ble_addr_t* peer_id_address) {
  std::array<ble_addr_t, 2> peers{};
  int count = 0;
  const int rc = ble_store_util_bonded_peers(peers.data(), &count, peers.size());
  if (rc != 0 || count < 0 || static_cast<std::size_t>(count) > peers.size()) {
    return {{BondStoreState::kStoreError, rc}, false};
  }
  if (count == 0) {
    return {{BondStoreState::kNone, 0}, peer_id_address != nullptr};
  }
  if (count > 1) {
    return {{BondStoreState::kMultipleInvalid, 0}, false};
  }
  const bool matches =
      peer_id_address != nullptr && peers[0].type == peer_id_address->type &&
      std::memcmp(peers[0].val, peer_id_address->val,
                  sizeof(peer_id_address->val)) == 0;
  return {{BondStoreState::kSingle, 0}, matches};
}

bool PeerMatchesOnlyBond(const ble_addr_t& peer_id_address) {
  const auto inventory = ReadBondInventory(&peer_id_address);
  return inventory.status.state == BondStoreState::kNone ||
         (inventory.status.state == BondStoreState::kSingle &&
          inventory.peer_matches);
}

int GapEvent(ble_gap_event* event, void*);

bool StartAdvertising() {
  const auto inventory = ReadBondInventory(nullptr);
  bool unbonded_allowed = false;
  portENTER_CRITICAL(&g_state.lock);
  unbonded_allowed = g_state.unbonded_advertising_allowed;
  portEXIT_CRITICAL(&g_state.lock);
  if (inventory.status.state == BondStoreState::kStoreError) {
    portENTER_CRITICAL(&g_state.lock);
    g_state.advertising = false;
    g_state.stage = PeripheralStage::kFault;
    g_state.error = inventory.status.error;
    portEXIT_CRITICAL(&g_state.lock);
    MarkEvent(kEventFault);
    return false;
  }
  if (inventory.status.state == BondStoreState::kMultipleInvalid ||
      (inventory.status.state == BondStoreState::kNone && !unbonded_allowed)) {
    portENTER_CRITICAL(&g_state.lock);
    g_state.advertising = false;
    g_state.stage = PeripheralStage::kHostSync;
    g_state.error = 0;
    portEXIT_CRITICAL(&g_state.lock);
    return true;
  }
  ble_hs_adv_fields fields{};
  fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
  const auto* name = ble_svc_gap_device_name();
  fields.name = reinterpret_cast<const std::uint8_t*>(name);
  fields.name_len = std::strlen(name);
  fields.name_is_complete = 1;
  fields.appearance = kKeyboardAppearance;
  fields.appearance_is_present = 1;
  static const ble_uuid16_t service = BLE_UUID16_INIT(BLE_SVC_HID_UUID16);
  fields.uuids16 = const_cast<ble_uuid16_t*>(&service);
  fields.num_uuids16 = 1;
  fields.uuids16_is_complete = 1;
  int rc = ble_gap_adv_set_fields(&fields);
  if (rc == 0) {
    ble_gap_adv_params parameters{};
    parameters.conn_mode = BLE_GAP_CONN_MODE_UND;
    parameters.disc_mode = BLE_GAP_DISC_MODE_GEN;
    rc = ble_gap_adv_start(g_state.address_type, nullptr, BLE_HS_FOREVER,
                           &parameters, GapEvent, nullptr);
  }
  portENTER_CRITICAL(&g_state.lock);
  g_state.advertising = rc == 0;
  g_state.stage = rc == 0 ? PeripheralStage::kAdvertising
                          : PeripheralStage::kFault;
  g_state.error = rc;
  portEXIT_CRITICAL(&g_state.lock);
  if (rc != 0) {
    MarkEvent(kEventFault);
  }
  return rc == 0;
}

void HostReset(const int reason) {
  portENTER_CRITICAL(&g_state.lock);
  g_state.synchronized = false;
  g_state.advertising = false;
  g_state.stage = PeripheralStage::kFault;
  g_state.error = reason;
  portEXIT_CRITICAL(&g_state.lock);
  MarkEvent(kEventFault);
}

void HostSynchronized() {
  std::uint8_t address_type = 0;
  std::uint16_t boot_input_handle = 0;
  std::uint16_t report_input_handle = 0;
  int rc = ble_hs_util_ensure_addr(0);
  if (rc == 0) {
    rc = ble_hs_id_infer_auto(0, &address_type);
  }
  if (rc == 0) {
    rc = ble_gatts_find_chr(&kHidServiceUuid.u,
                            &kBootKeyboardInputUuid.u,
                            nullptr, &boot_input_handle);
  }
  if (rc == 0) {
    // The input report is registered before the output report and is the
    // first 0x2A4D value in this fixed service definition.
    rc = ble_gatts_find_chr(&kHidServiceUuid.u, &kReportUuid.u,
                            nullptr, &report_input_handle);
  }
  portENTER_CRITICAL(&g_state.lock);
  g_state.address_type = address_type;
  g_state.boot_input_handle = boot_input_handle;
  g_state.report_input_handle = report_input_handle;
  g_state.synchronized = rc == 0;
  g_state.stage = rc == 0 ? PeripheralStage::kHostSync
                          : PeripheralStage::kFault;
  g_state.error = rc;
  portEXIT_CRITICAL(&g_state.lock);
  if (rc != 0) {
    MarkEvent(kEventFault);
  } else {
    (void)StartAdvertising();
  }
}

void HostTask(void*) {
  nimble_port_run();
  nimble_port_freertos_deinit();
}

void IgnoreOutputReport(std::uint16_t, std::uint8_t, std::uint8_t,
                        const std::uint8_t*, std::uint16_t) {}

void ProtocolModeChanged(std::uint16_t, std::uint16_t characteristic,
                         const std::uint8_t value) {
  if (characteristic != BLE_SVC_HID_CHR_UUID16_PROTOCOL_MODE ||
      (value != BLE_SVC_HID_PROTO_MODE_BOOT &&
       value != BLE_SVC_HID_PROTO_MODE_REPORT)) {
    return;
  }
  portENTER_CRITICAL(&g_state.lock);
  g_state.protocol_mode = value;
  const bool ready = g_state.authenticated && IsSubscribedLocked() &&
                     g_state.initial_release_complete;
  if (ready) {
    g_state.stage = PeripheralStage::kReady;
  }
  portEXIT_CRITICAL(&g_state.lock);
}

bool StartInitialReleaseLocked(const std::uint64_t now_ms) {
  if (!g_state.authenticated || !IsSubscribedLocked() ||
      g_state.release.state() != ReleaseState::idle) {
    return false;
  }
  g_state.initial_release_complete = false;
  g_state.release_for_report = false;
  return g_state.release.Start(g_state.generation,
                               g_state.connection_interval_units, now_ms);
}

int GapEvent(ble_gap_event* event, void*) {
  if (event == nullptr) {
    return 0;
  }
  switch (event->type) {
    case BLE_GAP_EVENT_CONNECT: {
      if (event->connect.status != 0) {
        (void)StartAdvertising();
        return 0;
      }
      ble_gap_conn_desc description{};
      const int found = ble_gap_conn_find(event->connect.conn_handle, &description);
      if (found != 0 || !PeerMatchesOnlyBond(description.peer_id_addr)) {
        (void)ble_gap_terminate(event->connect.conn_handle,
                               BLE_ERR_AUTH_FAIL);
        return 0;
      }
      portENTER_CRITICAL(&g_state.lock);
      g_state.connection_handle = event->connect.conn_handle;
      g_state.connection_interval_units = description.conn_itvl;
      g_state.generation = g_state.generation == UINT32_MAX
                               ? 1
                               : g_state.generation + 1;
      g_state.advertising = false;
      g_state.authenticated = false;
      g_state.boot_subscribed = false;
      g_state.report_subscribed = false;
      g_state.initial_release_complete = false;
      g_state.release_for_report = false;
      g_state.release = ReleaseBurst{};
      g_state.stage = PeripheralStage::kPairing;
      portEXIT_CRITICAL(&g_state.lock);
      ble_gap_upd_params update{};
      update.itvl_min = kMinimumConnectionIntervalUnits;
      update.itvl_max = 40;
      update.latency = 0;
      update.supervision_timeout = 400;
      update.min_ce_len = 0;
      update.max_ce_len = 0;
      (void)ble_gap_update_params(event->connect.conn_handle, &update);
      const int security_rc =
          ble_gap_security_initiate(event->connect.conn_handle);
      // Windows may start encryption before this callback initiates it. NimBLE
      // reports that harmless race as EALREADY; the same security procedure is
      // already in progress and must not be converted into a disconnect.
      if (security_rc != 0 && security_rc != BLE_HS_EALREADY) {
        MarkEvent(kEventFault);
        Terminate();
      }
      return 0;
    }
    case BLE_GAP_EVENT_DISCONNECT: {
      portENTER_CRITICAL(&g_state.lock);
      if (event->disconnect.conn.conn_handle == g_state.connection_handle) {
        g_state.connection_handle = kNoConnection;
        g_state.authenticated = false;
        g_state.boot_subscribed = false;
        g_state.report_subscribed = false;
        g_state.initial_release_complete = false;
        g_state.release_for_report = false;
        g_state.release = ReleaseBurst{};
        g_state.stage = PeripheralStage::kHostSync;
      }
      portEXIT_CRITICAL(&g_state.lock);
      MarkEvent(kEventDisconnected);
      (void)StartAdvertising();
      return 0;
    }
    case BLE_GAP_EVENT_ENC_CHANGE: {
      ble_gap_conn_desc description{};
      const bool secure = event->enc_change.status == 0 &&
                          ble_gap_conn_find(event->enc_change.conn_handle,
                                            &description) == 0 &&
                          description.sec_state.encrypted &&
                          description.sec_state.authenticated &&
                          description.sec_state.bonded &&
                          description.sec_state.key_size == 16 &&
                          PeerMatchesOnlyBond(description.peer_id_addr);
      bool release_started = false;
      portENTER_CRITICAL(&g_state.lock);
      if (secure && event->enc_change.conn_handle == g_state.connection_handle) {
        g_state.authenticated = true;
        g_state.unbonded_advertising_allowed = false;
        static_cast<void>(g_state.enrollment.Authenticated());
        g_state.stage = PeripheralStage::kConnected;
        release_started = StartInitialReleaseLocked(0);
      }
      portEXIT_CRITICAL(&g_state.lock);
      if (!secure) {
        MarkEvent(kEventFault);
        Terminate(BLE_ERR_AUTH_FAIL);
      }
      static_cast<void>(release_started);
      return 0;
    }
    case BLE_GAP_EVENT_PASSKEY_ACTION: {
      ble_sm_io io{};
      io.action = event->passkey.params.action;
      if (io.action != BLE_SM_IOACT_DISP) {
        MarkEvent(kEventFault);
        Terminate(BLE_ERR_AUTH_FAIL);
        return 0;
      }
      portENTER_CRITICAL(&g_state.lock);
      io.passkey = g_state.passkey;
      portEXIT_CRITICAL(&g_state.lock);
      if (ble_sm_inject_io(event->passkey.conn_handle, &io) != 0) {
        MarkEvent(kEventFault);
        Terminate(BLE_ERR_AUTH_FAIL);
      }
      return 0;
    }
    case BLE_GAP_EVENT_REPEAT_PAIRING:
      return BLE_GAP_REPEAT_PAIRING_IGNORE;
    case BLE_GAP_EVENT_SUBSCRIBE: {
      bool release_started = false;
      portENTER_CRITICAL(&g_state.lock);
      if (event->subscribe.conn_handle == g_state.connection_handle) {
        if (event->subscribe.attr_handle == g_state.boot_input_handle) {
          g_state.boot_subscribed = event->subscribe.cur_notify != 0;
        } else if (event->subscribe.attr_handle == g_state.report_input_handle) {
          g_state.report_subscribed = event->subscribe.cur_notify != 0;
        }
        release_started = StartInitialReleaseLocked(0);
      }
      portEXIT_CRITICAL(&g_state.lock);
      static_cast<void>(release_started);
      return 0;
    }
    case BLE_GAP_EVENT_CONN_UPDATE: {
      ble_gap_conn_desc description{};
      if (event->conn_update.status == 0 &&
          ble_gap_conn_find(event->conn_update.conn_handle, &description) == 0) {
        bool release_started = false;
        portENTER_CRITICAL(&g_state.lock);
        if (event->conn_update.conn_handle == g_state.connection_handle) {
          g_state.connection_interval_units = description.conn_itvl;
          release_started = StartInitialReleaseLocked(0);
        }
        portEXIT_CRITICAL(&g_state.lock);
        static_cast<void>(release_started);
      }
      return 0;
    }
    case BLE_GAP_EVENT_ADV_COMPLETE:
      portENTER_CRITICAL(&g_state.lock);
      g_state.advertising = false;
      portEXIT_CRITICAL(&g_state.lock);
      return 0;
    default:
      return 0;
  }
}

bool SubmitFlat(const KeyboardReport& report) {
  std::uint16_t connection_handle;
  std::uint16_t attribute_handle;
  portENTER_CRITICAL(&g_state.lock);
  connection_handle = g_state.connection_handle;
  attribute_handle = g_state.protocol_mode == BLE_SVC_HID_PROTO_MODE_BOOT
                         ? g_state.boot_input_handle
                         : g_state.report_input_handle;
  const bool allowed = connection_handle != kNoConnection &&
                       g_state.authenticated && IsSubscribedLocked();
  portEXIT_CRITICAL(&g_state.lock);
  if (!allowed) {
    return false;
  }
  os_mbuf* packet = ble_hs_mbuf_from_flat(report.data(), report.size());
  return packet != nullptr &&
         ble_gatts_notify_custom(connection_handle, attribute_handle, packet) == 0;
}

}  // namespace

bool IdfBleHidPeripheral::Initialize() {
  if (g_owner != nullptr) {
    return false;
  }
  int rc = nimble_port_init();
  if (rc != 0) {
    return false;
  }
  g_owner = this;
  g_state.passkey = esp_random() % 1000000U;
  g_state.unbonded_advertising_allowed = true;
  g_state.enrollment = EnrollmentWindow{};
  ble_hs_cfg.reset_cb = HostReset;
  ble_hs_cfg.sync_cb = HostSynchronized;
  ble_hs_cfg.sm_io_cap = BLE_HS_IO_DISPLAY_ONLY;
  ble_hs_cfg.sm_bonding = 1;
  ble_hs_cfg.sm_mitm = 1;
  ble_hs_cfg.sm_sc = 1;
  ble_hs_cfg.sm_sc_only = 1;
  ble_hs_cfg.sm_sec_lvl = 4;
  ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
  ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;

  ble_svc_gap_init();
  ble_svc_gatt_init();
  rc = ble_svc_gap_device_name_set("Keyferry Keyboard");
  ble_svc_hid_params params{};
  params.proto_mode_present = 1;
  params.kbd_inp_present = 1;
  params.kbd_out_present = 1;
  params.proto_mode = BLE_SVC_HID_PROTO_MODE_REPORT;
  params.rpts_len = 2;
  params.rpts[0].type = BLE_SVC_HID_RPT_TYPE_INPUT;
  params.rpts[0].id = kKeyboardReportId;
  params.rpts[0].len = KBD_INP_RPT_SIZE;
  params.rpts[1].type = BLE_SVC_HID_RPT_TYPE_OUTPUT;
  params.rpts[1].id = kKeyboardReportId;
  params.rpts[1].len = 1;
  params.report_map_len = kKeyboardReportMap.size();
  std::copy(kKeyboardReportMap.begin(), kKeyboardReportMap.end(),
            params.report_map);
  params.hid_info = 0x00000111;
  if (rc == 0) {
    rc = ble_svc_hid_add(params);
  }
  if (rc != 0) {
    g_owner = nullptr;
    (void)nimble_port_deinit();
    return false;
  }
  ble_svc_hid_register_report_write_cb(IgnoreOutputReport);
  ble_svc_hid_register_char_write_cb(ProtocolModeChanged);
  ble_svc_hid_init();

  portENTER_CRITICAL(&g_state.lock);
  g_state.initialized = true;
  g_state.stage = PeripheralStage::kHostSync;
  g_state.error = 0;
  portEXIT_CRITICAL(&g_state.lock);
  nimble_port_freertos_init(HostTask);
  return true;
}

BondResetResult IdfBleHidPeripheral::ResetBond() {
  bool initialized = false;
  portENTER_CRITICAL(&g_state.lock);
  initialized = g_state.initialized && g_state.synchronized;
  portEXIT_CRITICAL(&g_state.lock);
  if (!initialized) {
    return BondResetResult::kError;
  }

  std::array<ble_addr_t, 2> peers{};
  int count = 0;
  if (ble_store_util_bonded_peers(peers.data(), &count, peers.size()) != 0 ||
      count < 0 || static_cast<std::size_t>(count) > peers.size()) {
    return BondResetResult::kError;
  }
  if (count == 0) {
    return BondResetResult::kNoBond;
  }

  // The control plane is Wi-Fi-only in BLE-HID mode. Disconnecting the
  // keyboard target cannot interrupt the authenticated reset response.
  Terminate();
  for (int index = 0; index < count; ++index) {
    if (ble_store_util_delete_peer(&peers[static_cast<std::size_t>(index)]) != 0) {
      return BondResetResult::kError;
    }
  }

  count = 0;
  if (ble_store_util_bonded_peers(peers.data(), &count, peers.size()) != 0 ||
      count != 0) {
    return BondResetResult::kError;
  }
  return BondResetResult::kForgotten;
}

BondResetResult IdfBleHidPeripheral::ResetBondAndEnroll(
    const std::uint64_t now_ms) {
  const auto result = ResetBond();
  if (result == BondResetResult::kError) {
    return result;
  }
  portENTER_CRITICAL(&g_state.lock);
  g_state.passkey = esp_random() % 1000000U;
  g_state.unbonded_advertising_allowed = true;
  g_state.enrollment.Start(now_ms);
  const bool synchronized = g_state.synchronized;
  const bool disconnected = g_state.connection_handle == kNoConnection;
  const bool advertising = g_state.advertising;
  portEXIT_CRITICAL(&g_state.lock);
  if (synchronized && disconnected && !advertising) {
    (void)StartAdvertising();
  }
  return result;
}

bool IdfBleHidPeripheral::CancelEnrollment() {
  portENTER_CRITICAL(&g_state.lock);
  const bool active = g_state.enrollment.Cancel();
  const bool disconnect = active && !g_state.authenticated &&
                          g_state.connection_handle != kNoConnection;
  const bool stop_advertising = active && g_state.advertising;
  g_state.unbonded_advertising_allowed = false;
  if (active && !g_state.authenticated) {
    g_state.stage = PeripheralStage::kHostSync;
  }
  portEXIT_CRITICAL(&g_state.lock);
  if (disconnect) {
    Terminate();
  }
  if (stop_advertising) {
    (void)ble_gap_adv_stop();
  }
  return active;
}

PeripheralEvents IdfBleHidPeripheral::Poll(const std::uint64_t now_ms) {
  KeyboardReport zero{};
  bool submit_zero = false;
  bool enrollment_expired = false;
  bool disconnect_pairing = false;
  bool stop_advertising = false;
  std::uint32_t generation = 0;
  portENTER_CRITICAL(&g_state.lock);
  if (g_state.enrollment.Poll(now_ms)) {
    g_state.unbonded_advertising_allowed = false;
    enrollment_expired = true;
    disconnect_pairing = !g_state.authenticated &&
                         g_state.connection_handle != kNoConnection;
    stop_advertising = g_state.advertising;
    if (!g_state.authenticated) {
      g_state.stage = PeripheralStage::kHostSync;
    }
  }
  generation = g_state.generation;
  submit_zero = g_state.release.Poll(generation, now_ms) ==
                ReleaseState::submit_zero;
  portEXIT_CRITICAL(&g_state.lock);
  if (enrollment_expired) {
    if (disconnect_pairing) {
      Terminate();
    }
    if (stop_advertising) {
      (void)ble_gap_adv_stop();
    }
  }
  if (submit_zero) {
    const bool accepted = SubmitFlat(zero);
    portENTER_CRITICAL(&g_state.lock);
    if (generation == g_state.generation && accepted) {
      (void)g_state.release.MarkZeroAccepted(generation, now_ms);
      if (g_state.release.state() == ReleaseState::complete) {
        if (g_state.release_for_report) {
          MarkEvent(kEventReleaseComplete);
        } else {
          g_state.initial_release_complete = true;
          g_state.stage = PeripheralStage::kReady;
        }
      }
    } else {
      (void)g_state.release.MarkZeroFailed(generation);
      if (g_state.release.state() == ReleaseState::disconnect_required) {
        MarkEvent(kEventDisconnectRequired);
      }
    }
    portEXIT_CRITICAL(&g_state.lock);
  }
  const auto event_bits = g_state.events.exchange(0, std::memory_order_acq_rel);
  const PeripheralEvents events{
      (event_bits & kEventDisconnected) != 0,
      (event_bits & kEventReleaseComplete) != 0,
      (event_bits & kEventDisconnectRequired) != 0,
      (event_bits & kEventFault) != 0,
  };
  if (events.disconnect_required) {
    Terminate();
  }
  return events;
}

bool IdfBleHidPeripheral::Submit(const KeyboardReport& report,
                                 const std::uint64_t now_ms) {
  bool accepted = false;
  bool submit_nonzero = false;
  std::uint32_t generation = 0;
  portENTER_CRITICAL(&g_state.lock);
  if (g_owner == this && g_state.initial_release_complete &&
      g_state.release.state() == ReleaseState::complete) {
    if (IsZero(report)) {
      g_state.release = ReleaseBurst{};
      g_state.release_for_report = true;
      accepted = g_state.release.Start(g_state.generation,
                                       g_state.connection_interval_units,
                                       now_ms);
    } else {
      submit_nonzero = true;
      generation = g_state.generation;
    }
  }
  portEXIT_CRITICAL(&g_state.lock);
  if (submit_nonzero) {
    accepted = SubmitFlat(report);
    portENTER_CRITICAL(&g_state.lock);
    accepted = accepted && generation == g_state.generation;
    portEXIT_CRITICAL(&g_state.lock);
  }
  return accepted;
}

void IdfBleHidPeripheral::Disconnect() { Terminate(); }

bool IdfBleHidPeripheral::ready() const {
  portENTER_CRITICAL(&g_state.lock);
  const bool value = g_owner == this && g_state.stage == PeripheralStage::kReady &&
                     g_state.authenticated && IsSubscribedLocked() &&
                     g_state.initial_release_complete;
  portEXIT_CRITICAL(&g_state.lock);
  return value;
}

PeripheralStatus IdfBleHidPeripheral::status() const {
  portENTER_CRITICAL(&g_state.lock);
  const PeripheralStatus value{
      g_state.stage,
      g_state.error,
      g_state.generation,
      g_state.passkey,
      g_state.advertising,
      g_state.connection_handle != kNoConnection,
      g_state.authenticated,
      IsSubscribedLocked(),
      g_owner == this && g_state.stage == PeripheralStage::kReady,
  };
  portEXIT_CRITICAL(&g_state.lock);
  return value;
}

BondStoreStatus IdfBleHidPeripheral::bond_status() const {
  bool initialized = false;
  portENTER_CRITICAL(&g_state.lock);
  initialized = g_state.initialized && g_state.synchronized;
  portEXIT_CRITICAL(&g_state.lock);
  if (!initialized) {
    return {BondStoreState::kStoreError, BLE_HS_ENOTSYNCED};
  }
  return ReadBondInventory(nullptr).status;
}

EnrollmentStatus IdfBleHidPeripheral::enrollment_status(
    const std::uint64_t now_ms) const {
  portENTER_CRITICAL(&g_state.lock);
  const auto status = g_state.enrollment.Status(now_ms);
  portEXIT_CRITICAL(&g_state.lock);
  return status;
}

}  // namespace keyferry::ble_hid
