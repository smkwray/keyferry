#include "keyferry/idf_ble_transport.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "os/os_mbuf.h"
#include "services/gatt/ble_svc_gatt.h"

namespace keyferry::ble {
namespace {

constexpr std::uint16_t kNoConnection = BLE_HS_CONN_HANDLE_NONE;
constexpr std::uint32_t kEventConnected = 1U << 0U;
constexpr std::uint32_t kEventReady = 1U << 1U;
constexpr std::uint32_t kEventBytes = 1U << 2U;
constexpr std::uint32_t kEventDisconnected = 1U << 3U;
constexpr std::uint32_t kEventFault = 1U << 4U;
constexpr std::uint64_t kHostSyncTimeoutMs = 5000;

std::uint64_t NowMs() {
  return static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
}

ble_uuid128_t ReversedUuid(const std::array<std::uint8_t, 16>& source) {
  ble_uuid128_t output{};
  output.u.type = BLE_UUID_TYPE_128;
  std::reverse_copy(source.begin(), source.end(), output.value);
  return output;
}

struct State {
  portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
  BytePipe pipe;
  std::atomic<std::uint32_t> events{0};
  ble_uuid128_t service_uuid{};
  ble_uuid128_t gateway_to_device_uuid{};
  ble_uuid128_t device_to_gateway_uuid{};
  ble_gatt_chr_def characteristics[3]{};
  ble_gatt_svc_def services[2]{};
  std::uint16_t connection_handle = kNoConnection;
  std::uint16_t indication_handle = 0;
  std::uint32_t generation = 0;
  std::uint8_t address_type = 0;
  bool initialized = false;
  bool synchronized = false;
  bool advertise_requested = false;
  bool advertising = false;
  PeripheralStage stage = PeripheralStage::kOff;
  std::int32_t last_error = 0;
  std::uint64_t synchronization_deadline_ms = 0;
};

State g_state;
IdfBlePeripheral* g_owner = nullptr;

void MarkEvent(std::uint32_t event) {
  g_state.events.fetch_or(event, std::memory_order_release);
}

void TerminateCurrent() {
  std::uint16_t handle;
  portENTER_CRITICAL(&g_state.lock);
  handle = g_state.connection_handle;
  portEXIT_CRITICAL(&g_state.lock);
  if (handle != kNoConnection) {
    (void)ble_gap_terminate(handle, BLE_ERR_REM_USER_CONN_TERM);
  }
}

bool StopAdvertisingAndReconcile() {
  const int rc = ble_gap_adv_stop();
  bool stopped;
  portENTER_CRITICAL(&g_state.lock);
  stopped = ReconcileAdvertisingStopState(
      rc, BLE_HS_EALREADY, &g_state.advertising);
  if (stopped) {
    if (g_state.stage == PeripheralStage::kAdvertising &&
        g_state.connection_handle == kNoConnection) {
      g_state.stage = PeripheralStage::kHostSync;
      g_state.last_error = 0;
    }
  } else {
    g_state.stage = PeripheralStage::kFault;
    g_state.last_error = rc;
  }
  portEXIT_CRITICAL(&g_state.lock);
  if (!stopped) {
    MarkEvent(kEventFault);
  }
  return stopped;
}

int GapEvent(ble_gap_event* event, void*);

bool BeginAdvertising() {
  portENTER_CRITICAL(&g_state.lock);
  if (!g_state.initialized || !g_state.synchronized ||
      !g_state.advertise_requested || g_state.advertising ||
      g_state.connection_handle != kNoConnection) {
    portEXIT_CRITICAL(&g_state.lock);
    return false;
  }
  g_state.advertising = true;
  portEXIT_CRITICAL(&g_state.lock);

  ble_hs_adv_fields fields{};
  fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
  fields.uuids128 = &g_state.service_uuid;
  fields.num_uuids128 = 1;
  fields.uuids128_is_complete = 1;
  int rc = ble_gap_adv_set_fields(&fields);
  if (rc != 0) {
    portENTER_CRITICAL(&g_state.lock);
    g_state.stage = PeripheralStage::kAdvertisingFields;
    g_state.last_error = rc;
    portEXIT_CRITICAL(&g_state.lock);
  }
  if (rc == 0) {
    ble_gap_adv_params parameters{};
    parameters.conn_mode = BLE_GAP_CONN_MODE_UND;
    parameters.disc_mode = BLE_GAP_DISC_MODE_GEN;
    rc = ble_gap_adv_start(g_state.address_type, nullptr, BLE_HS_FOREVER,
                           &parameters, GapEvent, nullptr);
    if (rc != 0) {
      portENTER_CRITICAL(&g_state.lock);
      g_state.stage = PeripheralStage::kAdvertisingStart;
      g_state.last_error = rc;
      portEXIT_CRITICAL(&g_state.lock);
    }
  }
  if (rc != 0) {
    portENTER_CRITICAL(&g_state.lock);
    g_state.advertising = false;
    portEXIT_CRITICAL(&g_state.lock);
    MarkEvent(kEventFault);
    return false;
  }
  portENTER_CRITICAL(&g_state.lock);
  g_state.stage = PeripheralStage::kAdvertising;
  g_state.last_error = 0;
  portEXIT_CRITICAL(&g_state.lock);
  // Start/stop run on different FreeRTOS tasks. If Stop won the race while
  // NimBLE was starting the advertiser, immediately retract it. A concurrent
  // connection is rejected by GapEvent using the same request bit.
  portENTER_CRITICAL(&g_state.lock);
  const bool still_requested = g_state.advertise_requested;
  portEXIT_CRITICAL(&g_state.lock);
  if (!still_requested) {
    (void)StopAdvertisingAndReconcile();
  }
  return true;
}

void HostReset(const int reason) {
  portENTER_CRITICAL(&g_state.lock);
  g_state.synchronized = false;
  g_state.advertising = false;
  g_state.stage = PeripheralStage::kFault;
  g_state.last_error = reason;
  portEXIT_CRITICAL(&g_state.lock);
  MarkEvent(kEventFault);
}

void HostSynchronized() {
  std::uint8_t address_type = 0;
  // The mutually exclusive direct-HID personality has a different GATT
  // database and may be bonded by the operating system. Reusing that identity
  // for this unpaired byte pipe lets a central apply the keyboard's cached
  // attribute database to the gateway. Give the gateway a fresh static-random
  // identity each boot while leaving the direct-HID identity and bond intact.
  ble_addr_t gateway_address{};
  int rc = ble_hs_id_gen_rnd(0, &gateway_address);
  if (rc == 0) {
    rc = ble_hs_id_set_rnd(gateway_address.val);
  }
  if (rc == 0) {
    rc = ble_hs_util_ensure_addr(0);
  }
  if (rc == 0) {
    rc = ble_hs_id_infer_auto(0, &address_type);
  }
  if (rc != 0) {
    portENTER_CRITICAL(&g_state.lock);
    g_state.stage = PeripheralStage::kAddress;
    g_state.last_error = rc;
    portEXIT_CRITICAL(&g_state.lock);
    MarkEvent(kEventFault);
    return;
  }
  bool should_advertise;
  portENTER_CRITICAL(&g_state.lock);
  g_state.address_type = address_type;
  g_state.synchronized = true;
  g_state.synchronization_deadline_ms = 0;
  g_state.stage = PeripheralStage::kHostSync;
  g_state.last_error = 0;
  should_advertise = g_state.advertise_requested;
  portEXIT_CRITICAL(&g_state.lock);
  if (should_advertise) {
    (void)BeginAdvertising();
  }
}

void HostTask(void*) {
  nimble_port_run();
  nimble_port_freertos_deinit();
}

int CharacteristicAccess(std::uint16_t connection_handle, std::uint16_t,
                         ble_gatt_access_ctxt* context, void*) {
  if (context == nullptr || context->op != BLE_GATT_ACCESS_OP_WRITE_CHR ||
      context->om == nullptr) {
    return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
  }
  const auto size = static_cast<std::size_t>(OS_MBUF_PKTLEN(context->om));
  std::array<std::uint8_t, protocol::kBleMaximumFragmentBytes> fragment{};
  std::uint16_t copied = 0;
  if (size == 0 || size > fragment.size() ||
      ble_hs_mbuf_to_flat(context->om, fragment.data(), fragment.size(),
                          &copied) != 0 ||
      copied != size) {
    return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
  }

  const auto now_ms = NowMs();
  bool accepted = false;
  portENTER_CRITICAL(&g_state.lock);
  if (connection_handle == g_state.connection_handle) {
    accepted = g_state.pipe.ReceiveWrite(g_state.generation, fragment.data(),
                                         copied, now_ms);
  }
  portEXIT_CRITICAL(&g_state.lock);
  if (!accepted) {
    MarkEvent(kEventFault);
    TerminateCurrent();
    return BLE_ATT_ERR_INSUFFICIENT_RES;
  }
  MarkEvent(kEventBytes);
  return 0;
}

int IndicationAccess(std::uint16_t, std::uint16_t,
                     ble_gatt_access_ctxt*, void*) {
  // NimBLE requires every characteristic to have an access callback. This
  // characteristic remains indicate-only; direct ATT reads/writes never gain
  // access to the outbound TLS byte stream.
  return BLE_ATT_ERR_READ_NOT_PERMITTED;
}

int GapEvent(ble_gap_event* event, void*) {
  if (event == nullptr) {
    return 0;
  }
  switch (event->type) {
    case BLE_GAP_EVENT_CONNECT: {
      if (event->connect.status != 0) {
        portENTER_CRITICAL(&g_state.lock);
        g_state.advertising = false;
        portEXIT_CRITICAL(&g_state.lock);
        MarkEvent(kEventFault);
        return 0;
      }
      const auto att_mtu = ble_att_mtu(event->connect.conn_handle);
      const auto now_ms = NowMs();
      bool accepted = false;
      portENTER_CRITICAL(&g_state.lock);
      if (g_state.advertise_requested &&
          g_state.connection_handle == kNoConnection) {
        g_state.advertising = false;
        g_state.advertise_requested = false;
        g_state.connection_handle = event->connect.conn_handle;
        g_state.stage = PeripheralStage::kConnected;
        g_state.last_error = 0;
        g_state.generation =
            g_state.generation == UINT32_MAX ? 1 : g_state.generation + 1;
        accepted =
            g_state.pipe.Connect(g_state.generation, att_mtu, now_ms);
      }
      portEXIT_CRITICAL(&g_state.lock);
      if (!accepted) {
        MarkEvent(kEventFault);
        (void)ble_gap_terminate(event->connect.conn_handle,
                               BLE_ERR_REM_USER_CONN_TERM);
      } else {
        MarkEvent(kEventConnected);
      }
      return 0;
    }
    case BLE_GAP_EVENT_DISCONNECT: {
      bool should_advertise = false;
      portENTER_CRITICAL(&g_state.lock);
      if (event->disconnect.conn.conn_handle == g_state.connection_handle) {
        (void)g_state.pipe.Disconnect(g_state.generation);
        g_state.connection_handle = kNoConnection;
        g_state.advertising = false;
        should_advertise = g_state.advertise_requested;
    }
      portEXIT_CRITICAL(&g_state.lock);
      MarkEvent(kEventDisconnected);
      if (should_advertise) {
        (void)BeginAdvertising();
      }
      return 0;
      }
    case BLE_GAP_EVENT_SUBSCRIBE: {
      if (event->subscribe.attr_handle != g_state.indication_handle) {
        return 0;
      }
      const auto now_ms = NowMs();
      bool ready = false;
      portENTER_CRITICAL(&g_state.lock);
      if (event->subscribe.conn_handle == g_state.connection_handle) {
        ready = g_state.pipe.SetIndications(
            g_state.generation, event->subscribe.cur_indicate != 0, now_ms);
      }
      portEXIT_CRITICAL(&g_state.lock);
      MarkEvent(ready ? kEventReady : kEventFault);
      if (!ready) {
        TerminateCurrent();
      }
      return 0;
    }
    case BLE_GAP_EVENT_MTU: {
      bool updated = false;
      portENTER_CRITICAL(&g_state.lock);
      if (event->mtu.conn_handle == g_state.connection_handle) {
        updated =
            g_state.pipe.UpdateMtu(g_state.generation, event->mtu.value);
      }
      portEXIT_CRITICAL(&g_state.lock);
      if (!updated) {
        MarkEvent(kEventFault);
        TerminateCurrent();
      }
      return 0;
    }
    case BLE_GAP_EVENT_NOTIFY_TX: {
      if (!event->notify_tx.indication ||
          event->notify_tx.attr_handle != g_state.indication_handle) {
        return 0;
      }
      // NimBLE reports status 0 when the indication command is transmitted,
      // then BLE_HS_EDONE when its acknowledgement arrives. The first event
      // is progress, not completion and not a fault.
      if (event->notify_tx.status == 0) {
        return 0;
      }
      const bool success = event->notify_tx.status == BLE_HS_EDONE;
      const auto now_ms = NowMs();
      bool completed = false;
      portENTER_CRITICAL(&g_state.lock);
      if (event->notify_tx.conn_handle == g_state.connection_handle) {
        completed = g_state.pipe.CompleteIndication(
            g_state.generation, success, now_ms);
      }
      portEXIT_CRITICAL(&g_state.lock);
      if (!completed) {
        MarkEvent(kEventFault);
        TerminateCurrent();
      }
      return 0;
    }
    case BLE_GAP_EVENT_ADV_COMPLETE: {
      bool unexpected;
      portENTER_CRITICAL(&g_state.lock);
      g_state.advertising = false;
      unexpected = g_state.advertise_requested;
      portEXIT_CRITICAL(&g_state.lock);
      if (unexpected) {
        MarkEvent(kEventFault);
      }
      return 0;
    }
    default:
      return 0;
  }
}

void ConfigureGattDatabase() {
  g_state.service_uuid = ReversedUuid(protocol::kBleServiceUuid);
  g_state.gateway_to_device_uuid =
      ReversedUuid(protocol::kBleGatewayToDeviceUuid);
  g_state.device_to_gateway_uuid =
      ReversedUuid(protocol::kBleDeviceToGatewayUuid);

  g_state.characteristics[0].uuid = &g_state.gateway_to_device_uuid.u;
  g_state.characteristics[0].access_cb = CharacteristicAccess;
  g_state.characteristics[0].flags = BLE_GATT_CHR_F_WRITE;
  g_state.characteristics[1].uuid = &g_state.device_to_gateway_uuid.u;
  g_state.characteristics[1].access_cb = IndicationAccess;
  g_state.characteristics[1].val_handle = &g_state.indication_handle;
  g_state.characteristics[1].flags = BLE_GATT_CHR_F_INDICATE;
  g_state.services[0].type = BLE_GATT_SVC_TYPE_PRIMARY;
  g_state.services[0].uuid = &g_state.service_uuid.u;
  g_state.services[0].characteristics = g_state.characteristics;
}

}  // namespace

PeripheralInitialization IdfBlePeripheral::Initialize() {
  if (g_owner != nullptr) {
    return {false, PeripheralStage::kPortInit, BLE_HS_EALREADY};
  }
  int rc = nimble_port_init();
  if (rc != 0) {
    portENTER_CRITICAL(&g_state.lock);
    g_state.stage = PeripheralStage::kPortInit;
    g_state.last_error = rc;
    portEXIT_CRITICAL(&g_state.lock);
    return {false, PeripheralStage::kPortInit, rc};
  }
  g_owner = this;
  ConfigureGattDatabase();
  ble_hs_cfg.reset_cb = HostReset;
  ble_hs_cfg.sync_cb = HostSynchronized;
  ble_svc_gatt_init();
  rc = ble_gatts_count_cfg(g_state.services);
  if (rc != 0) {
    portENTER_CRITICAL(&g_state.lock);
    g_state.stage = PeripheralStage::kGattCount;
    g_state.last_error = rc;
    portEXIT_CRITICAL(&g_state.lock);
    g_owner = nullptr;
    (void)nimble_port_deinit();
    return {false, PeripheralStage::kGattCount, rc};
  }
  rc = ble_gatts_add_svcs(g_state.services);
  if (rc != 0) {
    portENTER_CRITICAL(&g_state.lock);
    g_state.stage = PeripheralStage::kGattAdd;
    g_state.last_error = rc;
    portEXIT_CRITICAL(&g_state.lock);
    g_owner = nullptr;
    (void)nimble_port_deinit();
    return {false, PeripheralStage::kGattAdd, rc};
  }
  portENTER_CRITICAL(&g_state.lock);
  g_state.initialized = true;
  g_state.stage = PeripheralStage::kHostSync;
  g_state.last_error = 0;
  portEXIT_CRITICAL(&g_state.lock);
  nimble_port_freertos_init(HostTask);
  return {true, PeripheralStage::kHostSync, 0};
}

bool IdfBlePeripheral::StartAdvertising() {
  bool synchronized;
  bool connected;
  portENTER_CRITICAL(&g_state.lock);
  if (g_owner != this || !g_state.initialized) {
    portEXIT_CRITICAL(&g_state.lock);
    return false;
  }
  g_state.advertise_requested = true;
  g_state.synchronization_deadline_ms = NowMs() + kHostSyncTimeoutMs;
  synchronized = g_state.synchronized;
  connected = g_state.connection_handle != kNoConnection;
  portEXIT_CRITICAL(&g_state.lock);
  return connected || !synchronized || BeginAdvertising();
}

PeripheralEvents IdfBlePeripheral::Poll(std::uint64_t now_ms) {
  PeripheralEvents result{};
  const auto events = g_state.events.exchange(0, std::memory_order_acq_rel);
  bool terminate = false;
  bool synchronization_timed_out = false;
  portENTER_CRITICAL(&g_state.lock);
  result.generation = g_state.generation;
  if (g_state.connection_handle != kNoConnection &&
      !g_state.pipe.Poll(now_ms)) {
    terminate = true;
  }
  result.fault = g_state.pipe.fault();
  if (g_state.advertise_requested && !g_state.synchronized &&
      g_state.synchronization_deadline_ms != 0 &&
      now_ms >= g_state.synchronization_deadline_ms) {
    g_state.synchronization_deadline_ms = 0;
    g_state.stage = PeripheralStage::kHostSync;
    g_state.last_error = BLE_HS_ETIMEOUT;
    synchronization_timed_out = true;
  }
  portEXIT_CRITICAL(&g_state.lock);
  result.connected = (events & kEventConnected) != 0;
  result.ready = (events & kEventReady) != 0;
  result.bytes_available = (events & kEventBytes) != 0;
  result.disconnected = (events & kEventDisconnected) != 0;
  if (((events & kEventFault) != 0 || synchronization_timed_out) &&
      result.fault == Fault::kNone) {
    result.fault = Fault::kBadState;
  }
  if (terminate) {
    MarkEvent(kEventFault);
    TerminateCurrent();
  }
  return result;
}

std::size_t IdfBlePeripheral::Read(std::uint8_t* output,
                                   std::size_t capacity) {
  portENTER_CRITICAL(&g_state.lock);
  const auto size = g_state.pipe.Read(output, capacity);
  portEXIT_CRITICAL(&g_state.lock);
  return size;
}

bool IdfBlePeripheral::Send(std::uint32_t generation,
                            const std::uint8_t* data, std::size_t size,
                            std::uint64_t now_ms) {
  std::uint16_t connection_handle;
  bool staged;
  portENTER_CRITICAL(&g_state.lock);
  connection_handle = g_state.connection_handle;
  staged = connection_handle != kNoConnection &&
           g_state.pipe.StageIndication(generation, data, size, now_ms);
  portEXIT_CRITICAL(&g_state.lock);
  if (!staged) {
    MarkEvent(kEventFault);
    TerminateCurrent();
    return false;
  }
  os_mbuf* packet = ble_hs_mbuf_from_flat(data, size);
  if (packet == nullptr ||
      ble_gatts_indicate_custom(connection_handle, g_state.indication_handle,
                                packet) != 0) {
    portENTER_CRITICAL(&g_state.lock);
    (void)g_state.pipe.CompleteIndication(generation, false, now_ms);
    portEXIT_CRITICAL(&g_state.lock);
    MarkEvent(kEventFault);
    TerminateCurrent();
    return false;
  }
  return true;
}

void IdfBlePeripheral::Stop() {
  bool advertising;
  portENTER_CRITICAL(&g_state.lock);
  g_state.advertise_requested = false;
  g_state.synchronization_deadline_ms = 0;
  advertising = g_state.advertising;
  portEXIT_CRITICAL(&g_state.lock);
  TerminateCurrent();
  if (advertising) {
    (void)StopAdvertisingAndReconcile();
  }
}

void IdfBlePeripheral::Disconnect() { TerminateCurrent(); }

bool IdfBlePeripheral::initialized() const {
  portENTER_CRITICAL(&g_state.lock);
  const bool initialized = g_owner == this && g_state.initialized;
  portEXIT_CRITICAL(&g_state.lock);
  return initialized;
}

bool IdfBlePeripheral::ready(std::uint32_t generation) const {
  portENTER_CRITICAL(&g_state.lock);
  const bool ready = g_owner == this && g_state.generation == generation &&
                     g_state.pipe.ready();
  portEXIT_CRITICAL(&g_state.lock);
  return ready;
}

bool IdfBlePeripheral::can_send(std::uint32_t generation) const {
  portENTER_CRITICAL(&g_state.lock);
  const bool can_send =
      g_owner == this && g_state.generation == generation &&
      g_state.pipe.ready() && !g_state.pipe.indication_pending();
  portEXIT_CRITICAL(&g_state.lock);
  return can_send;
}

std::size_t IdfBlePeripheral::fragment_capacity(
    std::uint32_t generation) const {
  portENTER_CRITICAL(&g_state.lock);
  const auto capacity =
      g_owner == this && g_state.generation == generation &&
              g_state.pipe.ready()
          ? g_state.pipe.fragment_capacity()
          : 0;
  portEXIT_CRITICAL(&g_state.lock);
  return capacity;
}

PeripheralStatus IdfBlePeripheral::status() const {
  portENTER_CRITICAL(&g_state.lock);
  const PeripheralStatus result{g_state.stage, g_state.last_error,
                                g_owner == this && g_state.initialized,
                                g_state.synchronized, g_state.advertising};
  portEXIT_CRITICAL(&g_state.lock);
  return result;
}

}  // namespace keyferry::ble
