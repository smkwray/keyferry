// Keep Awake (ADR 0018): a standalone relative mouse that, after an explicit local Start, sends a
// (+1, 0) then (-1, 0) pair every 25 s. Stops on unplug, suspend or an unconfirmed report.
#include "keep_awake.h"
#include "keyferry/handheld.h"

#include <atomic>
#include <cstdio>

#include "class/hid/hid_device.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"

namespace keyferry::handheld {
namespace {

constexpr char kTag[] = "keep_awake";
constexpr std::int64_t kNudgeIntervalUs = 25 * 1000 * 1000;
constexpr TickType_t kReportTimeout = pdMS_TO_TICKS(500);
constexpr std::uint16_t kKeepAwakePid = 0x4010;  // distinct from every keyferry personality

constexpr std::uint8_t kReportDescriptor[] = {TUD_HID_REPORT_DESC_MOUSE()};
constexpr std::uint16_t kConfigLength = TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN;
constexpr std::uint8_t kConfigDescriptor[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, kConfigLength, 0, 100),
    TUD_HID_DESCRIPTOR(0, 4, HID_ITF_PROTOCOL_NONE, sizeof(kReportDescriptor), 0x81, 8, 10),
};
const tusb_desc_device_t kDeviceDescriptor = {
    sizeof(tusb_desc_device_t), TUSB_DESC_DEVICE, 0x0200, 0x00, 0x00, 0x00,
    CFG_TUD_ENDPOINT0_SIZE, TINYUSB_ESPRESSIF_VID, kKeepAwakePid, 0x0100, 1, 2, 3, 1,
};
char g_serial[13] = "000000000000";
const char* g_strings[] = {"\x09\x04", "Keyferry", "Keyferry Keep Awake", g_serial,
                           "Keep Awake mouse"};

SemaphoreHandle_t g_report_done = nullptr;
std::atomic<bool> g_running{false};
std::atomic<KeepAwakeState> g_state{KeepAwakeState::kReady};
std::atomic<std::uint32_t> g_nudges{0};
std::atomic<bool> g_usb_owned{false};

bool SendAndConfirm(std::int8_t dx) {
  xSemaphoreTake(g_report_done, 0);  // drop any stale completion
  if (!tud_hid_mouse_report(0, 0, dx, 0, 0, 0)) return false;
  return xSemaphoreTake(g_report_done, kReportTimeout) == pdTRUE;
}

void StopWith(KeepAwakeState state) {
  g_running.store(false);
  g_state.store(state);
  ESP_LOGI(kTag, "stopped: state=%d nudges=%u", static_cast<int>(state),
           static_cast<unsigned>(g_nudges.load()));
}

void NudgeTask(void*) {
  std::int64_t next_due = 0;
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(50));
    if (!g_running.load()) {
      next_due = 0;
      continue;
    }
    if (!tud_mounted()) {
      StopWith(KeepAwakeState::kStoppedUnplugged);
      continue;
    }
    if (tud_suspended()) {
      StopWith(KeepAwakeState::kStoppedSuspended);
      continue;
    }
    const std::int64_t now = esp_timer_get_time();
    if (now < next_due || !tud_hid_ready()) continue;
    if (!SendAndConfirm(1)) {
      StopWith(KeepAwakeState::kStoppedUnconfirmed);
      continue;
    }
    vTaskDelay(pdMS_TO_TICKS(20));  // the return leg goes out on a later poll
    if (!SendAndConfirm(-1)) {
      StopWith(KeepAwakeState::kStoppedUnconfirmed);
      continue;
    }
    g_nudges.fetch_add(1);
    next_due = esp_timer_get_time() + kNudgeIntervalUs;
  }
}

}  // namespace

bool KeepAwakeStartUsb() {
  std::uint8_t mac[6] = {};
  if (esp_read_mac(mac, ESP_MAC_WIFI_STA) == ESP_OK) {
    std::snprintf(g_serial, sizeof(g_serial), "%02X%02X%02X%02X%02X%02X", mac[0], mac[1],
                  mac[2], mac[3], mac[4], mac[5]);
  }
  g_report_done = xSemaphoreCreateBinary();
  // Claim the HID callbacks before TinyUSB starts: its task can serve descriptor requests before
  // tinyusb_driver_install() returns. A failed install restarts to Home, so the claim never leaks.
  g_usb_owned.store(true);
  tinyusb_config_t config = TINYUSB_DEFAULT_CONFIG();
  config.descriptor.device = &kDeviceDescriptor;
  config.descriptor.full_speed_config = kConfigDescriptor;
  config.descriptor.string = g_strings;
  config.descriptor.string_count = sizeof(g_strings) / sizeof(g_strings[0]);
  if (g_report_done == nullptr || tinyusb_driver_install(&config) != ESP_OK) {
    ESP_LOGE(kTag, "USB mouse could not start");
    return false;
  }
  xTaskCreate(NudgeTask, "kf_keep_awake", 3072, nullptr, 4, nullptr);
  return true;
}

void KeepAwakeSetRunning(bool running) {
  if (running) {
    g_state.store(KeepAwakeState::kRunning);
    g_running.store(true);
    ESP_LOGI(kTag, "started");
  } else if (g_running.load()) {
    StopWith(KeepAwakeState::kReady);
  }
}

bool KeepAwakeRunning() { return g_running.load(); }
KeepAwakeState KeepAwakeStateNow() { return g_state.load(); }
std::uint32_t KeepAwakeNudges() { return g_nudges.load(); }
bool KeepAwakeUsbMounted() { return tud_mounted(); }

bool UsbOwnedByHandheld() { return g_usb_owned.load(); }

const std::uint8_t* HandheldHidReportDescriptor(std::uint8_t) { return kReportDescriptor; }

void HandheldHidReportComplete(std::uint8_t) {
  if (g_report_done != nullptr) xSemaphoreGive(g_report_done);
}

}  // namespace keyferry::handheld

#if !defined(KEYFERRY_HANDHELD_KEYFERRY)
// Check image: no bridge is linked, so these callbacks live here.
extern "C" std::uint8_t const* tud_hid_descriptor_report_cb(std::uint8_t instance) {
  return keyferry::handheld::HandheldHidReportDescriptor(instance);
}

extern "C" std::uint16_t tud_hid_get_report_cb(std::uint8_t, std::uint8_t, hid_report_type_t,
                                               std::uint8_t*, std::uint16_t) {
  return 0;
}

extern "C" void tud_hid_set_report_cb(std::uint8_t, std::uint8_t, hid_report_type_t,
                                      std::uint8_t const*, std::uint16_t) {}

extern "C" void tud_hid_report_complete_cb(std::uint8_t instance, std::uint8_t const*,
                                           std::uint16_t) {
  keyferry::handheld::HandheldHidReportComplete(instance);
}
#endif
