// The handheld's own USB HID device (Keep Awake, Macros): descriptors, install and confirmed
// report sends. Keyferry's bridge never runs in the same boot.
#include "usb_hid.h"
#include "keyferry/handheld.h"

#include <atomic>
#include <cstdio>
#include <cstring>

#include "class/hid/hid_device.h"
#include "device/usbd_pvt.h"  // usbd_defer_func: run on the TinyUSB task (pinned TinyUSB 0.21)
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"

namespace keyferry::handheld {
namespace {

constexpr char kTag[] = "usb_hid";
constexpr std::int64_t kReportTimeoutUs = 500000;
constexpr std::int64_t kReadyWaitUs = 100000;

constexpr std::uint8_t kMouseDescriptor[] = {TUD_HID_REPORT_DESC_MOUSE()};
constexpr std::uint8_t kMacroPadDescriptor[] = {
    TUD_HID_REPORT_DESC_KEYBOARD(HID_REPORT_ID(kReportKeyboard)),
    TUD_HID_REPORT_DESC_MOUSE(HID_REPORT_ID(kReportMouse)),
    TUD_HID_REPORT_DESC_CONSUMER(HID_REPORT_ID(kReportMedia)),
};

constexpr std::uint16_t kConfigLength = TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN;
constexpr std::uint8_t kMouseConfig[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, kConfigLength, 0, 100),
    TUD_HID_DESCRIPTOR(0, 4, HID_ITF_PROTOCOL_NONE, sizeof(kMouseDescriptor), 0x81, 8, 10),
};
constexpr std::uint8_t kMacroPadConfig[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, kConfigLength, 0, 100),
    TUD_HID_DESCRIPTOR(0, 4, HID_ITF_PROTOCOL_NONE, sizeof(kMacroPadDescriptor), 0x81, 16, 5),
};

tusb_desc_device_t Device(std::uint16_t pid) {
  return {sizeof(tusb_desc_device_t), TUSB_DESC_DEVICE, 0x0200, 0x00, 0x00, 0x00,
          CFG_TUD_ENDPOINT0_SIZE, TINYUSB_ESPRESSIF_VID, pid, 0x0100, 1, 2, 3, 1};
}
const tusb_desc_device_t kMouseDevice = Device(0x4010);  // distinct from every keyferry personality
const tusb_desc_device_t kMacroPadDevice = Device(0x4011);

char g_serial[13] = "000000000000";
const char* g_mouse_strings[] = {"\x09\x04", "Keyferry", "Keyferry Keep Awake", g_serial,
                                 "Keep Awake mouse"};
const char* g_macro_strings[] = {"\x09\x04", "Keyferry", "Keyferry Macros", g_serial,
                                 "Macros keyboard and mouse"};

enum : int { kDelivered, kFailed };
enum : int { kSubmitted, kNotReady, kRefused };

// Every submission, completion, failure and attach/detach runs on the TinyUSB task, so transfer
// ownership and the session counter change in one order: a new configuration cannot open the
// endpoint and take a report between its reset and its ATTACHED event, and a completion cannot
// be credited to a report submitted after it. The sending task hands each report over and waits.
struct Submission {
  std::uint8_t report_id;
  std::uint8_t length;
  bool press;
  std::uint8_t data[16];
};

Submission g_submission;                    // the single sender's report, read by Submit()
SemaphoreHandle_t g_submit_done = nullptr;  // TinyUSB task -> sender: g_submit_result is set
SemaphoreHandle_t g_report_done = nullptr;  // TinyUSB task -> sender: a transfer was retired
SemaphoreHandle_t g_submit_lock = nullptr;  // orders press hand-over against UsbHidClosePresses()
std::atomic<int> g_submit_result{kNotReady};
std::atomic<bool> g_presses_closed{false};
std::atomic<bool> g_usb_owned{false};
std::atomic<bool> g_in_flight{false};       // written on the TinyUSB task only
std::atomic<std::uint32_t> g_transfer{0};   // id of the newest submitted transfer
std::atomic<std::uint32_t> g_retired{0};    // id of the newest retired transfer
std::atomic<int> g_outcome{kFailed};        // outcome of g_retired
std::atomic<std::uint32_t> g_session{0};
std::atomic<std::uint32_t> g_last_session{0};
std::atomic<UsbPersonality> g_personality{UsbPersonality::kKeepAwakeMouse};

// TinyUSB task.
void Retire(int outcome) {
  if (!g_in_flight.load()) return;
  g_in_flight.store(false);
  g_outcome.store(outcome);
  g_retired.store(g_transfer.load());  // after the outcome: the sender reads the pair in reverse
  if (g_report_done != nullptr) xSemaphoreGive(g_report_done);
}

// TinyUSB task: one report, if the endpoint is free and no transfer of ours is outstanding.
void Submit(void*) {
  int result = kNotReady;
  if (g_submission.press && g_presses_closed.load()) {
    result = kRefused;
  } else if (!g_in_flight.load() && tud_mounted() && !tud_suspended() && tud_hid_ready() &&
             tud_hid_report(g_submission.report_id, g_submission.data, g_submission.length)) {
    g_in_flight.store(true);
    g_transfer.fetch_add(1);
    g_last_session.store(g_session.load());
    result = kSubmitted;
  }
  g_submit_result.store(result);
  xSemaphoreGive(g_submit_done);
}

// TinyUSB task. A new configuration or a detach discards the old session's transfer without any
// completion (a bus reset re-enumerates without an unmount callback), so retire it here.
void OnUsbEvent(tinyusb_event_t* event, void*) {
  if (event->id != TINYUSB_EVENT_ATTACHED && event->id != TINYUSB_EVENT_DETACHED) return;
  g_session.fetch_add(1);
  Retire(kFailed);
}

}  // namespace

bool UsbHidStart(UsbPersonality personality) {
  std::uint8_t mac[6] = {};
  if (esp_read_mac(mac, ESP_MAC_WIFI_STA) == ESP_OK) {
    std::snprintf(g_serial, sizeof(g_serial), "%02X%02X%02X%02X%02X%02X", mac[0], mac[1],
                  mac[2], mac[3], mac[4], mac[5]);
  }
  g_report_done = xSemaphoreCreateBinary();
  g_submit_done = xSemaphoreCreateBinary();
  g_submit_lock = xSemaphoreCreateMutex();
  if (g_report_done == nullptr || g_submit_done == nullptr || g_submit_lock == nullptr) return false;
  g_personality.store(personality);
  // Claim the HID callbacks before TinyUSB starts: its task can serve descriptor requests before
  // tinyusb_driver_install() returns. A failed install restarts to Home, so the claim never leaks.
  g_usb_owned.store(true);
  const bool macro_pad = personality == UsbPersonality::kMacroPad;
  tinyusb_config_t config = TINYUSB_DEFAULT_CONFIG();
  config.descriptor.device = macro_pad ? &kMacroPadDevice : &kMouseDevice;
  config.descriptor.full_speed_config = macro_pad ? kMacroPadConfig : kMouseConfig;
  config.descriptor.string = macro_pad ? g_macro_strings : g_mouse_strings;
  config.descriptor.string_count = 5;
  config.event_cb = OnUsbEvent;
  if (tinyusb_driver_install(&config) != ESP_OK) {
    ESP_LOGE(kTag, "USB device could not start");
    return false;
  }
  return true;
}

// Hands one report to the TinyUSB task (retrying while the endpoint is busy, up to 100 ms) and
// waits up to 500 ms for that transfer's own retirement. One transfer is outstanding at a time; a
// timed-out one stays outstanding until the stack retires it, which blocks later sends.
bool UsbHidSend(std::uint8_t report_id, const void* report, std::uint16_t length, bool press) {
  if (g_submit_done == nullptr || length > sizeof(g_submission.data)) return false;
  const std::int64_t ready_deadline = esp_timer_get_time() + kReadyWaitUs;
  for (;;) {
    if (!tud_mounted() || tud_suspended()) return false;  // a hint; Submit() decides
    // A press is handed over under the lock UsbHidClosePresses() takes, so once that returns no
    // press reaches the TinyUSB task.
    if (press) xSemaphoreTake(g_submit_lock, portMAX_DELAY);
    g_submission.report_id = report_id;
    g_submission.length = static_cast<std::uint8_t>(length);
    g_submission.press = press;
    std::memcpy(g_submission.data, report, length);
    usbd_defer_func(Submit, nullptr, false);  // queued, never dropped
    xSemaphoreTake(g_submit_done, portMAX_DELAY);
    if (press) xSemaphoreGive(g_submit_lock);
    const int result = g_submit_result.load();
    if (result == kRefused) return false;
    if (result == kSubmitted) break;
    if (esp_timer_get_time() >= ready_deadline) return false;
    vTaskDelay(1);  // at least one tick: the bridge runs FreeRTOS at 100 Hz
  }
  const std::uint32_t transfer = g_transfer.load();
  const std::int64_t deadline = esp_timer_get_time() + kReportTimeoutUs;
  while (g_retired.load() != transfer) {
    const std::int64_t left = deadline - esp_timer_get_time();
    if (left <= 0) return false;
    const TickType_t ticks = pdMS_TO_TICKS(left / 1000);
    xSemaphoreTake(g_report_done, ticks > 0 ? ticks : 1);  // a stale give only re-checks
  }
  return g_outcome.load() == kDelivered;
}

void UsbHidClosePresses() {
  g_presses_closed.store(true);
  if (g_submit_lock == nullptr) return;
  xSemaphoreTake(g_submit_lock, portMAX_DELAY);  // waits out a press hand-over in progress
  xSemaphoreGive(g_submit_lock);
}

std::uint32_t UsbHidSession() { return g_session.load(); }
std::uint32_t UsbHidLastSubmittedSession() { return g_last_session.load(); }

bool UsbHidMounted() { return tud_mounted(); }
bool UsbHidSuspended() { return tud_suspended(); }
bool UsbHidReady() { return !g_in_flight.load() && tud_hid_ready(); }

bool UsbOwnedByHandheld() { return g_usb_owned.load(); }

const std::uint8_t* HandheldHidReportDescriptor(std::uint8_t) {
  return g_personality.load() == UsbPersonality::kMacroPad ? kMacroPadDescriptor : kMouseDescriptor;
}

void HandheldHidReportComplete(std::uint8_t) { Retire(kDelivered); }

void HandheldHidReportFailed(std::uint8_t, bool input_report) {
  if (input_report) Retire(kFailed);
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

extern "C" void tud_hid_report_failed_cb(std::uint8_t instance, hid_report_type_t report_type,
                                         std::uint8_t const*, std::uint16_t) {
  keyferry::handheld::HandheldHidReportFailed(instance, report_type == HID_REPORT_TYPE_INPUT);
}
#endif
