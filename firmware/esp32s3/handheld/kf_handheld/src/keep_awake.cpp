// Keep Awake (ADR 0018): a standalone relative mouse that, after an explicit local Start, sends a
// (+1, 0) then (-1, 0) pair every 25 s. Stops on unplug, suspend or an unconfirmed report.
#include "keep_awake.h"

#include <atomic>

#include "class/hid/hid_device.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "usb_hid.h"

namespace keyferry::handheld {
namespace {

constexpr char kTag[] = "keep_awake";
constexpr std::int64_t kNudgeIntervalUs = kKeepAwakeIntervalSeconds * 1000000LL;

std::atomic<bool> g_running{false};
std::atomic<KeepAwakeState> g_state{KeepAwakeState::kReady};
std::atomic<std::uint32_t> g_nudges{0};
std::atomic<std::int64_t> g_next_due{0};  // 0: the next nudge is due now

bool Nudge(std::int8_t dx) {
  hid_mouse_report_t report{};
  report.x = dx;
  return UsbHidSend(0, &report, sizeof(report));
}

void StopWith(KeepAwakeState state) {
  g_running.store(false);
  g_state.store(state);
  ESP_LOGI(kTag, "stopped: state=%d nudges=%u", static_cast<int>(state),
           static_cast<unsigned>(g_nudges.load()));
}

void NudgeTask(void*) {
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(50));
    if (!g_running.load()) {
      g_next_due.store(0);
      continue;
    }
    if (!UsbHidMounted()) {
      StopWith(KeepAwakeState::kStoppedUnplugged);
      continue;
    }
    if (UsbHidSuspended()) {
      StopWith(KeepAwakeState::kStoppedSuspended);
      continue;
    }
    if (esp_timer_get_time() < g_next_due.load() || !UsbHidReady()) continue;
    if (!Nudge(1)) {
      StopWith(KeepAwakeState::kStoppedUnconfirmed);
      continue;
    }
    vTaskDelay(pdMS_TO_TICKS(20));  // the return leg goes out on a later poll
    if (!Nudge(-1)) {
      StopWith(KeepAwakeState::kStoppedUnconfirmed);
      continue;
    }
    g_nudges.fetch_add(1);
    g_next_due.store(esp_timer_get_time() + kNudgeIntervalUs);
  }
}

}  // namespace

bool KeepAwakeStartUsb() {
  if (!UsbHidStart(UsbPersonality::kKeepAwakeMouse)) return false;
  return xTaskCreate(NudgeTask, "kf_keep_awake", 3072, nullptr, 4, nullptr) == pdPASS;
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

int KeepAwakeSecondsToNext() {
  if (!g_running.load()) return -1;
  const std::int64_t left = g_next_due.load() - esp_timer_get_time();
  return left <= 0 ? 0 : static_cast<int>((left + 999999) / 1000000);
}

}  // namespace keyferry::handheld
