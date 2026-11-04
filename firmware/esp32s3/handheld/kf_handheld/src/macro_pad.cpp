// Macros (ADR 0018 rule 12): plays one compiled-in preset per tap on the handheld's own USB
// keyboard + mouse + media-key device. Every press is followed by its release, each report is
// confirmed, and a failure or stop ends with an all-released report. Nothing is retried.
#include "macro_pad.h"

#include <atomic>

#include "class/hid/hid_device.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "usb_hid.h"

namespace keyferry::handheld {
namespace {

constexpr char kTag[] = "macros";
constexpr int kHoldMs = 30;
constexpr int kGapMs = 20;

struct Request {
  int which;
  macros::Host host;
};

QueueHandle_t g_requests = nullptr;
std::atomic<int> g_busy{-1};
std::atomic<bool> g_stop{false};
std::atomic<MacroResult> g_result{MacroResult::kNone};
std::atomic<int> g_result_which{-1};
std::atomic<std::uint32_t> g_result_serial{0};

void Record(MacroResult result, int which) {
  g_result_which.store(which);
  g_result.store(result);
  g_result_serial.fetch_add(1);
}

bool Keyboard(std::uint8_t modifiers, std::uint8_t key) {
  hid_keyboard_report_t report{};
  report.modifier = modifiers;
  report.keycode[0] = key;
  return UsbHidSend(kReportKeyboard, &report, sizeof(report));
}

bool Mouse(std::uint8_t buttons, std::int8_t wheel) {
  hid_mouse_report_t report{};  // x and y stay 0: the pointer never moves
  report.buttons = buttons;
  report.wheel = wheel;
  return UsbHidSend(kReportMouse, &report, sizeof(report));
}

bool Media(std::uint16_t usage) { return UsbHidSend(kReportMedia, &usage, sizeof(usage)); }

void ReleaseAll() {
  const bool keyboard = Keyboard(0, 0);
  const bool mouse = Mouse(0, 0);
  const bool media = Media(0);
  if (!(keyboard && mouse && media)) {
    ESP_LOGW(kTag, "release not confirmed (keyboard=%d mouse=%d media=%d)", keyboard, mouse, media);
  }
}

bool Pause(int ms) {
  for (int waited = 0; waited < ms; waited += 10) {
    if (g_stop.load()) return false;
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  return !g_stop.load();
}

bool Play(const macros::Step& step) {
  const auto code = static_cast<std::uint16_t>(step.code);
  switch (step.kind) {
    case macros::Kind::kKeys:
      // Modifiers go down first and come up last, as a person types a shortcut.
      if (step.modifiers != 0 && !Keyboard(step.modifiers, 0)) return false;
      if (code != 0 && !Keyboard(step.modifiers, static_cast<std::uint8_t>(code))) return false;
      if (!Pause(kHoldMs)) return false;
      if (code != 0 && step.modifiers != 0 && !Keyboard(step.modifiers, 0)) return false;
      return Keyboard(0, 0);
    case macros::Kind::kMedia:
      return Media(code) && Pause(kHoldMs) && Media(0);
    case macros::Kind::kClick:
      return Mouse(static_cast<std::uint8_t>(code), 0) && Pause(kHoldMs) && Mouse(0, 0);
    case macros::Kind::kScroll:
      return Mouse(0, static_cast<std::int8_t>(step.code));
    case macros::Kind::kWait:
      return Pause(step.code);
    case macros::Kind::kNone:
      break;
  }
  return true;
}

void Player(void*) {
  Request request{};
  for (;;) {
    xQueueReceive(g_requests, &request, portMAX_DELAY);
    const macros::Page& page = macros::PageAt(request.which >> 8);
    const macros::Step* steps = macros::StepsFor(page.macros[request.which & 0xFF], request.host);
    bool ok = true;
    for (int i = 0; ok && i < macros::kMaxSteps && steps[i].kind != macros::Kind::kNone; ++i) {
      ok = Play(steps[i]) && Pause(kGapMs);
    }
    MacroResult result = MacroResult::kSent;
    if (!ok) {
      result = g_stop.load()      ? MacroResult::kStopped
               : !UsbHidMounted() ? MacroResult::kNotConnected
                                  : MacroResult::kNotConfirmed;
      ReleaseAll();
    }
    ESP_LOGI(kTag, "preset %d.%d: result=%d", request.which >> 8, request.which & 0xFF,
             static_cast<int>(result));
    Record(result, request.which);
    g_busy.store(-1);
  }
}

}  // namespace

bool MacroPadStart() {
  g_requests = xQueueCreate(1, sizeof(Request));
  if (g_requests == nullptr || !UsbHidStart(UsbPersonality::kMacroPad)) return false;
  return xTaskCreate(Player, "kf_macros", 3072, nullptr, 4, nullptr) == pdPASS;
}

bool MacroPadRun(int page, int index, macros::Host host) {
  if (g_requests == nullptr || page < 0 || page >= macros::PageCount() || index < 0 ||
      index >= macros::PageAt(page).count) {
    return false;
  }
  const int which = page << 8 | index;
  if (!UsbHidMounted() || UsbHidSuspended()) {
    Record(MacroResult::kNotConnected, which);
    return false;
  }
  int idle = -1;
  if (!g_busy.compare_exchange_strong(idle, which)) return false;
  g_stop.store(false);
  const Request request{which, host};
  if (xQueueSend(g_requests, &request, 0) != pdTRUE) {
    g_busy.store(-1);
    return false;
  }
  return true;
}

void MacroPadStop() { g_stop.store(true); }

int MacroPadBusy() { return g_busy.load(); }

MacroResult MacroPadLastResult(std::uint32_t* serial, int* which) {
  *serial = g_result_serial.load();
  *which = g_result_which.load();
  return g_result.load();
}

}  // namespace keyferry::handheld
