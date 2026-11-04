// Macros (ADR 0018 rule 12): plays one compiled-in preset per tap on the handheld's own USB
// keyboard + mouse + media-key device. Every press is followed by its release and each report is
// confirmed. Until a release is confirmed the pad counts as possibly holding something: it refuses
// presets and keeps sending all-released reports (never presses) until one is confirmed or the
// computer drops the device. Presets themselves are never queued or retried.
#include "macro_pad.h"

#include <atomic>

#include "class/hid/hid_device.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "usb_device.h"

namespace keyferry::handheld {
namespace {

constexpr char kTag[] = "macros";
constexpr int kHoldMs = 30;
constexpr int kGapMs = 20;
constexpr TickType_t kNeutralizeEvery = pdMS_TO_TICKS(200);

struct Request {
  int which;
  macros::Host host;
};

QueueHandle_t g_requests = nullptr;
std::atomic<int> g_busy{-1};
std::atomic<bool> g_closed{false};  // latched by MacroPadClose(); the boot ends in a restart
std::atomic<bool> g_dirty{false};   // a press may still be held on the computer
std::atomic<std::uint32_t> g_dirty_session{0};  // USB session of the last press submitted
std::atomic<MacroResult> g_result{MacroResult::kNone};
std::atomic<int> g_result_which{-1};
std::atomic<std::uint32_t> g_result_serial{0};

void Record(MacroResult result, int which) {
  g_result_which.store(which);
  g_result.store(result);
  g_result_serial.fetch_add(1);
}

// Every non-neutral report goes through here: refused after MacroPadClose(), and it records the
// USB session that may now hold it.
bool Send(std::uint8_t report_id, const void* report, std::uint16_t length, bool press) {
  const bool confirmed = UsbHidSend(report_id, report, length, press);
  if (press) g_dirty_session.store(UsbHidLastSubmittedSession());
  return confirmed;
}

bool Keyboard(std::uint8_t modifiers, std::uint8_t key) {
  hid_keyboard_report_t report{};
  report.modifier = modifiers;
  report.keycode[0] = key;
  return Send(kReportKeyboard, &report, sizeof(report), modifiers != 0 || key != 0);
}

bool Mouse(std::uint8_t buttons, std::int8_t wheel) {
  hid_mouse_report_t report{};  // x and y stay 0: the pointer never moves
  report.buttons = buttons;
  report.wheel = wheel;
  return Send(kReportMouse, &report, sizeof(report), buttons != 0 || wheel != 0);
}

bool Media(std::uint16_t usage) { return Send(kReportMedia, &usage, sizeof(usage), usage != 0); }

// Checked before every press; releases are always allowed.
bool Open() { return !g_closed.load(); }

bool ReleaseAll() {
  const bool keyboard = Keyboard(0, 0);
  const bool mouse = Mouse(0, 0);
  const bool media = Media(0);
  if (!(keyboard && mouse && media)) {
    ESP_LOGW(kTag, "release not confirmed (keyboard=%d mouse=%d media=%d)", keyboard, mouse, media);
  }
  return keyboard && mouse && media;
}

bool Pause(int ms) {
  for (int waited = 0; waited < ms; waited += 10) {
    if (!Open()) return false;
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  return Open();
}

bool Play(const macros::Step& step) {
  const auto code = static_cast<std::uint16_t>(step.code);
  switch (step.kind) {
    case macros::Kind::kKeys:
      // Modifiers go down first and come up last, as a person types a shortcut.
      if (step.modifiers != 0 && !(Open() && Keyboard(step.modifiers, 0))) return false;
      if (code != 0 && !(Open() && Keyboard(step.modifiers, static_cast<std::uint8_t>(code)))) return false;
      if (!Pause(kHoldMs)) return false;
      if (code != 0 && step.modifiers != 0 && !Keyboard(step.modifiers, 0)) return false;
      return Keyboard(0, 0);
    case macros::Kind::kMedia:
      return Open() && Media(code) && Pause(kHoldMs) && Media(0);
    case macros::Kind::kClick:
      return Open() && Mouse(static_cast<std::uint8_t>(code), 0) && Pause(kHoldMs) && Mouse(0, 0);
    case macros::Kind::kScroll:
      return Open() && Mouse(0, static_cast<std::int8_t>(step.code));
    case macros::Kind::kWait:
      return Pause(step.code);
    case macros::Kind::kNone:
      break;
  }
  return true;
}

// While something may be held: all-released reports until one set is confirmed. A computer that
// dropped or re-enumerated the device since the last press holds nothing from it.
void Neutralize() {
  if (!g_dirty.load()) return;
  if (!UsbDeviceMounted() || UsbHidSession() != g_dirty_session.load()) {
    g_dirty.store(false);
    ESP_LOGI(kTag, "computer dropped the device: nothing held");
    return;
  }
  if (UsbDeviceSuspended()) return;  // wait for resume; never wake the computer for this
  if (ReleaseAll()) {
    g_dirty.store(false);
    ESP_LOGI(kTag, "release confirmed");
  }
}

void Player(void*) {
  Request request{};
  for (;;) {
    if (xQueueReceive(g_requests, &request, kNeutralizeEvery) != pdTRUE) {
      Neutralize();
      continue;
    }
    MacroResult result = MacroResult::kStopped;
    if (Open() && g_dirty.load()) {
      result = MacroResult::kReleasing;  // never play over an unconfirmed release
    } else if (Open()) {
      const macros::Page& page = macros::PageAt(request.which >> 8);
      const macros::Step* steps = macros::StepsFor(page.macros[request.which & 0xFF], request.host);
      g_dirty_session.store(UsbHidSession());
      g_dirty.store(true);
      bool ok = true;
      for (int i = 0; ok && i < macros::kMaxSteps && steps[i].kind != macros::Kind::kNone; ++i) {
        ok = Play(steps[i]) && Pause(kGapMs);
      }
      if (ok) {
        result = MacroResult::kSent;  // every release in the preset was confirmed
        g_dirty.store(false);
      } else {
        result = !Open()            ? MacroResult::kStopped
                 : !UsbDeviceMounted() ? MacroResult::kNotConnected
                                    : MacroResult::kNotConfirmed;
        Neutralize();
      }
    }
    ESP_LOGI(kTag, "preset %d.%d: result=%d held=%d", request.which >> 8, request.which & 0xFF,
             static_cast<int>(result), g_dirty.load());
    Record(result, request.which);
    g_busy.store(-1);
  }
}

}  // namespace

bool MacroPadStart() {
  g_requests = xQueueCreate(1, sizeof(Request));
  if (g_requests == nullptr || !UsbDeviceStart(UsbPersonality::kMacroPad)) return false;
  return xTaskCreate(Player, "kf_macros", 3072, nullptr, 4, nullptr) == pdPASS;
}

bool MacroPadRun(int page, int index, macros::Host host) {
  if (g_requests == nullptr || page < 0 || page >= macros::PageCount() || index < 0 ||
      index >= macros::PageAt(page).count) {
    return false;
  }
  const int which = page << 8 | index;
  // Reserve the player first, then check: a release outstanding from the previous preset is
  // visible once its busy flag is clear, so no check can pass on stale state.
  int idle = -1;
  if (!g_busy.compare_exchange_strong(idle, which)) return false;
  MacroResult refusal = MacroResult::kNone;
  if (!Open()) {
    refusal = MacroResult::kStopped;
  } else if (g_dirty.load()) {
    refusal = MacroResult::kReleasing;
  } else if (!UsbDeviceMounted() || UsbDeviceSuspended()) {
    refusal = MacroResult::kNotConnected;
  }
  if (refusal != MacroResult::kNone) {
    g_busy.store(-1);
    Record(refusal, which);
    return false;
  }
  const Request request{which, host};
  if (xQueueSend(g_requests, &request, 0) != pdTRUE) {
    g_busy.store(-1);
    return false;
  }
  return true;
}

void MacroPadClose() {
  g_closed.store(true);
  UsbHidClosePresses();  // a press already past Open() is refused at submission
}

bool MacroPadNeutral() { return g_busy.load() == -1 && !g_dirty.load(); }

int MacroPadBusy() { return g_busy.load(); }

MacroResult MacroPadLastResult(std::uint32_t* serial, int* which) {
  *serial = g_result_serial.load();
  *which = g_result_which.load();
  return g_result.load();
}

}  // namespace keyferry::handheld
