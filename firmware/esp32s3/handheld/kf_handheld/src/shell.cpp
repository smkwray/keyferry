// Handheld shell (ADR 0018): boot selection, power and buttons, the supervisor and the glue
// between the screens (ui.cpp) and the functions (Keep Awake, Macros, Keyferry).
// Functions are mutually exclusive: launching one records it in RTC memory and restarts, and
// leaving it restarts to Home. Home has no radio, no application USB class and no SD writes.
#include "keyferry/handheld.h"

#include <algorithm>
#include <atomic>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <iterator>

#include "bsp/esp-bsp.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_io_expander.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hal/usb_serial_jtag_ll.h"
#include "keep_awake.h"
#include "lvgl.h"
#include "macro_pad.h"
#include "macros.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdmmc_cmd.h"
#include "soc/reset_reasons.h"
#include "ui.h"
#include "usb_hid.h"

namespace keyferry::handheld {
namespace {

static_assert(ui::kWidth == BSP_LCD_H_RES && ui::kHeight == BSP_LCD_V_RES, "panel size");

constexpr char kTag[] = "handheld";
constexpr char kNvsNamespace[] = "kf_hh";
constexpr char kBrightnessKey[] = "bright";
constexpr char kStartKey[] = "start";       // 1: power-up starts Keyferry
constexpr char kHostKey[] = "host";         // macros::Host for Macros shortcuts
constexpr char kMacroPageKey[] = "mpage";   // last Macros page shown
constexpr int kDefaultBrightness = 60;
constexpr int kMinBrightness = 5;
constexpr std::uint32_t kBlankAfterMs = 20000;
constexpr std::int64_t kBootLongHoldUs = 2000000;
constexpr std::int64_t kNoticeUs = 2500000;
constexpr gpio_num_t kBootGpio = GPIO_NUM_0;

// AXP2101 power management unit on the shared I2C bus.
constexpr std::uint8_t kPmuAddress = 0x34;
constexpr std::uint8_t kPmuStatus1 = 0x00;      // bit5 VBUS good, bit3 battery present
constexpr std::uint8_t kPmuStatus2 = 0x01;      // bits7..5 charge direction
constexpr std::uint8_t kPmuAdcControl = 0x30;   // bit0 battery voltage channel
constexpr std::uint8_t kPmuBatteryVoltageHigh = 0x34;
constexpr std::uint8_t kPmuInterruptEnable2 = 0x41;
constexpr std::uint8_t kPmuInterruptStatus2 = 0x49;  // bit3 PWR short, bit2 PWR long
constexpr std::uint8_t kPmuBatteryDetect = 0x68;     // bit0 detection enable
constexpr std::uint8_t kPmuBatteryPercent = 0xA4;
constexpr std::uint8_t kPwrShort = 1u << 3;
constexpr std::uint8_t kPwrLong = 1u << 2;

struct PowerStatus {
  bool readable = false;
  bool vbus_good = false;
  bool battery_present = false;
  int charge_direction = 0;  // 1 charging, 2 discharging, 0 standby
  int battery_mv = 0;
  int battery_percent = -1;
};

enum class Function : std::uint32_t { kHome = 0, kKeepAwake = 1, kKeyferry = 2, kMacros = 3 };

struct BootSelection {
  std::uint32_t magic;
  std::uint32_t function;
  std::uint32_t check;  // ~function ^ image tag: a choice made by another image is ignored
};

std::uint32_t ImageTag() {
  const esp_app_desc_t* description = esp_app_get_description();
  std::uint32_t tag = 0;
  if (description != nullptr) std::memcpy(&tag, description->app_elf_sha256, sizeof(tag));
  return tag;
}

// The CPU-only reset that RunShellUnlessKeyferry upgraded, kept for diagnostics.
RTC_NOINIT_ATTR std::uint32_t g_upgraded_reset_reason;
constexpr std::uint32_t kNoUpgrade = 0xFFFFFFFFU;
constexpr std::uint32_t kSelectionMagic = 0x4B464853;
// Survives the system reset in Launch(); garbage after power-on, which the magic and check reject (-> Home).
RTC_NOINIT_ATTR BootSelection g_selection;

// Consecutive Keyferry starts without 60 s of stable running; a third falls back to Home so a
// crashing bridge cannot trap the device away from its menu.
struct KeyferryStarts {
  std::uint32_t magic;
  std::uint32_t count;
};
constexpr std::uint32_t kStartsMagic = 0x4B465354 ^ 0x1;
constexpr std::uint32_t kMaxKeyferryStarts = 3;
RTC_NOINIT_ATTR KeyferryStarts g_keyferry_starts;

// *deliberate is true only for a choice recorded by Launch(); otherwise the start preference applies.
Function TakeSelection(bool* deliberate) {
  const BootSelection selection = g_selection;
  g_selection = BootSelection{0, 0, 0};  // a crash or reset inside Home or a function leaves it
  *deliberate = selection.magic == kSelectionMagic &&
                selection.check == (~selection.function ^ ImageTag());
  if (!*deliberate) {
    return Function::kHome;
  }
  switch (selection.function) {
    case static_cast<std::uint32_t>(Function::kKeepAwake): return Function::kKeepAwake;
    case static_cast<std::uint32_t>(Function::kMacros): return Function::kMacros;
#if defined(KEYFERRY_HANDHELD_KEYFERRY)
    case static_cast<std::uint32_t>(Function::kKeyferry): return Function::kKeyferry;
#endif
    default: return Function::kHome;
  }
}

[[noreturn]] void Launch(Function function) {
  const auto value = static_cast<std::uint32_t>(function);
  g_selection = BootSelection{kSelectionMagic, value, ~value ^ ImageTag()};
  g_keyferry_starts = KeyferryStarts{kStartsMagic, 0};
  ESP_LOGI("handheld", "restarting into function %u", static_cast<unsigned>(value));
  vTaskDelay(pdMS_TO_TICKS(50));
  // GPIO0 (BOOT) is the ROM download strap: reset only once it has read high for 50 ms straight,
  // checked here, immediately before the reset, so a press during the delay cannot slip through.
  for (int high_ms = 0; high_ms < 50;) {
    high_ms = gpio_get_level(kBootGpio) != 0 ? high_ms + 10 : 0;
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  // Full digital-system reset (RTC memory kept). A CPU-only esp_restart() left the display's
  // SPI/DMA state behind and the next panel reset hung on the bench (2026-11-04).
  esp_rom_software_reset_system();
  for (;;) {
  }
}

// Flight recorder: the last log bytes of each boot survive the Launch() system reset, so Home can
// print what a function did while USB-Serial/JTAG was unavailable to it.
struct FlightLog {
  std::uint32_t magic;
  std::uint32_t length;
  char text[2040];
};
constexpr std::uint32_t kFlightMagic = 0x4B46464C;
RTC_NOINIT_ATTR FlightLog g_flight;
vprintf_like_t g_console_vprintf = nullptr;

portMUX_TYPE g_flight_lock = portMUX_INITIALIZER_UNLOCKED;

int FlightVprintf(const char* format, va_list args) {
  va_list copy;
  va_copy(copy, args);
  char line[160];
  const int n = vsnprintf(line, sizeof(line), format, copy);
  va_end(copy);
  if (n > 0) {
    // ESP-IDF may call this from several tasks at once: the bounds check, copy and length update
    // form one critical section (formatting above and the console write below stay outside).
    const std::uint32_t take = std::min<std::uint32_t>(static_cast<std::uint32_t>(n), sizeof(line) - 1);
    taskENTER_CRITICAL(&g_flight_lock);
    if (g_flight.magic == kFlightMagic) {
      if (g_flight.length > sizeof(g_flight.text) ||
          g_flight.length + take > sizeof(g_flight.text)) {
        g_flight.length = 0;  // wrap: keep newest
      }
      std::memcpy(g_flight.text + g_flight.length, line, take);
      g_flight.length += take;
    }
    taskEXIT_CRITICAL(&g_flight_lock);
  }
  return g_console_vprintf != nullptr ? g_console_vprintf(format, args) : n;
}

char g_previous_flight[sizeof(FlightLog::text)];
std::uint32_t g_previous_flight_length = 0;

// Home prints the previous boot's log a few seconds in, once the host has re-enumerated the
// USB-Serial/JTAG port that the function had taken over.
void PrintPreviousFlightLog() {
  if (g_previous_flight_length == 0) return;
  std::printf("--- previous boot flight log (%u bytes) ---\n",
              static_cast<unsigned>(g_previous_flight_length));
  std::fwrite(g_previous_flight, 1, g_previous_flight_length, stdout);
  std::printf("--- end flight log ---\n");
  std::fflush(stdout);
  g_previous_flight_length = 0;
}

void StartFlightLog(bool keep_previous) {
  if (keep_previous && g_flight.magic == kFlightMagic && g_flight.length <= sizeof(g_flight.text)) {
    std::memcpy(g_previous_flight, g_flight.text, g_flight.length);
    g_previous_flight_length = g_flight.length;
  }
  g_flight.magic = kFlightMagic;
  g_flight.length = 0;
  g_console_vprintf = esp_log_set_vprintf(FlightVprintf);
}

#if defined(KEYFERRY_HANDHELD_SELFTEST)
// Bench self-test: Home launches Keep Awake, which starts, nudges once, runs 20 s and returns.
struct SelfTest {
  std::uint32_t magic;
  std::uint32_t round;
};
constexpr std::uint32_t kSelfTestMagic = 0x4B465354;
constexpr std::uint32_t kSelfTestRounds = 10;
RTC_NOINIT_ATTR SelfTest g_selftest;
#endif

enum class SdState : std::uint8_t { kUnchecked, kChecking, kMounted, kFailed };

Function g_function = Function::kHome;
std::atomic<std::uint32_t> g_ui_ticks{0};
std::atomic<std::uint32_t> g_renders{0};
KeyferryHooks g_keyferry{};
std::atomic<bool> g_leaving{false};
i2c_master_dev_handle_t g_pmu = nullptr;
int g_brightness = kDefaultBrightness;
macros::Host g_host = macros::Host::kWindows;
bool g_blanked = false;
bool g_boot_down = false;
bool g_boot_long = false;
std::int64_t g_boot_down_since = 0;
std::uint32_t g_pwr_short_count = 0;
std::uint32_t g_pwr_long_count = 0;
volatile SdState g_sd_state = SdState::kUnchecked;
std::uint64_t g_sd_bytes = 0;
esp_err_t g_sd_error = ESP_OK;
std::uint32_t g_macro_serial_seen = 0;
std::int64_t g_notice_until = 0;
char g_notice[48] = {};
bool g_notice_error = false;

bool UsbFunction() { return g_function == Function::kKeepAwake || g_function == Function::kMacros; }

// Stops any input a handheld USB function is producing; safe from any task. For Macros it is
// final for this boot: the only way on is the exit worker's restart.
void StopInput() {
  if (g_function == Function::kKeepAwake) KeepAwakeSetRunning(false);
  if (g_function == Function::kMacros) MacroPadClose();
}

// Leaving Keep Awake or Macros: a pre-created worker stops input and restarts to Home only once
// nothing may be held (Keep Awake's nudges hold nothing) and BOOT is up, so GPIO0 cannot select
// ROM download. Home, BOOT and the stall supervisor all go through it.
constexpr std::int64_t kExitWaitNoticeUs = 1500000;
TaskHandle_t g_usb_exit_worker = nullptr;
std::atomic<bool> g_usb_exit_requested{false};
std::atomic<bool> g_usb_exit_waiting{false};

void UsbExitWorker(void*) {
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
  StopInput();
  const std::int64_t started = esp_timer_get_time();
  for (;;) {
    const bool neutral = g_function != Function::kMacros || MacroPadNeutral();
    if (neutral && gpio_get_level(kBootGpio) != 0) Launch(Function::kHome);
    if (!neutral && esp_timer_get_time() - started > kExitWaitNoticeUs) {
      if (!g_usb_exit_waiting.exchange(true)) ESP_LOGW(kTag, "exit waiting for a confirmed release");
    }
    vTaskDelay(pdMS_TO_TICKS(20));
  }
}

void StartUsbExitWorker() {
  static StaticTask_t control;
  static StackType_t stack[3072 / sizeof(StackType_t)];
  g_usb_exit_worker = xTaskCreateStatic(UsbExitWorker, "kf_usb_leave", std::size(stack), nullptr, 5,
                                        stack, &control);
}

void RequestUsbExit() {
  StopInput();
  if (g_usb_exit_worker != nullptr && !g_usb_exit_requested.exchange(true)) {
    xTaskNotifyGive(g_usb_exit_worker);
  }
}

bool PmuRead(std::uint8_t reg, std::uint8_t* out, std::size_t length) {
  return g_pmu != nullptr &&
         i2c_master_transmit_receive(g_pmu, &reg, 1, out, length, 50) == ESP_OK;
}

bool PmuWrite(std::uint8_t reg, std::uint8_t value) {
  const std::uint8_t frame[2] = {reg, value};
  return g_pmu != nullptr && i2c_master_transmit(g_pmu, frame, sizeof(frame), 50) == ESP_OK;
}

bool PmuSetBits(std::uint8_t reg, std::uint8_t bits) {
  std::uint8_t value = 0;
  return PmuRead(reg, &value, 1) && PmuWrite(reg, value | bits);
}

void PmuInit() {
  i2c_device_config_t config{};
  config.dev_addr_length = I2C_ADDR_BIT_LEN_7;
  config.device_address = kPmuAddress;
  config.scl_speed_hz = 400000;
  if (i2c_master_bus_add_device(bsp_i2c_get_handle(), &config, &g_pmu) != ESP_OK) {
    g_pmu = nullptr;
    ESP_LOGW(kTag, "PMU device could not be added");
    return;
  }
  // Measurement and key-event latching only; no rail, charge or power-off settings change.
  const bool ok = PmuSetBits(kPmuBatteryDetect, 0x01) && PmuSetBits(kPmuAdcControl, 0x01) &&
                  PmuSetBits(kPmuInterruptEnable2, kPwrShort | kPwrLong) &&
                  PmuWrite(kPmuInterruptStatus2, kPwrShort | kPwrLong);
  if (!ok) ESP_LOGW(kTag, "PMU did not accept measurement setup");
}

PowerStatus ReadPower() {
  PowerStatus status;
  std::uint8_t s[2] = {};
  if (!PmuRead(kPmuStatus1, s, 2)) return status;
  status.readable = true;
  status.vbus_good = (s[0] & (1u << 5)) != 0;
  status.battery_present = (s[0] & (1u << 3)) != 0;
  status.charge_direction = s[1] >> 5;
  if (status.battery_present) {
    std::uint8_t v[2] = {};
    if (PmuRead(kPmuBatteryVoltageHigh, v, 2)) {
      status.battery_mv = ((v[0] & 0x1F) << 8) | v[1];
    }
    std::uint8_t percent = 0;
    if (PmuRead(kPmuBatteryPercent, &percent, 1) && percent <= 100) {
      status.battery_percent = percent;
    }
  }
  return status;
}

std::uint8_t TakePwrEvents() {
  std::uint8_t status = 0;
  if (!PmuRead(kPmuInterruptStatus2, &status, 1)) return 0;
  status &= kPwrShort | kPwrLong;
  if (status != 0) PmuWrite(kPmuInterruptStatus2, status);
  return status;
}

// Settings are single bytes in one NVS namespace; a missing or unreadable key gives `fallback`.
std::uint8_t LoadSetting(const char* key, std::uint8_t fallback) {
  nvs_handle_t handle;
  std::uint8_t value = fallback;
  if (nvs_open(kNvsNamespace, NVS_READONLY, &handle) != ESP_OK) return fallback;
  if (nvs_get_u8(handle, key, &value) != ESP_OK) value = fallback;
  nvs_close(handle);
  return value;
}

void StoreSetting(const char* key, std::uint8_t value) {
  nvs_handle_t handle;
  if (nvs_open(kNvsNamespace, NVS_READWRITE, &handle) != ESP_OK) return;
  if (nvs_set_u8(handle, key, value) == ESP_OK) nvs_commit(handle);
  nvs_close(handle);
}

int LoadBrightness() {
  const int value = LoadSetting(kBrightnessKey, kDefaultBrightness);
  return value < kMinBrightness || value > 100 ? kDefaultBrightness : value;
}

bool LoadStartInKeyferry() {
#if defined(KEYFERRY_HANDHELD_KEYFERRY)
  // ADR 0018: power-up shows Home unless the owner turned "Start in Keyferry" on (stored 1).
  return LoadSetting(kStartKey, 0) == 1;
#else
  return false;
#endif
}

macros::Host LoadHost() {
  return LoadSetting(kHostKey, 0) == static_cast<std::uint8_t>(macros::Host::kMac) ? macros::Host::kMac
                                                                                   : macros::Host::kWindows;
}

void SdCheckTask(void*) {
  g_sd_error = bsp_sdcard_mount();  // BSP keeps format-on-failure disabled
  if (g_sd_error == ESP_OK && bsp_sdcard != nullptr) {
    g_sd_bytes = static_cast<std::uint64_t>(bsp_sdcard->csd.capacity) * bsp_sdcard->csd.sector_size;
    g_sd_state = SdState::kMounted;
  } else {
    g_sd_state = SdState::kFailed;
  }
  vTaskDelete(nullptr);
}

void Blank() {
  if (g_blanked) return;
  g_blanked = true;
  bsp_display_brightness_set(0);
  ui::ShowWakeShield();
}

void Wake() {
  if (!g_blanked) return;
  g_blanked = false;
  bsp_display_brightness_set(g_brightness);
  lv_display_trigger_activity(nullptr);
}

constexpr TickType_t kExitDisplayLockTicks = pdMS_TO_TICKS(50);
constexpr std::int64_t kExitNeutralTimeoutUs = 3000000;
TaskHandle_t g_exit_worker = nullptr;

// Display text is optional during an exit and never waits long for the LVGL lock.
void ShowExitText(const char* text) {
  if (bsp_display_lock(kExitDisplayLockTicks * portTICK_PERIOD_MS)) {
    ui::SetKeyferryText(text);
    bsp_display_unlock();
  }
}

// Created once when the Keyferry screen starts, so an exit never depends on allocation or the UI.
void KeyferryExitWorker(void*) {
  for (;;) {
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    if (g_keyferry.begin_leave == nullptr || !g_keyferry.begin_leave(g_keyferry.context)) {
      g_leaving.store(false);
      ShowExitText("Busy (maintenance or provisioning).\nTry Home again shortly.");
      continue;
    }
    ShowExitText("Releasing all keys...");
    const std::int64_t deadline = esp_timer_get_time() + kExitNeutralTimeoutUs;
    while (esp_timer_get_time() < deadline) {
      if (g_keyferry.neutral_confirmed != nullptr && g_keyferry.neutral_confirmed(g_keyferry.context)) {
        Launch(Function::kHome);
      }
      vTaskDelay(pdMS_TO_TICKS(20));
    }
    // Admission stays closed and nothing retries; the bridge is stopped until power is removed.
    ShowExitText("Release not confirmed.\nKeyferry is stopped.\nUnplug to reset.");
    for (;;) vTaskDelay(portMAX_DELAY);
  }
}

void StartExitWorker() {
  static StaticTask_t control;
  static StackType_t stack[4096 / sizeof(StackType_t)];
  g_exit_worker = xTaskCreateStatic(KeyferryExitWorker, "kf_leave", std::size(stack), nullptr, 5,
                                    stack, &control);
}

void RequestKeyferryExit() {
  if (g_function != Function::kKeyferry || g_exit_worker == nullptr || g_leaving.exchange(true)) {
    return;
  }
  xTaskNotifyGive(g_exit_worker);
}

// --- Screen actions (LVGL task, display lock held) -----------------------------------------------

const char* ScreenName(ui::Screen screen) {
  switch (screen) {
    case ui::Screen::kHome: return "home";
    case ui::Screen::kCheck: return "check";
    case ui::Screen::kSettings: return "settings";
    default: return "function";
  }
}

void OnAction(ui::Action action, int value) {
  switch (action) {
    case ui::Action::kLaunchKeepAwake: Launch(Function::kKeepAwake);
    case ui::Action::kLaunchMacros: Launch(Function::kMacros);
    case ui::Action::kLaunchKeyferry:
#if defined(KEYFERRY_HANDHELD_KEYFERRY)
      Launch(Function::kKeyferry);
#endif
      break;
    case ui::Action::kLeave:
      if (g_function == Function::kKeyferry) {
        RequestKeyferryExit();
      } else {
        RequestUsbExit();
      }
      break;
    case ui::Action::kWake: Wake(); break;
    case ui::Action::kShown:
      ESP_LOGI(kTag, "screen %s", ScreenName(static_cast<ui::Screen>(value)));
      if (static_cast<ui::Screen>(value) == ui::Screen::kCheck && g_sd_state == SdState::kUnchecked) {
        g_sd_state = SdState::kChecking;
        xTaskCreate(SdCheckTask, "kf_sd_check", 4096, nullptr, 3, nullptr);
      }
      break;
    case ui::Action::kTouch: ESP_LOGI(kTag, "touch %d %d", value >> 16, value & 0xFFFF); break;
    case ui::Action::kKeepAwakeToggle: KeepAwakeSetRunning(!KeepAwakeRunning()); break;
    case ui::Action::kBrightness:
      g_brightness = value;
      bsp_display_brightness_set(g_brightness);
      break;
    case ui::Action::kBrightnessCommit: StoreSetting(kBrightnessKey, static_cast<std::uint8_t>(value)); break;
    case ui::Action::kStartInKeyferry:
#if defined(KEYFERRY_HANDHELD_KEYFERRY)
      StoreSetting(kStartKey, value == 1 ? 1 : 0);
#endif
      break;
    case ui::Action::kMacroHost:
      g_host = static_cast<macros::Host>(value);
      StoreSetting(kHostKey, static_cast<std::uint8_t>(value));
      break;
    case ui::Action::kMacroPage: StoreSetting(kMacroPageKey, static_cast<std::uint8_t>(value)); break;
    case ui::Action::kRunMacro: MacroPadRun(value >> 8, value & 0xFF, g_host); break;
  }
}

// --- Status refresh ------------------------------------------------------------------------------

const char* KeepAwakeText(KeepAwakeState state) {
  switch (state) {
    case KeepAwakeState::kRunning: return "Running";
    case KeepAwakeState::kStoppedUnplugged: return "Stopped: unplugged";
    case KeepAwakeState::kStoppedSuspended: return "Stopped: computer slept";
    case KeepAwakeState::kStoppedUnconfirmed: return "Stopped: not confirmed";
    default: return "Ready";
  }
}

void RefreshKeepAwake() {
  ui::KeepAwakeView view;
  const KeepAwakeState state = KeepAwakeStateNow();
  view.state = KeepAwakeText(state);
  view.running = KeepAwakeRunning();
  view.stopped_by_fault = state != KeepAwakeState::kReady && state != KeepAwakeState::kRunning;
  view.usb = UsbHidMounted();
  view.nudges = KeepAwakeNudges();
  view.seconds_to_next = KeepAwakeSecondsToNext();
  view.interval_seconds = kKeepAwakeIntervalSeconds;
  ui::RefreshKeepAwake(view);
}

void RefreshMacros() {
  std::uint32_t serial = 0;
  int which = -1;
  const MacroResult result = MacroPadLastResult(&serial, &which);
  const std::int64_t now = esp_timer_get_time();
  if (serial != g_macro_serial_seen) {
    g_macro_serial_seen = serial;
    const macros::Page& page = macros::PageAt(which >> 8);
    const int index = which & 0xFF;
    const char* name = index < page.count ? macros::NameFor(page.macros[index], g_host) : "";
    switch (result) {
      case MacroResult::kSent: std::snprintf(g_notice, sizeof(g_notice), "Sent: %s", name); break;
      case MacroResult::kNotConnected: std::snprintf(g_notice, sizeof(g_notice), "No computer connected"); break;
      case MacroResult::kNotConfirmed: std::snprintf(g_notice, sizeof(g_notice), "Not confirmed: %s", name); break;
      case MacroResult::kReleasing: std::snprintf(g_notice, sizeof(g_notice), "Releasing keys, try again"); break;
      default: std::snprintf(g_notice, sizeof(g_notice), "Stopped"); break;
    }
    g_notice_error = result != MacroResult::kSent;
    g_notice_until = now + kNoticeUs;
  }
  ui::MacrosView view;
  view.usb = UsbHidMounted();
  view.busy = MacroPadBusy();
  if (g_usb_exit_waiting.load()) {
    view.notice = "Releasing keys - wake or unplug the computer";
    view.notice_is_error = true;
  } else if (now < g_notice_until) {
    view.notice = g_notice;
    view.notice_is_error = g_notice_error;
  } else if (!view.usb) {
    view.notice = "Not connected";
    view.notice_is_error = true;
  }
  ui::RefreshMacros(view);
}

const char* ChargeText(int direction) {
  switch (direction) {
    case 1: return "charging";
    case 2: return "discharging";
    default: return "standby";
  }
}

void RefreshCheck() {
  char buttons[64];
  char power[96];
  char storage[80];
  char memory[96];
  std::snprintf(buttons, sizeof(buttons), "BOOT %s   PWR %" PRIu32 " short, %" PRIu32 " long",
                g_boot_down ? "DOWN" : "up", g_pwr_short_count, g_pwr_long_count);
  const PowerStatus status = ReadPower();
  if (!status.readable) {
    std::snprintf(power, sizeof(power), "Power chip: not readable");
  } else if (!status.battery_present) {
    std::snprintf(power, sizeof(power), "USB power: %s\nBattery: none", status.vbus_good ? "yes" : "no");
  } else {
    std::snprintf(power, sizeof(power), "USB power: %s\nBattery: %d mV, %d%%, %s",
                  status.vbus_good ? "yes" : "no", status.battery_mv, status.battery_percent,
                  ChargeText(status.charge_direction));
  }
  switch (g_sd_state) {
    case SdState::kUnchecked:
    case SdState::kChecking: std::snprintf(storage, sizeof(storage), "SD card: checking..."); break;
    case SdState::kMounted:
      std::snprintf(storage, sizeof(storage), "SD card: %" PRIu32 ".%" PRIu32 " GB, FAT",
                    static_cast<std::uint32_t>(g_sd_bytes / 1000000000ULL),
                    static_cast<std::uint32_t>(g_sd_bytes / 100000000ULL % 10));
      break;
    case SdState::kFailed:
      std::snprintf(storage, sizeof(storage), "SD card: not mounted\n(%s)", esp_err_to_name(g_sd_error));
      break;
  }
  std::snprintf(memory, sizeof(memory), "RAM %u KiB free (%u KiB block)\nPSRAM %u KiB free",
                static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) >> 10),
                static_cast<unsigned>(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) >> 10),
                static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) >> 10));
  ui::RefreshCheck(ui::CheckView{buttons, power, storage, memory});
}

void RefreshHome() {
  const PowerStatus status = ReadPower();
  ui::HomeView view;
  view.usb_power = status.vbus_good;
  view.battery_percent = status.battery_present ? status.battery_percent : -1;
  ui::RefreshHome(view);
}

void RefreshKeyferry() {
  if (g_leaving.load() || g_keyferry.status == nullptr) return;
  char text[256] = {};
  g_keyferry.status(g_keyferry.context, text, sizeof(text));
  ui::SetKeyferryText(text);
}

// Runs in the LVGL task with the display lock held.
void OnTick(lv_timer_t*) {
  g_ui_ticks.fetch_add(1);
  const bool boot_down = gpio_get_level(kBootGpio) == 0;
  const std::int64_t now = esp_timer_get_time();
  if (boot_down && !g_boot_down) {
    g_boot_down_since = now;
    g_boot_long = false;
    ESP_LOGI(kTag, "BOOT down");
    StopInput();  // stop input at once
  }
  if (boot_down && !g_boot_long && now - g_boot_down_since >= kBootLongHoldUs) {
    g_boot_long = true;  // restart only after release so GPIO0 cannot select ROM download
    Wake();
  }
  if (!boot_down && g_boot_down) {
    ESP_LOGI(kTag, "BOOT up%s", g_boot_long ? " (long)" : "");
    if (UsbFunction()) {
      RequestUsbExit();
      Wake();
      g_boot_down = boot_down;
      return;
    }
    if (g_function == Function::kKeyferry) {
      if (g_boot_long) RequestKeyferryExit();
      Wake();
      g_boot_down = boot_down;
      return;
    }
    if (g_boot_long) {
      ESP_LOGI(kTag, "BOOT long hold released: restarting to Home");
      Launch(Function::kHome);
    }
    if (g_blanked) {
      Wake();
    } else {
      ui::Show(ui::Screen::kHome);
    }
    lv_display_trigger_activity(nullptr);
  }
  g_boot_down = boot_down;

  static std::uint32_t divider = 0;
  ++divider;
  if (divider % 5 == 0) {  // every 100 ms
    const std::uint8_t events = TakePwrEvents();
    if (events) ESP_LOGI(kTag, "PWR event 0x%02x", events);
    if (events & kPwrShort) {
      ++g_pwr_short_count;
      if (g_blanked) {
        Wake();
      } else {
        Blank();
      }
    }
    if (events & kPwrLong) ++g_pwr_long_count;
    if (!g_blanked) {
      switch (ui::Active()) {
        case ui::Screen::kCheck: RefreshCheck(); break;
        case ui::Screen::kKeepAwake: RefreshKeepAwake(); break;
        case ui::Screen::kMacros: RefreshMacros(); break;
        case ui::Screen::kKeyferry: RefreshKeyferry(); break;
        case ui::Screen::kHome:
          if (divider % 50 == 0) RefreshHome();
          break;
        default: break;
      }
    }
  }

  if (!g_blanked && lv_display_get_inactive_time(nullptr) >= kBlankAfterMs) Blank();
}

void OnRenderReady(lv_event_t*) { g_renders.fetch_add(1); }

// Runs on the esp_timer task, independent of LVGL: a function can always be left with BOOT, and a
// stalled UI inside a function returns to Home on its own.
void Supervise(void*) {
  static std::uint32_t last_ticks = 0;
  static std::int64_t last_progress = esp_timer_get_time();
  static bool boot_was_down = false;
  static std::uint32_t periods = 0;
  const std::int64_t now = esp_timer_get_time();
  const std::uint32_t ticks = g_ui_ticks.load();
  if (ticks != last_ticks) {
    last_ticks = ticks;
    last_progress = now;
  }
  const bool boot_down = gpio_get_level(kBootGpio) == 0;
  static std::int64_t boot_down_since = 0;
  if (boot_down && !boot_was_down) boot_down_since = now;
  if (UsbFunction()) {
    if (boot_down) StopInput();
    if (boot_was_down && !boot_down) RequestUsbExit();
    if (now - last_progress > 5000000 && !g_usb_exit_requested.load()) {
      ESP_LOGE(kTag, "UI stalled for 5 s inside a function; returning Home");
      RequestUsbExit();
    }
  }
  if (g_function == Function::kKeyferry && now > 60000000 && g_keyferry_starts.count != 0) {
    g_keyferry_starts.count = 0;
  }
  if (g_function == Function::kKeyferry && boot_was_down && !boot_down &&
      now - boot_down_since >= kBootLongHoldUs) {
    RequestKeyferryExit();  // the bridge never depends on the UI task to be left
  }
  boot_was_down = boot_down;
  if (g_function == Function::kHome && now > 3000000) PrintPreviousFlightLog();
  if (++periods % 50 == 0) {  // every 5 s
    ESP_LOGI(kTag, "status fn=%u ui_ticks=%u renders=%u blanked=%d bright=%d usb=%d run=%d nudges=%u macro=%d",
             static_cast<unsigned>(g_function), static_cast<unsigned>(ticks),
             static_cast<unsigned>(g_renders.load()), g_blanked, g_brightness,
             UsbFunction() && UsbHidMounted(), KeepAwakeRunning(),
             static_cast<unsigned>(KeepAwakeNudges()), MacroPadBusy());
  }
#if defined(KEYFERRY_HANDHELD_SELFTEST)
  const std::uint32_t seconds = static_cast<std::uint32_t>(now / 1000000);
  if (g_selftest.magic != kSelfTestMagic) g_selftest = SelfTest{kSelfTestMagic, 0};
  if (g_function == Function::kHome && seconds >= 4 && g_selftest.round < kSelfTestRounds) {
    ++g_selftest.round;
    ESP_LOGI(kTag, "selftest round %u: launching Keep Awake", static_cast<unsigned>(g_selftest.round));
    Launch(Function::kKeepAwake);
  }
  if (g_function == Function::kKeepAwake) {
    if (seconds >= 4 && !KeepAwakeRunning() && KeepAwakeNudges() == 0 &&
        KeepAwakeStateNow() == KeepAwakeState::kReady && UsbHidMounted()) {
      KeepAwakeSetRunning(true);
    }
    if (seconds >= 20) {
      ESP_LOGI(kTag, "selftest: leaving Keep Awake");
      KeepAwakeSetRunning(false);
      Launch(Function::kHome);
    }
  }
#endif
}

// The panel and touch controller reset only through the TCA9554 expander (EXIO0..2), as the
// vendor examples do and the BSP does not. Without it an internal restart left the panel in its
// previous state and a launched function could come up black (bench, 2026-11-04).
void ResetPanelAndTouch() {
  if (bsp_i2c_init() != ESP_OK) return;
  esp_io_expander_handle_t expander = bsp_io_expander_init();
  if (expander == nullptr) return;
  const std::uint32_t pins = IO_EXPANDER_PIN_NUM_0 | IO_EXPANDER_PIN_NUM_1 | IO_EXPANDER_PIN_NUM_2;
  if (esp_io_expander_set_dir(expander, pins, IO_EXPANDER_OUTPUT) != ESP_OK ||
      esp_io_expander_set_level(expander, pins, 0) != ESP_OK) {
    return;
  }
  vTaskDelay(pdMS_TO_TICKS(20));
  esp_io_expander_set_level(expander, pins, 1);
  vTaskDelay(pdMS_TO_TICKS(120));  // reset-to-first-command time for the panel
}

ui::Screen FirstScreen() {
  switch (g_function) {
    case Function::kKeepAwake: return ui::Screen::kKeepAwake;
    case Function::kMacros: return ui::Screen::kMacros;
    case Function::kKeyferry: return ui::Screen::kKeyferry;
    default: return ui::Screen::kHome;
  }
}

void StartUi() {
  gpio_config_t boot{};
  boot.pin_bit_mask = 1ULL << kBootGpio;
  boot.mode = GPIO_MODE_INPUT;
  boot.pull_up_en = GPIO_PULLUP_ENABLE;
  gpio_config(&boot);

  // The supervisor carries the BOOT exit and stall recovery, so it starts before and does not
  // depend on the display.
  esp_timer_create_args_t supervisor{};
  supervisor.callback = Supervise;
  supervisor.name = "kf_supervise";
  esp_timer_handle_t supervisor_timer = nullptr;
  const bool supervised = esp_timer_create(&supervisor, &supervisor_timer) == ESP_OK &&
                          esp_timer_start_periodic(supervisor_timer, 100000) == ESP_OK;
  if (!supervised) {
    ESP_LOGE(kTag, "supervisor unavailable");
    // Without an independent exit the bridge must not keep accepting input: close it now.
    if (g_function == Function::kKeyferry && g_keyferry.begin_leave != nullptr) {
      g_keyferry.begin_leave(g_keyferry.context);
    }
  }

  if (UsbFunction()) StartUsbExitWorker();  // before any input can start

  ResetPanelAndTouch();
  if (bsp_display_start() == nullptr) {
    ESP_LOGE(kTag, "display start failed");
    return;
  }
  PmuInit();  // key-event latching and measurement only; PWR blanks/wakes in every function
  if (g_function == Function::kKeepAwake && !KeepAwakeStartUsb()) Launch(Function::kHome);
  if (g_function == Function::kMacros && !MacroPadStart()) Launch(Function::kHome);
  ui::Config config;
#if defined(KEYFERRY_HANDHELD_KEYFERRY)
  config.keyferry = true;
#endif
  config.brightness = g_brightness;
  config.min_brightness = kMinBrightness;
  config.start_in_keyferry = LoadStartInKeyferry();
  config.host = g_host;
  config.macro_page = LoadSetting(kMacroPageKey, 0);
  config.action = OnAction;
  bsp_display_lock(0);
  ui::Build(config, FirstScreen());
  lv_timer_create(OnTick, 20, nullptr);
  lv_display_add_event_cb(lv_display_get_default(), OnRenderReady, LV_EVENT_RENDER_READY, nullptr);
  bsp_display_unlock();
  bsp_display_brightness_set(g_brightness);
}

}  // namespace

void StartKeyferryShell(const KeyferryHooks& hooks) {
  g_keyferry = hooks;
  StartExitWorker();  // before any UI: leaving must not depend on the display coming up
  if (g_exit_worker == nullptr && g_keyferry.begin_leave != nullptr) {
    g_keyferry.begin_leave(g_keyferry.context);  // no way to leave cleanly: stop input now
  }
  g_brightness = LoadBrightness();  // the bridge has already initialized NVS
  StartUi();
}

void RunShellUnlessKeyferry() {
  // A CPU-only reset (esp_restart, panic, watchdog) leaves the display's SPI/DMA state behind and
  // the next panel reset can hang; turn it into a full digital-system reset before touching
  // anything. RTC memory, and so the function selection, survives it.
  switch (esp_rom_get_reset_reason(0)) {
    case RESET_REASON_CPU0_SW:
    case RESET_REASON_CPU0_MWDT0:
    case RESET_REASON_CPU0_MWDT1:
    case RESET_REASON_CPU0_RTC_WDT:
      g_upgraded_reset_reason = static_cast<std::uint32_t>(esp_rom_get_reset_reason(0));
      esp_rom_software_reset_system();
      break;
    case RESET_REASON_CORE_SW:
      break;  // keep the cause recorded just before an upgrade
    default:
      g_upgraded_reset_reason = kNoUpgrade;
      break;
  }
  const esp_err_t nvs = nvs_flash_init();  // never erases; the bridge reports any failure itself
  bool deliberate = false;
  g_function = TakeSelection(&deliberate);
  if (!deliberate && LoadStartInKeyferry()) g_function = Function::kKeyferry;
  if (g_function == Function::kKeyferry) {
    if (g_keyferry_starts.magic != kStartsMagic) g_keyferry_starts = KeyferryStarts{kStartsMagic, 0};
    if (++g_keyferry_starts.count > kMaxKeyferryStarts) {
      g_keyferry_starts.count = 0;
      g_function = Function::kHome;
    }
  }
  StartFlightLog(g_function == Function::kHome);
  if (g_function == Function::kKeyferry) {
    // Any restart inside the bridge (its own restarts, a crash) comes back to the bridge.
    const auto value = static_cast<std::uint32_t>(Function::kKeyferry);
    g_selection = BootSelection{kSelectionMagic, value, ~value ^ ImageTag()};
    return;
  }
#if defined(KEYFERRY_HANDHELD_SELFTEST)
  if (esp_reset_reason() != ESP_RST_SW) g_selftest = SelfTest{kSelfTestMagic, 0};
#endif
  ESP_LOGI(kTag, "boot: function=%u reset_reason=%d upgraded_from=0x%x", static_cast<unsigned>(g_function),
           static_cast<int>(esp_reset_reason()), static_cast<unsigned>(g_upgraded_reset_reason));
  if (g_function == Function::kHome) {
    // A previous function may have left the internal PHY on USB OTG (RTC register survives a
    // software restart); hand it back to USB-Serial/JTAG so Home keeps console and ROM access.
    usb_serial_jtag_ll_phy_enable_external(false);
  }
  if (nvs != ESP_OK) ESP_LOGE(kTag, "NVS unavailable (%s); settings will not persist", esp_err_to_name(nvs));
  g_brightness = LoadBrightness();
  g_host = LoadHost();
  StartUi();
  const PowerStatus power = ReadPower();
  ESP_LOGI(kTag, "shell ready: pmu=%d vbus=%d battery=%d mv=%d pct=%d charge=%d internal_free=%u largest=%u",
           power.readable, power.vbus_good, power.battery_present, power.battery_mv,
           power.battery_percent, power.charge_direction,
           static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL)),
           static_cast<unsigned>(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)));
  if (bsp_display_lock(0)) {
    RefreshHome();
    bsp_display_unlock();
  }
  for (;;) vTaskDelay(portMAX_DELAY);
}

}  // namespace keyferry::handheld
