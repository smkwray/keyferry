// Handheld touch shell (ADR 0018): Home, Board Check, Settings and the Keep Awake function.
// Functions are mutually exclusive: launching one records it in RTC memory and restarts, and
// leaving it restarts to Home. Home has no radio, no application USB class and no SD writes.
#include "keyferry/handheld.h"

#include <atomic>
#include <iterator>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>

#include "bsp/esp-bsp.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "soc/reset_reasons.h"
#include <algorithm>
#include <cstring>
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hal/usb_serial_jtag_ll.h"
#include "keep_awake.h"
#include "lvgl.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdmmc_cmd.h"

namespace keyferry::handheld {
namespace {

constexpr char kTag[] = "handheld";
constexpr char kNvsNamespace[] = "kf_hh";
constexpr char kBrightnessKey[] = "bright";
constexpr char kStartKey[] = "start";  // 1: power-up starts Keyferry
constexpr int kDefaultBrightness = 60;
constexpr int kMinBrightness = 5;
constexpr std::uint32_t kBlankAfterMs = 20000;
constexpr std::int64_t kBootLongHoldUs = 2000000;
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

enum class Function : std::uint32_t { kHome = 0, kKeepAwake = 1, kKeyferry = 2 };

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
  g_selection = BootSelection{0, 0, 0};  // a crash or reset inside Home or Keep Awake leaves it
  *deliberate = selection.magic == kSelectionMagic &&
                selection.check == (~selection.function ^ ImageTag());
  if (!*deliberate) {
    return Function::kHome;
  }
  switch (selection.function) {
    case static_cast<std::uint32_t>(Function::kKeepAwake): return Function::kKeepAwake;
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

struct Ui {
  lv_obj_t* home = nullptr;
  lv_obj_t* check = nullptr;
  lv_obj_t* settings = nullptr;
  lv_obj_t* touch_dot = nullptr;
  lv_obj_t* touch_label = nullptr;
  lv_obj_t* buttons_label = nullptr;
  lv_obj_t* power_label = nullptr;
  lv_obj_t* storage_label = nullptr;
  lv_obj_t* memory_label = nullptr;
  lv_obj_t* brightness_label = nullptr;
  lv_obj_t* wake_shield = nullptr;
  lv_obj_t* keep_awake = nullptr;
  lv_obj_t* keep_awake_status = nullptr;
  lv_obj_t* keep_awake_toggle = nullptr;
  lv_obj_t* keyferry = nullptr;
  lv_obj_t* keyferry_status = nullptr;
};

Ui g_ui;
Function g_function = Function::kHome;
std::atomic<std::uint32_t> g_ui_ticks{0};
std::atomic<std::uint32_t> g_renders{0};
KeyferryHooks g_keyferry{};
std::atomic<bool> g_leaving{false};
i2c_master_dev_handle_t g_pmu = nullptr;
int g_brightness = kDefaultBrightness;
bool g_blanked = false;
bool g_boot_down = false;
bool g_boot_long = false;
std::int64_t g_boot_down_since = 0;
std::uint32_t g_pwr_short_count = 0;
std::uint32_t g_pwr_long_count = 0;
volatile SdState g_sd_state = SdState::kUnchecked;
std::uint64_t g_sd_bytes = 0;
esp_err_t g_sd_error = ESP_OK;

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

int LoadBrightness() {
  nvs_handle_t handle;
  std::uint8_t value = kDefaultBrightness;
  if (nvs_open(kNvsNamespace, NVS_READONLY, &handle) == ESP_OK) {
    nvs_get_u8(handle, kBrightnessKey, &value);
    nvs_close(handle);
  }
  return value < kMinBrightness || value > 100 ? kDefaultBrightness : value;
}

bool LoadStartInKeyferry() {
#if defined(KEYFERRY_HANDHELD_KEYFERRY)
  // ADR 0018: power-up shows Home unless the owner turned "Start in Keyferry" on (stored 1).
  nvs_handle_t handle;
  std::uint8_t value = 0;
  if (nvs_open(kNvsNamespace, NVS_READONLY, &handle) != ESP_OK) return false;
  const esp_err_t read = nvs_get_u8(handle, kStartKey, &value);
  nvs_close(handle);
  return read == ESP_OK && value == 1;
#else
  return false;
#endif
}

#if defined(KEYFERRY_HANDHELD_KEYFERRY)
void StoreStartInKeyferry(bool value) {
  nvs_handle_t handle;
  if (nvs_open(kNvsNamespace, NVS_READWRITE, &handle) != ESP_OK) return;
  if (nvs_set_u8(handle, kStartKey, value ? 1 : 0) == ESP_OK) nvs_commit(handle);
  nvs_close(handle);
}
#endif

void StoreBrightness(int value) {
  nvs_handle_t handle;
  if (nvs_open(kNvsNamespace, NVS_READWRITE, &handle) != ESP_OK) return;
  if (nvs_set_u8(handle, kBrightnessKey, static_cast<std::uint8_t>(value)) == ESP_OK) {
    nvs_commit(handle);
  }
  nvs_close(handle);
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
  lv_obj_set_hidden(g_ui.wake_shield, false);
}

void Wake() {
  if (!g_blanked) return;
  g_blanked = false;
  bsp_display_brightness_set(g_brightness);
  lv_display_trigger_activity(nullptr);
}

void ShowScreen(lv_obj_t* screen) {
  ESP_LOGI(kTag, "screen %s",
           screen == g_ui.home ? "home" : screen == g_ui.check ? "check" : "settings");
  lv_screen_load(screen);
  if (screen == g_ui.check && g_sd_state == SdState::kUnchecked) {
    g_sd_state = SdState::kChecking;
    xTaskCreate(SdCheckTask, "kf_sd_check", 4096, nullptr, 3, nullptr);
  }
}

// --- UI construction -------------------------------------------------------------------------

lv_obj_t* NewScreen(const char* title) {
  lv_obj_t* screen = lv_obj_create(nullptr);
  lv_obj_set_style_bg_color(screen, lv_color_black(), 0);
  lv_obj_set_style_text_color(screen, lv_color_white(), 0);
  lv_obj_set_scrollable(screen, false);
  lv_obj_t* label = lv_label_create(screen);
  lv_label_set_text(label, title);
  lv_obj_set_style_text_font(label, &lv_font_montserrat_28, 0);
  lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 24);
  return screen;
}

lv_obj_t* AddButton(lv_obj_t* parent, const char* text, int y, lv_event_cb_t callback,
                    void* target, bool enabled = true) {
  lv_obj_t* button = lv_button_create(parent);
  lv_obj_set_size(button, 300, 58);
  lv_obj_align(button, LV_ALIGN_TOP_MID, 0, y);
  lv_obj_t* label = lv_label_create(button);
  lv_label_set_text(label, text);
  lv_obj_set_style_text_font(label, &lv_font_montserrat_20, 0);
  lv_obj_center(label);
  if (enabled) {
    lv_obj_add_event_cb(button, callback, LV_EVENT_CLICKED, target);
  } else {
    lv_obj_add_state(button, LV_STATE_DISABLED);
  }
  return button;
}

// Home tiles: a 2-column grid of near-square targets (about 160 x 113 px) with an icon above
// the name, easier to hit than full-width bars.
constexpr int kTileWidth = 160;
constexpr int kTileHeight = 113;
constexpr int kTileGap = 11;
constexpr int kTileTop = 72;

void AddTile(lv_obj_t* parent, int index, const char* symbol, const char* text,
             lv_event_cb_t callback, void* target, bool enabled = true) {
  lv_obj_t* tile = lv_button_create(parent);
  lv_obj_set_size(tile, kTileWidth, kTileHeight);
  const int column = index % 2;
  const int row = index / 2;
  const int left = (BSP_LCD_H_RES - 2 * kTileWidth - kTileGap) / 2;
  lv_obj_set_pos(tile, left + column * (kTileWidth + kTileGap),
                 kTileTop + row * (kTileHeight + kTileGap));
  lv_obj_set_flex_flow(tile, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(tile, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(tile, 8, 0);
  lv_obj_t* icon = lv_label_create(tile);
  lv_label_set_text(icon, symbol);
  lv_obj_set_style_text_font(icon, &lv_font_montserrat_28, 0);
  lv_obj_t* label = lv_label_create(tile);
  lv_label_set_text(label, text);
  lv_obj_set_style_text_font(label, &lv_font_montserrat_20, 0);
  if (enabled) {
    lv_obj_add_event_cb(tile, callback, LV_EVENT_CLICKED, target);
  } else {
    lv_obj_add_state(tile, LV_STATE_DISABLED);
  }
}

void OnNavigate(lv_event_t* event) {
  ShowScreen(static_cast<lv_obj_t*>(lv_event_get_user_data(event)));
}

lv_obj_t* AddInfoLabel(lv_obj_t* parent, int y) {
  lv_obj_t* label = lv_label_create(parent);
  lv_obj_set_width(label, 320);
  lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
  lv_obj_align(label, LV_ALIGN_TOP_LEFT, 24, y);
  lv_label_set_text(label, "");
  return label;
}

void OnCheckTouch(lv_event_t*) {
  lv_point_t point{};
  lv_indev_get_point(lv_indev_active(), &point);
  lv_obj_set_pos(g_ui.touch_dot, point.x - 12, point.y - 12);
  lv_obj_set_hidden(g_ui.touch_dot, false);
  lv_label_set_text_fmt(g_ui.touch_label, "Touch: x %d  y %d", static_cast<int>(point.x),
                        static_cast<int>(point.y));
}

void OnCheckPressed(lv_event_t*) {
  lv_point_t point{};
  lv_indev_get_point(lv_indev_active(), &point);
  ESP_LOGI(kTag, "touch %d %d", static_cast<int>(point.x), static_cast<int>(point.y));
}

void OnLaunchKeepAwake(lv_event_t*) { Launch(Function::kKeepAwake); }

void OnLeaveFunction(lv_event_t*) {
  KeepAwakeSetRunning(false);
  Launch(Function::kHome);
}

void OnKeepAwakeToggle(lv_event_t*) { KeepAwakeSetRunning(!KeepAwakeRunning()); }

#if defined(KEYFERRY_HANDHELD_KEYFERRY)
void OnLaunchKeyferry(lv_event_t*) { Launch(Function::kKeyferry); }
#endif

constexpr TickType_t kExitDisplayLockTicks = pdMS_TO_TICKS(50);
constexpr std::int64_t kExitNeutralTimeoutUs = 3000000;
TaskHandle_t g_exit_worker = nullptr;

// Display text is optional during an exit and never waits long for the LVGL lock.
void ShowExitText(const char* text) {
  if (g_ui.keyferry_status != nullptr &&
      bsp_display_lock(kExitDisplayLockTicks * portTICK_PERIOD_MS)) {
    lv_label_set_text(g_ui.keyferry_status, text);
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

void OnLeaveKeyferry(lv_event_t*) { RequestKeyferryExit(); }

void RefreshKeyferry() {
  if (g_leaving.load() || g_keyferry.status == nullptr) return;
  char text[256] = {};
  g_keyferry.status(g_keyferry.context, text, sizeof(text));
  lv_label_set_text(g_ui.keyferry_status, text);
}

#if defined(KEYFERRY_HANDHELD_KEYFERRY)
void OnStartInKeyferry(lv_event_t* event) {
  lv_obj_t* toggle = static_cast<lv_obj_t*>(lv_event_get_target(event));
  StoreStartInKeyferry(lv_obj_has_state(toggle, LV_STATE_CHECKED));
}
#endif

void OnBrightness(lv_event_t* event) {
  lv_obj_t* slider = static_cast<lv_obj_t*>(lv_event_get_target(event));
  g_brightness = lv_slider_get_value(slider);
  bsp_display_brightness_set(g_brightness);
  lv_label_set_text_fmt(g_ui.brightness_label, "Brightness: %d%%", g_brightness);
  if (lv_event_get_code(event) == LV_EVENT_RELEASED) StoreBrightness(g_brightness);
}

void OnWakeShield(lv_event_t* event) {
  // The whole gesture that wakes the screen is consumed; it never reaches a control.
  if (lv_event_get_code(event) == LV_EVENT_PRESSED) Wake();
  if (lv_event_get_code(event) == LV_EVENT_RELEASED) {
    lv_obj_set_hidden(g_ui.wake_shield, true);
  }
}

void BuildUi() {
  g_ui.home = NewScreen("Keyferry");
  g_ui.check = NewScreen("Board Check");
  g_ui.settings = NewScreen("Settings");

#if defined(KEYFERRY_HANDHELD_KEYFERRY)
  AddTile(g_ui.home, 0, LV_SYMBOL_KEYBOARD, "Keyferry", OnLaunchKeyferry, nullptr);
#else
  AddTile(g_ui.home, 0, LV_SYMBOL_KEYBOARD, "Keyferry", OnNavigate, nullptr, false);
#endif
  AddTile(g_ui.home, 1, LV_SYMBOL_EYE_OPEN, "Keep Awake", OnLaunchKeepAwake, nullptr);
  AddTile(g_ui.home, 2, LV_SYMBOL_USB, "USB Drive", OnNavigate, nullptr, false);
  AddTile(g_ui.home, 3, LV_SYMBOL_LIST, "Board Check", OnNavigate, g_ui.check);
  AddTile(g_ui.home, 4, LV_SYMBOL_SETTINGS, "Settings", OnNavigate, g_ui.settings);

  lv_obj_set_clickable(g_ui.check, true);
  lv_obj_add_event_cb(g_ui.check, OnCheckTouch, LV_EVENT_PRESSING, nullptr);
  lv_obj_add_event_cb(g_ui.check, OnCheckPressed, LV_EVENT_PRESSED, nullptr);
  g_ui.touch_label = AddInfoLabel(g_ui.check, 80);
  lv_label_set_text(g_ui.touch_label, "Touch: tap anywhere");
  g_ui.buttons_label = AddInfoLabel(g_ui.check, 108);
  g_ui.power_label = AddInfoLabel(g_ui.check, 154);
  g_ui.storage_label = AddInfoLabel(g_ui.check, 222);
  g_ui.memory_label = AddInfoLabel(g_ui.check, 268);
  g_ui.touch_dot = lv_obj_create(g_ui.check);
  lv_obj_set_size(g_ui.touch_dot, 24, 24);
  lv_obj_set_style_radius(g_ui.touch_dot, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(g_ui.touch_dot, lv_palette_main(LV_PALETTE_CYAN), 0);
  lv_obj_set_clickable(g_ui.touch_dot, false);
  lv_obj_set_hidden(g_ui.touch_dot, true);
  AddButton(g_ui.check, "Home", 370, OnNavigate, g_ui.home);

  g_ui.brightness_label = AddInfoLabel(g_ui.settings, 110);
  lv_obj_set_style_text_font(g_ui.brightness_label, &lv_font_montserrat_20, 0);
  lv_label_set_text_fmt(g_ui.brightness_label, "Brightness: %d%%", g_brightness);
  lv_obj_t* slider = lv_slider_create(g_ui.settings);
  lv_obj_set_width(slider, 300);
  lv_obj_align(slider, LV_ALIGN_TOP_MID, 0, 170);
  lv_slider_set_range(slider, kMinBrightness, 100);
  lv_slider_set_value(slider, g_brightness, LV_ANIM_OFF);
  lv_obj_add_event_cb(slider, OnBrightness, LV_EVENT_VALUE_CHANGED, nullptr);
  lv_obj_add_event_cb(slider, OnBrightness, LV_EVENT_RELEASED, nullptr);
#if defined(KEYFERRY_HANDHELD_KEYFERRY)
  lv_obj_t* start_label = AddInfoLabel(g_ui.settings, 290);
  lv_obj_set_style_text_font(start_label, &lv_font_montserrat_20, 0);
  lv_label_set_text(start_label, "Start in Keyferry");
  lv_obj_t* start_switch = lv_switch_create(g_ui.settings);
  lv_obj_align(start_switch, LV_ALIGN_TOP_RIGHT, -24, 284);
  if (LoadStartInKeyferry()) lv_obj_add_state(start_switch, LV_STATE_CHECKED);
  lv_obj_add_event_cb(start_switch, OnStartInKeyferry, LV_EVENT_VALUE_CHANGED, nullptr);
#endif
  lv_obj_t* hint = AddInfoLabel(g_ui.settings, 230);
  lv_label_set_text(hint, "Screen turns off after 30 s idle.\nTouch, BOOT or PWR wakes it.");
  AddButton(g_ui.settings, "Home", 370, OnNavigate, g_ui.home);

  g_ui.keep_awake = NewScreen("Keep Awake");
  g_ui.keep_awake_status = AddInfoLabel(g_ui.keep_awake, 100);
  lv_obj_set_style_text_font(g_ui.keep_awake_status, &lv_font_montserrat_20, 0);
  g_ui.keep_awake_toggle = AddButton(g_ui.keep_awake, "Start", 270, OnKeepAwakeToggle, nullptr);
  AddButton(g_ui.keep_awake, "Home", 370, OnLeaveFunction, nullptr);

  g_ui.keyferry = NewScreen("Keyferry");
  g_ui.keyferry_status = AddInfoLabel(g_ui.keyferry, 90);
  lv_obj_set_style_text_font(g_ui.keyferry_status, &lv_font_montserrat_20, 0);
  AddButton(g_ui.keyferry, "Home", 370, OnLeaveKeyferry, nullptr);

  g_ui.wake_shield = lv_obj_create(lv_layer_top());
  lv_obj_set_size(g_ui.wake_shield, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_opa(g_ui.wake_shield, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(g_ui.wake_shield, 0, 0);
  lv_obj_add_event_cb(g_ui.wake_shield, OnWakeShield, LV_EVENT_PRESSED, nullptr);
  lv_obj_add_event_cb(g_ui.wake_shield, OnWakeShield, LV_EVENT_RELEASED, nullptr);
  lv_obj_set_hidden(g_ui.wake_shield, true);

  lv_screen_load(g_function == Function::kKeepAwake  ? g_ui.keep_awake
                 : g_function == Function::kKeyferry ? g_ui.keyferry
                                                     : g_ui.home);
}

const char* KeepAwakeText(KeepAwakeState state) {
  switch (state) {
    case KeepAwakeState::kRunning: return "Running";
    case KeepAwakeState::kStoppedUnplugged: return "Stopped: unplugged";
    case KeepAwakeState::kStoppedSuspended: return "Stopped: computer slept";
    case KeepAwakeState::kStoppedUnconfirmed: return "Stopped: report not confirmed";
    default: return "Ready";
  }
}

void RefreshKeepAwake() {
  lv_label_set_text_fmt(g_ui.keep_awake_status, "%s\nUSB: %s\nNudges: %u (every 25 s)",
                        KeepAwakeText(KeepAwakeStateNow()),
                        KeepAwakeUsbMounted() ? "connected" : "not connected",
                        static_cast<unsigned>(KeepAwakeNudges()));
  lv_label_set_text(lv_obj_get_child(g_ui.keep_awake_toggle, 0),
                    KeepAwakeRunning() ? "Stop" : "Start");
}

const char* ChargeText(int direction) {
  switch (direction) {
    case 1: return "charging";
    case 2: return "discharging";
    default: return "standby";
  }
}

void RefreshCheck() {
  lv_label_set_text_fmt(g_ui.buttons_label, "BOOT: %s   PWR: %" PRIu32 " short, %" PRIu32 " long",
                        g_boot_down ? "DOWN" : "up", g_pwr_short_count, g_pwr_long_count);
  const PowerStatus power = ReadPower();
  if (!power.readable) {
    lv_label_set_text(g_ui.power_label, "Power chip: not readable");
  } else if (!power.battery_present) {
    lv_label_set_text_fmt(g_ui.power_label, "USB power: %s\nBattery: none detected",
                          power.vbus_good ? "yes" : "no");
  } else {
    lv_label_set_text_fmt(g_ui.power_label, "USB power: %s\nBattery: %d mV, %d%%, %s",
                          power.vbus_good ? "yes" : "no", power.battery_mv,
                          power.battery_percent, ChargeText(power.charge_direction));
  }
  switch (g_sd_state) {
    case SdState::kUnchecked:
    case SdState::kChecking:
      lv_label_set_text(g_ui.storage_label, "SD card: checking...");
      break;
    case SdState::kMounted:
      lv_label_set_text_fmt(g_ui.storage_label, "SD card: %" PRIu32 " MiB, FAT mounted (read only use)",
                            static_cast<std::uint32_t>(g_sd_bytes >> 20));
      break;
    case SdState::kFailed:
      lv_label_set_text_fmt(g_ui.storage_label, "SD card: not mounted (%s)", esp_err_to_name(g_sd_error));
      break;
  }
  lv_label_set_text_fmt(
      g_ui.memory_label, "Internal RAM: %u KiB free, %u KiB largest\nPSRAM: %u KiB free",
      static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) >> 10),
      static_cast<unsigned>(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) >> 10),
      static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) >> 10));
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
    if (g_function == Function::kKeepAwake) KeepAwakeSetRunning(false);  // stop input at once
  }
  if (boot_down && !g_boot_long && now - g_boot_down_since >= kBootLongHoldUs) {
    g_boot_long = true;  // restart only after release so GPIO0 cannot select ROM download
    Wake();
  }
  if (!boot_down && g_boot_down) {
    ESP_LOGI(kTag, "BOOT up%s", g_boot_long ? " (long)" : "");
    if (g_function == Function::kKeepAwake) Launch(Function::kHome);  // after release: no ROM strap
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
      ShowScreen(g_ui.home);
    }
    lv_display_trigger_activity(nullptr);
  }
  g_boot_down = boot_down;

  static std::uint32_t pmu_divider = 0;
  if (++pmu_divider % 5 == 0) {
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
    if (!g_blanked && lv_screen_active() == g_ui.check) RefreshCheck();
    if (!g_blanked && lv_screen_active() == g_ui.keep_awake) RefreshKeepAwake();
    if (!g_blanked && lv_screen_active() == g_ui.keyferry) RefreshKeyferry();
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
  if (g_function == Function::kKeepAwake) {
    if (boot_down) KeepAwakeSetRunning(false);
    if (boot_was_down && !boot_down) Launch(Function::kHome);  // after release: no ROM strap
    if (now - last_progress > 5000000) {
      ESP_LOGE(kTag, "UI stalled for 5 s inside a function; returning Home");
      Launch(Function::kHome);
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
    ESP_LOGI(kTag, "status fn=%u ui_ticks=%u renders=%u blanked=%d bright=%d usb=%d run=%d nudges=%u",
             static_cast<unsigned>(g_function), static_cast<unsigned>(ticks),
             static_cast<unsigned>(g_renders.load()), g_blanked, g_brightness,
             g_function == Function::kKeepAwake && KeepAwakeUsbMounted(), KeepAwakeRunning(),
             static_cast<unsigned>(KeepAwakeNudges()));
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
        KeepAwakeStateNow() == KeepAwakeState::kReady && KeepAwakeUsbMounted()) {
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

  if (bsp_display_start() == nullptr) {
    ESP_LOGE(kTag, "display start failed");
    return;
  }
  PmuInit();  // key-event latching and measurement only; PWR blanks/wakes in every function
  if (g_function == Function::kKeepAwake && !KeepAwakeStartUsb()) Launch(Function::kHome);
  bsp_display_lock(0);
  BuildUi();
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
  StartUi();
  const PowerStatus power = ReadPower();
  ESP_LOGI(kTag, "shell ready: pmu=%d vbus=%d battery=%d mv=%d pct=%d charge=%d internal_free=%u largest=%u",
           power.readable, power.vbus_good, power.battery_present, power.battery_mv,
           power.battery_percent, power.charge_direction,
           static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL)),
           static_cast<unsigned>(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)));
  for (;;) vTaskDelay(portMAX_DELAY);
}

}  // namespace keyferry::handheld
