// Handheld touch shell, phase 1 (ADR 0018): Home, Board Check and Settings.
// No radio, no application USB class, no SD writes.
#include "keyferry/handheld.h"

#include <cinttypes>
#include <cstdio>

#include "bsp/esp-bsp.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lvgl.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdmmc_cmd.h"

namespace keyferry::handheld {
namespace {

constexpr char kTag[] = "handheld";
constexpr char kNvsNamespace[] = "kf_hh";
constexpr char kBrightnessKey[] = "bright";
constexpr int kDefaultBrightness = 60;
constexpr int kMinBrightness = 5;
constexpr std::uint32_t kBlankAfterMs = 30000;
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
};

Ui g_ui;
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

  AddButton(g_ui.home, "Keyferry", 96, OnNavigate, nullptr, false);
  AddButton(g_ui.home, "Keep Awake", 166, OnNavigate, nullptr, false);
  AddButton(g_ui.home, "USB Drive", 236, OnNavigate, nullptr, false);
  AddButton(g_ui.home, "Board Check", 306, OnNavigate, g_ui.check);
  AddButton(g_ui.home, "Settings", 376, OnNavigate, g_ui.settings);

  lv_obj_set_clickable(g_ui.check, true);
  lv_obj_add_event_cb(g_ui.check, OnCheckTouch, LV_EVENT_PRESSING, nullptr);
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
  lv_obj_t* hint = AddInfoLabel(g_ui.settings, 230);
  lv_label_set_text(hint, "Screen turns off after 30 s idle.\nTouch, BOOT or PWR wakes it.");
  AddButton(g_ui.settings, "Home", 370, OnNavigate, g_ui.home);

  g_ui.wake_shield = lv_obj_create(lv_layer_top());
  lv_obj_set_size(g_ui.wake_shield, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_opa(g_ui.wake_shield, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(g_ui.wake_shield, 0, 0);
  lv_obj_add_event_cb(g_ui.wake_shield, OnWakeShield, LV_EVENT_PRESSED, nullptr);
  lv_obj_add_event_cb(g_ui.wake_shield, OnWakeShield, LV_EVENT_RELEASED, nullptr);
  lv_obj_set_hidden(g_ui.wake_shield, true);

  lv_screen_load(g_ui.home);
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
  const bool boot_down = gpio_get_level(kBootGpio) == 0;
  const std::int64_t now = esp_timer_get_time();
  if (boot_down && !g_boot_down) {
    g_boot_down_since = now;
    g_boot_long = false;
  }
  if (boot_down && !g_boot_long && now - g_boot_down_since >= kBootLongHoldUs) {
    g_boot_long = true;  // restart only after release so GPIO0 cannot select ROM download
    Wake();
  }
  if (!boot_down && g_boot_down) {
    if (g_boot_long) {
      ESP_LOGI(kTag, "BOOT long hold released: restarting to Home");
      esp_restart();
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
    if (events & kPwrShort) {
      ++g_pwr_short_count;
      if (g_blanked) {
        Wake();
      } else {
        Blank();
      }
    }
    if (events & kPwrLong) ++g_pwr_long_count;
    if (lv_screen_active() == g_ui.check) RefreshCheck();
  }

  if (!g_blanked && lv_display_get_inactive_time(nullptr) >= kBlankAfterMs) Blank();
}

}  // namespace

[[noreturn]] void RunShell() {
  const esp_err_t nvs = nvs_flash_init();
  if (nvs != ESP_OK) ESP_LOGE(kTag, "NVS unavailable (%s); settings will not persist", esp_err_to_name(nvs));
  g_brightness = LoadBrightness();

  gpio_config_t boot{};
  boot.pin_bit_mask = 1ULL << kBootGpio;
  boot.mode = GPIO_MODE_INPUT;
  boot.pull_up_en = GPIO_PULLUP_ENABLE;
  gpio_config(&boot);

  if (bsp_display_start() == nullptr) {
    ESP_LOGE(kTag, "display start failed");
    for (;;) vTaskDelay(portMAX_DELAY);
  }
  PmuInit();
  bsp_display_lock(0);
  BuildUi();
  lv_timer_create(OnTick, 20, nullptr);
  bsp_display_unlock();
  bsp_display_brightness_set(g_brightness);
  const PowerStatus power = ReadPower();
  ESP_LOGI(kTag, "shell ready: pmu=%d vbus=%d battery=%d mv=%d pct=%d charge=%d internal_free=%u largest=%u",
           power.readable, power.vbus_good, power.battery_present, power.battery_mv,
           power.battery_percent, power.charge_direction,
           static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL)),
           static_cast<unsigned>(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)));
  for (;;) vTaskDelay(portMAX_DELAY);
}

}  // namespace keyferry::handheld
