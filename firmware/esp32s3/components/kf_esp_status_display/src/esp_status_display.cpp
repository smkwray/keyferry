#include "keyferry/esp_status_display.h"

#include <algorithm>

#include "driver/gpio.h"
#include "driver/ledc.h"
#include "driver/spi_master.h"
#include "esp_lcd_io_spi.h"
#include "esp_log.h"
#include "freertos/task.h"
#include "keyferry/status_display_layout.h"

namespace keyferry::status {
namespace {

constexpr char kTag[] = "keyferry_lcd";
constexpr spi_host_device_t kSpiHost = SPI2_HOST;
constexpr ledc_mode_t kBacklightMode = LEDC_LOW_SPEED_MODE;
constexpr ledc_timer_t kBacklightTimer = LEDC_TIMER_0;
constexpr ledc_channel_t kBacklightChannel = LEDC_CHANNEL_0;
constexpr std::uint32_t kBacklightMaxDuty = (1U << 10U) - 1U;
constexpr std::uint32_t kTransferTimeoutMs = 100;
}  // namespace

bool EspStatusDisplay::Initialize(
    const protocol::DisplayOrientation orientation, const bool screen_on) {
  if constexpr (!board::capabilities.display) {
    return false;
  }
  static_assert(!board::capabilities.display ||
                (board::display.width > 0 && board::display.height > 0));
  static_assert(!board::capabilities.display ||
                (board::display.width <= 320 && board::display.height <= 320));
  if (orientation != protocol::DisplayOrientation::kNormal &&
      orientation != protocol::DisplayOrientation::kRotated180) {
    return false;
  }
  orientation_ = orientation;
  transfer_done_ = xSemaphoreCreateBinary();
  if (transfer_done_ == nullptr || !ConfigureBacklight() ||
      !ConfigurePanel()) {
    Disable();
    ESP_LOGW(kTag, "optional status display unavailable");
    return false;
  }
  available_ = true;
  const Snapshot boot{};
  if (!Show(BuildPresentation(boot, Page::kSummary))) {
    return false;
  }
  if (!SetBacklight(screen_on)) {
    Disable();
    return false;
  }
  backlight_on_ = screen_on;
  return true;
}

bool EspStatusDisplay::SetEnabled(const bool enabled) {
  if (!available_) return false;
  if (backlight_on_ == enabled) return true;
  if (!SetBacklight(enabled)) {
    Disable();
    return false;
  }
  backlight_on_ = enabled;
  return true;
}

bool EspStatusDisplay::ConfigureBacklight() {
  ledc_timer_config_t timer{};
  timer.speed_mode = kBacklightMode;
  timer.duty_resolution = LEDC_TIMER_10_BIT;
  timer.timer_num = kBacklightTimer;
  timer.freq_hz = 5000;
  timer.clk_cfg = LEDC_AUTO_CLK;
  if (ledc_timer_config(&timer) != ESP_OK) {
    return false;
  }
  ledc_channel_config_t channel{};
  channel.gpio_num = board::display.backlight_gpio;
  channel.speed_mode = kBacklightMode;
  channel.channel = kBacklightChannel;
  channel.timer_sel = kBacklightTimer;
  channel.duty =
      board::display.backlight_active_high ? 0 : kBacklightMaxDuty;
  channel.hpoint = 0;
  if (ledc_channel_config(&channel) != ESP_OK) {
    return false;
  }
  backlight_configured_ = true;
  return true;
}

bool EspStatusDisplay::ConfigurePanel() {
  spi_bus_config_t bus{};
  bus.mosi_io_num = board::display.mosi_gpio;
  bus.miso_io_num = -1;
  bus.sclk_io_num = board::display.clk_gpio;
  bus.quadwp_io_num = -1;
  bus.quadhd_io_num = -1;
  bus.max_transfer_sz = static_cast<int>(scanlines_.size() * sizeof(std::uint16_t));
  if (spi_bus_initialize(kSpiHost, &bus, SPI_DMA_CH_AUTO) != ESP_OK) {
    return false;
  }

  esp_lcd_panel_io_spi_config_t io_config{};
  io_config.cs_gpio_num = static_cast<gpio_num_t>(board::display.cs_gpio);
  io_config.dc_gpio_num = static_cast<gpio_num_t>(board::display.dc_gpio);
  io_config.spi_mode = 0;
  io_config.pclk_hz = board::display.pixel_clock_hz;
  io_config.trans_queue_depth = 1;
  io_config.on_color_trans_done = TransferDone;
  io_config.user_ctx = this;
  io_config.lcd_cmd_bits = 8;
  io_config.lcd_param_bits = 8;
  if (esp_lcd_new_panel_io_spi(
          static_cast<esp_lcd_spi_bus_handle_t>(kSpiHost), &io_config,
          &io_) != ESP_OK) {
    return false;
  }

  if (!ResetPanel() || !InitializeController()) {
    return false;
  }

  return true;
}

bool EspStatusDisplay::ResetPanel() {
  gpio_config_t reset{};
  reset.pin_bit_mask = 1ULL << board::display.reset_gpio;
  reset.mode = GPIO_MODE_OUTPUT;
  if (gpio_config(&reset) != ESP_OK ||
      gpio_set_level(static_cast<gpio_num_t>(board::display.reset_gpio), 0) !=
          ESP_OK) {
    return false;
  }
  vTaskDelay(pdMS_TO_TICKS(10));
  if (gpio_set_level(static_cast<gpio_num_t>(board::display.reset_gpio), 1) !=
      ESP_OK) {
    return false;
  }
  vTaskDelay(pdMS_TO_TICKS(10));
  return true;
}

bool EspStatusDisplay::InitializeController() {
  switch (board::display.controller) {
    case board::DisplayController::kSt7735:
      return InitializeSt7735();
    case board::DisplayController::kSt7789:
      return InitializeSt7789();
  }
  return false;
}

bool EspStatusDisplay::InitializeSt7789() {
  if (!SendPanelCommand(0x11, nullptr, 0)) {
    return false;
  }
  vTaskDelay(pdMS_TO_TICKS(100));

  const std::uint8_t color_mode = 0x55;
  const std::uint8_t ram_control[] = {0x00, 0xF8};
  if (!SendPanelCommand(0x3A, &color_mode, 1) ||
      !SendPanelCommand(0xB0, ram_control, sizeof(ram_control))) {
    return false;
  }

  const std::uint8_t porch[] = {0x0C, 0x0C, 0x00, 0x33, 0x33};
  const std::uint8_t gate = 0x35;
  const std::uint8_t vcom = 0x19;
  const std::uint8_t lcm = 0x2C;
  const std::uint8_t vdv_vrh_enable = 0x01;
  const std::uint8_t vrh = 0x12;
  const std::uint8_t vdv = 0x20;
  const std::uint8_t frame_rate = 0x0F;
  const std::uint8_t power[] = {0xA4, 0xA1};
  const std::uint8_t positive_gamma[] = {
      0xD0, 0x04, 0x0D, 0x11, 0x13, 0x2B, 0x3F,
      0x54, 0x4C, 0x18, 0x0D, 0x0B, 0x1F, 0x23};
  const std::uint8_t negative_gamma[] = {
      0xD0, 0x04, 0x0C, 0x11, 0x13, 0x2C, 0x3F,
      0x44, 0x51, 0x2F, 0x1F, 0x1F, 0x20, 0x23};
  const std::uint8_t madctl =
      orientation_ == protocol::DisplayOrientation::kRotated180
          ? static_cast<std::uint8_t>(board::display.madctl ^ 0xC0U)
          : board::display.madctl;
  if (!SendPanelCommand(0xB2, porch, sizeof(porch)) ||
      !SendPanelCommand(0xB7, &gate, 1) ||
      !SendPanelCommand(0xBB, &vcom, 1) ||
      !SendPanelCommand(0xC0, &lcm, 1) ||
      !SendPanelCommand(0xC2, &vdv_vrh_enable, 1) ||
      !SendPanelCommand(0xC3, &vrh, 1) ||
      !SendPanelCommand(0xC4, &vdv, 1) ||
      !SendPanelCommand(0xC6, &frame_rate, 1) ||
      !SendPanelCommand(0xD0, power, sizeof(power)) ||
      !SendPanelCommand(0xE0, positive_gamma, sizeof(positive_gamma)) ||
      !SendPanelCommand(0xE1, negative_gamma, sizeof(negative_gamma)) ||
      !SendPanelCommand(0x36, &madctl, 1) ||
      !SendPanelCommand(board::display.invert_colors ? 0x21 : 0x20, nullptr,
                        0) ||
      !SendPanelCommand(0x29, nullptr, 0)) {
    return false;
  }
  return true;
}

bool EspStatusDisplay::InitializeSt7735() {
  if (!SendPanelCommand(0x11, nullptr, 0)) {
    return false;
  }
  vTaskDelay(pdMS_TO_TICKS(100));

  const std::uint8_t frame_normal[] = {0x05, 0x3A, 0x3A};
  const std::uint8_t frame_partial[] = {0x05, 0x3A, 0x3A,
                                       0x05, 0x3A, 0x3A};
  const std::uint8_t inversion_control = 0x03;
  const std::uint8_t power_1[] = {0x62, 0x02, 0x04};
  const std::uint8_t power_2 = 0xC0;
  const std::uint8_t power_3[] = {0x0D, 0x00};
  const std::uint8_t power_4[] = {0x8D, 0x6A};
  const std::uint8_t power_5[] = {0x8D, 0xEE};
  const std::uint8_t vcom = 0x0E;
  const std::uint8_t color_mode = 0x05;
  const std::uint8_t positive_gamma[] = {
      0x10, 0x0E, 0x02, 0x03, 0x0E, 0x07, 0x02, 0x07,
      0x0A, 0x12, 0x27, 0x37, 0x00, 0x0D, 0x0E, 0x10};
  const std::uint8_t negative_gamma[] = {
      0x10, 0x0E, 0x03, 0x03, 0x0F, 0x06, 0x02, 0x08,
      0x0A, 0x13, 0x26, 0x36, 0x00, 0x0D, 0x0E, 0x10};
  const std::uint8_t madctl =
      orientation_ == protocol::DisplayOrientation::kRotated180
          ? static_cast<std::uint8_t>(board::display.madctl ^ 0xC0U)
          : board::display.madctl;
  if (!SendPanelCommand(0xB1, frame_normal, sizeof(frame_normal)) ||
      !SendPanelCommand(0xB2, frame_normal, sizeof(frame_normal)) ||
      !SendPanelCommand(0xB3, frame_partial, sizeof(frame_partial)) ||
      !SendPanelCommand(0xB4, &inversion_control, 1) ||
      !SendPanelCommand(0xC0, power_1, sizeof(power_1)) ||
      !SendPanelCommand(0xC1, &power_2, 1) ||
      !SendPanelCommand(0xC2, power_3, sizeof(power_3)) ||
      !SendPanelCommand(0xC3, power_4, sizeof(power_4)) ||
      !SendPanelCommand(0xC4, power_5, sizeof(power_5)) ||
      !SendPanelCommand(0xC5, &vcom, 1) ||
      !SendPanelCommand(board::display.invert_colors ? 0x21 : 0x20, nullptr,
                        0) ||
      !SendPanelCommand(0x3A, &color_mode, 1) ||
      !SendPanelCommand(0xE0, positive_gamma, sizeof(positive_gamma)) ||
      !SendPanelCommand(0xE1, negative_gamma, sizeof(negative_gamma)) ||
      !SendPanelCommand(0x36, &madctl, 1) ||
      !SendPanelCommand(0x13, nullptr, 0) ||
      !SendPanelCommand(0x29, nullptr, 0)) {
    return false;
  }
  return true;
}

bool EspStatusDisplay::SendPanelCommand(const std::uint8_t command,
                                        const std::uint8_t* data,
                                        const std::size_t size) {
  return io_ != nullptr &&
         esp_lcd_panel_io_tx_param(io_, command, data, size) == ESP_OK;
}

bool EspStatusDisplay::Show(const Presentation& presentation) {
  if (!available_) {
    return false;
  }
  if (last_.has_value() && *last_ == presentation) {
    return true;
  }
  for (std::size_t y = 0;
       y < static_cast<std::size_t>(board::display.height);
       y += kRowsPerTransfer) {
    const std::size_t rows =
        std::min(kRowsPerTransfer,
                 static_cast<std::size_t>(board::display.height) - y);
    PaintBlock(y, rows, presentation);
    if (!SendScanlines(y, rows)) {
      Disable();
      ESP_LOGW(kTag, "optional status display transfer failed");
      return false;
    }
  }
  last_ = presentation;
  return true;
}

void EspStatusDisplay::PaintBlock(const std::size_t y,
                                  const std::size_t rows,
                                  const Presentation& presentation) {
  display_layout::PaintBlock(scanlines_.data(), board::display.width,
                             board::display.height, y, rows, presentation);
}

bool EspStatusDisplay::SendScanlines(const std::size_t y,
                                     const std::size_t rows) {
  while (xSemaphoreTake(transfer_done_, 0) == pdTRUE) {
  }
  const int x_start = board::display.x_gap;
  const int x_end = x_start + board::display.width - 1;
  const int y_start = board::display.y_gap + static_cast<int>(y);
  const int y_end = y_start + static_cast<int>(rows) - 1;
  const std::uint8_t columns[] = {
      static_cast<std::uint8_t>(x_start >> 8),
      static_cast<std::uint8_t>(x_start),
      static_cast<std::uint8_t>(x_end >> 8),
      static_cast<std::uint8_t>(x_end)};
  const std::uint8_t row_range[] = {
      static_cast<std::uint8_t>(y_start >> 8),
      static_cast<std::uint8_t>(y_start),
      static_cast<std::uint8_t>(y_end >> 8),
      static_cast<std::uint8_t>(y_end)};
  if (!SendPanelCommand(0x2A, columns, sizeof(columns)) ||
      !SendPanelCommand(0x2B, row_range, sizeof(row_range))) {
    return false;
  }
  if constexpr (board::display.swap_color_bytes) {
    const std::size_t count =
        rows * static_cast<std::size_t>(board::display.width);
    for (std::size_t index = 0; index < count; ++index) {
      const std::uint16_t value = scanlines_[index];
      scanlines_[index] = static_cast<std::uint16_t>((value >> 8U) |
                                                     (value << 8U));
    }
  }
  const std::size_t transfer_bytes =
      rows * static_cast<std::size_t>(board::display.width) *
      sizeof(std::uint16_t);
  if (esp_lcd_panel_io_tx_color(io_, 0x2C, scanlines_.data(),
                                transfer_bytes) != ESP_OK) {
    return false;
  }
  return xSemaphoreTake(transfer_done_, pdMS_TO_TICKS(kTransferTimeoutMs)) ==
         pdTRUE;
}

bool EspStatusDisplay::TransferDone(esp_lcd_panel_io_handle_t,
                                    esp_lcd_panel_io_event_data_t*,
                                    void* context) {
  auto* self = static_cast<EspStatusDisplay*>(context);
  if (self == nullptr || self->transfer_done_ == nullptr) {
    return false;
  }
  BaseType_t higher_priority_task_woken = pdFALSE;
  xSemaphoreGiveFromISR(self->transfer_done_, &higher_priority_task_woken);
  return higher_priority_task_woken == pdTRUE;
}

bool EspStatusDisplay::SetBacklight(const bool enabled) {
  if (!backlight_configured_) {
    return false;
  }
  const std::uint32_t lit_duty =
      kBacklightMaxDuty * board::display.backlight_percent / 100U;
  const std::uint32_t duty =
      board::display.backlight_active_high
          ? (enabled ? lit_duty : 0U)
          : (enabled ? kBacklightMaxDuty - lit_duty : kBacklightMaxDuty);
  return ledc_set_duty(kBacklightMode, kBacklightChannel, duty) == ESP_OK &&
         ledc_update_duty(kBacklightMode, kBacklightChannel) == ESP_OK;
}

void EspStatusDisplay::Disable() {
  SetBacklight(false);
  available_ = false;
}

}  // namespace keyferry::status
