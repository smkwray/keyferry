#include "keyferry/esp_status_led.h"
#if defined(KEYFERRY_BOARD_RGB_STATUS)
#include <array>
#include "driver/gpio.h"
#include "driver/rmt_encoder.h"

namespace keyferry::status {
bool EspStatusLed::Initialize() {
  rmt_tx_channel_config_t config{};
  config.gpio_num = static_cast<gpio_num_t>(board::rgb_gpio);
  config.clk_src = RMT_CLK_SRC_DEFAULT;
  config.resolution_hz = 10000000;  // 100 ns ticks; WS2812C 800 kHz GRB.
  config.mem_block_symbols = 48;
  config.trans_queue_depth = 1;
  rmt_copy_encoder_config_t copy{};
  return rmt_new_tx_channel(&config, &channel_) == ESP_OK &&
         rmt_new_copy_encoder(&copy, &encoder_) == ESP_OK &&
         rmt_enable(channel_) == ESP_OK && Write({});
}

bool EspStatusLed::Write(const LedColor color) {
  std::array<rmt_symbol_word_t, 25> symbols{};
  const std::array<std::uint8_t, 3> grb{color.green, color.red, color.blue};
  std::size_t index = 0;
  for (auto byte : grb) {
    for (int bit = 7; bit >= 0; --bit) {
      const bool one = (byte & (1U << bit)) != 0;
      auto& symbol = symbols[index++];
      symbol.level0 = 1;
      symbol.duration0 = one ? 9 : 3;
      symbol.level1 = 0;
      symbol.duration1 = one ? 3 : 9;
    }
  }
  symbols[24].duration0 = 1500;
  symbols[24].duration1 = 1500;  // 300 us reset, both halves low.
  rmt_transmit_config_t transmit{};
  return channel_ != nullptr && encoder_ != nullptr &&
         rmt_transmit(channel_, encoder_, symbols.data(), sizeof(symbols), &transmit) == ESP_OK &&
         rmt_tx_wait_all_done(channel_, 100) == ESP_OK;
}

bool EspStatusLed::Show(const Snapshot& snapshot, const std::uint64_t now_ms, const bool armed) {
  if (Write(StatusLedColor(snapshot, now_ms, board::max_channel, armed))) return true;
  // The indicator is optional. Disable it permanently; input safety is independent.
  if (channel_ != nullptr) rmt_disable(channel_);
  gpio_set_level(static_cast<gpio_num_t>(board::rgb_gpio), 0);
  return false;
}

EspStatusLed::~EspStatusLed() {
  if (channel_ != nullptr) {
    rmt_disable(channel_);
    rmt_del_channel(channel_);
  }
  if (encoder_ != nullptr) rmt_del_encoder(encoder_);
}
}  // namespace keyferry::status
#endif
