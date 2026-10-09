#pragma once
#include "board_profile.h"
#if defined(KEYFERRY_BOARD_RGB_STATUS)
#include "driver/rmt_tx.h"
#include "keyferry/status_led.h"

namespace keyferry::status {
class EspStatusLed final {
 public:
  bool Initialize();
  bool Show(const Snapshot& snapshot, std::uint64_t now_ms, bool armed);
  ~EspStatusLed();
 private:
  bool Write(LedColor color);
  rmt_channel_handle_t channel_{};
  rmt_encoder_handle_t encoder_{};
};
}  // namespace keyferry::status
#endif
