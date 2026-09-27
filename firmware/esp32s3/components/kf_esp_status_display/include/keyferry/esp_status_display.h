#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "board_profile.h"
#include "esp_lcd_panel_io.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "keyferry_protocol_generated.h"
#include "keyferry/status.h"

namespace keyferry::status {

// Optional, non-authoritative display adapter. Any initialization or transfer
// failure permanently disables this instance without affecting USB, transport,
// provisioning, or key-release behavior.
class EspStatusDisplay final {
 public:
  bool Initialize(protocol::DisplayOrientation orientation, bool screen_on);
  bool Show(const Presentation& presentation);
  // Called only by the status task; false means hardware state is unknown.
  bool SetEnabled(bool enabled);
  [[nodiscard]] bool available() const noexcept { return available_; }

 private:
  static constexpr std::size_t kRowsPerTransfer = 8;
  static bool TransferDone(esp_lcd_panel_io_handle_t io,
                           esp_lcd_panel_io_event_data_t* event,
                           void* context);

  bool ConfigurePanel();
  bool ConfigureBacklight();
  bool ResetPanel();
  bool InitializeController();
  bool InitializeSt7735();
  bool InitializeSt7789();
  bool SendPanelCommand(std::uint8_t command, const std::uint8_t* data,
                        std::size_t size);
  bool SendScanlines(std::size_t y, std::size_t rows);
  void PaintBlock(std::size_t y, std::size_t rows,
                  const Presentation& presentation);
  bool SetBacklight(bool enabled);
  void Disable();

  SemaphoreHandle_t transfer_done_{nullptr};
  esp_lcd_panel_io_handle_t io_{nullptr};
  std::array<std::uint16_t,
             static_cast<std::size_t>(board::display.width) * kRowsPerTransfer>
      scanlines_{};
  std::optional<Presentation> last_{};
  bool backlight_configured_{false};
  bool available_{false};
  bool backlight_on_{false};
  protocol::DisplayOrientation orientation_{
      protocol::DisplayOrientation::kNormal};
};

}  // namespace keyferry::status
