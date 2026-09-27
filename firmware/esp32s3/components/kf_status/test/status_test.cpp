#include "keyferry/status.h"
#include "keyferry/status_display_layout.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <type_traits>
#include <vector>

namespace {

bool Overlaps(const keyferry::status::display_layout::PixelBounds& left,
              const keyferry::status::display_layout::PixelBounds& right) {
  return left.left < right.right && right.left < left.right &&
         left.top < right.bottom && right.top < left.bottom;
}

void ValidatePresentation(
    const keyferry::status::Presentation& presentation,
    const keyferry::status::display_layout::CanvasSize canvas) {
  using namespace keyferry::status::display_layout;
  for (std::size_t index = 0; index < presentation.line_count(); ++index) {
    const auto& line = presentation.line(index);
    assert(line.text.back() == '\0');
    assert(LineFits(line, canvas));
    for (const char* character = line.text.data(); *character != '\0';
         ++character) {
      assert(HasGlyph(*character));
    }
    for (std::size_t other = index + 1;
         other < presentation.line_count(); ++other) {
      assert(!Overlaps(BoundsFor(line, canvas),
                       BoundsFor(presentation.line(other), canvas)));
    }
  }

  constexpr std::size_t kRows = 8;
  std::vector<std::uint16_t> pixels(
      static_cast<std::size_t>(canvas.width) * kRows);
  bool painted = false;
  for (std::size_t y = 0; y < static_cast<std::size_t>(canvas.height);
       y += kRows) {
    const std::size_t rows =
        std::min(kRows, static_cast<std::size_t>(canvas.height) - y);
    std::fill(pixels.begin(), pixels.end(), std::uint16_t{0});
    PaintBlock(pixels.data(), canvas.width, canvas.height, y, rows,
               presentation);
    painted = painted ||
              std::any_of(pixels.begin(),
                          pixels.begin() + rows * canvas.width,
                          [](const std::uint16_t pixel) { return pixel != 0; });
  }
  assert(painted);
}

void WritePpm(const keyferry::status::Presentation& presentation,
              const keyferry::status::display_layout::CanvasSize canvas,
              const std::string& path) {
  using namespace keyferry::status::display_layout;
  constexpr std::size_t kRows = 8;
  std::vector<std::uint16_t> image(
      static_cast<std::size_t>(canvas.width) * canvas.height);
  std::vector<std::uint16_t> pixels(
      static_cast<std::size_t>(canvas.width) * kRows);
  for (std::size_t y = 0; y < static_cast<std::size_t>(canvas.height);
       y += kRows) {
    const std::size_t rows =
        std::min(kRows, static_cast<std::size_t>(canvas.height) - y);
    PaintBlock(pixels.data(), canvas.width, canvas.height, y, rows,
               presentation);
    std::copy_n(pixels.begin(), rows * canvas.width,
                image.begin() + y * canvas.width);
  }
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  assert(output.good());
  output << "P6\n" << canvas.width << ' ' << canvas.height << "\n255\n";
  for (const std::uint16_t pixel : image) {
    const std::array<char, 3> rgb{
        static_cast<char>(((pixel >> 11U) & 0x1FU) * 255U / 31U),
        static_cast<char>(((pixel >> 5U) & 0x3FU) * 255U / 63U),
        static_cast<char>((pixel & 0x1FU) * 255U / 31U)};
    output.write(rgb.data(), static_cast<std::streamsize>(rgb.size()));
  }
  assert(output.good());
}

}  // namespace

int main(const int argc, char** argv) {
  using namespace keyferry::status;
  using namespace keyferry::status::display_layout;
  constexpr CanvasSize kWaveshareCanvas{240, 135};
  constexpr CanvasSize kLilygoCanvas{160, 80};

  Snapshot ready{};
  ready.usb_mounted = true;
  ready.link = LinkPath::kWifi;
  ready.activity = Activity::kReady;
  ready.config_generation = 7;
  std::memcpy(ready.build_id.data(), "0123ABCD", 8);
  assert(std::strcmp(UsbLabel(true, false), "USB READY") == 0);
  assert(std::strcmp(UsbLabel(false, false), "USB OFF") == 0);
  assert(std::strcmp(UsbLabel(true, true), "USB SLEEP") == 0);
  assert(std::strcmp(LinkLabel(LinkPath::kBluetooth), "BLUETOOTH") == 0);
  assert(std::strcmp(ActivityLabel(Activity::kProvisioning), "SETUP") == 0);
  assert(std::strcmp(ConnectionLabel(ConnectionProgress::kWifiJoining),
                     "WIFI JOINING") == 0);

  const Presentation summary = BuildPresentation(ready, Page::kSummary);
  assert(summary.page() == Page::kSummary);
  assert(summary.activity() == Activity::kReady);
  assert(summary.line_count() == 5);
  assert(summary.line(0).role == LineRole::kActivity);
  assert(std::strcmp(summary.line(0).text.data(), "CONNECTED") == 0);
  assert(summary.line(1).role == LineRole::kDetail);
  assert(std::strcmp(summary.line(1).text.data(), "HOST AUTHENTICATED") == 0);
  assert(std::strcmp(summary.line(2).text.data(), "USB READY") == 0);
  assert(std::strcmp(summary.line(3).text.data(), "WIFI") == 0);
  assert(summary.line(4).tone == Tone::kSecondary);
  assert(std::strcmp(summary.line(4).text.data(),
                     "KEYFERRY FW 0123ABCD") == 0);
  ValidatePresentation(summary, kWaveshareCanvas);
  ValidatePresentation(summary, kLilygoCanvas);

  Snapshot pairing = ready;
  pairing.activity = Activity::kConnecting;
  pairing.ble_hid_mode = true;
  pairing.ble_hid_passkey = 12345;
  const Presentation waiting_summary =
      BuildPresentation(pairing, Page::kSummary);
  assert(std::strcmp(waiting_summary.line(0).text.data(), "BT KEYBOARD") ==
         0);
  assert(std::strcmp(waiting_summary.line(1).text.data(),
                     "PAIR CODE 012345") == 0);
  assert(std::strcmp(waiting_summary.line(2).text.data(), "ADD IN WINDOWS") ==
         0);
  assert(std::strcmp(waiting_summary.line(3).text.data(), "CONTROL WIFI") ==
         0);
  pairing.ble_hid_connected = true;
  const Presentation pairing_summary =
      BuildPresentation(pairing, Page::kSummary);
  assert(std::strcmp(pairing_summary.line(1).text.data(),
                     "PAIR CODE 012345") == 0);
  assert(std::strcmp(pairing_summary.line(2).text.data(),
                     "ADD IN WINDOWS") == 0);
  pairing.ble_hid_authenticated = true;
  pairing.ble_hid_ready = true;
  const Presentation ready_keyboard =
      BuildPresentation(pairing, Page::kSummary);
  assert(std::strcmp(ready_keyboard.line(1).text.data(), "PAIRED") == 0);
  assert(std::strcmp(ready_keyboard.line(2).text.data(), "READY") == 0);
  ValidatePresentation(pairing_summary, kWaveshareCanvas);
  ValidatePresentation(pairing_summary, kLilygoCanvas);

  Snapshot page_selection{};
  page_selection.activity = Activity::kReady;
  assert(SelectPage(page_selection, 9000) == Page::kSummary);
  page_selection.activity = Activity::kActive;
  assert(SelectPage(page_selection, 9000) == Page::kSummary);
  page_selection.activity = Activity::kProvisioning;
  assert(SelectPage(page_selection, 9000) == Page::kSummary);
  page_selection.activity = Activity::kConnecting;
  assert(SelectPage(page_selection, 0) == Page::kSummary);
  assert(SelectPage(page_selection, 7999) == Page::kSummary);
  assert(SelectPage(page_selection, 8000) == Page::kDiagnostics);
  page_selection.ble_hid_mode = true;
  assert(SelectPage(page_selection, 8000) == Page::kSummary);
  assert(SelectPage(page_selection, 11999) == Page::kSummary);
  page_selection.ble_hid_mode = false;
  page_selection.activity = Activity::kFault;
  assert(SelectPage(page_selection, 11999) == Page::kDiagnostics);
  page_selection.activity = Activity::kLocked;
  assert(SelectPage(page_selection, 12000) == Page::kSummary);

  ActivityPresentationFilter activity_filter;
  assert(activity_filter.Update(Activity::kReady, 1000) == Activity::kReady);
  assert(activity_filter.Update(Activity::kActive, 1100) ==
         Activity::kActive);
  assert(activity_filter.Update(Activity::kReady, 1599) ==
         Activity::kActive);
  assert(activity_filter.Update(Activity::kActive, 1600) ==
         Activity::kActive);
  assert(activity_filter.Update(Activity::kReady, 3099) ==
         Activity::kActive);
  assert(activity_filter.Update(Activity::kReady, 3100) == Activity::kReady);

  // Higher-priority or unauthenticated states are never hidden by the hold.
  assert(activity_filter.Update(Activity::kActive, 4000) ==
         Activity::kActive);
  assert(activity_filter.Update(Activity::kFault, 4001) == Activity::kFault);
  assert(activity_filter.Update(Activity::kReady, 4002) == Activity::kReady);
  assert(activity_filter.Update(Activity::kActive, 5000) ==
         Activity::kActive);
  assert(activity_filter.Update(Activity::kProvisioning, 5001) ==
         Activity::kProvisioning);
  assert(activity_filter.Update(Activity::kActive, 6000) ==
         Activity::kActive);
  assert(activity_filter.Update(Activity::kConnecting, 6001) ==
         Activity::kConnecting);
  assert(activity_filter.Update(Activity::kActive, 7000) ==
         Activity::kActive);
  assert(activity_filter.Update(Activity::kLocked, 7001) ==
         Activity::kLocked);

  // A regressed clock cannot extend a stale active presentation.
  assert(activity_filter.Update(Activity::kActive, 8000) ==
         Activity::kActive);
  assert(activity_filter.Update(Activity::kReady, 7999) == Activity::kReady);
  assert(activity_filter.Update(Activity::kReady, 8000) == Activity::kReady);
  activity_filter.Update(Activity::kActive, 9000);
  activity_filter.Reset();
  assert(activity_filter.Update(Activity::kReady, 9001) == Activity::kReady);

  Snapshot diagnostic = ready;
  diagnostic.free_internal_heap = 64 * 1024;
  diagnostic.largest_internal_block = 32 * 1024;
  diagnostic.minimum_internal_heap = 16 * 1024;
  diagnostic.nvs_error = -1;
  diagnostic.wifi_stage = 4;
  diagnostic.wifi_available = true;
  diagnostic.wifi_error = -2;
  diagnostic.ble_stage = 5;
  diagnostic.ble_available = true;
  diagnostic.ble_error = -3;
  diagnostic.ble_synchronized = true;
  diagnostic.ble_advertising = false;
  const Presentation diagnostics =
      BuildPresentation(diagnostic, Page::kDiagnostics);
  const Presentation compact_diagnostics = BuildPresentation(
      diagnostic, Page::kDiagnostics, PresentationDensity::kCompact);
  assert(diagnostics.page() == Page::kDiagnostics);
  assert(std::strcmp(diagnostics.line(0).text.data(),
                     "DIAG FW 0123ABCD G7") == 0);
  assert(std::strcmp(diagnostics.line(1).text.data(),
                     "TRANSPORT EXIT NVS -1") == 0);
  assert(diagnostics.line(1).tone == Tone::kAccent);
  assert(std::strcmp(diagnostics.line(2).text.data(),
                     "WIFI ST4 OK E-2") == 0);
  assert(std::strcmp(diagnostics.line(3).text.data(),
                     "BL ST5 OK E-3 SY1 AD0") == 0);
  assert(std::strcmp(diagnostics.line(4).text.data(),
                     "HEAP 64/32/16K") == 0);
  ValidatePresentation(diagnostics, kWaveshareCanvas);
  assert(std::strcmp(compact_diagnostics.line(0).text.data(),
                     "D 0123ABCD G00000007") == 0);
  assert(std::strcmp(compact_diagnostics.line(1).text.data(),
                     "TR OFF NFFFFFFFF") == 0);
  assert(std::strcmp(compact_diagnostics.line(2).text.data(),
                     "W S4 OK EFFFFFFFE") == 0);
  assert(std::strcmp(compact_diagnostics.line(3).text.data(),
                     "B S5 EFFFFFFFD Y1 A0") == 0);
  assert(std::strcmp(compact_diagnostics.line(4).text.data(),
                     "H 00040/00020/00010K") == 0);
  ValidatePresentation(compact_diagnostics, kLilygoCanvas);
  if (argc == 2) {
    const std::string prefix = argv[1];
    WritePpm(summary, kWaveshareCanvas, prefix + "-waveshare-summary.ppm");
    WritePpm(diagnostics, kWaveshareCanvas,
             prefix + "-waveshare-diagnostics.ppm");
    WritePpm(summary, kLilygoCanvas, prefix + "-lilygo-summary.ppm");
    WritePpm(compact_diagnostics, kLilygoCanvas,
             prefix + "-lilygo-diagnostics.ppm");
  }

  Snapshot changed = ready;
  changed.transport_running = true;
  assert(BuildPresentation(ready, Page::kSummary) ==
         BuildPresentation(changed, Page::kSummary));
  assert(BuildPresentation(ready, Page::kDiagnostics) !=
         BuildPresentation(changed, Page::kDiagnostics));

  Snapshot maximum = diagnostic;
  maximum.config_generation = std::numeric_limits<std::uint64_t>::max();
  maximum.nvs_error = std::numeric_limits<std::int32_t>::min();
  maximum.wifi_error = std::numeric_limits<std::int32_t>::min();
  maximum.ble_error = std::numeric_limits<std::int32_t>::min();
  maximum.free_internal_heap = std::numeric_limits<std::uint32_t>::max();
  maximum.largest_internal_block = std::numeric_limits<std::uint32_t>::max();
  maximum.minimum_internal_heap = std::numeric_limits<std::uint32_t>::max();
  const Presentation maximum_diagnostics =
      BuildPresentation(maximum, Page::kDiagnostics);
  const Presentation maximum_compact_diagnostics = BuildPresentation(
      maximum, Page::kDiagnostics, PresentationDensity::kCompact);
  ValidatePresentation(maximum_diagnostics, kWaveshareCanvas);
  ValidatePresentation(maximum_compact_diagnostics, kLilygoCanvas);

  const std::array<Activity, 6> activities{
      Activity::kLocked, Activity::kConnecting, Activity::kReady,
      Activity::kActive, Activity::kProvisioning, Activity::kFault};
  const std::array<LinkPath, 3> links{
      LinkPath::kOffline, LinkPath::kWifi, LinkPath::kBluetooth};
  const std::array<ConnectionProgress, 5> progress{
      ConnectionProgress::kSearching,
      ConnectionProgress::kWifiJoining,
      ConnectionProgress::kWifiAuthenticating,
      ConnectionProgress::kBluetoothAdvertising,
      ConnectionProgress::kBluetoothAuthenticating};
  for (const Activity activity : activities) {
    for (const LinkPath link : links) {
      for (const ConnectionProgress connection : progress) {
        Snapshot candidate = diagnostic;
        candidate.activity = activity;
        candidate.link = link;
        candidate.connection = connection;
        for (unsigned usb = 0; usb < 3; ++usb) {
          candidate.usb_mounted = usb != 0;
          candidate.usb_suspended = usb == 2;
          const Presentation candidate_summary =
              BuildPresentation(candidate, Page::kSummary);
          const Presentation candidate_diagnostics =
              BuildPresentation(candidate, Page::kDiagnostics);
          const Presentation candidate_compact_diagnostics =
              BuildPresentation(candidate, Page::kDiagnostics,
                                PresentationDensity::kCompact);
          ValidatePresentation(candidate_summary, kWaveshareCanvas);
          ValidatePresentation(candidate_summary, kLilygoCanvas);
          ValidatePresentation(candidate_diagnostics, kWaveshareCanvas);
          ValidatePresentation(candidate_compact_diagnostics, kLilygoCanvas);
        }
      }
    }
  }

  assert(HasGlyph('-'));
  assert(HasGlyph('.'));
  assert(HasGlyph(':'));
  assert(HasGlyph('/'));
  assert(!HasGlyph('?'));

  // Only fixed metadata labels can be rendered; the model has no payload or
  // credential string input.
  static_assert(!std::is_default_constructible_v<Presentation>);
  assert(sizeof(Snapshot) <= 64);

  std::cout << "status_test: ok\n";
}
