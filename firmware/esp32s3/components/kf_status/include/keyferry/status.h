#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace keyferry::status {

enum class LinkPath : std::uint8_t {
  kOffline,
  kWifi,
  kBluetooth,
};

enum class Activity : std::uint8_t {
  kLocked,
  kConnecting,
  kReady,
  kActive,
  kProvisioning,
  kFault,
};

inline constexpr std::uint64_t kActivePresentationHoldMs = 1500;

// Presentation-only smoothing for the short released gaps between wire chunks.
// It never changes command, arm, USB, transport, or authentication state.
class ActivityPresentationFilter final {
 public:
  Activity Update(Activity observed, std::uint64_t now_ms) noexcept;
  void Reset() noexcept;

 private:
  std::uint64_t last_active_ms_{};
  bool saw_active_{};
};

enum class ConnectionProgress : std::uint8_t {
  kSearching,
  kWifiJoining,
  kWifiAuthenticating,
  kBluetoothAdvertising,
  kBluetoothAuthenticating,
};

enum class Page : std::uint8_t {
  kSummary,
  kDiagnostics,
};

enum class PresentationDensity : std::uint8_t {
  kNormal,
  kCompact,
};

enum class LineRole : std::uint8_t {
  kActivity,
  kDetail,
  kUsb,
  kLink,
  kBuild,
  kDiagnosticHeader,
  kTransport,
  kWifi,
  kBluetooth,
  kHeap,
};

enum class Tone : std::uint8_t {
  kAccent,
  kPrimary,
  kSecondary,
};

struct Snapshot {
  bool usb_mounted{};
  bool usb_suspended{};
  LinkPath link{LinkPath::kOffline};
  Activity activity{Activity::kLocked};
  ConnectionProgress connection{ConnectionProgress::kSearching};
  std::uint64_t config_generation{};
  std::array<char, 9> build_id{};
  std::uint32_t free_internal_heap{};
  std::uint32_t largest_internal_block{};
  std::uint32_t minimum_internal_heap{};
  std::int32_t nvs_error{};
  std::int32_t wifi_error{};
  union {
    std::int32_t ble_error{};
    std::uint32_t ble_hid_passkey;
  };
  std::uint8_t wifi_stage{};
  std::uint8_t ble_stage{};
  bool transport_running{};
  bool wifi_available{};
  bool ble_available{};
  bool ble_synchronized{};
  bool ble_advertising{};
  bool ble_hid_mode{};
  bool ble_hid_connected{};
  bool ble_hid_authenticated{};
  bool ble_hid_ready{};
};

inline constexpr std::size_t kPresentationLineBytes = 41;
inline constexpr std::size_t kPresentationLines = 5;

struct Line {
  LineRole role{};
  Tone tone{};
  std::array<char, kPresentationLineBytes> text{};
};

// Bounded, metadata-only output. Construction is private so display adapters
// cannot accept arbitrary text or become a path for credentials or key data.
class Presentation final {
 public:
  [[nodiscard]] Page page() const noexcept { return page_; }
  [[nodiscard]] Activity activity() const noexcept { return activity_; }
  [[nodiscard]] std::size_t line_count() const noexcept { return line_count_; }
  [[nodiscard]] const Line& line(std::size_t index) const noexcept {
    return lines_[index];
  }

  friend bool operator==(const Presentation& left,
                         const Presentation& right) noexcept;
  friend bool operator!=(const Presentation& left,
                         const Presentation& right) noexcept;
  friend Presentation BuildPresentation(const Snapshot& snapshot,
                                         Page page,
                                         PresentationDensity density) noexcept;

 private:
  Presentation() = default;

  Page page_{Page::kSummary};
  Activity activity_{Activity::kLocked};
  std::array<Line, kPresentationLines> lines_{};
  std::size_t line_count_{};
};

Presentation BuildPresentation(
    const Snapshot& snapshot, Page page,
    PresentationDensity density = PresentationDensity::kNormal) noexcept;
Page SelectPage(const Snapshot& snapshot, std::uint64_t elapsed_ms) noexcept;

// Static, metadata-only labels. This interface deliberately has no string or
// payload field through which credentials or typed content could reach a display.
const char* UsbLabel(bool mounted, bool suspended) noexcept;
const char* LinkLabel(LinkPath path) noexcept;
const char* ActivityLabel(Activity activity) noexcept;
const char* ConnectionLabel(ConnectionProgress progress) noexcept;
const char* DetailLabel(const Snapshot& snapshot) noexcept;

}  // namespace keyferry::status
