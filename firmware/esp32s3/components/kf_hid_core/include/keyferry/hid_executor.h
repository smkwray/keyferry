#pragma once

#include <array>
#include <cstdint>

namespace keyferry::hid {

struct BootKeyboardReport {
    std::uint8_t modifiers{};
    std::uint8_t reserved{};
    std::array<std::uint8_t, 6> usages{};
};

static_assert(sizeof(BootKeyboardReport) == 8, "boot-keyboard reports must be exactly 8 bytes");

struct BootMouseReport {
    std::uint8_t buttons{};
    std::int8_t x{};
    std::int8_t y{};
};

static_assert(sizeof(BootMouseReport) == 3, "boot-mouse reports must be exactly 3 bytes");

bool operator==(const BootKeyboardReport& left, const BootKeyboardReport& right) noexcept;
bool operator!=(const BootKeyboardReport& left, const BootKeyboardReport& right) noexcept;
bool is_zero(const BootKeyboardReport& report) noexcept;
bool is_valid(const BootKeyboardReport& report) noexcept;
bool operator==(const BootMouseReport& left, const BootMouseReport& right) noexcept;
bool operator!=(const BootMouseReport& left, const BootMouseReport& right) noexcept;
bool is_zero(const BootMouseReport& report) noexcept;
bool is_valid(const BootMouseReport& report) noexcept;

enum class InputInterface : std::uint8_t { keyboard, mouse };

constexpr std::uint8_t kKeyboardNeutral = 0x01;
constexpr std::uint8_t kMouseNeutral = 0x02;

enum class SubmitResult {
    accepted,
    busy,
    disarmed,
    stale_epoch,
    invalid_report,
    held_state_conflict,
    movement_replayed,
};

// Pure state machine used by the native-USB adapter and host tests. It never sends a report itself.
// The adapter is the sole report emitter and acknowledges a report only after TinyUSB accepts it.
class ExecutorState final {
  public:
    ExecutorState() noexcept = default;

    [[nodiscard]] bool armed() const noexcept;
    [[nodiscard]] std::uint64_t epoch() const noexcept;
    [[nodiscard]] bool session_started() const noexcept;
    [[nodiscard]] bool mouse_enabled() const noexcept;
    [[nodiscard]] bool report_needed() const noexcept;
    [[nodiscard]] InputInterface desired_interface() const noexcept;
    [[nodiscard]] const BootKeyboardReport& desired_report() const noexcept;
    [[nodiscard]] const BootKeyboardReport& current_report() const noexcept;
    [[nodiscard]] const BootMouseReport& desired_mouse_report() const noexcept;
    [[nodiscard]] const BootMouseReport& current_mouse_report() const noexcept;
    [[nodiscard]] std::uint64_t desired_mouse_logical_token() const noexcept;
    [[nodiscard]] std::uint8_t neutral_mask() const noexcept;

    // Must be selected before the USB transport is made ready. The default remains keyboard-only.
    bool enable_mouse_interface() noexcept;
    // Arming is rejected until the transport has accepted the mandatory zero report.
    bool arm(std::uint64_t epoch) noexcept;
    SubmitResult submit(std::uint64_t epoch, const BootKeyboardReport& report) noexcept;
    SubmitResult submit_mouse_movement(std::uint64_t epoch, std::uint64_t logical_token,
                                       const BootMouseReport& report) noexcept;
    SubmitResult submit_mouse_buttons(std::uint64_t epoch,
                                      const BootMouseReport& report) noexcept;

    void on_transport_ready() noexcept;
    void on_transport_lost() noexcept;
    void disarm() noexcept;
    // Starts an explicit keyboard-zero then mouse-zero evidence barrier without arming input.
    void request_dual_neutral() noexcept;
    void fault() noexcept;
    // The independent held-key watchdog uses this stronger fail-closed transition. Logical current
    // state becomes zero immediately, but rearming stays blocked until USB accepts the pending zero.
    void watchdog_release() noexcept;

    // Returns false if the adapter acknowledges anything except the exact desired report.
    bool mark_report_accepted(const BootKeyboardReport& report) noexcept;
    bool mark_mouse_report_accepted(const BootMouseReport& report,
                                    std::uint64_t logical_token) noexcept;

  private:
    void request_release() noexcept;

    bool transport_ready_{false};
    bool mouse_enabled_{false};
    bool armed_{false};
    bool report_pending_{true};
    bool release_mouse_pending_{false};
    bool pending_mouse_movement_{false};
    bool session_started_{false};
    bool release_unconfirmed_{false};
    bool neutral_evidence_required_{false};
    bool dual_neutral_after_pending_zero_{false};
    InputInterface desired_interface_{InputInterface::keyboard};
    std::uint8_t neutral_mask_{0};
    std::uint64_t epoch_{0};
    std::uint64_t pending_movement_token_{0};
    std::uint64_t last_movement_token_{0};
    BootKeyboardReport desired_{};
    BootKeyboardReport current_{};
    BootMouseReport desired_mouse_{};
    BootMouseReport current_mouse_{};
};

}  // namespace keyferry::hid
