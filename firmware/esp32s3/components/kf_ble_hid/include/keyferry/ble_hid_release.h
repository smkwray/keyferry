#pragma once

#include <cstdint>

namespace keyferry::ble_hid {

constexpr std::uint8_t kReleaseReportCount = 3;
constexpr std::uint8_t kReleaseFailureLimit = 3;
constexpr std::uint16_t kMinimumConnectionIntervalUnits = 6;   // 7.5 ms
constexpr std::uint16_t kMaximumConnectionIntervalUnits = 40;  // 50 ms

enum class ReleaseState : std::uint8_t {
  idle,
  submit_zero,
  waiting,
  complete,
  disconnect_required,
};

// Allocation-free policy for redundant BLE keyboard release notifications.
// The adapter remains the sole report emitter. A burst belongs to one exact
// connection generation, and no nonzero report may be submitted until it is
// complete.
class ReleaseBurst final {
 public:
  bool Start(std::uint32_t generation,
             std::uint16_t connection_interval_units,
             std::uint64_t now_ms) noexcept;
  ReleaseState Poll(std::uint32_t generation,
                    std::uint64_t now_ms) noexcept;
  bool MarkZeroAccepted(std::uint32_t generation,
                        std::uint64_t now_ms) noexcept;
  bool MarkZeroFailed(std::uint32_t generation) noexcept;
  bool Disconnect(std::uint32_t generation) noexcept;

  [[nodiscard]] ReleaseState state() const noexcept { return state_; }
  [[nodiscard]] std::uint32_t generation() const noexcept {
    return generation_;
  }
  [[nodiscard]] std::uint8_t accepted_count() const noexcept {
    return accepted_count_;
  }
  [[nodiscard]] std::uint8_t failure_count() const noexcept {
    return failure_count_;
  }
  [[nodiscard]] std::uint16_t spacing_ms() const noexcept {
    return spacing_ms_;
  }
  [[nodiscard]] std::uint64_t next_due_ms() const noexcept {
    return next_due_ms_;
  }

 private:
  [[nodiscard]] bool IsCurrent(std::uint32_t generation) const noexcept;

  ReleaseState state_{ReleaseState::idle};
  std::uint32_t generation_{0};
  std::uint64_t next_due_ms_{0};
  std::uint16_t spacing_ms_{0};
  std::uint8_t accepted_count_{0};
  std::uint8_t failure_count_{0};
};

static_assert(sizeof(ReleaseBurst) <= 32,
              "BLE HID release policy exceeds its static budget");

struct EnrollmentStatus {
  bool active{};
  std::uint32_t remaining_ms{};
};

// Allocation-free deadline for the explicit unbonded pairing window.
class EnrollmentWindow final {
 public:
  static constexpr std::uint32_t kDurationMs = 120000;

  void Start(std::uint64_t now_ms) noexcept;
  [[nodiscard]] bool Cancel() noexcept;
  [[nodiscard]] bool Authenticated() noexcept;
  [[nodiscard]] bool Poll(std::uint64_t now_ms) noexcept;
  [[nodiscard]] EnrollmentStatus Status(std::uint64_t now_ms) const noexcept;

 private:
  std::uint64_t deadline_ms_{};
};

}  // namespace keyferry::ble_hid
