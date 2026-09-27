#include "keyferry/ble_hid_release.h"

#include <algorithm>
#include <limits>

namespace keyferry::ble_hid {
namespace {

constexpr std::uint16_t kMinimumSpacingMs = 20;
constexpr std::uint16_t kMaximumSpacingMs = 100;

std::uint16_t ComputeSpacingMs(
    const std::uint16_t connection_interval_units) noexcept {
  // One BLE interval unit is 1.25 ms. Five half-milliseconds per unit is two
  // complete connection intervals; round up to the next whole millisecond.
  const std::uint16_t two_intervals_ms =
      static_cast<std::uint16_t>((connection_interval_units * 5U + 1U) / 2U);
  return std::clamp(two_intervals_ms, kMinimumSpacingMs,
                    kMaximumSpacingMs);
}

std::uint64_t SaturatingAdd(const std::uint64_t value,
                            const std::uint64_t increment) noexcept {
  const auto maximum = std::numeric_limits<std::uint64_t>::max();
  return value > maximum - increment ? maximum : value + increment;
}

}  // namespace

bool ReleaseBurst::Start(const std::uint32_t generation,
                         const std::uint16_t connection_interval_units,
                         const std::uint64_t now_ms) noexcept {
  if (generation == 0 ||
      connection_interval_units < kMinimumConnectionIntervalUnits ||
      connection_interval_units > kMaximumConnectionIntervalUnits ||
      (state_ != ReleaseState::idle && state_ != ReleaseState::complete)) {
    return false;
  }

  generation_ = generation;
  spacing_ms_ = ComputeSpacingMs(connection_interval_units);
  next_due_ms_ = now_ms;
  accepted_count_ = 0;
  failure_count_ = 0;
  state_ = ReleaseState::submit_zero;
  return true;
}

ReleaseState ReleaseBurst::Poll(const std::uint32_t generation,
                                const std::uint64_t now_ms) noexcept {
  if (IsCurrent(generation) && state_ == ReleaseState::waiting &&
      now_ms >= next_due_ms_) {
    state_ = ReleaseState::submit_zero;
  }
  return state_;
}

bool ReleaseBurst::MarkZeroAccepted(const std::uint32_t generation,
                                    const std::uint64_t now_ms) noexcept {
  if (!IsCurrent(generation) || state_ != ReleaseState::submit_zero) {
    return false;
  }

  ++accepted_count_;
  if (accepted_count_ == kReleaseReportCount) {
    state_ = ReleaseState::complete;
    next_due_ms_ = now_ms;
  } else {
    state_ = ReleaseState::waiting;
    next_due_ms_ = SaturatingAdd(now_ms, spacing_ms_);
  }
  return true;
}

bool ReleaseBurst::MarkZeroFailed(const std::uint32_t generation) noexcept {
  if (!IsCurrent(generation) || state_ != ReleaseState::submit_zero) {
    return false;
  }

  ++failure_count_;
  if (failure_count_ >= kReleaseFailureLimit) {
    state_ = ReleaseState::disconnect_required;
  }
  return true;
}

bool ReleaseBurst::Disconnect(const std::uint32_t generation) noexcept {
  if (!IsCurrent(generation)) {
    return false;
  }

  *this = ReleaseBurst{};
  return true;
}

bool ReleaseBurst::IsCurrent(const std::uint32_t generation) const noexcept {
  return generation != 0 && generation == generation_;
}

void EnrollmentWindow::Start(const std::uint64_t now_ms) noexcept {
  deadline_ms_ = SaturatingAdd(now_ms, kDurationMs);
}

bool EnrollmentWindow::Cancel() noexcept {
  const bool active = deadline_ms_ != 0;
  deadline_ms_ = 0;
  return active;
}

bool EnrollmentWindow::Authenticated() noexcept { return Cancel(); }

bool EnrollmentWindow::Poll(const std::uint64_t now_ms) noexcept {
  if (deadline_ms_ == 0 || now_ms < deadline_ms_) {
    return false;
  }
  deadline_ms_ = 0;
  return true;
}

EnrollmentStatus EnrollmentWindow::Status(
    const std::uint64_t now_ms) const noexcept {
  if (deadline_ms_ == 0 || now_ms >= deadline_ms_) {
    return {};
  }
  const auto remaining = deadline_ms_ - now_ms;
  return {true, static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(remaining, kDurationMs))};
}

}  // namespace keyferry::ble_hid
