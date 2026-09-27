#include "keyferry/ble_hid_release.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>

using keyferry::ble_hid::ReleaseBurst;
using keyferry::ble_hid::ReleaseState;
using keyferry::ble_hid::EnrollmentWindow;

namespace {

void Sends_three_zeros_across_distinct_intervals() {
  ReleaseBurst burst;
  assert(burst.Start(7, 24, 100));  // 30-ms interval; 60-ms spacing.
  assert(burst.spacing_ms() == 60);
  assert(burst.state() == ReleaseState::submit_zero);

  assert(burst.MarkZeroAccepted(7, 101));
  assert(burst.accepted_count() == 1);
  assert(burst.Poll(7, 160) == ReleaseState::waiting);
  assert(burst.Poll(7, 161) == ReleaseState::submit_zero);

  assert(burst.MarkZeroAccepted(7, 162));
  assert(burst.Poll(7, 221) == ReleaseState::waiting);
  assert(burst.Poll(7, 222) == ReleaseState::submit_zero);
  assert(burst.MarkZeroAccepted(7, 223));
  assert(burst.state() == ReleaseState::complete);
  assert(burst.accepted_count() == 3);
}

void Enforces_supported_connection_intervals() {
  ReleaseBurst burst;
  assert(!burst.Start(0, 24, 0));
  assert(!burst.Start(1, 5, 0));
  assert(!burst.Start(1, 41, 0));
  assert(burst.Start(1, 6, 0));
  assert(burst.spacing_ms() == 20);
  assert(!burst.Start(1, 6, 0));
}

void Failed_release_requires_disconnect_without_counting_success() {
  ReleaseBurst burst;
  assert(burst.Start(9, 8, 0));
  assert(burst.MarkZeroFailed(9));
  assert(burst.MarkZeroFailed(9));
  assert(burst.state() == ReleaseState::submit_zero);
  assert(burst.accepted_count() == 0);
  assert(burst.MarkZeroFailed(9));
  assert(burst.state() == ReleaseState::disconnect_required);
  assert(!burst.MarkZeroAccepted(9, 1));
}

void Rejects_stale_callbacks_and_releases_first_after_reconnect() {
  ReleaseBurst burst;
  assert(burst.Start(11, 12, 10));
  assert(!burst.MarkZeroAccepted(10, 11));
  assert(!burst.MarkZeroFailed(12));
  assert(!burst.Disconnect(10));
  assert(burst.generation() == 11);
  assert(burst.Disconnect(11));
  assert(burst.state() == ReleaseState::idle);

  assert(burst.Start(12, 12, 20));
  assert(burst.state() == ReleaseState::submit_zero);
  assert(burst.accepted_count() == 0);
}

void Saturates_deadline_without_early_completion() {
  ReleaseBurst burst;
  const auto maximum = std::numeric_limits<std::uint64_t>::max();
  assert(burst.Start(20, 40, maximum - 50));
  assert(burst.MarkZeroAccepted(20, maximum - 50));
  assert(burst.next_due_ms() == maximum);
  assert(burst.Poll(20, maximum - 1) == ReleaseState::waiting);
  assert(burst.Poll(20, maximum) == ReleaseState::submit_zero);
  assert(burst.MarkZeroAccepted(20, maximum));
  assert(burst.state() == ReleaseState::waiting);
  assert(burst.Poll(20, maximum) == ReleaseState::submit_zero);
  assert(burst.MarkZeroAccepted(20, maximum));
  assert(burst.state() == ReleaseState::complete);
}

void Enrollment_is_bounded_cancelable_and_closes_on_authentication() {
  EnrollmentWindow window;
  assert(!window.Status(0).active);
  window.Start(1000);
  assert(window.Status(1000).active);
  assert(window.Status(1000).remaining_ms == EnrollmentWindow::kDurationMs);
  assert(!window.Poll(120999));
  assert(window.Status(120999).remaining_ms == 1);
  assert(window.Poll(121000));
  assert(!window.Status(121000).active);
  assert(!window.Cancel());

  window.Start(10);
  assert(window.Cancel());
  assert(!window.Status(10).active);
  window.Start(20);
  assert(window.Authenticated());
  assert(!window.Status(20).active);

  const auto maximum = std::numeric_limits<std::uint64_t>::max();
  window.Start(maximum - 10);
  assert(window.Status(maximum - 10).remaining_ms == 10);
  assert(!window.Poll(maximum - 1));
  assert(window.Poll(maximum));
}

}  // namespace

int main() {
  Sends_three_zeros_across_distinct_intervals();
  Enforces_supported_connection_intervals();
  Failed_release_requires_disconnect_without_counting_success();
  Rejects_stale_callbacks_and_releases_first_after_reconnect();
  Saturates_deadline_without_early_completion();
  Enrollment_is_bounded_cancelable_and_closes_on_authentication();
  std::cout << "release_burst_test: ok\n";
  return 0;
}
