#include "usb_attachment.h"

#include <cassert>
#include <cstdio>

namespace {

using keyferry::hil::UsbAttachmentLatch;

void ConfirmedAttachmentAdmitsUntilTheNextBusReset() {
  UsbAttachmentLatch latch;
  // The host resets the bus once before the first enumeration.
  latch.BusReset();
  assert(!latch.Admits());
  const auto observed = latch.Resets();
  latch.Confirm(observed);
  assert(latch.Admits());
  // A reset before the main loop runs again blocks submission on the old attachment.
  latch.BusReset();
  assert(!latch.Admits());
  latch.Confirm(latch.Resets());
  assert(latch.Admits());
}

void ResetBetweenObservingAndConfirmingStillBlocks() {
  UsbAttachmentLatch latch;
  latch.Confirm(latch.Resets());
  // The loop observes the count, the host resets and re-enumerates the device, and only then
  // does the loop confirm the mount it saw: the stale observation must not admit input.
  const auto observed = latch.Resets();
  latch.BusReset();
  latch.Confirm(observed);
  assert(!latch.Admits());
  latch.Confirm(latch.Resets());
  assert(latch.Admits());
}

}  // namespace

int main() {
  ConfirmedAttachmentAdmitsUntilTheNextBusReset();
  ResetBetweenObservingAndConfirmingStillBlocks();
  std::puts("usb_attachment_test: ok");
  return 0;
}
