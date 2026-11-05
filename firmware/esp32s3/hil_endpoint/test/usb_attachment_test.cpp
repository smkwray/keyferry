#include "usb_attachment.h"

#include <cassert>
#include <cstdio>

namespace {

using keyferry::hil::UsbAttachmentLatch;

void ConfirmedAttachmentAdmitsUntilItEnds() {
  UsbAttachmentLatch latch;
  // The host resets the bus once before the first enumeration.
  latch.End();
  assert(!latch.Admits());
  latch.Confirm(latch.Ends());
  assert(latch.Admits());
  // A reset, unplug or unconfiguration before the main loop runs again blocks submission on
  // the old attachment until the loop confirms the new one.
  latch.End();
  assert(!latch.Admits());
  latch.Confirm(latch.Ends());
  assert(latch.Admits());
}

void EndBetweenObservingAndConfirmingStillBlocks() {
  UsbAttachmentLatch latch;
  latch.Confirm(latch.Ends());
  // The loop observes the count; the host unconfigures and reconfigures the device; only then
  // does the loop confirm the mount it saw: the stale observation must not admit input.
  const auto observed = latch.Ends();
  latch.End();
  latch.Confirm(observed);
  assert(!latch.Admits());
  latch.Confirm(latch.Ends());
  assert(latch.Admits());
}

void EachNewConfigurationNeedsItsOwnConfirmation() {
  UsbAttachmentLatch latch;
  latch.End();  // bus reset
  latch.End();  // configuration 1
  latch.Confirm(latch.Ends());
  assert(latch.Admits());
  // Configuration 2, then back to 1, without a detach: each reopening ends the attachment.
  for (int change = 0; change < 2; ++change) {
    latch.End();
    assert(!latch.Admits());
    latch.Confirm(latch.Ends());
    assert(latch.Admits());
  }
}

}  // namespace

int main() {
  ConfirmedAttachmentAdmitsUntilItEnds();
  EndBetweenObservingAndConfirmingStillBlocks();
  EachNewConfigurationNeedsItsOwnConfirmation();
  std::puts("usb_attachment_test: ok");
  return 0;
}
