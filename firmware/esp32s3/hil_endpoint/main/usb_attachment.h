#pragma once

#include <atomic>
#include <cstdint>

namespace keyferry::hil {

// A USB bus reset ends the current attachment. TinyUSB reports it from the USB interrupt before
// the host re-enumerates the device, but configures the device again without a DETACHED event.
// Input reports are admitted only on the attachment the main loop last confirmed: a reset that
// lands anywhere after the loop observed the reset count blocks submission until the loop has
// ended the old session and confirmed the new attachment.
class UsbAttachmentLatch final {
 public:
  // Interrupt-safe: one lock-free atomic increment.
  void BusReset() noexcept { resets_.fetch_add(1, std::memory_order_acq_rel); }

  [[nodiscard]] std::uint32_t Resets() const noexcept {
    return resets_.load(std::memory_order_acquire);
  }

  // Confirms an attachment with the reset count observed before its mount state was checked.
  void Confirm(const std::uint32_t observed_resets) noexcept {
    confirmed_.store(observed_resets, std::memory_order_release);
  }

  [[nodiscard]] bool Admits() const noexcept {
    return Resets() == confirmed_.load(std::memory_order_acquire);
  }

 private:
  std::atomic<std::uint32_t> resets_{0};
  std::atomic<std::uint32_t> confirmed_{0};
};

}  // namespace keyferry::hil
