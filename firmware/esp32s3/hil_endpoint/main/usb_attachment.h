#pragma once

#include <atomic>
#include <cstdint>

namespace keyferry::hil {

// Counts the ends of USB attachments: bus resets and unplugs (reported from the USB interrupt
// before the host re-enumerates the device), unconfiguration (SET_CONFIGURATION(0)) and every
// new configuration, since a change between nonzero configurations reopens the endpoints
// without a detach. TinyUSB does not tell the main loop the old attachment ended. Input
// reports are admitted only on the attachment the main loop last confirmed: an end counted any
// time after the loop observed the count blocks submission until the loop has ended the old
// session and confirmed the new attachment.
class UsbAttachmentLatch final {
 public:
  // Interrupt-safe: one lock-free atomic increment.
  void End() noexcept { ends_.fetch_add(1, std::memory_order_acq_rel); }

  [[nodiscard]] std::uint32_t Ends() const noexcept {
    return ends_.load(std::memory_order_acquire);
  }

  // Confirms an attachment with the count observed before its mount state was checked.
  void Confirm(const std::uint32_t observed_ends) noexcept {
    confirmed_.store(observed_ends, std::memory_order_release);
  }

  [[nodiscard]] bool Admits() const noexcept {
    return Ends() == confirmed_.load(std::memory_order_acquire);
  }

 private:
  std::atomic<std::uint32_t> ends_{0};
  std::atomic<std::uint32_t> confirmed_{0};
};

}  // namespace keyferry::hil
