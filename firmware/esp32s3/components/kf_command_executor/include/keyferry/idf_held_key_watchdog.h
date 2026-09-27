#pragma once

#include <atomic>
#include <cstdint>

#include "esp_timer.h"
#include "keyferry/command_executor.h"

namespace keyferry::command {

using HeldKeyDeadlineCallback = void (*)(void* context, std::uint64_t token,
                                         std::uint64_t now_ms);

// ESP-IDF one-shot timer adapter. Its callback runs independently of command Poll(); the HIL
// composition must serialize the callback with USB/executor access using its shared safety lock.
class IdfHeldKeyWatchdog final : public HeldKeyDeadlineScheduler {
  public:
    IdfHeldKeyWatchdog() = default;
    ~IdfHeldKeyWatchdog() override;
    IdfHeldKeyWatchdog(const IdfHeldKeyWatchdog&) = delete;
    IdfHeldKeyWatchdog& operator=(const IdfHeldKeyWatchdog&) = delete;

    bool Initialize(HeldKeyDeadlineCallback callback, void* context);
    bool Schedule(std::uint64_t token, std::uint64_t monotonic_deadline_ms) override;
    void Cancel(std::uint64_t token) override;
    static std::uint64_t NowMs();

  private:
    static void TimerCallback(void* context);

    esp_timer_handle_t timer_{nullptr};
    HeldKeyDeadlineCallback callback_{nullptr};
    void* context_{nullptr};
    std::atomic<std::uint64_t> token_{0};
};

}  // namespace keyferry::command
