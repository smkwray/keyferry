#include "keyferry/idf_held_key_watchdog.h"

#include <algorithm>
#include <limits>

#include "esp_err.h"

namespace keyferry::command {

IdfHeldKeyWatchdog::~IdfHeldKeyWatchdog() {
    if (timer_ != nullptr) {
        (void)esp_timer_stop(timer_);
        (void)esp_timer_delete(timer_);
    }
}

bool IdfHeldKeyWatchdog::Initialize(const HeldKeyDeadlineCallback callback, void* context) {
    if (timer_ != nullptr || callback == nullptr) {
        return false;
    }
    callback_ = callback;
    context_ = context;
    esp_timer_create_args_t arguments{};
    arguments.callback = TimerCallback;
    arguments.arg = this;
    arguments.dispatch_method = ESP_TIMER_TASK;
    arguments.name = "kf-held-key";
    arguments.skip_unhandled_events = false;
    if (esp_timer_create(&arguments, &timer_) != ESP_OK) {
        callback_ = nullptr;
        context_ = nullptr;
        timer_ = nullptr;
        return false;
    }
    return true;
}

bool IdfHeldKeyWatchdog::Schedule(const std::uint64_t token,
                                  const std::uint64_t monotonic_deadline_ms) {
    if (timer_ == nullptr || callback_ == nullptr || token == 0) {
        return false;
    }
    (void)esp_timer_stop(timer_);
    token_.store(token, std::memory_order_release);
    const auto now_ms = NowMs();
    const auto delay_ms = monotonic_deadline_ms > now_ms ? monotonic_deadline_ms - now_ms : 0;
    const auto bounded_ms = std::min<std::uint64_t>(
        delay_ms, static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max() / 1000));
    const auto delay_us = std::max<std::uint64_t>(1, bounded_ms * 1000);
    if (esp_timer_start_once(timer_, delay_us) != ESP_OK) {
        token_.store(0, std::memory_order_release);
        return false;
    }
    return true;
}

void IdfHeldKeyWatchdog::Cancel(const std::uint64_t token) {
    if (token == 0 || token_.load(std::memory_order_acquire) != token) {
        return;
    }
    token_.store(0, std::memory_order_release);
    if (timer_ != nullptr) {
        (void)esp_timer_stop(timer_);
    }
}

std::uint64_t IdfHeldKeyWatchdog::NowMs() {
    const auto microseconds = esp_timer_get_time();
    return microseconds <= 0 ? 0 : static_cast<std::uint64_t>(microseconds) / 1000;
}

void IdfHeldKeyWatchdog::TimerCallback(void* context) {
    auto* self = static_cast<IdfHeldKeyWatchdog*>(context);
    const auto token = self->token_.exchange(0, std::memory_order_acq_rel);
    if (token != 0 && self->callback_ != nullptr) {
        self->callback_(self->context_, token, NowMs());
    }
}

}  // namespace keyferry::command
