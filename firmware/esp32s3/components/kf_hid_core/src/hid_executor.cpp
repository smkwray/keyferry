#include "keyferry/hid_executor.h"

#include <algorithm>
#include <limits>

namespace keyferry::hid {

std::size_t SerializePointerReport(const PointerReport& r,
                                 std::array<std::uint8_t, 8>* out) noexcept {
    out->fill(0);
    if (r.absolute) {
        (*out)[0] = 4; (*out)[1] = r.buttons;
        (*out)[2] = static_cast<std::uint8_t>(r.absolute_x);
        (*out)[3] = static_cast<std::uint8_t>(r.absolute_x >> 8U);
        (*out)[4] = static_cast<std::uint8_t>(r.absolute_y);
        (*out)[5] = static_cast<std::uint8_t>(r.absolute_y >> 8U);
        (*out)[6] = static_cast<std::uint8_t>(r.wheel);
        return 7;
    }
    (*out)[0] = 1; (*out)[1] = r.buttons;
    (*out)[2] = static_cast<std::uint8_t>(r.x); (*out)[3] = static_cast<std::uint8_t>(r.y);
    (*out)[4] = static_cast<std::uint8_t>(r.wheel); (*out)[5] = static_cast<std::uint8_t>(r.pan);
    return 6;
}

bool operator==(const BootKeyboardReport& left, const BootKeyboardReport& right) noexcept {
    return left.modifiers == right.modifiers && left.reserved == right.reserved &&
           left.usages == right.usages;
}

bool operator!=(const BootKeyboardReport& left, const BootKeyboardReport& right) noexcept {
    return !(left == right);
}

bool is_zero(const BootKeyboardReport& report) noexcept {
    return report.modifiers == 0 && report.reserved == 0 &&
           std::all_of(report.usages.begin(), report.usages.end(), [](std::uint8_t usage) {
               return usage == 0;
           });
}

bool is_valid(const BootKeyboardReport& report) noexcept {
    if (report.reserved != 0) {
        return false;
    }
    for (std::size_t left = 0; left < report.usages.size(); ++left) {
        if (report.usages[left] == 0) {
            continue;
        }
        for (std::size_t right = left + 1; right < report.usages.size(); ++right) {
            if (report.usages[left] == report.usages[right]) {
                return false;
            }
        }
    }
    return true;
}

bool operator==(const PointerReport& left, const PointerReport& right) noexcept {
    return left.buttons == right.buttons && left.x == right.x && left.y == right.y &&
           left.wheel == right.wheel && left.pan == right.pan && left.absolute == right.absolute &&
           left.position_event == right.position_event && left.absolute_x == right.absolute_x &&
           left.absolute_y == right.absolute_y;
}

bool operator!=(const PointerReport& left, const PointerReport& right) noexcept {
    return !(left == right);
}

bool is_zero(const PointerReport& report) noexcept {
    return report.buttons == 0 && report.x == 0 && report.y == 0 && report.wheel == 0 && report.pan == 0 && !report.position_event;
}

bool is_valid(const PointerReport& report) noexcept {
    return (report.buttons & 0xE0U) == 0 &&
           report.x != std::numeric_limits<std::int8_t>::min() &&
           report.y != std::numeric_limits<std::int8_t>::min() &&
           report.wheel != std::numeric_limits<std::int8_t>::min() &&
           report.pan != std::numeric_limits<std::int8_t>::min() &&
           report.absolute_x <= 32767 && report.absolute_y <= 32767;
}

bool ExecutorState::armed() const noexcept {
    return armed_;
}

std::uint64_t ExecutorState::epoch() const noexcept {
    return epoch_;
}

bool ExecutorState::session_started() const noexcept {
    return session_started_;
}

bool ExecutorState::mouse_enabled() const noexcept {
    return mouse_enabled_;
}

bool ExecutorState::report_needed() const noexcept {
    return transport_ready_ && report_pending_;
}

InputInterface ExecutorState::desired_interface() const noexcept {
    return desired_interface_;
}

const BootKeyboardReport& ExecutorState::desired_report() const noexcept {
    return desired_;
}

const BootKeyboardReport& ExecutorState::current_report() const noexcept {
    return current_;
}

const PointerReport& ExecutorState::desired_mouse_report() const noexcept {
    return desired_mouse_;
}

const PointerReport& ExecutorState::current_mouse_report() const noexcept {
    return current_mouse_;
}

std::uint64_t ExecutorState::desired_mouse_logical_token() const noexcept {
    return pending_mouse_movement_ ? pending_movement_token_ : 0;
}

std::uint8_t ExecutorState::neutral_mask() const noexcept {
    return neutral_mask_;
}

PointerReport ExecutorState::pointer_snapshot(const bool absolute) const noexcept {
    PointerReport r{};
    r.buttons = armed_ ? current_mouse_.buttons : 0;
    r.absolute = absolute;
    r.absolute_x = absolute_x_;
    r.absolute_y = absolute_y_;
    return r;
}

bool ExecutorState::extended_pointer_enabled() const noexcept { return extended_pointer_; }
bool ExecutorState::enable_extended_pointer() noexcept {
    if (!enable_mouse_interface()) { return false; }
    extended_pointer_ = true;
    return true;
}

bool ExecutorState::enable_mouse_interface() noexcept {
    if (transport_ready_ || armed_) {
        return false;
    }
    mouse_enabled_ = true;
    return true;
}

bool ExecutorState::arm(const std::uint64_t epoch) noexcept {
    if (epoch == 0 || armed_ || report_pending_ || release_unconfirmed_ || !is_zero(current_) ||
        (mouse_enabled_ && !is_zero(current_mouse_))) {
        return false;
    }
    armed_ = true;
    epoch_ = epoch;
    session_started_ = false;
    neutral_mask_ = 0;
    neutral_evidence_required_ = false;
    last_movement_token_ = 0;
    return true;
}

SubmitResult ExecutorState::submit(const std::uint64_t epoch,
                                   const BootKeyboardReport& report) noexcept {
    if (!is_valid(report)) {
        return SubmitResult::invalid_report;
    }
    if (!armed_) {
        return SubmitResult::disarmed;
    }
    if (epoch == 0 || epoch != epoch_) {
        return SubmitResult::stale_epoch;
    }
    if (report_pending_) {
        return SubmitResult::busy;
    }
    if (!is_zero(report) && !is_zero(current_mouse_)) {
        return SubmitResult::held_state_conflict;
    }
    desired_ = report;
    desired_interface_ = InputInterface::keyboard;
    report_pending_ = true;
    return SubmitResult::accepted;
}

SubmitResult ExecutorState::submit_mouse_movement(const std::uint64_t epoch,
                                                  const std::uint64_t logical_token,
                                                  const PointerReport& report) noexcept {
    if (!mouse_enabled_ || !is_valid(report) ||
        (!extended_pointer_ && (report.buttons != 0 || report.absolute || report.wheel != 0 || report.pan != 0)) ||
        (report.x == 0 && report.y == 0 && report.wheel == 0 && report.pan == 0 && !report.position_event)) {
        return SubmitResult::invalid_report;
    }
    if (!armed_) {
        return SubmitResult::disarmed;
    }
    if (epoch == 0 || epoch != epoch_) {
        return SubmitResult::stale_epoch;
    }
    if (report_pending_) {
        return SubmitResult::busy;
    }
    if (!is_zero(current_) || (!extended_pointer_ && current_mouse_.buttons != 0) ||
        (current_mouse_.buttons != 0 && !report.absolute)) {
        return SubmitResult::held_state_conflict;
    }
    if (report.buttons != current_mouse_.buttons) { return SubmitResult::held_state_conflict; }
    if (logical_token == 0 || logical_token <= last_movement_token_) {
        return SubmitResult::movement_replayed;
    }
    desired_mouse_ = report;
    desired_interface_ = InputInterface::mouse;
    pending_mouse_movement_ = true;
    pending_movement_token_ = logical_token;
    report_pending_ = true;
    return SubmitResult::accepted;
}

SubmitResult ExecutorState::submit_mouse_buttons(const std::uint64_t epoch,
                                                 const PointerReport& report) noexcept {
    if (!mouse_enabled_ || !is_valid(report) || report.x != 0 || report.y != 0 ||
        report.wheel != 0 || report.pan != 0 || report.position_event ||
        (!extended_pointer_ && (report.buttons & ~0x03U) != 0)) {
        return SubmitResult::invalid_report;
    }
    if (!armed_) {
        return SubmitResult::disarmed;
    }
    if (epoch == 0 || epoch != epoch_) {
        return SubmitResult::stale_epoch;
    }
    if (report_pending_) {
        return SubmitResult::busy;
    }
    if (report.buttons != 0 && (!is_zero(current_) || current_mouse_.buttons != 0)) {
        return SubmitResult::held_state_conflict;
    }
    desired_mouse_ = report;
    // Report IDs 1 and 4 are separate Mouse application collections. A press must
    // accompany the coordinates in the collection that positioned the pointer.
    // Do not invent an absolute position before a move, or reuse it after relative motion.
    if (extended_pointer_ && report.buttons != 0) {
        desired_mouse_.absolute = absolute_button_target_;
        desired_mouse_.absolute_x = absolute_x_;
        desired_mouse_.absolute_y = absolute_y_;
    }
    if (extended_pointer_ && report.buttons == 0) { release_absolute_pending_ = true; }
    desired_interface_ = InputInterface::mouse;
    pending_mouse_movement_ = false;
    pending_movement_token_ = 0;
    report_pending_ = true;
    return SubmitResult::accepted;
}

void ExecutorState::on_transport_ready() noexcept {
    transport_ready_ = true;
    request_release();
}

void ExecutorState::on_transport_lost() noexcept {
    transport_ready_ = false;
    disarm();
}

void ExecutorState::request_release() noexcept {
    desired_ = BootKeyboardReport{};
    desired_interface_ = InputInterface::keyboard;
    release_mouse_pending_ = mouse_enabled_;
    release_absolute_pending_ = extended_pointer_;
    pending_mouse_movement_ = false;
    pending_movement_token_ = 0;
    report_pending_ = true;
}

void ExecutorState::disarm() noexcept {
    armed_ = false;
    epoch_ = 0;
    request_release();
}

void ExecutorState::request_dual_neutral() noexcept {
    neutral_mask_ = 0;
    neutral_evidence_required_ = true;
    armed_ = false;
    epoch_ = 0;
    const bool pending_keyboard_zero =
        report_pending_ && desired_interface_ == InputInterface::keyboard && is_zero(desired_);
    const bool pending_mouse_zero = report_pending_ && desired_interface_ == InputInterface::mouse &&
                                    !pending_mouse_movement_ && is_zero(desired_mouse_);
    if (pending_keyboard_zero || pending_mouse_zero) {
        // A zero report can already be inside TinyUSB while its completion callback is pending.
        // Preserve that exact expected report, then start a fresh keyboard-zero/mouse-zero barrier
        // after the callback. Overwriting it here would make the valid callback look stale and
        // fault the authenticated session.
        dual_neutral_after_pending_zero_ = true;
        release_mouse_pending_ = false;
        return;
    }
    dual_neutral_after_pending_zero_ = false;
    disarm();
}

void ExecutorState::fault() noexcept {
    disarm();
}

void ExecutorState::watchdog_release() noexcept {
    armed_ = false;
    epoch_ = 0;
    desired_ = BootKeyboardReport{};
    current_ = BootKeyboardReport{};
    desired_mouse_ = PointerReport{};
    current_mouse_ = PointerReport{};
    neutral_mask_ = 0;
    release_unconfirmed_ = true;
    request_release();
}

bool ExecutorState::mark_report_accepted(const BootKeyboardReport& report) noexcept {
    if (!report_pending_ || desired_interface_ != InputInterface::keyboard || report != desired_) {
        return false;
    }
    current_ = report;
    report_pending_ = false;
    if (is_zero(report)) {
        if (session_started_ || neutral_evidence_required_) {
            neutral_mask_ |= kKeyboardNeutral;
        }
        if (release_mouse_pending_) {
            desired_mouse_ = PointerReport{};
            desired_interface_ = InputInterface::mouse;
            pending_mouse_movement_ = false;
            pending_movement_token_ = 0;
            report_pending_ = true;
        } else {
            release_unconfirmed_ = false;
        }
    }
    if (!is_zero(report)) {
        session_started_ = true;
        neutral_mask_ = 0;
    }
    if (dual_neutral_after_pending_zero_) {
        dual_neutral_after_pending_zero_ = false;
        neutral_mask_ = 0;
        neutral_evidence_required_ = true;
        request_release();
    }
    return true;
}

bool ExecutorState::mark_mouse_report_accepted(const PointerReport& report,
                                               const std::uint64_t logical_token) noexcept {
    if (!report_pending_ || desired_interface_ != InputInterface::mouse ||
        report != desired_mouse_) {
        return false;
    }
    if (pending_mouse_movement_) {
        if (logical_token == 0 || logical_token != pending_movement_token_ ||
            logical_token <= last_movement_token_) {
            return false;
        }
        last_movement_token_ = logical_token;
        current_mouse_ = PointerReport{report.buttons, 0, 0};
        if (report.absolute) {
            absolute_x_ = report.absolute_x;
            absolute_y_ = report.absolute_y;
            absolute_button_target_ = true;
        } else if (report.x != 0 || report.y != 0) {
            absolute_button_target_ = false;
        }
        session_started_ = true;
        neutral_mask_ = 0;
    } else {
        if (logical_token != 0) {
            return false;
        }
        current_mouse_ = report;
        if (is_zero(report)) {
            if (report.absolute || !extended_pointer_) {
                if (session_started_ || neutral_evidence_required_) { neutral_mask_ |= kMouseNeutral; }
            }
            release_mouse_pending_ = false;
            release_unconfirmed_ = false;
            neutral_evidence_required_ = false;
        } else {
            session_started_ = true;
            neutral_mask_ = 0;
        }
    }
    pending_mouse_movement_ = false;
    pending_movement_token_ = 0;
    report_pending_ = false;
    if (is_zero(report) && !report.absolute && release_absolute_pending_) {
        desired_mouse_ = {};
        desired_mouse_.absolute = true;
        desired_mouse_.absolute_x = absolute_x_;
        desired_mouse_.absolute_y = absolute_y_;
        release_absolute_pending_ = false;
        report_pending_ = true;
        release_unconfirmed_ = true;
        neutral_evidence_required_ = true;
    }
    if (dual_neutral_after_pending_zero_) {
        dual_neutral_after_pending_zero_ = false;
        neutral_mask_ = 0;
        neutral_evidence_required_ = true;
        request_release();
    }
    return true;
}

}  // namespace keyferry::hid
