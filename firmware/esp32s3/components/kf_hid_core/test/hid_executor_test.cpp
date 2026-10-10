#include "keyferry/hid_executor.h"

#include <cassert>
#include <iostream>

using keyferry::hid::BootKeyboardReport;
using keyferry::hid::BootMouseReport;
using keyferry::hid::ExecutorState;
using keyferry::hid::InputInterface;
using keyferry::hid::SubmitResult;

namespace {

BootKeyboardReport key_a() {
    BootKeyboardReport report{};
    report.usages[0] = 0x04;
    return report;
}

void accept_initial_dual_neutral(ExecutorState& state) {
    state.on_transport_ready();
    assert(state.desired_interface() == InputInterface::keyboard);
    assert(state.mark_report_accepted({}));
    assert(state.report_needed());
    assert(state.desired_interface() == InputInterface::mouse);
    assert(state.mark_mouse_report_accepted({}, 0));
    assert(!state.report_needed());
}

void starts_disarmed_and_requires_release() {
    ExecutorState state;
    assert(!state.armed());
    assert(!state.report_needed());
    assert(!state.arm(1));

    state.on_transport_ready();
    assert(state.report_needed());
    assert(keyferry::hid::is_zero(state.desired_report()));
    assert(state.mark_report_accepted({}));
    assert(!state.report_needed());
    assert(state.arm(1));
}

void releases_after_fault_without_erasing_start_evidence() {
    ExecutorState state;
    state.on_transport_ready();
    assert(state.mark_report_accepted({}));
    assert(state.arm(7));

    const auto report = key_a();
    assert(state.submit(7, report) == SubmitResult::accepted);
    assert(state.report_needed());
    assert(state.mark_report_accepted(report));
    assert(state.session_started());

    state.fault();
    assert(!state.armed());
    assert(state.epoch() == 0);
    assert(state.report_needed());
    assert(keyferry::hid::is_zero(state.desired_report()));
    assert(state.session_started());
    assert(state.mark_report_accepted({}));
    assert(keyferry::hid::is_zero(state.current_report()));
}

void rejects_invalid_and_stale_reports() {
    ExecutorState state;
    state.on_transport_ready();
    assert(state.mark_report_accepted({}));
    assert(state.arm(11));

    auto duplicate = key_a();
    duplicate.usages[1] = duplicate.usages[0];
    assert(state.submit(11, duplicate) == SubmitResult::invalid_report);

    auto reserved = key_a();
    reserved.reserved = 1;
    assert(state.submit(11, reserved) == SubmitResult::invalid_report);
    assert(state.submit(12, key_a()) == SubmitResult::stale_epoch);
}

void rejects_report_overwrite_until_transport_accepts_pending_report() {
    ExecutorState state;
    state.on_transport_ready();
    assert(state.mark_report_accepted({}));
    assert(state.arm(13));

    const auto report = key_a();
    assert(state.submit(13, report) == SubmitResult::accepted);
    assert(state.submit(13, {}) == SubmitResult::busy);
    assert(state.desired_report() == report);
    assert(state.mark_report_accepted(report));
    assert(state.submit(13, {}) == SubmitResult::accepted);
}

void reconnect_reasserts_zero_before_rearming() {
    ExecutorState state;
    state.on_transport_ready();
    assert(state.mark_report_accepted({}));
    assert(state.arm(19));
    assert(state.submit(19, key_a()) == SubmitResult::accepted);
    assert(state.mark_report_accepted(key_a()));

    state.on_transport_lost();
    assert(!state.armed());
    assert(!state.report_needed());
    assert(!state.arm(20));

    state.on_transport_ready();
    assert(state.report_needed());
    assert(state.mark_report_accepted({}));
    assert(state.arm(20));
}

void watchdog_forces_logical_zero_and_blocks_rearm_until_usb_release() {
    ExecutorState state;
    state.on_transport_ready();
    assert(state.mark_report_accepted({}));
    assert(state.arm(0x100000001ULL));
    assert(state.submit(0x100000001ULL, key_a()) == SubmitResult::accepted);
    assert(state.mark_report_accepted(key_a()));

    state.watchdog_release();
    assert(!state.armed());
    assert(state.epoch() == 0);
    assert(keyferry::hid::is_zero(state.current_report()));
    assert(keyferry::hid::is_zero(state.desired_report()));
    assert(state.report_needed());
    assert(!state.arm(22));
    assert(state.mark_report_accepted({}));
    assert(state.arm(22));
}

void mixed_mode_requires_dual_neutral_before_arm() {
    ExecutorState state;
    assert(state.enable_mouse_interface());
    assert(state.mouse_enabled());
    accept_initial_dual_neutral(state);
    assert(state.arm(31));
    assert(!state.enable_mouse_interface());
}

void movement_is_consumed_once_and_equal_reports_are_not_coalesced() {
    ExecutorState state;
    assert(state.enable_mouse_interface());
    accept_initial_dual_neutral(state);
    assert(state.arm(41));

    const BootMouseReport movement{0, 120, -20};
    assert(state.submit_mouse_movement(41, 1, movement) == SubmitResult::accepted);
    assert(state.desired_interface() == InputInterface::mouse);
    assert(state.mark_mouse_report_accepted(movement, 1));
    assert(state.session_started());
    assert(keyferry::hid::is_zero(state.current_mouse_report()));
    assert(state.submit_mouse_movement(41, 1, movement) == SubmitResult::movement_replayed);
    assert(state.submit_mouse_movement(41, 2, movement) == SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted(movement, 2));
}

void movement_is_forbidden_during_any_held_state() {
    ExecutorState state;
    assert(state.enable_mouse_interface());
    accept_initial_dual_neutral(state);
    assert(state.arm(51));
    const BootMouseReport movement{0, 1, 0};

    assert(state.submit(51, key_a()) == SubmitResult::accepted);
    assert(state.mark_report_accepted(key_a()));
    assert(state.submit_mouse_movement(51, 1, movement) ==
           SubmitResult::held_state_conflict);
    assert(state.submit(51, {}) == SubmitResult::accepted);
    assert(state.mark_report_accepted({}));

    assert(state.submit_mouse_buttons(51, BootMouseReport{1, 0, 0}) ==
           SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted(BootMouseReport{1, 0, 0}, 0));
    assert(state.submit_mouse_movement(51, 1, movement) ==
           SubmitResult::held_state_conflict);
    assert(state.submit_mouse_buttons(51, {}) == SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted({}, 0));
}

void post_effect_terminal_evidence_requires_both_interfaces() {
    ExecutorState state;
    assert(state.enable_mouse_interface());
    accept_initial_dual_neutral(state);
    assert(state.arm(61));

    assert(state.submit_mouse_buttons(61, BootMouseReport{1, 0, 0}) ==
           SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted(BootMouseReport{1, 0, 0}, 0));
    assert(state.neutral_mask() == 0);
    assert(state.submit_mouse_buttons(61, {}) == SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted({}, 0));
    assert(state.neutral_mask() == keyferry::hid::kMouseNeutral);
    assert(state.submit(61, {}) == SubmitResult::accepted);
    assert(state.mark_report_accepted({}));
    assert(state.neutral_mask() ==
           (keyferry::hid::kKeyboardNeutral | keyferry::hid::kMouseNeutral));

    const BootMouseReport movement{0, 1, 0};
    assert(state.submit_mouse_movement(61, 1, movement) == SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted(movement, 1));
    assert(state.neutral_mask() == 0);
}

void invalid_mouse_reports_and_completion_tokens_fail_closed() {
    ExecutorState state;
    assert(state.enable_mouse_interface());
    accept_initial_dual_neutral(state);
    assert(state.arm(71));
    assert(state.submit_mouse_movement(71, 1, BootMouseReport{0, -128, 0}) ==
           SubmitResult::invalid_report);
    assert(state.submit_mouse_buttons(71, BootMouseReport{4, 0, 0}) ==
           SubmitResult::invalid_report);
    const BootMouseReport movement{0, 2, -1};
    assert(state.submit_mouse_movement(71, 2, movement) == SubmitResult::accepted);
    assert(!state.mark_mouse_report_accepted(movement, 1));
    assert(state.report_needed());
    assert(state.mark_mouse_report_accepted(movement, 2));
}

void cancellation_during_pending_keyboard_zero_restarts_dual_neutral() {
    ExecutorState state;
    assert(state.enable_mouse_interface());
    accept_initial_dual_neutral(state);
    assert(state.arm(81));
    assert(state.submit(81, key_a()) == SubmitResult::accepted);
    assert(state.mark_report_accepted(key_a()));
    assert(state.submit(81, {}) == SubmitResult::accepted);

    state.request_dual_neutral();
    assert(!state.armed());
    assert(state.desired_interface() == InputInterface::keyboard);
    assert(state.mark_report_accepted({}));
    assert(state.report_needed());
    assert(state.desired_interface() == InputInterface::keyboard);
    assert(state.mark_report_accepted({}));
    assert(state.report_needed());
    assert(state.desired_interface() == InputInterface::mouse);
    assert(state.mark_mouse_report_accepted({}, 0));
    assert(!state.report_needed());
    assert(state.neutral_mask() ==
           (keyferry::hid::kKeyboardNeutral | keyferry::hid::kMouseNeutral));
}

void cancellation_during_pending_mouse_zero_restarts_dual_neutral() {
    ExecutorState state;
    assert(state.enable_mouse_interface());
    accept_initial_dual_neutral(state);
    assert(state.arm(91));
    assert(state.submit_mouse_buttons(91, BootMouseReport{1, 0, 0}) ==
           SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted(BootMouseReport{1, 0, 0}, 0));
    assert(state.submit_mouse_buttons(91, {}) == SubmitResult::accepted);

    state.request_dual_neutral();
    assert(!state.armed());
    assert(state.desired_interface() == InputInterface::mouse);
    assert(state.mark_mouse_report_accepted({}, 0));
    assert(state.report_needed());
    assert(state.desired_interface() == InputInterface::keyboard);
    assert(state.mark_report_accepted({}));
    assert(state.report_needed());
    assert(state.desired_interface() == InputInterface::mouse);
    assert(state.mark_mouse_report_accepted({}, 0));
    assert(!state.report_needed());
    assert(state.neutral_mask() ==
           (keyferry::hid::kKeyboardNeutral | keyferry::hid::kMouseNeutral));
}

void scroll_selection_survives_neutral_and_consumes_each_token_once() {
    ExecutorState state;
    assert(state.enable_extended_pointer());
    // Keyboard zero, relative zero, and report 4 only while a report-4 button may be held.
    auto neutral = [&](const bool absolute_leg) {
        assert(state.mark_report_accepted({}));
        assert(state.mark_mouse_report_accepted({}, 0));
        if (absolute_leg) {
            assert(state.desired_mouse_report().absolute);
            assert(state.mark_mouse_report_accepted(state.desired_mouse_report(), 0));
        }
        assert(!state.report_needed());
    };
    state.on_transport_ready(); neutral(false);
    assert(state.arm(101));
    keyferry::hid::PointerReport scroll{};
    scroll.wheel = -1; scroll.pan = 1;
    std::array<std::uint8_t, 8> wire{};
    assert(state.submit_mouse_movement(101, 1, scroll) == SubmitResult::accepted);
    assert(keyferry::hid::SerializePointerReport(state.desired_mouse_report(), &wire) == 6);
    assert((wire == std::array<std::uint8_t, 8>{1,0,0,0,255,1,0,0}));
    assert(state.mark_mouse_report_accepted(state.desired_mouse_report(), 1));
    keyferry::hid::PointerReport position{};
    position.absolute = true; position.position_event = true;
    position.absolute_x = 0x1234; position.absolute_y = 0x2345;
    assert(state.submit_mouse_movement(101, 2, position) == SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted(position, 2));
    state.request_dual_neutral(); neutral(false);
    assert(state.arm(102)); // separate MCP commands preserve the positioning collection
    assert(state.submit_mouse_movement(102, 1, scroll) == SubmitResult::accepted);
    const auto routed = state.desired_mouse_report();
    assert(keyferry::hid::SerializePointerReport(routed, &wire) == 8);
    assert((wire == std::array<std::uint8_t, 8>{4,0,0x34,0x12,0x45,0x23,255,1}));
    assert(!state.mark_mouse_report_accepted(scroll, 1)); // original relative bytes cannot confirm it
    assert(!state.mark_mouse_report_accepted(routed, 2));
    assert(state.mark_mouse_report_accepted(routed, 1));
    assert(state.submit_mouse_movement(102, 1, scroll) == SubmitResult::movement_replayed);
    assert(state.pointer_snapshot(true).wheel == 0 && state.pointer_snapshot(true).pan == 0);
    assert(state.submit_mouse_buttons(102, BootMouseReport{2,0,0}) == SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted(state.desired_mouse_report(), 0));
    assert(keyferry::hid::SerializePointerReport(state.pointer_snapshot(true), &wire) == 8);
    assert((wire == std::array<std::uint8_t, 8>{4,2,0x34,0x12,0x45,0x23,0,0}));
    state.fault(); neutral(true);
    assert(keyferry::hid::SerializePointerReport(state.pointer_snapshot(true), &wire) == 8);
    assert((wire == std::array<std::uint8_t, 8>{4,0,0x34,0x12,0x45,0x23,0,0}));
}

// Windows applies every report-4 coordinate. A barrier that re-sent the retained position
// (or 0,0 before any absolute move) snapped the cursor back after relative motion or a
// physical mouse move, so relative moves appeared to do nothing.
void barrier_never_repositions_without_held_absolute_button() {
    ExecutorState state;
    assert(state.enable_extended_pointer());
    auto drain = [&]() {
        int absolute_reports = 0;
        while (state.report_needed()) {
            if (state.desired_interface() == InputInterface::keyboard) {
                assert(state.mark_report_accepted({}));
                continue;
            }
            const auto report = state.desired_mouse_report();
            assert(keyferry::hid::is_zero(report));
            absolute_reports += report.absolute ? 1 : 0;
            assert(state.mark_mouse_report_accepted(report, 0));
        }
        return absolute_reports;
    };
    state.on_transport_ready();
    assert(drain() == 0);  // mount never moves the cursor to 0,0
    assert(state.arm(111));
    keyferry::hid::PointerReport position{};
    position.absolute = true; position.position_event = true;
    position.absolute_x = 0x1234; position.absolute_y = 0x2345;
    assert(state.submit_mouse_movement(111, 1, position) == SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted(position, 1));
    const keyferry::hid::PointerReport relative{0, 40, -20};
    assert(state.submit_mouse_movement(111, 2, relative) == SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted(relative, 2));
    state.disarm();
    assert(drain() == 0);  // the relative displacement is kept
    assert(state.neutral_mask() ==
           (keyferry::hid::kKeyboardNeutral | keyferry::hid::kMouseNeutral));

    // A relative-collection click releases on report 1 alone.
    assert(state.arm(112));
    assert(state.submit_mouse_buttons(112, BootMouseReport{1, 0, 0}) == SubmitResult::accepted);
    assert(!state.desired_mouse_report().absolute);
    assert(state.mark_mouse_report_accepted(state.desired_mouse_report(), 0));
    assert(state.submit_mouse_buttons(112, {}) == SubmitResult::accepted);
    assert(drain() == 0);
    state.disarm();
    assert(drain() == 0);

    // A report-4 press keeps the report-4 release on the button-up and on every fault.
    assert(state.arm(113));
    assert(state.submit_mouse_movement(113, 3, position) == SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted(position, 3));
    assert(state.submit_mouse_buttons(113, BootMouseReport{1, 0, 0}) == SubmitResult::accepted);
    assert(state.desired_mouse_report().absolute);
    state.fault();  // press still in flight: the host may have seen it
    assert(drain() == 1);
    assert(state.neutral_mask() ==
           (keyferry::hid::kKeyboardNeutral | keyferry::hid::kMouseNeutral));
    assert(state.arm(114));
    assert(state.submit_mouse_buttons(114, BootMouseReport{1, 0, 0}) == SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted(state.desired_mouse_report(), 0));
    assert(state.submit_mouse_buttons(114, {}) == SubmitResult::accepted);
    assert(state.mark_mouse_report_accepted({}, 0));
    assert(state.neutral_mask() == 0);  // relative zero alone is not the release
    assert(drain() == 1);
    state.disarm();
    assert(drain() == 0);  // report-4 button already released: no further reposition
}

}  // namespace

int main() {
    scroll_selection_survives_neutral_and_consumes_each_token_once();
    barrier_never_repositions_without_held_absolute_button();
    starts_disarmed_and_requires_release();
    releases_after_fault_without_erasing_start_evidence();
    rejects_invalid_and_stale_reports();
    rejects_report_overwrite_until_transport_accepts_pending_report();
    reconnect_reasserts_zero_before_rearming();
    watchdog_forces_logical_zero_and_blocks_rearm_until_usb_release();
    mixed_mode_requires_dual_neutral_before_arm();
    movement_is_consumed_once_and_equal_reports_are_not_coalesced();
    movement_is_forbidden_during_any_held_state();
    post_effect_terminal_evidence_requires_both_interfaces();
    invalid_mouse_reports_and_completion_tokens_fail_closed();
    cancellation_during_pending_keyboard_zero_restarts_dual_neutral();
    cancellation_during_pending_mouse_zero_restarts_dual_neutral();
    std::cout << "hid_executor_test: ok\n";
    return 0;
}
