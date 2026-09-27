#include "keyferry/command_executor.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

using keyferry::command::CommandExecutor;
using keyferry::hid::BootKeyboardReport;
using keyferry::protocol::DecodedFrame;
using keyferry::protocol::ErrorCode;
using keyferry::protocol::MessageType;
using keyferry::protocol::ReportAction;
using keyferry::protocol::ResultCode;

namespace {

constexpr std::array<std::uint8_t, 32> kProfileHash = {0x55};

struct Event {
    std::uint32_t sequence;
    std::array<std::uint8_t, 16> command_id;
    ResultCode result;
};

struct InputEvent {
    std::uint32_t sequence;
    keyferry::command::InputResultEvidence evidence;
};

class Results final : public keyferry::command::ResultSink {
  public:
    void CommandResult(const std::uint32_t sequence,
                       const std::array<std::uint8_t, 16>& command_id,
                       const ResultCode result) override {
        events.push_back({sequence, command_id, result});
    }
    void InputCommandResult(
        const std::uint32_t sequence,
        const keyferry::command::InputResultEvidence& evidence) override {
        input_events.push_back({sequence, evidence});
    }
    std::vector<Event> events;
    std::vector<InputEvent> input_events;
};

class Watchdog final : public keyferry::command::HeldKeyDeadlineScheduler {
  public:
    bool Schedule(const std::uint64_t value, const std::uint64_t deadline) override {
        ++schedule_count;
        token = value;
        deadline_ms = deadline;
        return schedule_succeeds;
    }
    void Cancel(const std::uint64_t value) override {
        if (value == token) {
            ++cancel_count;
            token = 0;
        }
    }
    bool schedule_succeeds{true};
    int schedule_count{0};
    int cancel_count{0};
    std::uint64_t token{0};
    std::uint64_t deadline_ms{0};
};

std::array<std::uint8_t, 16> Id(const std::uint8_t first) {
    std::array<std::uint8_t, 16> id{};
    id[0] = first;
    return id;
}

BootKeyboardReport KeyA() {
    BootKeyboardReport report{};
    report.usages[0] = 0x04;
    return report;
}

void AppendU16(std::vector<std::uint8_t>& output, const std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void AppendU32(std::vector<std::uint8_t>& output, const std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
}

std::vector<std::uint8_t> Actions() {
    std::vector<std::uint8_t> body;
    const auto report = KeyA();
    body.push_back(static_cast<std::uint8_t>(ReportAction::kKeyReport));
    body.push_back(sizeof(report));
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&report);
    body.insert(body.end(), bytes, bytes + sizeof(report));
    body.push_back(static_cast<std::uint8_t>(ReportAction::kReleaseAllAction));
    body.push_back(0);
    body.push_back(static_cast<std::uint8_t>(ReportAction::kWaitMs));
    body.push_back(2);
    AppendU16(body, 8);
    return body;
}

std::vector<std::uint8_t> WaitActions(const std::uint16_t wait_ms) {
    std::vector<std::uint8_t> body;
    body.push_back(static_cast<std::uint8_t>(ReportAction::kWaitMs));
    body.push_back(2);
    AppendU16(body, wait_ms);
    body.push_back(static_cast<std::uint8_t>(ReportAction::kReleaseAllAction));
    body.push_back(0);
    return body;
}

std::vector<std::uint8_t> InputActions() {
    return {
        0x00, 0x00, 0x01, 0x00, 0x05, 0x04, 0xF0, 0x00, 0xD8,
        0xFF, 0x06, 0x05, 0x01, 0x28, 0x00, 0x28, 0x00, 0x04,
        0x06, 0x00, 0x28, 0x0C, 0x00, 0x08, 0x00, 0x07, 0x00,
    };
}

std::vector<std::uint8_t> InputTapActions() {
    return {
        0x00, 0x00, 0x01, 0x00, 0x04, 0x06, 0x00,
        0x28, 0x0C, 0x00, 0x08, 0x00, 0x07, 0x00,
    };
}

std::vector<std::uint8_t> Envelope(const std::array<std::uint8_t, 16>& id,
                                   const std::uint32_t valid_for_ms, const std::uint8_t kind,
                                   const std::vector<std::uint8_t>& body) {
    std::vector<std::uint8_t> payload(id.begin(), id.end());
    AppendU32(payload, valid_for_ms);
    payload.insert(payload.end(), kProfileHash.begin(), kProfileHash.end());
    payload.push_back(kind);
    AppendU16(payload, static_cast<std::uint16_t>(body.size()));
    payload.insert(payload.end(), body.begin(), body.end());
    return payload;
}

DecodedFrame Frame(const std::uint32_t sequence, const std::vector<std::uint8_t>& payload) {
    return {1,
            0,
            static_cast<std::uint8_t>(MessageType::kCommand),
            0,
            sequence,
            payload.data(),
            payload.size()};
}

struct Fixture {
    Fixture() : executor(hid, results, watchdog, kProfileHash) {
        hid.on_transport_ready();
        assert(hid.mark_report_accepted({}));
        executor.BeginSession(7, 2);
        executor.UsbReportAccepted({}, 0);
    }

    void Arm() { assert(executor.CommandScopedArm(7, 2)); }

    keyferry::hid::ExecutorState hid;
    Results results;
    Watchdog watchdog;
    CommandExecutor executor;
};

struct MixedFixture {
    MixedFixture() : executor(hid, results, watchdog, kProfileHash) {
        assert(hid.enable_mouse_interface());
        hid.on_transport_ready();
        assert(hid.mark_report_accepted({}));
        assert(hid.mark_mouse_report_accepted({}, 0));
        executor.BeginSession(7, 2, true);
        executor.UsbReportAccepted({}, 0);
        executor.UsbMouseReportAccepted({}, 0, 0);
    }

    void Arm(const std::uint32_t sequence = 2) {
        assert(executor.CommandScopedArm(7, sequence));
    }

    keyferry::hid::ExecutorState hid;
    Results results;
    Watchdog watchdog;
    CommandExecutor executor;
};

void Executes_with_exact_results_and_terminal_zero() {
    Fixture fixture;
    fixture.Arm();
    const auto payload = Envelope(Id(1), 5000, 1, Actions());
    assert(fixture.executor.HandleAuthenticated(7, Frame(2, payload), 10));
    assert(fixture.results.events.size() == 1);
    assert(fixture.results.events[0].result == ResultCode::kAccepted);
    assert(fixture.hid.desired_report() == KeyA());

    fixture.executor.UsbReportAccepted(KeyA(), 11);
    assert(fixture.results.events.size() == 2);
    assert(fixture.results.events[1].result == ResultCode::kStarted);
    assert(fixture.watchdog.deadline_ms == 2011);
    assert(keyferry::hid::is_zero(fixture.hid.desired_report()));

    fixture.executor.UsbReportAccepted({}, 12);
    assert(fixture.executor.active());
    assert(!fixture.hid.report_needed());
    fixture.executor.Poll(20);
    assert(fixture.hid.report_needed());
    fixture.executor.UsbReportAccepted({}, 21);
    assert(!fixture.executor.active());
    assert(!fixture.hid.armed());
    assert(fixture.results.events.size() == 3);
    assert(fixture.results.events[2].result == ResultCode::kEmitted);
    assert(fixture.watchdog.cancel_count == 1);
}

void Enforces_sequence_expiry_busy_and_arm_consumption() {
    Fixture fixture;
    fixture.Arm();
    const auto first = Envelope(Id(2), 50, 1, WaitActions(20));
    assert(!fixture.executor.HandleAuthenticated(7, Frame(3, first), 0));
    assert(fixture.results.events.back().result == ResultCode::kRejected);
    assert(fixture.executor.expected_sequence() == 2);

    assert(fixture.executor.HandleAuthenticated(7, Frame(2, first), 100));
    const auto busy = Envelope(Id(3), 50, 1, Actions());
    assert(!fixture.executor.HandleAuthenticated(7, Frame(3, busy), 101));
    assert(fixture.results.events.back().result == ResultCode::kRejected);
    fixture.executor.Poll(150);
    assert(keyferry::hid::is_zero(fixture.hid.desired_report()));
    fixture.executor.UsbReportAccepted({}, 151);
    assert(fixture.results.events.back().result == ResultCode::kAborted);

    const auto unarmed = Envelope(Id(4), 50, 1, Actions());
    assert(!fixture.executor.HandleAuthenticated(7, Frame(4, unarmed), 160));
    assert(fixture.results.events.back().result == ResultCode::kRejected);
}

void Cancellation_aborts_after_release() {
    Fixture fixture;
    fixture.Arm();
    const auto id = Id(5);
    const auto execute = Envelope(id, 5000, 1, Actions());
    assert(fixture.executor.HandleAuthenticated(7, Frame(2, execute), 10));
    fixture.executor.UsbReportAccepted(KeyA(), 11);
    const auto cancel = Envelope(id, 5000, 2, {});
    assert(fixture.executor.HandleAuthenticated(7, Frame(3, cancel), 12));
    fixture.executor.UsbReportAccepted({}, 13);
    assert(fixture.results.events.back().result == ResultCode::kAborted);
    assert(!fixture.executor.active());
}

void Independent_watchdog_forces_zero_disarm_and_unknown_without_poll() {
    Fixture fixture;
    fixture.Arm();
    const auto payload = Envelope(Id(6), 5000, 1, Actions());
    assert(fixture.executor.HandleAuthenticated(7, Frame(2, payload), 10));
    fixture.executor.UsbReportAccepted(KeyA(), 11);
    const auto token = fixture.watchdog.token;
    assert(token != 0);

    fixture.executor.HeldKeyDeadlineFired(token, 2011);
    assert(keyferry::hid::is_zero(fixture.hid.current_report()));
    assert(keyferry::hid::is_zero(fixture.hid.desired_report()));
    assert(!fixture.hid.armed());
    assert(fixture.hid.report_needed());
    fixture.executor.UsbReportAccepted({}, 2012);
    assert(fixture.results.events.back().result == ResultCode::kUnknown);
    assert(!fixture.executor.active());
}

void Watchdog_scheduler_failure_fails_closed() {
    Fixture fixture;
    fixture.Arm();
    fixture.watchdog.schedule_succeeds = false;
    const auto payload = Envelope(Id(7), 5000, 1, Actions());
    assert(fixture.executor.HandleAuthenticated(7, Frame(2, payload), 10));
    fixture.executor.UsbReportAccepted(KeyA(), 11);
    assert(keyferry::hid::is_zero(fixture.hid.current_report()));
    assert(!fixture.hid.armed());
    fixture.executor.UsbReportAccepted({}, 12);
    assert(fixture.results.events.back().result == ResultCode::kUnknown);
}

void Session_loss_classifies_started_as_unknown_and_prestart_as_aborted() {
    Fixture before;
    before.Arm();
    const auto waiting = Envelope(Id(8), 5000, 1, WaitActions(100));
    assert(before.executor.HandleAuthenticated(7, Frame(2, waiting), 0));
    before.executor.EndSession();
    assert(before.results.events.back().result == ResultCode::kAborted);

    Fixture after;
    after.Arm();
    const auto started = Envelope(Id(9), 5000, 1, Actions());
    assert(after.executor.HandleAuthenticated(7, Frame(2, started), 0));
    after.executor.UsbReportAccepted(KeyA(), 1);
    after.executor.EndSession();
    assert(after.results.events.back().result == ResultCode::kUnknown);
}

void A_later_arm_resynchronizes_the_command_sequence() {
    Fixture fixture;
    assert(fixture.executor.CommandScopedArm(7, 17));
    assert(fixture.executor.expected_sequence() == 17);
    const auto payload = Envelope(Id(10), 5000, 1, Actions());
    assert(fixture.executor.HandleAuthenticated(7, Frame(17, payload), 10));
    assert(fixture.results.events.back().result == ResultCode::kAccepted);
    fixture.executor.EndSession();
}

void Mixed_input_preserves_order_and_requires_both_terminal_neutrals() {
    MixedFixture fixture;
    fixture.Arm();
    const auto id = Id(11);
    const auto payload = Envelope(id, 5000, 4, InputActions());
    assert(fixture.executor.HandleAuthenticated(7, Frame(2, payload), 10));
    assert(fixture.results.input_events.size() == 1);
    assert(fixture.results.input_events[0].evidence.result == ResultCode::kAccepted);
    assert(fixture.hid.desired_interface() == keyferry::hid::InputInterface::mouse);
    assert(fixture.hid.desired_mouse_report() ==
           (keyferry::hid::BootMouseReport{0, 120, -20}));

    fixture.executor.UsbMouseReportAccepted(
        fixture.hid.desired_mouse_report(), fixture.hid.desired_mouse_logical_token(), 11);
    assert(fixture.results.input_events.size() == 2);
    assert(fixture.results.input_events.back().evidence.result == ResultCode::kStarted);
    assert(fixture.hid.desired_mouse_report() ==
           (keyferry::hid::BootMouseReport{0, 120, -20}));
    fixture.executor.UsbMouseReportAccepted(
        fixture.hid.desired_mouse_report(), fixture.hid.desired_mouse_logical_token(), 12);

    assert(fixture.hid.desired_mouse_report() ==
           (keyferry::hid::BootMouseReport{1, 0, 0}));
    fixture.executor.UsbMouseReportAccepted(fixture.hid.desired_mouse_report(), 0, 13);
    assert(fixture.watchdog.token != 0);
    fixture.executor.Poll(53);
    assert(keyferry::hid::is_zero(fixture.hid.desired_mouse_report()));
    fixture.executor.UsbMouseReportAccepted({}, 0, 54);
    fixture.executor.Poll(94);

    BootKeyboardReport enter{};
    enter.usages[0] = 0x28;
    assert(fixture.hid.desired_report() == enter);
    fixture.executor.UsbReportAccepted(enter, 95);
    fixture.executor.Poll(107);
    fixture.executor.UsbReportAccepted({}, 108);
    fixture.executor.Poll(116);
    assert(fixture.executor.active());
    assert(fixture.hid.neutral_mask() == 0);

    fixture.executor.UsbReportAccepted({}, 117);
    assert(fixture.executor.active());
    assert(fixture.hid.neutral_mask() == keyferry::hid::kKeyboardNeutral);
    fixture.executor.UsbMouseReportAccepted({}, 0, 118);
    assert(!fixture.executor.active());
    const auto& terminal = fixture.results.input_events.back().evidence;
    assert(terminal.result == ResultCode::kEmitted);
    assert(terminal.neutral_mask ==
           (keyferry::hid::kKeyboardNeutral | keyferry::hid::kMouseNeutral));
    assert(terminal.effect_flags == keyferry::command::kInputEffectOccurred);
    assert(terminal.reason == keyferry::command::kNoInputError);
}

void Mixed_cancellation_neutralizes_and_duplicate_chunks_do_not_reexecute() {
    MixedFixture fixture;
    fixture.Arm();
    const auto id = Id(12);
    auto first_body = InputActions();
    first_body[2] = 2;
    const auto execute = Envelope(id, 5000, 4, first_body);
    assert(fixture.executor.HandleAuthenticated(7, Frame(2, execute), 10));
    fixture.executor.UsbMouseReportAccepted(
        fixture.hid.desired_mouse_report(), fixture.hid.desired_mouse_logical_token(), 11);

    const auto cancel = Envelope(id, 5000, 5, {});
    assert(fixture.executor.HandleAuthenticated(7, Frame(3, cancel), 12));
    fixture.executor.UsbReportAccepted({}, 13);
    fixture.executor.UsbMouseReportAccepted({}, 0, 14);
    const auto& aborted = fixture.results.input_events.back().evidence;
    assert(aborted.result == ResultCode::kAborted);
    assert(aborted.reason == ErrorCode::kCancelled);
    assert(aborted.neutral_mask ==
           (keyferry::hid::kKeyboardNeutral | keyferry::hid::kMouseNeutral));

    fixture.Arm(4);
    auto later_body = InputActions();
    later_body[0] = 1;
    later_body[2] = 2;
    const auto later = Envelope(id, 5000, 4, later_body);
    assert(!fixture.executor.HandleAuthenticated(7, Frame(4, later), 20));
    const auto& duplicate = fixture.results.input_events.back().evidence;
    assert(duplicate.result == ResultCode::kRejected);
    assert(duplicate.reason == ErrorCode::kDuplicate);
    assert(!fixture.hid.armed());
}

void Late_input_cancellation_is_rejected_after_the_original_terminal_result() {
    MixedFixture fixture;
    fixture.Arm();
    const auto id = Id(15);
    const auto execute = Envelope(id, 5000, 4, InputTapActions());
    assert(fixture.executor.HandleAuthenticated(7, Frame(2, execute), 10));

    BootKeyboardReport enter{};
    enter.usages[0] = 0x28;
    fixture.executor.UsbReportAccepted(enter, 11);
    fixture.executor.Poll(23);
    fixture.executor.UsbReportAccepted({}, 24);
    fixture.executor.Poll(32);
    assert(fixture.executor.active());
    const auto results_before_cancel = fixture.results.input_events.size();

    const auto cancel = Envelope(id, 5000, 5, {});
    assert(fixture.executor.HandleAuthenticated(7, Frame(3, cancel), 33));
    assert(fixture.results.input_events.size() == results_before_cancel);

    fixture.executor.UsbReportAccepted({}, 34);
    fixture.executor.UsbMouseReportAccepted({}, 0, 35);
    assert(!fixture.executor.active());
    assert(fixture.results.input_events.size() == results_before_cancel + 2);
    const auto& original = fixture.results.input_events[results_before_cancel];
    assert(original.sequence == 2);
    assert(original.evidence.result == ResultCode::kEmitted);
    const auto& late_cancel = fixture.results.input_events[results_before_cancel + 1];
    assert(late_cancel.sequence == 3);
    assert(late_cancel.evidence.result == ResultCode::kRejected);
    assert(late_cancel.evidence.reason == ErrorCode::kInvalidMode);
}

void Mixed_capability_rejection_clears_arm_and_release_confirms_both_zeros() {
    Fixture legacy;
    legacy.Arm();
    const auto unsupported = Envelope(Id(13), 5000, 4, InputActions());
    assert(!legacy.executor.HandleAuthenticated(7, Frame(2, unsupported), 10));
    assert(!legacy.hid.armed());
    assert(legacy.results.input_events.back().evidence.result == ResultCode::kRejected);
    assert(legacy.results.input_events.back().evidence.reason == ErrorCode::kCapabilityRequired);

    keyferry::hid::ExecutorState unnegotiated_hid;
    Results unnegotiated_results;
    Watchdog unnegotiated_watchdog;
    CommandExecutor unnegotiated(unnegotiated_hid, unnegotiated_results,
                                 unnegotiated_watchdog, kProfileHash);
    assert(unnegotiated_hid.enable_mouse_interface());
    unnegotiated_hid.on_transport_ready();
    assert(unnegotiated_hid.mark_report_accepted({}));
    assert(unnegotiated_hid.mark_mouse_report_accepted({}, 0));
    unnegotiated.BeginSession(7, 2);
    unnegotiated.UsbReportAccepted({}, 0);
    unnegotiated.UsbMouseReportAccepted({}, 0, 0);
    assert(unnegotiated.CommandScopedArm(7, 2));
    assert(!unnegotiated.HandleAuthenticated(7, Frame(2, unsupported), 10));
    assert(!unnegotiated_hid.armed());
    assert(unnegotiated_results.input_events.back().evidence.reason ==
           ErrorCode::kCapabilityRequired);

    MixedFixture mixed;
    const auto release = Envelope(Id(14), 5000, 6, {});
    assert(mixed.executor.HandleAuthenticated(7, Frame(2, release), 20));
    assert(mixed.results.input_events.back().evidence.result == ResultCode::kAccepted);
    mixed.executor.UsbReportAccepted({}, 21);
    assert(mixed.executor.active());
    mixed.executor.UsbMouseReportAccepted({}, 0, 22);
    const auto& emitted = mixed.results.input_events.back().evidence;
    assert(emitted.result == ResultCode::kEmitted);
    assert(emitted.effect_flags == 0);
    assert(emitted.neutral_mask ==
           (keyferry::hid::kKeyboardNeutral | keyferry::hid::kMouseNeutral));
}

}  // namespace

int main() {
    Executes_with_exact_results_and_terminal_zero();
    Enforces_sequence_expiry_busy_and_arm_consumption();
    Cancellation_aborts_after_release();
    Independent_watchdog_forces_zero_disarm_and_unknown_without_poll();
    Watchdog_scheduler_failure_fails_closed();
    Session_loss_classifies_started_as_unknown_and_prestart_as_aborted();
    A_later_arm_resynchronizes_the_command_sequence();
    Mixed_input_preserves_order_and_requires_both_terminal_neutrals();
    Mixed_cancellation_neutralizes_and_duplicate_chunks_do_not_reexecute();
    Late_input_cancellation_is_rejected_after_the_original_terminal_result();
    Mixed_capability_rejection_clears_arm_and_release_confirms_both_zeros();
    std::cout << "command_executor_test: ok\n";
    return 0;
}
