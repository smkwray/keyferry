#include "keyferry/command_executor.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace keyferry::command {
namespace {

constexpr std::size_t kCommandEnvelopeLength = 16 + 4 + 32 + 1 + 2;
constexpr std::uint8_t kExecuteReportChunk =
    static_cast<std::uint8_t>(protocol::CommandKind::kExecuteReportChunk);
constexpr std::uint8_t kCancel = static_cast<std::uint8_t>(protocol::CommandKind::kCancel);
constexpr std::uint8_t kReleaseAll =
    static_cast<std::uint8_t>(protocol::CommandKind::kReleaseAll);
constexpr std::uint8_t kExecuteInputChunk =
    static_cast<std::uint8_t>(protocol::CommandKind::kExecuteInputChunkV1);
constexpr std::uint8_t kCancelInput =
    static_cast<std::uint8_t>(protocol::CommandKind::kCancelInputSequenceV1);
constexpr std::uint8_t kReleaseInputAll =
    static_cast<std::uint8_t>(protocol::CommandKind::kReleaseInputAllV1);

std::uint16_t ReadU16(const std::uint8_t* input) {
    return static_cast<std::uint16_t>(input[0]) |
           (static_cast<std::uint16_t>(input[1]) << 8U);
}

std::uint32_t ReadU32(const std::uint8_t* input) {
    return static_cast<std::uint32_t>(input[0]) |
           (static_cast<std::uint32_t>(input[1]) << 8U) |
           (static_cast<std::uint32_t>(input[2]) << 16U) |
           (static_cast<std::uint32_t>(input[3]) << 24U);
}

std::uint64_t AddDeadline(const std::uint64_t now, const std::uint64_t delta) {
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    return now > maximum - delta ? maximum : now + delta;
}

bool IsZeroId(const std::array<std::uint8_t, 16>& value) {
    return std::all_of(value.begin(), value.end(), [](const std::uint8_t byte) {
        return byte == 0;
    });
}

protocol::ErrorCode ReplayError(const InputReplayDecision decision) {
    switch (decision) {
        case InputReplayDecision::kDuplicate:
        case InputReplayDecision::kConflict:
        case InputReplayDecision::kOutOfOrder:
            return protocol::ErrorCode::kDuplicate;
        case InputReplayDecision::kWindowFull:
            return protocol::ErrorCode::kReplayWindowFull;
        case InputReplayDecision::kInvalid:
            return protocol::ErrorCode::kMalformed;
        case InputReplayDecision::kAccepted:
            return kNoInputError;
    }
    return protocol::ErrorCode::kInternal;
}

}  // namespace

CommandExecutor::CommandExecutor(hid::ExecutorState& hid, ResultSink& results,
                                 HeldKeyDeadlineScheduler& watchdog,
                                 const std::array<std::uint8_t, 32>& accepted_profile_hash)
    : hid_(hid),
      results_(results),
      watchdog_(watchdog),
      accepted_profile_hash_(accepted_profile_hash) {}

void CommandExecutor::BeginSession(const std::uint64_t epoch,
                                   const std::uint32_t first_sequence,
                                   const bool input_v1_enabled) {
    EndSession();
    if (epoch == 0) {
        return;
    }
    epoch_ = epoch;
    expected_sequence_ = first_sequence;
    sequence_exhausted_ = false;
    input_v1_enabled_ = input_v1_enabled;
    command_arm_available_ = false;
    input_replay_.Reset();
    hid_.disarm();
}

void CommandExecutor::EndSession() {
    CancelHeldKeyWatchdog();
    if (active_) {
        if (input_active_) {
            input_replay_.Close(command_id_);
            const bool neutral =
                hid_.neutral_mask() == (hid::kKeyboardNeutral | hid::kMouseNeutral);
            EmitInput(neutral ? protocol::ResultCode::kAborted
                              : protocol::ResultCode::kUnknown,
                      protocol::ErrorCode::kNeutralUnconfirmed);
        } else {
            Emit(command_id_, command_sequence_,
                 started_ ? protocol::ResultCode::kUnknown : protocol::ResultCode::kAborted);
        }
    }
    active_ = false;
    started_ = false;
    terminal_pending_ = false;
    input_active_ = false;
    late_input_cancel_pending_ = false;
    late_input_cancel_sequence_ = 0;
    phase_ = Phase::kIdle;
    action_count_ = 0;
    action_index_ = 0;
    input_chunk_ = {};
    movement_part_index_ = 0;
    movement_token_ = 0;
    input_effect_flags_ = 0;
    command_arm_available_ = false;
    epoch_ = 0;
    expected_sequence_ = 0;
    sequence_exhausted_ = false;
    input_v1_enabled_ = false;
    hid_.disarm();
}

bool CommandExecutor::CommandScopedArm(const std::uint64_t epoch,
                                       const std::uint32_t command_sequence) {
    if (epoch == 0 || epoch != epoch_ || active_ || command_arm_available_) {
        return false;
    }
    if (!hid_.arm(epoch)) {
        return false;
    }
    expected_sequence_ = command_sequence;
    sequence_exhausted_ = false;
    command_arm_available_ = true;
    return true;
}

bool CommandExecutor::HandleAuthenticated(const std::uint64_t epoch,
                                          const protocol::DecodedFrame& frame,
                                          const std::uint64_t now_ms) {
    if (epoch == 0 || epoch != epoch_ || sequence_exhausted_ ||
        frame.message_type != static_cast<std::uint8_t>(protocol::MessageType::kCommand)) {
        return false;
    }

    std::array<std::uint8_t, 16> command_id{};
    if (frame.payload != nullptr && frame.payload_length >= command_id.size()) {
        std::copy_n(frame.payload, command_id.size(), command_id.begin());
    }
    if (frame.sequence != expected_sequence_) {
        if (!IsZeroId(command_id)) {
            Emit(command_id, frame.sequence, protocol::ResultCode::kRejected);
        }
        return false;
    }
    if (expected_sequence_ == std::numeric_limits<std::uint32_t>::max()) {
        sequence_exhausted_ = true;
    } else {
        ++expected_sequence_;
    }

    std::uint32_t valid_for_ms = 0;
    std::uint8_t kind = 0;
    const std::uint8_t* body = nullptr;
    std::size_t body_length = 0;
    if (frame.major != protocol::kMajor || frame.minor != protocol::kMinor || frame.flags != 0 ||
        !ParseEnvelope(frame, &command_id, &valid_for_ms, &kind, &body, &body_length) ||
        IsZeroId(command_id)) {
        if (!IsZeroId(command_id)) {
            Emit(command_id, frame.sequence, protocol::ResultCode::kRejected);
        }
        return false;
    }

    const bool input_kind = kind == kExecuteInputChunk || kind == kCancelInput ||
                            kind == kReleaseInputAll;
    if (input_kind) {
        const bool clear_arm = kind == kExecuteInputChunk && command_arm_available_;
        if (!input_v1_enabled_ || !hid_.mouse_enabled()) {
            RejectInput(command_id, frame.sequence, protocol::ErrorCode::kCapabilityRequired,
                        clear_arm);
            return false;
        }
        if (kind == kCancelInput) {
            if (body_length != 0 || !active_ || !input_active_ || command_id != command_id_) {
                RejectInput(command_id, frame.sequence, protocol::ErrorCode::kMalformed, false);
                return false;
            }
            if (terminal_pending_) {
                if (terminal_result_ == protocol::ResultCode::kEmitted &&
                    !late_input_cancel_pending_) {
                    late_input_cancel_pending_ = true;
                    late_input_cancel_sequence_ = frame.sequence;
                }
                return true;
            }
            BeginTerminal(protocol::ResultCode::kAborted, protocol::ErrorCode::kCancelled);
            return true;
        }
        if (kind == kReleaseInputAll) {
            if (body_length != 0 || active_) {
                RejectInput(command_id, frame.sequence, protocol::ErrorCode::kBusy, false);
                return false;
            }
            command_arm_available_ = false;
            active_ = true;
            input_active_ = true;
            started_ = false;
            terminal_pending_ = false;
            input_effect_flags_ = 0;
            command_id_ = command_id;
            command_sequence_ = frame.sequence;
            expiry_ms_ = AddDeadline(now_ms, valid_for_ms);
            EmitInput(protocol::ResultCode::kAccepted, kNoInputError);
            BeginTerminal(protocol::ResultCode::kEmitted, kNoInputError);
            return true;
        }

        ParsedInputChunk parsed{};
        if (!ParseInputChunk(body, body_length, &parsed)) {
            RejectInput(command_id, frame.sequence, protocol::ErrorCode::kMalformed, clear_arm);
            return false;
        }
        if (active_) {
            RejectInput(command_id, frame.sequence, protocol::ErrorCode::kBusy, clear_arm);
            return false;
        }
        if (!command_arm_available_ || !hid_.armed()) {
            RejectInput(command_id, frame.sequence, protocol::ErrorCode::kNotArmed, clear_arm);
            return false;
        }
        const auto replay = input_replay_.Admit(command_id, parsed.index, parsed.count);
        if (replay != InputReplayDecision::kAccepted) {
            RejectInput(command_id, frame.sequence, ReplayError(replay), true);
            return false;
        }

        command_arm_available_ = false;
        active_ = true;
        input_active_ = true;
        started_ = false;
        terminal_pending_ = false;
        input_effect_flags_ = 0;
        command_id_ = command_id;
        command_sequence_ = frame.sequence;
        expiry_ms_ = AddDeadline(now_ms, valid_for_ms);
        input_chunk_ = parsed;
        action_index_ = 0;
        movement_part_index_ = 0;
        phase_ = Phase::kReady;
        EmitInput(protocol::ResultCode::kAccepted, kNoInputError);
        DriveInput(now_ms);
        return true;
    }

    if (kind == kCancel) {
        if (body_length != 0 || !active_ || command_id != command_id_) {
            Emit(command_id, frame.sequence, protocol::ResultCode::kRejected);
            return false;
        }
        BeginTerminal(protocol::ResultCode::kAborted);
        return true;
    }

    if (kind == kReleaseAll) {
        if (body_length != 0 || active_) {
            Emit(command_id, frame.sequence, protocol::ResultCode::kRejected);
            return false;
        }
        active_ = true;
        input_active_ = false;
        started_ = false;
        command_id_ = command_id;
        command_sequence_ = frame.sequence;
        expiry_ms_ = AddDeadline(now_ms, valid_for_ms);
        action_count_ = 0;
        action_index_ = 0;
        Emit(command_id_, command_sequence_, protocol::ResultCode::kAccepted);
        BeginTerminal(protocol::ResultCode::kEmitted);
        return true;
    }

    if (kind != kExecuteReportChunk || active_ || !command_arm_available_ || !hid_.armed() ||
        !ParseActions(body, body_length)) {
        Emit(command_id, frame.sequence, protocol::ResultCode::kRejected);
        return false;
    }

    command_arm_available_ = false;
    active_ = true;
    input_active_ = false;
    started_ = false;
    terminal_pending_ = false;
    command_id_ = command_id;
    command_sequence_ = frame.sequence;
    expiry_ms_ = AddDeadline(now_ms, valid_for_ms);
    action_index_ = 0;
    phase_ = Phase::kReady;
    Emit(command_id_, command_sequence_, protocol::ResultCode::kAccepted);
    Drive(now_ms);
    return true;
}

void CommandExecutor::Poll(const std::uint64_t now_ms) {
    if (!active_ || terminal_pending_) {
        return;
    }
    if (now_ms >= expiry_ms_) {
        BeginTerminal(protocol::ResultCode::kAborted,
                      input_active_ ? protocol::ErrorCode::kExpired : kNoInputError);
        return;
    }
    if ((phase_ == Phase::kWait || phase_ == Phase::kTapHold || phase_ == Phase::kTapGap ||
         phase_ == Phase::kMouseClickHold || phase_ == Phase::kMouseClickGap) &&
        now_ms >= wait_deadline_ms_) {
        if (phase_ == Phase::kWait) {
            ++action_index_;
            phase_ = Phase::kReady;
        } else if (phase_ == Phase::kTapHold) {
            const auto result = hid_.submit(epoch_, {});
            if (result != hid::SubmitResult::accepted) {
                FailActive(started_);
                return;
            }
            phase_ = Phase::kAwaitTapRelease;
        } else if (phase_ == Phase::kMouseClickHold) {
            const auto result = hid_.submit_mouse_buttons(epoch_, {});
            if (result != hid::SubmitResult::accepted) {
                FailActive(started_);
                return;
            }
            phase_ = Phase::kAwaitMouseClickRelease;
        } else {
            ++action_index_;
            phase_ = Phase::kReady;
        }
    }
    if (input_active_) {
        DriveInput(now_ms);
    } else {
        Drive(now_ms);
    }
}

void CommandExecutor::UsbReportAccepted(const hid::BootKeyboardReport& report,
                                        const std::uint64_t now_ms) {
    const bool previously_nonzero = !hid::is_zero(hid_.current_report());
    if (!hid_.mark_report_accepted(report)) {
        UsbFault();
        return;
    }
    const bool zero = hid::is_zero(report);
    if (input_active_) {
        if (zero) {
            if (hid_.current_mouse_report().buttons == 0) {
                CancelHeldKeyWatchdog();
            }
        } else {
            const bool first_started_report = active_ && !started_;
            if (first_started_report) {
                started_ = true;
                input_effect_flags_ |= kInputEffectOccurred;
            }
            if (!previously_nonzero) {
                ArmHeldKeyWatchdog(now_ms);
            }
            if (first_started_report) {
                EmitInput(protocol::ResultCode::kStarted, kNoInputError);
            }
        }
        if (!active_) {
            return;
        }
        if (terminal_pending_) {
            if (hid_.neutral_mask() == (hid::kKeyboardNeutral | hid::kMouseNeutral)) {
                FinishTerminal();
            }
            return;
        }
        if (phase_ == Phase::kAwaitActionReport) {
            ++action_index_;
            phase_ = Phase::kReady;
        } else if (phase_ == Phase::kAwaitTapPress && !zero) {
            phase_ = Phase::kTapHold;
            wait_deadline_ms_ =
                AddDeadline(now_ms, input_chunk_.actions[action_index_].first_ms);
        } else if (phase_ == Phase::kAwaitTapRelease && zero) {
            phase_ = Phase::kTapGap;
            wait_deadline_ms_ =
                AddDeadline(now_ms, input_chunk_.actions[action_index_].second_ms);
        } else {
            FailActive(started_);
            return;
        }
        DriveInput(now_ms);
        return;
    }
    if (zero) {
        CancelHeldKeyWatchdog();
    } else {
        const bool first_started_report = active_ && !started_;
        if (first_started_report) {
            started_ = true;
        }
        if (!previously_nonzero) {
            ArmHeldKeyWatchdog(now_ms);
        }
        if (first_started_report) {
            Emit(command_id_, command_sequence_, protocol::ResultCode::kStarted);
        }
        if (!active_ || terminal_pending_) {
            return;
        }
    }

    if (!active_) {
        return;
    }
    if (terminal_pending_) {
        if (zero) {
            FinishTerminal();
        }
        return;
    }

    if (phase_ == Phase::kAwaitActionReport) {
        ++action_index_;
        phase_ = Phase::kReady;
    } else if (phase_ == Phase::kAwaitTapPress && !zero) {
        phase_ = Phase::kTapHold;
        wait_deadline_ms_ = AddDeadline(now_ms, actions_[action_index_].first_ms);
    } else if (phase_ == Phase::kAwaitTapRelease && zero) {
        phase_ = Phase::kTapGap;
        wait_deadline_ms_ = AddDeadline(now_ms, actions_[action_index_].second_ms);
    } else {
        FailActive(started_);
        return;
    }
    Drive(now_ms);
}

void CommandExecutor::UsbMouseReportAccepted(const hid::BootMouseReport& report,
                                             const std::uint64_t logical_token,
                                             const std::uint64_t now_ms) {
    const bool previously_held = hid_.current_mouse_report().buttons != 0;
    if (!hid_.mark_mouse_report_accepted(report, logical_token)) {
        UsbFault();
        return;
    }
    if (!input_active_) {
        return;
    }
    const bool effect = logical_token != 0 || report.buttons != 0;
    if (effect) {
        const bool first_started_report = active_ && !started_;
        if (first_started_report) {
            started_ = true;
            input_effect_flags_ |= kInputEffectOccurred;
        }
        if (report.buttons != 0 && !previously_held) {
            ArmHeldKeyWatchdog(now_ms);
        }
        if (first_started_report) {
            EmitInput(protocol::ResultCode::kStarted, kNoInputError);
        }
    } else if (hid::is_zero(report) && hid::is_zero(hid_.current_report())) {
        CancelHeldKeyWatchdog();
    }

    if (!active_) {
        return;
    }
    if (terminal_pending_) {
        if (hid_.neutral_mask() == (hid::kKeyboardNeutral | hid::kMouseNeutral)) {
            FinishTerminal();
        }
        return;
    }
    if (phase_ == Phase::kAwaitMouseMove && logical_token != 0) {
        const auto parts = input_chunk_.actions[action_index_].movement_parts;
        if (movement_part_index_ >= parts) {
            ++action_index_;
            movement_part_index_ = 0;
        } else {
            ++movement_part_index_;
        }
        phase_ = Phase::kReady;
    } else if (phase_ == Phase::kAwaitMouseClickPress && report.buttons != 0 &&
               logical_token == 0) {
        phase_ = Phase::kMouseClickHold;
        wait_deadline_ms_ =
            AddDeadline(now_ms, input_chunk_.actions[action_index_].first_ms);
    } else if (phase_ == Phase::kAwaitMouseClickRelease && hid::is_zero(report) &&
               logical_token == 0) {
        phase_ = Phase::kMouseClickGap;
        wait_deadline_ms_ =
            AddDeadline(now_ms, input_chunk_.actions[action_index_].second_ms);
    } else {
        FailActive(started_);
        return;
    }
    DriveInput(now_ms);
}

void CommandExecutor::UsbFault() {
    CancelHeldKeyWatchdog();
    if (active_) {
        if (input_active_) {
            input_replay_.Close(command_id_);
            EmitInput(protocol::ResultCode::kUnknown, protocol::ErrorCode::kUsbUnavailable);
        } else {
            Emit(command_id_, command_sequence_,
                 started_ ? protocol::ResultCode::kUnknown : protocol::ResultCode::kAborted);
        }
    }
    active_ = false;
    started_ = false;
    terminal_pending_ = false;
    input_active_ = false;
    late_input_cancel_pending_ = false;
    late_input_cancel_sequence_ = 0;
    input_effect_flags_ = 0;
    phase_ = Phase::kIdle;
    command_arm_available_ = false;
    hid_.fault();
}

void CommandExecutor::HeldKeyDeadlineFired(const std::uint64_t token,
                                           const std::uint64_t now_ms) {
    if (!held_key_watchdog_armed_ || token == 0 || token != watchdog_token_) {
        return;
    }
    if (now_ms < held_key_deadline_ms_) {
        if (!watchdog_.Schedule(token, held_key_deadline_ms_)) {
            WatchdogFailure();
        }
        return;
    }
    held_key_watchdog_armed_ = false;
    hid_.watchdog_release();
    command_arm_available_ = false;
    if (active_) {
        terminal_pending_ = true;
        terminal_result_ = input_active_ ? protocol::ResultCode::kAborted
                                         : (started_ ? protocol::ResultCode::kUnknown
                                                     : protocol::ResultCode::kAborted);
        terminal_reason_ =
            input_active_ ? protocol::ErrorCode::kWatchdog : kNoInputError;
        phase_ = Phase::kTerminalRelease;
    }
}

bool CommandExecutor::active() const noexcept {
    return active_;
}

std::uint64_t CommandExecutor::epoch() const noexcept {
    return epoch_;
}

std::uint32_t CommandExecutor::expected_sequence() const noexcept {
    return expected_sequence_;
}

bool CommandExecutor::ParseEnvelope(const protocol::DecodedFrame& frame,
                                    std::array<std::uint8_t, 16>* command_id,
                                    std::uint32_t* valid_for_ms, std::uint8_t* kind,
                                    const std::uint8_t** body,
                                    std::size_t* body_length) const {
    if (frame.payload == nullptr || frame.payload_length < kCommandEnvelopeLength) {
        return false;
    }
    std::copy_n(frame.payload, command_id->size(), command_id->begin());
    *valid_for_ms = ReadU32(frame.payload + 16);
    if (*valid_for_ms == 0 || *valid_for_ms > kMaximumValidForMs ||
        !std::equal(accepted_profile_hash_.begin(), accepted_profile_hash_.end(),
                    frame.payload + 20)) {
        return false;
    }
    *kind = frame.payload[52];
    *body_length = ReadU16(frame.payload + 53);
    if (*body_length != frame.payload_length - kCommandEnvelopeLength) {
        return false;
    }
    *body = frame.payload + kCommandEnvelopeLength;
    return true;
}

bool CommandExecutor::ParseActions(const std::uint8_t* body, const std::size_t length) {
    if (body == nullptr || length == 0) {
        return false;
    }
    std::array<Action, kMaximumActions> parsed{};
    std::size_t count = 0;
    std::size_t offset = 0;
    std::uint32_t duration_ms = 0;
    ActionKind last_report_kind = ActionKind::kReport;
    bool saw_report = false;
    while (offset < length) {
        if (length - offset < 2 || count == parsed.size()) {
            return false;
        }
        const auto tag = body[offset];
        const auto field_length = static_cast<std::size_t>(body[offset + 1]);
        offset += 2;
        if (field_length > length - offset) {
            return false;
        }
        auto& action = parsed[count];
        if (tag == static_cast<std::uint8_t>(protocol::ReportAction::kKeyReport) &&
            field_length == sizeof(hid::BootKeyboardReport)) {
            action.kind = ActionKind::kReport;
            std::memcpy(&action.report, body + offset, sizeof(action.report));
            if (!hid::is_valid(action.report)) {
                return false;
            }
            last_report_kind = hid::is_zero(action.report) ? ActionKind::kRelease
                                                           : ActionKind::kReport;
            saw_report = true;
        } else if (tag == static_cast<std::uint8_t>(protocol::ReportAction::kWaitMs) &&
                   field_length == 2) {
            action.kind = ActionKind::kWait;
            action.first_ms = ReadU16(body + offset);
            if (action.first_ms == 0 || action.first_ms > kMaximumActionDelayMs) {
                return false;
            }
            duration_ms += action.first_ms;
        } else if (tag ==
                       static_cast<std::uint8_t>(protocol::ReportAction::kReleaseAllAction) &&
                   field_length == 0) {
            action.kind = ActionKind::kRelease;
            last_report_kind = ActionKind::kRelease;
            saw_report = true;
        } else if (tag == static_cast<std::uint8_t>(protocol::ReportAction::kTapKey) &&
                   field_length == 6) {
            action.kind = ActionKind::kTap;
            action.report.modifiers = body[offset];
            action.report.usages[0] = body[offset + 1];
            action.first_ms = ReadU16(body + offset + 2);
            action.second_ms = ReadU16(body + offset + 4);
            if (action.report.usages[0] == 0 ||
                action.first_ms < kMinimumTapDurationMs ||
                action.first_ms > kMaximumActionDelayMs ||
                action.second_ms < kMinimumTapDurationMs ||
                action.second_ms > kMaximumActionDelayMs) {
                return false;
            }
            duration_ms += action.first_ms + action.second_ms;
            last_report_kind = ActionKind::kRelease;
            saw_report = true;
        } else {
            return false;
        }
        if (duration_ms > kMaximumChunkDurationMs) {
            return false;
        }
        offset += field_length;
        ++count;
    }
    // A trailing release-gap wait is valid; the last report-producing action must release.
    if (count == 0 || !saw_report || last_report_kind != ActionKind::kRelease) {
        return false;
    }
    actions_ = parsed;
    action_count_ = count;
    return true;
}

void CommandExecutor::Drive(const std::uint64_t now_ms) {
    while (active_ && !terminal_pending_ && phase_ == Phase::kReady) {
        if (now_ms >= expiry_ms_) {
            BeginTerminal(protocol::ResultCode::kAborted);
            return;
        }
        if (action_index_ == action_count_) {
            BeginTerminal(protocol::ResultCode::kEmitted);
            return;
        }
        const auto& action = actions_[action_index_];
        if (action.kind == ActionKind::kWait) {
            wait_deadline_ms_ = AddDeadline(now_ms, action.first_ms);
            phase_ = Phase::kWait;
            return;
        }
        const hid::BootKeyboardReport report =
            action.kind == ActionKind::kTap ? action.report
            : action.kind == ActionKind::kRelease ? hid::BootKeyboardReport{}
                                                  : action.report;
        const auto result = hid_.submit(epoch_, report);
        if (result != hid::SubmitResult::accepted) {
            FailActive(started_);
            return;
        }
        phase_ = action.kind == ActionKind::kTap ? Phase::kAwaitTapPress
                                                : Phase::kAwaitActionReport;
    }
}

void CommandExecutor::DriveInput(const std::uint64_t now_ms) {
    while (active_ && input_active_ && !terminal_pending_ && phase_ == Phase::kReady) {
        if (now_ms >= expiry_ms_) {
            BeginTerminal(protocol::ResultCode::kAborted, protocol::ErrorCode::kExpired);
            return;
        }
        if (action_index_ == input_chunk_.action_count) {
            BeginTerminal(protocol::ResultCode::kUnknown,
                          protocol::ErrorCode::kNeutralUnconfirmed);
            return;
        }
        const auto& action = input_chunk_.actions[action_index_];
        switch (action.kind) {
            case InputActionKind::kWait:
                wait_deadline_ms_ = AddDeadline(now_ms, action.first_ms);
                phase_ = Phase::kWait;
                return;
            case InputActionKind::kKeyboardReport:
            case InputActionKind::kKeyboardRelease: {
                const auto report = action.kind == InputActionKind::kKeyboardRelease
                                        ? hid::BootKeyboardReport{}
                                        : action.keyboard;
                if (hid_.submit(epoch_, report) != hid::SubmitResult::accepted) {
                    FailActive(started_);
                    return;
                }
                phase_ = Phase::kAwaitActionReport;
                return;
            }
            case InputActionKind::kTap:
                if (hid_.submit(epoch_, action.keyboard) != hid::SubmitResult::accepted) {
                    FailActive(started_);
                    return;
                }
                phase_ = Phase::kAwaitTapPress;
                return;
            case InputActionKind::kMouseMove: {
                if (movement_part_index_ == 0) {
                    movement_part_index_ = 1;
                }
                hid::BootMouseReport report{};
                report.x = RelativeMovementAxisPart(action.dx_counts, movement_part_index_,
                                                    action.movement_parts);
                report.y = RelativeMovementAxisPart(action.dy_counts, movement_part_index_,
                                                    action.movement_parts);
                ++movement_token_;
                if (movement_token_ == 0 ||
                    hid_.submit_mouse_movement(epoch_, movement_token_, report) !=
                        hid::SubmitResult::accepted) {
                    FailActive(started_);
                    return;
                }
                phase_ = Phase::kAwaitMouseMove;
                return;
            }
            case InputActionKind::kMouseClick: {
                const hid::BootMouseReport report{
                    static_cast<std::uint8_t>(1U << (action.button - 1U)), 0, 0};
                if (hid_.submit_mouse_buttons(epoch_, report) != hid::SubmitResult::accepted) {
                    FailActive(started_);
                    return;
                }
                phase_ = Phase::kAwaitMouseClickPress;
                return;
            }
            case InputActionKind::kNeutralAll:
                BeginTerminal(protocol::ResultCode::kEmitted, kNoInputError);
                return;
        }
    }
}

void CommandExecutor::BeginTerminal(const protocol::ResultCode result,
                                    const protocol::ErrorCode reason) {
    if (!active_ || terminal_pending_) {
        return;
    }
    terminal_pending_ = true;
    terminal_result_ = result;
    terminal_reason_ = reason;
    phase_ = Phase::kTerminalRelease;
    command_arm_available_ = false;
    if (input_active_) {
        hid_.request_dual_neutral();
    } else {
        hid_.disarm();
    }
}

void CommandExecutor::FinishTerminal() {
    if (!active_ || !terminal_pending_) {
        return;
    }
    const auto result = terminal_result_;
    const auto reason = terminal_reason_;
    const auto command_id = command_id_;
    const auto sequence = command_sequence_;
    const bool input = input_active_;
    const bool reject_late_input_cancel = input && late_input_cancel_pending_;
    const auto late_input_cancel_sequence = late_input_cancel_sequence_;
    if (input) {
        if (input_chunk_.count != 0 &&
            (result != protocol::ResultCode::kEmitted ||
             input_chunk_.index + 1U == input_chunk_.count)) {
            input_replay_.Close(command_id_);
        }
        EmitInput(result, reason);
        if (reject_late_input_cancel) {
            RejectInput(command_id, late_input_cancel_sequence,
                        protocol::ErrorCode::kInvalidMode, false);
        }
    }
    active_ = false;
    started_ = false;
    terminal_pending_ = false;
    input_active_ = false;
    late_input_cancel_pending_ = false;
    late_input_cancel_sequence_ = 0;
    phase_ = Phase::kIdle;
    action_count_ = 0;
    action_index_ = 0;
    input_chunk_ = {};
    movement_part_index_ = 0;
    input_effect_flags_ = 0;
    terminal_reason_ = kNoInputError;
    if (!input) {
        Emit(command_id, sequence, result);
    }
}

void CommandExecutor::FailActive(const bool uncertain) {
    if (!active_) {
        hid_.fault();
        return;
    }
    BeginTerminal(uncertain ? protocol::ResultCode::kUnknown
                            : protocol::ResultCode::kAborted,
                  input_active_ ? protocol::ErrorCode::kInternal : kNoInputError);
}

void CommandExecutor::Emit(const std::array<std::uint8_t, 16>& command_id,
                           const std::uint32_t sequence,
                           const protocol::ResultCode result) {
    results_.CommandResult(sequence, command_id, result);
}

void CommandExecutor::EmitInput(const protocol::ResultCode result,
                                const protocol::ErrorCode reason) {
    InputResultEvidence evidence{};
    evidence.command_id = command_id_;
    evidence.result = result;
    evidence.neutral_mask =
        result == protocol::ResultCode::kAccepted || result == protocol::ResultCode::kStarted
            ? 0
            : hid_.neutral_mask();
    evidence.effect_flags = input_effect_flags_;
    evidence.reason = reason;
    results_.InputCommandResult(command_sequence_, evidence);
}

void CommandExecutor::RejectInput(const std::array<std::uint8_t, 16>& command_id,
                                  const std::uint32_t sequence,
                                  const protocol::ErrorCode reason,
                                  const bool clear_arm) {
    if (clear_arm) {
        command_arm_available_ = false;
        hid_.disarm();
    }
    InputResultEvidence evidence{};
    evidence.command_id = command_id;
    evidence.result = protocol::ResultCode::kRejected;
    evidence.reason = reason;
    results_.InputCommandResult(sequence, evidence);
}

void CommandExecutor::ArmHeldKeyWatchdog(const std::uint64_t now_ms) {
    if (held_key_watchdog_armed_) {
        return;
    }
    ++watchdog_token_;
    if (watchdog_token_ == 0) {
        ++watchdog_token_;
    }
    held_key_deadline_ms_ = AddDeadline(now_ms, kHeldKeyMaximumMs);
    held_key_watchdog_armed_ = true;
    if (!watchdog_.Schedule(watchdog_token_, held_key_deadline_ms_)) {
        WatchdogFailure();
    }
}

void CommandExecutor::CancelHeldKeyWatchdog() {
    if (!held_key_watchdog_armed_) {
        return;
    }
    watchdog_.Cancel(watchdog_token_);
    held_key_watchdog_armed_ = false;
}

void CommandExecutor::WatchdogFailure() {
    held_key_watchdog_armed_ = false;
    hid_.watchdog_release();
    command_arm_available_ = false;
    if (active_) {
        terminal_pending_ = true;
        terminal_result_ = input_active_ ? protocol::ResultCode::kAborted
                                         : (started_ ? protocol::ResultCode::kUnknown
                                                     : protocol::ResultCode::kAborted);
        terminal_reason_ =
            input_active_ ? protocol::ErrorCode::kWatchdog : kNoInputError;
        phase_ = Phase::kTerminalRelease;
    }
}

}  // namespace keyferry::command
