#include "keyferry/input_command.h"

#include <algorithm>
#include <cstring>

namespace keyferry::command {
namespace {

constexpr std::uint32_t kTransferMs = 10;
constexpr std::uint32_t kDualNeutralMs = 20;

std::uint16_t ReadU16(const std::uint8_t* input) noexcept {
    return static_cast<std::uint16_t>(input[0]) |
           (static_cast<std::uint16_t>(input[1]) << 8U);
}

std::int16_t ReadI16(const std::uint8_t* input) noexcept {
    return static_cast<std::int16_t>(ReadU16(input));
}

bool IsZeroId(const std::array<std::uint8_t, 16>& value) noexcept {
    return std::all_of(value.begin(), value.end(),
                       [](const std::uint8_t byte) { return byte == 0; });
}

bool AddDuration(std::uint32_t amount, std::uint32_t* total) noexcept {
    if (amount > kMaximumInputChunkDurationMs - *total) {
        return false;
    }
    *total += amount;
    return true;
}

bool IsKnownReason(const protocol::ErrorCode reason) noexcept {
    switch (reason) {
        case protocol::ErrorCode::kMalformed:
        case protocol::ErrorCode::kUnsupportedVersion:
        case protocol::ErrorCode::kUnknownCriticalField:
        case protocol::ErrorCode::kNotAuthenticated:
        case protocol::ErrorCode::kNotArmed:
        case protocol::ErrorCode::kExpired:
        case protocol::ErrorCode::kDuplicate:
        case protocol::ErrorCode::kBusy:
        case protocol::ErrorCode::kInvalidMode:
        case protocol::ErrorCode::kUsbUnavailable:
        case protocol::ErrorCode::kLegacyUartFaultReserved:
        case protocol::ErrorCode::kCapabilityRequired:
        case protocol::ErrorCode::kLimitExceeded:
        case protocol::ErrorCode::kNeutralUnconfirmed:
        case protocol::ErrorCode::kReplayWindowFull:
        case protocol::ErrorCode::kCancelled:
        case protocol::ErrorCode::kWatchdog:
        case protocol::ErrorCode::kInternal:
            return true;
    }
    return static_cast<std::uint16_t>(reason) == 0;
}

bool ValidEvidence(const InputResultEvidence& evidence) noexcept {
    if (IsZeroId(evidence.command_id) || (evidence.neutral_mask & ~0x03U) != 0 ||
        (evidence.effect_flags & ~kInputEffectOccurred) != 0 || !IsKnownReason(evidence.reason)) {
        return false;
    }
    const bool effect = (evidence.effect_flags & kInputEffectOccurred) != 0;
    const bool dual_neutral = evidence.neutral_mask == 0x03;
    const bool reason_ok = static_cast<std::uint16_t>(evidence.reason) != 0;
    switch (evidence.result) {
        case protocol::ResultCode::kAccepted:
            return !effect && evidence.neutral_mask == 0 && !reason_ok;
        case protocol::ResultCode::kStarted:
            return effect && evidence.neutral_mask == 0 && !reason_ok;
        case protocol::ResultCode::kEmitted:
            return dual_neutral && !reason_ok;
        case protocol::ResultCode::kAborted:
            return dual_neutral && reason_ok;
        case protocol::ResultCode::kRejected:
            return !effect && reason_ok;
        case protocol::ResultCode::kUnknown:
            return !dual_neutral && reason_ok;
        case protocol::ResultCode::kQueued:
            return false;
    }
    return false;
}

}  // namespace

std::uint16_t RelativeMovementPartCount(const std::int16_t dx,
                                        const std::int16_t dy) noexcept {
    const std::int32_t x = dx;
    const std::int32_t y = dy;
    const std::int32_t maximum = std::max(x < 0 ? -x : x, y < 0 ? -y : y);
    return maximum == 0 ? 0 : static_cast<std::uint16_t>((maximum + 126) / 127);
}

std::int8_t RelativeMovementAxisPart(const std::int16_t value, const std::uint16_t index,
                                     const std::uint16_t count) noexcept {
    if (count == 0 || index == 0 || index > count) {
        return 0;
    }
    const std::int32_t signed_value = value;
    const std::int32_t magnitude = signed_value < 0 ? -signed_value : signed_value;
    const std::int32_t current = static_cast<std::int32_t>(index) * magnitude / count;
    const std::int32_t previous = static_cast<std::int32_t>(index - 1) * magnitude / count;
    const std::int32_t part = (current - previous) * (signed_value < 0 ? -1 : 1);
    return static_cast<std::int8_t>(part);
}

bool ParseInputChunk(const std::uint8_t* body, const std::size_t length,
                     ParsedInputChunk* output) noexcept {
    if (body == nullptr || output == nullptr || length < 6 || length > 4 + kMaximumInputActionBytes) {
        return false;
    }
    ParsedInputChunk parsed{};
    parsed.index = ReadU16(body);
    parsed.count = ReadU16(body + 2);
    if (parsed.count == 0 || parsed.count > kMaximumInputChunks || parsed.index >= parsed.count) {
        return false;
    }

    std::size_t offset = 4;
    while (offset < length) {
        if (length - offset < 2 || parsed.action_count == parsed.actions.size()) {
            return false;
        }
        const auto tag = body[offset];
        const auto field_length = static_cast<std::size_t>(body[offset + 1]);
        offset += 2;
        if (field_length > length - offset) {
            return false;
        }
        auto& action = parsed.actions[parsed.action_count];
        if (tag == static_cast<std::uint8_t>(protocol::ReportAction::kKeyReport) &&
            field_length == sizeof(hid::BootKeyboardReport)) {
            action.kind = InputActionKind::kKeyboardReport;
            std::memcpy(&action.keyboard, body + offset, sizeof(action.keyboard));
            if (!hid::is_valid(action.keyboard) || !AddDuration(kTransferMs, &parsed.duration_ms)) {
                return false;
            }
            parsed.effectful |= !hid::is_zero(action.keyboard);
        } else if (tag == static_cast<std::uint8_t>(protocol::ReportAction::kWaitMs) &&
                   field_length == 2) {
            action.kind = InputActionKind::kWait;
            action.first_ms = ReadU16(body + offset);
            if (action.first_ms == 0 || action.first_ms > 100 ||
                !AddDuration(action.first_ms, &parsed.duration_ms)) {
                return false;
            }
        } else if (tag ==
                       static_cast<std::uint8_t>(protocol::ReportAction::kReleaseAllAction) &&
                   field_length == 0) {
            action.kind = InputActionKind::kKeyboardRelease;
            if (!AddDuration(kTransferMs, &parsed.duration_ms)) {
                return false;
            }
        } else if (tag == static_cast<std::uint8_t>(protocol::ReportAction::kTapKey) &&
                   field_length == 6) {
            action.kind = InputActionKind::kTap;
            action.keyboard.modifiers = body[offset];
            action.keyboard.usages[0] = body[offset + 1];
            action.first_ms = ReadU16(body + offset + 2);
            action.second_ms = ReadU16(body + offset + 4);
            if (action.keyboard.usages[0] == 0 || action.first_ms < 5 || action.first_ms > 100 ||
                action.second_ms < 5 || action.second_ms > 100 ||
                !AddDuration(2 * kTransferMs + action.first_ms + action.second_ms,
                             &parsed.duration_ms)) {
                return false;
            }
            parsed.effectful = true;
        } else if (tag ==
                       static_cast<std::uint8_t>(protocol::ReportAction::kMouseMoveRelative) &&
                   field_length == 4) {
            action.kind = InputActionKind::kMouseMove;
            action.dx_counts = ReadI16(body + offset);
            action.dy_counts = ReadI16(body + offset + 2);
            if (action.dx_counts < -4096 || action.dx_counts > 4096 ||
                action.dy_counts < -4096 || action.dy_counts > 4096) {
                return false;
            }
            action.movement_parts =
                RelativeMovementPartCount(action.dx_counts, action.dy_counts);
            if (action.movement_parts == 0 ||
                !AddDuration(kTransferMs * action.movement_parts, &parsed.duration_ms)) {
                return false;
            }
            parsed.effectful = true;
        } else if (tag == static_cast<std::uint8_t>(protocol::ReportAction::kMouseClick) &&
                   field_length == 5) {
            action.kind = InputActionKind::kMouseClick;
            action.button = body[offset];
            action.first_ms = ReadU16(body + offset + 1);
            action.second_ms = ReadU16(body + offset + 3);
            if ((action.button != 1 && action.button != 2) || action.first_ms < 10 ||
                action.first_ms > 100 || action.second_ms < 10 || action.second_ms > 100 ||
                !AddDuration(2 * kTransferMs + action.first_ms + action.second_ms,
                             &parsed.duration_ms)) {
                return false;
            }
            parsed.effectful = true;
        } else if (tag == static_cast<std::uint8_t>(protocol::ReportAction::kNeutralAll) &&
                   field_length == 0 && offset == length) {
            action.kind = InputActionKind::kNeutralAll;
            if (!AddDuration(kDualNeutralMs, &parsed.duration_ms)) {
                return false;
            }
        } else {
            return false;
        }
        offset += field_length;
        ++parsed.action_count;
    }
    if (parsed.action_count == 0 ||
        parsed.actions[parsed.action_count - 1].kind != InputActionKind::kNeutralAll) {
        return false;
    }
    *output = parsed;
    return true;
}

void InputReplayWindow::Reset() noexcept {
    entries_.fill({});
    size_ = 0;
}

InputReplayDecision InputReplayWindow::Admit(
    const std::array<std::uint8_t, 16>& command_id, const std::uint16_t chunk_index,
    const std::uint16_t chunk_count) noexcept {
    if (IsZeroId(command_id) || chunk_count == 0 || chunk_count > kMaximumInputChunks ||
        chunk_index >= chunk_count) {
        return InputReplayDecision::kInvalid;
    }
    for (auto& entry : entries_) {
        if (!entry.occupied || entry.command_id != command_id) {
            continue;
        }
        if (entry.chunk_count != chunk_count) {
            return InputReplayDecision::kConflict;
        }
        if (entry.closed) {
            return InputReplayDecision::kDuplicate;
        }
        if (chunk_index < entry.next_chunk) {
            return InputReplayDecision::kDuplicate;
        }
        if (chunk_index > entry.next_chunk) {
            return InputReplayDecision::kOutOfOrder;
        }
        ++entry.next_chunk;
        return InputReplayDecision::kAccepted;
    }
    if (chunk_index != 0) {
        return InputReplayDecision::kOutOfOrder;
    }
    if (size_ == entries_.size()) {
        return InputReplayDecision::kWindowFull;
    }
    auto& entry = entries_[size_++];
    entry.command_id = command_id;
    entry.chunk_count = chunk_count;
    entry.next_chunk = 1;
    entry.occupied = true;
    return InputReplayDecision::kAccepted;
}

bool InputReplayWindow::Close(
    const std::array<std::uint8_t, 16>& command_id) noexcept {
    for (auto& entry : entries_) {
        if (entry.occupied && entry.command_id == command_id) {
            entry.closed = true;
            return true;
        }
    }
    return false;
}

std::size_t InputReplayWindow::size() const noexcept {
    return size_;
}

bool EncodeInputResultPayload(const InputResultEvidence& evidence,
                              std::array<std::uint8_t, 21>* output) noexcept {
    if (output == nullptr || !ValidEvidence(evidence)) {
        return false;
    }
    output->fill(0);
    std::copy(evidence.command_id.begin(), evidence.command_id.end(), output->begin());
    (*output)[16] = static_cast<std::uint8_t>(evidence.result);
    (*output)[17] = evidence.neutral_mask;
    (*output)[18] = evidence.effect_flags;
    const auto reason = static_cast<std::uint16_t>(evidence.reason);
    (*output)[19] = static_cast<std::uint8_t>(reason);
    (*output)[20] = static_cast<std::uint8_t>(reason >> 8U);
    return true;
}

}  // namespace keyferry::command
