#include "keyferry/input_command.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

using keyferry::command::InputActionKind;
using keyferry::command::InputReplayDecision;
using keyferry::command::InputReplayWindow;
using keyferry::command::InputResultEvidence;
using keyferry::command::ParsedInputChunk;

namespace {

std::array<std::uint8_t, 16> Id(const std::uint8_t value) {
    std::array<std::uint8_t, 16> id{};
    id[0] = value;
    return id;
}

void Parses_the_canonical_cross_language_body() {
    const std::array<std::uint8_t, 27> body = {
        0x00, 0x00, 0x01, 0x00, 0x05, 0x04, 0xF0, 0x00, 0xD8,
        0xFF, 0x06, 0x05, 0x01, 0x28, 0x00, 0x28, 0x00, 0x04,
        0x06, 0x00, 0x28, 0x0C, 0x00, 0x08, 0x00, 0x07, 0x00,
    };
    ParsedInputChunk parsed{};
    assert(keyferry::command::ParseInputChunk(body.data(), body.size(), &parsed));
    assert(parsed.index == 0);
    assert(parsed.count == 1);
    assert(parsed.action_count == 4);
    assert(parsed.duration_ms == 180);
    assert(parsed.effectful);
    assert(parsed.actions[0].kind == InputActionKind::kMouseMove);
    assert(parsed.actions[0].dx_counts == 240);
    assert(parsed.actions[0].dy_counts == -40);
    assert(parsed.actions[0].movement_parts == 2);
    assert(keyferry::command::RelativeMovementAxisPart(240, 1, 2) == 120);
    assert(keyferry::command::RelativeMovementAxisPart(-40, 1, 2) == -20);
    assert(keyferry::command::RelativeMovementAxisPart(240, 2, 2) == 120);
    assert(keyferry::command::RelativeMovementAxisPart(-40, 2, 2) == -20);
    assert(parsed.actions[1].kind == InputActionKind::kMouseClick);
    assert(parsed.actions[1].button == 1);
    assert(parsed.actions[1].first_ms == 40);
    assert(parsed.actions[1].second_ms == 40);
    assert(parsed.actions[2].kind == InputActionKind::kTap);
    assert(parsed.actions[2].keyboard.usages[0] == 0x28);
    assert(parsed.actions[3].kind == InputActionKind::kNeutralAll);
}

void Movement_splitting_is_exact_and_never_emits_negative_128() {
    constexpr std::array<std::int16_t, 8> values{
        -4096, -128, -127, -1, 1, 127, 128, 4096,
    };
    for (const std::int16_t value : values) {
        const auto count = keyferry::command::RelativeMovementPartCount(value, -value);
        std::int32_t x = 0;
        std::int32_t y = 0;
        for (std::uint16_t index = 1; index <= count; ++index) {
            const auto x_part = keyferry::command::RelativeMovementAxisPart(value, index, count);
            const auto y_part = keyferry::command::RelativeMovementAxisPart(-value, index, count);
            assert(x_part >= -127 && x_part <= 127);
            assert(y_part >= -127 && y_part <= 127);
            x += x_part;
            y += y_part;
        }
        assert(x == value);
        assert(y == -value);
    }
}

void Parser_rejects_malformed_deferred_and_over_budget_chunks() {
    ParsedInputChunk parsed{};
    const std::array<std::uint8_t, 12> zero_move = {
        0, 0, 1, 0, 5, 4, 0, 0, 0, 0, 7, 0,
    };
    assert(!keyferry::command::ParseInputChunk(zero_move.data(), zero_move.size(), &parsed));

    const std::array<std::uint8_t, 8> missing_neutral = {0, 0, 1, 0, 1, 2, 1, 0};
    assert(!keyferry::command::ParseInputChunk(missing_neutral.data(),
                                               missing_neutral.size(), &parsed));

    const std::array<std::uint8_t, 8> unknown = {0, 0, 1, 0, 0x7F, 0, 7, 0};
    assert(!keyferry::command::ParseInputChunk(unknown.data(), unknown.size(), &parsed));

    std::vector<std::uint8_t> too_long = {0, 0, 1, 0};
    for (int index = 0; index < 5; ++index) {
        too_long.insert(too_long.end(), {6, 5, 1, 100, 0, 100, 0});
    }
    too_long.insert(too_long.end(), {7, 0});
    assert(!keyferry::command::ParseInputChunk(too_long.data(), too_long.size(), &parsed));
}

void Replay_window_is_non_evicting_and_orders_chunks() {
    InputReplayWindow window;
    assert(window.Admit(Id(1), 0, 3) == InputReplayDecision::kAccepted);
    assert(window.Admit(Id(1), 0, 3) == InputReplayDecision::kDuplicate);
    assert(window.Admit(Id(1), 1, 2) == InputReplayDecision::kConflict);
    assert(window.Admit(Id(1), 1, 3) == InputReplayDecision::kAccepted);
    assert(window.Close(Id(1)));
    assert(window.Admit(Id(1), 2, 3) == InputReplayDecision::kDuplicate);
    assert(!window.Close(Id(99)));
    assert(window.Admit(Id(2), 1, 2) == InputReplayDecision::kOutOfOrder);
    for (std::uint8_t value = 2; value <= 64; ++value) {
        assert(window.Admit(Id(value), 0, 1) == InputReplayDecision::kAccepted);
    }
    assert(window.size() == 64);
    assert(window.Admit(Id(65), 0, 1) == InputReplayDecision::kWindowFull);
    window.Reset();
    assert(window.size() == 0);
}

void Encodes_the_exact_evidence_result_vector_and_rejects_dishonest_results() {
    InputResultEvidence emitted{};
    emitted.command_id = {0x01, 0x99, 0x5F, 0xA0, 0x00, 0x00, 0x70, 0x00,
                          0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    emitted.result = keyferry::protocol::ResultCode::kEmitted;
    emitted.neutral_mask = keyferry::hid::kKeyboardNeutral | keyferry::hid::kMouseNeutral;
    emitted.effect_flags = keyferry::command::kInputEffectOccurred;
    emitted.reason = keyferry::command::kNoInputError;
    std::array<std::uint8_t, 21> payload{};
    assert(keyferry::command::EncodeInputResultPayload(emitted, &payload));
    const std::array<std::uint8_t, 21> expected = {
        0x01, 0x99, 0x5F, 0xA0, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x03, 0x01, 0x00, 0x00,
    };
    assert(payload == expected);

    auto dishonest = emitted;
    dishonest.neutral_mask = keyferry::hid::kKeyboardNeutral;
    assert(!keyferry::command::EncodeInputResultPayload(dishonest, &payload));
    dishonest = emitted;
    dishonest.result = keyferry::protocol::ResultCode::kRejected;
    assert(!keyferry::command::EncodeInputResultPayload(dishonest, &payload));

    auto release_only = emitted;
    release_only.effect_flags = 0;
    assert(keyferry::command::EncodeInputResultPayload(release_only, &payload));
}

}  // namespace

int main() {
    Parses_the_canonical_cross_language_body();
    Movement_splitting_is_exact_and_never_emits_negative_128();
    Parser_rejects_malformed_deferred_and_over_budget_chunks();
    Replay_window_is_non_evicting_and_orders_chunks();
    Encodes_the_exact_evidence_result_vector_and_rejects_dishonest_results();
    std::cout << "input_command_test: ok\n";
    return 0;
}
