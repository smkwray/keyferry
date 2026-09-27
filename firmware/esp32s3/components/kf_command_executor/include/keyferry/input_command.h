#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry/hid_executor.h"
#include "keyferry_protocol_generated.h"

namespace keyferry::command {

constexpr std::size_t kMaximumInputActions = 64;
constexpr std::size_t kMaximumInputActionBytes = 183;
constexpr std::uint16_t kMaximumInputChunks = 256;
constexpr std::uint32_t kMaximumInputChunkDurationMs = 500;
constexpr std::uint8_t kInputEffectOccurred = 0x01;
constexpr protocol::ErrorCode kNoInputError = static_cast<protocol::ErrorCode>(0);

enum class InputActionKind : std::uint8_t {
    kKeyboardReport,
    kWait,
    kKeyboardRelease,
    kTap,
    kMouseMove,
    kMouseClick,
    kNeutralAll,
};

struct InputActionRecord {
    InputActionKind kind{};
    hid::BootKeyboardReport keyboard{};
    std::int16_t dx_counts{};
    std::int16_t dy_counts{};
    std::uint16_t movement_parts{};
    std::uint16_t first_ms{};
    std::uint16_t second_ms{};
    std::uint8_t button{};
};

struct ParsedInputChunk {
    std::uint16_t index{};
    std::uint16_t count{};
    std::array<InputActionRecord, kMaximumInputActions> actions{};
    std::size_t action_count{};
    std::uint32_t duration_ms{};
    bool effectful{};
};

bool ParseInputChunk(const std::uint8_t* body, std::size_t length,
                     ParsedInputChunk* output) noexcept;
std::uint16_t RelativeMovementPartCount(std::int16_t dx, std::int16_t dy) noexcept;
std::int8_t RelativeMovementAxisPart(std::int16_t value, std::uint16_t index,
                                     std::uint16_t count) noexcept;

enum class InputReplayDecision : std::uint8_t {
    kAccepted,
    kDuplicate,
    kConflict,
    kOutOfOrder,
    kWindowFull,
    kInvalid,
};

class InputReplayWindow final {
  public:
    void Reset() noexcept;
    InputReplayDecision Admit(const std::array<std::uint8_t, 16>& command_id,
                              std::uint16_t chunk_index,
                              std::uint16_t chunk_count) noexcept;
    bool Close(const std::array<std::uint8_t, 16>& command_id) noexcept;
    [[nodiscard]] std::size_t size() const noexcept;

  private:
    struct Entry {
        std::array<std::uint8_t, 16> command_id{};
        std::uint16_t chunk_count{};
        std::uint16_t next_chunk{};
        bool occupied{};
        bool closed{};
    };
    std::array<Entry, 64> entries_{};
    std::size_t size_{};
};

struct InputResultEvidence {
    std::array<std::uint8_t, 16> command_id{};
    protocol::ResultCode result{protocol::ResultCode::kRejected};
    std::uint8_t neutral_mask{};
    std::uint8_t effect_flags{};
    protocol::ErrorCode reason{protocol::ErrorCode::kInternal};
};

bool EncodeInputResultPayload(const InputResultEvidence& evidence,
                              std::array<std::uint8_t, 21>* output) noexcept;

}  // namespace keyferry::command
