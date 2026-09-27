#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "frame_codec.h"
#include "keyferry/hid_executor.h"
#include "keyferry/input_command.h"
#include "keyferry_protocol_generated.h"

namespace keyferry::command {

constexpr std::uint32_t kMaximumValidForMs = 5000;
constexpr std::uint32_t kMaximumActionDelayMs = 100;
constexpr std::uint32_t kMaximumChunkDurationMs = 500;
constexpr std::uint32_t kMinimumTapDurationMs = 5;
constexpr std::uint64_t kHeldKeyMaximumMs = 2000;
constexpr std::size_t kMaximumActions = 64;

class ResultSink {
  public:
    virtual ~ResultSink() = default;
    virtual void CommandResult(std::uint32_t sequence,
                               const std::array<std::uint8_t, 16>& command_id,
                               protocol::ResultCode result) = 0;
    virtual void InputCommandResult(std::uint32_t sequence,
                                    const InputResultEvidence& evidence) = 0;
};

class HeldKeyDeadlineScheduler {
  public:
    virtual ~HeldKeyDeadlineScheduler() = default;
    virtual bool Schedule(std::uint64_t token, std::uint64_t monotonic_deadline_ms) = 0;
    virtual void Cancel(std::uint64_t token) = 0;
};

class CommandExecutor final {
  public:
    CommandExecutor(hid::ExecutorState& hid, ResultSink& results,
                    HeldKeyDeadlineScheduler& watchdog,
                    const std::array<std::uint8_t, 32>& accepted_profile_hash);

    void BeginSession(std::uint64_t epoch, std::uint32_t first_sequence,
                      bool input_v1_enabled = false);
    void EndSession();
    bool CommandScopedArm(std::uint64_t epoch, std::uint32_t command_sequence);

    // The caller supplies one authenticated COMMAND frame and a monotonic millisecond timestamp.
    bool HandleAuthenticated(std::uint64_t epoch, const protocol::DecodedFrame& frame,
                             std::uint64_t now_ms);
    void Poll(std::uint64_t now_ms);
    void UsbReportAccepted(const hid::BootKeyboardReport& report, std::uint64_t now_ms);
    void UsbMouseReportAccepted(const hid::BootMouseReport& report,
                                std::uint64_t logical_token, std::uint64_t now_ms);
    void UsbFault();

    // Called by an independently scheduled monotonic deadline source, never by Poll().
    void HeldKeyDeadlineFired(std::uint64_t token, std::uint64_t now_ms);

    [[nodiscard]] bool active() const noexcept;
    [[nodiscard]] std::uint64_t epoch() const noexcept;
    [[nodiscard]] std::uint32_t expected_sequence() const noexcept;

  private:
    enum class ActionKind : std::uint8_t { kReport, kWait, kRelease, kTap };
    struct Action {
        ActionKind kind{};
        hid::BootKeyboardReport report{};
        std::uint16_t first_ms{};
        std::uint16_t second_ms{};
    };
    enum class Phase : std::uint8_t {
        kIdle,
        kReady,
        kAwaitActionReport,
        kWait,
        kAwaitTapPress,
        kTapHold,
        kAwaitTapRelease,
        kTapGap,
        kAwaitMouseMove,
        kAwaitMouseClickPress,
        kMouseClickHold,
        kAwaitMouseClickRelease,
        kMouseClickGap,
        kTerminalRelease,
    };

    bool ParseEnvelope(const protocol::DecodedFrame& frame,
                       std::array<std::uint8_t, 16>* command_id, std::uint32_t* valid_for_ms,
                       std::uint8_t* kind, const std::uint8_t** body,
                       std::size_t* body_length) const;
    bool ParseActions(const std::uint8_t* body, std::size_t length);
    void Drive(std::uint64_t now_ms);
    void DriveInput(std::uint64_t now_ms);
    void BeginTerminal(protocol::ResultCode result,
                       protocol::ErrorCode reason = kNoInputError);
    void FinishTerminal();
    void FailActive(bool uncertain);
    void Emit(const std::array<std::uint8_t, 16>& command_id, std::uint32_t sequence,
              protocol::ResultCode result);
    void EmitInput(protocol::ResultCode result, protocol::ErrorCode reason);
    void RejectInput(const std::array<std::uint8_t, 16>& command_id,
                     std::uint32_t sequence, protocol::ErrorCode reason,
                     bool clear_arm);
    void ArmHeldKeyWatchdog(std::uint64_t now_ms);
    void CancelHeldKeyWatchdog();
    void WatchdogFailure();

    hid::ExecutorState& hid_;
    ResultSink& results_;
    HeldKeyDeadlineScheduler& watchdog_;
    std::array<std::uint8_t, 32> accepted_profile_hash_{};
    std::uint64_t epoch_{0};
    std::uint32_t expected_sequence_{0};
    bool sequence_exhausted_{false};
    bool input_v1_enabled_{false};
    bool command_arm_available_{false};
    bool active_{false};
    bool started_{false};
    bool terminal_pending_{false};
    bool input_active_{false};
    bool late_input_cancel_pending_{false};
    std::uint32_t late_input_cancel_sequence_{0};
    protocol::ResultCode terminal_result_{protocol::ResultCode::kRejected};
    protocol::ErrorCode terminal_reason_{kNoInputError};
    std::array<std::uint8_t, 16> command_id_{};
    std::uint32_t command_sequence_{0};
    std::uint64_t expiry_ms_{0};
    std::array<Action, kMaximumActions> actions_{};
    std::size_t action_count_{0};
    std::size_t action_index_{0};
    ParsedInputChunk input_chunk_{};
    InputReplayWindow input_replay_{};
    std::uint16_t movement_part_index_{0};
    std::uint64_t movement_token_{0};
    std::uint8_t input_effect_flags_{0};
    Phase phase_{Phase::kIdle};
    std::uint64_t wait_deadline_ms_{0};
    bool held_key_watchdog_armed_{false};
    std::uint64_t watchdog_token_{0};
    std::uint64_t held_key_deadline_ms_{0};
};

}  // namespace keyferry::command
