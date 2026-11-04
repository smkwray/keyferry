#pragma once
#include <cstdint>

namespace keyferry::handheld {

constexpr int kKeepAwakeIntervalSeconds = 25;

enum class KeepAwakeState : std::uint8_t {
  kReady,
  kRunning,
  kFinished,  // its timer ran out
  kStoppedUnplugged,
  kStoppedSuspended,
  kStoppedUnconfirmed,
};

// Attaches the standalone mouse. Sends nothing until KeepAwakeStart().
bool KeepAwakeStartUsb();
// Starts nudging; it stops by itself after `seconds` (0: until stopped).
void KeepAwakeStart(int seconds);
// While running, restarts the timer from now with a new length (0: until stopped).
void KeepAwakeSetTimer(int seconds);
void KeepAwakeStop();
bool KeepAwakeRunning();
KeepAwakeState KeepAwakeStateNow();
std::uint32_t KeepAwakeNudges();
// Whole seconds until the next nudge while running (0: due now), else -1.
int KeepAwakeSecondsToNext();
// While running on a timer: whole seconds left and the timer's length. Otherwise -1 and 0.
int KeepAwakeSecondsLeft();
int KeepAwakeTimerSeconds();

}  // namespace keyferry::handheld
