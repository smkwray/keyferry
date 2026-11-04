#pragma once
#include <cstdint>

namespace keyferry::handheld {

constexpr int kKeepAwakeIntervalSeconds = 25;

enum class KeepAwakeState : std::uint8_t {
  kReady,
  kRunning,
  kStoppedUnplugged,
  kStoppedSuspended,
  kStoppedUnconfirmed,
};

// Attaches the standalone mouse. Sends nothing until KeepAwakeSetRunning(true).
bool KeepAwakeStartUsb();
void KeepAwakeSetRunning(bool running);
bool KeepAwakeRunning();
KeepAwakeState KeepAwakeStateNow();
std::uint32_t KeepAwakeNudges();
// Whole seconds until the next nudge while running (0: due now), else -1.
int KeepAwakeSecondsToNext();

}  // namespace keyferry::handheld
