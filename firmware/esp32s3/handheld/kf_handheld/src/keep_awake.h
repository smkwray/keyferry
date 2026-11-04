#pragma once
#include <cstdint>

namespace keyferry::handheld {

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
bool KeepAwakeUsbMounted();

}  // namespace keyferry::handheld
