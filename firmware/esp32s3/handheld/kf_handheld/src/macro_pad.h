#pragma once
#include <cstdint>

#include "macros.h"

namespace keyferry::handheld {

enum class MacroResult : std::uint8_t {
  kNone,
  kSent,
  kNotConnected,
  kNotConfirmed,
  kStopped,
  kReleasing,  // refused: an earlier release is not confirmed yet
};

// Attaches the Macros USB device (keyboard, mouse, media keys) and its player. Sends nothing.
bool MacroPadStart();
// Plays one preset once. Refused (false) while another plays, while a release is outstanding,
// after MacroPadClose() or with no computer connected; nothing is queued or retried.
bool MacroPadRun(int page, int index, macros::Host host);
// For leaving the function, from any task: no further press is sent this boot. A playing preset
// stops before its next press and the player releases everything.
void MacroPadClose();
// True when the player is idle and nothing may be held: every press since the last neutral
// state has a confirmed release, or the computer dropped the device.
bool MacroPadNeutral();
int MacroPadBusy();  // page << 8 | index while playing, else -1
// Last outcome; *serial changes with every new outcome, *which names its preset.
MacroResult MacroPadLastResult(std::uint32_t* serial, int* which);

}  // namespace keyferry::handheld
