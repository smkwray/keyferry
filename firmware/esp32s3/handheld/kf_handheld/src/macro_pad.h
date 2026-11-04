#pragma once
#include <cstdint>

#include "macros.h"

namespace keyferry::handheld {

enum class MacroResult : std::uint8_t { kNone, kSent, kNotConnected, kNotConfirmed, kStopped };

// Attaches the Macros USB device (keyboard, mouse, media keys) and its player. Sends nothing.
bool MacroPadStart();
// Plays one preset once. Refused (false) while another plays or no computer is connected;
// nothing is queued or retried.
bool MacroPadRun(int page, int index, macros::Host host);
// Stops the playing preset; the player then releases every key and button.
void MacroPadStop();
int MacroPadBusy();  // page << 8 | index while playing, else -1
// Last outcome; *serial changes with every new outcome, *which names its preset.
MacroResult MacroPadLastResult(std::uint32_t* serial, int* which);

}  // namespace keyferry::handheld
