#pragma once

namespace keyferry::handheld {

// Microphone (ADR 0018 rule 14): the board's microphone as a USB Audio Class 2 microphone,
// 48 kHz mono 16-bit. Audio goes only to the USB host, only while it has the stream open.

// Starts the audio chip (recording only), checks it answers and delivers sound, starts capture,
// then the USB device. A chip that fails is reported through MicStatusNow().fault and no USB
// device is presented. False only when the USB device could not start.
bool MicStart(int gain_db);
// Leaving the function (any task): no further samples reach the computer this boot.
void MicStop();
// The computer has the stream open and samples are flowing to it.
bool MicLive();
void MicSetMuted(bool muted);
void MicSetGain(int gain_db);

struct MicStatus {
  bool usb = false;         // configured by a computer and not suspended
  bool live = false;        // the computer has the stream open
  bool muted = false;       // muted on the board
  bool host_muted = false;  // muted by the computer
  bool fault = false;       // the audio chip did not start or stopped delivering samples (final)
  int level = 0;            // loudest input since the last call, 0-100 for -60 to 0 dBFS
};
MicStatus MicStatusNow();

}  // namespace keyferry::handheld
