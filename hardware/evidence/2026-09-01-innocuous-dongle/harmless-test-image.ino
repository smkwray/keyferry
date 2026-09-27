// keyferry Phase-0 harmless recovery-test image.
//
// Purpose: prove the AVR recovery route by flashing a KNOWN-SAFE image and then
// restoring this unit's captured backup. Intentionally does nothing:
//   - no Keyboard/Mouse/HID  -> cannot inject keystrokes
//   - the Arduino 32u4 core still brings up USB CDC + the 1200-baud touch, so the
//     bootloader stays reachable in software (no physical replug needed to recover).
// Recognizable state: enumerates as a CDC serial "LilyPad USB" with NO keyboard or
// mouse collection, versus the stock ESPloit composite (CDC + HID kbd + mouse).
void setup() {}
void loop() {}
