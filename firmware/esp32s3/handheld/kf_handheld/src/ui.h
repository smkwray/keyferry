// Handheld screens (ADR 0018). LVGL only, no hardware calls: shell.cpp feeds status in and takes
// actions out, and the host preview (scripts/preview_handheld.py) renders this same code.
#pragma once
#include <cstdint>

#include "lvgl.h"
#include "macros.h"

namespace keyferry::handheld::ui {

constexpr int kWidth = 368;
constexpr int kHeight = 448;

enum class Screen : std::uint8_t { kHome, kCheck, kSettings, kKeepAwake, kMacros, kKeyferry };

enum class Action : std::uint8_t {
  kLaunchKeyferry,
  kLaunchKeepAwake,
  kLaunchMacros,
  kLeave,             // Home from inside a function
  kWake,              // a touch on the blanked panel
  kShown,             // value: Screen
  kTouch,             // Board Check touch, value: x << 16 | y
  kKeepAwakeToggle,
  kBrightness,        // value: percent, while it changes
  kBrightnessCommit,  // value: percent, to store
  kStartInKeyferry,   // value: 0 or 1
  kMacroHost,         // value: macros::Host
  kRunMacro,          // value: page << 8 | index
  kMacroPage,         // value: page now showing
};

struct Config {
  bool keyferry = false;  // bridge linked: Keyferry tile and the Start in Keyferry row
  int brightness = 60;
  int min_brightness = 5;
  bool start_in_keyferry = false;
  macros::Host host = macros::Host::kWindows;
  int macro_page = 0;
  void (*action)(Action action, int value) = nullptr;
};

// Builds what `first` needs: Home with Board Check and Settings, or the one function screen.
void Build(const Config& config, Screen first);
void Show(Screen screen);
Screen Active();
// Call when the panel blanks: the gesture that wakes it (Action::kWake) never reaches a control.
void ShowWakeShield();

struct HomeView {
  bool usb_power = false;
  int battery_percent = -1;  // -1: no battery
};
void RefreshHome(const HomeView& view);

struct CheckView {
  const char* buttons;
  const char* power;
  const char* storage;
  const char* memory;
};
void RefreshCheck(const CheckView& view);

struct KeepAwakeView {
  const char* state;  // "Ready", "Running", "Stopped: ..."
  bool running = false;
  bool stopped_by_fault = false;
  bool usb = false;
  std::uint32_t nudges = 0;
  int seconds_to_next = -1;
  int interval_seconds = 25;
};
void RefreshKeepAwake(const KeepAwakeView& view);

struct MacrosView {
  bool usb = false;
  int busy = -1;              // page << 8 | index while a macro plays
  const char* notice = nullptr;  // short result, shown under the title for a moment
  bool notice_is_error = false;
};
void RefreshMacros(const MacrosView& view);

void SetKeyferryText(const char* text);

}  // namespace keyferry::handheld::ui
