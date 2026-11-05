// Handheld screens. LVGL only, no hardware calls: shell.cpp feeds status in and takes
// actions out, and the host preview (scripts/preview_handheld.py) renders this same code.
#pragma once
#include <cstdint>
#include <iterator>

#include "lvgl.h"
#include "macros.h"
#include "messages.h"

namespace keyferry::handheld::ui {

constexpr int kWidth = 368;
constexpr int kHeight = 448;

// Choices the screens offer; the shell applies them by the same index.
inline constexpr int kKeepAwakeMinutes[] = {30, 60, 120, 0};  // 0: until stopped
inline constexpr int kScreenOffSeconds[] = {15, 30, 60, 120, 300};
inline constexpr int kDriveSizesMiB[] = {64, 256, 1024};
inline constexpr int kMicGainDb[] = {0, 6, 12, 18, 24, 30, 36, 42};  // the codec's mic gain steps
constexpr int kKeepAwakeChoices = static_cast<int>(std::size(kKeepAwakeMinutes));
constexpr int kScreenOffChoices = static_cast<int>(std::size(kScreenOffSeconds));
constexpr int kDriveSizeChoices = static_cast<int>(std::size(kDriveSizesMiB));
constexpr int kMicGainChoices = static_cast<int>(std::size(kMicGainDb));

enum class Screen : std::uint8_t {
  kHome, kCheck, kSettings, kKeepAwake, kMacros, kKeyferry, kDrive, kMic, kMessages
};
constexpr int kScreenCount = 9;

enum class Action : std::uint8_t {
  kLaunchKeyferry,
  kLaunchKeepAwake,
  kLaunchMacros,
  kLaunchDrive,
  kLaunchMic,
  kLaunchMessages,
  kLeave,               // Home from inside a function
  kWake,                // a touch on the blanked panel
  kShown,               // value: Screen
  kTouch,               // Board Check touch, value: x << 16 | y
  kKeepAwakeToggle,
  kKeepAwakeDuration,   // value: index into kKeepAwakeMinutes
  kBrightness,          // value: percent, while it changes
  kBrightnessCommit,    // value: percent, to store
  kScreenOff,           // value: index into kScreenOffSeconds
  kMacroHost,           // value: macros::Host
  kRunMacro,            // value: page << 8 | index
  kMacroPage,           // value: page now showing
  kDriveRescan,         // look for the SD card and its drives again
  kDriveConnect,        // value: index | writable << 8
  kDriveDisconnect,     // value: 1 back to the drive list, 0 Home
  kDriveCreate,         // value: index into kDriveSizesMiB
  kDriveCancelCreate,
  kMicMute,             // value: 1 muted, 0 not
  kMicGain,             // value: index into kMicGainDb
  kMessageRead,         // value: message id
  kMessageAnswer,       // value: message id << 1 | 1 for Yes
  kMessagesClear,
};

struct Config {
  bool keyferry = false;  // bridge linked: the Keyferry tile works
  int brightness = 60;
  int min_brightness = 5;
  int screen_off = 1;           // index into kScreenOffSeconds
  int keep_awake_duration = 1;  // index into kKeepAwakeMinutes
  macros::Host host = macros::Host::kWindows;
  int macro_page = 0;
  int mic_gain = 5;             // index into kMicGainDb
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

// One short line each (about 24 characters fit).
struct CheckView {
  const char* buttons;
  const char* power;
  const char* storage;
  const char* memory;
};
void RefreshCheck(const CheckView& view);

struct KeepAwakeView {
  const char* state;  // "Ready", "Running", "Done", "Stopped: ..."
  bool running = false;
  bool stopped_by_fault = false;
  bool usb = false;
  std::uint32_t nudges = 0;
  int seconds_to_next = -1;   // next nudge, while running
  int interval_seconds = 25;
  int seconds_left = -1;      // timer, while running; -1: until stopped
  int timer_seconds = 0;      // the running timer's full length; 0: until stopped
};
void RefreshKeepAwake(const KeepAwakeView& view);

struct MacrosView {
  bool usb = false;
  int busy = -1;                 // page << 8 | index while a macro plays
  const char* notice = nullptr;  // short result, shown under the title for a moment
  bool notice_is_error = false;
};
void RefreshMacros(const MacrosView& view);

// Keyferry status: the first line is shown large, the rest small under it.
void SetKeyferryText(const char* text);

// --- USB Drive ---

enum class DriveCard : std::uint8_t { kChecking, kReady, kNoCard, kError };
struct DriveRow {
  const char* name;
  std::uint64_t bytes;
  bool dirty;  // not ejected cleanly last time
};
struct DriveListView {
  DriveCard card = DriveCard::kChecking;
  const DriveRow* rows = nullptr;
  int count = 0;
  std::uint64_t free_bytes = 0;
};
void SetDriveList(const DriveListView& view);
// Opens one drive's page, or the New drive page (also used by the host preview).
void ShowDriveDetail(int index);
void ShowDriveCreate();
// Shown on the drive's page when connecting fails.
void ShowDriveError(const char* text);

enum class DriveLink : std::uint8_t { kWaiting, kConnected, kEjected, kStopped, kFailed };
struct DriveExportView {
  const char* name = "";
  std::uint64_t bytes = 0;
  bool writable = false;
  DriveLink link = DriveLink::kWaiting;
  bool busy = false;  // reading or writing right now
  bool marker_kept = false;  // ejected, but its not-ejected mark could not be cleared
  std::uint64_t read_bytes = 0;
  std::uint64_t written_bytes = 0;
};
// Switches to the connected view on first call; later calls refresh it.
void ShowDriveExport(const DriveExportView& view);
// The question asked before disconnecting a writable drive the computer has not ejected (also
// used by the host preview).
void ShowDisconnectConfirm();

struct DriveCreateView {
  bool busy = false;
  int percent = 0;
  bool finished = false;  // a creation ended since the last refresh
  int result = 0;         // of that creation: 1 created, -1 failed or cancelled
  const char* message = "";
};
void RefreshDriveCreate(const DriveCreateView& view);

// --- Microphone ---

struct MicView {
  bool usb = false;         // a computer has configured the device
  bool live = false;        // the computer has the microphone open
  bool muted = false;       // muted here (the board's button)
  bool host_muted = false;  // muted on the computer
  bool fault = false;       // the audio chip did not start or stopped answering
  int level = 0;            // input level, 0-100 (-60 to 0 dBFS)
};
void RefreshMic(const MicView& view);

// --- Messages ---

using handheld::MessageKind;
using handheld::MessageState;
struct MessageRow {
  std::uint32_t id;
  MessageKind kind;
  MessageState state;
  const char* text;
  int age_seconds;
};
struct MessagesView {
  bool usb = false;        // configured by a computer
  bool listening = false;  // a program on the computer has the port open
  const MessageRow* rows = nullptr;  // newest first
  int count = 0;
};
// Rebuilds the list; call when it changes and now and then so ages stay current.
void RefreshMessages(const MessagesView& view);

}  // namespace keyferry::handheld::ui
