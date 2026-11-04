// Macro presets (ADR 0018 rule 12): compiled-in key, media-key and mouse-button sequences, grouped
// in pages. Data only, so the UI, the USB runner and the host preview share one table.
#pragma once
#include <cstdint>

namespace keyferry::handheld::macros {

enum class Host : std::uint8_t { kWindows = 0, kMac = 1 };

enum class Kind : std::uint8_t {
  kNone,
  kKeys,    // modifiers + one HID keyboard usage (0: modifiers alone), pressed then released
  kMedia,   // one HID consumer usage, pressed then released
  kClick,   // mouse button mask, pressed then released; the pointer never moves
  kScroll,  // wheel detents, signed
  kWait,    // milliseconds
};

struct Step {
  Kind kind = Kind::kNone;
  std::uint8_t modifiers = 0;
  std::int16_t code = 0;
};

constexpr int kMaxSteps = 4;
constexpr int kMaxPages = 8;     // the Macros screen shows at most this many pages
constexpr int kMaxPerPage = 6;   // as a 2 x 3 grid

struct Macro {
  const char* name;
  const char* symbol;  // an LV_SYMBOL_* glyph
  Step windows[kMaxSteps];
  Step mac[kMaxSteps];          // all kNone: same as windows
  const char* mac_name = nullptr;  // null: same as name
};

struct Page {
  const char* name;
  std::uint32_t color;  // 0xRRGGBB accent
  const Macro* macros;
  int count;
};

// HID modifier bits and the keyboard usages the presets use (HID Usage Tables, page 0x07).
constexpr std::uint8_t kCtrl = 0x01, kShift = 0x02, kAlt = 0x04, kGui = 0x08;

int PageCount();
const Page& PageAt(int page);
const Step* StepsFor(const Macro& macro, Host host);
const char* NameFor(const Macro& macro, Host host);

}  // namespace keyferry::handheld::macros
