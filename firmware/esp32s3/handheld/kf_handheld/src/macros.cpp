// The built-in macro pages. Each preset is a short, fixed sequence: no text, no secrets, no pointer
// motion. Adding a preset is one row here.
#include "macros.h"

#include <iterator>

#include "lvgl.h"

namespace keyferry::handheld::macros {
namespace {

constexpr std::int16_t Letter(char c) { return static_cast<std::int16_t>(0x04 + (c - 'A')); }
constexpr std::int16_t kEnter = 0x28, kEsc = 0x29, kTab = 0x2B, kSpace = 0x2C, kDigit4 = 0x21,
                       kF5 = 0x3E, kF11 = 0x44, kHome = 0x4A, kPageUp = 0x4B, kPageDown = 0x4E;

constexpr Step Keys(std::uint8_t modifiers, std::int16_t key) { return {Kind::kKeys, modifiers, key}; }
constexpr Step Media(std::int16_t usage) { return {Kind::kMedia, 0, usage}; }
constexpr Step Click(std::int16_t buttons) { return {Kind::kClick, 0, buttons}; }
constexpr Step Scroll(std::int16_t detents) { return {Kind::kScroll, 0, detents}; }
constexpr Step Wait(std::int16_t ms) { return {Kind::kWait, 0, ms}; }

const Macro kMedia[] = {
    {"Play/Pause", LV_SYMBOL_PLAY, {Media(0x00CD)}, {}},
    {"Mute", LV_SYMBOL_MUTE, {Media(0x00E2)}, {}},
    {"Previous", LV_SYMBOL_PREV, {Media(0x00B6)}, {}},
    {"Next", LV_SYMBOL_NEXT, {Media(0x00B5)}, {}},
    {"Volume -", LV_SYMBOL_VOLUME_MID, {Media(0x00EA)}, {}},
    {"Volume +", LV_SYMBOL_VOLUME_MAX, {Media(0x00E9)}, {}},
};

const Macro kShortcuts[] = {
    {"Lock", LV_SYMBOL_EYE_CLOSE, {Keys(kGui, Letter('L'))}, {Keys(kCtrl | kGui, Letter('Q'))}},
    {"Desktop", LV_SYMBOL_HOME, {Keys(kGui, Letter('D'))}, {Keys(0, kF11)}},
    {"Screenshot", LV_SYMBOL_IMAGE, {Keys(kGui | kShift, Letter('S'))}, {Keys(kGui | kShift, kDigit4)}},
    {"Switch App", LV_SYMBOL_SHUFFLE, {Keys(kAlt, kTab)}, {Keys(kGui, kTab)}},
    {"Search", LV_SYMBOL_LIST, {Keys(kGui, Letter('S'))}, {Keys(kGui, kSpace)}},
    {"Task Manager", LV_SYMBOL_WARNING, {Keys(kCtrl | kShift, kEsc)}, {Keys(kGui | kAlt, kEsc)},
     "Force Quit"},
};

const Macro kEdit[] = {
    {"Copy", LV_SYMBOL_COPY, {Keys(kCtrl, Letter('C'))}, {Keys(kGui, Letter('C'))}},
    {"Paste", LV_SYMBOL_PASTE, {Keys(kCtrl, Letter('V'))}, {Keys(kGui, Letter('V'))}},
    {"Cut", LV_SYMBOL_CUT, {Keys(kCtrl, Letter('X'))}, {Keys(kGui, Letter('X'))}},
    {"Select All", LV_SYMBOL_LIST, {Keys(kCtrl, Letter('A'))}, {Keys(kGui, Letter('A'))}},
    {"Undo", LV_SYMBOL_LEFT, {Keys(kCtrl, Letter('Z'))}, {Keys(kGui, Letter('Z'))}},
    {"Redo", LV_SYMBOL_RIGHT, {Keys(kCtrl, Letter('Y'))}, {Keys(kGui | kShift, Letter('Z'))}},
};

const Macro kPresent[] = {
    {"Back", LV_SYMBOL_LEFT, {Keys(0, kPageUp)}, {}},
    {"Next", LV_SYMBOL_RIGHT, {Keys(0, kPageDown)}, {}},
    {"Start", LV_SYMBOL_PLAY, {Keys(0, kF5)}, {Keys(kGui | kShift, kEnter)}},
    {"End", LV_SYMBOL_STOP, {Keys(0, kEsc)}, {}},
    {"Black", LV_SYMBOL_EYE_CLOSE, {Keys(0, Letter('B'))}, {}},
    {"First", LV_SYMBOL_PREV, {Keys(0, kHome)}, {}},
};

const Macro kMouse[] = {
    {"Click", LV_SYMBOL_OK, {Click(1)}, {}},
    {"Right Click", LV_SYMBOL_BARS, {Click(2)}, {}},
    {"Double Click", LV_SYMBOL_OK, {Click(1), Wait(60), Click(1)}, {}},
    {"Middle Click", LV_SYMBOL_PLUS, {Click(4)}, {}},
    {"Scroll Up", LV_SYMBOL_UP, {Scroll(3)}, {}},
    {"Scroll Down", LV_SYMBOL_DOWN, {Scroll(-3)}, {}},
};

static_assert(std::size(kMedia) <= kMaxPerPage && std::size(kShortcuts) <= kMaxPerPage &&
                  std::size(kEdit) <= kMaxPerPage && std::size(kPresent) <= kMaxPerPage &&
                  std::size(kMouse) <= kMaxPerPage,
              "a page holds at most kMaxPerPage presets");

const Page kPages[] = {
    {"Media", 0xA970FF, kMedia, static_cast<int>(std::size(kMedia))},
    {"Shortcuts", 0x4C8DFF, kShortcuts, static_cast<int>(std::size(kShortcuts))},
    {"Edit", 0x2ECC8F, kEdit, static_cast<int>(std::size(kEdit))},
    {"Present", 0xFF7A45, kPresent, static_cast<int>(std::size(kPresent))},
    {"Mouse", 0x22C3E6, kMouse, static_cast<int>(std::size(kMouse))},
};

static_assert(std::size(kPages) <= kMaxPages, "at most kMaxPages pages");

}  // namespace

int PageCount() { return static_cast<int>(std::size(kPages)); }

const Page& PageAt(int page) { return kPages[page < 0 || page >= PageCount() ? 0 : page]; }

const Step* StepsFor(const Macro& macro, Host host) {
  return host == Host::kMac && macro.mac[0].kind != Kind::kNone ? macro.mac : macro.windows;
}

const char* NameFor(const Macro& macro, Host host) {
  return host == Host::kMac && macro.mac_name != nullptr ? macro.mac_name : macro.name;
}

}  // namespace keyferry::handheld::macros
