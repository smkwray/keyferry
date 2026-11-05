// Handheld screens. Design rules: true black (AMOLED), one accent colour per function, raised
// buttons that press in when touched, and nothing to tap under 72 px tall (about 6 mm on this
// panel). Every screen but Home and Keyferry (End along the bottom) has the Home button in the
// same top-left place.
#include "ui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>

namespace keyferry::handheld::ui {
namespace {

// --- Look ----------------------------------------------------------------------------------------

constexpr std::uint32_t kBlack = 0x000000;
constexpr std::uint32_t kCard = 0x121418;         // flat panels that hold controls
constexpr std::uint32_t kRaisedTop = 0x22252D;    // buttons: a soft top-to-bottom gradient
constexpr std::uint32_t kRaisedBottom = 0x16181D;
constexpr std::uint32_t kPressed = 0x30343E;
constexpr std::uint32_t kBorder = 0x2A2E37;
constexpr std::uint32_t kDivider = 0x22252C;
constexpr std::uint32_t kText = 0xF2F4F8;
constexpr std::uint32_t kMuted = 0x9AA3B2;
constexpr std::uint32_t kError = 0xFF6B6B;
constexpr std::uint32_t kKeyferryColor = 0x4C8DFF;
constexpr std::uint32_t kKeepAwakeColor = 0xFFB020;
constexpr std::uint32_t kMacrosColor = 0xA970FF;
constexpr std::uint32_t kDriveColor = 0x2ECC8F;
constexpr std::uint32_t kCheckColor = 0x22C3E6;
constexpr std::uint32_t kSettingsColor = 0x8C96A8;
constexpr std::uint32_t kMicColor = 0xFF5C7A;
constexpr std::uint32_t kMessagesColor = 0x5CC8FF;

const lv_font_t* const kSmall = &lv_font_montserrat_16;
const lv_font_t* const kBody = &lv_font_montserrat_20;
const lv_font_t* const kTitle = &lv_font_montserrat_28;
const lv_font_t* const kLarge = &lv_font_montserrat_40;

constexpr int kMargin = 12;
constexpr int kGap = 10;
constexpr int kRadius = 22;
constexpr int kControl = 72;  // the smallest touch target
constexpr int kHomeWidth = 88;
constexpr int kContentTop = kMargin + kControl + 10;
constexpr int kInnerWidth = kWidth - 2 * kMargin;
constexpr int kHalfWidth = (kInnerWidth - kGap) / 2;

struct State {
  Config config;
  lv_obj_t* screens[kScreenCount] = {};
  lv_obj_t* wake_shield = nullptr;
  lv_obj_t* home_status = nullptr;
  lv_obj_t* touch_dot = nullptr;
  lv_obj_t* touch_value = nullptr;
  lv_obj_t* check_values[4] = {};
  lv_obj_t* brightness_value = nullptr;
  int brightness = 60;
  lv_obj_t* screen_off_value = nullptr;
  int screen_off = 1;
  lv_obj_t* host_buttons[2] = {};
  lv_obj_t* awake_chips[kKeepAwakeChoices] = {};
  int awake_duration = 1;
  lv_obj_t* awake_arc = nullptr;
  lv_obj_t* awake_button = nullptr;
  lv_obj_t* awake_icon = nullptr;
  lv_obj_t* awake_label = nullptr;
  lv_obj_t* awake_state = nullptr;
  lv_obj_t* awake_detail = nullptr;
  std::uint32_t awake_nudges = 0;
  lv_obj_t* macro_title = nullptr;
  lv_obj_t* macro_dots = nullptr;
  lv_obj_t* macro_notice = nullptr;
  lv_obj_t* macro_pages = nullptr;
  lv_obj_t* macro_buttons[macros::kMaxPages][macros::kMaxPerPage] = {};
  int macro_page = 0;
  int macro_busy = -1;
  lv_obj_t* keyferry_state = nullptr;
  lv_obj_t* keyferry_detail = nullptr;
  // USB Drive
  lv_obj_t* drive_title = nullptr;
  lv_obj_t* drive_back_icon = nullptr;
  lv_obj_t* drive_views[4] = {};  // list, detail, connected, create
  int drive_view = 0;
  lv_obj_t* drive_status = nullptr;
  lv_obj_t* drive_retry = nullptr;
  lv_obj_t* drive_rows = nullptr;
  lv_obj_t* drive_new = nullptr;
  lv_obj_t* drive_new_detail = nullptr;
  DriveRow drive_list[8] = {};
  char drive_names[8][32] = {};
  int drive_count = 0;
  std::uint64_t drive_free = 0;
  int drive_selected = -1;
  bool drive_writable = false;
  lv_obj_t* detail_name = nullptr;
  lv_obj_t* detail_size = nullptr;
  lv_obj_t* detail_warning = nullptr;
  lv_obj_t* detail_modes[2] = {};
  lv_obj_t* detail_hint = nullptr;
  lv_obj_t* export_ring = nullptr;
  lv_obj_t* export_icon = nullptr;
  lv_obj_t* export_name = nullptr;
  lv_obj_t* export_status = nullptr;
  lv_obj_t* export_detail = nullptr;
  lv_obj_t* export_confirm = nullptr;
  bool export_shown = false;
  bool export_needs_eject = false;
  lv_obj_t* create_chips[kDriveSizeChoices] = {};
  int create_size = 0;
  lv_obj_t* create_info = nullptr;
  lv_obj_t* create_bar = nullptr;
  lv_obj_t* create_message = nullptr;
  lv_obj_t* create_button = nullptr;
  bool create_busy = false;
  // Microphone
  lv_obj_t* mic_arc = nullptr;
  lv_obj_t* mic_button = nullptr;
  lv_obj_t* mic_glyph[4] = {};  // capsule, holder, stem, base
  lv_obj_t* mic_slash = nullptr;
  lv_obj_t* mic_label = nullptr;
  lv_obj_t* mic_state = nullptr;
  lv_obj_t* mic_detail = nullptr;
  lv_obj_t* mic_gain_value = nullptr;
  bool mic_muted = false;
  int mic_gain = 5;
  // Messages
  lv_obj_t* msg_status = nullptr;
  lv_obj_t* msg_clear = nullptr;
  lv_obj_t* msg_rows = nullptr;
  lv_obj_t* msg_empty = nullptr;
  lv_obj_t* msg_empty_detail = nullptr;
  lv_obj_t* msg_ages[16] = {};
  int msg_shown = 0;
  std::uint32_t msg_signature = 0;
};

State g;
lv_style_t g_screen_style;
lv_style_t g_card_style;
lv_style_t g_button_style;
lv_style_t g_pressed_style;
lv_style_t g_disabled_style;
lv_style_transition_dsc_t g_press_transition;
const lv_style_prop_t kPressProps[] = {LV_STYLE_TRANSFORM_WIDTH, LV_STYLE_TRANSFORM_HEIGHT,
                                       LV_STYLE_BG_COLOR, LV_STYLE_BG_GRAD_COLOR, LV_STYLE_PROP_INV};

void Emit(Action action, int value) {
  if (g.config.action != nullptr) g.config.action(action, value);
}

void* Pack(int value) { return reinterpret_cast<void*>(static_cast<std::intptr_t>(value)); }
int Unpack(lv_event_t* event) {
  return static_cast<int>(reinterpret_cast<std::intptr_t>(lv_event_get_user_data(event)));
}

void InitStyles() {
  lv_style_init(&g_screen_style);
  lv_style_set_bg_color(&g_screen_style, lv_color_hex(kBlack));
  lv_style_set_bg_opa(&g_screen_style, LV_OPA_COVER);
  lv_style_set_text_color(&g_screen_style, lv_color_hex(kText));
  lv_style_set_text_font(&g_screen_style, kBody);

  lv_style_init(&g_card_style);
  lv_style_set_bg_color(&g_card_style, lv_color_hex(kCard));
  lv_style_set_bg_opa(&g_card_style, LV_OPA_COVER);
  lv_style_set_radius(&g_card_style, kRadius);
  lv_style_set_pad_all(&g_card_style, 16);

  lv_style_transition_dsc_init(&g_press_transition, kPressProps, lv_anim_path_ease_out, 90, 0, nullptr);

  lv_style_init(&g_button_style);
  lv_style_set_bg_color(&g_button_style, lv_color_hex(kRaisedTop));
  lv_style_set_bg_grad_color(&g_button_style, lv_color_hex(kRaisedBottom));
  lv_style_set_bg_grad_dir(&g_button_style, LV_GRAD_DIR_VER);
  lv_style_set_bg_opa(&g_button_style, LV_OPA_COVER);
  lv_style_set_radius(&g_button_style, kRadius);
  lv_style_set_border_width(&g_button_style, 2);
  lv_style_set_border_color(&g_button_style, lv_color_hex(kBorder));
  lv_style_set_text_color(&g_button_style, lv_color_hex(kText));
  lv_style_set_transition(&g_button_style, &g_press_transition);

  // Pressed: a little smaller and lighter, like a key going down.
  lv_style_init(&g_pressed_style);
  lv_style_set_bg_color(&g_pressed_style, lv_color_hex(kPressed));
  lv_style_set_bg_grad_color(&g_pressed_style, lv_color_hex(kPressed));
  lv_style_set_border_color(&g_pressed_style, lv_color_hex(kMuted));
  lv_style_set_transform_width(&g_pressed_style, -3);
  lv_style_set_transform_height(&g_pressed_style, -3);
  lv_style_set_transition(&g_pressed_style, &g_press_transition);

  lv_style_init(&g_disabled_style);
  lv_style_set_opa(&g_disabled_style, LV_OPA_40);
}

lv_obj_t* Label(lv_obj_t* parent, const lv_font_t* font, std::uint32_t color, const char* text) {
  lv_obj_t* label = lv_label_create(parent);
  lv_obj_set_style_text_font(label, font, 0);
  lv_obj_set_style_text_color(label, lv_color_hex(color), 0);
  lv_label_set_text(label, text);
  return label;
}

lv_obj_t* Plain(lv_obj_t* parent) {
  lv_obj_t* object = lv_obj_create(parent);
  lv_obj_remove_style_all(object);
  lv_obj_set_clickable(object, false);
  lv_obj_set_scrollable(object, false);
  return object;
}

lv_obj_t* Card(lv_obj_t* parent, int width, int height) {
  lv_obj_t* card = Plain(parent);
  lv_obj_add_style(card, &g_card_style, 0);
  lv_obj_set_size(card, width, height);
  return card;
}

lv_obj_t* Button(lv_obj_t* parent, int width, int height) {
  lv_obj_t* button = lv_button_create(parent);
  lv_obj_remove_style_all(button);
  lv_obj_add_style(button, &g_button_style, 0);
  lv_obj_add_style(button, &g_pressed_style, LV_STATE_PRESSED);
  lv_obj_add_style(button, &g_disabled_style, LV_STATE_DISABLED);
  lv_obj_set_size(button, width, height);
  lv_obj_set_scrollable(button, false);
  return button;
}

// Selected chips and segments: filled with the accent, dark text.
void SetSelected(lv_obj_t* button, bool selected, std::uint32_t accent) {
  const std::uint32_t top = selected ? accent : kRaisedTop;
  const std::uint32_t bottom = selected ? accent : kRaisedBottom;
  lv_obj_set_style_bg_color(button, lv_color_hex(top), 0);
  lv_obj_set_style_bg_grad_color(button, lv_color_hex(bottom), 0);
  lv_obj_set_style_border_color(button, lv_color_hex(selected ? accent : kBorder), 0);
  lv_obj_set_style_text_color(lv_obj_get_child(button, 0), lv_color_hex(selected ? kBlack : kText), 0);
}

// A tinted circle with the function's icon.
lv_obj_t* Badge(lv_obj_t* parent, const char* symbol, std::uint32_t color, int size,
                const lv_font_t* font) {
  lv_obj_t* badge = Plain(parent);
  lv_obj_set_size(badge, size, size);
  lv_obj_set_style_radius(badge, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(badge, lv_color_hex(color), 0);
  lv_obj_set_style_bg_opa(badge, LV_OPA_20, 0);
  lv_obj_center(Label(badge, font, color, symbol));
  return badge;
}

// An icon over a name, centered; Home tiles carry the icon in a badge.
void IconAndName(lv_obj_t* button, const char* symbol, const char* name, std::uint32_t color,
                 bool badge) {
  lv_obj_set_flex_flow(button, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(button, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(button, badge ? 10 : 6, 0);
  if (badge) {
    Badge(button, symbol, color, 56, kTitle);
  } else {
    Label(button, kTitle, color, symbol);
  }
  lv_obj_t* label = Label(button, kBody, kText, name);
  lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
}

lv_obj_t* NewScreen(Screen which) {
  lv_obj_t* screen = lv_obj_create(nullptr);
  lv_obj_remove_style_all(screen);
  lv_obj_add_style(screen, &g_screen_style, 0);
  lv_obj_set_scrollable(screen, false);
  g.screens[static_cast<int>(which)] = screen;
  return screen;
}

void OnHome(lv_event_t*) {
  const Screen active = Active();
  if (active == Screen::kCheck || active == Screen::kSettings) {
    Show(Screen::kHome);
  } else {
    Emit(Action::kLeave, 0);
  }
}

// Top bar: Home button in the corner, title beside it. Returns the title label.
lv_obj_t* Header(lv_obj_t* screen, const char* title) {
  lv_obj_t* home = Button(screen, kHomeWidth, kControl);
  lv_obj_set_pos(home, kMargin, kMargin);
  lv_obj_center(Label(home, kTitle, kText, LV_SYMBOL_HOME));
  lv_obj_add_event_cb(home, OnHome, LV_EVENT_CLICKED, nullptr);
  lv_obj_t* label = Label(screen, kTitle, kText, title);
  lv_obj_align_to(label, home, LV_ALIGN_OUT_RIGHT_MID, 16, 0);
  return label;
}

void OnAction(lv_event_t* event) { Emit(static_cast<Action>(Unpack(event)), 0); }
void OnShow(lv_event_t* event) { Show(static_cast<Screen>(Unpack(event))); }

// --- Microphone glyph ----------------------------------------------------------------------------

lv_obj_t* GlyphPart(lv_obj_t* parent, int x, int y, int w, int h, int radius) {
  lv_obj_t* part = Plain(parent);
  lv_obj_set_pos(part, x, y);
  lv_obj_set_size(part, w, h);
  lv_obj_set_style_radius(part, radius, 0);
  lv_obj_set_style_bg_opa(part, LV_OPA_COVER, 0);
  return part;
}

// LVGL's symbol font has no microphone, so it is drawn: capsule, holder, stem and base, scaled
// from a 72 x 80 design by `unit`/32 (the capsule's width). parts[]: capsule, holder, stem, base.
lv_obj_t* MicGlyph(lv_obj_t* parent, int unit, lv_obj_t* parts[4]) {
  const auto at = [unit](int v) { return v * unit / 32; };
  lv_obj_t* glyph = Plain(parent);
  lv_obj_set_size(glyph, at(72), at(80));
  parts[0] = GlyphPart(glyph, at(20), 0, at(32), at(52), at(16));
  lv_obj_t* holder = lv_arc_create(glyph);
  lv_obj_set_size(holder, at(56), at(56));
  lv_obj_set_pos(holder, at(8), at(6));
  lv_arc_set_bg_angles(holder, 0, 180);  // the lower half: a cup under the capsule
  lv_obj_remove_style(holder, nullptr, LV_PART_KNOB);
  lv_obj_remove_style(holder, nullptr, LV_PART_INDICATOR);
  lv_obj_set_clickable(holder, false);
  lv_obj_set_style_arc_width(holder, at(5) > 2 ? at(5) : 2, LV_PART_MAIN);
  lv_obj_set_style_arc_rounded(holder, true, LV_PART_MAIN);
  parts[1] = holder;
  parts[2] = GlyphPart(glyph, at(34), at(62), at(5) > 2 ? at(5) : 2, at(12), 0);
  parts[3] = GlyphPart(glyph, at(22), at(73), at(28), at(5) > 2 ? at(5) : 2, at(2));
  return glyph;
}

void SetGlyphColor(lv_obj_t* const parts[4], std::uint32_t color) {
  for (int i : {0, 2, 3}) lv_obj_set_style_bg_color(parts[i], lv_color_hex(color), 0);
  lv_obj_set_style_arc_color(parts[1], lv_color_hex(color), LV_PART_MAIN);
}

void BuildMicGlyph(lv_obj_t* parent) {
  lv_obj_t* glyph = MicGlyph(parent, 32, g.mic_glyph);
  static lv_point_precise_t slash[2] = {{6, 2}, {66, 78}};
  g.mic_slash = lv_line_create(glyph);
  lv_line_set_points(g.mic_slash, slash, 2);
  lv_obj_set_style_line_width(g.mic_slash, 6, 0);
  lv_obj_set_style_line_rounded(g.mic_slash, true, 0);
  lv_obj_set_style_line_color(g.mic_slash, lv_color_hex(kError), 0);
  lv_obj_set_hidden(g.mic_slash, true);
}

// --- Home ----------------------------------------------------------------------------------------

lv_obj_t* AddTile(lv_obj_t* parent, int index, const char* symbol, const char* name, std::uint32_t color,
                  lv_event_cb_t callback, int data, bool enabled) {
  constexpr int kTop = kMargin + kControl + 8;  // under the title bar and its Settings button
  constexpr int kTileHeight = (kHeight - kTop - kMargin - 2 * kGap) / 3;
  lv_obj_t* tile = Button(parent, kHalfWidth, kTileHeight);
  lv_obj_set_pos(tile, kMargin + (index % 2) * (kHalfWidth + kGap),
                 kTop + (index / 2) * (kTileHeight + kGap));
  IconAndName(tile, symbol, name, color, true);
  if (enabled) {
    lv_obj_add_event_cb(tile, callback, LV_EVENT_CLICKED, Pack(data));
    return tile;
  }
  lv_obj_add_state(tile, LV_STATE_DISABLED);
  lv_obj_t* soon = Label(tile, kSmall, kMuted, "Soon");
  lv_obj_set_ignore_layout(soon, true);
  lv_obj_align(soon, LV_ALIGN_TOP_RIGHT, -12, 8);
  return tile;
}

void BuildHome() {
  lv_obj_t* screen = NewScreen(Screen::kHome);
  lv_obj_t* settings = Button(screen, kControl, kControl);
  lv_obj_set_pos(settings, kWidth - kMargin - kControl, kMargin);
  lv_obj_center(Label(settings, kTitle, kSettingsColor, LV_SYMBOL_SETTINGS));
  lv_obj_add_event_cb(settings, OnShow, LV_EVENT_CLICKED, Pack(static_cast<int>(Screen::kSettings)));
  lv_obj_t* title = Label(screen, kTitle, kText, "Keyferry");
  lv_obj_align(title, LV_ALIGN_TOP_LEFT, kMargin + 8, kMargin + 18);
  g.home_status = Label(screen, kBody, kMuted, "");
  lv_obj_align(g.home_status, LV_ALIGN_TOP_RIGHT, -(kMargin + kControl + 14), kMargin + 24);
  AddTile(screen, 0, LV_SYMBOL_KEYBOARD, "Keyferry", kKeyferryColor, OnAction,
          static_cast<int>(Action::kLaunchKeyferry), g.config.keyferry);
  AddTile(screen, 1, LV_SYMBOL_EYE_OPEN, "Keep Awake", kKeepAwakeColor, OnAction,
          static_cast<int>(Action::kLaunchKeepAwake), true);
  AddTile(screen, 2, LV_SYMBOL_BARS, "Macros", kMacrosColor, OnAction,
          static_cast<int>(Action::kLaunchMacros), true);
  AddTile(screen, 3, LV_SYMBOL_SD_CARD, "USB Drive", kDriveColor, OnAction,
          static_cast<int>(Action::kLaunchDrive), true);
  lv_obj_t* mic = AddTile(screen, 4, "", "Microphone", kMicColor, OnAction,
                          static_cast<int>(Action::kLaunchMic), true);
  lv_obj_t* parts[4];
  lv_obj_center(MicGlyph(lv_obj_get_child(mic, 0), 15, parts));
  SetGlyphColor(parts, kMicColor);
  AddTile(screen, 5, LV_SYMBOL_ENVELOPE, "Messages", kMessagesColor, OnAction,
          static_cast<int>(Action::kLaunchMessages), true);
}

// --- Board Check ---------------------------------------------------------------------------------

void OnCheckTouch(lv_event_t* event) {
  lv_point_t point{};
  lv_indev_get_point(lv_indev_active(), &point);
  lv_obj_set_pos(g.touch_dot, point.x - 14, point.y - 14);
  lv_obj_set_hidden(g.touch_dot, false);
  lv_label_set_text_fmt(g.touch_value, "x %d   y %d", static_cast<int>(point.x),
                        static_cast<int>(point.y));
  if (lv_event_get_code(event) == LV_EVENT_PRESSED) {
    Emit(Action::kTouch, static_cast<int>(point.x) << 16 | static_cast<int>(point.y));
  }
}

// One list row: tinted icon, small caption, one-line value. Returns the value label.
lv_obj_t* CheckRow(lv_obj_t* list, const char* symbol, const char* caption, bool divider) {
  constexpr int kRow = 66;
  lv_obj_t* row = Plain(list);
  lv_obj_set_size(row, LV_PCT(100), kRow);
  if (divider) {
    lv_obj_set_style_border_side(row, LV_BORDER_SIDE_TOP, 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(kDivider), 0);
  }
  Badge(row, symbol, kCheckColor, 40, kBody);
  lv_obj_align(lv_obj_get_child(row, 0), LV_ALIGN_LEFT_MID, 0, 0);
  lv_obj_t* label = Label(row, kSmall, kMuted, caption);
  lv_obj_align(label, LV_ALIGN_TOP_LEFT, 56, 10);
  lv_obj_t* value = Label(row, kBody, kText, "");
  // One line: a value too long for it ends in dots rather than wrapping into the next row.
  lv_obj_set_size(value, kInnerWidth - 32 - 56, lv_font_get_line_height(kBody));
  lv_label_set_long_mode(value, LV_LABEL_LONG_MODE_DOTS);
  lv_obj_align(value, LV_ALIGN_TOP_LEFT, 56, 30);
  return value;
}

void BuildCheck() {
  lv_obj_t* screen = NewScreen(Screen::kCheck);
  Header(screen, "Board Check");
  lv_obj_set_clickable(screen, true);
  lv_obj_add_event_cb(screen, OnCheckTouch, LV_EVENT_PRESSED, nullptr);
  lv_obj_add_event_cb(screen, OnCheckTouch, LV_EVENT_PRESSING, nullptr);
  lv_obj_t* list = Card(screen, kInnerWidth, kHeight - kContentTop - kMargin);
  lv_obj_set_pos(list, kMargin, kContentTop);
  lv_obj_set_style_pad_ver(list, 4, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  g.touch_value = CheckRow(list, LV_SYMBOL_GPS, "Touch", false);
  lv_label_set_text(g.touch_value, "Tap anywhere");
  g.check_values[0] = CheckRow(list, LV_SYMBOL_POWER, "Buttons", true);
  g.check_values[1] = CheckRow(list, LV_SYMBOL_CHARGE, "Power", true);
  g.check_values[2] = CheckRow(list, LV_SYMBOL_SD_CARD, "SD card", true);
  g.check_values[3] = CheckRow(list, LV_SYMBOL_DRIVE, "Memory", true);
  g.touch_dot = Plain(screen);
  lv_obj_set_size(g.touch_dot, 28, 28);
  lv_obj_set_style_radius(g.touch_dot, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(g.touch_dot, lv_color_hex(kCheckColor), 0);
  lv_obj_set_style_bg_opa(g.touch_dot, LV_OPA_COVER, 0);
  lv_obj_set_hidden(g.touch_dot, true);
}

// --- Settings ------------------------------------------------------------------------------------

// A tappable list row: badge, name, detail line and a chevron.
lv_obj_t* RowButtonWithDetail(lv_obj_t* parent, const char* symbol, std::uint32_t color,
                              const char* name, const char* detail, std::uint32_t detail_color) {
  lv_obj_t* row = Button(parent, kInnerWidth, 84);
  lv_obj_t* badge = Badge(row, symbol, color, 48, kBody);
  lv_obj_align(badge, LV_ALIGN_LEFT_MID, 14, 0);
  lv_obj_t* label = Label(row, kBody, kText, name);
  lv_obj_set_width(label, kInnerWidth - 76 - 48);
  lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_DOTS);
  lv_obj_set_height(label, lv_font_get_line_height(kBody));
  lv_obj_set_pos(label, 76, 14);
  lv_obj_t* line = Label(row, kSmall, detail_color, detail);
  lv_obj_set_size(line, kInnerWidth - 76 - 48, lv_font_get_line_height(kSmall));
  lv_label_set_long_mode(line, LV_LABEL_LONG_MODE_DOTS);
  lv_obj_set_pos(line, 76, 46);
  lv_obj_align(Label(row, kBody, kMuted, LV_SYMBOL_RIGHT), LV_ALIGN_RIGHT_MID, -18, 0);
  return row;
}

constexpr int kRowHeight = 96;

// A vertical list under the header that scrolls; rows fade out at the bottom edge instead of
// being cut off, so it is clear there is more below.
lv_obj_t* ScrollList(lv_obj_t* parent) {
  lv_obj_t* list = Plain(parent);
  lv_obj_set_pos(list, 0, kContentTop);
  lv_obj_set_size(list, kWidth, kHeight - kContentTop);
  lv_obj_set_scrollable(list, true);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_ACTIVE);
  lv_obj_set_style_pad_hor(list, kMargin, 0);
  lv_obj_set_style_pad_row(list, 8, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_bg_color(list, lv_color_hex(kSettingsColor), LV_PART_SCROLLBAR);
  lv_obj_set_style_bg_opa(list, LV_OPA_60, LV_PART_SCROLLBAR);
  lv_obj_set_style_width(list, 4, LV_PART_SCROLLBAR);
  return list;
}

void AddFade(lv_obj_t* list) {
  constexpr int kFade = 36;
  lv_obj_set_style_pad_bottom(list, kFade, 0);
  lv_obj_t* fade = Plain(list);
  lv_obj_set_floating(fade, true);
  lv_obj_set_size(fade, kWidth, kFade);
  lv_obj_align(fade, LV_ALIGN_BOTTOM_MID, 0, kFade);  // the list's bottom padding holds it
  lv_obj_set_style_bg_color(fade, lv_color_hex(kBlack), 0);
  lv_obj_set_style_bg_grad_color(fade, lv_color_hex(kBlack), 0);
  lv_obj_set_style_bg_grad_dir(fade, LV_GRAD_DIR_VER, 0);
  lv_obj_set_style_bg_main_opa(fade, LV_OPA_TRANSP, 0);
  lv_obj_set_style_bg_grad_opa(fade, LV_OPA_COVER, 0);
  lv_obj_set_style_bg_opa(fade, LV_OPA_COVER, 0);
}

lv_obj_t* SettingsRow(lv_obj_t* list, const char* caption) {
  lv_obj_t* row = Card(list, kInnerWidth, kRowHeight);
  lv_obj_set_style_pad_all(row, 12, 0);
  lv_obj_set_style_pad_left(row, 18, 0);
  lv_obj_t* label = Label(row, kBody, kText, caption);
  lv_obj_align(label, LV_ALIGN_LEFT_MID, 0, 0);
  return row;
}

lv_obj_t* RowButton(lv_obj_t* row, int width, int x_from_right, const char* text) {
  lv_obj_t* button = Button(row, width, kControl);
  lv_obj_align(button, LV_ALIGN_RIGHT_MID, -x_from_right, 0);
  lv_obj_center(Label(button, kTitle, kText, text));
  return button;
}

// Caption over an accent value on the left, - and + on the right. Returns the value label.
lv_obj_t* StepperRow(lv_obj_t* list, const char* caption, lv_event_cb_t callback, bool repeat) {
  lv_obj_t* row = SettingsRow(list, caption);
  lv_obj_align(lv_obj_get_child(row, 0), LV_ALIGN_TOP_LEFT, 0, 2);
  lv_obj_t* value = Label(row, kTitle, kKeepAwakeColor, "");
  lv_obj_align(value, LV_ALIGN_BOTTOM_LEFT, 0, -2);
  lv_obj_t* plus = RowButton(row, kControl, 0, LV_SYMBOL_PLUS);
  lv_obj_t* minus = RowButton(row, kControl, kControl + 8, LV_SYMBOL_MINUS);
  for (lv_obj_t* button : {minus, plus}) {
    void* step = Pack(button == plus ? 1 : -1);
    lv_obj_add_event_cb(button, callback, LV_EVENT_SHORT_CLICKED, step);
    if (repeat) {
      lv_obj_add_event_cb(button, callback, LV_EVENT_LONG_PRESSED, step);
      lv_obj_add_event_cb(button, callback, LV_EVENT_LONG_PRESSED_REPEAT, step);
      lv_obj_add_event_cb(button, callback, LV_EVENT_RELEASED, step);
    }
  }
  return value;
}

void ShowBrightness() { lv_label_set_text_fmt(g.brightness_value, "%d%%", g.brightness); }

// A tap stores its new value at once. A long press steps repeatedly and stores once on release;
// LVGL sends RELEASED before SHORT_CLICKED, so a tap's release has nothing pending to store.
void OnBrightnessStep(lv_event_t* event) {
  static bool pending = false;
  const lv_event_code_t code = lv_event_get_code(event);
  if (code == LV_EVENT_RELEASED) {
    if (pending) Emit(Action::kBrightnessCommit, g.brightness);
    pending = false;
    return;
  }
  const int step = Unpack(event) * 10;
  int value = g.brightness + step;
  if (step < 0 && g.brightness > g.config.min_brightness && value < g.config.min_brightness) {
    value = g.config.min_brightness;
  }
  if (value < g.config.min_brightness || value > 100) return;
  g.brightness = value;
  ShowBrightness();
  Emit(Action::kBrightness, value);
  if (code == LV_EVENT_SHORT_CLICKED) {
    Emit(Action::kBrightnessCommit, value);
  } else {
    pending = true;
  }
}

void ShowScreenOff() {
  const int seconds = kScreenOffSeconds[g.screen_off];
  if (seconds < 60) {
    lv_label_set_text_fmt(g.screen_off_value, "%d s", seconds);
  } else {
    lv_label_set_text_fmt(g.screen_off_value, "%d min", seconds / 60);
  }
}

void OnScreenOffStep(lv_event_t* event) {
  const int index = g.screen_off + Unpack(event);
  if (index < 0 || index >= kScreenOffChoices) return;
  g.screen_off = index;
  ShowScreenOff();
  Emit(Action::kScreenOff, index);
}

void ShowHost() {
  for (int i = 0; i < 2; ++i) {
    SetSelected(g.host_buttons[i], static_cast<int>(g.config.host) == i, kMacrosColor);
  }
}

void OnHost(lv_event_t* event) {
  g.config.host = static_cast<macros::Host>(Unpack(event));
  ShowHost();
  Emit(Action::kMacroHost, static_cast<int>(g.config.host));
}

void BuildSettings() {
  lv_obj_t* screen = NewScreen(Screen::kSettings);
  Header(screen, "Settings");
  lv_obj_t* list = ScrollList(screen);

  g.brightness = g.config.brightness;
  g.brightness_value = StepperRow(list, "Brightness", OnBrightnessStep, true);
  ShowBrightness();

  g.screen_off = g.config.screen_off >= 0 && g.config.screen_off < kScreenOffChoices ? g.config.screen_off : 1;
  g.screen_off_value = StepperRow(list, "Screen off after", OnScreenOffStep, false);
  ShowScreenOff();

  lv_obj_t* host = SettingsRow(list, "Macros for");
  const char* names[2] = {"Mac", "Win"};
  for (int i = 0; i < 2; ++i) {
    // Right to left: Mac, then Windows.
    lv_obj_t* button = RowButton(host, 80, i * 88, names[i]);
    lv_obj_set_style_text_font(lv_obj_get_child(button, 0), kBody, 0);
    const int value = i == 0 ? static_cast<int>(macros::Host::kMac) : static_cast<int>(macros::Host::kWindows);
    g.host_buttons[value] = button;
    lv_obj_add_event_cb(button, OnHost, LV_EVENT_CLICKED, Pack(value));
  }
  ShowHost();

  lv_obj_t* check = RowButtonWithDetail(list, LV_SYMBOL_LIST, kCheckColor, "Board Check",
                                        "Touch, buttons, power, SD card", kMuted);
  lv_obj_add_event_cb(check, OnShow, LV_EVENT_CLICKED, Pack(static_cast<int>(Screen::kCheck)));

  lv_obj_t* hint = Label(list, kSmall, kMuted,
                         "A touch wakes the screen.\n"
                         "PWR: screen off/on.   BOOT: back to Home.");
  lv_obj_set_style_pad_left(hint, 8, 0);
  lv_obj_set_style_pad_top(hint, 4, 0);

  AddFade(list);
}

// --- Keep Awake ----------------------------------------------------------------------------------

void PulseStep(void* object, std::int32_t value) {
  lv_obj_t* button = static_cast<lv_obj_t*>(object);
  lv_obj_set_style_outline_width(button, value, 0);
  lv_obj_set_style_outline_opa(button, static_cast<lv_opa_t>(LV_OPA_COVER * (20 - value) / 20), 0);
}

// A ring that swells out of the button on every nudge: proof it is working.
void Pulse() {
  lv_anim_t animation;
  lv_anim_init(&animation);
  lv_anim_set_var(&animation, g.awake_button);
  lv_anim_set_values(&animation, 0, 20);
  lv_anim_set_duration(&animation, 700);
  lv_anim_set_path_cb(&animation, lv_anim_path_ease_out);
  lv_anim_set_exec_cb(&animation, PulseStep);
  lv_anim_start(&animation);
}

void ShowDuration() {
  for (int i = 0; i < kKeepAwakeChoices; ++i) {
    SetSelected(g.awake_chips[i], i == g.awake_duration, kKeepAwakeColor);
  }
}

void OnDuration(lv_event_t* event) {
  g.awake_duration = Unpack(event);
  ShowDuration();
  Emit(Action::kKeepAwakeDuration, g.awake_duration);
}

void BuildKeepAwake() {
  lv_obj_t* screen = NewScreen(Screen::kKeepAwake);
  Header(screen, "Keep Awake");
  constexpr int kChipWidth = (kInnerWidth - (kKeepAwakeChoices - 1) * 8) / kKeepAwakeChoices;
  g.awake_duration = g.config.keep_awake_duration >= 0 && g.config.keep_awake_duration < kKeepAwakeChoices
                         ? g.config.keep_awake_duration
                         : 1;
  for (int i = 0; i < kKeepAwakeChoices; ++i) {
    lv_obj_t* chip = Button(screen, kChipWidth, kControl);
    lv_obj_set_pos(chip, kMargin + i * (kChipWidth + 8), kContentTop);
    char text[16];
    const int minutes = kKeepAwakeMinutes[i];
    if (minutes == 0) {
      std::snprintf(text, sizeof(text), "Always");
    } else if (minutes < 60) {
      std::snprintf(text, sizeof(text), "%d min", minutes);
    } else {
      std::snprintf(text, sizeof(text), "%d h", minutes / 60);
    }
    lv_obj_center(Label(chip, kBody, kText, text));
    lv_obj_add_event_cb(chip, OnDuration, LV_EVENT_CLICKED, Pack(i));
    g.awake_chips[i] = chip;
  }
  ShowDuration();

  constexpr int kArc = 206;
  constexpr int kCircle = 164;
  constexpr int kArcTop = kContentTop + kControl + 10;
  g.awake_arc = lv_arc_create(screen);
  lv_obj_set_size(g.awake_arc, kArc, kArc);
  lv_obj_align(g.awake_arc, LV_ALIGN_TOP_MID, 0, kArcTop);
  lv_arc_set_rotation(g.awake_arc, 270);
  lv_arc_set_bg_angles(g.awake_arc, 0, 360);
  lv_arc_set_range(g.awake_arc, 0, 25);
  lv_arc_set_value(g.awake_arc, 0);
  lv_obj_remove_style(g.awake_arc, nullptr, LV_PART_KNOB);
  lv_obj_set_clickable(g.awake_arc, false);
  lv_obj_set_style_arc_width(g.awake_arc, 9, LV_PART_MAIN);
  lv_obj_set_style_arc_color(g.awake_arc, lv_color_hex(kDivider), LV_PART_MAIN);
  lv_obj_set_style_arc_width(g.awake_arc, 9, LV_PART_INDICATOR);
  lv_obj_set_style_arc_color(g.awake_arc, lv_color_hex(kKeepAwakeColor), LV_PART_INDICATOR);

  g.awake_button = Button(screen, kCircle, kCircle);
  lv_obj_set_style_radius(g.awake_button, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_border_width(g.awake_button, 3, 0);
  lv_obj_set_style_outline_color(g.awake_button, lv_color_hex(kKeepAwakeColor), 0);
  lv_obj_align(g.awake_button, LV_ALIGN_TOP_MID, 0, kArcTop + (kArc - kCircle) / 2);
  lv_obj_set_flex_flow(g.awake_button, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(g.awake_button, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(g.awake_button, 4, 0);
  g.awake_icon = Label(g.awake_button, kLarge, kKeepAwakeColor, LV_SYMBOL_PLAY);
  g.awake_label = Label(g.awake_button, kTitle, kText, "Start");
  lv_obj_add_event_cb(g.awake_button, OnAction, LV_EVENT_CLICKED,
                      Pack(static_cast<int>(Action::kKeepAwakeToggle)));

  g.awake_state = Label(screen, kBody, kText, "Ready");
  lv_obj_set_width(g.awake_state, kInnerWidth);
  lv_obj_set_style_text_align(g.awake_state, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(g.awake_state, LV_ALIGN_TOP_MID, 0, kArcTop + kArc + 8);
  g.awake_detail = Label(screen, kSmall, kMuted, "");
  lv_obj_set_width(g.awake_detail, kInnerWidth);
  lv_obj_set_style_text_align(g.awake_detail, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(g.awake_detail, LV_ALIGN_TOP_MID, 0, kArcTop + kArc + 36);
}

// --- Macros --------------------------------------------------------------------------------------

void ShowMacroPage(int page) {
  if (page != g.macro_page) Emit(Action::kMacroPage, page);
  g.macro_page = page;
  lv_label_set_text(g.macro_title, macros::PageAt(page).name);
  const int pages = macros::PageCount();
  for (int i = 0; i < pages; ++i) {
    lv_obj_t* dot = lv_obj_get_child(g.macro_dots, i);
    lv_obj_set_width(dot, i == page ? 22 : 10);  // the current page is a short bar
    lv_obj_set_style_bg_color(dot, lv_color_hex(i == page ? macros::PageAt(page).color : kBorder), 0);
  }
}

void OnMacroPageChanged(lv_event_t*) {
  lv_obj_t* tile = lv_tileview_get_tile_active(g.macro_pages);
  ShowMacroPage(static_cast<int>(lv_obj_get_index(tile)));
}

void OnNextPage(lv_event_t*) {
  const int next = (g.macro_page + 1) % macros::PageCount();
  lv_tileview_set_tile_by_index(g.macro_pages, static_cast<std::uint32_t>(next), 0, LV_ANIM_ON);
  ShowMacroPage(next);
}

void OnMacro(lv_event_t* event) { Emit(Action::kRunMacro, Unpack(event)); }

void BuildMacros() {
  lv_obj_t* screen = NewScreen(Screen::kMacros);
  g.macro_title = Header(screen, "");
  lv_obj_align(g.macro_title, LV_ALIGN_TOP_LEFT, kMargin + kHomeWidth + 16, kMargin + 6);

  lv_obj_t* next = Button(screen, kControl, kControl);
  lv_obj_align(next, LV_ALIGN_TOP_RIGHT, -kMargin, kMargin);
  lv_obj_center(Label(next, kTitle, kText, LV_SYMBOL_RIGHT));
  lv_obj_add_event_cb(next, OnNextPage, LV_EVENT_CLICKED, nullptr);

  const int pages = macros::PageCount();  // the table is bounded at compile time
  g.macro_dots = Plain(screen);
  lv_obj_set_size(g.macro_dots, LV_SIZE_CONTENT, 10);
  lv_obj_set_flex_flow(g.macro_dots, LV_FLEX_FLOW_ROW);
  lv_obj_set_style_pad_column(g.macro_dots, 6, 0);
  lv_obj_set_pos(g.macro_dots, kMargin + kHomeWidth + 18, kMargin + 52);
  for (int i = 0; i < pages; ++i) {
    lv_obj_t* dot = Plain(g.macro_dots);
    lv_obj_set_size(dot, 10, 10);
    lv_obj_set_style_radius(dot, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_bg_opa(dot, LV_OPA_COVER, 0);
  }
  g.macro_notice = Label(screen, kSmall, kMuted, "");
  lv_obj_set_pos(g.macro_notice, kMargin + kHomeWidth + 16, kMargin + 46);
  // Between the Home and next-page buttons; longer notices scroll.
  lv_obj_set_width(g.macro_notice, kInnerWidth - kHomeWidth - kControl - 32);
  lv_label_set_long_mode(g.macro_notice, LV_LABEL_LONG_MODE_SCROLL_CIRCULAR);
  lv_obj_set_hidden(g.macro_notice, true);

  g.macro_pages = lv_tileview_create(screen);
  lv_obj_remove_style_all(g.macro_pages);
  lv_obj_set_pos(g.macro_pages, 0, kContentTop);
  lv_obj_set_size(g.macro_pages, kWidth, kHeight - kContentTop);
  lv_obj_set_scrollbar_mode(g.macro_pages, LV_SCROLLBAR_MODE_OFF);
  lv_obj_add_event_cb(g.macro_pages, OnMacroPageChanged, LV_EVENT_VALUE_CHANGED, nullptr);
  constexpr int kButtonHeight = (kHeight - kContentTop - kMargin - 2 * kGap) / 3;
  for (int p = 0; p < pages; ++p) {
    const macros::Page& page = macros::PageAt(p);
    lv_obj_t* tile = lv_tileview_add_tile(g.macro_pages, static_cast<std::uint8_t>(p), 0, LV_DIR_HOR);
    lv_obj_set_scrollable(tile, false);  // horizontal drags reach the tileview
    for (int m = 0; m < page.count; ++m) {
      const macros::Macro& macro = page.macros[m];
      lv_obj_t* button = Button(tile, kHalfWidth, kButtonHeight);
      lv_obj_set_pos(button, kMargin + (m % 2) * (kHalfWidth + kGap), (m / 2) * (kButtonHeight + kGap));
      // Playing: accent border over an accent-tinted face; icon and name stay legible.
      const lv_color_t tint = lv_color_mix(lv_color_hex(page.color), lv_color_hex(kRaisedBottom), 80);
      lv_obj_set_style_bg_color(button, tint, LV_STATE_CHECKED);
      lv_obj_set_style_bg_grad_color(button, tint, LV_STATE_CHECKED);
      lv_obj_set_style_border_color(button, lv_color_hex(page.color), LV_STATE_CHECKED);
      lv_obj_set_style_border_width(button, 4, LV_STATE_CHECKED);
      IconAndName(button, macro.symbol, macros::NameFor(macro, g.config.host), page.color, false);
      lv_obj_add_event_cb(button, OnMacro, LV_EVENT_CLICKED, Pack(p << 8 | m));
      g.macro_buttons[p][m] = button;
    }
  }
  const int first = g.config.macro_page >= 0 && g.config.macro_page < pages ? g.config.macro_page : 0;
  g.macro_page = first;
  lv_tileview_set_tile_by_index(g.macro_pages, static_cast<std::uint32_t>(first), 0, LV_ANIM_OFF);
  ShowMacroPage(first);
}

// --- Keyferry ------------------------------------------------------------------------------------

// The main action along the bottom edge.
lv_obj_t* WideButton(lv_obj_t* parent, const char* text, std::uint32_t accent) {
  lv_obj_t* button = Button(parent, kInnerWidth, 80);
  lv_obj_align(button, LV_ALIGN_BOTTOM_MID, 0, -kMargin);
  lv_obj_t* label = Label(button, kTitle, kText, text);
  lv_obj_center(label);
  if (accent != 0) SetSelected(button, true, accent);
  return button;
}

// Keyferry runs until ended: its status, and one button back to Home (holding BOOT works too).
void BuildKeyferry() {
  lv_obj_t* screen = NewScreen(Screen::kKeyferry);
  lv_obj_t* title = Label(screen, kTitle, kText, "Keyferry");
  lv_obj_set_pos(title, kMargin + 8, 20);

  constexpr int kRing = 128;
  constexpr int kRingTop = 76;
  lv_obj_t* ring = Plain(screen);
  lv_obj_set_size(ring, kRing, kRing);
  lv_obj_align(ring, LV_ALIGN_TOP_MID, 0, kRingTop);
  lv_obj_set_style_radius(ring, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(ring, lv_color_hex(kKeyferryColor), 0);
  lv_obj_set_style_bg_opa(ring, LV_OPA_20, 0);
  lv_obj_set_style_border_width(ring, 4, 0);
  lv_obj_set_style_border_color(ring, lv_color_hex(kKeyferryColor), 0);
  lv_obj_center(Label(ring, kLarge, kKeyferryColor, LV_SYMBOL_KEYBOARD));

  g.keyferry_state = Label(screen, kTitle, kText, "Starting...");
  lv_obj_set_width(g.keyferry_state, kInnerWidth);
  lv_obj_set_style_text_align(g.keyferry_state, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_pos(g.keyferry_state, kMargin, kRingTop + kRing + 14);
  g.keyferry_detail = Label(screen, kSmall, kMuted, "");
  lv_obj_set_width(g.keyferry_detail, kInnerWidth);
  lv_obj_set_style_text_align(g.keyferry_detail, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_pos(g.keyferry_detail, kMargin, kRingTop + kRing + 54);

  lv_obj_add_event_cb(WideButton(screen, LV_SYMBOL_HOME "   End Keyferry", 0), OnAction, LV_EVENT_CLICKED,
                      Pack(static_cast<int>(Action::kLeave)));
}

// --- Microphone ----------------------------------------------------------------------------------

void ShowMicGain() { lv_label_set_text_fmt(g.mic_gain_value, "%d dB", kMicGainDb[g.mic_gain]); }

void OnMicGainStep(lv_event_t* event) {
  const int index = g.mic_gain + Unpack(event);
  if (index < 0 || index >= kMicGainChoices) return;
  g.mic_gain = index;
  ShowMicGain();
  Emit(Action::kMicGain, index);
}

void OnMicMute(lv_event_t*) {
  g.mic_muted = !g.mic_muted;
  lv_label_set_text(g.mic_label, g.mic_muted ? "Unmute" : "Mute");
  Emit(Action::kMicMute, g.mic_muted ? 1 : 0);
}

void BuildMic() {
  lv_obj_t* screen = NewScreen(Screen::kMic);
  Header(screen, "Microphone");
  g.mic_gain = g.config.mic_gain >= 0 && g.config.mic_gain < kMicGainChoices ? g.config.mic_gain : 5;

  // The ring is a level meter: how loud the microphone hears the room.
  constexpr int kArc = 196;
  constexpr int kCircle = 152;
  constexpr int kArcTop = kContentTop;
  g.mic_arc = lv_arc_create(screen);
  lv_obj_set_size(g.mic_arc, kArc, kArc);
  lv_obj_align(g.mic_arc, LV_ALIGN_TOP_MID, 0, kArcTop);
  lv_arc_set_rotation(g.mic_arc, 135);
  lv_arc_set_bg_angles(g.mic_arc, 0, 270);
  lv_arc_set_range(g.mic_arc, 0, 100);
  lv_arc_set_value(g.mic_arc, 0);
  lv_obj_remove_style(g.mic_arc, nullptr, LV_PART_KNOB);
  lv_obj_set_clickable(g.mic_arc, false);
  lv_obj_set_style_arc_width(g.mic_arc, 10, LV_PART_MAIN);
  lv_obj_set_style_arc_color(g.mic_arc, lv_color_hex(kDivider), LV_PART_MAIN);
  lv_obj_set_style_arc_width(g.mic_arc, 10, LV_PART_INDICATOR);
  lv_obj_set_style_arc_color(g.mic_arc, lv_color_hex(kMicColor), LV_PART_INDICATOR);

  g.mic_button = Button(screen, kCircle, kCircle);
  lv_obj_set_style_radius(g.mic_button, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_border_width(g.mic_button, 3, 0);
  lv_obj_align(g.mic_button, LV_ALIGN_TOP_MID, 0, kArcTop + (kArc - kCircle) / 2);
  lv_obj_set_flex_flow(g.mic_button, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(g.mic_button, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(g.mic_button, 6, 0);
  BuildMicGlyph(g.mic_button);
  g.mic_label = Label(g.mic_button, kBody, kText, "Mute");
  lv_obj_add_event_cb(g.mic_button, OnMicMute, LV_EVENT_CLICKED, nullptr);

  g.mic_state = Label(screen, kBody, kText, "Starting...");
  lv_obj_set_width(g.mic_state, kInnerWidth);
  lv_obj_set_style_text_align(g.mic_state, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(g.mic_state, LV_ALIGN_TOP_MID, 0, kArcTop + kArc + 2);
  g.mic_detail = Label(screen, kSmall, kMuted, "");
  lv_obj_set_width(g.mic_detail, kInnerWidth);
  lv_obj_set_style_text_align(g.mic_detail, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(g.mic_detail, LV_ALIGN_TOP_MID, 0, kArcTop + kArc + 28);

  // Sensitivity: caption over the value on the left, - and + on the right.
  constexpr int kRow = kControl + 12;
  lv_obj_t* row = Card(screen, kInnerWidth, kRow);
  lv_obj_set_pos(row, kMargin, kHeight - kMargin - kRow);
  lv_obj_set_style_pad_all(row, 6, 0);
  lv_obj_set_style_pad_left(row, 18, 0);
  lv_obj_align(Label(row, kSmall, kMuted, "Sensitivity"), LV_ALIGN_TOP_LEFT, 0, 6);
  g.mic_gain_value = Label(row, kTitle, kMicColor, "");
  lv_obj_align(g.mic_gain_value, LV_ALIGN_BOTTOM_LEFT, 0, -4);
  lv_obj_t* plus = RowButton(row, kControl, 0, LV_SYMBOL_PLUS);
  lv_obj_t* minus = RowButton(row, kControl, kControl + 8, LV_SYMBOL_MINUS);
  lv_obj_add_event_cb(minus, OnMicGainStep, LV_EVENT_CLICKED, Pack(-1));
  lv_obj_add_event_cb(plus, OnMicGainStep, LV_EVENT_CLICKED, Pack(1));
  ShowMicGain();
  SetGlyphColor(g.mic_glyph, kText);
}

// --- Messages ------------------------------------------------------------------------------------

void FormatAge(char* out, std::size_t size, int seconds) {
  if (seconds < 60) {
    std::snprintf(out, size, "just now");
  } else if (seconds < 3600) {
    std::snprintf(out, size, "%d min ago", seconds / 60);
  } else {
    std::snprintf(out, size, "%d h ago", seconds / 3600);
  }
}

std::uint32_t KindColor(MessageKind kind) {
  switch (kind) {
    case MessageKind::kAlert: return kError;
    case MessageKind::kQuestion: return kKeepAwakeColor;
    default: return kMessagesColor;
  }
}

void OnMessageTap(lv_event_t* event) { Emit(Action::kMessageRead, Unpack(event)); }
void OnMessageAnswer(lv_event_t* event) { Emit(Action::kMessageAnswer, Unpack(event)); }
void OnMessagesClear(lv_event_t*) { Emit(Action::kMessagesClear, 0); }

// One message: kind badge, text, age; a question carries Yes and No until it is answered.
void MessageCard(lv_obj_t* parent, const MessageRow& row, int index) {
  constexpr int kBadge = 44;
  constexpr int kTextLeft = 14 + kBadge + 12;
  const bool fresh = row.state == MessageState::kNew;
  const bool question = row.kind == MessageKind::kQuestion;
  const std::uint32_t accent = KindColor(row.kind);
  lv_obj_t* card = Button(parent, kInnerWidth, LV_SIZE_CONTENT);
  lv_obj_set_style_pad_ver(card, 14, 0);
  lv_obj_set_style_pad_left(card, kTextLeft, 0);
  lv_obj_set_style_pad_right(card, 14, 0);
  lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(card, 6, 0);
  if (fresh) {
    lv_obj_set_style_border_color(card, lv_color_hex(accent), 0);
    lv_obj_set_style_border_width(card, 3, 0);
  }
  const char* symbol = row.kind == MessageKind::kAlert ? LV_SYMBOL_WARNING
                       : question                      ? "?"
                                                       : LV_SYMBOL_BELL;
  lv_obj_t* badge = Badge(card, symbol, accent, kBadge, kBody);
  lv_obj_set_ignore_layout(badge, true);
  lv_obj_align(badge, LV_ALIGN_TOP_LEFT, 14 - kTextLeft, 0);
  lv_obj_t* text = Label(card, kBody, kText, row.text);
  lv_obj_set_width(text, LV_PCT(100));
  lv_label_set_long_mode(text, LV_LABEL_LONG_MODE_WRAP);
  char age[32];
  FormatAge(age, sizeof(age), row.age_seconds);
  g.msg_ages[index] = Label(card, kSmall, fresh ? accent : kMuted, age);
  if (!question) {
    lv_obj_add_event_cb(card, OnMessageTap, LV_EVENT_CLICKED, Pack(static_cast<int>(row.id)));
    return;
  }
  lv_obj_set_clickable(card, false);  // only its answers take a tap
  if (row.state == MessageState::kAnsweredYes || row.state == MessageState::kAnsweredNo) {
    Label(card, kBody, kKeepAwakeColor, row.state == MessageState::kAnsweredYes ? LV_SYMBOL_OK "  Answered Yes"
                                                                                : LV_SYMBOL_CLOSE "  Answered No");
    return;
  }
  lv_obj_t* answers = Plain(card);
  lv_obj_set_size(answers, LV_PCT(100), kControl);
  lv_obj_set_flex_flow(answers, LV_FLEX_FLOW_ROW);
  lv_obj_set_style_pad_column(answers, 8, 0);
  const char* names[2] = {"Yes", "No"};
  for (int i = 0; i < 2; ++i) {
    lv_obj_t* answer = Button(answers, 0, kControl);
    lv_obj_set_flex_grow(answer, 1);
    lv_obj_center(Label(answer, kBody, kText, names[i]));
    if (i == 0) SetSelected(answer, true, kKeepAwakeColor);
    lv_obj_add_event_cb(answer, OnMessageAnswer, LV_EVENT_CLICKED,
                        Pack(static_cast<int>(row.id << 1 | (i == 0 ? 1U : 0U))));
  }
}

void BuildMessages() {
  lv_obj_t* screen = NewScreen(Screen::kMessages);
  Header(screen, "Messages");
  g.msg_clear = Button(screen, kControl, kControl);
  lv_obj_set_pos(g.msg_clear, kWidth - kMargin - kControl, kMargin);
  lv_obj_center(Label(g.msg_clear, kTitle, kText, LV_SYMBOL_TRASH));
  lv_obj_add_event_cb(g.msg_clear, OnMessagesClear, LV_EVENT_CLICKED, nullptr);
  lv_obj_t* list = ScrollList(screen);
  g.msg_status = Label(list, kSmall, kMuted, "");
  lv_obj_set_style_pad_left(g.msg_status, 6, 0);
  g.msg_rows = Plain(list);
  lv_obj_set_size(g.msg_rows, kInnerWidth, LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(g.msg_rows, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(g.msg_rows, 8, 0);
  AddFade(list);

  g.msg_empty = Plain(screen);
  lv_obj_set_size(g.msg_empty, kInnerWidth, 230);
  lv_obj_align(g.msg_empty, LV_ALIGN_TOP_MID, 0, kContentTop + 50);
  lv_obj_set_flex_flow(g.msg_empty, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(g.msg_empty, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(g.msg_empty, 12, 0);
  Badge(g.msg_empty, LV_SYMBOL_ENVELOPE, kMessagesColor, 96, kLarge);
  Label(g.msg_empty, kTitle, kText, "No messages");
  g.msg_empty_detail = Label(g.msg_empty, kSmall, kMuted, "");
  lv_obj_set_width(g.msg_empty_detail, kInnerWidth);
  lv_obj_set_style_text_align(g.msg_empty_detail, LV_TEXT_ALIGN_CENTER, 0);
}

// --- USB Drive -----------------------------------------------------------------------------------

enum DriveView : int { kDriveListView, kDriveDetailView, kDriveExportView, kDriveCreateView };

// Binary units with the familiar names, as computers show them: 64 MB, 1.0 GB.
void FormatSize(char* out, std::size_t size, std::uint64_t bytes) {
  if (bytes >= (1ULL << 30)) {
    const auto tenths = static_cast<unsigned>((bytes * 10) >> 30);
    std::snprintf(out, size, "%u.%u GB", tenths / 10, tenths % 10);
  } else {
    std::snprintf(out, size, "%u MB", static_cast<unsigned>(bytes >> 20));
  }
}

void ShowDriveView(int view) {
  g.drive_view = view;
  for (int i = 0; i < 4; ++i) lv_obj_set_hidden(g.drive_views[i], i != view);
  // The corner button goes back from a drive's page and New drive; elsewhere it is Home.
  const bool back = view == kDriveDetailView || view == kDriveCreateView;
  lv_label_set_text(g.drive_back_icon, back ? LV_SYMBOL_LEFT : LV_SYMBOL_HOME);
  lv_label_set_text(g.drive_title, view == kDriveCreateView ? "New drive" : "USB Drive");
}

int g_disconnect_target = 0;

void AskDisconnect(int target) {
  if (g.export_needs_eject) {
    g_disconnect_target = target;
    lv_obj_set_hidden(g.export_confirm, false);
  } else {
    Emit(Action::kDriveDisconnect, target);
  }
}

void OnDriveCorner(lv_event_t*) {
  switch (g.drive_view) {
    case kDriveDetailView: ShowDriveView(kDriveListView); break;
    case kDriveCreateView:
      if (!g.create_busy) ShowDriveView(kDriveListView);
      break;
    case kDriveExportView: AskDisconnect(0); break;
    default: Emit(Action::kLeave, 0); break;
  }
}

void OnConfirm(lv_event_t* event) {
  lv_obj_set_hidden(g.export_confirm, true);
  if (Unpack(event) == 1) Emit(Action::kDriveDisconnect, g_disconnect_target);
}

// detail_modes[0] is Writable, [1] Read-only.
void ShowModes() {
  SetSelected(g.detail_modes[0], g.drive_writable, kDriveColor);
  SetSelected(g.detail_modes[1], !g.drive_writable, kDriveColor);
  lv_label_set_text(g.detail_hint, g.drive_writable
                                       ? "The computer can save to it.\nEject it there before unplugging."
                                       : "The computer can open files\nbut not change them.");
}

void OnMode(lv_event_t* event) {
  g.drive_writable = Unpack(event) == 0;
  ShowModes();
}

void OnConnect(lv_event_t*) {
  Emit(Action::kDriveConnect, g.drive_selected | (g.drive_writable ? 1 << 8 : 0));
}

void OpenDetail(int index) {
  if (index < 0 || index >= g.drive_count) return;
  g.drive_selected = index;
  g.drive_writable = true;
  const DriveRow& row = g.drive_list[index];
  lv_label_set_text(g.detail_name, row.name);
  char size[24];
  FormatSize(size, sizeof(size), row.bytes);
  lv_label_set_text(g.detail_size, size);
  lv_obj_set_style_text_color(g.detail_warning, lv_color_hex(kKeepAwakeColor), 0);
  lv_label_set_text(g.detail_warning,
                    row.dirty ? "Not ejected cleanly last time. Connect it writable so the "
                                "computer can repair it."
                              : "");
  ShowModes();
  ShowDriveView(kDriveDetailView);
}

void OnDriveRow(lv_event_t* event) { OpenDetail(Unpack(event)); }

void ShowCreateChoices() {
  for (int i = 0; i < kDriveSizeChoices; ++i) {
    SetSelected(g.create_chips[i], i == g.create_size, kDriveColor);
  }
  // About 2 MB/s on this card bus, plus formatting.
  const int seconds = kDriveSizesMiB[g.create_size] / 2 + 5;
  char free_text[24];
  FormatSize(free_text, sizeof(free_text), g.drive_free);
  if (seconds < 90) {
    lv_label_set_text_fmt(g.create_info, "FAT32   " LV_SYMBOL_BULLET "   about %d s   " LV_SYMBOL_BULLET
                                         "   %s free",
                          seconds, free_text);
  } else {
    lv_label_set_text_fmt(g.create_info, "FAT32   " LV_SYMBOL_BULLET "   about %d min   " LV_SYMBOL_BULLET
                                         "   %s free",
                          (seconds + 30) / 60, free_text);
  }
}

void OnCreateSize(lv_event_t* event) {
  if (g.create_busy) return;
  g.create_size = Unpack(event);
  ShowCreateChoices();
}

void OnCreateButton(lv_event_t*) {
  Emit(g.create_busy ? Action::kDriveCancelCreate : Action::kDriveCreate, g.create_size);
}

void OnOpenCreate(lv_event_t*) {
  ShowCreateChoices();
  lv_label_set_text(g.create_message, "");
  ShowDriveView(kDriveCreateView);
}

lv_obj_t* DriveView(lv_obj_t* screen) {
  lv_obj_t* view = Plain(screen);
  lv_obj_set_pos(view, 0, 0);
  lv_obj_set_size(view, kWidth, kHeight);
  lv_obj_set_hidden(view, true);
  return view;
}

void BuildDriveList(lv_obj_t* view) {
  lv_obj_t* list = ScrollList(view);
  g.drive_status = Label(list, kBody, kMuted, "Looking for the SD card...");
  lv_obj_set_width(g.drive_status, kInnerWidth - 16);
  lv_obj_set_style_pad_all(g.drive_status, 8, 0);
  g.drive_retry = Button(list, kInnerWidth, kControl);
  lv_obj_center(Label(g.drive_retry, kBody, kText, LV_SYMBOL_REFRESH "   Try again"));
  lv_obj_add_event_cb(g.drive_retry, OnAction, LV_EVENT_CLICKED,
                      Pack(static_cast<int>(Action::kDriveRescan)));
  lv_obj_set_hidden(g.drive_retry, true);
  g.drive_rows = Plain(list);
  lv_obj_set_size(g.drive_rows, kInnerWidth, LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(g.drive_rows, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(g.drive_rows, 8, 0);
  g.drive_new = RowButtonWithDetail(list, LV_SYMBOL_PLUS, kDriveColor, "New drive", "", kMuted);
  g.drive_new_detail = lv_obj_get_child(g.drive_new, 2);
  lv_obj_add_event_cb(g.drive_new, OnOpenCreate, LV_EVENT_CLICKED, nullptr);
  lv_obj_set_hidden(g.drive_new, true);
  AddFade(list);
}

void BuildDriveDetail(lv_obj_t* view) {
  lv_obj_t* badge = Badge(view, LV_SYMBOL_DRIVE, kDriveColor, 64, kTitle);
  lv_obj_set_pos(badge, kMargin + 4, kContentTop + 4);
  g.detail_name = Label(view, kTitle, kText, "");
  lv_obj_set_width(g.detail_name, kInnerWidth - 88);
  lv_label_set_long_mode(g.detail_name, LV_LABEL_LONG_MODE_DOTS);
  lv_obj_set_height(g.detail_name, lv_font_get_line_height(kTitle));
  lv_obj_set_pos(g.detail_name, kMargin + 84, kContentTop + 2);
  g.detail_size = Label(view, kBody, kMuted, "");
  lv_obj_set_pos(g.detail_size, kMargin + 84, kContentTop + 40);
  g.detail_warning = Label(view, kSmall, kKeepAwakeColor, "");
  lv_obj_set_width(g.detail_warning, kInnerWidth - 8);
  lv_obj_set_pos(g.detail_warning, kMargin + 4, kContentTop + 80);
  const char* modes[2] = {LV_SYMBOL_EDIT "  Writable", LV_SYMBOL_EYE_OPEN "  Read-only"};
  for (int i = 0; i < 2; ++i) {
    lv_obj_t* button = Button(view, kHalfWidth, kControl);
    lv_obj_set_pos(button, kMargin + i * (kHalfWidth + kGap), 224);
    lv_obj_center(Label(button, kBody, kText, modes[i]));
    lv_obj_add_event_cb(button, OnMode, LV_EVENT_CLICKED, Pack(i));
    g.detail_modes[i] = button;
  }
  g.detail_hint = Label(view, kSmall, kMuted, "");
  lv_obj_set_width(g.detail_hint, kInnerWidth);
  lv_obj_set_style_text_align(g.detail_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_pos(g.detail_hint, kMargin, 306);
  lv_obj_add_event_cb(WideButton(view, "Connect", kDriveColor), OnConnect, LV_EVENT_CLICKED, nullptr);
}

void BuildDriveExport(lv_obj_t* view) {
  constexpr int kRing = 140;
  g.export_ring = Plain(view);
  lv_obj_set_size(g.export_ring, kRing, kRing);
  lv_obj_align(g.export_ring, LV_ALIGN_TOP_MID, 0, kContentTop + 4);
  lv_obj_set_style_radius(g.export_ring, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(g.export_ring, lv_color_hex(kCard), 0);
  lv_obj_set_style_bg_opa(g.export_ring, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(g.export_ring, 6, 0);
  lv_obj_set_style_border_color(g.export_ring, lv_color_hex(kBorder), 0);
  lv_obj_set_style_outline_color(g.export_ring, lv_color_hex(kDriveColor), 0);
  g.export_icon = Label(g.export_ring, kLarge, kMuted, LV_SYMBOL_USB);
  lv_obj_center(g.export_icon);
  g.export_name = Label(view, kTitle, kText, "");
  lv_obj_set_width(g.export_name, kInnerWidth);
  lv_obj_set_style_text_align(g.export_name, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_pos(g.export_name, kMargin, kContentTop + kRing + 12);
  g.export_status = Label(view, kBody, kText, "");
  lv_obj_set_width(g.export_status, kInnerWidth);
  lv_obj_set_style_text_align(g.export_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_pos(g.export_status, kMargin, kContentTop + kRing + 52);
  g.export_detail = Label(view, kSmall, kMuted, "");
  lv_obj_set_width(g.export_detail, kInnerWidth);
  lv_obj_set_style_text_align(g.export_detail, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_pos(g.export_detail, kMargin, kContentTop + kRing + 82);
  lv_obj_add_event_cb(WideButton(view, "Disconnect", 0), [](lv_event_t*) { AskDisconnect(1); },
                      LV_EVENT_CLICKED, nullptr);
}

// Covers the screen until answered: unplugging a writable drive the computer has not ejected
// can lose what it has not written yet.
void BuildDisconnectConfirm(lv_obj_t* screen) {
  g.export_confirm = Plain(screen);
  lv_obj_set_size(g.export_confirm, kWidth, kHeight);
  lv_obj_set_clickable(g.export_confirm, true);  // nothing underneath takes a tap meanwhile
  lv_obj_set_style_bg_color(g.export_confirm, lv_color_hex(kBlack), 0);
  lv_obj_set_style_bg_opa(g.export_confirm, LV_OPA_COVER, 0);
  lv_obj_t* text = Label(g.export_confirm, kBody, kText,
                         "Eject the drive on the computer first.\n\n"
                         "Disconnecting now can lose changes the computer has not saved yet.");
  lv_obj_set_width(text, kInnerWidth - 16);
  lv_obj_set_pos(text, kMargin + 8, 40);
  lv_obj_t* keep = Button(g.export_confirm, kInnerWidth, 80);
  lv_obj_align(keep, LV_ALIGN_BOTTOM_MID, 0, -kMargin - 80 - kGap);
  lv_obj_center(Label(keep, kTitle, kText, "Keep connected"));
  SetSelected(keep, true, kDriveColor);
  lv_obj_add_event_cb(keep, OnConfirm, LV_EVENT_CLICKED, Pack(0));
  lv_obj_t* leave = Button(g.export_confirm, kInnerWidth, 80);
  lv_obj_align(leave, LV_ALIGN_BOTTOM_MID, 0, -kMargin);
  lv_obj_t* leave_label = Label(leave, kBody, kError, "Disconnect anyway");
  lv_obj_center(leave_label);
  lv_obj_add_event_cb(leave, OnConfirm, LV_EVENT_CLICKED, Pack(1));
  lv_obj_set_hidden(g.export_confirm, true);
}

void BuildDriveCreate(lv_obj_t* view) {
  lv_obj_t* caption = Label(view, kBody, kMuted, "Size");
  lv_obj_set_pos(caption, kMargin + 6, kContentTop + 4);
  constexpr int kChipWidth = (kInnerWidth - (kDriveSizeChoices - 1) * 8) / kDriveSizeChoices;
  for (int i = 0; i < kDriveSizeChoices; ++i) {
    lv_obj_t* chip = Button(view, kChipWidth, kControl);
    lv_obj_set_pos(chip, kMargin + i * (kChipWidth + 8), kContentTop + 36);
    char text[16];
    const int mib = kDriveSizesMiB[i];
    if (mib >= 1024) {
      std::snprintf(text, sizeof(text), "%d GB", mib / 1024);
    } else {
      std::snprintf(text, sizeof(text), "%d MB", mib);
    }
    lv_obj_center(Label(chip, kBody, kText, text));
    lv_obj_add_event_cb(chip, OnCreateSize, LV_EVENT_CLICKED, Pack(i));
    g.create_chips[i] = chip;
  }
  g.create_info = Label(view, kSmall, kMuted, "");
  lv_obj_set_width(g.create_info, kInnerWidth);
  lv_obj_set_style_text_align(g.create_info, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_pos(g.create_info, kMargin, kContentTop + 122);
  g.create_bar = lv_bar_create(view);
  lv_obj_set_size(g.create_bar, kInnerWidth, 14);
  lv_obj_set_pos(g.create_bar, kMargin, kContentTop + 172);
  lv_bar_set_range(g.create_bar, 0, 100);
  lv_obj_set_style_bg_color(g.create_bar, lv_color_hex(kDivider), LV_PART_MAIN);
  lv_obj_set_style_bg_color(g.create_bar, lv_color_hex(kDriveColor), LV_PART_INDICATOR);
  lv_obj_set_hidden(g.create_bar, true);
  g.create_message = Label(view, kBody, kText, "");
  lv_obj_set_width(g.create_message, kInnerWidth);
  lv_obj_set_style_text_align(g.create_message, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_pos(g.create_message, kMargin, kContentTop + 198);
  g.create_button = WideButton(view, "Create", kDriveColor);
  lv_obj_add_event_cb(g.create_button, OnCreateButton, LV_EVENT_CLICKED, nullptr);
}

void BuildDrive() {
  lv_obj_t* screen = NewScreen(Screen::kDrive);
  for (int i = 0; i < 4; ++i) g.drive_views[i] = DriveView(screen);
  BuildDriveList(g.drive_views[kDriveListView]);
  BuildDriveDetail(g.drive_views[kDriveDetailView]);
  BuildDriveExport(g.drive_views[kDriveExportView]);
  BuildDriveCreate(g.drive_views[kDriveCreateView]);
  // One corner button for every view: Home, or Back from a drive's page and New drive.
  lv_obj_t* corner = Button(screen, kHomeWidth, kControl);
  lv_obj_set_pos(corner, kMargin, kMargin);
  g.drive_back_icon = Label(corner, kTitle, kText, LV_SYMBOL_HOME);
  lv_obj_center(g.drive_back_icon);
  lv_obj_add_event_cb(corner, OnDriveCorner, LV_EVENT_CLICKED, nullptr);
  g.drive_title = Label(screen, kTitle, kText, "USB Drive");
  lv_obj_align_to(g.drive_title, corner, LV_ALIGN_OUT_RIGHT_MID, 16, 0);
  BuildDisconnectConfirm(screen);
  ShowDriveView(kDriveListView);
}

void OnWakeShield(lv_event_t* event) {
  if (lv_event_get_code(event) == LV_EVENT_PRESSED) Emit(Action::kWake, 0);
  if (lv_event_get_code(event) == LV_EVENT_RELEASED) lv_obj_set_hidden(g.wake_shield, true);
}

}  // namespace

void Build(const Config& config, Screen first) {
  g.config = config;
  InitStyles();
  lv_display_t* display = lv_display_get_default();
  lv_display_set_theme(display, lv_theme_default_init(display, lv_color_hex(kKeyferryColor),
                                                      lv_color_hex(kError), true, kBody));
  switch (first) {
    case Screen::kKeepAwake: BuildKeepAwake(); break;
    case Screen::kMacros: BuildMacros(); break;
    case Screen::kKeyferry: BuildKeyferry(); break;
    case Screen::kDrive: BuildDrive(); break;
    case Screen::kMic: BuildMic(); break;
    case Screen::kMessages: BuildMessages(); break;
    default:
      BuildHome();
      BuildCheck();
      BuildSettings();
      first = Screen::kHome;
      break;
  }
  g.wake_shield = lv_obj_create(lv_layer_top());
  lv_obj_remove_style_all(g.wake_shield);
  lv_obj_set_size(g.wake_shield, LV_PCT(100), LV_PCT(100));
  lv_obj_add_event_cb(g.wake_shield, OnWakeShield, LV_EVENT_PRESSED, nullptr);
  lv_obj_add_event_cb(g.wake_shield, OnWakeShield, LV_EVENT_RELEASED, nullptr);
  lv_obj_set_hidden(g.wake_shield, true);
  lv_screen_load(g.screens[static_cast<int>(first)]);
}

void Show(Screen screen) {
  lv_obj_t* target = g.screens[static_cast<int>(screen)];
  if (target == nullptr) return;
  lv_screen_load(target);
  Emit(Action::kShown, static_cast<int>(screen));
}

Screen Active() {
  lv_obj_t* active = lv_screen_active();
  for (int i = 0; i < kScreenCount; ++i) {
    if (g.screens[i] == active) return static_cast<Screen>(i);
  }
  return Screen::kHome;
}

void ShowWakeShield() {
  if (g.wake_shield == nullptr) return;
  lv_obj_set_hidden(g.wake_shield, false);
  // A finger already down when the screen goes black must not click what was under it on
  // release: LVGL drops that press (PRESS_LOST) and ignores the pointer until it lifts.
  for (lv_indev_t* indev = lv_indev_get_next(nullptr); indev != nullptr; indev = lv_indev_get_next(indev)) {
    if (lv_indev_get_type(indev) == LV_INDEV_TYPE_POINTER) lv_indev_wait_release(indev);
  }
}

void RefreshHome(const HomeView& view) {
  if (g.home_status == nullptr) return;
  if (view.battery_percent >= 0) {
    const char* symbol = view.battery_percent > 80   ? LV_SYMBOL_BATTERY_FULL
                         : view.battery_percent > 55 ? LV_SYMBOL_BATTERY_3
                         : view.battery_percent > 30 ? LV_SYMBOL_BATTERY_2
                         : view.battery_percent > 10 ? LV_SYMBOL_BATTERY_1
                                                     : LV_SYMBOL_BATTERY_EMPTY;
    lv_label_set_text_fmt(g.home_status, "%s%s %d%%", view.usb_power ? LV_SYMBOL_CHARGE " " : "",
                          symbol, view.battery_percent);
  } else {
    lv_label_set_text(g.home_status, view.usb_power ? LV_SYMBOL_USB : "");
  }
}

void RefreshCheck(const CheckView& view) {
  if (g.check_values[0] == nullptr) return;
  const char* values[4] = {view.buttons, view.power, view.storage, view.memory};
  for (int i = 0; i < 4; ++i) lv_label_set_text(g.check_values[i], values[i]);
}

void RefreshKeepAwake(const KeepAwakeView& view) {
  if (g.awake_button == nullptr) return;
  const bool timed = view.running && view.seconds_left >= 0 && view.timer_seconds > 0;
  if (timed) {
    // The time left fills the button; the ring drains with it.
    const int h = view.seconds_left / 3600;
    const int m = view.seconds_left / 60 % 60;
    const int s = view.seconds_left % 60;
    lv_obj_set_style_text_font(g.awake_icon, kTitle, 0);
    lv_obj_set_style_text_color(g.awake_icon, lv_color_hex(kText), 0);
    if (h > 0) {
      lv_label_set_text_fmt(g.awake_icon, "%d:%02d:%02d", h, m, s);
    } else {
      lv_label_set_text_fmt(g.awake_icon, "%d:%02d", m, s);
    }
    lv_obj_set_style_text_font(g.awake_label, kBody, 0);
    lv_obj_set_style_text_color(g.awake_label, lv_color_hex(kMuted), 0);
    lv_arc_set_range(g.awake_arc, 0, view.timer_seconds);
    lv_arc_set_value(g.awake_arc, view.seconds_left);
  } else {
    lv_obj_set_style_text_font(g.awake_icon, kLarge, 0);
    lv_obj_set_style_text_color(g.awake_icon, lv_color_hex(kKeepAwakeColor), 0);
    lv_label_set_text(g.awake_icon, view.running ? LV_SYMBOL_PAUSE : LV_SYMBOL_PLAY);
    lv_obj_set_style_text_font(g.awake_label, kTitle, 0);
    lv_obj_set_style_text_color(g.awake_label, lv_color_hex(kText), 0);
    // Until stopped: the ring counts down to the next nudge.
    lv_arc_set_range(g.awake_arc, 0, view.interval_seconds);
    lv_arc_set_value(g.awake_arc, view.running && view.seconds_to_next >= 0
                                      ? view.interval_seconds - view.seconds_to_next
                                      : 0);
  }
  lv_label_set_text(g.awake_label, view.running ? "Stop" : "Start");
  lv_obj_set_style_border_color(g.awake_button, lv_color_hex(view.running ? kKeepAwakeColor : kBorder), 0);
  lv_obj_set_style_text_color(g.awake_state, lv_color_hex(view.stopped_by_fault ? kError : kText), 0);
  if (view.running && view.seconds_to_next >= 0) {
    lv_label_set_text_fmt(g.awake_state, "%s   " LV_SYMBOL_BULLET "   next nudge in %d s", view.state,
                          view.seconds_to_next);
  } else {
    lv_label_set_text(g.awake_state, view.state);
  }
  if (!view.usb) {
    lv_label_set_text(g.awake_detail, "Not connected to a computer");
  } else if (view.running || view.nudges > 0) {
    lv_label_set_text_fmt(g.awake_detail, LV_SYMBOL_USB " Connected   " LV_SYMBOL_BULLET "   %u nudge%s",
                          static_cast<unsigned>(view.nudges), view.nudges == 1 ? "" : "s");
  } else {
    lv_label_set_text_fmt(g.awake_detail, "Nudges the pointer 1 px every %d s",
                          view.interval_seconds);
  }
  if (view.nudges > g.awake_nudges) Pulse();
  g.awake_nudges = view.nudges;
}

void RefreshMacros(const MacrosView& view) {
  if (g.macro_pages == nullptr) return;
  if (view.busy != g.macro_busy) {
    for (int value : {g.macro_busy, view.busy}) {
      const int page = value >> 8;
      const int index = value & 0xFF;
      if (value < 0 || page >= macros::kMaxPages || index >= macros::kMaxPerPage) continue;
      lv_obj_t* button = g.macro_buttons[page][index];
      if (button == nullptr) continue;
      if (value == view.busy) {
        lv_obj_add_state(button, LV_STATE_CHECKED);
      } else {
        lv_obj_remove_state(button, LV_STATE_CHECKED);
      }
    }
    g.macro_busy = view.busy;
  }
  const bool notice = view.notice != nullptr;
  lv_obj_set_hidden(g.macro_notice, !notice);
  lv_obj_set_hidden(g.macro_dots, notice);
  if (notice) {
    // Setting the same text again would restart the scroll of a long notice.
    if (std::strcmp(lv_label_get_text(g.macro_notice), view.notice) != 0) {
      lv_label_set_text(g.macro_notice, view.notice);
    }
    lv_obj_set_style_text_color(g.macro_notice, lv_color_hex(view.notice_is_error ? kError : kMuted), 0);
  }
}

void SetKeyferryText(const char* text) {
  if (g.keyferry_state == nullptr) return;
  char state[48];
  const char* rest = std::strchr(text, '\n');
  const std::size_t length = rest == nullptr ? std::strlen(text) : static_cast<std::size_t>(rest - text);
  std::snprintf(state, sizeof(state), "%.*s", static_cast<int>(length), text);
  lv_label_set_text(g.keyferry_state, state);
  // The rest, without the trailing line break.
  char detail[192];
  std::snprintf(detail, sizeof(detail), "%s", rest == nullptr ? "" : rest + 1);
  const std::size_t end = std::strlen(detail);
  if (end > 0 && detail[end - 1] == '\n') detail[end - 1] = '\0';
  lv_label_set_text(g.keyferry_detail, detail);
}

void RefreshMic(const MicView& view) {
  if (g.mic_button == nullptr) return;
  g.mic_muted = view.muted;
  const bool silent = view.muted || view.host_muted;
  SetGlyphColor(g.mic_glyph, view.fault || silent ? kMuted : view.live ? kMicColor : kText);
  lv_obj_set_hidden(g.mic_slash, !silent);
  lv_label_set_text(g.mic_label, view.muted ? "Unmute" : "Mute");
  lv_arc_set_value(g.mic_arc, view.fault ? 0 : view.level);
  lv_obj_set_style_arc_color(g.mic_arc, lv_color_hex(silent ? kMuted : kMicColor), LV_PART_INDICATOR);
  lv_obj_set_style_border_color(g.mic_button, lv_color_hex(view.live && !silent ? kMicColor : kBorder), 0);
  // Live is shown whenever the computer has the stream open, muted or not.
  std::uint32_t color = kText;
  const char* state = "Ready";
  const char* detail = "Choose it as the computer's microphone.";
  if (view.fault) {
    color = kError;
    state = "Microphone not responding";
    detail = "It is off. Go Home and open Microphone again.";
  } else if (!view.usb) {
    state = "Not connected";
    detail = "Plug the board into a computer.";
  } else if (view.live) {
    color = silent ? kKeepAwakeColor : kMicColor;
    state = view.muted        ? LV_SYMBOL_BULLET " Live, muted here"
            : view.host_muted ? LV_SYMBOL_BULLET " Live, muted on the computer"
                              : LV_SYMBOL_BULLET " Live";
    detail = silent ? "The computer hears silence." : "The computer is listening.";
  } else if (view.muted) {
    color = kKeepAwakeColor;
    state = "Muted";
    detail = "Tap the microphone to unmute.";
  } else if (view.host_muted) {
    color = kKeepAwakeColor;
    state = "Muted on the computer";
    detail = "Unmute it in the computer's sound settings.";
  }
  lv_obj_set_style_text_color(g.mic_state, lv_color_hex(color), 0);
  lv_label_set_text(g.mic_state, state);
  lv_label_set_text(g.mic_detail, detail);
}

void RefreshMessages(const MessagesView& view) {
  if (g.msg_rows == nullptr) return;
  const int count = view.count < 16 ? view.count : 16;
  if (!view.usb) {
    lv_label_set_text(g.msg_status, "Not connected to a computer");
  } else if (view.listening) {
    lv_label_set_text(g.msg_status, LV_SYMBOL_BULLET " A program is connected");
  } else {
    lv_label_set_text(g.msg_status, LV_SYMBOL_USB " Connected: waiting for messages");
  }
  lv_obj_set_style_text_color(g.msg_status, lv_color_hex(view.listening ? kMessagesColor : kMuted), 0);
  lv_label_set_text(g.msg_empty_detail, view.usb ? "What programs on the computer send to the Keyferry Messages port shows here."
                                                 : "Plug the board into a computer.");
  lv_obj_set_hidden(g.msg_empty, count > 0);
  lv_obj_set_hidden(g.msg_status, count == 0);
  if (count > 0) {
    lv_obj_remove_state(g.msg_clear, LV_STATE_DISABLED);
  } else {
    lv_obj_add_state(g.msg_clear, LV_STATE_DISABLED);
  }
  // Rebuild only when the messages or their states change; otherwise just age them.
  std::uint32_t signature = 2166136261U;
  for (int i = 0; i < count; ++i) {
    signature = (signature ^ view.rows[i].id) * 16777619U;
    signature = (signature ^ static_cast<std::uint32_t>(view.rows[i].state)) * 16777619U;
  }
  signature ^= static_cast<std::uint32_t>(count);
  if (signature != g.msg_signature || count != g.msg_shown) {
    g.msg_signature = signature;
    g.msg_shown = count;
    lv_obj_clean(g.msg_rows);
    for (int i = 0; i < count; ++i) MessageCard(g.msg_rows, view.rows[i], i);
    return;
  }
  for (int i = 0; i < count; ++i) {
    char age[32];
    FormatAge(age, sizeof(age), view.rows[i].age_seconds);
    lv_label_set_text(g.msg_ages[i], age);
  }
}

void SetDriveList(const DriveListView& view) {
  if (g.drive_rows == nullptr) return;
  g.drive_free = view.free_bytes;
  g.drive_count = view.count < 8 ? view.count : 8;
  for (int i = 0; i < g.drive_count; ++i) {
    std::snprintf(g.drive_names[i], sizeof(g.drive_names[i]), "%s", view.rows[i].name);
    g.drive_list[i] = DriveRow{g.drive_names[i], view.rows[i].bytes, view.rows[i].dirty};
  }
  const bool ready = view.card == DriveCard::kReady;
  const char* status = nullptr;
  switch (view.card) {
    case DriveCard::kChecking: status = "Looking for the SD card..."; break;
    case DriveCard::kNoCard: status = "No SD card found.\nInsert a card, then try again."; break;
    case DriveCard::kError: status = "The SD card could not be read.\nIt needs to be formatted FAT32 on a computer."; break;
    case DriveCard::kReady:
      if (g.drive_count == 0) {
        status = "No drives yet. Make one below, or copy .IMG files into the DRIVES folder on the card.";
      }
      break;
  }
  lv_obj_set_hidden(g.drive_status, status == nullptr);
  if (status != nullptr) lv_label_set_text(g.drive_status, status);
  lv_obj_set_hidden(g.drive_retry, view.card != DriveCard::kNoCard && view.card != DriveCard::kError);
  lv_obj_clean(g.drive_rows);
  for (int i = 0; i < g.drive_count; ++i) {
    const DriveRow& row = g.drive_list[i];
    char detail[64];
    char size[24];
    FormatSize(size, sizeof(size), row.bytes);
    if (row.dirty) {
      std::snprintf(detail, sizeof(detail), "%s   " LV_SYMBOL_WARNING " not ejected", size);
    } else {
      std::snprintf(detail, sizeof(detail), "%s", size);
    }
    lv_obj_t* button = RowButtonWithDetail(g.drive_rows, LV_SYMBOL_DRIVE, kDriveColor, row.name, detail,
                                      row.dirty ? kKeepAwakeColor : kMuted);
    lv_obj_add_event_cb(button, OnDriveRow, LV_EVENT_CLICKED, Pack(i));
  }
  lv_obj_set_hidden(g.drive_new, !ready);
  char free_text[24];
  FormatSize(free_text, sizeof(free_text), view.free_bytes);
  lv_label_set_text_fmt(g.drive_new_detail, "%s free on the card", free_text);
}

void ShowDriveDetail(int index) {
  if (g.drive_rows != nullptr) OpenDetail(index);
}

void ShowDriveCreate() {
  if (g.drive_rows != nullptr) OnOpenCreate(nullptr);
}

void ShowDriveError(const char* text) {
  if (g.detail_warning == nullptr) return;
  lv_obj_set_style_text_color(g.detail_warning, lv_color_hex(kError), 0);
  lv_label_set_text(g.detail_warning, text);
}

void ShowDriveExport(const DriveExportView& view) {
  if (g.export_ring == nullptr) return;
  if (!g.export_shown) {
    g.export_shown = true;
    ShowDriveView(kDriveExportView);
  }
  lv_label_set_text(g.export_name, view.name);
  std::uint32_t ring = kBorder;
  std::uint32_t status_color = kText;
  const char* status = "";
  switch (view.link) {
    case DriveLink::kWaiting: status = "Waiting for a computer"; break;
    case DriveLink::kConnected:
      ring = kDriveColor;
      status = view.busy ? (view.writable ? "In use: reading or writing" : "In use: reading") : "Connected";
      break;
    case DriveLink::kEjected:
      ring = kKeyferryColor;
      status = "Ejected: safe to unplug";
      status_color = kDriveColor;
      break;
    case DriveLink::kStopped: status = "Disconnected"; break;
    case DriveLink::kFailed:
      ring = kError;
      status = "Card error: drive stopped";
      status_color = kError;
      break;
  }
  lv_obj_set_style_border_color(g.export_ring, lv_color_hex(ring), 0);
  lv_obj_set_style_text_color(g.export_icon, lv_color_hex(ring == kBorder ? kMuted : ring), 0);
  // Activity: a soft glow around the ring while data moves.
  lv_obj_set_style_outline_width(g.export_ring, view.busy ? 8 : 0, 0);
  lv_obj_set_style_outline_opa(g.export_ring, LV_OPA_30, 0);
  lv_label_set_text(g.export_status, status);
  lv_obj_set_style_text_color(g.export_status, lv_color_hex(status_color), 0);
  char read[24];
  char written[24];
  FormatSize(read, sizeof(read), view.read_bytes);
  FormatSize(written, sizeof(written), view.written_bytes);
  if (view.link == DriveLink::kWaiting) {
    lv_label_set_text_fmt(g.export_detail, "%s   " LV_SYMBOL_BULLET "   plug into a computer",
                          view.writable ? "Writable" : "Read-only");
  } else if (view.marker_kept) {
    lv_label_set_text(g.export_detail, "Saved, but its not-ejected mark could not be cleared");
  } else if (view.writable) {
    lv_label_set_text_fmt(g.export_detail, "Writable   " LV_SYMBOL_BULLET "   read %s, wrote %s", read, written);
  } else {
    lv_label_set_text_fmt(g.export_detail, "Read-only   " LV_SYMBOL_BULLET "   read %s", read);
  }
  g.export_needs_eject = view.writable && view.link == DriveLink::kConnected;
}

void ShowDisconnectConfirm() {
  if (g.export_confirm == nullptr) return;
  g_disconnect_target = 1;
  lv_obj_set_hidden(g.export_confirm, false);
}

void RefreshDriveCreate(const DriveCreateView& view) {
  if (g.create_button == nullptr) return;
  const bool finished = view.finished && !view.busy;
  g.create_busy = view.busy;
  lv_obj_set_hidden(g.create_bar, !view.busy);
  lv_bar_set_value(g.create_bar, view.percent, LV_ANIM_OFF);
  lv_label_set_text(lv_obj_get_child(g.create_button, 0), view.busy ? "Cancel" : "Create");
  SetSelected(g.create_button, !view.busy, kDriveColor);
  for (lv_obj_t* chip : g.create_chips) {
    if (view.busy) {
      lv_obj_add_state(chip, LV_STATE_DISABLED);
    } else {
      lv_obj_remove_state(chip, LV_STATE_DISABLED);
    }
  }
  if (view.busy) {
    lv_label_set_text_fmt(g.create_message, "%s  %d%%", view.message, view.percent);
    lv_obj_set_style_text_color(g.create_message, lv_color_hex(kText), 0);
  } else if (finished && view.result == 1) {
    ShowDriveView(kDriveListView);  // the new drive is in the list, ready to connect
  } else if (finished) {
    lv_label_set_text(g.create_message, view.message);
    lv_obj_set_style_text_color(g.create_message, lv_color_hex(kError), 0);
  }
}

}  // namespace keyferry::handheld::ui
