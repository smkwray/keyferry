// Handheld screens: one dark theme, big targets (nothing under 72 px tall, about 6 mm on this
// panel), tinted icon tiles and a Home button in the same top-left place on every screen.
#include "ui.h"

#include <cstdint>
#include <cstring>
#include <initializer_list>

namespace keyferry::handheld::ui {
namespace {

constexpr std::uint32_t kBlack = 0x000000;
constexpr std::uint32_t kSurface = 0x16181D;
constexpr std::uint32_t kSurfacePressed = 0x2B2F38;
constexpr std::uint32_t kBorder = 0x2A2E37;
constexpr std::uint32_t kText = 0xF2F4F8;
constexpr std::uint32_t kMuted = 0x9AA3B2;
constexpr std::uint32_t kError = 0xFF6B6B;
constexpr std::uint32_t kKeyferryColor = 0x4C8DFF;
constexpr std::uint32_t kKeepAwakeColor = 0xFFB020;
constexpr std::uint32_t kMacrosColor = 0xA970FF;
constexpr std::uint32_t kDriveColor = 0x2ECC8F;
constexpr std::uint32_t kCheckColor = 0x22C3E6;
constexpr std::uint32_t kSettingsColor = 0x8C96A8;

const lv_font_t* const kSmall = &lv_font_montserrat_16;
const lv_font_t* const kBody = &lv_font_montserrat_20;
const lv_font_t* const kTitle = &lv_font_montserrat_28;
const lv_font_t* const kLarge = &lv_font_montserrat_40;

constexpr int kMargin = 12;
constexpr int kGap = 10;
constexpr int kRadius = 22;
constexpr int kHomeWidth = 88;
constexpr int kHomeHeight = 72;
constexpr int kContentTop = kMargin + kHomeHeight + 10;
constexpr int kHalfWidth = (kWidth - 2 * kMargin - kGap) / 2;

struct State {
  Config config;
  lv_obj_t* screens[6] = {};
  lv_obj_t* wake_shield = nullptr;
  lv_obj_t* home_status = nullptr;
  lv_obj_t* touch_dot = nullptr;
  lv_obj_t* touch_label = nullptr;
  lv_obj_t* buttons_label = nullptr;
  lv_obj_t* power_label = nullptr;
  lv_obj_t* storage_label = nullptr;
  lv_obj_t* memory_label = nullptr;
  lv_obj_t* brightness_value = nullptr;
  int brightness = 60;
  lv_obj_t* host_buttons[2] = {};
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
  lv_obj_t* keyferry_text = nullptr;
};

State g;
lv_style_t g_screen_style;
lv_style_t g_card_style;
lv_style_t g_button_style;
lv_style_t g_pressed_style;
lv_style_t g_disabled_style;

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
  lv_style_set_bg_color(&g_card_style, lv_color_hex(kSurface));
  lv_style_set_bg_opa(&g_card_style, LV_OPA_COVER);
  lv_style_set_radius(&g_card_style, kRadius);
  lv_style_set_pad_all(&g_card_style, 16);

  lv_style_init(&g_button_style);
  lv_style_set_bg_color(&g_button_style, lv_color_hex(kSurface));
  lv_style_set_bg_opa(&g_button_style, LV_OPA_COVER);
  lv_style_set_radius(&g_button_style, kRadius);
  lv_style_set_border_width(&g_button_style, 2);
  lv_style_set_border_color(&g_button_style, lv_color_hex(kBorder));
  lv_style_set_text_color(&g_button_style, lv_color_hex(kText));

  lv_style_init(&g_pressed_style);
  lv_style_set_bg_color(&g_pressed_style, lv_color_hex(kSurfacePressed));
  lv_style_set_border_color(&g_pressed_style, lv_color_hex(kMuted));

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

lv_obj_t* Card(lv_obj_t* parent, int x, int y, int width, int height) {
  lv_obj_t* card = Plain(parent);
  lv_obj_add_style(card, &g_card_style, 0);
  lv_obj_set_pos(card, x, y);
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

// An icon over a name, centered; used by Home tiles and macro buttons.
void IconAndName(lv_obj_t* button, const char* symbol, const char* name, std::uint32_t color,
                 bool badge) {
  lv_obj_set_flex_flow(button, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(button, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(button, badge ? 10 : 6, 0);
  lv_obj_t* holder = button;
  if (badge) {
    holder = Plain(button);
    lv_obj_set_size(holder, 56, 56);
    lv_obj_set_style_radius(holder, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_bg_color(holder, lv_color_hex(color), 0);
    lv_obj_set_style_bg_opa(holder, LV_OPA_20, 0);
  }
  lv_obj_t* icon = Label(holder, kTitle, color, symbol);
  if (badge) lv_obj_center(icon);
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
  lv_obj_t* home = Button(screen, kHomeWidth, kHomeHeight);
  lv_obj_set_pos(home, kMargin, kMargin);
  lv_obj_center(Label(home, kTitle, kText, LV_SYMBOL_HOME));
  lv_obj_add_event_cb(home, OnHome, LV_EVENT_CLICKED, nullptr);
  lv_obj_t* label = Label(screen, kTitle, kText, title);
  lv_obj_align_to(label, home, LV_ALIGN_OUT_RIGHT_MID, 16, 0);
  return label;
}

void OnAction(lv_event_t* event) { Emit(static_cast<Action>(Unpack(event)), 0); }
void OnShow(lv_event_t* event) { Show(static_cast<Screen>(Unpack(event))); }

void AddTile(lv_obj_t* parent, int index, const char* symbol, const char* name, std::uint32_t color,
             lv_event_cb_t callback, int data, bool enabled) {
  constexpr int kTop = 72;
  constexpr int kTileHeight = (kHeight - kTop - kMargin - 2 * kGap) / 3;
  lv_obj_t* tile = Button(parent, kHalfWidth, kTileHeight);
  lv_obj_set_pos(tile, kMargin + (index % 2) * (kHalfWidth + kGap),
                 kTop + (index / 2) * (kTileHeight + kGap));
  IconAndName(tile, symbol, name, color, true);
  if (enabled) {
    lv_obj_add_event_cb(tile, callback, LV_EVENT_CLICKED, Pack(data));
  } else {
    lv_obj_add_state(tile, LV_STATE_DISABLED);
  }
}

void BuildHome() {
  lv_obj_t* screen = NewScreen(Screen::kHome);
  lv_obj_t* title = Label(screen, kTitle, kText, "Keyferry");
  lv_obj_set_pos(title, kMargin + 8, 20);
  g.home_status = Label(screen, kBody, kMuted, "");
  lv_obj_align(g.home_status, LV_ALIGN_TOP_RIGHT, -kMargin - 8, 24);
  AddTile(screen, 0, LV_SYMBOL_KEYBOARD, "Keyferry", kKeyferryColor, OnAction,
          static_cast<int>(Action::kLaunchKeyferry), g.config.keyferry);
  AddTile(screen, 1, LV_SYMBOL_EYE_OPEN, "Keep Awake", kKeepAwakeColor, OnAction,
          static_cast<int>(Action::kLaunchKeepAwake), true);
  AddTile(screen, 2, LV_SYMBOL_BARS, "Macros", kMacrosColor, OnAction,
          static_cast<int>(Action::kLaunchMacros), true);
  AddTile(screen, 3, LV_SYMBOL_SD_CARD, "USB Drive", kDriveColor, OnAction, 0, false);
  AddTile(screen, 4, LV_SYMBOL_LIST, "Board Check", kCheckColor, OnShow,
          static_cast<int>(Screen::kCheck), true);
  AddTile(screen, 5, LV_SYMBOL_SETTINGS, "Settings", kSettingsColor, OnShow,
          static_cast<int>(Screen::kSettings), true);
}

// --- Board Check ---------------------------------------------------------------------------------

void OnCheckTouch(lv_event_t* event) {
  lv_point_t point{};
  lv_indev_get_point(lv_indev_active(), &point);
  lv_obj_set_pos(g.touch_dot, point.x - 14, point.y - 14);
  lv_obj_set_hidden(g.touch_dot, false);
  lv_label_set_text_fmt(g.touch_label, "Touch  x %d  y %d", static_cast<int>(point.x),
                        static_cast<int>(point.y));
  if (lv_event_get_code(event) == LV_EVENT_PRESSED) {
    Emit(Action::kTouch, static_cast<int>(point.x) << 16 | static_cast<int>(point.y));
  }
}

void BuildCheck() {
  lv_obj_t* screen = NewScreen(Screen::kCheck);
  Header(screen, "Board Check");
  lv_obj_set_clickable(screen, true);
  lv_obj_add_event_cb(screen, OnCheckTouch, LV_EVENT_PRESSED, nullptr);
  lv_obj_add_event_cb(screen, OnCheckTouch, LV_EVENT_PRESSING, nullptr);
  lv_obj_t* card = Card(screen, kMargin, kContentTop, kWidth - 2 * kMargin, kHeight - kContentTop - kMargin);
  lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(card, 14, 0);
  g.touch_label = Label(card, kBody, kCheckColor, "Touch  tap anywhere");
  g.buttons_label = Label(card, kBody, kText, "");
  g.power_label = Label(card, kBody, kText, "");
  g.storage_label = Label(card, kBody, kText, "");
  g.memory_label = Label(card, kSmall, kMuted, "");
  for (lv_obj_t* label : {g.buttons_label, g.power_label, g.storage_label, g.memory_label}) {
    lv_obj_set_width(label, LV_PCT(100));
  }
  g.touch_dot = Plain(screen);
  lv_obj_set_size(g.touch_dot, 28, 28);
  lv_obj_set_style_radius(g.touch_dot, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(g.touch_dot, lv_color_hex(kCheckColor), 0);
  lv_obj_set_style_bg_opa(g.touch_dot, LV_OPA_COVER, 0);
  lv_obj_set_hidden(g.touch_dot, true);
}

// --- Settings ------------------------------------------------------------------------------------

constexpr int kRowHeight = 92;
constexpr int kControl = 72;

lv_obj_t* SettingsRow(lv_obj_t* screen, int row, const char* caption) {
  lv_obj_t* card = Card(screen, kMargin, kContentTop + row * (kRowHeight + 8), kWidth - 2 * kMargin,
                        kRowHeight);
  lv_obj_set_style_pad_all(card, 10, 0);
  lv_obj_set_style_pad_left(card, 18, 0);
  lv_obj_t* label = Label(card, kBody, kText, caption);
  lv_obj_align(label, LV_ALIGN_LEFT_MID, 0, 0);
  return card;
}

lv_obj_t* RowButton(lv_obj_t* row, int width, int x_from_right, const char* text) {
  lv_obj_t* button = Button(row, width, kControl);
  lv_obj_align(button, LV_ALIGN_RIGHT_MID, -x_from_right, 0);
  lv_obj_center(Label(button, kTitle, kText, text));
  return button;
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
  const int step = Unpack(event);
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

void ShowHost() {
  for (int i = 0; i < 2; ++i) {
    lv_obj_t* button = g.host_buttons[i];
    const bool selected = static_cast<int>(g.config.host) == i;
    lv_obj_set_style_bg_color(button, lv_color_hex(selected ? kMacrosColor : kSurface), 0);
    lv_obj_set_style_border_color(button, lv_color_hex(selected ? kMacrosColor : kBorder), 0);
    lv_obj_set_style_text_color(lv_obj_get_child(button, 0), lv_color_hex(selected ? kBlack : kText), 0);
  }
}

void OnHost(lv_event_t* event) {
  g.config.host = static_cast<macros::Host>(Unpack(event));
  ShowHost();
  Emit(Action::kMacroHost, static_cast<int>(g.config.host));
}

void OnStartInKeyferry(lv_event_t* event) {
  lv_obj_t* toggle = lv_event_get_target_obj(event);
  Emit(Action::kStartInKeyferry, lv_obj_has_state(toggle, LV_STATE_CHECKED) ? 1 : 0);
}

void BuildSettings() {
  lv_obj_t* screen = NewScreen(Screen::kSettings);
  Header(screen, "Settings");

  lv_obj_t* brightness = SettingsRow(screen, 0, "Brightness");
  g.brightness = g.config.brightness;
  lv_obj_t* plus = RowButton(brightness, kControl, 0, LV_SYMBOL_PLUS);
  lv_obj_t* minus = RowButton(brightness, kControl, kControl + 8, LV_SYMBOL_MINUS);
  for (lv_obj_t* button : {minus, plus}) {
    void* step = Pack(button == plus ? 10 : -10);
    lv_obj_add_event_cb(button, OnBrightnessStep, LV_EVENT_SHORT_CLICKED, step);
    lv_obj_add_event_cb(button, OnBrightnessStep, LV_EVENT_LONG_PRESSED, step);
    lv_obj_add_event_cb(button, OnBrightnessStep, LV_EVENT_LONG_PRESSED_REPEAT, step);
    lv_obj_add_event_cb(button, OnBrightnessStep, LV_EVENT_RELEASED, step);
  }
  lv_obj_align(lv_obj_get_child(brightness, 0), LV_ALIGN_TOP_LEFT, 0, 2);
  g.brightness_value = Label(brightness, kTitle, kKeepAwakeColor, "");
  lv_obj_align(g.brightness_value, LV_ALIGN_BOTTOM_LEFT, 0, -2);
  ShowBrightness();

  lv_obj_t* host = SettingsRow(screen, 1, "Macros for");
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

  int next_row = 2;
  if (g.config.keyferry) {
    lv_obj_t* start = SettingsRow(screen, next_row++, "Start in Keyferry");
    lv_obj_t* toggle = lv_switch_create(start);
    lv_obj_set_size(toggle, 96, 52);
    lv_obj_align(toggle, LV_ALIGN_RIGHT_MID, 0, 0);
    lv_obj_set_style_bg_color(toggle, lv_color_hex(kKeyferryColor),
                              static_cast<lv_style_selector_t>(LV_PART_INDICATOR) | LV_STATE_CHECKED);
    if (g.config.start_in_keyferry) lv_obj_add_state(toggle, LV_STATE_CHECKED);
    lv_obj_add_event_cb(toggle, OnStartInKeyferry, LV_EVENT_VALUE_CHANGED, nullptr);
  }
  lv_obj_t* hint = Label(screen, kSmall, kMuted,
                         "Screen sleeps after 20 s; a touch wakes it.\n"
                         "PWR: screen off/on.   BOOT: back to Home.");
  lv_obj_set_pos(hint, kMargin + 8, kContentTop + next_row * (kRowHeight + 8) + 6);
}

// --- Keep Awake ----------------------------------------------------------------------------------

void PulseStep(void* object, std::int32_t value) {
  lv_obj_t* button = static_cast<lv_obj_t*>(object);
  lv_obj_set_style_outline_width(button, value, 0);
  lv_obj_set_style_outline_opa(button, static_cast<lv_opa_t>(LV_OPA_COVER * (24 - value) / 24), 0);
}

void Pulse() {
  lv_anim_t animation;
  lv_anim_init(&animation);
  lv_anim_set_var(&animation, g.awake_button);
  lv_anim_set_values(&animation, 0, 24);
  lv_anim_set_duration(&animation, 700);
  lv_anim_set_exec_cb(&animation, PulseStep);
  lv_anim_start(&animation);
}

void BuildKeepAwake() {
  lv_obj_t* screen = NewScreen(Screen::kKeepAwake);
  Header(screen, "Keep Awake");
  constexpr int kArc = 228;
  constexpr int kCircle = 180;
  constexpr int kArcTop = kContentTop + 2;

  g.awake_arc = lv_arc_create(screen);
  lv_obj_set_size(g.awake_arc, kArc, kArc);
  lv_obj_align(g.awake_arc, LV_ALIGN_TOP_MID, 0, kArcTop);
  lv_arc_set_rotation(g.awake_arc, 270);
  lv_arc_set_bg_angles(g.awake_arc, 0, 360);
  lv_arc_set_range(g.awake_arc, 0, 25);
  lv_arc_set_value(g.awake_arc, 0);
  lv_obj_remove_style(g.awake_arc, nullptr, LV_PART_KNOB);
  lv_obj_set_clickable(g.awake_arc, false);
  lv_obj_set_style_arc_width(g.awake_arc, 10, LV_PART_MAIN);
  lv_obj_set_style_arc_color(g.awake_arc, lv_color_hex(kSurface), LV_PART_MAIN);
  lv_obj_set_style_arc_width(g.awake_arc, 10, LV_PART_INDICATOR);
  lv_obj_set_style_arc_color(g.awake_arc, lv_color_hex(kKeepAwakeColor), LV_PART_INDICATOR);

  g.awake_button = Button(screen, kCircle, kCircle);
  lv_obj_set_style_radius(g.awake_button, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_border_width(g.awake_button, 3, 0);
  lv_obj_set_style_outline_color(g.awake_button, lv_color_hex(kKeepAwakeColor), 0);
  lv_obj_align(g.awake_button, LV_ALIGN_TOP_MID, 0, kArcTop + (kArc - kCircle) / 2);
  lv_obj_set_flex_flow(g.awake_button, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(g.awake_button, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(g.awake_button, 6, 0);
  g.awake_icon = Label(g.awake_button, kLarge, kKeepAwakeColor, LV_SYMBOL_PLAY);
  g.awake_label = Label(g.awake_button, kTitle, kText, "Start");
  lv_obj_add_event_cb(g.awake_button, OnAction, LV_EVENT_CLICKED,
                      Pack(static_cast<int>(Action::kKeepAwakeToggle)));

  g.awake_state = Label(screen, kBody, kText, "Ready");
  lv_obj_set_width(g.awake_state, kWidth - 2 * kMargin);
  lv_obj_set_style_text_align(g.awake_state, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(g.awake_state, LV_ALIGN_TOP_MID, 0, kArcTop + kArc + 12);
  g.awake_detail = Label(screen, kSmall, kMuted, "");
  lv_obj_set_width(g.awake_detail, kWidth - 2 * kMargin);
  lv_obj_set_style_text_align(g.awake_detail, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(g.awake_detail, LV_ALIGN_TOP_MID, 0, kArcTop + kArc + 44);
}

// --- Macros --------------------------------------------------------------------------------------

void ShowMacroPage(int page) {
  if (page != g.macro_page) Emit(Action::kMacroPage, page);
  g.macro_page = page;
  lv_label_set_text(g.macro_title, macros::PageAt(page).name);
  const int pages = macros::PageCount();
  for (int i = 0; i < pages; ++i) {
    lv_obj_t* dot = lv_obj_get_child(g.macro_dots, i);
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

  lv_obj_t* next = Button(screen, kControl, kHomeHeight);
  lv_obj_align(next, LV_ALIGN_TOP_RIGHT, -kMargin, kMargin);
  lv_obj_center(Label(next, kTitle, kText, LV_SYMBOL_RIGHT));
  lv_obj_add_event_cb(next, OnNextPage, LV_EVENT_CLICKED, nullptr);

  const int pages = macros::PageCount();  // the table is bounded at compile time
  g.macro_dots = Plain(screen);
  lv_obj_set_size(g.macro_dots, LV_SIZE_CONTENT, 12);
  lv_obj_set_flex_flow(g.macro_dots, LV_FLEX_FLOW_ROW);
  lv_obj_set_style_pad_column(g.macro_dots, 8, 0);
  lv_obj_set_pos(g.macro_dots, kMargin + kHomeWidth + 18, kMargin + 50);
  for (int i = 0; i < pages; ++i) {
    lv_obj_t* dot = Plain(g.macro_dots);
    lv_obj_set_size(dot, 10, 10);
    lv_obj_set_style_radius(dot, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_bg_opa(dot, LV_OPA_COVER, 0);
  }
  g.macro_notice = Label(screen, kSmall, kMuted, "");
  lv_obj_set_pos(g.macro_notice, kMargin + kHomeWidth + 16, kMargin + 46);
  // Between the Home and next-page buttons; longer notices scroll.
  lv_obj_set_width(g.macro_notice, kWidth - 2 * kMargin - kHomeWidth - kControl - 32);
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
    const int count = page.count;
    for (int m = 0; m < count; ++m) {
      const macros::Macro& macro = page.macros[m];
      lv_obj_t* button = Button(tile, kHalfWidth, kButtonHeight);
      lv_obj_set_pos(button, kMargin + (m % 2) * (kHalfWidth + kGap), (m / 2) * (kButtonHeight + kGap));
      // Playing: accent border over an accent-tinted face; icon and name stay legible.
      lv_obj_set_style_bg_color(
          button, lv_color_mix(lv_color_hex(page.color), lv_color_hex(kSurface), 80), LV_STATE_CHECKED);
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

void BuildKeyferry() {
  lv_obj_t* screen = NewScreen(Screen::kKeyferry);
  Header(screen, "Keyferry");
  lv_obj_t* card = Card(screen, kMargin, kContentTop, kWidth - 2 * kMargin, kHeight - kContentTop - kMargin);
  g.keyferry_text = Label(card, kBody, kText, "Starting...");
  lv_obj_set_width(g.keyferry_text, LV_PCT(100));
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
  for (int i = 0; i < 6; ++i) {
    if (g.screens[i] == active) return static_cast<Screen>(i);
  }
  return Screen::kHome;
}

void ShowWakeShield() {
  if (g.wake_shield != nullptr) lv_obj_set_hidden(g.wake_shield, false);
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
  if (g.buttons_label == nullptr) return;
  lv_label_set_text(g.buttons_label, view.buttons);
  lv_label_set_text(g.power_label, view.power);
  lv_label_set_text(g.storage_label, view.storage);
  lv_label_set_text(g.memory_label, view.memory);
}

void RefreshKeepAwake(const KeepAwakeView& view) {
  if (g.awake_button == nullptr) return;
  lv_label_set_text(g.awake_icon, view.running ? LV_SYMBOL_PAUSE : LV_SYMBOL_PLAY);
  lv_label_set_text(g.awake_label, view.running ? "Stop" : "Start");
  lv_obj_set_style_border_color(g.awake_button, lv_color_hex(view.running ? kKeepAwakeColor : kBorder), 0);
  lv_obj_set_style_text_color(g.awake_state, lv_color_hex(view.stopped_by_fault ? kError : kText), 0);
  lv_arc_set_range(g.awake_arc, 0, view.interval_seconds);
  if (view.running && view.seconds_to_next >= 0) {
    lv_arc_set_value(g.awake_arc, view.interval_seconds - view.seconds_to_next);
    lv_label_set_text_fmt(g.awake_state, "%s  -  next in %d s", view.state, view.seconds_to_next);
  } else {
    lv_arc_set_value(g.awake_arc, 0);
    lv_label_set_text(g.awake_state, view.state);
  }
  lv_label_set_text_fmt(g.awake_detail,
                        "%s   |   %u nudge%s\nNudges the pointer 1 px every %d s",
                        view.usb ? LV_SYMBOL_USB " Connected" : "Not connected",
                        static_cast<unsigned>(view.nudges), view.nudges == 1 ? "" : "s",
                        view.interval_seconds);
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
  if (g.keyferry_text != nullptr) lv_label_set_text(g.keyferry_text, text);
}

}  // namespace keyferry::handheld::ui
