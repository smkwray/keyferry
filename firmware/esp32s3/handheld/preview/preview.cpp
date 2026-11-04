// Host preview of the handheld screens, driven by scripts/preview_handheld.py: renders one named
// scene of ui.cpp with LVGL (configured from the device build's sdkconfig.h) to an RGB565 file.
#include <cstdio>
#include <cstring>

#include "lvgl.h"
#include "ui.h"

namespace ui = keyferry::handheld::ui;
namespace macros = keyferry::handheld::macros;

namespace {

std::uint32_t g_now = 0;
std::uint8_t g_frame[ui::kWidth * ui::kHeight * 2];

std::uint32_t Tick() { return g_now; }
void Flush(lv_display_t* display, const lv_area_t*, std::uint8_t*) { lv_display_flush_ready(display); }
void Ignore(ui::Action, int) {}

void Settle() {
  for (int i = 0; i < 100; ++i) {  // 2 s of animations and timers
    g_now += 20;
    lv_timer_handler();
  }
  lv_refr_now(nullptr);
}

const char* const kScenes[] = {
    "home", "check", "settings", "keep-awake", "keep-awake-timer", "keep-awake-always",
    "keep-awake-done", "macros-0", "macros-1",
    "macros-1-mac", "macros-2", "macros-3", "macros-4", "macros-1-busy", "macros-2-releasing",
    "keyferry",
};

bool Scene(const char* name) {
  ui::Config config;
  config.keyferry = true;
  config.action = Ignore;
  const bool mac = std::strstr(name, "-mac") != nullptr;
  config.host = mac ? macros::Host::kMac : macros::Host::kWindows;
  if (std::strcmp(name, "home") == 0) {
    ui::Build(config, ui::Screen::kHome);
    ui::RefreshHome(ui::HomeView{true, -1});
  } else if (std::strcmp(name, "check") == 0) {
    ui::Build(config, ui::Screen::kHome);
    ui::Show(ui::Screen::kCheck);
    ui::RefreshCheck(ui::CheckView{"BOOT up " LV_SYMBOL_BULLET " PWR pressed 2x", "USB, no battery",
                                   "14.8 GB, FAT", "328K RAM " LV_SYMBOL_BULLET " 7.9M PSRAM"});
  } else if (std::strcmp(name, "settings") == 0) {
    ui::Build(config, ui::Screen::kHome);
    ui::Show(ui::Screen::kSettings);
  } else if (std::strcmp(name, "keep-awake") == 0) {
    ui::Build(config, ui::Screen::kKeepAwake);
    ui::KeepAwakeView view;
    view.state = "Ready";
    view.usb = true;
    ui::RefreshKeepAwake(view);
  } else if (std::strncmp(name, "keep-awake-", 11) == 0) {
    const bool always = std::strcmp(name, "keep-awake-always") == 0;
    const bool done = std::strcmp(name, "keep-awake-done") == 0;
    config.keep_awake_duration = always ? 3 : 1;
    ui::Build(config, ui::Screen::kKeepAwake);
    ui::KeepAwakeView view;
    view.state = done ? "Done: timer ended" : "Running";
    view.running = !done;
    view.usb = true;
    view.nudges = done ? 144 : 34;
    view.seconds_to_next = done ? -1 : 12;
    view.seconds_left = always || done ? -1 : 2592;
    view.timer_seconds = always || done ? 0 : 3600;
    ui::RefreshKeepAwake(view);
  } else if (std::strncmp(name, "macros-", 7) == 0) {
    config.macro_page = name[7] - '0';
    ui::Build(config, ui::Screen::kMacros);
    ui::MacrosView view;
    view.usb = true;
    if (std::strstr(name, "-busy") != nullptr) {
      view.busy = config.macro_page << 8 | 2;
      view.notice = "Sent: Screenshot";
    }
    if (std::strstr(name, "-releasing") != nullptr) {
      view.notice = "Releasing keys - wake or unplug the computer";
      view.notice_is_error = true;
    }
    ui::RefreshMacros(view);
  } else if (std::strcmp(name, "keyferry") == 0) {
    ui::Build(config, ui::Screen::kKeyferry);
    ui::SetKeyferryText("Ready, disarmed\nWi-Fi: connected\nDaemon: authenticated\nUSB: keyboard + mouse");
  } else {
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::strcmp(argv[1], "--list") == 0) {
    for (const char* scene : kScenes) std::printf("%s\n", scene);
    return 0;
  }
  if (argc != 3) {
    std::fprintf(stderr, "usage: preview SCENE OUT.rgb565\n");
    return 2;
  }
  lv_init();
  lv_tick_set_cb(Tick);
  lv_display_t* display = lv_display_create(ui::kWidth, ui::kHeight);
  lv_display_set_color_format(display, LV_COLOR_FORMAT_RGB565);
  lv_display_set_buffers(display, g_frame, nullptr, sizeof(g_frame), LV_DISPLAY_RENDER_MODE_DIRECT);
  lv_display_set_flush_cb(display, Flush);
  if (!Scene(argv[1])) {
    std::fprintf(stderr, "unknown scene %s\n", argv[1]);
    return 2;
  }
  Settle();
  std::FILE* out = std::fopen(argv[2], "wb");
  if (out == nullptr || std::fwrite(g_frame, 1, sizeof(g_frame), out) != sizeof(g_frame)) return 1;
  return std::fclose(out) == 0 ? 0 : 1;
}
