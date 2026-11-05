// Host test of handheld Messages (ADR 0018 rule 15). Production messages.cpp runs unchanged over a
// simulated USB serial port: the test plays the TinyUSB task (receive and line-state callbacks,
// deferred work), the screen (the public API in messages.h) and the computer (bytes in, bytes out
// of a TX FIFO the size the board configures, DTR, unplugging).
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <string>
#include <utility>

#include "messages.h"
#include "messages_test_stubs.h"
#include "usb_device.h"

namespace hh = keyferry::handheld;

namespace {

void Check(bool ok, const char* what, int line) {
  if (ok) return;
  std::fprintf(stderr, "messages_test.cpp:%d: CHECK failed: %s\n", line, what);
  std::exit(1);
}
#define CHECK(condition) Check(static_cast<bool>(condition), #condition, __LINE__)

constexpr std::size_t kTxFifo = 256;  // CONFIG_TINYUSB_CDC_TX_BUFSIZE on the handheld

tinyusb_config_cdcacm_t g_callbacks{};
std::deque<std::pair<void (*)(void*), void*>> g_deferred;  // the TinyUSB task's queue
bool g_on_usb_task = false;
bool g_deferred_from_usb_task = false;
std::string g_rx;  // computer -> board, not yet read by the board
std::string g_tx;  // board -> computer, in the TX FIFO
std::size_t g_tx_capacity = kTxFifo;
std::uint32_t g_session = 1;
bool g_dtr = false;
int g_locks = 0;
std::int64_t g_now = 0;

// The TinyUSB task: one callback or deferred function at a time.
void OnUsbTask(void (*callback)(int, cdcacm_event_t*), cdcacm_event_t* event) {
  g_on_usb_task = true;
  callback(0, event);
  g_on_usb_task = false;
}

void RunUsbTask() {
  while (!g_deferred.empty()) {
    const auto work = g_deferred.front();
    g_deferred.pop_front();
    g_on_usb_task = true;
    work.first(work.second);
    g_on_usb_task = false;
  }
}

void SetDtr(bool dtr) {
  g_dtr = dtr;
  cdcacm_event_t event{};
  event.line_state_changed_data.dtr = dtr;
  event.line_state_changed_data.rts = dtr;
  OnUsbTask(g_callbacks.callback_line_state_changed, &event);
  RunUsbTask();
}

void Send(const std::string& bytes) {
  g_rx += bytes;
  cdcacm_event_t event{};
  OnUsbTask(g_callbacks.callback_rx, &event);
  RunUsbTask();
}

// Unplug and plug back in: TinyUSB drops DTR on the new session without a line-state callback.
void Replug() {
  ++g_session;
  g_dtr = false;
  g_tx.clear();
}

std::string Take() {
  std::string out;
  out.swap(g_tx);
  return out;
}

int List(hh::Message* out) {
  std::uint32_t serial = 0;
  return hh::MessagesList(out, hh::kMaxMessages, &serial);
}

std::uint32_t LastId(const std::string& reply) {
  const std::size_t space = reply.rfind(' ');
  return static_cast<std::uint32_t>(std::strtoul(reply.c_str() + space + 1, nullptr, 10));
}

}  // namespace

// --- Platform -----------------------------------------------------------------------------------

void* heap_caps_calloc(std::size_t count, std::size_t size, std::uint32_t) { return std::calloc(count, size); }
std::int64_t esp_timer_get_time() { return g_now += 1000; }
SemaphoreHandle_t xSemaphoreCreateMutex() { return reinterpret_cast<SemaphoreHandle_t>(&g_locks); }
int xSemaphoreTake(SemaphoreHandle_t, TickType_t) {
  CHECK(g_locks == 0);  // single-threaded here: a nested take would deadlock on the board
  ++g_locks;
  return 1;
}
int xSemaphoreGive(SemaphoreHandle_t) {
  --g_locks;
  return 1;
}

void usbd_defer_func(void (*func)(void*), void* param, bool) {
  if (g_on_usb_task) g_deferred_from_usb_task = true;  // could block the task on a full queue
  g_deferred.emplace_back(func, param);
}

std::uint32_t tud_cdc_n_write_available(std::uint8_t) {
  return static_cast<std::uint32_t>(g_tx_capacity - g_tx.size());
}
bool tud_cdc_n_write_clear(std::uint8_t) {
  g_tx.clear();
  return true;
}

esp_err_t tinyusb_cdcacm_init(const tinyusb_config_cdcacm_t* config) {
  g_callbacks = *config;
  return ESP_OK;
}
// Like the vendored wrapper: copies what fits and returns that count.
std::size_t tinyusb_cdcacm_write_queue(tinyusb_cdcacm_itf_t, const std::uint8_t* data, std::size_t size) {
  CHECK(g_on_usb_task);
  const std::size_t fits = std::min(size, g_tx_capacity - g_tx.size());
  g_tx.append(reinterpret_cast<const char*>(data), fits);
  return fits;
}
esp_err_t tinyusb_cdcacm_write_flush(tinyusb_cdcacm_itf_t, std::uint32_t) { return ESP_OK; }
esp_err_t tinyusb_cdcacm_read(tinyusb_cdcacm_itf_t, std::uint8_t* out, std::size_t size, std::size_t* received) {
  CHECK(g_on_usb_task);
  *received = std::min(size, g_rx.size());
  std::memcpy(out, g_rx.data(), *received);
  g_rx.erase(0, *received);
  return ESP_OK;
}

namespace keyferry::handheld {
bool UsbDeviceStart(UsbPersonality personality) { return personality == UsbPersonality::kMessages; }
std::uint32_t UsbDeviceSession() { return g_session; }
}  // namespace keyferry::handheld

// --- Test -----------------------------------------------------------------------------------------

int main() {
  hh::Message list[hh::kMaxMessages];
  CHECK(hh::MessagesStart());
  CHECK(!hh::MessagesListening());

  // Opening the port: "ready"; each message: "ok <id>".
  SetDtr(true);
  CHECK(hh::MessagesListening());
  CHECK(Take() == "ready\r\n");
  Send("Build finished\r\n");
  CHECK(Take() == "ok 1\r\n");
  CHECK(List(list) == 1 && list[0].kind == hh::MessageKind::kInfo);
  CHECK(std::strcmp(list[0].text, "Build finished") == 0);

  // Kinds, escapes and commands.
  Send("!Disk full\n?Ship it?\n.?odd\n..NET built\n.plain\n/ping\n");
  CHECK(Take() == "ok 2\r\nok 3\r\nok 4\r\nok 5\r\nok 6\r\npong\r\n");
  CHECK(List(list) == 6);
  CHECK(list[4].kind == hh::MessageKind::kAlert && std::strcmp(list[4].text, "Disk full") == 0);
  CHECK(list[3].kind == hh::MessageKind::kQuestion && std::strcmp(list[3].text, "Ship it?") == 0);
  CHECK(list[2].kind == hh::MessageKind::kInfo && std::strcmp(list[2].text, "?odd") == 0);
  CHECK(std::strcmp(list[1].text, ".NET built") == 0);
  CHECK(std::strcmp(list[0].text, ".plain") == 0);
  Send("/clear\n");
  CHECK(List(list) == 0 && Take().empty());

  // UTF-8 becomes the screen's ASCII; control characters go; long lines are cut.
  Send("\xC3\x89" "chec \xE2\x80\x93 \xE2\x80\x9C" "done" "\xE2\x80\x9D\xE2\x80\xA6\x01\n");
  CHECK(List(list) == 1 && std::strcmp(list[0].text, "?chec - \"done\"...") == 0);
  Send(std::string(600, 'x') + "\n");
  CHECK(List(list) == 2 && std::strlen(list[0].text) == static_cast<std::size_t>(hh::kMaxText));
  Take();

  // The port echoes the board's own replies back on macOS and Linux: they are never messages.
  Send("ready\r\nok 7\r\nyes 3\nno 12\nread 4\npong\n");
  CHECK(List(list) == 2 && Take().empty());
  Send("ok\nok 7x\n");  // not reply forms: messages
  CHECK(List(list) == 4 && Take() == "ok 9\r\nok 10\r\n");

  // A burst in one transfer gets every acknowledgement, in order, and nothing queues work for the
  // TinyUSB task from the TinyUSB task.
  Send("/clear\n");
  std::string burst;
  for (int i = 0; i < 24; ++i) burst += "m\n";
  Send(burst);
  std::string expected;
  for (int i = 11; i < 35; ++i) expected += "ok " + std::to_string(i) + "\r\n";
  CHECK(Take() == expected);
  CHECK(List(list) == hh::kMaxMessages && list[0].id == 34 && list[15].id == 19);  // oldest dropped
  CHECK(!g_deferred_from_usb_task);

  // A program that stops reading loses whole replies, never part of one.
  g_tx = std::string(kTxFifo - 9, '.');
  Send("a\nb\n");  // "ok 35\r\n" fits (7 bytes); "ok 36\r\n" does not
  CHECK(Take() == std::string(kTxFifo - 9, '.') + "ok 35\r\n");

  // Answers on the screen reach the program that has the port open, once, via one deferred flush.
  Send("?Delete scans?\nnotice\n");
  const std::string acks = Take();
  const std::uint32_t question = LastId(acks.substr(0, acks.find('\n')));
  const std::uint32_t notice = LastId(acks.substr(0, acks.size() - 2));
  hh::MessagesAnswer(question, true);
  hh::MessagesMarkRead(notice);
  CHECK(g_deferred.size() == 1);
  RunUsbTask();
  CHECK(Take() == "yes " + std::to_string(question) + "\r\nread " + std::to_string(notice) + "\r\n");
  hh::MessagesAnswer(question, false);  // already answered
  RunUsbTask();
  CHECK(Take().empty());

  // Closed port: messages still arrive, replies are dropped when made and never reach the next
  // program.
  SetDtr(false);
  CHECK(!hh::MessagesListening());
  Send("?Restart now?\n");
  CHECK(Take().empty());
  CHECK(List(list) == hh::kMaxMessages && list[0].kind == hh::MessageKind::kQuestion);
  hh::MessagesAnswer(list[0].id, true);
  RunUsbTask();
  CHECK(Take().empty());
  SetDtr(true);
  CHECK(Take() == "ready\r\n");

  // An unfinished line does not join the next program's first line.
  Send("?Delete ");
  SetDtr(false);
  SetDtr(true);
  Take();
  Send("backup\n");
  CHECK(List(list) == hh::kMaxMessages && list[0].kind == hh::MessageKind::kInfo);
  CHECK(std::strcmp(list[0].text, "backup") == 0);
  Take();

  // Unplugged with the port open: no reply goes out, nothing unfinished survives, and the next
  // program to open the port is greeted.
  Send("?Format card");
  Replug();
  CHECK(!hh::MessagesListening());
  hh::MessagesAnswer(list[0].id, true);  // not a question: nothing; and nothing is listening
  RunUsbTask();
  Send("disk\n");  // written before DTR (a program that never sets it): shown, unanswered
  CHECK(List(list) == hh::kMaxMessages && std::strcmp(list[0].text, "disk") == 0);
  CHECK(Take().empty());
  SetDtr(true);
  CHECK(Take() == "ready\r\n");

  // RTS-only changes do not reopen the port.
  cdcacm_event_t event{};
  event.line_state_changed_data.dtr = true;
  event.line_state_changed_data.rts = false;
  OnUsbTask(g_callbacks.callback_line_state_changed, &event);
  RunUsbTask();
  CHECK(Take().empty());

  CHECK(g_locks == 0 && !g_deferred_from_usb_task);
  std::printf("handheld messages test: PASS\n");
  return 0;
}
