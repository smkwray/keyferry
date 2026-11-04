// Messages (ADR 0018 rule 15): lines a program on the computer writes to a USB serial port, shown
// on the screen. Receiving runs on the TinyUSB task (esp_tinyusb's CDC-ACM callbacks); replies
// are queued from any task and written on the TinyUSB task. Message text is never logged.
#include "messages.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>

#include "device/usbd_pvt.h"  // usbd_defer_func: run on the TinyUSB task (pinned TinyUSB 0.21)
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "tinyusb_cdc_acm.h"
#include "tusb.h"
#include "usb_device.h"

namespace keyferry::handheld {
namespace {

constexpr char kTag[] = "messages";
constexpr tinyusb_cdcacm_itf_t kPort = TINYUSB_CDC_ACM_0;
constexpr std::size_t kMaxLine = 512;  // longer input lines are cut at kMaxText anyway
constexpr int kReplySlots = 8;

// Claimed when Messages starts (PSRAM when there is some), so Keyferry and the other functions
// carry none of it.
struct Store {
  Message messages[kMaxMessages];  // oldest first
  char replies[kReplySlots][24];
  char line[kMaxLine + 1];         // receive state: TinyUSB task only
};

SemaphoreHandle_t g_lock = nullptr;       // guards the messages and the reply queue
Store* g_store = nullptr;
int g_count = 0;
std::uint32_t g_next_id = 1;
std::atomic<std::uint32_t> g_serial{0};
std::atomic<std::uint32_t> g_received{0};
std::atomic<bool> g_listening{false};
int g_reply_count = 0;
std::size_t g_line_length = 0;  // TinyUSB task only

struct Lock {
  Lock() { xSemaphoreTake(g_lock, portMAX_DELAY); }
  ~Lock() { xSemaphoreGive(g_lock); }
};

// TinyUSB task: writes every queued reply. Replies made while no program has the port open are
// dropped there, so a program never reads an earlier one's answers.
void FlushReplies(void*) {
  char lines[kReplySlots][24];
  int count = 0;
  {
    Lock lock;
    count = g_reply_count;
    std::memcpy(lines, g_store->replies, sizeof(lines));
    g_reply_count = 0;
  }
  if (!g_listening.load()) return;
  for (int i = 0; i < count; ++i) {
    tinyusb_cdcacm_write_queue(kPort, reinterpret_cast<const std::uint8_t*>(lines[i]), std::strlen(lines[i]));
  }
  tinyusb_cdcacm_write_flush(kPort, 0);
}

// Any task, without the lock held.
void Reply(const char* word, std::uint32_t id) {
  {
    Lock lock;
    if (g_reply_count == kReplySlots) return;  // a program that never reads loses replies, not messages
    if (id == 0) {
      std::snprintf(g_store->replies[g_reply_count], sizeof(g_store->replies[0]), "%s\r\n", word);
    } else {
      std::snprintf(g_store->replies[g_reply_count], sizeof(g_store->replies[0]), "%s %u\r\n", word,
                    static_cast<unsigned>(id));
    }
    ++g_reply_count;
  }
  usbd_defer_func(FlushReplies, nullptr, false);
}

// One UTF-8 code point from `text`, or -1 for a malformed sequence; advances *at.
long DecodeUtf8(const unsigned char* text, std::size_t length, std::size_t* at) {
  const unsigned char lead = text[*at];
  int extra = lead < 0x80 ? 0 : (lead >> 5) == 0x6 ? 1 : (lead >> 4) == 0xE ? 2 : (lead >> 3) == 0x1E ? 3 : -1;
  ++*at;
  if (extra < 0) return -1;
  long code = extra == 0 ? lead : lead & (0x3F >> extra);
  for (; extra > 0; --extra) {
    if (*at >= length || (text[*at] & 0xC0) != 0x80) return -1;
    code = (code << 6) | (text[(*at)++] & 0x3F);
  }
  return code;
}

// The screen's font has printable ASCII only: common punctuation is spelled out, the rest
// becomes '?', and control characters are dropped.
void Sanitize(const char* in, std::size_t length, char* out, std::size_t size) {
  const auto* text = reinterpret_cast<const unsigned char*>(in);
  std::size_t used = 0;
  const auto put = [&](const char* piece) {
    for (; *piece != '\0' && used + 1 < size; ++piece) out[used++] = *piece;
  };
  for (std::size_t at = 0; at < length && used + 1 < size;) {
    const long code = DecodeUtf8(text, length, &at);
    char ascii[2] = {static_cast<char>(code), '\0'};
    if (code == '\t' || code == 0xA0) {
      put(" ");
    } else if (code >= 0x20 && code < 0x7F) {
      put(ascii);
    } else if (code == 0x2018 || code == 0x2019) {
      put("'");
    } else if (code == 0x201C || code == 0x201D) {
      put("\"");
    } else if (code == 0x2013 || code == 0x2014) {
      put("-");
    } else if (code == 0x2026) {
      put("...");
    } else if (code == 0x2022) {
      put("*");
    } else if (code >= 0x80 || code < 0) {
      put("?");
    }
  }
  out[used] = '\0';
}

// TinyUSB task: one complete line from the computer.
void Accept(const char* line, std::size_t length) {
  while (length > 0 && (line[length - 1] == ' ' || line[length - 1] == '\t')) --length;
  while (length > 0 && (*line == ' ' || *line == '\t')) ++line, --length;
  if (length == 0) return;
  if (length == 6 && std::memcmp(line, "/clear", 6) == 0) {
    MessagesClear();
    return;
  }
  if (length == 5 && std::memcmp(line, "/ping", 5) == 0) {
    Reply("pong", 0);
    return;
  }
  MessageKind kind = MessageKind::kInfo;
  if (*line == '!' || *line == '?') {
    kind = *line == '!' ? MessageKind::kAlert : MessageKind::kQuestion;
    ++line;
    --length;
  }
  std::uint32_t id = 0;
  {
    Lock lock;
    if (g_count == kMaxMessages) {  // the oldest makes room
      std::memmove(&g_store->messages[0], &g_store->messages[1], sizeof(Message) * (kMaxMessages - 1));
      --g_count;
    }
    Message& message = g_store->messages[g_count++];
    id = g_next_id++;
    message.id = id;
    message.kind = kind;
    message.state = MessageState::kNew;
    message.received_us = esp_timer_get_time();
    Sanitize(line, length, message.text, sizeof(message.text));
    if (message.text[0] == '\0') std::snprintf(message.text, sizeof(message.text), "(empty)");
  }
  g_serial.fetch_add(1);
  g_received.fetch_add(1);
  ESP_LOGI(kTag, "message %u (%s)", static_cast<unsigned>(id),
           kind == MessageKind::kAlert ? "alert" : kind == MessageKind::kQuestion ? "question" : "notice");
  Reply("ok", id);
}

void OnReceive(int, cdcacm_event_t*) {
  std::uint8_t chunk[64];
  std::size_t received = 0;
  while (tinyusb_cdcacm_read(kPort, chunk, sizeof(chunk), &received) == ESP_OK && received > 0) {
    for (std::size_t i = 0; i < received; ++i) {
      const char c = static_cast<char>(chunk[i]);
      if (c == '\n') {
        Accept(g_store->line, g_line_length);
        g_line_length = 0;
      } else if (c != '\r' && g_line_length < kMaxLine) {
        g_store->line[g_line_length++] = c;
      }
    }
  }
}

void OnLineState(int, cdcacm_event_t* event) {
  const bool listening = event->line_state_changed_data.dtr;
  if (listening == g_listening.exchange(listening)) return;
  if (listening) {
    tud_cdc_n_write_clear(kPort);  // nothing left over from an earlier program
    Reply("ready", 0);
  }
}

Message* FindLocked(std::uint32_t id) {
  for (int i = 0; i < g_count; ++i) {
    if (g_store->messages[i].id == id) return &g_store->messages[i];
  }
  return nullptr;
}

}  // namespace

bool MessagesStart() {
  void* store = heap_caps_calloc(1, sizeof(Store), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (store == nullptr) store = heap_caps_calloc(1, sizeof(Store), MALLOC_CAP_8BIT);
  g_store = static_cast<Store*>(store);
  g_lock = xSemaphoreCreateMutex();
  if (g_store == nullptr || g_lock == nullptr) return false;
  if (!UsbDeviceStart(UsbPersonality::kMessages)) return false;
  tinyusb_config_cdcacm_t config{};
  config.cdc_port = kPort;
  config.callback_rx = OnReceive;
  config.callback_line_state_changed = OnLineState;
  if (tinyusb_cdcacm_init(&config) != ESP_OK) {
    ESP_LOGE(kTag, "serial port could not start");
    return false;
  }
  return true;
}

int MessagesList(Message* out, int max, std::uint32_t* serial) {
  if (g_lock == nullptr) return 0;
  Lock lock;
  *serial = g_serial.load();
  const int count = std::min(g_count, max);
  for (int i = 0; i < count; ++i) out[i] = g_store->messages[g_count - 1 - i];
  return count;
}

std::uint32_t MessagesSerial() { return g_serial.load(); }
std::uint32_t MessagesReceived() { return g_received.load(); }
bool MessagesListening() { return g_listening.load(); }

void MessagesMarkRead(std::uint32_t id) {
  bool changed = false;
  {
    Lock lock;
    Message* message = FindLocked(id);
    if (message != nullptr && message->state == MessageState::kNew && message->kind != MessageKind::kQuestion) {
      message->state = MessageState::kRead;
      changed = true;
    }
  }
  if (!changed) return;
  g_serial.fetch_add(1);
  Reply("read", id);
}

void MessagesAnswer(std::uint32_t id, bool yes) {
  bool changed = false;
  {
    Lock lock;
    Message* message = FindLocked(id);
    if (message != nullptr && message->kind == MessageKind::kQuestion && message->state == MessageState::kNew) {
      message->state = yes ? MessageState::kAnsweredYes : MessageState::kAnsweredNo;
      changed = true;
    }
  }
  if (!changed) return;
  g_serial.fetch_add(1);
  Reply(yes ? "yes" : "no", id);
}

void MessagesClear() {
  if (g_lock == nullptr) return;
  {
    Lock lock;
    g_count = 0;
  }
  g_serial.fetch_add(1);
}

}  // namespace keyferry::handheld
