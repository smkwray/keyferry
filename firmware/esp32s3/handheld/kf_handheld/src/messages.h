#pragma once
#include <cstdint>

namespace keyferry::handheld {

// Messages (ADR 0018 rule 15): a USB serial port (CDC-ACM) a program on the computer writes
// lines to; they are shown on the screen and nothing else. Display only: no input, no files, no
// path to Keyferry. The last kMaxMessages stay in RAM until the board restarts.
//
// Computer -> board, one line each (UTF-8, LF or CRLF, longer than kMaxText is cut):
//   text      a notice          !text   an alert          ?text   a Yes/No question
//   /clear    removes them all  /ping   answers "pong"
// Board -> computer, one line each: "ready" when a program opens the port, "ok <id>" for each
// message, "read <id>" when one is tapped, "yes <id>" or "no <id>" when a question is answered.

constexpr int kMaxMessages = 16;
constexpr int kMaxText = 160;

enum class MessageKind : std::uint8_t { kInfo, kAlert, kQuestion };
enum class MessageState : std::uint8_t { kNew, kRead, kAnsweredYes, kAnsweredNo };

struct Message {
  std::uint32_t id;
  MessageKind kind;
  MessageState state;
  std::int64_t received_us;  // esp_timer time
  char text[kMaxText + 1];   // printable ASCII
};

// Starts the USB serial device. False when it could not start.
bool MessagesStart();
// Copies the messages, newest first; *serial changes whenever they or their states do.
int MessagesList(Message* out, int max, std::uint32_t* serial);
std::uint32_t MessagesSerial();
// Counts messages received since boot: the screen wakes when it changes.
std::uint32_t MessagesReceived();
bool MessagesListening();  // a program on the computer has the port open (DTR)
void MessagesMarkRead(std::uint32_t id);
void MessagesAnswer(std::uint32_t id, bool yes);
void MessagesClear();

}  // namespace keyferry::handheld
