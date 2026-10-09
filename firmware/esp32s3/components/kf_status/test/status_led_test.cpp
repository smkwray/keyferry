#include "keyferry/status_led.h"
#include <cassert>
using namespace keyferry::status;
static bool equal(LedColor c, int r, int g, int b) {
  return c.red == r && c.green == g && c.blue == b;
}
int main() {
  Snapshot s;
  assert(equal(StatusLedColor(s, 0, 8, false), 8,4,0));
  s.activity = Activity::kReady;
  assert(equal(StatusLedColor(s, 500, 8, false),0,8,0));
  assert(equal(StatusLedColor(s, 500, 8, true),8,8,0));
  s.link = LinkPath::kWifi;
  assert(equal(StatusLedColor(s, 0, 8, false),0,8,8));
  s.link = LinkPath::kBluetooth;
  assert(equal(StatusLedColor(s, 0, 8, false),0,0,8));
  s.activity = Activity::kConnecting;
  s.connection = ConnectionProgress::kWifiJoining;
  assert(equal(StatusLedColor(s, 0, 8, false),0,8,8));
  assert(equal(StatusLedColor(s, 500, 8, false),0,0,0));
  s.connection = ConnectionProgress::kBluetoothAdvertising;
  assert(equal(StatusLedColor(s, 0, 8, false),0,0,8));
  s.activity = Activity::kActive;
  assert(equal(StatusLedColor(s, 0, 8, false),8,8,0));
  assert(equal(StatusLedColor(s, 250, 8, false),0,0,0));
  s.activity = Activity::kProvisioning;
  assert(equal(StatusLedColor(s, 0, 8, false),8,0,8));
  s.activity = Activity::kFault;
  assert(equal(StatusLedColor(s, 0, 8, true),8,0,0));
  assert(equal(StatusLedColor(s, 250, 8, true),0,0,0));
}
