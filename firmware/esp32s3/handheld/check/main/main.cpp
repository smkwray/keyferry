#include "keyferry/handheld.h"

// The check image has no bridge linked, so Keyferry is never selectable and this never returns.
extern "C" void app_main() { keyferry::handheld::RunShellUnlessKeyferry(); }
