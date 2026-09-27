#include "keyferry/command_executor.h"
#include "keyferry/idf_held_key_watchdog.h"

namespace {

class NoResults final : public keyferry::command::ResultSink {
  public:
    void CommandResult(std::uint32_t, const std::array<std::uint8_t, 16>&,
                       keyferry::protocol::ResultCode) override {}
    void InputCommandResult(
        std::uint32_t,
        const keyferry::command::InputResultEvidence&) override {}
};

}  // namespace

extern "C" void app_main() {
    // Compile/link proof only. Real composition must initialize the timer with a callback that
    // serializes watchdog expiry against USB and command access using one shared safety lock.
    keyferry::hid::ExecutorState hid;
    NoResults results;
    keyferry::command::IdfHeldKeyWatchdog watchdog;
    const std::array<std::uint8_t, 32> profile_hash{};
    keyferry::command::CommandExecutor executor(hid, results, watchdog, profile_hash);
    (void)executor;
}
