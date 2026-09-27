#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "keyferry/secure_endpoint.h"

namespace {

class OfflineEffects final : public keyferry::endpoint::Effects {
 public:
  void FailClosed(std::uint64_t epoch) override {
    std::printf("endpoint_epoch=%llu state=disarmed transport=offline\n",
                static_cast<unsigned long long>(epoch));
  }

  bool FillRandom(std::uint8_t*, std::size_t) override { return false; }
  bool HmacSha256(const std::uint8_t[16], const std::uint8_t*, std::size_t,
                  std::uint8_t[32]) override {
    return false;
  }
  bool SendTls(const std::uint8_t*, std::size_t) override { return false; }
  bool SessionAuthenticated(std::uint64_t,
                            const keyferry::endpoint::SessionReady&) override {
    return false;
  }
  bool CommandScopedArm(std::uint64_t, std::uint32_t) override { return false; }
  bool Disarm(std::uint64_t) override { return true; }
  bool DisarmComplete(std::uint64_t) override { return true; }
  bool BuildRouteProof(std::uint64_t, const std::uint8_t[16],
                       const std::uint8_t[32], std::uint8_t*) override {
    return false;
  }
  bool HandleGatewayHandoff(
      std::uint64_t, const keyferry::protocol::GatewayHandoffRequest&,
      keyferry::protocol::GatewayHandoffStatusPayload*, bool*) override {
    return false;
  }
  bool ServiceGatewayHandoff(
      std::uint64_t, keyferry::protocol::GatewayHandoffStatusPayload*,
      bool*) override {
    return false;
  }
  void GatewayHandoffReplySent(
      std::uint64_t,
      keyferry::protocol::GatewayHandoffOperation) override {}
  bool AuthenticatedFrame(std::uint64_t,
                          const keyferry::protocol::DecodedFrame&) override {
    return false;
  }
};

}  // namespace

extern "C" void app_main() {
  // This compile/HIL scaffold has no credential provider and never initializes Wi-Fi. Its only
  // runtime state is the mandatory fail-closed boot epoch.
  constexpr std::array<std::uint8_t, 16> kUnprovisionedDeviceId{};
  static OfflineEffects effects;
  static keyferry::endpoint::EndpointSession session(kUnprovisionedDeviceId,
                                                      effects);
  session.Boot();
  std::puts("keyferry secure endpoint skeleton: credentials absent; network and HID inactive");
}
