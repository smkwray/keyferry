#pragma once

#include <cstddef>
#include <cstdint>

#include "keyferry/ble_transport.h"

namespace keyferry::ble {

// Reconcile project-owned state after NimBLE's synchronous advertising-stop
// result. NimBLE does not emit ADV_COMPLETE for an intentional legacy stop.
inline bool ReconcileAdvertisingStopState(const int result,
                                          const int already_stopped,
                                          bool* advertising) {
  if (advertising == nullptr ||
      (result != 0 && result != already_stopped)) {
    return false;
  }
  *advertising = false;
  return true;
}

struct PeripheralEvents {
  std::uint32_t generation = 0;
  Fault fault = Fault::kNone;
  bool connected = false;
  bool ready = false;
  bool bytes_available = false;
  bool disconnected = false;
};

enum class PeripheralStage : std::uint8_t {
  kOff = 0,
  kPortInit,
  kGattCount,
  kGattAdd,
  kHostSync,
  kAddress,
  kAdvertisingFields,
  kAdvertisingStart,
  kAdvertising,
  kConnected,
  kFault,
};

struct PeripheralInitialization {
  bool ok = false;
  PeripheralStage stage = PeripheralStage::kOff;
  std::int32_t error = 0;
};

struct PeripheralStatus {
  PeripheralStage stage = PeripheralStage::kOff;
  std::int32_t error = 0;
  bool initialized = false;
  bool synchronized = false;
  bool advertising = false;
};

// Single-instance ESP-IDF NimBLE peripheral. It exposes only an ordered byte
// pipe; TLS and command semantics remain outside this adapter.
class IdfBlePeripheral final {
 public:
  PeripheralInitialization Initialize();
  bool StartAdvertising();
  PeripheralEvents Poll(std::uint64_t now_ms);
  std::size_t Read(std::uint8_t* output, std::size_t capacity);
  bool Send(std::uint32_t generation, const std::uint8_t* data,
            std::size_t size, std::uint64_t now_ms);
  void Stop();
  void Disconnect();

  [[nodiscard]] bool initialized() const;
  [[nodiscard]] bool ready(std::uint32_t generation) const;
  [[nodiscard]] bool can_send(std::uint32_t generation) const;
  [[nodiscard]] std::size_t fragment_capacity(
      std::uint32_t generation) const;
  [[nodiscard]] PeripheralStatus status() const;
};

}  // namespace keyferry::ble
