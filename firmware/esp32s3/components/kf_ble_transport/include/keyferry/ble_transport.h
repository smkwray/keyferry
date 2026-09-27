#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry_protocol_generated.h"

namespace keyferry::ble {

constexpr std::size_t kReceiveRingBytes = protocol::kBleReceiveRingBytes;
constexpr std::size_t kTransmitStagingBytes = protocol::kBleTransmitStagingBytes;

enum class Fault : std::uint8_t {
  kNone = 0,
  kInvalidMtu,
  kBadState,
  kBadFragment,
  kReceiveOverflow,
  kCccdDisabled,
  kCccdTimeout,
  kIndicationFailed,
  kIndicationTimeout,
};

struct ByteView {
  const std::uint8_t* data;
  std::size_t size;
};

// Bounded, allocation-free byte transport shared by the NimBLE adapter and
// native tests. It owns no TLS, command, identity, or retry state.
class BytePipe final {
 public:
  bool Connect(std::uint32_t generation, std::uint16_t att_mtu,
               std::uint64_t now_ms);
  bool UpdateMtu(std::uint32_t generation, std::uint16_t att_mtu);
  bool SetIndications(std::uint32_t generation, bool enabled,
                      std::uint64_t now_ms);
  bool ReceiveWrite(std::uint32_t generation, const std::uint8_t* data,
                    std::size_t size, std::uint64_t now_ms);
  std::size_t Read(std::uint8_t* output, std::size_t capacity);

  bool StageIndication(std::uint32_t generation, const std::uint8_t* data,
                       std::size_t size, std::uint64_t now_ms);
  [[nodiscard]] ByteView PendingIndication() const;
  bool CompleteIndication(std::uint32_t generation, bool success,
                          std::uint64_t now_ms);

  // Returns false after a setup or indication deadline closes the pipe.
  bool Poll(std::uint64_t now_ms);
  bool Disconnect(std::uint32_t generation);

  [[nodiscard]] bool connected() const { return connected_; }
  [[nodiscard]] bool ready() const {
    return connected_ && indications_enabled_ && fault_ == Fault::kNone;
  }
  [[nodiscard]] bool indication_pending() const {
    return indication_pending_;
  }
  [[nodiscard]] std::uint32_t generation() const { return generation_; }
  [[nodiscard]] std::size_t fragment_capacity() const {
    return fragment_capacity_;
  }
  [[nodiscard]] std::size_t received_size() const { return receive_size_; }
  [[nodiscard]] Fault fault() const { return fault_; }

 private:
  bool IsCurrent(std::uint32_t generation) const;
  bool Fail(Fault fault);
  void ClearBuffers();

  std::array<std::uint8_t, kReceiveRingBytes> receive_{};
  std::array<std::uint8_t, kTransmitStagingBytes> transmit_{};
  std::size_t receive_head_ = 0;
  std::size_t receive_size_ = 0;
  std::size_t transmit_size_ = 0;
  std::size_t fragment_capacity_ = 0;
  std::uint32_t generation_ = 0;
  std::uint64_t connected_at_ms_ = 0;
  std::uint64_t indication_started_at_ms_ = 0;
  Fault fault_ = Fault::kNone;
  bool connected_ = false;
  bool indications_enabled_ = false;
  bool indication_pending_ = false;
};

static_assert(sizeof(BytePipe) <= 1536,
              "custom BLE byte-pipe storage exceeds the 1.5 KiB budget");

}  // namespace keyferry::ble
