#include "keyferry/ble_transport.h"

#include <algorithm>

namespace keyferry::ble {
namespace {

constexpr std::uint16_t kMaximumAttMtu = 517;

bool DeadlineReached(std::uint64_t now_ms, std::uint64_t started_ms,
                     std::size_t timeout_ms) {
  return now_ms >= started_ms && now_ms - started_ms >= timeout_ms;
}

}  // namespace

bool BytePipe::Connect(std::uint32_t generation, std::uint16_t att_mtu,
                       std::uint64_t now_ms) {
  ClearBuffers();
  generation_ = generation;
  connected_at_ms_ = now_ms;
  indication_started_at_ms_ = 0;
  indications_enabled_ = false;
  connected_ = generation != 0;
  fault_ = Fault::kNone;
  if (!connected_ || att_mtu < protocol::kBleMinimumAttMtu ||
      att_mtu > kMaximumAttMtu) {
    return Fail(Fault::kInvalidMtu);
  }
  fragment_capacity_ = std::min<std::size_t>(
      protocol::kBleMaximumFragmentBytes, att_mtu - 3U);
  return true;
}

bool BytePipe::UpdateMtu(std::uint32_t generation, std::uint16_t att_mtu) {
  if (!IsCurrent(generation)) {
    return false;
  }
  if (att_mtu < protocol::kBleMinimumAttMtu || att_mtu > kMaximumAttMtu) {
    return Fail(Fault::kInvalidMtu);
  }
  fragment_capacity_ = std::min<std::size_t>(
      protocol::kBleMaximumFragmentBytes, att_mtu - 3);
  return true;
}

bool BytePipe::SetIndications(std::uint32_t generation, bool enabled,
                              std::uint64_t now_ms) {
  if (!IsCurrent(generation) || fault_ != Fault::kNone) {
    return false;
  }
  if (!enabled) {
    return Fail(Fault::kCccdDisabled);
  }
  indications_enabled_ = true;
  connected_at_ms_ = now_ms;
  return true;
}

bool BytePipe::ReceiveWrite(std::uint32_t generation,
                            const std::uint8_t* data, std::size_t size,
                            std::uint64_t /*now_ms*/) {
  if (!IsCurrent(generation)) {
    return false;
  }
  if (!ready()) {
    return Fail(Fault::kBadState);
  }
  if (data == nullptr || size == 0 || size > fragment_capacity_) {
    return Fail(Fault::kBadFragment);
  }
  if (size > receive_.size() - receive_size_) {
    return Fail(Fault::kReceiveOverflow);
  }
  const std::size_t tail = (receive_head_ + receive_size_) % receive_.size();
  const std::size_t first = std::min(size, receive_.size() - tail);
  std::copy_n(data, first, receive_.begin() + tail);
  std::copy_n(data + first, size - first, receive_.begin());
  receive_size_ += size;
  return true;
}

std::size_t BytePipe::Read(std::uint8_t* output, std::size_t capacity) {
  if (output == nullptr || capacity == 0 || receive_size_ == 0) {
    return 0;
  }
  const std::size_t size = std::min(capacity, receive_size_);
  const std::size_t first = std::min(size, receive_.size() - receive_head_);
  std::copy_n(receive_.begin() + receive_head_, first, output);
  std::copy_n(receive_.begin(), size - first, output + first);
  receive_head_ = (receive_head_ + size) % receive_.size();
  receive_size_ -= size;
  return size;
}

bool BytePipe::StageIndication(std::uint32_t generation,
                               const std::uint8_t* data, std::size_t size,
                               std::uint64_t now_ms) {
  if (!IsCurrent(generation)) {
    return false;
  }
  if (!ready() || indication_pending_) {
    return Fail(Fault::kBadState);
  }
  if (data == nullptr || size == 0 || size > fragment_capacity_) {
    return Fail(Fault::kBadFragment);
  }
  std::copy_n(data, size, transmit_.begin());
  transmit_size_ = size;
  indication_pending_ = true;
  indication_started_at_ms_ = now_ms;
  return true;
}

ByteView BytePipe::PendingIndication() const {
  if (!indication_pending_) {
    return {nullptr, 0};
  }
  return {transmit_.data(), transmit_size_};
}

bool BytePipe::CompleteIndication(std::uint32_t generation, bool success,
                                  std::uint64_t /*now_ms*/) {
  if (!IsCurrent(generation)) {
    return false;
  }
  if (!indication_pending_) {
    return Fail(Fault::kBadState);
  }
  if (!success) {
    return Fail(Fault::kIndicationFailed);
  }
  transmit_.fill(0);
  transmit_size_ = 0;
  indication_pending_ = false;
  indication_started_at_ms_ = 0;
  return true;
}

bool BytePipe::Poll(std::uint64_t now_ms) {
  if (!connected_ || fault_ != Fault::kNone) {
    return false;
  }
  if (!indications_enabled_ &&
      DeadlineReached(now_ms, connected_at_ms_,
                      protocol::kBleCccdSetupTimeoutMs)) {
    return Fail(Fault::kCccdTimeout);
  }
  if (indication_pending_ &&
      DeadlineReached(now_ms, indication_started_at_ms_,
                      protocol::kBleOperationTimeoutMs)) {
    return Fail(Fault::kIndicationTimeout);
  }
  return true;
}

bool BytePipe::Disconnect(std::uint32_t generation) {
  if (!IsCurrent(generation)) {
    return false;
  }
  ClearBuffers();
  connected_ = false;
  indications_enabled_ = false;
  fragment_capacity_ = 0;
  return true;
}

bool BytePipe::IsCurrent(std::uint32_t generation) const {
  return connected_ && generation == generation_;
}

bool BytePipe::Fail(Fault fault) {
  ClearBuffers();
  fault_ = fault;
  connected_ = false;
  indications_enabled_ = false;
  fragment_capacity_ = 0;
  return false;
}

void BytePipe::ClearBuffers() {
  receive_.fill(0);
  transmit_.fill(0);
  receive_head_ = 0;
  receive_size_ = 0;
  transmit_size_ = 0;
  indication_pending_ = false;
}

}  // namespace keyferry::ble
