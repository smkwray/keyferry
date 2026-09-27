#pragma once

#include <array>
#include <cstdint>

#include "keyferry/ble_hid_release.h"

namespace keyferry::ble_hid {

using KeyboardReport = std::array<std::uint8_t, 8>;

enum class PeripheralStage : std::uint8_t {
  kOff,
  kPortInit,
  kGatt,
  kHostSync,
  kAdvertising,
  kConnected,
  kPairing,
  kReady,
  kFault,
};

struct PeripheralStatus {
  PeripheralStage stage{PeripheralStage::kOff};
  std::int32_t error{};
  std::uint32_t generation{};
  std::uint32_t passkey{};
  bool advertising{};
  bool connected{};
  bool authenticated{};
  bool subscribed{};
  bool ready{};
};

struct PeripheralEvents {
  bool disconnected{};
  bool release_complete{};
  bool disconnect_required{};
  bool fault{};
};

enum class BondStoreState : std::uint8_t {
  kNone,
  kSingle,
  kMultipleInvalid,
  kStoreError,
};

struct BondStoreStatus {
  BondStoreState state{BondStoreState::kStoreError};
  std::int32_t error{};
};

enum class BondResetResult : std::uint8_t {
  kNoBond,
  kForgotten,
  kError,
};

// Single-instance ESP-IDF NimBLE HID peripheral. It owns BLE only in the
// reboot-bound BLE-output mode; the gateway BLE transport must be disabled.
class IdfBleHidPeripheral final {
 public:
  static constexpr std::uint32_t kEnrollmentWindowMs =
      EnrollmentWindow::kDurationMs;

  bool Initialize();
  PeripheralEvents Poll(std::uint64_t now_ms);
  bool Submit(const KeyboardReport& report, std::uint64_t now_ms);
  // Deletes only NimBLE HID peer records. Keyferry ownership, recovery,
  // network, and output-mode storage use separate namespaces and are untouched.
  BondResetResult ResetBond();
  BondResetResult ResetBondAndEnroll(std::uint64_t now_ms);
  bool CancelEnrollment();
  void Disconnect();

  [[nodiscard]] bool ready() const;
  [[nodiscard]] PeripheralStatus status() const;
  // Reports only bounded inventory state. Peer addresses and key material are
  // never returned through local management or logs.
  [[nodiscard]] BondStoreStatus bond_status() const;
  [[nodiscard]] EnrollmentStatus enrollment_status(std::uint64_t now_ms) const;
};

}  // namespace keyferry::ble_hid
