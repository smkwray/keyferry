#pragma once

#include <array>
#include <cstdint>

#include "keyferry/local_management_coordinator.h"

namespace keyferry::local_management {

struct DeviceStatus {
  protocol::OutputMode active_output_mode{protocol::OutputMode::kUsbHid};
  protocol::OutputMode stored_output_mode{protocol::OutputMode::kUsbHid};
  std::uint8_t board_compatibility_id{};
  std::array<std::uint8_t, 8> release{};
  std::uint32_t capabilities{};
};

struct SafetyStatus {
  bool maintenance_active{};
  bool command_active{};
  bool armed{};
  bool usb_mounted{};
  bool keyboard_neutral{};
  bool mouse_neutral{};
  bool restart_pending{};
  bool receipt_storage_healthy{};
  std::uint32_t usb_attachment_generation{};
};

struct NetworkStatus {
  std::uint8_t wifi_stage{};
  std::uint8_t active_path{};
  bool running{};
  bool wifi_available{};
  bool ble_available{};
  bool endpoint_authenticated{};
  bool configuration_valid{};
  std::uint8_t wifi_profile_count{};
  std::uint8_t paired_host_count{};
  std::uint8_t policy_state{};
  std::int32_t wifi_error{};
  std::int32_t nvs_error{};
};

struct BleHidStatus {
  protocol::LocalManagementBondState bond_state{
      protocol::LocalManagementBondState::kStoreError};
  std::uint8_t peripheral_stage{};
  bool advertising{};
  bool connected{};
  bool authenticated{};
  bool subscribed{};
  bool ready{};
  bool enrollment_active{};
  std::int32_t error{};
  std::uint32_t generation{};
  std::uint32_t enrollment_remaining_ms{};
};

struct PolicyStatus {
  std::uint8_t state{};
  std::uint64_t sequence{};
};

// Volatile, metadata-only snapshot populated only by the opt-in MSC memory
// probe. A common sequence lets the host detect a snapshot change across the
// three fixed status pages.
struct ProbeStatus {
  std::uint16_t sample_seq{};
  std::uint8_t phase{};
  std::uint32_t uptime_seconds{};
  std::uint8_t held_flags{};
  std::uint8_t first_outcome{};
  std::uint8_t second_outcome{};
  bool transport_running{};
  std::uint8_t link{};
  std::uint8_t output_mode{};
  std::uint32_t free_internal_heap{};
  std::uint32_t largest_internal_block{};
  std::uint32_t minimum_internal_heap{};
  std::uint32_t main_stack_free{};
  std::uint32_t transport_stack_free{};
  std::uint32_t probe_stack_free{};
};

struct StatusSnapshot {
  DeviceStatus device{};
  SafetyStatus safety{};
  NetworkStatus network{};
  BleHidStatus ble_hid{};
  PolicyStatus policy{};
  bool probe_available{};
  ProbeStatus probe{};
  Receipt last_receipt{};
  bool has_last_receipt{};
};

// Encodes exactly one fixed status page. False means the supplied snapshot is
// outside the registered bounded vocabulary; output is cleared on failure.
bool EncodeStatusPage(protocol::LocalManagementStatusPage page,
                      const StatusSnapshot& snapshot,
                      ResponsePayload* output);

}  // namespace keyferry::local_management
