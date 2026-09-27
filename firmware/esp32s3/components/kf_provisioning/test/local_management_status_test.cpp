#include "keyferry/local_management_status.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>

namespace {

namespace local = keyferry::local_management;
namespace protocol = keyferry::protocol;

void TestEveryPageHasOneExactBoundedEncoding() {
  local::StatusSnapshot snapshot{};
  snapshot.device.active_output_mode = protocol::OutputMode::kUsbHid;
  snapshot.device.stored_output_mode = protocol::OutputMode::kBleHid;
  snapshot.device.board_compatibility_id = 1;
  snapshot.device.release = {'7', 'D', '9', '8', '7', 'C', '6', '5'};
  snapshot.device.capabilities = 0x00800041;
  local::ResponsePayload payload{};
  assert(local::EncodeStatusPage(protocol::LocalManagementStatusPage::kDevice,
                                 snapshot, &payload));
  const local::ResponsePayload expected_device{
      1,   1,   2,   1,   '7', 'D', '9', '8',
      '7', 'C', '6', '5', 0x41, 0x00, 0x80, 0x00};
  assert(payload == expected_device);

  snapshot.safety.maintenance_active = true;
  snapshot.safety.usb_mounted = true;
  snapshot.safety.keyboard_neutral = true;
  snapshot.safety.mouse_neutral = true;
  snapshot.safety.receipt_storage_healthy = true;
  snapshot.safety.usb_attachment_generation = 17;
  assert(local::EncodeStatusPage(protocol::LocalManagementStatusPage::kSafety,
                                 snapshot, &payload));
  const local::ResponsePayload expected_safety{
      1, 0xB9, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  assert(payload == expected_safety);

  snapshot.network.wifi_stage = 14;
  snapshot.network.active_path = 1;
  snapshot.network.running = true;
  snapshot.network.wifi_available = true;
  snapshot.network.ble_available = true;
  snapshot.network.endpoint_authenticated = true;
  snapshot.network.configuration_valid = true;
  snapshot.network.wifi_profile_count = 2;
  snapshot.network.paired_host_count = 3;
  snapshot.network.policy_state = 4;
  snapshot.network.wifi_error = -7;
  snapshot.network.nvs_error = 11;
  assert(local::EncodeStatusPage(protocol::LocalManagementStatusPage::kNetwork,
                                 snapshot, &payload));
  const local::ResponsePayload expected_network{
      1, 14, 1, 0x1F, 2, 3, 4, 0,
      0xF9, 0xFF, 0xFF, 0xFF, 11, 0, 0, 0};
  assert(payload == expected_network);

  snapshot.ble_hid.bond_state = protocol::LocalManagementBondState::kSingle;
  snapshot.ble_hid.peripheral_stage = 7;
  snapshot.ble_hid.advertising = true;
  snapshot.ble_hid.connected = true;
  snapshot.ble_hid.authenticated = true;
  snapshot.ble_hid.subscribed = true;
  snapshot.ble_hid.ready = true;
  snapshot.ble_hid.error = -2;
  snapshot.ble_hid.generation = 9;
  assert(local::EncodeStatusPage(protocol::LocalManagementStatusPage::kBleHid,
                                 snapshot, &payload));
  const local::ResponsePayload expected_ble{
      1, 1, 7, 0x1F, 0xFE, 0xFF, 0xFF, 0xFF,
      9, 0, 0, 0, 0, 0, 0, 0};
  assert(payload == expected_ble);

  snapshot.policy.state = 4;
  snapshot.policy.sequence = 77;
  assert(local::EncodeStatusPage(protocol::LocalManagementStatusPage::kPolicy,
                                 snapshot, &payload));
  const local::ResponsePayload expected_policy{
      1, 4, 0, 0, 0, 0, 0, 0, 77, 0, 0, 0, 0, 0, 0, 0};
  assert(payload == expected_policy);

  assert(local::EncodeStatusPage(
      protocol::LocalManagementStatusPage::kLastReceipt, snapshot, &payload));
  assert(payload[0] == 1 && payload[1] == 0);
  snapshot.has_last_receipt = true;
  snapshot.last_receipt.operation_id.fill(0x42);
  snapshot.last_receipt.operation = protocol::LocalManagementOperation::kReboot;
  snapshot.last_receipt.state =
      protocol::LocalManagementReceiptState::kCommitted;
  snapshot.last_receipt.result = protocol::LocalManagementStatus::kOk;
  snapshot.last_receipt.flags = local::Coordinator::kFlagRestartPending;
  assert(local::EncodeStatusPage(
      protocol::LocalManagementStatusPage::kLastReceipt, snapshot, &payload));
  const local::ResponsePayload expected_receipt{
      1, 2, 0x19, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  assert(payload == expected_receipt);
}

void TestInvalidSnapshotsClearOutputAndFailClosed() {
  local::StatusSnapshot snapshot{};
  local::ResponsePayload payload{};
  payload.fill(0xA5);
  assert(!local::EncodeStatusPage(protocol::LocalManagementStatusPage::kDevice,
                                  snapshot, &payload));
  for (const auto byte : payload) {
    assert(byte == 0);
  }

  snapshot.device.active_output_mode = protocol::OutputMode::kUsbHid;
  snapshot.device.stored_output_mode = protocol::OutputMode::kUsbHid;
  snapshot.device.board_compatibility_id = 1;
  snapshot.device.release = {'A', 0, 'B', 0, 0, 0, 0, 0};
  assert(!local::EncodeStatusPage(protocol::LocalManagementStatusPage::kDevice,
                                  snapshot, &payload));
  snapshot.network.wifi_profile_count = 9;
  assert(!local::EncodeStatusPage(protocol::LocalManagementStatusPage::kNetwork,
                                  snapshot, &payload));
  snapshot.ble_hid.enrollment_remaining_ms =
      protocol::kLocalManagementEnrollmentTimeoutMs + 1;
  assert(!local::EncodeStatusPage(protocol::LocalManagementStatusPage::kBleHid,
                                  snapshot, &payload));
  assert(!local::EncodeStatusPage(
      static_cast<protocol::LocalManagementStatusPage>(0x7F), snapshot,
      &payload));
}

void TestProbePagesAreUnavailableAndExact() {
  local::StatusSnapshot snapshot{};
  local::ResponsePayload payload{};
  payload.fill(0xA5);
  assert(!local::EncodeStatusPage(protocol::LocalManagementStatusPage::kProbeRun,
                                  snapshot, &payload));
  for (const auto byte : payload) assert(byte == 0);
  snapshot.probe_available = true;
  auto& probe = snapshot.probe;
  probe.sample_seq = 0x1234;
  probe.phase = 5;
  probe.uptime_seconds = 0x01020304;
  probe.held_flags = 3;
  probe.first_outcome = 1;
  probe.second_outcome = 2;
  probe.transport_running = true;
  probe.link = 2;
  probe.output_mode = 1;
  probe.free_internal_heap = 0x11223344;
  probe.largest_internal_block = 0x55667788;
  probe.minimum_internal_heap = 0x99AABBCC;
  probe.main_stack_free = 0x10203040;
  probe.transport_stack_free = 0x50607080;
  probe.probe_stack_free = 0x90A0B0C0;
  assert(local::EncodeStatusPage(protocol::LocalManagementStatusPage::kProbeRun,
                                 snapshot, &payload));
  const local::ResponsePayload run{1, 0x34, 0x12, 5, 4, 3, 2, 1,
                                   3, 1, 2, 1, 2, 1, 0, 0};
  assert(payload == run);
  assert(local::EncodeStatusPage(protocol::LocalManagementStatusPage::kProbeHeap,
                                 snapshot, &payload));
  const local::ResponsePayload heap{1, 0x34, 0x12, 0, 0x44, 0x33, 0x22, 0x11,
                                    0x88, 0x77, 0x66, 0x55, 0xCC, 0xBB, 0xAA, 0x99};
  assert(payload == heap);
  assert(local::EncodeStatusPage(protocol::LocalManagementStatusPage::kProbeStack,
                                 snapshot, &payload));
  const local::ResponsePayload stack{1, 0x34, 0x12, 0, 0x40, 0x30, 0x20, 0x10,
                                     0x80, 0x70, 0x60, 0x50, 0xC0, 0xB0, 0xA0, 0x90};
  assert(payload == stack);
  probe.held_flags = 0x04;
  assert(!local::EncodeStatusPage(protocol::LocalManagementStatusPage::kProbeRun,
                                  snapshot, &payload));
  for (const auto byte : payload) assert(byte == 0);
}

}  // namespace

int main() {
  TestEveryPageHasOneExactBoundedEncoding();
  TestInvalidSnapshotsClearOutputAndFailClosed();
  TestProbePagesAreUnavailableAndExact();
  std::puts("local_management_status_test: ok");
  return 0;
}
