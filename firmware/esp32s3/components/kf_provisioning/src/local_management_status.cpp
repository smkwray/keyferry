#include "keyferry/local_management_status.h"

#include <algorithm>

namespace keyferry::local_management {
namespace {

void Put32(std::uint8_t* output, const std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    output[index] = static_cast<std::uint8_t>(value >> (index * 8));
  }
}

void Put16(std::uint8_t* output, const std::uint16_t value) {
  output[0] = static_cast<std::uint8_t>(value);
  output[1] = static_cast<std::uint8_t>(value >> 8);
}

void Put64(std::uint8_t* output, const std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    output[index] = static_cast<std::uint8_t>(value >> (index * 8));
  }
}

bool SupportedOutputMode(const protocol::OutputMode mode) {
  return mode == protocol::OutputMode::kUsbHid ||
         mode == protocol::OutputMode::kBleHid;
}

bool CanonicalRelease(const std::array<std::uint8_t, 8>& release) {
  bool ended = false;
  for (const auto value : release) {
    if (value == 0) {
      ended = true;
    } else if (ended || value < 0x20 || value > 0x7E) {
      return false;
    }
  }
  return true;
}

bool ValidReceiptState(const protocol::LocalManagementReceiptState state) {
  return state >= protocol::LocalManagementReceiptState::kInProgress &&
         state <= protocol::LocalManagementReceiptState::kUnknown;
}

bool ValidReceipt(const Receipt& receipt) {
  if (!ValidReceiptState(receipt.state) ||
      receipt.operation < protocol::LocalManagementOperation::kOpenMaintenance ||
      receipt.operation > protocol::LocalManagementOperation::kReboot ||
      (receipt.flags & ~Coordinator::kFlagRestartPending) != 0) {
    return false;
  }
  if (receipt.operation == protocol::LocalManagementOperation::kSetOutputMode) {
    if (receipt.argument !=
            static_cast<std::uint16_t>(protocol::OutputMode::kUsbHid) &&
        receipt.argument !=
            static_cast<std::uint16_t>(protocol::OutputMode::kBleHid)) {
      return false;
    }
  } else if (receipt.argument != 0) {
    return false;
  }
  switch (receipt.state) {
    case protocol::LocalManagementReceiptState::kInProgress:
      return receipt.result == protocol::LocalManagementStatus::kInProgress &&
             receipt.flags == 0;
    case protocol::LocalManagementReceiptState::kCommitted:
      return receipt.result == protocol::LocalManagementStatus::kOk;
    case protocol::LocalManagementReceiptState::kFailed:
      return receipt.result != protocol::LocalManagementStatus::kOk &&
             receipt.result != protocol::LocalManagementStatus::kInProgress;
    case protocol::LocalManagementReceiptState::kUnknown:
      return receipt.result == protocol::LocalManagementStatus::kInternal &&
             receipt.flags == 0;
    case protocol::LocalManagementReceiptState::kNone:
      return false;
  }
  return false;
}

}  // namespace

bool EncodeStatusPage(const protocol::LocalManagementStatusPage page,
                      const StatusSnapshot& snapshot,
                      ResponsePayload* output) {
  if (output == nullptr) {
    return false;
  }
  output->fill(0);
  (*output)[0] = protocol::kLocalManagementStatusSchema;
  switch (page) {
    case protocol::LocalManagementStatusPage::kDevice:
      if (!SupportedOutputMode(snapshot.device.active_output_mode) ||
          !SupportedOutputMode(snapshot.device.stored_output_mode) ||
          snapshot.device.board_compatibility_id == 0 ||
          !CanonicalRelease(snapshot.device.release)) {
        output->fill(0);
        return false;
      }
      (*output)[1] =
          static_cast<std::uint8_t>(snapshot.device.active_output_mode);
      (*output)[2] =
          static_cast<std::uint8_t>(snapshot.device.stored_output_mode);
      (*output)[3] = snapshot.device.board_compatibility_id;
      std::copy(snapshot.device.release.begin(), snapshot.device.release.end(),
                output->begin() + 4);
      Put32(output->data() + 12, snapshot.device.capabilities);
      return true;
    case protocol::LocalManagementStatusPage::kSafety: {
      std::uint8_t flags = 0;
      flags |= snapshot.safety.maintenance_active ? 0x01 : 0;
      flags |= snapshot.safety.command_active ? 0x02 : 0;
      flags |= snapshot.safety.armed ? 0x04 : 0;
      flags |= snapshot.safety.usb_mounted ? 0x08 : 0;
      flags |= snapshot.safety.keyboard_neutral ? 0x10 : 0;
      flags |= snapshot.safety.mouse_neutral ? 0x20 : 0;
      flags |= snapshot.safety.restart_pending ? 0x40 : 0;
      flags |= snapshot.safety.receipt_storage_healthy ? 0x80 : 0;
      (*output)[1] = flags;
      Put32(output->data() + 4,
            snapshot.safety.usb_attachment_generation);
      return true;
    }
    case protocol::LocalManagementStatusPage::kNetwork: {
      if (snapshot.network.wifi_stage > 15 ||
          snapshot.network.active_path > 2 ||
          snapshot.network.wifi_profile_count > 8 ||
          snapshot.network.paired_host_count > 8 ||
          snapshot.network.policy_state > 5) {
        output->fill(0);
        return false;
      }
      (*output)[1] = snapshot.network.wifi_stage;
      (*output)[2] = snapshot.network.active_path;
      (*output)[3] = (snapshot.network.running ? 0x01 : 0) |
                     (snapshot.network.wifi_available ? 0x02 : 0) |
                     (snapshot.network.ble_available ? 0x04 : 0) |
                     (snapshot.network.endpoint_authenticated ? 0x08 : 0) |
                     (snapshot.network.configuration_valid ? 0x10 : 0);
      (*output)[4] = snapshot.network.wifi_profile_count;
      (*output)[5] = snapshot.network.paired_host_count;
      (*output)[6] = snapshot.network.policy_state;
      Put32(output->data() + 8,
            static_cast<std::uint32_t>(snapshot.network.wifi_error));
      Put32(output->data() + 12,
            static_cast<std::uint32_t>(snapshot.network.nvs_error));
      return true;
    }
    case protocol::LocalManagementStatusPage::kBleHid:
      if (snapshot.ble_hid.bond_state >
              protocol::LocalManagementBondState::kStoreError ||
          snapshot.ble_hid.peripheral_stage > 8 ||
          snapshot.ble_hid.enrollment_remaining_ms >
              protocol::kLocalManagementEnrollmentTimeoutMs) {
        output->fill(0);
        return false;
      }
      (*output)[1] = static_cast<std::uint8_t>(snapshot.ble_hid.bond_state);
      (*output)[2] = snapshot.ble_hid.peripheral_stage;
      (*output)[3] = (snapshot.ble_hid.advertising ? 0x01 : 0) |
                     (snapshot.ble_hid.connected ? 0x02 : 0) |
                     (snapshot.ble_hid.authenticated ? 0x04 : 0) |
                     (snapshot.ble_hid.subscribed ? 0x08 : 0) |
                     (snapshot.ble_hid.ready ? 0x10 : 0) |
                     (snapshot.ble_hid.enrollment_active ? 0x20 : 0);
      Put32(output->data() + 4,
            static_cast<std::uint32_t>(snapshot.ble_hid.error));
      Put32(output->data() + 8, snapshot.ble_hid.generation);
      Put32(output->data() + 12,
            snapshot.ble_hid.enrollment_remaining_ms);
      return true;
    case protocol::LocalManagementStatusPage::kPolicy:
      if (snapshot.policy.state > 5) {
        output->fill(0);
        return false;
      }
      (*output)[1] = snapshot.policy.state;
      Put64(output->data() + 8, snapshot.policy.sequence);
      return true;
    case protocol::LocalManagementStatusPage::kLastReceipt:
      if (!snapshot.has_last_receipt) {
        (*output)[1] = static_cast<std::uint8_t>(
            protocol::LocalManagementReceiptState::kNone);
        return true;
      }
      if (!ValidReceipt(snapshot.last_receipt)) {
        output->fill(0);
        return false;
      }
      (*output)[1] =
          static_cast<std::uint8_t>(snapshot.last_receipt.state);
      (*output)[2] =
          static_cast<std::uint8_t>(snapshot.last_receipt.operation);
      (*output)[3] = static_cast<std::uint8_t>(snapshot.last_receipt.result);
      (*output)[4] = snapshot.last_receipt.flags;
      (*output)[5] =
          static_cast<std::uint8_t>(snapshot.last_receipt.argument & 0xFF);
      (*output)[6] =
          static_cast<std::uint8_t>(snapshot.last_receipt.argument >> 8);
      return true;
    case protocol::LocalManagementStatusPage::kProbeRun:
    case protocol::LocalManagementStatusPage::kProbeHeap:
    case protocol::LocalManagementStatusPage::kProbeStack: {
      const auto& probe = snapshot.probe;
      if (!snapshot.probe_available || probe.sample_seq == 0 ||
          probe.phase < static_cast<std::uint8_t>(
                            protocol::LocalManagementProbePhase::kBoot) ||
          probe.phase > static_cast<std::uint8_t>(
                            protocol::LocalManagementProbePhase::kWaiting) ||
          (probe.held_flags & ~std::uint8_t{0x03}) != 0 ||
          probe.first_outcome > static_cast<std::uint8_t>(
                                    protocol::LocalManagementProbeOutcome::kPostGuardFailed) ||
          probe.second_outcome > static_cast<std::uint8_t>(
                                     protocol::LocalManagementProbeOutcome::kPostGuardFailed) ||
          probe.link > 2 ||
          (probe.output_mode !=
               static_cast<std::uint8_t>(protocol::OutputMode::kUsbHid) &&
           probe.output_mode !=
               static_cast<std::uint8_t>(protocol::OutputMode::kBleHid))) {
        output->fill(0);
        return false;
      }
      Put16(output->data() + 1, probe.sample_seq);
      if (page == protocol::LocalManagementStatusPage::kProbeRun) {
        (*output)[3] = probe.phase;
        Put32(output->data() + 4, probe.uptime_seconds);
        (*output)[8] = probe.held_flags;
        (*output)[9] = probe.first_outcome;
        (*output)[10] = probe.second_outcome;
        (*output)[11] = probe.transport_running ? 1 : 0;
        (*output)[12] = probe.link;
        (*output)[13] = probe.output_mode;
      } else if (page == protocol::LocalManagementStatusPage::kProbeHeap) {
        Put32(output->data() + 4, probe.free_internal_heap);
        Put32(output->data() + 8, probe.largest_internal_block);
        Put32(output->data() + 12, probe.minimum_internal_heap);
      } else {
        Put32(output->data() + 4, probe.main_stack_free);
        Put32(output->data() + 8, probe.transport_stack_free);
        Put32(output->data() + 12, probe.probe_stack_free);
      }
      return true;
    }
  }
  output->fill(0);
  return false;
}

}  // namespace keyferry::local_management
