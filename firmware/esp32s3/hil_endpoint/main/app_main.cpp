#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <optional>

#include "board_profile.h"
#include "class/hid/hid_device.h"
#if defined(KEYFERRY_MSC_SIZE_PROBE) || defined(KEYFERRY_FILE_HANDOFF)
#include "class/msc/msc_device.h"
#endif
#if defined(KEYFERRY_FILE_HANDOFF)
#include "keyferry/file_handoff.h"
#include "mbedtls/md.h"
#endif
#include "esp_err.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#if defined(KEYFERRY_FILE_HANDOFF) && defined(CONFIG_SPIRAM)
#include "esp_psram.h"
#endif
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "keyferry/command_executor.h"
#include "keyferry/idf_ble_hid_peripheral.h"
#include "keyferry/esp_transport.h"
#include "keyferry/esp_provisioning.h"
#include "keyferry/esp_status_display.h"
#include "keyferry/hid_executor.h"
#include "keyferry/idf_held_key_watchdog.h"
#include "keyferry/idf_config_storage.h"
#include "keyferry/idf_recovery_anchor_storage.h"
#include "keyferry/idf_roaming_policy_crypto.h"
#include "keyferry/idf_local_management_receipts.h"
#include "keyferry/local_management_receipts.h"
#include "keyferry/local_management_status.h"
#include "keyferry/idf_output_mode_storage.h"
#include "keyferry/display_orientation.h"
#include "keyferry/idf_display_orientation_storage.h"
#include "keyferry/output_mode.h"
#include "keyferry/runtime_config.h"
#include "keyferry/status.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "nvs_flash.h"

#include "provisioning_adapter.h"

#ifndef KEYFERRY_HIL_PRIVATE_CONFIG
#error "first-HIL firmware requires generated private configuration"
#endif
#include "keyferry_hil_private.h"

namespace {

using keyferry::hid::BootKeyboardReport;
using keyferry::hid::BootMouseReport;

constexpr char kTag[] = "keyferry_hil";
constexpr std::uint8_t kKeyboardInterface = 0;
constexpr std::uint8_t kProvisioningInterface = 1;
constexpr std::uint8_t kMouseInterface = 2;
constexpr std::uint8_t kKeyboardString = 4;
constexpr std::uint8_t kProvisioningString = 5;
constexpr std::uint8_t kMouseString = 6;
constexpr std::uint8_t kKeyboardEndpoint = 0x81;
constexpr std::uint8_t kProvisioningOutEndpoint = 0x02;
constexpr std::uint8_t kProvisioningInEndpoint = 0x82;
constexpr std::uint8_t kMouseEndpoint = 0x83;
#if defined(KEYFERRY_MSC_SIZE_PROBE) || defined(KEYFERRY_FILE_HANDOFF)
constexpr std::uint8_t kMscInterface = 3;
constexpr std::uint8_t kMscOutEndpoint = 0x04;
constexpr std::uint8_t kMscInEndpoint = 0x84;
constexpr std::uint8_t kMscString = 7;
#endif
constexpr std::uint8_t kKeyboardEndpointSize = 8;
constexpr std::uint8_t kProvisioningEndpointSize =
    keyferry::provisioning::kReportBytes;
constexpr std::uint8_t kHidPollIntervalMs = 10;
constexpr std::uint16_t kUsbPowerMilliamps = 100;
constexpr std::uint16_t kConfigurationLength =
    TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN + TUD_HID_INOUT_DESC_LEN +
    TUD_HID_DESC_LEN
#if defined(KEYFERRY_MSC_SIZE_PROBE) || defined(KEYFERRY_FILE_HANDOFF)
    + TUD_MSC_DESC_LEN
#endif
    ;
constexpr std::uint16_t kBleControlConfigurationLength =
    TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN
#if defined(KEYFERRY_MSC_SIZE_PROBE) || defined(KEYFERRY_FILE_HANDOFF)
    + TUD_MSC_DESC_LEN
#endif
    ;
constexpr std::size_t kResultQueueCapacity = 8;
#if defined(KEYFERRY_FILE_HANDOFF)
constexpr std::uint32_t kFileHeapReserveBytes = 32768;
// Dynamic mbedTLS may need a full inbound record after publication. Include
// header/allocator slack as well as the unchanged 16 KiB TLS content limit.
constexpr std::uint32_t kFileTlsRxReserveBytes =
    CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN + 512U;
std::uint32_t FileReadLe32(const std::uint8_t* bytes) {
  return static_cast<std::uint32_t>(bytes[0]) |
         (static_cast<std::uint32_t>(bytes[1]) << 8) |
         (static_cast<std::uint32_t>(bytes[2]) << 16) |
         (static_cast<std::uint32_t>(bytes[3]) << 24);
}
void FileWriteLe32(std::uint8_t* bytes, const std::uint32_t value) {
  bytes[0] = static_cast<std::uint8_t>(value);
  bytes[1] = static_cast<std::uint8_t>(value >> 8);
  bytes[2] = static_cast<std::uint8_t>(value >> 16);
  bytes[3] = static_cast<std::uint8_t>(value >> 24);
}
bool FileSha256(const std::uint8_t* bytes, const std::size_t length,
                std::uint8_t output[32], void*) {
  const auto* sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return sha256 != nullptr && mbedtls_md(sha256, bytes, length, output) == 0;
}
#endif
#if defined(KEYFERRY_MSC_MEMORY_PROBE)
portMUX_TYPE g_msc_probe_status_mux = portMUX_INITIALIZER_UNLOCKED;
keyferry::local_management::ProbeStatus g_msc_probe_status{};
bool g_msc_probe_status_available = false;

std::uint16_t PublishMscProbeStatus(
    keyferry::local_management::ProbeStatus sample) {
  portENTER_CRITICAL(&g_msc_probe_status_mux);
  sample.sample_seq = static_cast<std::uint16_t>(g_msc_probe_status.sample_seq + 1);
  if (sample.sample_seq == 0) {
    sample.sample_seq = 1;
  }
  g_msc_probe_status = sample;
  g_msc_probe_status_available = true;
  portEXIT_CRITICAL(&g_msc_probe_status_mux);
  return sample.sample_seq;
}

bool CopyMscProbeStatus(keyferry::local_management::ProbeStatus* output) {
  portENTER_CRITICAL(&g_msc_probe_status_mux);
  const bool available = g_msc_probe_status_available;
  if (available) {
    *output = g_msc_probe_status;
  }
  portEXIT_CRITICAL(&g_msc_probe_status_mux);
  return available;
}
#endif
// Roaming policy verification uses boot-owned scratch storage instead of this
// task's stack. Reserve the task itself statically so transport startup cannot
// depend on a contiguous heap allocation after USB initialization.
constexpr std::uint32_t kTransportTaskStackBytes = 12288;
static_assert(kTransportTaskStackBytes % sizeof(StackType_t) == 0);
constexpr std::array<std::uint8_t, 32> kWindowsUsProfileHash{
    0x73, 0x0c, 0x3f, 0xc2, 0xd4, 0x9f, 0x2c, 0x09, 0x2d, 0xe5, 0x91,
    0x7d, 0x8f, 0x73, 0xdc, 0xb8, 0x8c, 0x7f, 0x32, 0x46, 0x2a, 0xc8,
    0x06, 0x87, 0x7f, 0x0b, 0xe1, 0xca, 0x7f, 0x40, 0xbe, 0xf4};

static constexpr std::uint8_t kKeyboardReportDescriptor[] = {
    TUD_HID_REPORT_DESC_KEYBOARD(),
};

static constexpr std::uint8_t kProvisioningReportDescriptor[] = {
    TUD_HID_REPORT_DESC_GENERIC_INOUT(kProvisioningEndpointSize),
};

// Three buttons plus signed relative X/Y. Boot and Report protocol are deliberately identical:
// there is no report ID, wheel, pan, absolute axis, output, or feature report.
static constexpr std::uint8_t kMouseReportDescriptor[] = {
    0x05, 0x01,  // Usage Page (Generic Desktop)
    0x09, 0x02,  // Usage (Mouse)
    0xA1, 0x01,  // Collection (Application)
    0x09, 0x01,  // Usage (Pointer)
    0xA1, 0x00,  // Collection (Physical)
    0x05, 0x09,  // Usage Page (Button)
    0x19, 0x01,  // Usage Minimum (Button 1)
    0x29, 0x03,  // Usage Maximum (Button 3)
    0x15, 0x00,  // Logical Minimum (0)
    0x25, 0x01,  // Logical Maximum (1)
    0x95, 0x03,  // Report Count (3)
    0x75, 0x01,  // Report Size (1)
    0x81, 0x02,  // Input (Data, Variable, Absolute)
    0x95, 0x01,  // Report Count (1)
    0x75, 0x05,  // Report Size (5)
    0x81, 0x03,  // Input (Constant, Variable, Absolute)
    0x05, 0x01,  // Usage Page (Generic Desktop)
    0x09, 0x30,  // Usage (X)
    0x09, 0x31,  // Usage (Y)
    0x15, 0x81,  // Logical Minimum (-127)
    0x25, 0x7F,  // Logical Maximum (127)
    0x75, 0x08,  // Report Size (8)
    0x95, 0x02,  // Report Count (2)
    0x81, 0x06,  // Input (Data, Variable, Relative)
    0xC0,        // End Collection
    0xC0,        // End Collection
};
static_assert(sizeof(kMouseReportDescriptor) == 50);

static constexpr std::uint8_t kConfigurationDescriptor[] = {
#if defined(KEYFERRY_MSC_SIZE_PROBE) || defined(KEYFERRY_FILE_HANDOFF)
    TUD_CONFIG_DESCRIPTOR(1, 4, 0, kConfigurationLength, 0, kUsbPowerMilliamps),
#else
    TUD_CONFIG_DESCRIPTOR(1, 3, 0, kConfigurationLength, 0, kUsbPowerMilliamps),
#endif
    TUD_HID_DESCRIPTOR(kKeyboardInterface, kKeyboardString,
                       HID_ITF_PROTOCOL_KEYBOARD,
                       sizeof(kKeyboardReportDescriptor), kKeyboardEndpoint,
                       kKeyboardEndpointSize,
                       kHidPollIntervalMs),
    TUD_HID_INOUT_DESCRIPTOR(
        kProvisioningInterface, kProvisioningString, HID_ITF_PROTOCOL_NONE,
        sizeof(kProvisioningReportDescriptor), kProvisioningOutEndpoint,
        kProvisioningInEndpoint, kProvisioningEndpointSize,
        kHidPollIntervalMs),
    TUD_HID_DESCRIPTOR(kMouseInterface, kMouseString,
                       HID_ITF_PROTOCOL_MOUSE,
                       sizeof(kMouseReportDescriptor), kMouseEndpoint,
                       kKeyboardEndpointSize, kHidPollIntervalMs),
#if defined(KEYFERRY_MSC_SIZE_PROBE) || defined(KEYFERRY_FILE_HANDOFF)
    TUD_MSC_DESCRIPTOR(kMscInterface, kMscString, kMscOutEndpoint,
                       kMscInEndpoint, 64),
#endif
};

static_assert(sizeof(kConfigurationDescriptor) == kConfigurationLength);
#if defined(KEYFERRY_MSC_SIZE_PROBE) || defined(KEYFERRY_FILE_HANDOFF)
static_assert(kConfigurationDescriptor[4] == 4);
static_assert(kConfigurationDescriptor[91 + 2] == kMscInterface);
#else
static_assert(kConfigurationDescriptor[4] == 3);
#endif
static_assert(kConfigurationDescriptor[11] == kKeyboardInterface);
static_assert(kConfigurationDescriptor[13] == 1);
static_assert(kConfigurationDescriptor[14] == TUSB_CLASS_HID);
static_assert(kConfigurationDescriptor[15] == HID_SUBCLASS_BOOT);
static_assert(kConfigurationDescriptor[16] == HID_ITF_PROTOCOL_KEYBOARD);
static_assert(kConfigurationDescriptor[29] == kKeyboardEndpoint);
static_assert(kConfigurationDescriptor[31] == kKeyboardEndpointSize);
static_assert(kConfigurationDescriptor[36] == kProvisioningInterface);
static_assert(kConfigurationDescriptor[38] == 2);
static_assert(kConfigurationDescriptor[39] == TUSB_CLASS_HID);
static_assert(kConfigurationDescriptor[40] == HID_SUBCLASS_NONE);
static_assert(kConfigurationDescriptor[41] == HID_ITF_PROTOCOL_NONE);
static_assert(kConfigurationDescriptor[54] == kProvisioningOutEndpoint);
static_assert(kConfigurationDescriptor[56] == kProvisioningEndpointSize);
static_assert(kConfigurationDescriptor[61] == kProvisioningInEndpoint);
static_assert(kConfigurationDescriptor[63] == kProvisioningEndpointSize);
static_assert(kConfigurationDescriptor[68] == kMouseInterface);
static_assert(kConfigurationDescriptor[70] == 1);
static_assert(kConfigurationDescriptor[71] == TUSB_CLASS_HID);
static_assert(kConfigurationDescriptor[72] == HID_SUBCLASS_BOOT);
static_assert(kConfigurationDescriptor[73] == HID_ITF_PROTOCOL_MOUSE);
static_assert(kConfigurationDescriptor[86] == kMouseEndpoint);
static_assert(kConfigurationDescriptor[88] == kKeyboardEndpointSize);

// BLE keyboard output remains exclusive. USB exposes only the authenticated
// provisioning channel so a cable can repair Wi-Fi or configuration without
// creating a second keyboard or mouse on the controller computer.
static constexpr std::uint8_t kBleControlConfigurationDescriptor[] = {
#if defined(KEYFERRY_MSC_SIZE_PROBE) || defined(KEYFERRY_FILE_HANDOFF)
    TUD_CONFIG_DESCRIPTOR(1, 2, 0, kBleControlConfigurationLength, 0,
                          kUsbPowerMilliamps),
#else
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, kBleControlConfigurationLength, 0,
                          kUsbPowerMilliamps),
#endif
    TUD_HID_INOUT_DESCRIPTOR(
        0, kProvisioningString, HID_ITF_PROTOCOL_NONE,
        sizeof(kProvisioningReportDescriptor), kProvisioningOutEndpoint,
        kProvisioningInEndpoint, kProvisioningEndpointSize,
        kHidPollIntervalMs),
#if defined(KEYFERRY_MSC_SIZE_PROBE) || defined(KEYFERRY_FILE_HANDOFF)
    TUD_MSC_DESCRIPTOR(1, kMscString, kMscOutEndpoint, kMscInEndpoint, 64),
#endif
};
static_assert(sizeof(kBleControlConfigurationDescriptor) ==
              kBleControlConfigurationLength);
#if defined(KEYFERRY_MSC_SIZE_PROBE) || defined(KEYFERRY_FILE_HANDOFF)
static_assert(kBleControlConfigurationDescriptor[4] == 2);
static_assert(kBleControlConfigurationDescriptor[41 + 2] == 1);
#else
static_assert(kBleControlConfigurationDescriptor[4] == 1);
#endif
static_assert(kBleControlConfigurationDescriptor[11] == 0);
static_assert(kBleControlConfigurationDescriptor[13] == 2);
static_assert(kBleControlConfigurationDescriptor[14] == TUSB_CLASS_HID);
static_assert(kBleControlConfigurationDescriptor[15] == HID_SUBCLASS_NONE);
static_assert(kBleControlConfigurationDescriptor[16] ==
              HID_ITF_PROTOCOL_NONE);
static_assert(kBleControlConfigurationDescriptor[29] ==
              kProvisioningOutEndpoint);
static_assert(kBleControlConfigurationDescriptor[36] ==
              kProvisioningInEndpoint);

static constexpr tusb_desc_device_t kDeviceDescriptor = {
    sizeof(tusb_desc_device_t), TUSB_DESC_DEVICE, 0x0200, 0x00, 0x00, 0x00,
    CFG_TUD_ENDPOINT0_SIZE,     TINYUSB_ESPRESSIF_VID,
#if defined(KEYFERRY_MSC_SIZE_PROBE)
    0x4006,
#elif defined(KEYFERRY_FILE_HANDOFF)
    0x4008,
#else
    0x4004,
#endif
    0x0101, 1,
    2,                          3,                     1,
};
static_assert(kDeviceDescriptor.idVendor == TINYUSB_ESPRESSIF_VID);
static_assert(kDeviceDescriptor.bcdDevice == 0x0101);
#if defined(KEYFERRY_MSC_SIZE_PROBE)
static_assert(kDeviceDescriptor.idProduct == 0x4006);
#elif defined(KEYFERRY_FILE_HANDOFF)
static_assert(kDeviceDescriptor.idProduct == 0x4008);
#else
static_assert(kDeviceDescriptor.idProduct == 0x4004);
#endif
static_assert(kDeviceDescriptor.bNumConfigurations == 1);

static constexpr tusb_desc_device_t kBleControlDeviceDescriptor = {
    sizeof(tusb_desc_device_t), TUSB_DESC_DEVICE, 0x0200, 0x00, 0x00, 0x00,
    CFG_TUD_ENDPOINT0_SIZE,     TINYUSB_ESPRESSIF_VID,
#if defined(KEYFERRY_MSC_SIZE_PROBE)
    0x4007,
#elif defined(KEYFERRY_FILE_HANDOFF)
    0x4009,
#else
    0x4005,
#endif
    0x0101, 1,
    2,                          3,                     1,
};
static_assert(kBleControlDeviceDescriptor.idVendor == TINYUSB_ESPRESSIF_VID);
#if defined(KEYFERRY_MSC_SIZE_PROBE)
static_assert(kBleControlDeviceDescriptor.idProduct == 0x4007);
#elif defined(KEYFERRY_FILE_HANDOFF)
static_assert(kBleControlDeviceDescriptor.idProduct == 0x4009);
#else
static_assert(kBleControlDeviceDescriptor.idProduct == 0x4005);
#endif
static_assert(kBleControlDeviceDescriptor.bNumConfigurations == 1);

static char kEnglishLanguage[] = {0x09, 0x04};
static std::array<char, 33> kSerialDescriptor{};
static const char* kStringDescriptors[] = {
    kEnglishLanguage,
    "keyferry",
    "keyferry owner device",
    kSerialDescriptor.data(),
    "Boot keyboard",
    "Authenticated provisioning",
    "Relative mouse",
#if defined(KEYFERRY_MSC_SIZE_PROBE)
    "Empty MSC size probe",
#elif defined(KEYFERRY_FILE_HANDOFF)
    "KEYFERRY file handoff",
#endif
};

struct PendingResult {
  std::uint32_t sequence{};
  std::array<std::uint8_t, 16> command_id{};
  keyferry::protocol::ResultCode result{keyferry::protocol::ResultCode::kRejected};
  bool input{};
  keyferry::command::InputResultEvidence input_evidence{};
};

struct PendingModeStatus {
  std::uint32_t sequence{};
  keyferry::protocol::OutputMode stored{keyferry::protocol::OutputMode::kUsbHid};
  bool available{};
  bool restart_after_send{};
};

struct PendingBondResetStatus {
  std::uint32_t sequence{};
  std::uint8_t result{};
  bool available{};
  bool restart_after_send{};
};

struct PendingDisplayOrientationStatus {
  std::uint32_t sequence{};
  keyferry::protocol::DisplayOrientation stored{
      keyferry::protocol::DisplayOrientation::kNormal};
  bool available{};
  bool restart_after_send{};
};

struct PendingScreenPowerStatus {
  std::uint32_t sequence{};
  keyferry::protocol::ScreenPower active{keyferry::protocol::ScreenPower::kOn};
  keyferry::protocol::ScreenPower stored{keyferry::protocol::ScreenPower::kOn};
  bool hardware_available{};
  bool available{};
};

#if defined(KEYFERRY_FILE_HANDOFF)
struct PendingFileStatus {
  std::uint32_t sequence{};
  keyferry::file_handoff::FileStatus status{};
  bool available{};
  bool refresh_after_send{};
  bool clear_on_detach{};
};
struct PendingFileSetStatus {
  std::uint32_t sequence{};
  keyferry::file_handoff::FileSetStatus status{};
  std::array<std::uint8_t, keyferry::file_handoff::kMaximumNameBytes> name{};
  bool available{};
  bool refresh_after_send{};
  bool clear_on_detach{};
};
#endif

struct LocalManagementMetadata {
  std::array<std::uint8_t, 8> release{};
  std::uint32_t capabilities{};
  std::uint64_t policy_sequence{};
  keyferry::local_management::ReceiptJournal* receipts{};
  std::uint8_t board_compatibility_id{};
  std::uint8_t wifi_profile_count{};
  std::uint8_t paired_host_count{};
  std::uint8_t policy_state{};
  bool configuration_valid{};
  bool receipt_storage_healthy{};
};

class HilRuntime final : public keyferry::transport::Delegate,
                          public keyferry::command::ResultSink,
                          public keyferry::hil::ProvisioningPolicy,
                          public keyferry::local_management::Platform {
 public:
  HilRuntime(const keyferry::protocol::OutputMode output_mode,
             const keyferry::protocol::OutputMode stored_output_mode,
             keyferry::output_mode::Storage& output_mode_storage,
             const keyferry::protocol::DisplayOrientation display_orientation,
             keyferry::display_orientation::Storage& display_orientation_storage,
             const keyferry::protocol::ScreenPower screen_power)
      : output_mode_(output_mode),
        stored_output_mode_(stored_output_mode),
        output_mode_storage_(output_mode_storage),
        display_orientation_(display_orientation),
        stored_display_orientation_(display_orientation),
        display_orientation_storage_(display_orientation_storage),
        screen_power_(screen_power),
        command_(hid_, *this, watchdog_, kWindowsUsProfileHash) {}

  bool Initialize() {
    lock_ = xSemaphoreCreateMutex();
    if (lock_ == nullptr || !watchdog_.Initialize(WatchdogCallback, this)) {
      return false;
    }
    return output_mode_ == keyferry::protocol::OutputMode::kUsbHid
               ? hid_.enable_mouse_interface()
               : ble_hid_.Initialize();
  }

  void SetTransport(keyferry::transport::EspTransport* transport) { transport_ = transport; }

  bool ScreenPowerDesired(keyferry::protocol::ScreenPower* output) {
    if (output == nullptr || !Lock()) return false;
    *output = screen_power_.stored();
    Unlock();
    return true;
  }

  void ScreenPowerApplied(const keyferry::protocol::ScreenPower power,
                          const bool succeeded) {
    if (!Lock()) return;
    if (succeeded) {
      screen_power_.Applied(power);
    } else {
      screen_power_.Unavailable();
    }
    Unlock();
  }

#if defined(KEYFERRY_FILE_HANDOFF)
  bool FileReady() {
    if (!Lock()) return false;
    const bool ready = file_volume_ != nullptr && file_volume_->Ready();
    Unlock();
    return ready;
  }

  bool FileRead(std::uint32_t lba, std::uint32_t offset,
                std::uint8_t* output, std::size_t length) {
    if (!Lock()) return false;
    bool read = file_volume_ != nullptr && output != nullptr && length != 0 &&
                offset < keyferry::file_handoff::kBlockBytes &&
                static_cast<std::uint64_t>(lba) * keyferry::file_handoff::kBlockBytes +
                    offset + length <=
                    static_cast<std::uint64_t>(keyferry::file_handoff::kBlockCount) *
                        keyferry::file_handoff::kBlockBytes;
    while (read && length != 0) {
      const auto bytes = std::min<std::size_t>(
          length, keyferry::file_handoff::kBlockBytes - offset);
      read = file_volume_->Read(lba, offset, output, bytes);
      output += bytes;
      length -= bytes;
      ++lba;
      offset = 0;
    }
    Unlock();
    return read;
  }

  bool TakeFileMediaRefresh() {
    if (!Lock()) return false;
    const bool requested = file_refresh_ready_ && NeutralConfirmedLocked();
    if (requested) {
      file_refresh_ready_ = false;
      file_refresh_in_flight_ = true;
    }
    Unlock();
    return requested;
  }

  void FileMediaDetached() {
    if (!Lock()) return;
    usb_mounted_ = false;
    ++usb_attachment_generation_;
    if (usb_attachment_generation_ == 0) ++usb_attachment_generation_;
    if (output_mode_ == keyferry::protocol::OutputMode::kUsbHid) {
      hid_.on_transport_lost();
      hid_.request_dual_neutral();
      file_neutral_pending_ = true;
    }
    if (file_clear_on_detach_) ReleaseFileVolumeLocked();
    file_clear_on_detach_ = false;
    Unlock();
  }
#endif

  void ConfigureLocalManagement(const LocalManagementMetadata& metadata) {
    if (!Lock()) {
      return;
    }
    local_management_metadata_ = metadata;
    Unlock();
  }

  void SetUsbMounted(const bool mounted) {
    if (!Lock()) {
      return;
    }
    usb_mounted_ = mounted;
#if defined(KEYFERRY_FILE_HANDOFF)
    if (mounted) file_refresh_in_flight_ = false;
#endif
    if (output_mode_ == keyferry::protocol::OutputMode::kBleHid) {
      Unlock();
      return;
    }
    ++usb_attachment_generation_;
    if (usb_attachment_generation_ == 0) {
      ++usb_attachment_generation_;
    }
    if (mounted) {
      hid_.on_transport_ready();
    } else {
      command_.UsbFault();
      hid_.on_transport_lost();
#if defined(KEYFERRY_FILE_HANDOFF)
      ReleaseFileVolumeLocked();
      file_neutral_pending_ = false;
#endif
      authenticated_epoch_ = 0;
      peer_input_v1_ = false;
#if defined(KEYFERRY_FILE_HANDOFF)
      file_negotiated_ = false;
      file_set_negotiated_ = false;
#endif
      disarm_waiting_ = false;
      provisioning_active_ = false;
      usb_transfer_in_flight_ = false;
      usb_transfer_interface_ = keyferry::hid::InputInterface::keyboard;
      usb_transfer_mouse_report_ = {};
      usb_transfer_mouse_token_ = 0;
      usb_transfer_epoch_ = 0;
      usb_transfer_generation_ = 0;
      session_abort_requested_ = true;
      ClearResults();
    }
    Unlock();
  }

  BootKeyboardReport CurrentReport() {
    if (!Lock()) {
      return {};
    }
    const auto report = hid_.current_report();
    Unlock();
    return report;
  }

  BootMouseReport CurrentMouseReport() {
    if (!Lock()) {
      return {};
    }
    // Relative displacement is an event and is never cached for GET_REPORT or idle traffic.
    const auto report = BootMouseReport{hid_.current_mouse_report().buttons, 0, 0};
    Unlock();
    return report;
  }

  void ServiceUsb() {
    if (output_mode_ != keyferry::protocol::OutputMode::kUsbHid) {
      ServiceBleHid();
      return;
    }
    if (!Lock()) {
      return;
    }
    if (!usb_mounted_ || usb_transfer_in_flight_ || !hid_.report_needed()) {
      Unlock();
      return;
    }
    const auto interface = hid_.desired_interface();
    const auto instance = interface == keyferry::hid::InputInterface::keyboard
                              ? keyferry::hil::kKeyboardHidInstance
                              : keyferry::hil::kMouseHidInstance;
    if (!tud_hid_n_ready(instance)) {
      Unlock();
      return;
    }
    bool queued = false;
    if (interface == keyferry::hid::InputInterface::keyboard) {
      const auto report = hid_.desired_report();
      queued = tud_hid_n_report(instance, 0, &report, sizeof(report));
      if (queued) {
        usb_transfer_report_ = report;
        usb_transfer_mouse_report_ = {};
        usb_transfer_mouse_token_ = 0;
        if (!keyferry::hid::is_zero(report)) {
          command_.UsbReportAccepted(
              report, keyferry::command::IdfHeldKeyWatchdog::NowMs());
        }
      }
    } else {
      const auto report = hid_.desired_mouse_report();
      const auto token = hid_.desired_mouse_logical_token();
      queued = tud_hid_n_report(instance, 0, &report, sizeof(report));
      if (queued) {
        usb_transfer_report_ = {};
        usb_transfer_mouse_report_ = report;
        usb_transfer_mouse_token_ = token;
        if (!keyferry::hid::is_zero(report)) {
          command_.UsbMouseReportAccepted(
              report, token, keyferry::command::IdfHeldKeyWatchdog::NowMs());
        }
      }
    }
    if (queued) {
      usb_transfer_in_flight_ = true;
      usb_transfer_interface_ = interface;
      usb_transfer_epoch_ = authenticated_epoch_;
      usb_transfer_generation_ = usb_attachment_generation_;
    }
    Unlock();
  }

  void UsbReportCompleted(const std::uint8_t instance,
                          const std::uint8_t* report_bytes,
                          const std::uint16_t length) {
    if (!Lock()) {
      return;
    }
    const auto expected_instance =
        usb_transfer_interface_ == keyferry::hid::InputInterface::keyboard
            ? keyferry::hil::kKeyboardHidInstance
            : keyferry::hil::kMouseHidInstance;
    const bool keyboard =
        usb_transfer_interface_ == keyferry::hid::InputInterface::keyboard;
    const auto expected_length = keyboard ? sizeof(BootKeyboardReport)
                                          : sizeof(BootMouseReport);
    const void* expected_report = keyboard
                                      ? static_cast<const void*>(&usb_transfer_report_)
                                      : static_cast<const void*>(&usb_transfer_mouse_report_);
    if (!usb_transfer_in_flight_ || report_bytes == nullptr ||
        instance != expected_instance || length != expected_length ||
        usb_transfer_generation_ != usb_attachment_generation_ ||
        usb_transfer_epoch_ != authenticated_epoch_ ||
        std::memcmp(report_bytes, expected_report, expected_length) != 0) {
      UsbTransferFailedLocked();
      Unlock();
      return;
    }
    const auto keyboard_report = usb_transfer_report_;
    const auto mouse_report = usb_transfer_mouse_report_;
    const auto mouse_token = usb_transfer_mouse_token_;
    usb_transfer_in_flight_ = false;
    usb_transfer_report_ = {};
    usb_transfer_mouse_report_ = {};
    usb_transfer_mouse_token_ = 0;
    usb_transfer_epoch_ = 0;
    usb_transfer_generation_ = 0;
    // Neutral evidence advances only after a matching TinyUSB completion callback.
    if (keyboard && keyferry::hid::is_zero(keyboard_report)) {
      command_.UsbReportAccepted(
          keyboard_report, keyferry::command::IdfHeldKeyWatchdog::NowMs());
    } else if (!keyboard && keyferry::hid::is_zero(mouse_report)) {
      command_.UsbMouseReportAccepted(
          mouse_report, mouse_token,
          keyferry::command::IdfHeldKeyWatchdog::NowMs());
    }
    Unlock();
  }

  void UsbReportFailed(const std::uint8_t instance) {
    if (!Lock()) {
      return;
    }
    // Any failed callback is terminal. The instance still participates in the
    // explicit callback dispatch; there is no safe report to acknowledge.
    static_cast<void>(instance);
    UsbTransferFailedLocked();
    Unlock();
  }

  void Poll() {
    if (!Lock()) {
      return;
    }
    command_.Poll(keyferry::command::IdfHeldKeyWatchdog::NowMs());
#if defined(KEYFERRY_FILE_HANDOFF)
    const auto now_ms = keyferry::command::IdfHeldKeyWatchdog::NowMs();
    if (file_volume_ != nullptr &&
        file_volume_->Status().state == keyferry::file_handoff::State::kReceiving &&
        now_ms - file_upload_last_ms_ > 30000) {
      ReleaseFileVolumeLocked();
    }
#endif
    Unlock();
  }

  void FailClosed(std::uint64_t) override {
    if (!Lock()) {
      return;
    }
    command_.EndSession();
#if defined(KEYFERRY_FILE_HANDOFF)
    ReleaseFileVolumeLocked();
#endif
    hid_.fault();
    ClearResults();
    authenticated_epoch_ = 0;
    peer_input_v1_ = false;
#if defined(KEYFERRY_FILE_HANDOFF)
    file_negotiated_ = false;
    file_set_negotiated_ = false;
    file_neutral_pending_ = false;
#endif
    disarm_waiting_ = false;
    provisioning_active_ = false;
    Unlock();
  }

  bool SessionAuthenticated(const std::uint64_t epoch,
                            const keyferry::endpoint::SessionReady& ready) override {
    if (epoch == 0 ||
        (ready.capability_mask &
         static_cast<std::uint32_t>(keyferry::protocol::Capability::kKeyboard)) == 0 ||
        !Lock()) {
      return false;
    }
    ClearResults();
    // The authenticated control plane remains available while a paired BLE
    // keyboard is idle or temporarily disconnected. Effectful admission is
    // separately gated on OutputReadyLocked() in CommandScopedArm().
    if (provisioning_active_ || local_maintenance_active_) {
      Unlock();
      return false;
    }
    authenticated_epoch_ = epoch;
#if defined(KEYFERRY_FILE_HANDOFF)
    file_negotiated_ =
        (ready.capability_mask & static_cast<std::uint32_t>(
            keyferry::protocol::Capability::kUsbFileHandoffV1)) != 0;
    file_set_negotiated_ =
        (ready.capability_mask & static_cast<std::uint32_t>(
            keyferry::protocol::Capability::kUsbFileSetV2)) != 0;
    file_neutral_pending_ = false;
#endif
    peer_input_v1_ =
        (ready.capability_mask &
         static_cast<std::uint32_t>(
             keyferry::protocol::Capability::kMouseRelativeV1)) != 0;
    command_.BeginSession(epoch, 0, peer_input_v1_);
    Unlock();
    return true;
  }

  bool CommandScopedArm(const std::uint64_t epoch,
                        const std::uint32_t next_command_sequence) override {
    if (!Lock()) {
      return false;
    }
    const bool armed = !provisioning_active_ && !local_maintenance_active_ &&
                         OutputReadyLocked() &&
#if defined(KEYFERRY_FILE_HANDOFF)
                         !FileArmBlockedLocked() &&
#endif
                         epoch == authenticated_epoch_ &&
                        command_.CommandScopedArm(epoch, next_command_sequence);
#if defined(KEYFERRY_FILE_HANDOFF)
    if (armed) file_neutral_pending_ = false;
#endif
    Unlock();
    return armed;
  }

  bool Disarm(const std::uint64_t epoch) override {
    if (!Lock()) {
      return false;
    }
    const bool matched = epoch != 0 && epoch == authenticated_epoch_;
    if (matched) {
      command_.EndSession();
      command_.BeginSession(epoch, 0, peer_input_v1_);
      disarm_waiting_ = true;
    }
    Unlock();
    return matched;
  }

  bool DisarmComplete(const std::uint64_t epoch) override {
    if (!Lock()) {
      return false;
    }
    const bool complete =
        disarm_waiting_ && epoch != 0 && epoch == authenticated_epoch_ &&
        keyferry::hid::is_zero(hid_.current_report()) &&
        keyferry::hid::is_zero(hid_.current_mouse_report()) &&
        !hid_.report_needed() && !usb_transfer_in_flight_;
    if (complete) {
      disarm_waiting_ = false;
    }
    Unlock();
    return complete;
  }

  bool AuthenticatedFrame(const std::uint64_t epoch,
                          const keyferry::protocol::DecodedFrame& frame) override {
    if (!Lock()) {
      return false;
    }
    bool handled = false;
    if (!provisioning_active_ && !local_maintenance_active_ &&
        epoch == authenticated_epoch_) {
      const auto type =
          static_cast<keyferry::protocol::MessageType>(frame.message_type);
      if (type == keyferry::protocol::MessageType::kGetOutputMode) {
        handled = frame.payload_length == 0 && !pending_mode_status_.available &&
                  !pending_bond_reset_status_.available &&
                  !pending_display_orientation_status_.available;
        if (handled) {
          pending_mode_status_ = {
              frame.sequence, stored_output_mode_, true, false};
        }
      } else if (type == keyferry::protocol::MessageType::kSetOutputMode) {
        const auto requested = frame.payload_length == 1
                                   ? static_cast<keyferry::protocol::OutputMode>(
                                         frame.payload[0])
                                   : static_cast<keyferry::protocol::OutputMode>(0);
        const bool safe = !pending_mode_status_.available &&
                          !pending_bond_reset_status_.available &&
                          !pending_display_orientation_status_.available &&
                          keyferry::output_mode::IsSupported(requested) &&
                          !command_.active() && !hid_.armed() &&
                          keyferry::hid::is_zero(hid_.current_report()) &&
                          keyferry::hid::is_zero(hid_.desired_report()) &&
                          keyferry::hid::is_zero(hid_.current_mouse_report()) &&
                          keyferry::hid::is_zero(hid_.desired_mouse_report()) &&
                          !hid_.report_needed() && !usb_transfer_in_flight_ &&
                          !ble_release_in_flight_;
        handled = safe &&
                  (requested == stored_output_mode_ ||
                   keyferry::output_mode::Save(output_mode_storage_, requested));
        if (handled) {
          stored_output_mode_ = requested;
          pending_mode_status_ = {
              frame.sequence, requested, true, requested != output_mode_};
        }
      } else if (type == keyferry::protocol::MessageType::kResetBleHidBond) {
        const bool safe = frame.payload_length == 0 &&
                          !pending_mode_status_.available &&
                          !pending_bond_reset_status_.available &&
                          !pending_display_orientation_status_.available &&
                          output_mode_ ==
                              keyferry::protocol::OutputMode::kBleHid &&
                          !command_.active() && !hid_.armed() &&
                          keyferry::hid::is_zero(hid_.current_report()) &&
                          keyferry::hid::is_zero(hid_.desired_report()) &&
                          !hid_.report_needed() && !ble_release_in_flight_;
        if (safe) {
          const auto result = ble_hid_.ResetBond();
          const bool succeeded =
              result != keyferry::ble_hid::BondResetResult::kError;
          const std::uint8_t status =
              result == keyferry::ble_hid::BondResetResult::kForgotten
                  ? 1U
                  : (succeeded ? 0U : 2U);
          pending_bond_reset_status_ = {
              frame.sequence, status, true, succeeded};
          handled = true;
        }
      } else if (type ==
                 keyferry::protocol::MessageType::kGetDisplayOrientation) {
        handled = frame.payload_length == 0 &&
                  !pending_mode_status_.available &&
                  !pending_bond_reset_status_.available &&
                  !pending_display_orientation_status_.available;
        if (handled) {
          pending_display_orientation_status_ = {
              frame.sequence, stored_display_orientation_, true, false};
        }
      } else if (type ==
                 keyferry::protocol::MessageType::kSetDisplayOrientation) {
        const auto requested =
            frame.payload_length == 1
                ? static_cast<keyferry::protocol::DisplayOrientation>(
                      frame.payload[0])
                : static_cast<keyferry::protocol::DisplayOrientation>(0);
        const bool safe = !pending_mode_status_.available &&
                          !pending_bond_reset_status_.available &&
                          !pending_display_orientation_status_.available &&
                          keyferry::display_orientation::IsSupported(requested) &&
                          !command_.active() && !hid_.armed() &&
                          keyferry::hid::is_zero(hid_.current_report()) &&
                          keyferry::hid::is_zero(hid_.desired_report()) &&
                          keyferry::hid::is_zero(hid_.current_mouse_report()) &&
                          keyferry::hid::is_zero(hid_.desired_mouse_report()) &&
                          !hid_.report_needed() && !usb_transfer_in_flight_ &&
                          !ble_release_in_flight_;
        handled = safe &&
                  (requested == stored_display_orientation_ ||
                   keyferry::display_orientation::Save(
                       display_orientation_storage_, requested));
        if (handled) {
          stored_display_orientation_ = requested;
          pending_display_orientation_status_ = {
              frame.sequence, requested, true,
              requested != display_orientation_};
        }
      } else if (type == keyferry::protocol::MessageType::kGetScreenPower) {
        handled = frame.payload_length == 0 &&
                  !pending_screen_power_status_.available;
        if (handled) {
          pending_screen_power_status_ = {
              frame.sequence, screen_power_.active(), screen_power_.stored(),
              screen_power_.available(), true};
        }
      } else if (type == keyferry::protocol::MessageType::kSetScreenPower) {
        keyferry::protocol::ScreenPower requested{};
        const bool valid = keyferry::display_orientation::DecodeSetPowerRequest(
            frame.payload, frame.payload_length, &requested);
        const keyferry::display_orientation::PowerMutationInputs input{
            screen_power_.available(), command_.active(), hid_.armed(),
            keyferry::hid::is_zero(hid_.current_report()) &&
                keyferry::hid::is_zero(hid_.desired_report()),
            keyferry::hid::is_zero(hid_.current_mouse_report()) &&
                keyferry::hid::is_zero(hid_.desired_mouse_report()),
            hid_.report_needed(), usb_transfer_in_flight_,
            ble_release_in_flight_};
        const bool safe = !pending_mode_status_.available &&
                          !pending_bond_reset_status_.available &&
                          !pending_display_orientation_status_.available &&
                          !pending_screen_power_status_.available &&
                          valid && keyferry::display_orientation::CanSetPower(input);
        handled = safe &&
                  (requested == screen_power_.stored() ||
                   keyferry::display_orientation::SavePower(
                       display_orientation_storage_, requested));
        if (handled) {
          screen_power_.SetStored(requested);
          pending_screen_power_status_ = {
              frame.sequence, screen_power_.active(), screen_power_.stored(),
              screen_power_.available(), true};
        }
#if defined(KEYFERRY_FILE_HANDOFF)
      } else if (type == keyferry::protocol::MessageType::kFileRequest) {
        handled = HandleFileRequestLocked(frame);
      } else if (type == keyferry::protocol::MessageType::kFileSetRequest) {
        handled = HandleFileSetRequestLocked(frame);
#endif
      } else {
        handled = command_.HandleAuthenticated(
            epoch, frame, keyferry::command::IdfHeldKeyWatchdog::NowMs());
      }
    }
    Unlock();
    return handled;
  }

  bool UsbReady() override {
    if (!Lock()) {
      return false;
    }
    const bool ready = OutputReadyLocked() && !provisioning_active_ &&
                       !local_maintenance_active_;
    Unlock();
    return ready;
  }

  bool Service(const std::uint64_t epoch) override {
    if (transport_ == nullptr || !Lock()) {
      return false;
    }
    if (session_abort_requested_) {
      session_abort_requested_ = false;
      Unlock();
      return false;
    }
    if (provisioning_active_ || local_maintenance_active_) {
      Unlock();
      return false;
    }
    if (result_overflow_ || epoch == 0 ||
        (authenticated_epoch_ != 0 && epoch != authenticated_epoch_)) {
      Unlock();
      return false;
    }
    if (authenticated_epoch_ == 0) {
      const bool empty = result_count_ == 0;
      Unlock();
      return empty;
    }
    if (pending_mode_status_.available) {
      const auto pending = pending_mode_status_;
      pending_mode_status_ = {};
      Unlock();
      if (!SendModeStatus(pending)) {
        return false;
      }
      if (pending.restart_after_send && Lock()) {
        restart_not_before_ms_ =
            keyferry::command::IdfHeldKeyWatchdog::NowMs() + 250U;
        Unlock();
      }
      return true;
    }
    if (pending_bond_reset_status_.available) {
      const auto pending = pending_bond_reset_status_;
      pending_bond_reset_status_ = {};
      Unlock();
      if (!SendBondResetStatus(pending)) {
        return false;
      }
      if (pending.restart_after_send && Lock()) {
        restart_not_before_ms_ =
            keyferry::command::IdfHeldKeyWatchdog::NowMs() + 250U;
        Unlock();
      }
      return true;
    }
    if (pending_display_orientation_status_.available) {
      const auto pending = pending_display_orientation_status_;
      pending_display_orientation_status_ = {};
      Unlock();
      if (!SendDisplayOrientationStatus(pending)) {
        return false;
      }
      if (pending.restart_after_send && Lock()) {
        restart_not_before_ms_ =
            keyferry::command::IdfHeldKeyWatchdog::NowMs() + 250U;
        Unlock();
      }
      return true;
    }
    if (pending_screen_power_status_.available) {
      const auto pending = pending_screen_power_status_;
      pending_screen_power_status_ = {};
      Unlock();
      return SendScreenPowerStatus(pending);
    }
#if defined(KEYFERRY_FILE_HANDOFF)
    if (pending_file_status_.available) {
      const auto pending = pending_file_status_;
      pending_file_status_ = {};
      Unlock();
      if (!SendFileStatus(pending)) return false;
      if (pending.refresh_after_send && Lock()) {
        file_refresh_ready_ = true;
        file_clear_on_detach_ = pending.clear_on_detach;
        Unlock();
      }
      return true;
    }
    if (pending_file_set_status_.available) {
      const auto pending = pending_file_set_status_;
      pending_file_set_status_ = {};
      Unlock();
      if (!SendFileSetStatus(pending)) return false;
      if (pending.refresh_after_send && Lock()) {
        file_refresh_ready_ = true;
        file_clear_on_detach_ = pending.clear_on_detach;
        Unlock();
      }
      return true;
    }
#endif
    PendingResult pending{};
    const bool available = PopResult(&pending);
    Unlock();
    return !available || SendResult(pending);
  }

  void CommandResult(const std::uint32_t sequence,
                     const std::array<std::uint8_t, 16>& command_id,
                     const keyferry::protocol::ResultCode result) override {
    // CommandExecutor invokes this while the shared safety lock is already held.
    if (result_count_ == results_.size()) {
      result_overflow_ = true;
      hid_.fault();
      return;
    }
    const std::size_t tail = (result_head_ + result_count_) % results_.size();
    results_[tail].sequence = sequence;
    results_[tail].command_id = command_id;
    results_[tail].result = result;
    results_[tail].input = false;
    ++result_count_;
  }

  void InputCommandResult(
      const std::uint32_t sequence,
      const keyferry::command::InputResultEvidence& evidence) override {
    // CommandExecutor invokes this while the shared safety lock is already held.
    if (result_count_ == results_.size()) {
      result_overflow_ = true;
      hid_.fault();
      return;
    }
    const std::size_t tail = (result_head_ + result_count_) % results_.size();
    results_[tail].sequence = sequence;
    results_[tail].input = true;
    results_[tail].input_evidence = evidence;
    ++result_count_;
  }

  std::uint64_t MonotonicMilliseconds() override {
    return keyferry::command::IdfHeldKeyWatchdog::NowMs();
  }

  keyferry::protocol::LocalManagementStatus ReadStatus(
      const keyferry::protocol::LocalManagementStatusPage page,
      keyferry::local_management::ResponsePayload* payload) override {
    using keyferry::protocol::LocalManagementBondState;
    using keyferry::protocol::LocalManagementStatus;
    if (payload == nullptr || !Lock()) {
      return LocalManagementStatus::kInternal;
    }
    keyferry::local_management::StatusSnapshot snapshot{};
    const bool probe_page =
        page == keyferry::protocol::LocalManagementStatusPage::kProbeRun ||
        page == keyferry::protocol::LocalManagementStatusPage::kProbeHeap ||
        page == keyferry::protocol::LocalManagementStatusPage::kProbeStack;
    if (probe_page) {
#if defined(KEYFERRY_MSC_MEMORY_PROBE)
      snapshot.probe_available = CopyMscProbeStatus(&snapshot.probe);
      if (!snapshot.probe_available) {
        Unlock();
        payload->fill(0);
        return LocalManagementStatus::kUnsupported;
      }
      const bool encoded =
          keyferry::local_management::EncodeStatusPage(page, snapshot, payload);
      Unlock();
      return encoded ? LocalManagementStatus::kOk
                     : LocalManagementStatus::kInternal;
#else
      Unlock();
      payload->fill(0);
      return LocalManagementStatus::kUnsupported;
#endif
    }
    snapshot.device.active_output_mode = output_mode_;
    snapshot.device.stored_output_mode = stored_output_mode_;
    snapshot.device.board_compatibility_id =
        local_management_metadata_.board_compatibility_id;
    snapshot.device.release = local_management_metadata_.release;
    snapshot.device.capabilities = local_management_metadata_.capabilities;

    snapshot.safety.maintenance_active = local_maintenance_active_;
    snapshot.safety.command_active = command_.active();
    snapshot.safety.armed = hid_.armed();
    snapshot.safety.usb_mounted = usb_mounted_;
    snapshot.safety.keyboard_neutral =
        keyferry::hid::is_zero(hid_.current_report()) &&
        keyferry::hid::is_zero(hid_.desired_report());
    snapshot.safety.mouse_neutral =
        keyferry::hid::is_zero(hid_.current_mouse_report()) &&
        keyferry::hid::is_zero(hid_.desired_mouse_report());
    snapshot.safety.restart_pending =
        restart_requested_ || restart_not_before_ms_ != 0;
    snapshot.safety.receipt_storage_healthy =
        local_management_metadata_.receipt_storage_healthy;
    snapshot.safety.usb_attachment_generation =
        static_cast<std::uint32_t>(usb_attachment_generation_);

    if (transport_ != nullptr) {
      const auto diagnostics = transport_->diagnostics();
      snapshot.network.wifi_stage =
          static_cast<std::uint8_t>(diagnostics.wifi_stage);
      snapshot.network.active_path =
          static_cast<std::uint8_t>(transport_->active_path());
      snapshot.network.running = diagnostics.running;
      snapshot.network.wifi_available = diagnostics.wifi_available;
      snapshot.network.ble_available = diagnostics.ble_available;
      snapshot.network.wifi_error = diagnostics.wifi_error;
      snapshot.network.nvs_error = diagnostics.nvs_error;
    }
    snapshot.network.endpoint_authenticated = authenticated_epoch_ != 0;
    snapshot.network.configuration_valid =
        local_management_metadata_.configuration_valid;
    snapshot.network.wifi_profile_count =
        local_management_metadata_.wifi_profile_count;
    snapshot.network.paired_host_count =
        local_management_metadata_.paired_host_count;
    snapshot.network.policy_state = local_management_metadata_.policy_state;

    const auto ble_status = ble_hid_.status();
    const auto bond_status = ble_hid_.bond_status();
    switch (bond_status.state) {
      case keyferry::ble_hid::BondStoreState::kNone:
        snapshot.ble_hid.bond_state = LocalManagementBondState::kNone;
        break;
      case keyferry::ble_hid::BondStoreState::kSingle:
        snapshot.ble_hid.bond_state = LocalManagementBondState::kSingle;
        break;
      case keyferry::ble_hid::BondStoreState::kMultipleInvalid:
        snapshot.ble_hid.bond_state =
            LocalManagementBondState::kMultipleInvalid;
        break;
      case keyferry::ble_hid::BondStoreState::kStoreError:
        snapshot.ble_hid.bond_state = LocalManagementBondState::kStoreError;
        break;
    }
    snapshot.ble_hid.peripheral_stage =
        static_cast<std::uint8_t>(ble_status.stage);
    snapshot.ble_hid.advertising = ble_status.advertising;
    snapshot.ble_hid.connected = ble_status.connected;
    snapshot.ble_hid.authenticated = ble_status.authenticated;
    snapshot.ble_hid.subscribed = ble_status.subscribed;
    snapshot.ble_hid.ready = ble_status.ready;
    snapshot.ble_hid.error =
        bond_status.state == keyferry::ble_hid::BondStoreState::kStoreError
            ? bond_status.error
            : ble_status.error;
    snapshot.ble_hid.generation = ble_status.generation;
    const auto enrollment = ble_hid_.enrollment_status(MonotonicMilliseconds());
    snapshot.ble_hid.enrollment_active = enrollment.active;
    snapshot.ble_hid.enrollment_remaining_ms = enrollment.remaining_ms;

    snapshot.policy.state = local_management_metadata_.policy_state;
    snapshot.policy.sequence = local_management_metadata_.policy_sequence;
    if (local_management_metadata_.receipts != nullptr &&
        !local_management_metadata_.receipts->Last(&snapshot.last_receipt,
                                                   &snapshot.has_last_receipt)) {
      Unlock();
      payload->fill(0);
      return LocalManagementStatus::kStorageError;
    }
    const bool encoded =
        keyferry::local_management::EncodeStatusPage(page, snapshot, payload);
    Unlock();
    return encoded ? LocalManagementStatus::kOk
                   : LocalManagementStatus::kInternal;
  }

  void SetMaintenanceActive(const bool active) override {
    if (!Lock()) {
      return;
    }
    local_maintenance_active_ = active;
#if defined(KEYFERRY_FILE_HANDOFF)
    if (active) ReleaseFileVolumeLocked();
#endif
    Unlock();
  }

  keyferry::protocol::LocalManagementStatus RequestNeutralization() override {
    if (!Lock()) {
      return keyferry::protocol::LocalManagementStatus::kInternal;
    }
    command_.EndSession();
#if defined(KEYFERRY_FILE_HANDOFF)
    ReleaseFileVolumeLocked();
    file_neutral_pending_ = false;
#endif
    hid_.request_dual_neutral();
    authenticated_epoch_ = 0;
    peer_input_v1_ = false;
    disarm_waiting_ = false;
    session_abort_requested_ = true;
    ClearResults();
    Unlock();
    return keyferry::protocol::LocalManagementStatus::kInProgress;
  }

  bool NeutralConfirmed() override {
    if (!Lock()) {
      return false;
    }
    const bool confirmed = NeutralConfirmedLocked();
    Unlock();
    return confirmed;
  }

  keyferry::protocol::LocalManagementStatus RestartNetwork() override {
    if (transport_ == nullptr) {
      return keyferry::protocol::LocalManagementStatus::kBadState;
    }
    return transport_->RequestRestart()
               ? keyferry::protocol::LocalManagementStatus::kOk
               : keyferry::protocol::LocalManagementStatus::kBusy;
  }

  keyferry::protocol::LocalManagementStatus ClearBleBondAndEnroll() override {
    if (output_mode_ != keyferry::protocol::OutputMode::kBleHid) {
      return keyferry::protocol::LocalManagementStatus::kBadState;
    }
    return ble_hid_.ResetBondAndEnroll(MonotonicMilliseconds()) ==
                   keyferry::ble_hid::BondResetResult::kError
               ? keyferry::protocol::LocalManagementStatus::kStorageError
               : keyferry::protocol::LocalManagementStatus::kOk;
  }

  keyferry::protocol::LocalManagementStatus CancelEnrollment() override {
    if (output_mode_ != keyferry::protocol::OutputMode::kBleHid) {
      return keyferry::protocol::LocalManagementStatus::kBadState;
    }
    static_cast<void>(ble_hid_.CancelEnrollment());
    return keyferry::protocol::LocalManagementStatus::kOk;
  }

  keyferry::protocol::LocalManagementStatus SetOutputMode(
      const keyferry::protocol::OutputMode mode,
      bool* restart_required) override {
    if (restart_required == nullptr ||
        !keyferry::output_mode::IsSupported(mode) || !Lock()) {
      return keyferry::protocol::LocalManagementStatus::kBadReport;
    }
    const bool changed = mode != stored_output_mode_;
    const bool saved = !changed || keyferry::output_mode::Save(
                                      output_mode_storage_, mode);
    if (saved) {
      stored_output_mode_ = mode;
      *restart_required = mode != output_mode_;
    }
    Unlock();
    return saved ? keyferry::protocol::LocalManagementStatus::kOk
                 : keyferry::protocol::LocalManagementStatus::kStorageError;
  }

  void RestartDevice() override {
    if (!Lock()) {
      return;
    }
    restart_requested_ = true;
    Unlock();
  }

  bool EnterProvisioning(const bool local_maintenance_authorized) override {
    if (!Lock()) {
      return false;
    }
    const bool maintenance_matches =
        local_maintenance_authorized ? local_maintenance_active_
                                     : !local_maintenance_active_;
    const bool safe =
        usb_mounted_ && authenticated_epoch_ == 0 && !command_.active() &&
        maintenance_matches &&
        !hid_.armed() &&
        keyferry::hid::is_zero(hid_.current_report()) &&
        keyferry::hid::is_zero(hid_.desired_report()) &&
        keyferry::hid::is_zero(hid_.current_mouse_report()) &&
        keyferry::hid::is_zero(hid_.desired_mouse_report()) &&
        !hid_.report_needed() && !usb_transfer_in_flight_ &&
        !ble_release_in_flight_;
    if (safe) {
      provisioning_active_ = true;
      provisioning_from_local_maintenance_ = local_maintenance_authorized;
      session_abort_requested_ = true;
    }
    Unlock();
    return safe;
  }

  bool ProvisioningActive() override {
    if (!Lock()) {
      return false;
    }
    const bool active = provisioning_active_;
    Unlock();
    return active;
  }

  bool CommitAllowed() override {
    if (!Lock()) {
      return false;
    }
    const bool maintenance_matches = provisioning_from_local_maintenance_
                                         ? local_maintenance_active_
                                         : !local_maintenance_active_;
    const bool safe =
        provisioning_active_ && maintenance_matches && usb_mounted_ &&
        authenticated_epoch_ == 0 &&
        !command_.active() && !hid_.armed() &&
        keyferry::hid::is_zero(hid_.current_report()) &&
        keyferry::hid::is_zero(hid_.desired_report()) &&
        keyferry::hid::is_zero(hid_.current_mouse_report()) &&
        keyferry::hid::is_zero(hid_.desired_mouse_report()) &&
        !hid_.report_needed() && !usb_transfer_in_flight_ &&
        !ble_release_in_flight_;
    Unlock();
    return safe;
  }

  void LeaveProvisioning() override {
    if (!Lock()) {
      return;
    }
    provisioning_active_ = false;
    provisioning_from_local_maintenance_ = false;
    Unlock();
  }

  void ProvisioningFault() override {
    if (!Lock()) {
      return;
    }
    // A malformed or overrun local USB exchange outside an admitted
    // maintenance session is scoped to that USB transport. It must not tear
    // down an unrelated authenticated network session or input executor.
    if (!provisioning_active_) {
      Unlock();
      return;
    }
    command_.EndSession();
    hid_.fault();
    ClearResults();
    authenticated_epoch_ = 0;
    peer_input_v1_ = false;
    disarm_waiting_ = false;
    provisioning_active_ = false;
    provisioning_from_local_maintenance_ = false;
    session_abort_requested_ = true;
    Unlock();
  }

  void ProvisioningCommitResponseCompleted() override {
    if (!Lock()) {
      return;
    }
    const bool maintenance_matches = provisioning_from_local_maintenance_
                                         ? local_maintenance_active_
                                         : !local_maintenance_active_;
    const bool safe = provisioning_active_ && maintenance_matches && usb_mounted_ &&
                      authenticated_epoch_ == 0 && !command_.active() &&
                      !hid_.armed() &&
                      keyferry::hid::is_zero(hid_.current_report()) &&
                      keyferry::hid::is_zero(hid_.desired_report()) &&
                      keyferry::hid::is_zero(hid_.current_mouse_report()) &&
                      keyferry::hid::is_zero(hid_.desired_mouse_report()) &&
                      !hid_.report_needed() && !usb_transfer_in_flight_ &&
                      !ble_release_in_flight_;
    provisioning_active_ = false;
    provisioning_from_local_maintenance_ = false;
    restart_requested_ = safe;
    if (!safe) {
      command_.EndSession();
      hid_.fault();
      session_abort_requested_ = true;
    }
    Unlock();
  }

  bool RestartRequested() {
    if (!Lock()) {
      return false;
    }
    const bool requested = restart_requested_ ||
                           (restart_not_before_ms_ != 0 &&
                            keyferry::command::IdfHeldKeyWatchdog::NowMs() >=
                                restart_not_before_ms_);
    Unlock();
    return requested;
  }

  keyferry::status::Snapshot StatusSnapshot(
      const bool transport_allowed, const keyferry::status::LinkPath link,
      const std::uint64_t config_generation) {
    keyferry::status::Snapshot snapshot{};
    snapshot.link = link;
    snapshot.config_generation = config_generation;
    if (!Lock()) {
      snapshot.activity = keyferry::status::Activity::kFault;
      return snapshot;
    }
    snapshot.usb_mounted =
        output_mode_ == keyferry::protocol::OutputMode::kUsbHid && usb_mounted_;
    snapshot.ble_hid_mode =
        output_mode_ == keyferry::protocol::OutputMode::kBleHid;
    if (snapshot.ble_hid_mode) {
      const auto ble_status = ble_hid_.status();
      snapshot.ble_hid_connected = ble_status.connected;
      snapshot.ble_hid_authenticated = ble_status.authenticated;
      snapshot.ble_hid_ready = ble_status.ready;
      snapshot.ble_hid_passkey = ble_status.passkey;
    }
    if (!transport_allowed) {
      snapshot.activity = keyferry::status::Activity::kLocked;
    } else if (provisioning_active_ || local_maintenance_active_) {
      snapshot.activity = keyferry::status::Activity::kProvisioning;
    } else if (command_.active()) {
      snapshot.activity = keyferry::status::Activity::kActive;
    } else if (authenticated_epoch_ != 0) {
      snapshot.activity = keyferry::status::Activity::kReady;
    } else {
      snapshot.activity = keyferry::status::Activity::kConnecting;
    }
    Unlock();
    return snapshot;
  }

#if defined(KEYFERRY_MSC_MEMORY_PROBE)
  // A nonzero epoch means the live connection is authenticated and the USB
  // output is neutral. Never hold the runtime lock while allocating or logging.
  std::uint64_t MemoryProbeSafeEpoch() {
    if (!Lock()) {
      return 0;
    }
    const bool safe = authenticated_epoch_ != 0 && usb_mounted_ &&
                      !provisioning_active_ && !local_maintenance_active_ &&
                      NeutralConfirmedLocked() &&
                      !restart_requested_ && restart_not_before_ms_ == 0;
    const auto epoch = safe ? authenticated_epoch_ : 0;
    Unlock();
    return epoch;
  }
#endif

 private:
#if defined(KEYFERRY_FILE_HANDOFF)
  bool AllocateFileVolumeLocked(std::size_t required_bytes) {
    if (file_volume_ != nullptr) {
      if (file_buffer_capacity_ >= required_bytes ||
          file_volume_->Status().state ==
              keyferry::file_handoff::State::kReceiving) {
        return true;
      }
      ReleaseFileVolumeLocked();
    }
    constexpr auto kInternalCaps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
    const auto internal_safe = [] {
      return heap_caps_get_free_size(kInternalCaps) >=
                 kFileHeapReserveBytes &&
             heap_caps_get_largest_free_block(kInternalCaps) >=
                 kFileTlsRxReserveBytes;
    };
    if (!internal_safe()) {
      return false;
    }
    std::uint8_t* bytes = nullptr;
#if defined(CONFIG_SPIRAM)
    if (esp_psram_is_initialized()) {
      bytes = static_cast<std::uint8_t*>(heap_caps_malloc(
          required_bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    }
#endif
    if (bytes == nullptr) {
      if (heap_caps_get_free_size(kInternalCaps) <
              required_bytes + kFileHeapReserveBytes ||
          heap_caps_get_largest_free_block(kInternalCaps) < required_bytes) {
        return false;
      }
      bytes = static_cast<std::uint8_t*>(
          heap_caps_malloc(required_bytes, kInternalCaps));
    }
    if (bytes == nullptr) return false;
    if (!internal_safe()) {
      std::memset(bytes, 0, required_bytes);
      heap_caps_free(bytes);
      return false;
    }
    file_volume_storage_.emplace(bytes, required_bytes, FileSha256);
    file_buffer_ = bytes;
    file_buffer_capacity_ = required_bytes;
    file_volume_ = &*file_volume_storage_;
    return true;
  }

  void ReleaseFileVolumeLocked() {
    if (file_volume_ == nullptr) return;
    file_volume_storage_.reset();  // Wipes contents before heap release.
    file_volume_ = nullptr;
    heap_caps_free(file_buffer_);
    file_buffer_ = nullptr;
    file_buffer_capacity_ = 0;
    file_upload_last_ms_ = 0;
  }

  bool HandleFileRequestLocked(const keyferry::protocol::DecodedFrame& frame) {
    if (pending_file_status_.available || pending_file_set_status_.available ||
        frame.payload == nullptr ||
        frame.payload_length == 0) {
      return false;
    }
    keyferry::file_handoff::FileStatus status{};
    bool refresh = false;
    bool clear_on_detach = false;
    const auto operation = frame.payload[0];
    if ((operation == 1 && frame.payload_length != 37) ||
        (operation == 2 && (frame.payload_length < 6 ||
                            frame.payload_length > 205)) ||
        (operation >= 3 && operation <= 5 && frame.payload_length != 1) ||
        operation < 1 || operation > 5) return false;
    if (!file_negotiated_) {
      status.error = keyferry::file_handoff::Error::kUnavailable;
    } else {
      if (file_volume_ != nullptr && !file_volume_->IsSet())
        status = file_volume_->Status();
      else if (file_volume_ != nullptr)
        status.error = keyferry::file_handoff::Error::kUnavailable;
      const bool admitted = authenticated_epoch_ != 0 &&
                            !provisioning_active_ &&
                            !local_maintenance_active_ && !restart_requested_;
      if (operation == 5) {
        // STATUS is read-only and does not need a HID release barrier.
      } else if (!admitted || !FileNeutralIdleLocked()) {
        status.error = keyferry::file_handoff::Error::kBusy;
      } else if (!NeutralConfirmedLocked()) {
        if (!file_neutral_pending_) {
          hid_.request_dual_neutral();
          file_neutral_pending_ = true;
        }
        status.error = keyferry::file_handoff::Error::kBusy;
      } else {
        file_neutral_pending_ = false;
        if (operation == 1 &&
            FileReadLe32(frame.payload + 1) >
                keyferry::file_handoff::kMaximumFileBytes) {
          status.error = keyferry::file_handoff::Error::kLimit;
        } else if (operation == 1 && file_volume_ != nullptr &&
                   file_volume_->Ready() && usb_mounted_) {
          status.error = keyferry::file_handoff::Error::kBusy;
          refresh = true;
          clear_on_detach = true;
        } else if (operation == 1 &&
                   !AllocateFileVolumeLocked(std::max<std::size_t>(
                       1, FileReadLe32(frame.payload + 1)))) {
          status.error = keyferry::file_handoff::Error::kMemory;
        } else if (file_volume_ == nullptr) {
          status.error = (operation == 4 || operation == 5)
                             ? keyferry::file_handoff::Error::kOk
                             : keyferry::file_handoff::Error::kOrder;
        } else {
          keyferry::file_handoff::Error result =
              keyferry::file_handoff::Error::kOk;
          bool release_after_status = false;
          if (operation == 4 && file_volume_->Ready() && usb_mounted_) {
            result = keyferry::file_handoff::Error::kBusy;
            refresh = true;
            clear_on_detach = true;
          } else if (operation == 1) {
            result = file_volume_->Begin(FileReadLe32(frame.payload + 1),
                                         frame.payload + 5);
            file_upload_last_ms_ =
                keyferry::command::IdfHeldKeyWatchdog::NowMs();
          } else if (operation == 2) {
            result = file_volume_->Ready() || file_volume_->IsSet()
                         ? keyferry::file_handoff::Error::kOrder
                         : file_volume_->Chunk(FileReadLe32(frame.payload + 1),
                                               frame.payload + 5,
                                               frame.payload_length - 5);
            file_upload_last_ms_ =
                keyferry::command::IdfHeldKeyWatchdog::NowMs();
          } else if (operation == 3) {
            result = file_volume_->Ready() || file_volume_->IsSet()
                         ? keyferry::file_handoff::Error::kOrder
                         : file_volume_->Commit();
            refresh = result == keyferry::file_handoff::Error::kOk &&
                      usb_mounted_;
          } else if (operation == 4) {
            result = file_volume_->Clear();
            release_after_status = true;
          } else if (operation != 5) {
            return false;
          }
          status = file_volume_->IsSet()
                       ? keyferry::file_handoff::FileStatus{}
                       : file_volume_->Status();
          status.error = result;
          if (release_after_status ||
              (result != keyferry::file_handoff::Error::kOk &&
               file_volume_->Status().state ==
                   keyferry::file_handoff::State::kEmpty)) {
            ReleaseFileVolumeLocked();
          }
        }
      }
    }
    pending_file_status_ = {frame.sequence, status, true, refresh, clear_on_detach};
    return true;
  }

  bool HandleFileSetRequestLocked(const keyferry::protocol::DecodedFrame& frame) {
    if (pending_file_status_.available || pending_file_set_status_.available ||
        frame.payload == nullptr || frame.payload_length == 0) return false;
    const auto operation = frame.payload[0];
    if ((operation == 1 && frame.payload_length != 37) ||
        (operation == 2 && (frame.payload_length < 6 ||
                            frame.payload_length > 205)) ||
        ((operation == 3 || operation == 4) && frame.payload_length != 1) ||
        (operation == 5 && frame.payload_length != 2) ||
        operation < 1 || operation > 5) return false;
    const std::uint8_t index = operation == 5 ? frame.payload[1] : 255;
    keyferry::file_handoff::FileSetStatus status{};
    if (file_volume_ != nullptr) status = file_volume_->SetStatus(index);
    bool refresh = false;
    bool clear_on_detach = false;
    if (!file_set_negotiated_) {
      status.error = keyferry::file_handoff::Error::kUnavailable;
      status.has_entry = false;
    } else {
      const bool admitted = authenticated_epoch_ != 0 &&
                            !provisioning_active_ &&
                            !local_maintenance_active_ && !restart_requested_;
      if (operation == 5) {
        if (file_volume_ == nullptr && index != 255)
          status.error = keyferry::file_handoff::Error::kLimit;
      } else if (!admitted || !FileNeutralIdleLocked()) {
        status.error = keyferry::file_handoff::Error::kBusy;
      } else if (!NeutralConfirmedLocked()) {
        if (!file_neutral_pending_) {
          hid_.request_dual_neutral();
          file_neutral_pending_ = true;
        }
        status.error = keyferry::file_handoff::Error::kBusy;
      } else {
        file_neutral_pending_ = false;
        if (operation == 1 &&
            FileReadLe32(frame.payload + 1) >
                keyferry::file_handoff::kMaximumBundleBytes) {
          status.error = keyferry::file_handoff::Error::kLimit;
        } else if (operation == 1 && file_volume_ != nullptr &&
                   file_volume_->Ready() && usb_mounted_) {
          status.error = keyferry::file_handoff::Error::kBusy;
          refresh = true;
          clear_on_detach = true;
        } else if (operation == 1 &&
                   !AllocateFileVolumeLocked(std::max<std::size_t>(
                       1, FileReadLe32(frame.payload + 1)))) {
          status.error = keyferry::file_handoff::Error::kMemory;
        } else if (file_volume_ == nullptr) {
          status.error = operation == 4
                             ? keyferry::file_handoff::Error::kOk
                             : keyferry::file_handoff::Error::kOrder;
        } else {
          auto result = keyferry::file_handoff::Error::kOk;
          bool release_after_status = false;
          if (operation == 4 && file_volume_->Ready() && usb_mounted_) {
            result = keyferry::file_handoff::Error::kBusy;
            refresh = true;
            clear_on_detach = true;
          } else if (operation == 1) {
            result = file_volume_->BeginSet(FileReadLe32(frame.payload + 1),
                                            frame.payload + 5);
            file_upload_last_ms_ =
                keyferry::command::IdfHeldKeyWatchdog::NowMs();
          } else if (operation == 2) {
            result = file_volume_->Ready() || !file_volume_->IsSet()
                         ? keyferry::file_handoff::Error::kOrder
                         : file_volume_->Chunk(FileReadLe32(frame.payload + 1),
                                               frame.payload + 5,
                                               frame.payload_length - 5);
            file_upload_last_ms_ =
                keyferry::command::IdfHeldKeyWatchdog::NowMs();
          } else if (operation == 3) {
            result = file_volume_->Ready() || !file_volume_->IsSet()
                         ? keyferry::file_handoff::Error::kOrder
                         : file_volume_->CommitSet();
            refresh = result == keyferry::file_handoff::Error::kOk &&
                      usb_mounted_;
          } else if (operation == 4) {
            result = file_volume_->Clear();
            release_after_status = true;
          }
          status = file_volume_->SetStatus(255);
          status.error = result;
          if (release_after_status ||
              (result != keyferry::file_handoff::Error::kOk &&
               status.state == keyferry::file_handoff::State::kEmpty))
            ReleaseFileVolumeLocked();
        }
      }
    }
    PendingFileSetStatus pending{};
    pending.sequence = frame.sequence;
    pending.status = status;
    pending.available = true;
    pending.refresh_after_send = refresh;
    pending.clear_on_detach = clear_on_detach;
    if (status.has_entry) {
      std::copy_n(status.name, status.name_length, pending.name.data());
      pending.status.name = nullptr;  // Pending response owns its copied name.
    }
    pending_file_set_status_ = pending;
    return true;
  }
#endif

  bool FileNeutralIdleLocked() const {
    return
         !command_.active() && !hid_.armed() &&
         keyferry::hid::is_zero(hid_.current_report()) &&
         keyferry::hid::is_zero(hid_.desired_report()) &&
         keyferry::hid::is_zero(hid_.current_mouse_report()) &&
         keyferry::hid::is_zero(hid_.desired_mouse_report()) &&
         !hid_.report_needed() && !usb_transfer_in_flight_ &&
         !ble_release_in_flight_;
  }

  bool NeutralConfirmedLocked() {
    const bool stable = FileNeutralIdleLocked();
    const auto required_neutral =
        output_mode_ == keyferry::protocol::OutputMode::kUsbHid
            ? static_cast<std::uint8_t>(keyferry::hid::kKeyboardNeutral |
                                        keyferry::hid::kMouseNeutral)
            : static_cast<std::uint8_t>(keyferry::hid::kKeyboardNeutral);
    const bool output_transport_unavailable =
        output_mode_ == keyferry::protocol::OutputMode::kBleHid &&
        !ble_transport_ready_ && !ble_hid_.ready();
    return keyferry::local_management::NeutralizationSatisfied(
        stable, hid_.neutral_mask(), required_neutral,
        output_transport_unavailable);
  }

#if defined(KEYFERRY_FILE_HANDOFF)
  bool FileArmBlockedLocked() const {
    return (file_volume_ != nullptr &&
            file_volume_->Status().state ==
                keyferry::file_handoff::State::kReceiving) ||
           (pending_file_status_.available &&
            pending_file_status_.refresh_after_send) ||
           (pending_file_set_status_.available &&
            pending_file_set_status_.refresh_after_send) ||
           file_refresh_ready_ || file_refresh_in_flight_;
  }
#endif

  bool OutputReadyLocked() const {
    return output_mode_ == keyferry::protocol::OutputMode::kUsbHid
               ? usb_mounted_
               : ble_hid_.ready();
  }

  void ServiceBleHid() {
    if (!Lock()) {
      return;
    }
    const auto now_ms = keyferry::command::IdfHeldKeyWatchdog::NowMs();
    const auto events = ble_hid_.Poll(now_ms);
    const bool peripheral_failed =
        events.disconnected || events.disconnect_required || events.fault;
    const bool peripheral_ready = ble_hid_.ready() && !peripheral_failed;
    if (peripheral_ready && !ble_transport_ready_) {
      hid_.on_transport_ready();
      ble_transport_ready_ = true;
    } else if (!peripheral_ready && ble_transport_ready_) {
      // Preserve the authenticated Wi-Fi session so the host can observe the
      // conservative command result or switch output mode. Only the HID
      // transport and any active/armed command are revoked here.
      command_.UsbFault();
      hid_.on_transport_lost();
      ble_transport_ready_ = false;
      ble_release_in_flight_ = false;
    }
    if (events.release_complete && ble_release_in_flight_) {
      ble_release_in_flight_ = false;
      command_.UsbReportAccepted({}, now_ms);
    }
    if (peripheral_failed) {
      ble_release_in_flight_ = false;
      disarm_waiting_ = false;
      Unlock();
      return;
    }
    if (!ble_release_in_flight_ && ble_hid_.ready() && hid_.report_needed()) {
      if (hid_.desired_interface() !=
          keyferry::hid::InputInterface::keyboard) {
        command_.UsbFault();
        Unlock();
        return;
      }
      const auto report = hid_.desired_report();
      keyferry::ble_hid::KeyboardReport bytes{};
      static_assert(sizeof(report) == bytes.size());
      std::memcpy(bytes.data(), &report, bytes.size());
      if (ble_hid_.Submit(bytes, now_ms)) {
        if (keyferry::hid::is_zero(report)) {
          ble_release_in_flight_ = true;
        } else {
          // BLE notifications have no peer acknowledgement. Acceptance here
          // means the local NimBLE stack accepted this one nonzero report;
          // it is never retried.
          command_.UsbReportAccepted(report, now_ms);
        }
      }
    }
    Unlock();
  }

  bool Lock() { return lock_ != nullptr && xSemaphoreTake(lock_, portMAX_DELAY) == pdTRUE; }

  void Unlock() { xSemaphoreGive(lock_); }

  void ClearResults() {
    results_.fill({});
    result_head_ = 0;
    result_count_ = 0;
    result_overflow_ = false;
    pending_mode_status_ = {};
    pending_bond_reset_status_ = {};
    pending_display_orientation_status_ = {};
    pending_screen_power_status_ = {};
#if defined(KEYFERRY_FILE_HANDOFF)
    pending_file_status_ = {};
    pending_file_set_status_ = {};
    file_refresh_ready_ = false;
    file_clear_on_detach_ = false;
#endif
  }

  void UsbTransferFailedLocked() {
    usb_transfer_in_flight_ = false;
    usb_transfer_interface_ = keyferry::hid::InputInterface::keyboard;
    usb_transfer_report_ = {};
    usb_transfer_mouse_report_ = {};
    usb_transfer_mouse_token_ = 0;
    usb_transfer_epoch_ = 0;
    usb_transfer_generation_ = 0;
    command_.UsbFault();
#if defined(KEYFERRY_FILE_HANDOFF)
    ReleaseFileVolumeLocked();
    file_negotiated_ = false;
    file_set_negotiated_ = false;
#endif
    authenticated_epoch_ = 0;
    peer_input_v1_ = false;
    disarm_waiting_ = false;
    session_abort_requested_ = true;
    ClearResults();
  }

  bool PopResult(PendingResult* pending) {
    if (result_count_ == 0) {
      return false;
    }
    *pending = results_[result_head_];
    results_[result_head_] = {};
    result_head_ = (result_head_ + 1) % results_.size();
    --result_count_;
    return true;
  }

  bool SendResult(const PendingResult& pending) {
    std::array<std::uint8_t, 21> payload{};
    std::size_t payload_length = 17;
    auto message_type = keyferry::protocol::MessageType::kCommandResult;
    if (pending.input) {
      if (!keyferry::command::EncodeInputResultPayload(pending.input_evidence,
                                                        &payload)) {
        return false;
      }
      payload_length = payload.size();
      message_type = keyferry::protocol::MessageType::kInputCommandResultV1;
    } else {
      std::copy(pending.command_id.begin(), pending.command_id.end(), payload.begin());
      payload[16] = static_cast<std::uint8_t>(pending.result);
    }
    std::array<std::uint8_t, keyferry::endpoint::kMaxWireFrame> wire{};
    std::size_t wire_length = 0;
    return keyferry::protocol::EncodeWireFrame(
               keyferry::protocol::kMajor, keyferry::protocol::kMinor,
               static_cast<std::uint8_t>(message_type), 0, pending.sequence,
               payload.data(), payload_length, wire.data(), wire.size(),
               &wire_length) == keyferry::protocol::CodecError::kOk &&
           transport_->SendTls(wire.data(), wire_length);
  }

  bool SendModeStatus(const PendingModeStatus& pending) {
    const std::array<std::uint8_t, 2> payload{
        static_cast<std::uint8_t>(output_mode_),
        static_cast<std::uint8_t>(pending.stored),
    };
    std::array<std::uint8_t, keyferry::endpoint::kMaxWireFrame> wire{};
    std::size_t wire_length = 0;
    return keyferry::protocol::EncodeWireFrame(
               keyferry::protocol::kMajor, keyferry::protocol::kMinor,
               static_cast<std::uint8_t>(
                   keyferry::protocol::MessageType::kOutputModeStatus),
               0, pending.sequence, payload.data(), payload.size(), wire.data(),
               wire.size(), &wire_length) ==
               keyferry::protocol::CodecError::kOk &&
           transport_->SendTls(wire.data(), wire_length);
  }

  bool SendBondResetStatus(const PendingBondResetStatus& pending) {
    const std::array<std::uint8_t, 2> payload{
        pending.result,
        static_cast<std::uint8_t>(pending.restart_after_send ? 1U : 0U),
    };
    std::array<std::uint8_t, keyferry::endpoint::kMaxWireFrame> wire{};
    std::size_t wire_length = 0;
    return keyferry::protocol::EncodeWireFrame(
               keyferry::protocol::kMajor, keyferry::protocol::kMinor,
               static_cast<std::uint8_t>(
                   keyferry::protocol::MessageType::kBleHidBondStatus),
               0, pending.sequence, payload.data(), payload.size(), wire.data(),
               wire.size(), &wire_length) ==
               keyferry::protocol::CodecError::kOk &&
           transport_->SendTls(wire.data(), wire_length);
  }

  bool SendDisplayOrientationStatus(
      const PendingDisplayOrientationStatus& pending) {
    const std::array<std::uint8_t, 2> payload{
        static_cast<std::uint8_t>(display_orientation_),
        static_cast<std::uint8_t>(pending.stored),
    };
    std::array<std::uint8_t, keyferry::endpoint::kMaxWireFrame> wire{};
    std::size_t wire_length = 0;
    return keyferry::protocol::EncodeWireFrame(
               keyferry::protocol::kMajor, keyferry::protocol::kMinor,
               static_cast<std::uint8_t>(keyferry::protocol::MessageType::
                                             kDisplayOrientationStatus),
               0, pending.sequence, payload.data(), payload.size(), wire.data(),
               wire.size(), &wire_length) ==
               keyferry::protocol::CodecError::kOk &&
           transport_->SendTls(wire.data(), wire_length);
  }

  bool SendScreenPowerStatus(const PendingScreenPowerStatus& pending) {
    const std::array<std::uint8_t, 3> payload{
        static_cast<std::uint8_t>(pending.active),
        static_cast<std::uint8_t>(pending.stored),
        static_cast<std::uint8_t>(pending.hardware_available ? 1U : 0U)};
    std::array<std::uint8_t, keyferry::endpoint::kMaxWireFrame> wire{};
    std::size_t wire_length = 0;
    return keyferry::protocol::EncodeWireFrame(
               keyferry::protocol::kMajor, keyferry::protocol::kMinor,
               static_cast<std::uint8_t>(
                   keyferry::protocol::MessageType::kScreenPowerStatus),
               0, pending.sequence, payload.data(), payload.size(), wire.data(),
               wire.size(), &wire_length) ==
               keyferry::protocol::CodecError::kOk &&
           transport_->SendTls(wire.data(), wire_length);
  }

#if defined(KEYFERRY_FILE_HANDOFF)
  bool SendFileStatus(const PendingFileStatus& pending) {
    std::array<std::uint8_t, 10> payload{};
    payload[0] = static_cast<std::uint8_t>(pending.status.state);
    payload[1] = static_cast<std::uint8_t>(pending.status.error);
    FileWriteLe32(payload.data() + 2, pending.status.size);
    FileWriteLe32(payload.data() + 6, pending.status.received);
    std::array<std::uint8_t, keyferry::endpoint::kMaxWireFrame> wire{};
    std::size_t wire_length = 0;
    return keyferry::protocol::EncodeWireFrame(
               keyferry::protocol::kMajor, keyferry::protocol::kMinor,
               static_cast<std::uint8_t>(
                   keyferry::protocol::MessageType::kFileStatus),
               0, pending.sequence, payload.data(), payload.size(),
               wire.data(), wire.size(), &wire_length) ==
               keyferry::protocol::CodecError::kOk &&
           transport_->SendTls(wire.data(), wire_length);
  }

  bool SendFileSetStatus(const PendingFileSetStatus& pending) {
    std::array<std::uint8_t, keyferry::protocol::kFileHandoffFileSetStatusBytes +
                                 2 + keyferry::file_handoff::kMaximumNameBytes + 4>
        payload{};
    payload[0] = static_cast<std::uint8_t>(pending.status.state);
    payload[1] = static_cast<std::uint8_t>(pending.status.error);
    FileWriteLe32(payload.data() + 2, pending.status.wire_size);
    FileWriteLe32(payload.data() + 6, pending.status.received);
    payload[10] = pending.status.count;
    std::size_t length = keyferry::protocol::kFileHandoffFileSetStatusBytes;
    if (pending.status.has_entry) {
      payload[length++] = pending.status.index;
      payload[length++] = pending.status.name_length;
      std::copy_n(pending.name.data(), pending.status.name_length,
                  payload.data() + length);
      length += pending.status.name_length;
      FileWriteLe32(payload.data() + length, pending.status.size);
      length += 4;
    }
    std::array<std::uint8_t, keyferry::endpoint::kMaxWireFrame> wire{};
    std::size_t wire_length = 0;
    return keyferry::protocol::EncodeWireFrame(
               keyferry::protocol::kMajor, keyferry::protocol::kMinor,
               static_cast<std::uint8_t>(
                   keyferry::protocol::MessageType::kFileSetStatus),
               0, pending.sequence, payload.data(), length,
               wire.data(), wire.size(), &wire_length) ==
               keyferry::protocol::CodecError::kOk &&
           transport_->SendTls(wire.data(), wire_length);
  }
#endif

  static void WatchdogCallback(void* context, const std::uint64_t token,
                               const std::uint64_t now_ms) {
    auto* self = static_cast<HilRuntime*>(context);
    if (!self->Lock()) {
      return;
    }
    self->command_.HeldKeyDeadlineFired(token, now_ms);
    self->Unlock();
  }

  SemaphoreHandle_t lock_{nullptr};
  keyferry::protocol::OutputMode output_mode_;
  keyferry::protocol::OutputMode stored_output_mode_;
  keyferry::output_mode::Storage& output_mode_storage_;
  keyferry::protocol::DisplayOrientation display_orientation_;
  keyferry::protocol::DisplayOrientation stored_display_orientation_;
  keyferry::display_orientation::Storage& display_orientation_storage_;
  keyferry::display_orientation::PowerState screen_power_;
  keyferry::hid::ExecutorState hid_;
  keyferry::ble_hid::IdfBleHidPeripheral ble_hid_;
  keyferry::command::IdfHeldKeyWatchdog watchdog_;
  keyferry::command::CommandExecutor command_;
  keyferry::transport::EspTransport* transport_{nullptr};
  std::uint64_t authenticated_epoch_{0};
  bool peer_input_v1_{false};
#if defined(KEYFERRY_FILE_HANDOFF)
  bool file_negotiated_{false};
  bool file_set_negotiated_{false};
#endif
  bool usb_mounted_{false};
  std::uint64_t usb_attachment_generation_{0};
  bool usb_transfer_in_flight_{false};
  keyferry::hid::InputInterface usb_transfer_interface_{
      keyferry::hid::InputInterface::keyboard};
  BootKeyboardReport usb_transfer_report_{};
  BootMouseReport usb_transfer_mouse_report_{};
  std::uint64_t usb_transfer_mouse_token_{0};
  std::uint64_t usb_transfer_epoch_{0};
  std::uint64_t usb_transfer_generation_{0};
  bool disarm_waiting_{false};
  bool session_abort_requested_{false};
  bool provisioning_active_{false};
  bool provisioning_from_local_maintenance_{false};
  bool local_maintenance_active_{false};
  LocalManagementMetadata local_management_metadata_{};
  bool restart_requested_{false};
  std::uint64_t restart_not_before_ms_{0};
  bool ble_release_in_flight_{false};
  bool ble_transport_ready_{false};
  PendingModeStatus pending_mode_status_{};
  PendingBondResetStatus pending_bond_reset_status_{};
  PendingDisplayOrientationStatus pending_display_orientation_status_{};
  PendingScreenPowerStatus pending_screen_power_status_{};
#if defined(KEYFERRY_FILE_HANDOFF)
  keyferry::file_handoff::Volume* file_volume_{nullptr};
  std::optional<keyferry::file_handoff::Volume> file_volume_storage_{};
  std::uint8_t* file_buffer_{nullptr};
  std::size_t file_buffer_capacity_{0};
  PendingFileStatus pending_file_status_{};
  PendingFileSetStatus pending_file_set_status_{};
  std::uint64_t file_upload_last_ms_{0};
  bool file_refresh_ready_{false};
  bool file_refresh_in_flight_{false};
  bool file_neutral_pending_{false};
  bool file_clear_on_detach_{false};
#endif
  std::array<PendingResult, kResultQueueCapacity> results_{};
  std::size_t result_head_{0};
  std::size_t result_count_{0};
  bool result_overflow_{false};
};

HilRuntime* g_runtime = nullptr;
keyferry::hil::ProvisioningAdapter* g_provisioning = nullptr;
std::atomic_bool g_usb_mounted{false};
std::atomic_bool g_usb_suspended{false};
#if defined(KEYFERRY_FILE_HANDOFF)
std::atomic<std::uint32_t> g_usb_attach_generation{0};
#endif
std::atomic_bool g_ble_control_usb{false};

struct DeviceConfigContext {
  keyferry::config::IdfConfigStorage storage;
  keyferry::config::IdfRecoveryAnchorStorage anchor_storage;
  keyferry::config::IdfRoamingPolicyCrypto roaming_crypto;
  keyferry::runtime_config::OperationalBootContext boot;
};

keyferry::transport::RuntimeConfig BuildPrivateBootstrapConfig() {
  using namespace keyferry::hil_private;
  keyferry::transport::RuntimeConfig config{};
  config.wifi_configured = true;
  config.wifi = {kWifiSsid.data(), kWifiSsid.size(), kWifiPassword.data(),
                 kWifiPassword.size(), keyferry::endpoint::WifiAuth::kWpa2Personal, false};
  config.host_ipv4 = kHostIpv4;
  config.host_ipv4_length = sizeof(kHostIpv4) - 1;
  config.tls = {kTlsServerName, sizeof(kTlsServerName) - 1, kHostPort, kSpkiSha256};
  config.ca_certificate_der = kCaCertificateDer.data();
  config.ca_certificate_der_length = kCaCertificateDer.size();
  config.device_id = kDeviceId;
  config.host_id = kHostId;
  config.link_secret = kLinkSecret;
  config.wifi_connect_timeout_ms = 15000;
  config.discovery_timeout_ms = 1500;
  config.tls_connect_timeout_ms = 10000;
  return config;
}

keyferry::endpoint::FirmwareIdentity BuildFirmwareIdentity(
    const keyferry::protocol::OutputMode output_mode,
    const bool local_management_ready,
    const bool file_handoff_ready) {
  keyferry::endpoint::FirmwareIdentity identity{};
  const esp_app_desc_t* description = esp_app_get_description();
  if (description == nullptr) {
    return identity;
  }
  std::copy_n(reinterpret_cast<const std::uint8_t*>(description->version),
              identity.release.size(), identity.release.begin());
  identity.board_compatibility_id = keyferry::board::compatibility_id;
  identity.mouse_relative_v1 =
      output_mode == keyferry::protocol::OutputMode::kUsbHid;
  identity.ble_hid_output_v1 = true;
  identity.ble_hid_bond_reset_v1 = true;
  identity.targeted_gateway_transfer_v1 = true;
  identity.display_orientation_v1 = keyferry::board::capabilities.display;
  identity.screen_power_v1 = keyferry::board::capabilities.display;
  identity.local_management_v1 = local_management_ready;
  identity.usb_file_handoff_v1 = file_handoff_ready;
  identity.usb_file_set_v2 = file_handoff_ready;
  std::copy_n(description->app_elf_sha256, identity.elf_sha256.size(),
              identity.elf_sha256.begin());
  return identity;
}

keyferry::runtime_config::BootStatus ResolveBootConfig(
    DeviceConfigContext* context,
    keyferry::transport::RuntimeConfig* output,
    keyferry::config::Selection* selection) {
  if (context == nullptr) {
    return keyferry::runtime_config::BootStatus::kLockedStorageIo;
  }
  return keyferry::runtime_config::ResolveOperationalBoot(
      context->storage, context->anchor_storage,
      keyferry::hil_private::kDeviceId, BuildPrivateBootstrapConfig(),
      context->roaming_crypto, &context->boot, output, selection);
}

void BuildSerialDescriptor(const std::array<std::uint8_t, 16>& device_id) {
  constexpr char kHex[] = "0123456789ABCDEF";
  for (std::size_t index = 0; index < device_id.size(); ++index) {
    kSerialDescriptor[index * 2] = kHex[device_id[index] >> 4];
    kSerialDescriptor[index * 2 + 1] = kHex[device_id[index] & 0x0F];
  }
  kSerialDescriptor.back() = '\0';
}

void TinyUsbEventCallback(tinyusb_event_t* event, void*) {
  if (event == nullptr) {
    return;
  }
  if (event->id == TINYUSB_EVENT_ATTACHED) {
    g_usb_mounted.store(true, std::memory_order_release);
    g_usb_suspended.store(false, std::memory_order_release);
#if defined(KEYFERRY_FILE_HANDOFF)
    g_usb_attach_generation.fetch_add(1, std::memory_order_acq_rel);
#endif
  } else if (event->id == TINYUSB_EVENT_DETACHED) {
    g_usb_mounted.store(false, std::memory_order_release);
    g_usb_suspended.store(false, std::memory_order_release);
    if (g_provisioning != nullptr) {
      g_provisioning->TransportLost();
    }
  }
}

void TransportTask(void* context) {
  static_cast<keyferry::transport::EspTransport*>(context)->Run();
#if defined(KEYFERRY_MSC_MEMORY_PROBE)
  // Preserve the static task handle for probe-only stack telemetry after a
  // transport exit. Production firmware still deletes the task as before.
  while (true) {
    vTaskSuspend(nullptr);
  }
#else
  vTaskDelete(nullptr);
#endif
}

#if defined(KEYFERRY_MSC_MEMORY_PROBE)
constexpr std::size_t kMscProbeBufferBytes = 65536;
constexpr std::size_t kMscProbeHeapReserveBytes = 32768;
constexpr std::uint32_t kMscProbeHoldSeconds = 30;
static_assert(kMscProbeBufferBytes == 64 * 1024);

struct MscMemoryProbeContext {
  HilRuntime* runtime{};
  TaskHandle_t main_task{};
  TaskHandle_t transport_task{};
  keyferry::transport::EspTransport* transport{};
  keyferry::protocol::OutputMode output_mode{keyferry::protocol::OutputMode::kUsbHid};
  std::uint8_t first_outcome{};
  std::uint8_t second_outcome{};
};

using MscProbePhase = keyferry::protocol::LocalManagementProbePhase;

// Outcome 0 is not attempted; 1 succeeds; 2 is the provisional 32 KiB
// free-heap guard; 3 is no contiguous 64 KiB block; 4 is malloc failure; 5
// is a post-allocation guard drop. The guard is not a measured TLS floor.
using MscProbeAllocationOutcome =
    keyferry::protocol::LocalManagementProbeOutcome;

void MscMemoryProbeLog(MscProbePhase phase,
                       const MscMemoryProbeContext& context,
                       bool first_held, bool second_held) {
  constexpr std::uint32_t kCaps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
  keyferry::local_management::ProbeStatus sample{};
  sample.phase = static_cast<std::uint8_t>(phase);
  sample.uptime_seconds = static_cast<std::uint32_t>(esp_timer_get_time() / 1000000);
  sample.held_flags = static_cast<std::uint8_t>((first_held ? 1U : 0U) |
                                                (second_held ? 2U : 0U));
  sample.first_outcome = context.first_outcome;
  sample.second_outcome = context.second_outcome;
  sample.free_internal_heap = static_cast<std::uint32_t>(heap_caps_get_free_size(kCaps));
  sample.largest_internal_block =
      static_cast<std::uint32_t>(heap_caps_get_largest_free_block(kCaps));
  sample.minimum_internal_heap =
      static_cast<std::uint32_t>(heap_caps_get_minimum_free_size(kCaps));
  sample.main_stack_free = context.main_task == nullptr
                               ? 0U : uxTaskGetStackHighWaterMark(context.main_task);
  sample.transport_stack_free = context.transport_task == nullptr
                                    ? 0U : uxTaskGetStackHighWaterMark(context.transport_task);
  sample.probe_stack_free = uxTaskGetStackHighWaterMark(nullptr);
  sample.link = context.transport == nullptr
                    ? 0U : static_cast<std::uint8_t>(context.transport->active_path());
  sample.transport_running =
      context.transport != nullptr && context.transport->diagnostics().running;
  sample.output_mode = static_cast<std::uint8_t>(context.output_mode);
  sample.sample_seq = PublishMscProbeStatus(sample);
  ESP_LOGW(kTag,
           "msc_memory_probe seq=%u phase=%u uptime_s=%u free=%u largest=%u "
           "minimum=%u main_stack_free=%u transport_stack_free=%u "
           "probe_stack_free=%u held=%u first=%u second=%u link=%u "
           "transport_running=%u output_mode=%u",
           static_cast<unsigned>(sample.sample_seq),
           static_cast<unsigned>(sample.phase), sample.uptime_seconds,
           sample.free_internal_heap, sample.largest_internal_block,
           sample.minimum_internal_heap, sample.main_stack_free,
           sample.transport_stack_free, sample.probe_stack_free,
           static_cast<unsigned>(sample.held_flags),
           static_cast<unsigned>(sample.first_outcome),
           static_cast<unsigned>(sample.second_outcome),
           static_cast<unsigned>(sample.link),
           sample.transport_running ? 1U : 0U,
           static_cast<unsigned>(sample.output_mode));
}

void MscMemoryProbeRelease(std::uint8_t*& bytes) {
  if (bytes == nullptr) {
    return;
  }
  volatile std::uint8_t* writable = bytes;
  for (std::size_t index = 0; index < kMscProbeBufferBytes; ++index) {
    writable[index] = 0;
  }
  heap_caps_free(bytes);
  bytes = nullptr;
}

std::uint8_t* MscMemoryProbeAllocate(MscProbeAllocationOutcome* outcome) {
  constexpr std::uint32_t kCaps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
  *outcome = MscProbeAllocationOutcome::kGuardFailed;
  if (heap_caps_get_free_size(kCaps) <
      kMscProbeBufferBytes + kMscProbeHeapReserveBytes) {
    return nullptr;
  }
  *outcome = MscProbeAllocationOutcome::kContiguousFailed;
  if (heap_caps_get_largest_free_block(kCaps) < kMscProbeBufferBytes) {
    return nullptr;
  }
  *outcome = MscProbeAllocationOutcome::kMallocFailed;
  auto* bytes = static_cast<std::uint8_t*>(
      heap_caps_malloc(kMscProbeBufferBytes, kCaps));
  if (bytes != nullptr) {
    volatile std::uint8_t* writable = bytes;
    for (std::size_t index = 0; index < kMscProbeBufferBytes; ++index) {
      writable[index] = 0xA5;
    }
    if (heap_caps_get_free_size(kCaps) < kMscProbeHeapReserveBytes) {
      MscMemoryProbeRelease(bytes);
      *outcome = MscProbeAllocationOutcome::kPostGuardFailed;
      return nullptr;
    }
    *outcome = MscProbeAllocationOutcome::kSuccess;
  }
  return bytes;
}

void MscMemoryProbeTask(void* raw_context) {
  auto& context = *static_cast<MscMemoryProbeContext*>(raw_context);
  std::uint8_t* first = nullptr;
  std::uint8_t* second = nullptr;
  std::uint64_t selected_epoch = 0;
  std::uint32_t stage_seconds = 0;
  std::uint32_t elapsed_seconds = 0;
  bool attempted = false;
  bool finished = false;
  MscProbePhase terminal_phase = MscProbePhase::kWaiting;
  MscMemoryProbeLog(MscProbePhase::kBoot, context, false, false);

  while (true) {
    vTaskDelay(pdMS_TO_TICKS(1000));
    ++elapsed_seconds;
    const auto safe_epoch = context.runtime->MemoryProbeSafeEpoch();
    if ((first != nullptr || second != nullptr) &&
        safe_epoch != selected_epoch) {
      MscMemoryProbeRelease(second);
      MscMemoryProbeRelease(first);
      finished = true;
      terminal_phase = MscProbePhase::kInterrupted;
      MscMemoryProbeLog(MscProbePhase::kInterrupted, context, false, false);
    } else if ((first != nullptr || second != nullptr) &&
               heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) <
                   kMscProbeHeapReserveBytes) {
      MscMemoryProbeRelease(second);
      MscMemoryProbeRelease(first);
      finished = true;
      terminal_phase = MscProbePhase::kFloorDrop;
      MscMemoryProbeLog(MscProbePhase::kFloorDrop, context, false, false);
    } else if (!attempted && safe_epoch != 0) {
      attempted = true;
      selected_epoch = safe_epoch;
      const auto monitor_result = heap_caps_monitor_local_minimum_free_size_start();
      if (monitor_result != ESP_OK) {
        finished = true;
        terminal_phase = MscProbePhase::kMonitorFailed;
        MscMemoryProbeLog(MscProbePhase::kMonitorFailed, context, false, false);
      } else {
        MscMemoryProbeLog(MscProbePhase::kPostAuth, context, false, false);
        MscProbeAllocationOutcome outcome{};
        first = MscMemoryProbeAllocate(&outcome);
        context.first_outcome = static_cast<std::uint8_t>(outcome);
        if (first == nullptr) {
          finished = true;
          terminal_phase = MscProbePhase::kFirstFailed;
          MscMemoryProbeLog(MscProbePhase::kFirstFailed, context, false, false);
        } else {
          stage_seconds = 0;
          MscMemoryProbeLog(MscProbePhase::kFirstHeld, context, true, false);
        }
      }
    } else if (first != nullptr && !finished) {
      ++stage_seconds;
      if (stage_seconds == kMscProbeHoldSeconds && second == nullptr) {
        MscProbeAllocationOutcome outcome{};
        second = MscMemoryProbeAllocate(&outcome);
        context.second_outcome = static_cast<std::uint8_t>(outcome);
        if (second == nullptr) {
          MscMemoryProbeLog(MscProbePhase::kSecondFailed, context, true, false);
          MscMemoryProbeRelease(first);
          finished = true;
          terminal_phase = MscProbePhase::kSecondFailed;
          MscMemoryProbeLog(MscProbePhase::kSecondFailed, context, false, false);
        } else {
          stage_seconds = 0;
          MscMemoryProbeLog(MscProbePhase::kSecondHeld, context, true, true);
        }
      } else if (stage_seconds == kMscProbeHoldSeconds && second != nullptr) {
        MscMemoryProbeRelease(second);
        MscMemoryProbeRelease(first);
        finished = true;
        terminal_phase = MscProbePhase::kReleased;
        MscMemoryProbeLog(MscProbePhase::kReleased, context, false, false);
      } else if (stage_seconds % 5 == 0) {
        MscMemoryProbeLog(MscProbePhase::kHolding, context, true,
                          second != nullptr);
      }
    }
    if (elapsed_seconds % 60 == 0) {
      MscMemoryProbeLog(finished ? terminal_phase
                                 : first != nullptr ? MscProbePhase::kHolding
                                                    : MscProbePhase::kWaiting,
                        context, first != nullptr, second != nullptr);
    }
  }
}
#endif

struct StatusTaskContext {
  HilRuntime* runtime{};
  bool transport_allowed{};
  keyferry::transport::EspTransport* transport{};
  std::uint64_t config_generation{};
  std::int32_t nvs_result{};
  keyferry::protocol::DisplayOrientation display_orientation{
      keyferry::protocol::DisplayOrientation::kNormal};
  keyferry::protocol::ScreenPower screen_power{
      keyferry::protocol::ScreenPower::kOn};
};

void StatusTask(void* context) {
  if constexpr (!keyferry::board::capabilities.display) {
    vTaskDelete(nullptr);
    return;
  }
  const auto* status = static_cast<const StatusTaskContext*>(context);
  // The scanline buffer belongs in static internal RAM, never on this task's
  // stack and never in PSRAM.
  static keyferry::status::EspStatusDisplay display;
  if (status == nullptr || status->runtime == nullptr ||
      !display.Initialize(status->display_orientation,
                          status->screen_power ==
                              keyferry::protocol::ScreenPower::kOn)) {
    if (status != nullptr && status->runtime != nullptr) {
      status->runtime->ScreenPowerApplied(status->screen_power, false);
    }
    vTaskDelete(nullptr);
    return;
  }
  bool screen_on = status->screen_power == keyferry::protocol::ScreenPower::kOn;
  status->runtime->ScreenPowerApplied(status->screen_power, true);
  keyferry::status::ActivityPresentationFilter activity_filter;
  while (true) {
    keyferry::protocol::ScreenPower desired{};
    if (!status->runtime->ScreenPowerDesired(&desired)) {
      vTaskDelay(pdMS_TO_TICKS(250));
      continue;
    }
    if (desired == keyferry::protocol::ScreenPower::kOff) {
      if (screen_on) {
        if (!display.SetEnabled(false)) {
          status->runtime->ScreenPowerApplied(desired, false);
          vTaskDelete(nullptr);
          return;
        }
        screen_on = false;
        status->runtime->ScreenPowerApplied(desired, true);
      }
      vTaskDelay(pdMS_TO_TICKS(250));
      continue;
    }
    keyferry::status::LinkPath link = keyferry::status::LinkPath::kOffline;
    if (status->transport != nullptr) {
      const auto active = status->transport->active_path();
      if (active == keyferry::transport::Path::kWifi) {
        link = keyferry::status::LinkPath::kWifi;
      } else if (active == keyferry::transport::Path::kBluetooth) {
        link = keyferry::status::LinkPath::kBluetooth;
      }
    }
    auto snapshot = status->runtime->StatusSnapshot(
        status->transport_allowed, link,
        status->config_generation);
    snapshot.usb_suspended =
        g_usb_suspended.load(std::memory_order_acquire);
    const esp_app_desc_t* description = esp_app_get_description();
    if (description != nullptr) {
      constexpr char kHex[] = "0123456789ABCDEF";
      for (std::size_t index = 0; index < 4; ++index) {
        snapshot.build_id[index * 2] =
            kHex[description->app_elf_sha256[index] >> 4];
        snapshot.build_id[index * 2 + 1] =
            kHex[description->app_elf_sha256[index] & 0x0F];
      }
    }
    snapshot.nvs_error = status->nvs_result;
    snapshot.free_internal_heap =
        heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) &
        ~std::uint32_t{1023};
    snapshot.largest_internal_block = heap_caps_get_largest_free_block(
        MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) &
        ~std::uint32_t{1023};
    snapshot.minimum_internal_heap = heap_caps_get_minimum_free_size(
        MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) &
        ~std::uint32_t{1023};
    const std::uint64_t elapsed_ms =
        static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
    snapshot.activity = activity_filter.Update(snapshot.activity, elapsed_ms);
    if (status->transport != nullptr) {
      const auto diagnostics = status->transport->diagnostics();
      snapshot.transport_running = diagnostics.running;
      snapshot.wifi_available = diagnostics.wifi_available;
      snapshot.wifi_stage = static_cast<std::uint8_t>(diagnostics.wifi_stage);
      snapshot.wifi_error = diagnostics.wifi_error;
      if (!snapshot.ble_hid_mode) {
        snapshot.ble_available = diagnostics.ble_available;
        snapshot.ble_stage = static_cast<std::uint8_t>(diagnostics.ble.stage);
        snapshot.ble_error = diagnostics.ble.error;
        snapshot.ble_synchronized = diagnostics.ble.synchronized;
        snapshot.ble_advertising = diagnostics.ble.advertising;
      }
      if (diagnostics.wifi_stage ==
          keyferry::transport::WifiStage::kConnecting) {
        snapshot.connection =
            keyferry::status::ConnectionProgress::kWifiJoining;
      } else if (diagnostics.wifi_stage ==
                     keyferry::transport::WifiStage::kGotIp ||
                 diagnostics.wifi_stage ==
                     keyferry::transport::WifiStage::kTls) {
        snapshot.connection =
            keyferry::status::ConnectionProgress::kWifiAuthenticating;
      } else if (diagnostics.ble.stage ==
                 keyferry::ble::PeripheralStage::kConnected) {
        snapshot.connection =
            keyferry::status::ConnectionProgress::kBluetoothAuthenticating;
      } else if (diagnostics.ble.advertising) {
        snapshot.connection =
            keyferry::status::ConnectionProgress::kBluetoothAdvertising;
      }
    }
    const auto page = keyferry::status::SelectPage(snapshot, elapsed_ms);
    constexpr auto kPresentationDensity =
        keyferry::board::display.presentation ==
                keyferry::board::DisplayPresentation::kCompact
            ? keyferry::status::PresentationDensity::kCompact
            : keyferry::status::PresentationDensity::kNormal;
    if (!display.Show(keyferry::status::BuildPresentation(
            snapshot, page, kPresentationDensity))) {
      status->runtime->ScreenPowerApplied(desired, false);
      vTaskDelete(nullptr);
      return;
    }
    if (!screen_on) {
      keyferry::protocol::ScreenPower still_desired{};
      if (status->runtime->ScreenPowerDesired(&still_desired) &&
          still_desired == keyferry::protocol::ScreenPower::kOn) {
        if (!display.SetEnabled(true)) {
          status->runtime->ScreenPowerApplied(desired, false);
          vTaskDelete(nullptr);
          return;
        }
        screen_on = true;
        status->runtime->ScreenPowerApplied(desired, true);
      }
    }
    vTaskDelay(pdMS_TO_TICKS(250));
  }
}

bool UsbRecoveryRequested(
    const keyferry::protocol::OutputMode stored_output_mode) {
  if (stored_output_mode != keyferry::protocol::OutputMode::kBleHid) {
    return false;
  }
  if constexpr (!keyferry::board::capabilities.button ||
                keyferry::board::boot_gpio < 0 ||
                keyferry::board::boot_gpio >= GPIO_NUM_MAX) {
    ESP_LOGE(kTag, "BLE output has no usable recovery button; using USB for this boot");
    return true;
  }
  gpio_config_t config{};
  config.pin_bit_mask = 1ULL << keyferry::board::boot_gpio;
  config.mode = GPIO_MODE_INPUT;
  config.pull_up_en = GPIO_PULLUP_ENABLE;
  config.pull_down_en = GPIO_PULLDOWN_DISABLE;
  config.intr_type = GPIO_INTR_DISABLE;
  if (gpio_config(&config) != ESP_OK) {
    ESP_LOGE(kTag, "BLE output recovery button unavailable; using USB for this boot");
    return true;
  }
  ESP_LOGI(kTag, "BLE output selected; tap BOOT within 3 seconds for one-boot USB recovery");
  constexpr std::uint32_t kPollMs = 20;
  constexpr std::uint32_t kWindowMs = 3000;
  constexpr std::uint32_t kDebounceSamples = 3;
  std::uint32_t pressed_samples = 0;
  for (std::uint32_t elapsed = 0; elapsed < kWindowMs; elapsed += kPollMs) {
    if (gpio_get_level(static_cast<gpio_num_t>(keyferry::board::boot_gpio)) == 0) {
      ++pressed_samples;
      if (pressed_samples >= kDebounceSamples) {
        ESP_LOGW(kTag, "BOOT pressed; using USB output for this boot only");
        return true;
      }
    } else {
      pressed_samples = 0;
    }
    vTaskDelay(pdMS_TO_TICKS(kPollMs));
  }
  return false;
}

}  // namespace

#if defined(KEYFERRY_MSC_SIZE_PROBE)
// The size probe deliberately has no medium. These entry points also keep the
// pinned stack's flash/SD adapter out of the linked image.
extern "C" void msc_storage_mount_to_usb(void) {}
extern "C" void msc_storage_mount_to_app(void) {}

extern "C" void tud_msc_inquiry_cb(std::uint8_t, std::uint8_t vendor[8],
                                    std::uint8_t product[16],
                                    std::uint8_t revision[4]) {
  std::memcpy(vendor, "KEYFERRY", 8);
  std::memcpy(product, "EMPTY SIZE PROBE", 16);
  std::memcpy(revision, "0.0 ", 4);
}
extern "C" bool tud_msc_test_unit_ready_cb(std::uint8_t lun) {
  tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, 0x3a, 0x00);
  return false;
}
extern "C" void tud_msc_capacity_cb(std::uint8_t, std::uint32_t* block_count,
                                      std::uint16_t* block_size) {
  *block_count = 0;
  *block_size = 512;
}
extern "C" std::int32_t tud_msc_read10_cb(std::uint8_t lun, std::uint32_t,
                                            std::uint32_t, void*, std::uint32_t) {
  tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, 0x3a, 0x00);
  return -1;
}
extern "C" std::int32_t tud_msc_write10_cb(std::uint8_t lun, std::uint32_t,
                                             std::uint32_t, std::uint8_t*,
                                             std::uint32_t) {
  tud_msc_set_sense(lun, SCSI_SENSE_DATA_PROTECT, 0x27, 0x00);
  return -1;
}
extern "C" std::int32_t tud_msc_scsi_cb(std::uint8_t lun,
                                         const std::uint8_t[16], void*,
                                         std::uint16_t) {
  tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, 0x20, 0x00);
  return -1;
}
extern "C" bool tud_msc_is_writable_cb(std::uint8_t) { return false; }
#endif

#if defined(KEYFERRY_FILE_HANDOFF)
// The managed flash/SD MSC adapter is excluded for this build. Every SCSI
// request reaches this immutable RAM-backed volume instead.
extern "C" void msc_storage_mount_to_usb(void) {}
extern "C" void msc_storage_mount_to_app(void) {}
extern "C" void tud_msc_inquiry_cb(std::uint8_t, std::uint8_t vendor[8],
                                     std::uint8_t product[16],
                                     std::uint8_t revision[4]) {
  std::memcpy(vendor, "KEYFERRY", 8);
  std::memcpy(product, "MESSAGE TXT     ", 16);
  std::memcpy(revision, "0.2 ", 4);
}
extern "C" bool tud_msc_test_unit_ready_cb(std::uint8_t lun) {
  if (lun == 0 && g_runtime != nullptr && g_runtime->FileReady()) return true;
  tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, 0x3a, 0x00);
  return false;
}
extern "C" void tud_msc_capacity_cb(std::uint8_t, std::uint32_t* blocks,
                                      std::uint16_t* block_size) {
  *blocks = keyferry::file_handoff::kBlockCount;
  *block_size = keyferry::file_handoff::kBlockBytes;
}
extern "C" std::int32_t tud_msc_read10_cb(std::uint8_t lun, std::uint32_t lba,
                                            std::uint32_t offset, void* buffer,
                                            std::uint32_t length) {
  if (lun == 0 && length == 0) return 0;
  if (lun == 0 && buffer != nullptr && g_runtime != nullptr &&
      g_runtime->FileRead(lba, offset, static_cast<std::uint8_t*>(buffer), length)) {
    return static_cast<std::int32_t>(length);
  }
  tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, 0x3a, 0x00);
  return -1;
}
extern "C" std::int32_t tud_msc_write10_cb(std::uint8_t lun, std::uint32_t,
                                             std::uint32_t, std::uint8_t*,
                                             std::uint32_t) {
  tud_msc_set_sense(lun, SCSI_SENSE_DATA_PROTECT, 0x27, 0x00);
  return -1;
}
extern "C" std::int32_t tud_msc_scsi_cb(std::uint8_t lun,
                                         const std::uint8_t[16], void*,
                                         std::uint16_t) {
  tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, 0x20, 0x00);
  return -1;
}
extern "C" bool tud_msc_is_writable_cb(std::uint8_t) { return false; }
#endif

extern "C" std::uint8_t const* tud_hid_descriptor_report_cb(
    const std::uint8_t instance) {
  if (g_ble_control_usb.load(std::memory_order_acquire)) {
    return instance == keyferry::hil::kBleControlProvisioningHidInstance
               ? kProvisioningReportDescriptor
               : nullptr;
  }
  if (instance == keyferry::hil::kKeyboardHidInstance) {
    return kKeyboardReportDescriptor;
  }
  if (instance == keyferry::hil::kProvisioningHidInstance) {
    return kProvisioningReportDescriptor;
  }
  if (instance == keyferry::hil::kMouseHidInstance) {
    return kMouseReportDescriptor;
  }
  return nullptr;
}

extern "C" std::uint16_t tud_hid_get_report_cb(
    const std::uint8_t instance, const std::uint8_t report_id,
    const hid_report_type_t report_type, std::uint8_t* buffer,
    const std::uint16_t requested_length) {
  if (g_runtime == nullptr || report_id != 0 ||
      report_type != HID_REPORT_TYPE_INPUT ||
      g_ble_control_usb.load(std::memory_order_acquire)) {
    return 0;
  }
  if (instance == keyferry::hil::kKeyboardHidInstance) {
    const auto report = g_runtime->CurrentReport();
    const auto bytes = std::min<std::uint16_t>(requested_length, sizeof(report));
    if (buffer == nullptr && bytes != 0) {
      return 0;
    }
    std::memcpy(buffer, &report, bytes);
    return bytes;
  }
  if (instance == keyferry::hil::kMouseHidInstance) {
    const auto report = g_runtime->CurrentMouseReport();
    const auto bytes = std::min<std::uint16_t>(requested_length, sizeof(report));
    if (buffer == nullptr && bytes != 0) {
      return 0;
    }
    std::memcpy(buffer, &report, bytes);
    return bytes;
  }
  return 0;
}

extern "C" void tud_hid_set_report_cb(
    const std::uint8_t instance, const std::uint8_t report_id,
    const hid_report_type_t report_type, const std::uint8_t* buffer,
    const std::uint16_t length) {
  const auto provisioning_instance =
      g_ble_control_usb.load(std::memory_order_acquire)
          ? keyferry::hil::kBleControlProvisioningHidInstance
          : keyferry::hil::kProvisioningHidInstance;
  if (!g_ble_control_usb.load(std::memory_order_acquire) &&
      instance == keyferry::hil::kKeyboardHidInstance) {
    // Boot-keyboard LED output is intentionally ignored and never routed to
    // provisioning or command authority.
    return;
  }
  if (instance == provisioning_instance && g_provisioning != nullptr) {
    g_provisioning->SetReport(instance, report_id, report_type, buffer, length);
  } else if (g_runtime != nullptr) {
    g_runtime->FailClosed(0);
  }
}

extern "C" void tud_hid_report_complete_cb(
    const std::uint8_t instance, const std::uint8_t* report,
    const std::uint16_t length) {
  const bool control_only = g_ble_control_usb.load(std::memory_order_acquire);
  const auto provisioning_instance =
      control_only ? keyferry::hil::kBleControlProvisioningHidInstance
                   : keyferry::hil::kProvisioningHidInstance;
  if (!control_only && instance == keyferry::hil::kKeyboardHidInstance &&
      g_runtime != nullptr) {
    g_runtime->UsbReportCompleted(instance, report, length);
  } else if (!control_only && instance == keyferry::hil::kMouseHidInstance &&
             g_runtime != nullptr) {
    g_runtime->UsbReportCompleted(instance, report, length);
  } else if (instance == provisioning_instance && g_provisioning != nullptr) {
    g_provisioning->ReportCompleted(instance, length);
  } else if (g_runtime != nullptr) {
    g_runtime->FailClosed(0);
  }
}

extern "C" void tud_hid_report_failed_cb(
    const std::uint8_t instance, hid_report_type_t, const std::uint8_t*,
    std::uint16_t) {
  const bool control_only = g_ble_control_usb.load(std::memory_order_acquire);
  const auto provisioning_instance =
      control_only ? keyferry::hil::kBleControlProvisioningHidInstance
                   : keyferry::hil::kProvisioningHidInstance;
  if (!control_only && instance == keyferry::hil::kKeyboardHidInstance &&
      g_runtime != nullptr) {
    g_runtime->UsbReportFailed(instance);
  } else if (!control_only && instance == keyferry::hil::kMouseHidInstance &&
             g_runtime != nullptr) {
    g_runtime->UsbReportFailed(instance);
  } else if (instance == provisioning_instance && g_provisioning != nullptr) {
    g_provisioning->ReportFailed(instance);
  } else if (g_runtime != nullptr) {
    g_runtime->FailClosed(0);
  }
}

extern "C" void tud_suspend_cb(bool) {
  g_usb_suspended.store(true, std::memory_order_release);
  if (g_provisioning != nullptr) {
    g_provisioning->TransportLost();
  }
}

extern "C" void tud_resume_cb() {
  g_usb_suspended.store(false, std::memory_order_release);
}

#if defined(KEYFERRY_BLE_HID_COMPILE_ONLY_SPIKE)
#include "keyferry/ble_hid_spike.h"
#else
#line 1057
#endif

extern "C" void app_main() {
#if defined(KEYFERRY_BLE_HID_COMPILE_ONLY_SPIKE)
  // This branch exists only to retain the proposed BLE HID service and output
  // adapter in an off-device size build. The anchor is defined false and the
  // spike image is never a flashable release artifact.
  if (keyferry::ble_hid_spike::g_compile_only_anchor) {
    (void)keyferry::ble_hid_spike::PrepareCompileOnlyService();
    const std::uint8_t released_report[8]{};
    (void)keyferry::ble_hid_spike::SubmitCompileOnlyReport(
        0, 0, released_report, sizeof(released_report));
  }
#endif
#line 1058
  const esp_err_t nvs_result = nvs_flash_init();
  if (nvs_result != ESP_OK) {
    ESP_LOGE(kTag, "NVS initialization failed without erase: %ld",
             static_cast<long>(nvs_result));
  }
  static keyferry::output_mode::IdfStorage output_mode_storage;
  const auto output_mode_result = keyferry::output_mode::Load(output_mode_storage);
  const auto stored_output_mode = output_mode_result.mode;
  const auto output_mode = keyferry::output_mode::EffectiveBootMode(
      stored_output_mode, UsbRecoveryRequested(stored_output_mode));
  static keyferry::display_orientation::IdfStorage display_orientation_storage;
  const auto display_orientation_result =
      keyferry::display_orientation::Load(display_orientation_storage);
  const auto display_orientation = display_orientation_result.orientation;
  const auto screen_power_result =
      keyferry::display_orientation::LoadPower(display_orientation_storage);
  const auto screen_power = screen_power_result.power;
  static HilRuntime runtime(output_mode, stored_output_mode,
                            output_mode_storage, display_orientation,
                            display_orientation_storage, screen_power);
  if (!runtime.Initialize()) {
    ESP_LOGE(kTag, "safety runtime initialization failed");
    return;
  }
#if defined(KEYFERRY_FILE_HANDOFF)
  // Admission and allocation happen on the first authenticated BEGIN, after
  // TLS has settled. Startup leaves the complete heap available to TLS.
  constexpr bool file_handoff_ready = true;
#else
  constexpr bool file_handoff_ready = false;
#endif
  static DeviceConfigContext config_context;
  keyferry::transport::RuntimeConfig runtime_config{};
  keyferry::config::Selection selection{};
  const auto boot_status =
      ResolveBootConfig(&config_context, &runtime_config, &selection);
  runtime_config.ble_gateway_allowed =
      output_mode == keyferry::protocol::OutputMode::kUsbHid;
  const bool transport_allowed =
      boot_status == keyferry::runtime_config::BootStatus::kStored ||
      boot_status == keyferry::runtime_config::BootStatus::kRoaming ||
      boot_status == keyferry::runtime_config::BootStatus::kPrivateBootstrap;

  std::array<std::uint8_t, 16> provisioning_device_id{};
  std::array<std::uint8_t, 32> provisioning_key{};
  std::uint64_t provisioning_generation = 0;
  keyferry::provisioning::PolicyStatus provisioning_policy{};
  const bool roaming_authority =
      keyferry::config::ValidateRecoveryAnchor(
          config_context.boot.roaming.anchor) &&
      config_context.boot.roaming.anchor.device_id ==
          keyferry::hil_private::kDeviceId;
  const bool stored_authority =
      selection.state == keyferry::config::ConfigState::kReady &&
      boot_status == keyferry::runtime_config::BootStatus::kStored &&
      keyferry::config::ValidateConfig(config_context.boot.legacy.persisted) &&
      config_context.boot.legacy.persisted.device_id ==
          keyferry::hil_private::kDeviceId;
  if (roaming_authority) {
    provisioning_device_id = config_context.boot.roaming.anchor.device_id;
    provisioning_key =
        config_context.boot.roaming.anchor.device_recovery_secret;
    provisioning_generation =
        config_context.boot.roaming.anchor.policy_sequence;
    provisioning_policy.state =
        config_context.boot.roaming.anchor.phase ==
                keyferry::config::RecoveryAnchorPhase::kActive
            ? keyferry::provisioning::PolicyState::kActive
            : keyferry::provisioning::PolicyState::kMigrationPending;
    provisioning_policy.epoch = config_context.boot.roaming.anchor.epoch;
    provisioning_policy.sequence =
        config_context.boot.roaming.anchor.policy_sequence;
    provisioning_policy.hash = config_context.boot.roaming.anchor.policy_hash;
  } else if (stored_authority) {
    provisioning_device_id = config_context.boot.legacy.persisted.device_id;
    provisioning_key = config_context.boot.legacy.persisted.provisioning_key;
    provisioning_generation = selection.generation;
  } else if (boot_status ==
             keyferry::runtime_config::BootStatus::kPrivateBootstrap) {
    provisioning_device_id = keyferry::hil_private::kDeviceId;
    provisioning_key = keyferry::hil_private::kProvisioningKey;
  }
  if (!roaming_authority &&
      boot_status == keyferry::runtime_config::BootStatus::kLockedRecoveryMalformed) {
    provisioning_policy.state =
        keyferry::provisioning::PolicyState::kMalformed;
  } else if (!roaming_authority &&
             boot_status == keyferry::runtime_config::BootStatus::kLockedRecoveryIo) {
    provisioning_policy.state =
        keyferry::provisioning::PolicyState::kStorageError;
  }
  BuildSerialDescriptor(keyferry::hil_private::kDeviceId);
  static keyferry::provisioning::IdfProvisioningEffects provisioning_effects(
      config_context.storage, config_context.boot.legacy_workspace,
      config_context.anchor_storage, config_context.roaming_crypto,
      config_context.boot.migration_workspace);
  const bool provisioning_random_ready = provisioning_effects.InitializeRandom();
  if (!provisioning_random_ready) {
    ESP_LOGE(kTag, "provisioning random initialization failed");
  }
  static keyferry::provisioning::Session provisioning_session(
      provisioning_device_id, provisioning_key, provisioning_generation,
      provisioning_effects,
      keyferry::provisioning::PayloadFormat::kRoamingV2,
      provisioning_policy);
  const auto provisioning_hid_instance =
      output_mode == keyferry::protocol::OutputMode::kBleHid
          ? keyferry::hil::kBleControlProvisioningHidInstance
          : keyferry::hil::kProvisioningHidInstance;
  static keyferry::local_management::IdfReceiptBlobStorage local_receipt_storage;
  static keyferry::local_management::ReceiptJournal local_receipts(
      local_receipt_storage);
  static std::optional<keyferry::local_management::Coordinator>
      local_coordinator;
  static std::optional<keyferry::local_management::Session> local_session;
  const bool active_recovery_authority =
      roaming_authority &&
      config_context.boot.roaming.anchor.phase ==
          keyferry::config::RecoveryAnchorPhase::kActive;
  bool local_management_ready = false;
  if (active_recovery_authority && provisioning_random_ready &&
      local_receipts.Initialize()) {
    local_coordinator.emplace(runtime, local_receipts);
    if (local_coordinator->Initialize()) {
      local_session.emplace(
          provisioning_device_id, provisioning_key,
          static_cast<std::uint32_t>(
              keyferry::protocol::Capability::kLocalManagementV1),
          provisioning_effects, *local_coordinator);
      local_management_ready = true;
    }
  }

  const auto firmware_identity =
      BuildFirmwareIdentity(output_mode, local_management_ready,
                            file_handoff_ready);
  if (local_management_ready) {
    LocalManagementMetadata metadata{};
    std::copy_n(firmware_identity.release.begin(), metadata.release.size(),
                metadata.release.begin());
    metadata.capabilities =
        keyferry::endpoint::FirmwareCapabilityMask(firmware_identity);
    metadata.policy_sequence =
        config_context.boot.roaming.anchor.policy_sequence;
    metadata.receipts = &local_receipts;
    metadata.board_compatibility_id =
        static_cast<std::uint8_t>(firmware_identity.board_compatibility_id);
    metadata.wifi_profile_count =
        boot_status == keyferry::runtime_config::BootStatus::kRoaming
            ? config_context.boot.roaming.persisted.wifi_profile_count
            : 0;
    metadata.policy_state = static_cast<std::uint8_t>(provisioning_policy.state);
    metadata.configuration_valid =
        boot_status == keyferry::runtime_config::BootStatus::kRoaming;
    metadata.receipt_storage_healthy = true;
    runtime.ConfigureLocalManagement(metadata);
  }

  static keyferry::hil::ProvisioningAdapter provisioning_adapter(
      provisioning_session, provisioning_effects, runtime,
      provisioning_hid_instance,
      local_management_ready ? &*local_session : nullptr,
      local_management_ready ? &*local_coordinator : nullptr);
  if (!provisioning_adapter.Initialize()) {
    runtime.FailClosed(0);
    ESP_LOGE(kTag, "provisioning queue initialization failed");
    return;
  }
  g_provisioning = &provisioning_adapter;

  static std::optional<keyferry::transport::EspTransport> transport;
  if (transport_allowed) {
    transport.emplace(runtime_config, runtime,
                      static_cast<std::int32_t>(nvs_result),
                      firmware_identity);
    runtime.SetTransport(&*transport);
  } else {
    ESP_LOGE(kTag, "configuration locked: boot_status=%u generation=%llu",
             static_cast<unsigned>(boot_status),
             static_cast<unsigned long long>(selection.generation));
  }
  g_runtime = &runtime;

  const bool ble_control_usb =
      output_mode == keyferry::protocol::OutputMode::kBleHid;
  g_ble_control_usb.store(ble_control_usb, std::memory_order_release);
  tinyusb_config_t usb_config = TINYUSB_DEFAULT_CONFIG();
  usb_config.descriptor.device = ble_control_usb
                                     ? &kBleControlDeviceDescriptor
                                     : &kDeviceDescriptor;
  usb_config.descriptor.full_speed_config =
      ble_control_usb ? kBleControlConfigurationDescriptor
                      : kConfigurationDescriptor;
  usb_config.descriptor.string = kStringDescriptors;
  usb_config.descriptor.string_count = std::size(kStringDescriptors);
  usb_config.event_cb = TinyUsbEventCallback;
  if (tinyusb_driver_install(&usb_config) != ESP_OK) {
    runtime.FailClosed(0);
    ESP_LOGE(kTag, "TinyUSB install failed");
    return;
  }

  TaskHandle_t transport_task_handle = nullptr;
  if (transport) {
    static std::array<StackType_t,
                      kTransportTaskStackBytes / sizeof(StackType_t)>
        transport_task_stack{};
    static StaticTask_t transport_task_control{};
    transport_task_handle =
        xTaskCreateStatic(TransportTask, "kf-transport",
                          transport_task_stack.size(), &*transport, 5,
                          transport_task_stack.data(),
                          &transport_task_control);
    if (transport_task_handle == nullptr) {
      runtime.FailClosed(0);
      ESP_LOGE(kTag, "static transport task creation failed");
      return;
    }
  }

#if defined(KEYFERRY_MSC_MEMORY_PROBE)
  static MscMemoryProbeContext msc_probe_context{
      &runtime, xTaskGetCurrentTaskHandle(), transport_task_handle,
      transport ? &*transport : nullptr, output_mode};
  static std::array<StackType_t, 4096 / sizeof(StackType_t)> msc_probe_stack{};
  static StaticTask_t msc_probe_task_control{};
  if (xTaskCreateStatic(MscMemoryProbeTask, "kf-msc-mem",
                        msc_probe_stack.size(), &msc_probe_context, 1,
                        msc_probe_stack.data(),
                        &msc_probe_task_control) == nullptr) {
    runtime.FailClosed(0);
    ESP_LOGE(kTag, "MSC memory probe task unavailable");
    return;
  }
#endif

  if constexpr (keyferry::board::capabilities.display) {
    static StatusTaskContext status_context{
        &runtime, transport_allowed, transport ? &*transport : nullptr,
        selection.generation, static_cast<std::int32_t>(nvs_result),
        display_orientation, screen_power};
    if (xTaskCreate(StatusTask, "kf-status", 4096, &status_context, 1,
                    nullptr) != pdPASS) {
      ESP_LOGW(kTag, "optional status display task unavailable");
    }
  }

  bool was_mounted = false;
#if defined(KEYFERRY_FILE_HANDOFF)
  bool file_refresh_waiting_for_attach = false;
  bool file_refresh_timed_out = false;
  std::uint32_t file_refresh_attach_generation = 0;
  std::uint64_t file_refresh_deadline_ms = 0;
#endif
  while (true) {
#if defined(KEYFERRY_FILE_HANDOFF)
    if (runtime.TakeFileMediaRefresh()) {
      // The response is already on TLS. Quiesce MSC on the target bus before
      // changing any published FAT sectors, then force a fresh host mount.
      tud_disconnect();
      g_usb_mounted.store(false, std::memory_order_release);
      runtime.FileMediaDetached();
      provisioning_adapter.TransportLost();
      vTaskDelay(pdMS_TO_TICKS(250));
      // tud_disconnect() does not synchronously clear TinyUSB's configured
      // state. Only a new ATTACHED event proves the host remounted this media.
      g_usb_mounted.store(false, std::memory_order_release);
      file_refresh_attach_generation =
          g_usb_attach_generation.load(std::memory_order_acquire);
      file_refresh_deadline_ms =
          keyferry::command::IdfHeldKeyWatchdog::NowMs() + 10000U;
      file_refresh_waiting_for_attach = true;
      file_refresh_timed_out = false;
      tud_connect();
      was_mounted = false;
    }
    if (file_refresh_waiting_for_attach) {
      const bool fresh_attach =
          g_usb_attach_generation.load(std::memory_order_acquire) !=
              file_refresh_attach_generation &&
          g_usb_mounted.load(std::memory_order_acquire) &&
          !g_usb_suspended.load(std::memory_order_acquire);
      if (fresh_attach) {
        file_refresh_waiting_for_attach = false;
      } else if (!file_refresh_timed_out &&
                 keyferry::command::IdfHeldKeyWatchdog::NowMs() >=
                     file_refresh_deadline_ms) {
        // A missing remount is a real USB fault. Wipe the snapshot once, then
        // ignore stale TinyUSB state until a fresh ATTACHED event arrives.
        runtime.SetUsbMounted(false);
        provisioning_adapter.TransportLost();
        file_refresh_timed_out = true;
      }
    }
#endif
#if defined(KEYFERRY_FILE_HANDOFF)
    const bool mounted = !file_refresh_waiting_for_attach &&
                         !g_usb_suspended.load(std::memory_order_acquire) &&
                         g_usb_mounted.load(std::memory_order_acquire);
#else
    const bool mounted =
        !g_usb_suspended.load(std::memory_order_acquire) &&
        (g_usb_mounted.load(std::memory_order_acquire) || tud_mounted());
#endif
    if (mounted != was_mounted) {
      runtime.SetUsbMounted(mounted);
      if (!mounted) {
        provisioning_adapter.TransportLost();
      }
      was_mounted = mounted;
    }
    runtime.Poll();
    runtime.ServiceUsb();
    if (mounted) {
      provisioning_adapter.Service();
    }
    if (runtime.RestartRequested()) {
      esp_restart();
    }
    // CONFIG_FREERTOS_HZ is 100, so pdMS_TO_TICKS(1) truncates to zero and
    // starves IDLE0 until the task watchdog resets the device.
    vTaskDelay(1);
  }
}
