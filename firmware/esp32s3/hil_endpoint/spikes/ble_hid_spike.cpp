#include "keyferry/ble_hid_spike.h"

#include "keyferry/ble_hid_release.h"

#include "sdkconfig.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>

extern "C" {
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_hs_mbuf.h"
#include "services/bas/ble_svc_bas.h"
#include "services/dis/ble_svc_dis.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "services/hid/ble_svc_hid.h"
}

namespace keyferry::ble_hid_spike {
namespace {

constexpr std::uint8_t kKeyboardReportId = 1;

// Standard eight-byte boot-keyboard input plus five LED output bits. Report
// mode uses ID 1; the service also exposes the dedicated boot characteristics.
constexpr std::array<std::uint8_t, 65> kKeyboardReportMap{{
    0x05, 0x01,  // Usage Page (Generic Desktop)
    0x09, 0x06,  // Usage (Keyboard)
    0xA1, 0x01,  // Collection (Application)
    0x85, 0x01,  // Report ID (1)
    0x05, 0x07,  // Usage Page (Keyboard/Keypad)
    0x19, 0xE0,  // Usage Minimum (Keyboard Left Control)
    0x29, 0xE7,  // Usage Maximum (Keyboard Right GUI)
    0x15, 0x00,  // Logical Minimum (0)
    0x25, 0x01,  // Logical Maximum (1)
    0x75, 0x01,  // Report Size (1)
    0x95, 0x08,  // Report Count (8)
    0x81, 0x02,  // Input (Data, Variable, Absolute)
    0x95, 0x01,  // Report Count (1)
    0x75, 0x08,  // Report Size (8)
    0x81, 0x01,  // Input (Constant)
    0x95, 0x06,  // Report Count (6)
    0x75, 0x08,  // Report Size (8)
    0x15, 0x00,  // Logical Minimum (0)
    0x25, 0x65,  // Logical Maximum (101)
    0x05, 0x07,  // Usage Page (Keyboard/Keypad)
    0x19, 0x00,  // Usage Minimum (Reserved)
    0x29, 0x65,  // Usage Maximum (Keyboard Application)
    0x81, 0x00,  // Input (Data, Array, Absolute)
    0x95, 0x05,  // Report Count (5)
    0x75, 0x01,  // Report Size (1)
    0x05, 0x08,  // Usage Page (LEDs)
    0x19, 0x01,  // Usage Minimum (Num Lock)
    0x29, 0x05,  // Usage Maximum (Kana)
    0x91, 0x02,  // Output (Data, Variable, Absolute)
    0x95, 0x01,  // Report Count (1)
    0x75, 0x03,  // Report Size (3)
    0x91, 0x01,  // Output (Constant)
    0xC0,        // End Collection
}};

constexpr std::array<char, 7> kPnpId{{
    0x02,        // USB Implementer's Forum vendor-ID source
    0x3A, 0x30,  // Espressif USB VID 0x303A, little-endian
    0x04, 0x40,  // Keyferry product ID 0x4004, little-endian
    0x01, 0x01,  // Product version 0x0101, little-endian
}};

void IgnoreOutputReport(std::uint16_t, std::uint8_t, std::uint8_t,
                        const std::uint8_t*, std::uint16_t) {}

}  // namespace

volatile bool g_compile_only_anchor = false;

int PrepareCompileOnlyService() {
  ble_hid::ReleaseBurst release_burst;
  if (!release_burst.Start(1, 24, 0) ||
      !release_burst.MarkZeroAccepted(1, 0)) {
    return BLE_HS_EINVAL;
  }

  ble_hs_cfg.sm_io_cap = BLE_HS_IO_DISPLAY_YESNO;
  ble_hs_cfg.sm_bonding = 1;
  ble_hs_cfg.sm_mitm = 1;
  ble_hs_cfg.sm_sc = 1;
  ble_hs_cfg.sm_sc_only = 1;
  ble_hs_cfg.sm_sec_lvl = CONFIG_BT_NIMBLE_SM_LVL;
  ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
  ble_hs_cfg.sm_their_key_dist =
      BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;

  ble_svc_gap_init();
  ble_svc_gatt_init();
  ble_svc_bas_init();
  ble_svc_dis_init();
  if (const int rc = ble_svc_dis_pnp_id_set(kPnpId.data()); rc != 0) {
    return rc;
  }

  ble_svc_hid_params params{};
  params.proto_mode_present = 1;
  params.kbd_inp_present = 1;
  params.kbd_out_present = 1;
  params.proto_mode = BLE_SVC_HID_PROTO_MODE_REPORT;
  params.rpts_len = 2;
  params.rpts[0].type = BLE_SVC_HID_RPT_TYPE_INPUT;
  params.rpts[0].id = kKeyboardReportId;
  params.rpts[0].len = KBD_INP_RPT_SIZE;
  params.rpts[1].type = BLE_SVC_HID_RPT_TYPE_OUTPUT;
  params.rpts[1].id = kKeyboardReportId;
  params.rpts[1].len = 1;
  params.report_map_len = kKeyboardReportMap.size();
  std::copy(kKeyboardReportMap.begin(), kKeyboardReportMap.end(),
            params.report_map);
  params.external_rpt_ref = BLE_SVC_BAS_CHR_UUID16_BATTERY_LEVEL;
  params.hid_info = 0x00000111;

  if (const int rc = ble_svc_hid_add(params); rc != 0) {
    return rc;
  }
  ble_svc_hid_register_report_write_cb(IgnoreOutputReport);
  ble_svc_hid_init();
  return ble_svc_bas_battery_level_set(0);
}

int SubmitCompileOnlyReport(const std::uint16_t connection_handle,
                            const std::uint16_t attribute_handle,
                            const std::uint8_t* const report,
                            const std::size_t report_size) {
  if (report == nullptr || report_size != KBD_INP_RPT_SIZE ||
      report_size > std::numeric_limits<std::uint16_t>::max()) {
    return BLE_HS_EINVAL;
  }
  os_mbuf* const packet =
      ble_hs_mbuf_from_flat(report, static_cast<std::uint16_t>(report_size));
  if (packet == nullptr) {
    return BLE_HS_ENOMEM;
  }
  // For notifications this return value proves only host-stack acceptance of
  // the transmission attempt. It is not report-correlated controller or
  // central receipt evidence.
  return ble_gatts_notify_custom(connection_handle, attribute_handle, packet);
}

}  // namespace keyferry::ble_hid_spike
