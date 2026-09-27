#pragma once

#include <cstddef>
#include <cstdint>

namespace keyferry::ble_hid_spike {

// This code is retained only by KEYFERRY_BLE_HID_SPIKE=hid builds. It is a
// compile-and-measure probe, not production firmware and not safe to flash.
extern volatile bool g_compile_only_anchor;

int PrepareCompileOnlyService();
int SubmitCompileOnlyReport(std::uint16_t connection_handle,
                            std::uint16_t attribute_handle,
                            const std::uint8_t* report,
                            std::size_t report_size);

}  // namespace keyferry::ble_hid_spike
