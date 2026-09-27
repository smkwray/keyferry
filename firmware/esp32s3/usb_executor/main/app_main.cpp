#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <iterator>

#include "class/hid/hid_device.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "keyferry/hid_executor.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"

namespace {

using keyferry::hid::BootKeyboardReport;
using keyferry::hid::ExecutorState;

constexpr std::uint8_t kHidInterface = 0;
constexpr std::uint8_t kHidString = 4;
constexpr std::uint8_t kHidEndpoint = 0x81;
constexpr std::uint8_t kHidEndpointSize = 8;
constexpr std::uint8_t kHidPollIntervalMs = 10;
constexpr std::uint16_t kUsbPowerMilliamps = 100;
constexpr std::uint16_t kConfigurationLength = TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN;

static const std::uint8_t kHidReportDescriptor[] = {
    TUD_HID_REPORT_DESC_KEYBOARD(),
};

static const std::uint8_t kConfigurationDescriptor[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, kConfigurationLength, 0, kUsbPowerMilliamps),
    TUD_HID_DESCRIPTOR(kHidInterface, kHidString, HID_ITF_PROTOCOL_KEYBOARD,
                       sizeof(kHidReportDescriptor), kHidEndpoint, kHidEndpointSize,
                       kHidPollIntervalMs),
};

static char kEnglishLanguage[] = {0x09, 0x04};
static const char* kStringDescriptors[] = {
    kEnglishLanguage,
    "keyferry",
    "keyferry offline executor",
    "OFFLINE-NOAUTH",
    "Boot keyboard",
};

ExecutorState g_executor;
portMUX_TYPE g_executor_lock = portMUX_INITIALIZER_UNLOCKED;
std::atomic_bool g_usb_mounted{false};

void tinyusb_event_callback(tinyusb_event_t* event, void* argument) {
    (void)argument;
    if (event == nullptr) {
        return;
    }
    if (event->id == TINYUSB_EVENT_ATTACHED) {
        g_usb_mounted.store(true, std::memory_order_release);
    } else if (event->id == TINYUSB_EVENT_DETACHED) {
        g_usb_mounted.store(false, std::memory_order_release);
    }
}

BootKeyboardReport current_report() {
    portENTER_CRITICAL(&g_executor_lock);
    const auto report = g_executor.current_report();
    portEXIT_CRITICAL(&g_executor_lock);
    return report;
}

void set_transport_state(const bool mounted) {
    portENTER_CRITICAL(&g_executor_lock);
    if (mounted) {
        g_executor.on_transport_ready();
    } else {
        g_executor.on_transport_lost();
    }
    portEXIT_CRITICAL(&g_executor_lock);
}

bool take_pending_report(BootKeyboardReport& report) {
    portENTER_CRITICAL(&g_executor_lock);
    const bool pending = g_executor.report_needed();
    if (pending) {
        report = g_executor.desired_report();
    }
    portEXIT_CRITICAL(&g_executor_lock);
    return pending;
}

void acknowledge_report(const BootKeyboardReport& report) {
    portENTER_CRITICAL(&g_executor_lock);
    if (!g_executor.mark_report_accepted(report)) {
        g_executor.fault();
    }
    portEXIT_CRITICAL(&g_executor_lock);
}

}  // namespace

extern "C" std::uint8_t const* tud_hid_descriptor_report_cb(std::uint8_t instance) {
    (void)instance;
    return kHidReportDescriptor;
}

extern "C" std::uint16_t tud_hid_get_report_cb(std::uint8_t instance, std::uint8_t report_id,
                                                hid_report_type_t report_type, std::uint8_t* buffer,
                                                std::uint16_t requested_length) {
    (void)instance;
    (void)report_id;
    (void)report_type;
    const auto report = current_report();
    const auto bytes = std::min<std::uint16_t>(requested_length, sizeof(report));
    if (buffer == nullptr && bytes != 0) {
        return 0;
    }
    std::memcpy(buffer, &report, bytes);
    return bytes;
}

extern "C" void tud_hid_set_report_cb(std::uint8_t instance, std::uint8_t report_id,
                                       hid_report_type_t report_type, std::uint8_t const* buffer,
                                       std::uint16_t buffer_size) {
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)buffer_size;
}

extern "C" void app_main() {
    static constexpr char kTag[] = "keyferry_usb";
    ESP_LOGW(kTag, "offline executor: starts disarmed and has no command or network input");

    tinyusb_config_t usb_config = TINYUSB_DEFAULT_CONFIG();
    usb_config.descriptor.device = nullptr;
    usb_config.descriptor.full_speed_config = kConfigurationDescriptor;
    usb_config.descriptor.string = kStringDescriptors;
    usb_config.descriptor.string_count = std::size(kStringDescriptors);
    usb_config.event_cb = tinyusb_event_callback;
    usb_config.event_arg = nullptr;

    const auto install_result = tinyusb_driver_install(&usb_config);
    if (install_result != ESP_OK) {
        portENTER_CRITICAL(&g_executor_lock);
        g_executor.fault();
        portEXIT_CRITICAL(&g_executor_lock);
        ESP_LOGE(kTag, "TinyUSB install failed: %s", esp_err_to_name(install_result));
        while (true) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }

    bool was_mounted = false;
    while (true) {
        const bool mounted = g_usb_mounted.load(std::memory_order_acquire) || tud_mounted();
        if (mounted != was_mounted) {
            set_transport_state(mounted);
            was_mounted = mounted;
        }

        BootKeyboardReport report{};
        if (mounted && tud_hid_ready() && take_pending_report(report) &&
            tud_hid_report(0, &report, sizeof(report))) {
            acknowledge_report(report);
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}
