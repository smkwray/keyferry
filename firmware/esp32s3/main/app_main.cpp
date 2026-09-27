#ifndef KEYFERRY_QUALIFICATION_IMAGE
#error "This source is only for the qualification image"
#endif

#include <cinttypes>
#include <cstdio>

#include "board_profile.h"
#include "esp_chip_info.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

extern "C" void app_main() {
    esp_chip_info_t chip{};
    esp_chip_info(&chip);

    std::printf("keyferry qualification image\n");
    std::printf("board_profile=%s\n", keyferry::board::id);
    std::printf("chip_revision=%" PRIu16 " cores=%u\n", chip.revision, chip.cores);
    std::printf("reset_reason=%d\n", static_cast<int>(esp_reset_reason()));
    std::printf("radios=off input_interfaces=absent storage=off peripherals=off\n");

    std::uint32_t heartbeat = 0;
    while (true) {
        std::printf("heartbeat=%" PRIu32 "\n", heartbeat++);
        std::fflush(stdout);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
