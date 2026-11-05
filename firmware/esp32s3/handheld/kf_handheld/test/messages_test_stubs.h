#pragma once

// Native substitutes for the platform headers messages.cpp includes (ESP-IDF, FreeRTOS,
// esp_tinyusb CDC-ACM, TinyUSB). scripts/check.py writes a one-line forwarder to this file under
// each of those header names; production messages.cpp compiles unchanged against it and
// messages_test.cpp implements the declarations as a simulated USB serial port.
#include <cstddef>
#include <cstdint>

typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL (-1)

#define MALLOC_CAP_8BIT (1u << 2)
#define MALLOC_CAP_SPIRAM (1u << 10)
void* heap_caps_calloc(std::size_t count, std::size_t size, std::uint32_t caps);

#define ESP_LOGI(tag, ...) ((void)(tag))
#define ESP_LOGE(tag, ...) ((void)(tag))
std::int64_t esp_timer_get_time();

typedef struct TestSemaphore* SemaphoreHandle_t;
typedef std::uint32_t TickType_t;
#define portMAX_DELAY 0xFFFFFFFFu
SemaphoreHandle_t xSemaphoreCreateMutex();
int xSemaphoreTake(SemaphoreHandle_t semaphore, TickType_t ticks);
int xSemaphoreGive(SemaphoreHandle_t semaphore);

// TinyUSB: queue work for the TinyUSB task.
void usbd_defer_func(void (*func)(void*), void* param, bool in_isr);
// TinyUSB CDC: bytes free in the TX FIFO, and dropping its unsent bytes.
std::uint32_t tud_cdc_n_write_available(std::uint8_t itf);
bool tud_cdc_n_write_clear(std::uint8_t itf);

// esp_tinyusb CDC-ACM (the fields messages.cpp uses, with the vendored names and types).
typedef enum { TINYUSB_CDC_ACM_0 = 0 } tinyusb_cdcacm_itf_t;
typedef struct {
  bool dtr;
  bool rts;
} cdcacm_event_line_state_changed_data_t;
typedef struct {
  int type;
  cdcacm_event_line_state_changed_data_t line_state_changed_data;
} cdcacm_event_t;
typedef void (*tusb_cdcacm_callback_t)(int itf, cdcacm_event_t* event);
typedef struct {
  tinyusb_cdcacm_itf_t cdc_port;
  tusb_cdcacm_callback_t callback_rx;
  tusb_cdcacm_callback_t callback_rx_wanted_char;
  tusb_cdcacm_callback_t callback_line_state_changed;
  tusb_cdcacm_callback_t callback_line_coding_changed;
} tinyusb_config_cdcacm_t;
esp_err_t tinyusb_cdcacm_init(const tinyusb_config_cdcacm_t* config);
std::size_t tinyusb_cdcacm_write_queue(tinyusb_cdcacm_itf_t itf, const std::uint8_t* data, std::size_t size);
esp_err_t tinyusb_cdcacm_write_flush(tinyusb_cdcacm_itf_t itf, std::uint32_t timeout_ticks);
esp_err_t tinyusb_cdcacm_read(tinyusb_cdcacm_itf_t itf, std::uint8_t* out, std::size_t size, std::size_t* received);
