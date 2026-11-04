#pragma once

// Native substitutes for the platform pieces drive.cpp includes (BSP, ESP-IDF, FreeRTOS,
// sdmmc, TinyUSB). scripts/check.py writes a one-line forwarder to this file under each of
// those header names. Production drive.cpp and ESP-IDF's own FatFs compile unchanged against
// it; drive_test.cpp implements the declarations. Plain C as well: FatFs reaches sdkconfig.h,
// esp_err.h, esp_heap_caps.h and FreeRTOS through here.
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* sdkconfig.h: the handheld board build's FatFs and MSC settings. */
#define CONFIG_FATFS_VOLUME_COUNT 2
#define CONFIG_FATFS_LFN_HEAP 1
#define CONFIG_FATFS_CODEPAGE 437
#define CONFIG_FATFS_MAX_LFN 255
#define CONFIG_FATFS_API_ENCODING_ANSI_OEM 1
#define CONFIG_FATFS_USE_LABEL 0
#define CONFIG_FATFS_FS_LOCK 0
#define CONFIG_FATFS_TIMEOUT_MS 10000
#define CONFIG_FATFS_PER_FILE_CACHE 1
#define CONFIG_FATFS_ALLOC_PREFER_EXTRAM 1
#define CONFIG_FATFS_USE_FASTSEEK 1
#define CONFIG_FATFS_USE_STRFUNC_NONE 1
#define CONFIG_FATFS_USE_DYN_BUFFERS 1
#define CONFIG_FATFS_DONT_TRUST_FREE_CLUSTER_CNT 0
#define CONFIG_FATFS_DONT_TRUST_LAST_ALLOC 0
#define CONFIG_WL_SECTOR_SIZE 4096
#define CONFIG_TINYUSB_MSC_ENABLED 1

#if defined(_WIN32)
/* ff.h takes its integer types from <windows.h> on Windows; the forwarder standing in for it
   leaves these, the target's own widths, which also match diskio_impl.h. */
typedef unsigned int UINT;
typedef unsigned char BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef WORD WCHAR;
#endif

#if defined(__GNUC__) && !defined(__clang__)
/* Unoptimised host builds lack the range drive.cpp's "DRIVE%d.IMG" (n < 100) has on the target. */
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

#if defined(_MSC_VER)
/* MSVC-only warnings on drive.cpp that the target's GCC flags do not raise: implicit int to WORD
   narrowing (C4244) and CRT deprecation of strncpy (C4996). */
#pragma warning(disable : 4244 4996)
/* POSIX pieces newlib provides on the target (strings.h, sys/param.h, sys/time.h). */
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif
static __inline int strcasecmp(const char* a, const char* b) { return _stricmp(a, b); }
static __inline int strncasecmp(const char* a, const char* b, size_t n) { return _strnicmp(a, b, n); }
static __inline struct tm* localtime_r(const time_t* t, struct tm* out) {
  return localtime_s(out, t) == 0 ? out : NULL;
}
#endif

/* newlib's strlcpy; not every host C library has it. */
static inline size_t kf_test_strlcpy(char* dst, const char* src, size_t size) {
  const size_t length = strlen(src);
  if (size != 0) {
    const size_t n = length < size - 1 ? length : size - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
  }
  return length;
}
#undef strlcpy
#define strlcpy kf_test_strlcpy

/* esp_err.h */
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_SIZE 0x104
#define ESP_ERR_NOT_FOUND 0x105
const char* esp_err_to_name(esp_err_t code);

/* esp_log.h */
void kf_test_log(char level, const char* tag, const char* format, ...);
#define ESP_LOGE(tag, ...) kf_test_log('E', tag, __VA_ARGS__)
#define ESP_LOGW(tag, ...) kf_test_log('W', tag, __VA_ARGS__)
#define ESP_LOGI(tag, ...) kf_test_log('I', tag, __VA_ARGS__)

/* esp_timer.h */
int64_t esp_timer_get_time(void);

/* esp_heap_caps.h */
#define MALLOC_CAP_DMA (1u << 3)
#define MALLOC_CAP_SPIRAM (1u << 10)
#define MALLOC_CAP_INTERNAL (1u << 11)
#define MALLOC_CAP_DEFAULT (1u << 12)
void* heap_caps_malloc(size_t size, uint32_t caps);
void* heap_caps_calloc(size_t count, size_t size, uint32_t caps);
void* heap_caps_malloc_prefer(size_t size, size_t count, ...);
void heap_caps_free(void* block);

/* FreeRTOS: mutexes and critical sections (tasks are C++, below). */
typedef uint32_t TickType_t;
typedef int BaseType_t;
typedef unsigned UBaseType_t;
#define pdFALSE 0
#define pdTRUE 1
#define pdPASS 1
#define portMAX_DELAY ((TickType_t)0xFFFFFFFFu)
#define portTICK_PERIOD_MS 1
typedef struct KfTestSemaphore* SemaphoreHandle_t;
typedef struct { void* unused; } StaticSemaphore_t;
SemaphoreHandle_t xSemaphoreCreateMutex(void);
SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t* storage);
BaseType_t xSemaphoreTake(SemaphoreHandle_t semaphore, TickType_t ticks);
BaseType_t xSemaphoreGive(SemaphoreHandle_t semaphore);
void vSemaphoreDelete(SemaphoreHandle_t semaphore);
typedef struct { int unused; } portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED {0}
void kf_test_critical(int enter);
#define taskENTER_CRITICAL(mux) ((void)(mux), kf_test_critical(1))
#define taskEXIT_CRITICAL(mux) ((void)(mux), kf_test_critical(0))
typedef void* TaskHandle_t;

/* sd_protocol_types.h, sdmmc_cmd.h and the board BSP's card. */
typedef struct {
  int capacity;     /* sectors */
  int sector_size;  /* bytes */
} sdmmc_csd_t;
typedef struct {
  sdmmc_csd_t csd;
} sdmmc_card_t;
esp_err_t sdmmc_read_sectors(sdmmc_card_t* card, void* dst, size_t start_sector, size_t sector_count);
esp_err_t sdmmc_write_sectors(sdmmc_card_t* card, const void* src, size_t start_sector, size_t sector_count);
extern sdmmc_card_t* bsp_sdcard;
esp_err_t bsp_sdcard_mount(void);

/* tusb.h: TinyUSB 0.21 MSC device types and callbacks. */
typedef enum {
  SCSI_SENSE_NONE = 0x00,
  SCSI_SENSE_NOT_READY = 0x02,
  SCSI_SENSE_MEDIUM_ERROR = 0x03,
  SCSI_SENSE_ILLEGAL_REQUEST = 0x05,
} scsi_sense_key_type_t;
typedef struct {
  uint8_t peripheral_device_type : 5;
  uint8_t peripheral_qualifier : 3;
  uint8_t : 7;
  uint8_t is_removable : 1;
  uint8_t version;
  uint8_t response_data_format : 4;
  uint8_t hierarchical_support : 1;
  uint8_t normal_aca : 1;
  uint8_t : 2;
  uint8_t additional_length;
  uint8_t flags[3];
  uint8_t vendor_id[8];
  uint8_t product_id[16];
  uint8_t product_rev[4];
} scsi_inquiry_resp_t;
bool tud_msc_set_sense(uint8_t lun, uint8_t sense_key, uint8_t add_sense_code, uint8_t add_sense_qualifier);
int32_t tud_msc_read10_cb(uint8_t lun, uint32_t lba, uint32_t offset, void* buffer, uint32_t bufsize);
int32_t tud_msc_write10_cb(uint8_t lun, uint32_t lba, uint32_t offset, uint8_t* buffer, uint32_t bufsize);
uint32_t tud_msc_inquiry2_cb(uint8_t lun, scsi_inquiry_resp_t* inquiry_resp, uint32_t bufsize);
bool tud_msc_test_unit_ready_cb(uint8_t lun);
void tud_msc_capacity_cb(uint8_t lun, uint32_t* block_count, uint16_t* block_size);
int32_t tud_msc_scsi_cb(uint8_t lun, uint8_t const scsi_cmd[16], void* buffer, uint16_t bufsize);
uint8_t tud_msc_get_maxlun_cb(void);
bool tud_msc_start_stop_cb(uint8_t lun, uint8_t power_condition, bool start, bool load_eject);
bool tud_msc_prevent_allow_medium_removal_cb(uint8_t lun, uint8_t prohibit_removal, uint8_t control);
bool tud_msc_is_writable_cb(uint8_t lun);

#ifdef __cplusplus
}  // extern "C"

static_assert(sizeof(scsi_inquiry_resp_t) == 36, "TinyUSB's inquiry response is 36 bytes");

// FreeRTOS tasks run on host threads. vTaskDelete(nullptr) never returns: it ends the thread.
typedef void (*TaskFunction_t)(void*);
BaseType_t xTaskCreate(TaskFunction_t task, const char* name, uint32_t stack, void* argument,
                       UBaseType_t priority, TaskHandle_t* created);
void vTaskDelete(TaskHandle_t task);
#endif
