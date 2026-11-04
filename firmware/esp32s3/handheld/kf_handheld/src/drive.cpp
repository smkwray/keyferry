// USB Drive (ADR 0018 rule 4): one fixed-size image file from DRIVES/ on the SD card, exported
// as a removable USB disk with 512-byte sectors. The computer reaches only the bytes of that one
// file: never the card's own file system, other images or spare space. Read-only unless chosen
// writable; each write is on the card (written, read back, synced) before it is acknowledged.
#include "drive.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <strings.h>

#include "bsp/esp-bsp.h"
#include "diskio_impl.h"
#include "diskio_sdmmc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "ff.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdmmc_cmd.h"
#include "tusb.h"
#include "usb_device.h"

#if !CONFIG_TINYUSB_MSC_ENABLED
#error "USB Drive needs CONFIG_TINYUSB_MSC_ENABLED (board sdkconfig.defaults)"
#endif
#if defined(CONFIG_BSP_SD_FORMAT_ON_MOUNT_FAIL)
#error "The SD card itself must never be formatted automatically (ADR 0018 rule 4)"
#endif
#if !FF_USE_FASTSEEK
#error "USB Drive needs CONFIG_FATFS_USE_FASTSEEK for constant-time seeks inside images"
#endif

namespace keyferry::handheld {
namespace {

constexpr char kTag[] = "drive";
constexpr char kDir[] = "DRIVES";
constexpr std::uint32_t kSector = 512;
constexpr std::uint64_t kMinImage = 1ULL << 20;
constexpr std::uint64_t kMaxImage = 0xFFFFFE00ULL;  // the largest sector-aligned FAT32 file
constexpr std::int64_t kBusyUs = 1000000;
constexpr std::size_t kFillChunk = 32 * 1024;
constexpr std::size_t kVerifyChunk = 4096;

// g_lock guards the card volume work this module starts and the exported image; card I/O runs
// under it. The list has its own short lock so the screen never waits on the card.
SemaphoreHandle_t g_lock = nullptr;
StaticSemaphore_t g_lock_storage;
portMUX_TYPE g_list_mux = portMUX_INITIALIZER_UNLOCKED;
portMUX_TYPE g_message_mux = portMUX_INITIALIZER_UNLOCKED;
char g_root[8] = "0:";  // FatFs drive prefix of the card

std::atomic<bool> g_closed{false};    // DriveClose(): no new card work this boot
std::atomic<bool> g_scanning{false};
std::atomic<CardState> g_card{CardState::kChecking};
DriveInfo g_drives[kMaxDrives];  // under g_list_mux
int g_count = 0;                 // under g_list_mux
std::atomic<std::uint32_t> g_serial{0};
std::atomic<std::uint64_t> g_free{0};

FIL g_image;
bool g_open = false;
std::atomic<bool> g_writable{false};
std::atomic<std::uint64_t> g_bytes{0};
bool g_prevent_removal = false;  // TinyUSB task only; held for the USB session that set it
std::uint32_t g_prevent_session = 0;
char g_marker[64] = {};
DWORD g_linkmap[64];  // fast-seek cluster map: up to 31 fragments
std::atomic<ExportState> g_export{ExportState::kNone};
std::atomic<bool> g_marker_kept{false};
std::atomic<std::uint64_t> g_read{0};
std::atomic<std::uint64_t> g_written{0};
std::atomic<std::int64_t> g_last_io{0};

std::atomic<bool> g_creating{false};
std::atomic<bool> g_cancel{false};
std::atomic<int> g_percent{0};
std::atomic<int> g_create_result{0};
std::atomic<std::uint32_t> g_create_finished{0};
char g_create_message[48] = {};  // under g_message_mux

void Lock() { xSemaphoreTake(g_lock, portMAX_DELAY); }
void Unlock() { xSemaphoreGive(g_lock); }

// First called by DriveScan(), which the shell runs before any other drive call.
void EnsureLock() {
  if (g_lock == nullptr) g_lock = xSemaphoreCreateMutexStatic(&g_lock_storage);
}

bool Cancelled() { return g_cancel.load() || g_closed.load(); }

void Path(char* out, std::size_t size, const char* name) {
  std::snprintf(out, size, "%s/%s/%s", g_root, kDir, name);
}

// DRIVE1.IMG -> DRIVE1.DRT: the outstanding-writable-session marker next to its image.
void MarkerPath(char* out, std::size_t size, const char* name) {
  char base[32];
  std::snprintf(base, sizeof(base), "%s", name);
  char* dot = std::strrchr(base, '.');
  if (dot != nullptr) *dot = '\0';
  char marker[40];
  std::snprintf(marker, sizeof(marker), "%s.DRT", base);
  Path(out, size, marker);
}

bool IsImageName(const char* name) {
  const std::size_t length = std::strlen(name);
  return length > 4 && length < sizeof(DriveInfo::name) && strcasecmp(name + length - 4, ".IMG") == 0;
}

// Exactly DRIVE1.TMP .. DRIVE99.TMP: the names CreateImage() builds under, and nothing else.
bool IsOwnTemp(const char* name) {
  const std::size_t length = std::strlen(name);
  if ((length != 10 && length != 11) || strncasecmp(name, "DRIVE", 5) != 0 ||
      strcasecmp(name + length - 4, ".TMP") != 0) {
    return false;
  }
  const std::size_t digits = length - 9;
  for (std::size_t i = 0; i < digits; ++i) {
    if (!std::isdigit(static_cast<unsigned char>(name[5 + i]))) return false;
  }
  return name[5] != '0';
}

// --- The card's disk driver, with every multi-block write read back --------------------------------
// ESP-IDF v6.0.3's sdmmc_write_sectors() can return ESP_OK after a failed multi-block write: its
// error is replaced by the result of the follow-up written-blocks query (sdmmc_cmd.c). USB Drive
// acknowledges a write only once it is on the card, so every multi-block write is read back and
// compared; single-block writes report their own errors. FatFs serialises all calls for the card
// volume under its volume lock, so one verify buffer serves them.

sdmmc_card_t* g_sd = nullptr;
std::uint8_t* g_verify = nullptr;
// Latched by any failed card read or write. FatFs ignores some write results (the second FAT copy,
// FSInfo), so the fault is kept here and reported through CTRL_SYNC, serving and admission.
std::atomic<bool> g_card_fault{false};

DRESULT Fault() {
  g_card_fault.store(true);
  return RES_ERROR;
}

DSTATUS CardInit(unsigned char) { return 0; }
DSTATUS CardStatus(unsigned char) { return 0; }

DRESULT CardRead(unsigned char, unsigned char* buffer, uint32_t sector, unsigned count) {
  return sdmmc_read_sectors(g_sd, buffer, sector, count) == ESP_OK ? RES_OK : Fault();
}

DRESULT CardWrite(unsigned char, const unsigned char* buffer, uint32_t sector, unsigned count) {
  if (sdmmc_write_sectors(g_sd, buffer, sector, count) != ESP_OK) return Fault();
  if (count == 1) return RES_OK;
  constexpr unsigned kPerRead = kVerifyChunk / kSector;
  for (unsigned done = 0; done < count;) {
    const unsigned now = std::min(kPerRead, count - done);
    if (sdmmc_read_sectors(g_sd, g_verify, sector + done, now) != ESP_OK ||
        std::memcmp(g_verify, buffer + static_cast<std::size_t>(done) * kSector, now * kSector) != 0) {
      ESP_LOGE(kTag, "card write of %u blocks at %u did not read back", count, static_cast<unsigned>(sector));
      return Fault();
    }
    done += now;
  }
  return RES_OK;
}

DRESULT CardIoctl(unsigned char, unsigned char command, void* buffer) {
  switch (command) {
    case CTRL_SYNC: return g_card_fault.load() ? RES_ERROR : RES_OK;  // no write cache to flush
    case GET_SECTOR_COUNT: *static_cast<DWORD*>(buffer) = g_sd->csd.capacity; return RES_OK;
    case GET_SECTOR_SIZE: *static_cast<WORD*>(buffer) = g_sd->csd.sector_size; return RES_OK;
    default: return RES_PARERR;  // no TRIM: nothing on the card is discarded
  }
}

const ff_diskio_impl_t kCardDisk = {CardInit, CardStatus, CardRead, CardWrite, CardIoctl};

// Called once, right after mounting and before any other card work.
bool UseVerifyingDriver(BYTE pdrv) {
  g_verify = static_cast<std::uint8_t*>(heap_caps_malloc(kVerifyChunk, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL));
  if (g_verify == nullptr || bsp_sdcard == nullptr || bsp_sdcard->csd.sector_size != kSector) return false;
  g_sd = bsp_sdcard;
  ff_diskio_register(pdrv, &kCardDisk);
  return true;
}

// --- Listing -------------------------------------------------------------------------------------

void Publish(const DriveInfo* drives, int count, CardState state) {
  taskENTER_CRITICAL(&g_list_mux);
  std::copy(drives, drives + count, g_drives);
  g_count = count;
  taskEXIT_CRITICAL(&g_list_mux);
  g_card.store(state);
  g_serial.fetch_add(1);
}

// Lists DRIVES/ (creating it if missing) and removes this module's unfinished temporaries.
// Caller holds g_lock. Errors make the card state kError rather than an empty list.
void ScanLocked() {
  char path[48];
  std::snprintf(path, sizeof(path), "%s/%s", g_root, kDir);
  FRESULT result = f_mkdir(path);
  if (result != FR_OK && result != FR_EXIST) ESP_LOGW(kTag, "cannot create %s: %d", kDir, result);
  DriveInfo found[kMaxDrives];
  int count = 0;
  FF_DIR dir;
  FILINFO info;
  result = f_opendir(&dir, path);
  if (result == FR_NO_PATH) {
    Publish(found, 0, CardState::kReady);  // a read-only card without DRIVES/: nothing to list
    return;
  }
  const bool opened = result == FR_OK;
  bool ok = opened;
  while (ok) {
    result = f_readdir(&dir, &info);
    if (result != FR_OK) {
      ok = false;
      break;
    }
    if (info.fname[0] == '\0') break;
    const bool regular = (info.fattrib & AM_DIR) == 0;
    if (regular && IsOwnTemp(info.fname)) {
      // An image creation that never finished (power lost, card pulled): never a drive.
      char leftover[64];
      Path(leftover, sizeof(leftover), info.fname);
      const FRESULT removed = f_unlink(leftover);
      if (removed != FR_OK) ESP_LOGW(kTag, "cannot remove %s: %d", info.fname, removed);
      continue;
    }
    if (!regular || !IsImageName(info.fname) || count >= kMaxDrives) continue;
    const std::uint64_t bytes = info.fsize;
    if (bytes < kMinImage || bytes > kMaxImage || bytes % kSector != 0) continue;
    DriveInfo& drive = found[count++];
    strlcpy(drive.name, info.fname, sizeof(drive.name));  // IsImageName() bounded its length
    drive.bytes = bytes;
    char marker[64];
    MarkerPath(marker, sizeof(marker), drive.name);
    FILINFO marker_info;
    const FRESULT marked = f_stat(marker, &marker_info);
    if (marked != FR_OK && marked != FR_NO_FILE) {
      result = marked;  // the marker could not be read: a card error, not a listing
      ok = false;
      break;
    }
    drive.dirty = marked == FR_OK;
  }
  if (opened) f_closedir(&dir);
  if (!ok) {
    ESP_LOGE(kTag, "cannot list %s: %d", kDir, result);
    Publish(found, 0, CardState::kError);
    return;
  }
  // By name (insertion sort: at most kMaxDrives entries).
  for (int i = 1; i < count; ++i) {
    const DriveInfo entry = found[i];
    int j = i;
    for (; j > 0 && strcasecmp(found[j - 1].name, entry.name) > 0; --j) found[j] = found[j - 1];
    found[j] = entry;
  }
  DWORD free_clusters = 0;
  FATFS* fs = nullptr;
  if (f_getfree(g_root, &free_clusters, &fs) == FR_OK && fs != nullptr) {
    g_free.store(static_cast<std::uint64_t>(free_clusters) * fs->csize * kSector);
  } else {
    g_free.store(0);  // unknown: creation refuses
    ESP_LOGW(kTag, "free space unknown");
  }
  Publish(found, count, g_card_fault.load() ? CardState::kError : CardState::kReady);
}

void ScanTask(void*) {
  if (bsp_sdcard == nullptr) {
    const esp_err_t result = bsp_sdcard_mount();  // format-on-failure stays off
    if (result == ESP_OK) {
      const BYTE pdrv = ff_diskio_get_pdrv_card(bsp_sdcard);
      std::snprintf(g_root, sizeof(g_root), "%u:", pdrv);
      if (!UseVerifyingDriver(pdrv)) ESP_LOGE(kTag, "verifying card driver unavailable: card not used");
    } else {
      ESP_LOGW(kTag, "SD card not mounted: %s", esp_err_to_name(result));
      // ESP_FAIL: a card answered but holds no readable FAT volume.
      Publish(nullptr, 0, result == ESP_FAIL ? CardState::kError : CardState::kNoCard);
      g_scanning.store(false);
      vTaskDelete(nullptr);
    }
  }
  if (g_sd == nullptr) {
    Publish(nullptr, 0, CardState::kError);  // mounted, but never without the verifying driver
  } else {
    Lock();
    if (!g_closed.load()) ScanLocked();
    Unlock();
    ESP_LOGI(kTag, "card scanned: %d MiB free", static_cast<int>(g_free.load() >> 20));
  }
  g_scanning.store(false);
  vTaskDelete(nullptr);
}

// --- Serving -------------------------------------------------------------------------------------

// A card error while serving: stop serving that image for good. Caller holds g_lock.
void FailLocked(const char* what, FRESULT result) {
  ESP_LOGE(kTag, "%s failed (%d): image no longer served", what, result);
  if (g_open) f_close(&g_image);
  g_open = false;
  g_export.store(ExportState::kFailed);
}

// TinyUSB derives each READ(10)/WRITE(10) block size from the CBW (bytes / blocks, truncated) and
// keeps the CBW to itself, so a host whose byte count disagrees with its block count cannot be
// caught here in general (ADR 0018 rule 4 records this). Every chunk must still be whole sectors
// at offset 0, and every byte stays inside the selected image either way.
int32_t Transfer(std::uint32_t lba, std::uint32_t offset, void* buffer, std::uint32_t size, bool write) {
  if (offset != 0 || size == 0 || size % kSector != 0) {
    tud_msc_set_sense(0, SCSI_SENSE_ILLEGAL_REQUEST, 0x24, 0x00);  // invalid field in CDB
    return -1;
  }
  const std::uint64_t at = static_cast<std::uint64_t>(lba) * kSector;
  Lock();
  const std::uint64_t bytes = g_bytes.load();
  if (g_card_fault.load() && g_open) FailLocked("card", FR_DISK_ERR);
  if (!g_open || g_export.load() != ExportState::kServing || (write && !g_writable.load()) ||
      at > bytes || size > bytes - at) {
    Unlock();
    return -1;  // TinyUSB fails the command
  }
  UINT moved = 0;
  FRESULT result = f_lseek(&g_image, static_cast<FSIZE_t>(at));
  if (result == FR_OK) {
    result = write ? f_write(&g_image, buffer, size, &moved) : f_read(&g_image, buffer, size, &moved);
  }
  if (result == FR_OK && write) result = f_sync(&g_image);  // on the card before acknowledged
  if (result != FR_OK || moved != size || g_card_fault.load()) {
    FailLocked(write ? "write" : "read", result != FR_OK ? result : FR_DISK_ERR);
    Unlock();
    return -1;
  }
  Unlock();
  (write ? g_written : g_read).fetch_add(size);
  g_last_io.store(esp_timer_get_time());
  return static_cast<int32_t>(size);
}

// The computer ejected the disk. True only when the image is synced and closed; the marker is
// removed only then. A failed sync or close is a failed eject: the drive stops being served, and
// every later eject request fails too. Repeating a clean eject succeeds.
bool Eject() {
  Lock();
  const ExportState state = g_export.load();
  if (state != ExportState::kServing) {
    Unlock();
    return state == ExportState::kEjected;
  }
  bool clean = !g_card_fault.load();
  if (g_open) {
    const FRESULT synced = f_sync(&g_image);
    const FRESULT closed = f_close(&g_image);
    g_open = false;
    clean = clean && synced == FR_OK && closed == FR_OK && !g_card_fault.load();
    if (clean && g_writable.load()) {
      const FRESULT cleared = f_unlink(g_marker);
      if (cleared != FR_OK) {
        g_marker_kept.store(true);
        ESP_LOGW(kTag, "ejected, but the marker could not be removed (%d)", cleared);
      }
    }
    if (!clean) ESP_LOGE(kTag, "eject: sync %d, close %d", synced, closed);
  }
  g_export.store(clean ? ExportState::kEjected : ExportState::kFailed);
  Unlock();
  ESP_LOGI(kTag, "eject from the computer: %s", clean ? "clean" : "failed");
  return clean;
}

// --- Creating images -------------------------------------------------------------------------------

FIL* g_inner_file = nullptr;  // the image being formatted, as a disk for FatFs
LBA_t g_inner_sectors = 0;

DSTATUS InnerInit(unsigned char) { return 0; }
DSTATUS InnerStatus(unsigned char) { return 0; }

DRESULT InnerRead(unsigned char, unsigned char* buffer, uint32_t sector, unsigned count) {
  UINT moved = 0;
  const UINT size = count * kSector;
  return f_lseek(g_inner_file, static_cast<FSIZE_t>(sector) * kSector) == FR_OK &&
                 f_read(g_inner_file, buffer, size, &moved) == FR_OK && moved == size
             ? RES_OK
             : RES_ERROR;
}

DRESULT InnerWrite(unsigned char, const unsigned char* buffer, uint32_t sector, unsigned count) {
  UINT moved = 0;
  const UINT size = count * kSector;
  return f_lseek(g_inner_file, static_cast<FSIZE_t>(sector) * kSector) == FR_OK &&
                 f_write(g_inner_file, buffer, size, &moved) == FR_OK && moved == size
             ? RES_OK
             : RES_ERROR;
}

DRESULT InnerIoctl(unsigned char, unsigned char command, void* buffer) {
  switch (command) {
    case CTRL_SYNC: return f_sync(g_inner_file) == FR_OK ? RES_OK : RES_ERROR;
    case GET_SECTOR_COUNT: *static_cast<LBA_t*>(buffer) = g_inner_sectors; return RES_OK;
    case GET_SECTOR_SIZE: *static_cast<WORD*>(buffer) = kSector; return RES_OK;
    case GET_BLOCK_SIZE: *static_cast<DWORD*>(buffer) = 1; return RES_OK;
    default: return RES_PARERR;
  }
}

const ff_diskio_impl_t kInnerDisk = {InnerInit, InnerStatus, InnerRead, InnerWrite, InnerIoctl};

void Progress(int percent, const char* message) {
  g_percent.store(percent);
  taskENTER_CRITICAL(&g_message_mux);
  std::strncpy(g_create_message, message, sizeof(g_create_message) - 1);
  g_create_message[sizeof(g_create_message) - 1] = '\0';
  taskEXIT_CRITICAL(&g_message_mux);
}

// Formats the open, zero-filled image as one FAT32 partition (MBR) and checks the result by
// mounting it. The card's own volume is only ever reached through the image file.
bool FormatImage(FIL* file, std::uint64_t bytes, void* work, std::size_t work_size) {
  BYTE pdrv = 0xFF;
  if (ff_diskio_get_drive(&pdrv) != ESP_OK) return false;
  g_inner_file = file;
  g_inner_sectors = static_cast<LBA_t>(bytes / kSector);
  ff_diskio_register(pdrv, &kInnerDisk);
  char drive[8];
  std::snprintf(drive, sizeof(drive), "%u:", pdrv);
  // About 131k clusters for 64 and 256 MiB, 262k for 1 GiB: inside FAT32's range.
  const DWORD cluster = static_cast<DWORD>(std::clamp<std::uint64_t>(bytes / 131072, 512, 4096));
  const MKFS_PARM options = {FM_FAT32, 2, 0, 0, cluster};
  FRESULT result = f_mkfs(drive, &options, work, static_cast<UINT>(work_size));
  bool ok = result == FR_OK;
  if (ok) {
    Progress(97, "Checking...");
    FATFS* inner = static_cast<FATFS*>(heap_caps_calloc(1, sizeof(FATFS), MALLOC_CAP_DEFAULT));
    DWORD free_clusters = 0;
    FATFS* mounted = nullptr;
    ok = inner != nullptr && f_mount(inner, drive, 1) == FR_OK &&
         f_getfree(drive, &free_clusters, &mounted) == FR_OK && mounted != nullptr &&
         mounted->fs_type == FS_FAT32 && free_clusters + 1 >= mounted->n_fatent - 2;
    f_mount(nullptr, drive, 0);
    heap_caps_free(inner);
  }
  ff_diskio_unregister(pdrv);
  g_inner_file = nullptr;
  if (!ok) ESP_LOGE(kTag, "format failed (%d)", result);
  return ok;
}

// Builds DRIVEn.TMP and renames it to DRIVEn.IMG only when it is complete and checked; any
// failure or cancellation removes the temporary.
bool CreateImage(std::uint64_t bytes) {
  if (g_free.load() < bytes + (1ULL << 20)) {
    Progress(0, g_free.load() == 0 ? "Card free space unknown" : "Not enough space on the card");
    return false;
  }
  char final_path[64] = {};
  char temp_path[64] = {};
  char name[16] = {};
  FIL file;
  bool opened = false;
  for (int n = 1; n < 100 && !opened && !Cancelled(); ++n) {
    std::snprintf(name, sizeof(name), "DRIVE%d.IMG", n);
    Path(final_path, sizeof(final_path), name);
    FILINFO info;
    if (f_stat(final_path, &info) != FR_NO_FILE) continue;
    char temp[16];
    std::snprintf(temp, sizeof(temp), "DRIVE%d.TMP", n);
    Path(temp_path, sizeof(temp_path), temp);
    opened = f_open(&file, temp_path, FA_CREATE_NEW | FA_WRITE | FA_READ) == FR_OK;
  }
  if (!opened) {
    Progress(0, Cancelled() ? "Cancelled" : "Cannot create a file on the card");
    return false;
  }
  void* buffer = heap_caps_calloc(1, kFillChunk, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
  bool ok = buffer != nullptr;
  if (ok) {
    const FRESULT expanded = f_expand(&file, static_cast<FSIZE_t>(bytes), 1);
    if (expanded == FR_DENIED) {
      ESP_LOGI(kTag, "no contiguous space: the image will be fragmented");
    } else if (expanded != FR_OK) {
      ESP_LOGE(kTag, "allocating the image failed (%d)", expanded);
      ok = false;
    }
  }
  // Zero the whole image so nothing left on the card shows through it.
  std::uint64_t written = 0;
  ok = ok && f_lseek(&file, 0) == FR_OK;
  while (ok && written < bytes && !Cancelled()) {
    const UINT size = static_cast<UINT>(std::min<std::uint64_t>(kFillChunk, bytes - written));
    UINT moved = 0;
    ok = f_write(&file, buffer, size, &moved) == FR_OK && moved == size;
    written += size;
    const int percent = static_cast<int>(written * 90 / bytes);
    if (percent != g_percent.load()) Progress(percent, "Preparing...");
  }
  ok = ok && !Cancelled() && f_sync(&file) == FR_OK;
  if (ok) {
    Progress(92, "Formatting...");
    ok = FormatImage(&file, bytes, buffer, kFillChunk);
    if (!ok) Progress(0, "Formatting failed");
  } else if (!Cancelled()) {
    Progress(0, "Card write failed");
  }
  heap_caps_free(buffer);
  ok = f_close(&file) == FR_OK && ok;
  ok = ok && !Cancelled();  // a cancel during formatting still discards the result
  ok = ok && f_rename(temp_path, final_path) == FR_OK;
  if (!ok) {
    if (Cancelled()) Progress(0, "Cancelled");
    const FRESULT removed = f_unlink(temp_path);
    if (removed != FR_OK) ESP_LOGW(kTag, "cannot remove the unfinished image (%d)", removed);
    return false;
  }
  char done[48];
  std::snprintf(done, sizeof(done), "Created %s", name);
  Progress(100, done);
  ESP_LOGI(kTag, "created %s (%u MiB)", name, static_cast<unsigned>(bytes >> 20));
  return true;
}

void CreateTask(void* argument) {
  const auto mib = static_cast<std::uint64_t>(reinterpret_cast<std::intptr_t>(argument));
  Lock();
  const bool created = CreateImage(mib << 20);
  if (!g_closed.load()) ScanLocked();
  Unlock();
  g_create_result.store(created ? 1 : -1);
  g_create_finished.fetch_add(1);
  g_creating.store(false);
  vTaskDelete(nullptr);
}

}  // namespace

void DriveScan() {
  EnsureLock();
  // Admission: set scanning, then check closing; DriveClose() sets closing, then waits for it.
  if (g_scanning.exchange(true)) return;
  if (g_closed.load()) {
    g_scanning.store(false);
    return;
  }
  g_card.store(CardState::kChecking);
  g_serial.fetch_add(1);
  if (xTaskCreate(ScanTask, "kf_drive_scan", 6144, nullptr, 3, nullptr) != pdPASS) {
    Publish(nullptr, 0, CardState::kError);
    g_scanning.store(false);
  }
}

CardState DriveCard() { return g_card.load(); }
std::uint32_t DriveListSerial() { return g_serial.load(); }

int DriveList(DriveInfo* out, int max, std::uint32_t* serial) {
  *serial = g_serial.load();
  taskENTER_CRITICAL(&g_list_mux);
  const int count = std::min(max, g_count);
  std::copy(g_drives, g_drives + count, out);
  taskEXIT_CRITICAL(&g_list_mux);
  return count;
}

std::uint64_t DriveFreeBytes() { return g_free.load(); }

bool DriveExport(int index, bool writable) {
  EnsureLock();
  if (g_creating.load() || g_card.load() != CardState::kReady) return false;
  DriveInfo drive{};
  taskENTER_CRITICAL(&g_list_mux);
  const bool listed = index >= 0 && index < g_count;
  if (listed) drive = g_drives[index];
  taskEXIT_CRITICAL(&g_list_mux);
  if (!listed) return false;
  Lock();
  if (g_closed.load() || g_card_fault.load() || g_export.load() != ExportState::kNone) {
    Unlock();
    return false;
  }
  char path[64];
  Path(path, sizeof(path), drive.name);
  FRESULT result = f_open(&g_image, path, writable ? FA_READ | FA_WRITE : FA_READ);
  if (result != FR_OK || f_size(&g_image) != drive.bytes) {
    if (result == FR_OK) f_close(&g_image);
    Unlock();
    ESP_LOGE(kTag, "cannot open %s (%d)", drive.name, result);
    return false;
  }
  g_linkmap[0] = static_cast<DWORD>(std::size(g_linkmap));
  g_image.cltbl = g_linkmap;
  result = f_lseek(&g_image, CREATE_LINKMAP);
  if (result == FR_NOT_ENOUGH_CORE) {
    g_image.cltbl = nullptr;  // too fragmented for the map: correct, only slower seeks
    ESP_LOGW(kTag, "%s is fragmented: seeks walk the cluster chain", drive.name);
  } else if (result != FR_OK) {
    f_close(&g_image);
    Unlock();
    ESP_LOGE(kTag, "cannot map %s (%d)", drive.name, result);
    return false;
  }
  MarkerPath(g_marker, sizeof(g_marker), drive.name);
  if (writable) {
    // Recorded before the computer can write; fail closed unless it is fully on the card.
    FIL marker;
    UINT moved = 0;
    const bool opened = f_open(&marker, g_marker, FA_CREATE_ALWAYS | FA_WRITE) == FR_OK;
    const bool wrote = opened && f_write(&marker, "1", 1, &moved) == FR_OK && moved == 1;
    const bool closed = opened && f_close(&marker) == FR_OK;
    if (!(wrote && closed)) {
      f_close(&g_image);
      Unlock();
      ESP_LOGE(kTag, "cannot record the writable session for %s", drive.name);
      return false;
    }
  }
  g_open = true;
  g_writable.store(writable);
  g_bytes.store(drive.bytes);
  g_export.store(ExportState::kServing);
  Unlock();
  ESP_LOGI(kTag, "exporting %s (%u MiB, %s)", drive.name, static_cast<unsigned>(drive.bytes >> 20),
           writable ? "writable" : "read-only");
  if (!UsbDeviceStart(UsbPersonality::kDrive)) {
    DriveClose();
    return false;
  }
  return true;
}

ExportStatus DriveExportStatus() {
  ExportStatus status;
  status.state = g_export.load();
  status.writable = g_writable.load();
  status.connected = status.state != ExportState::kNone && UsbDeviceMounted();
  const std::int64_t last = g_last_io.load();
  status.busy = last != 0 && esp_timer_get_time() - last < kBusyUs;
  status.marker_kept = g_marker_kept.load();
  status.read_bytes = g_read.load();
  status.written_bytes = g_written.load();
  return status;
}

void DriveClose() {
  g_closed.store(true);  // before anything else: no new scan, creation or export from here on
  g_cancel.store(true);
  if (g_lock == nullptr) return;
  Lock();  // waits out a transfer, scan or creation step in progress
  if (g_open) {
    f_sync(&g_image);
    f_close(&g_image);  // a writable session's marker stays: the computer never ejected it
    g_open = false;
  }
  if (g_export.load() == ExportState::kServing) g_export.store(ExportState::kStopped);
  Unlock();
}

bool DriveIdle() { return !g_scanning.load() && !g_creating.load(); }

bool DriveCreate(int mib) {
  if (g_card.load() != CardState::kReady || g_export.load() != ExportState::kNone) return false;
  // Admission: set creating, then check closing; DriveClose() sets closing, then waits for it.
  if (g_creating.exchange(true)) return false;
  if (g_closed.load()) {
    g_creating.store(false);
    return false;
  }
  g_cancel.store(false);
  Progress(0, "Preparing...");
  if (xTaskCreate(CreateTask, "kf_drive_new", 6144, reinterpret_cast<void*>(static_cast<std::intptr_t>(mib)),
                  3, nullptr) != pdPASS) {
    // Accepted but never started: still a finished, failed creation the screen can show.
    Progress(0, "Could not start: out of memory");
    g_create_result.store(-1);
    g_create_finished.fetch_add(1);
    g_creating.store(false);
    return false;
  }
  return true;
}

void DriveCancelCreate() { g_cancel.store(true); }

CreateStatus DriveCreateStatus() {
  CreateStatus status;
  status.finished = g_create_finished.load();
  status.result = g_create_result.load();
  status.busy = g_creating.load();
  status.percent = g_percent.load();
  taskENTER_CRITICAL(&g_message_mux);
  std::memcpy(status.message, g_create_message, sizeof(status.message));
  taskEXIT_CRITICAL(&g_message_mux);
  return status;
}

}  // namespace keyferry::handheld

// --- TinyUSB mass-storage callbacks (TinyUSB task). One LUN; the bridge defines none in this
// board's builds and Espressif's flash/SD adapter is left out of the link (handheld CMake).

namespace {

using keyferry::handheld::ExportState;

constexpr std::uint8_t kSenseInvalidField = 0x24;

bool Serving() { return keyferry::handheld::g_export.load() == ExportState::kServing; }

// LUN 0 only; anything else is "logical unit not supported".
bool KnownLun(std::uint8_t lun) {
  if (lun == 0) return true;
  tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, 0x25, 0x00);
  return false;
}

bool MediumPresent(std::uint8_t lun) {
  if (Serving()) return true;
  tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, 0x3A, 0x00);  // medium not present
  return false;
}

}  // namespace

extern "C" void msc_storage_mount_to_usb(void) {}
extern "C" void msc_storage_mount_to_app(void) {}

extern "C" std::uint8_t tud_msc_get_maxlun_cb(void) { return 1; }

// LUN 0 is the drive. Any other LUN answers "no device here" (qualifier 011b, type 1Fh).
extern "C" std::uint32_t tud_msc_inquiry2_cb(std::uint8_t lun, scsi_inquiry_resp_t* response, std::uint32_t) {
  if (lun != 0) {
    std::memset(response, 0, sizeof(*response));
    response->peripheral_qualifier = 3;
    response->peripheral_device_type = 0x1F;
    response->version = 2;
    response->response_data_format = 2;
    response->additional_length = sizeof(scsi_inquiry_resp_t) - 5;
    return sizeof(scsi_inquiry_resp_t);
  }
  std::memcpy(response->vendor_id, "Keyferry", 8);
  std::memcpy(response->product_id, "USB Drive       ", 16);
  std::memcpy(response->product_rev, "1.0 ", 4);
  return sizeof(scsi_inquiry_resp_t);
}

extern "C" bool tud_msc_test_unit_ready_cb(std::uint8_t lun) { return KnownLun(lun) && MediumPresent(lun); }

// No medium (ejected, stopped, failed) reports zero, which TinyUSB answers with NOT READY.
extern "C" void tud_msc_capacity_cb(std::uint8_t lun, std::uint32_t* block_count, std::uint16_t* block_size) {
  const bool present = lun == 0 && Serving();
  *block_count = present ? static_cast<std::uint32_t>(keyferry::handheld::g_bytes.load() /
                                                      keyferry::handheld::kSector)
                         : 0;
  *block_size = present ? keyferry::handheld::kSector : 0;
}

extern "C" bool tud_msc_is_writable_cb(std::uint8_t lun) {
  return lun == 0 && keyferry::handheld::g_writable.load() && Serving();
}

extern "C" bool tud_msc_prevent_allow_medium_removal_cb(std::uint8_t lun, std::uint8_t prohibit, std::uint8_t) {
  if (!KnownLun(lun)) return false;
  keyferry::handheld::g_prevent_removal = (prohibit & 0x01) != 0;
  keyferry::handheld::g_prevent_session = keyferry::handheld::UsbDeviceSession();
  return true;
}

extern "C" bool tud_msc_start_stop_cb(std::uint8_t lun, std::uint8_t, bool start, bool load_eject) {
  if (!KnownLun(lun)) return false;
  if (!load_eject || start) return true;  // spin up/down and load: nothing to do
  if (keyferry::handheld::g_prevent_removal &&
      keyferry::handheld::g_prevent_session == keyferry::handheld::UsbDeviceSession()) {
    tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, 0x53, 0x02);  // medium removal prevented
    return false;
  }
  if (keyferry::handheld::Eject()) return true;
  tud_msc_set_sense(lun, SCSI_SENSE_MEDIUM_ERROR, 0x0C, 0x00);  // write error
  return false;
}

extern "C" std::int32_t tud_msc_read10_cb(std::uint8_t lun, std::uint32_t lba, std::uint32_t offset,
                                          void* buffer, std::uint32_t size) {
  if (!KnownLun(lun)) return -1;
  return keyferry::handheld::Transfer(lba, offset, buffer, size, false);
}

extern "C" std::int32_t tud_msc_write10_cb(std::uint8_t lun, std::uint32_t lba, std::uint32_t offset,
                                           std::uint8_t* buffer, std::uint32_t size) {
  if (!KnownLun(lun)) return -1;
  return keyferry::handheld::Transfer(lba, offset, buffer, size, true);
}


extern "C" std::int32_t tud_msc_scsi_cb(std::uint8_t lun, std::uint8_t const command[16], void* buffer,
                                        std::uint16_t size) {
  if (!KnownLun(lun)) return -1;
  switch (command[0]) {
    case 0x35:  // SYNCHRONIZE CACHE(10): every acknowledged write is already synced
      return MediumPresent(lun) ? 0 : -1;
    case 0x2F: {  // VERIFY(10): medium verification only; no byte comparison is offered
      if (((command[1] >> 1) & 0x03) != 0) break;  // BYTCHK set
      if (!MediumPresent(lun)) return -1;
      const std::uint64_t lba = static_cast<std::uint64_t>(command[2]) << 24 | command[3] << 16 |
                                command[4] << 8 | command[5];
      const std::uint64_t count = static_cast<std::uint64_t>(command[7]) << 8 | command[8];
      if ((lba + count) * keyferry::handheld::kSector > keyferry::handheld::g_bytes.load()) {
        tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, 0x21, 0x00);  // LBA out of range
        return -1;
      }
      return 0;
    }
    case 0x5A: {  // MODE SENSE(10): header only, with the write-protect bit
      std::uint8_t header[8] = {0, 6, 0, static_cast<std::uint8_t>(tud_msc_is_writable_cb(lun) ? 0x00 : 0x80),
                                0, 0, 0, 0};
      const std::size_t allocation = static_cast<std::size_t>(command[7]) << 8 | command[8];
      const std::size_t length = std::min({sizeof(header), allocation, static_cast<std::size_t>(size)});
      std::memcpy(buffer, header, length);
      return static_cast<std::int32_t>(length);
    }
    default:
      tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, 0x20, 0x00);  // invalid command
      return -1;
  }
  tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, kSenseInvalidField, 0x00);
  return -1;
}
