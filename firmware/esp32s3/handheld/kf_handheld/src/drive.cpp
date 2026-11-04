// USB Drive (ADR 0018 rule 4): one fixed-size image file from DRIVES/ on the SD card, exported
// as a removable USB disk with 512-byte sectors. The computer reaches only the bytes of that one
// file: never the card's own file system, other images or spare space. Read-only unless chosen
// writable; each write is on the card (written and synced) before it is acknowledged.
#include "drive.h"

#include <algorithm>
#include <atomic>
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

// Guards the exported image and the list. Never held across a long job (creation).
SemaphoreHandle_t g_lock = nullptr;
StaticSemaphore_t g_lock_storage;
char g_root[8] = "0:";  // FatFs drive prefix of the card

std::atomic<CardState> g_card{CardState::kChecking};
DriveInfo g_drives[kMaxDrives];
int g_count = 0;
std::atomic<std::uint32_t> g_serial{0};
std::atomic<std::uint64_t> g_free{0};

FIL g_image;
bool g_open = false;
bool g_writable = false;
std::uint64_t g_bytes = 0;
char g_marker[64] = {};
DWORD g_linkmap[64];  // fast-seek cluster map: up to 31 fragments
std::atomic<ExportState> g_export{ExportState::kNone};
std::atomic<std::uint64_t> g_read{0};
std::atomic<std::uint64_t> g_written{0};
std::atomic<std::int64_t> g_last_io{0};

std::atomic<bool> g_creating{false};
std::atomic<bool> g_cancel{false};
std::atomic<int> g_percent{0};
std::atomic<int> g_create_result{0};
char g_create_message[48] = {};

void Lock() { xSemaphoreTake(g_lock, portMAX_DELAY); }
void Unlock() { xSemaphoreGive(g_lock); }

void EnsureLock() {
  if (g_lock == nullptr) g_lock = xSemaphoreCreateMutexStatic(&g_lock_storage);
}

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

// DRIVEn.TMP: only CreateImage() makes these.
bool IsLeftoverTemp(const char* name) {
  const std::size_t length = std::strlen(name);
  return length > 9 && strncasecmp(name, "DRIVE", 5) == 0 && strcasecmp(name + length - 4, ".TMP") == 0;
}

// Lists DRIVES/ (creating it if missing). Caller holds g_lock.
void ScanLocked() {
  char path[48];
  std::snprintf(path, sizeof(path), "%s/%s", g_root, kDir);
  FRESULT result = f_mkdir(path);
  if (result != FR_OK && result != FR_EXIST) ESP_LOGW(kTag, "cannot create %s: %d", kDir, result);
  FF_DIR dir;
  FILINFO info;
  g_count = 0;
  if (f_opendir(&dir, path) == FR_OK) {
    while (g_count < kMaxDrives && f_readdir(&dir, &info) == FR_OK && info.fname[0] != '\0') {
      if (!g_creating.load() && IsLeftoverTemp(info.fname)) {
        // An image creation that never finished (power lost, card pulled): never a drive.
        char leftover[64];
        Path(leftover, sizeof(leftover), info.fname);
        f_unlink(leftover);
        continue;
      }
      if ((info.fattrib & AM_DIR) != 0 || !IsImageName(info.fname)) continue;
      const std::uint64_t bytes = info.fsize;
      if (bytes < kMinImage || bytes > kMaxImage || bytes % kSector != 0) continue;
      DriveInfo& drive = g_drives[g_count++];
      strlcpy(drive.name, info.fname, sizeof(drive.name));  // IsImageName() bounded its length
      drive.bytes = bytes;
      char marker[64];
      MarkerPath(marker, sizeof(marker), drive.name);
      FILINFO marker_info;
      drive.dirty = f_stat(marker, &marker_info) == FR_OK;
    }
    f_closedir(&dir);
    // By name (insertion sort: at most kMaxDrives entries).
    for (int i = 1; i < g_count; ++i) {
      const DriveInfo entry = g_drives[i];
      int j = i;
      for (; j > 0 && strcasecmp(g_drives[j - 1].name, entry.name) > 0; --j) g_drives[j] = g_drives[j - 1];
      g_drives[j] = entry;
    }
  }
  DWORD free_clusters = 0;
  FATFS* fs = nullptr;
  if (f_getfree(g_root, &free_clusters, &fs) == FR_OK && fs != nullptr) {
    g_free.store(static_cast<std::uint64_t>(free_clusters) * fs->csize * kSector);
  }
  g_serial.fetch_add(1);
}

void ScanTask(void*) {
  if (bsp_sdcard == nullptr) {
    const esp_err_t mounted = bsp_sdcard_mount();  // format-on-failure stays off
    if (mounted != ESP_OK) {
      ESP_LOGW(kTag, "SD card not mounted: %s", esp_err_to_name(mounted));
      // ESP_FAIL: a card answered but holds no readable FAT volume.
      g_card.store(mounted == ESP_FAIL ? CardState::kError : CardState::kNoCard);
      g_serial.fetch_add(1);
      vTaskDelete(nullptr);
    }
    std::snprintf(g_root, sizeof(g_root), "%u:", ff_diskio_get_pdrv_card(bsp_sdcard));
  }
  Lock();
  ScanLocked();
  Unlock();
  g_card.store(CardState::kReady);
  ESP_LOGI(kTag, "card ready: %d images, %llu MiB free", g_count,
           static_cast<unsigned long long>(g_free.load() >> 20));
  vTaskDelete(nullptr);
}

// A card error while serving: stop serving that image for good. Caller holds g_lock.
void FailLocked(const char* what, FRESULT result) {
  ESP_LOGE(kTag, "%s failed (%d): image no longer served", what, result);
  if (g_open) f_close(&g_image);
  g_open = false;
  g_export.store(ExportState::kFailed);
}

// The TinyUSB task's whole I/O path, one transfer at a time under g_lock.
int32_t Transfer(std::uint32_t lba, std::uint32_t offset, void* buffer, std::uint32_t size, bool write) {
  const std::uint64_t at = static_cast<std::uint64_t>(lba) * kSector + offset;
  Lock();
  if (!g_open || g_export.load() != ExportState::kServing || (write && !g_writable) ||
      at > g_bytes || size > g_bytes - at) {
    Unlock();
    return -1;  // TinyUSB fails the command
  }
  UINT moved = 0;
  FRESULT result = f_lseek(&g_image, static_cast<FSIZE_t>(at));
  if (result == FR_OK) {
    result = write ? f_write(&g_image, buffer, size, &moved) : f_read(&g_image, buffer, size, &moved);
  }
  if (result == FR_OK && write) result = f_sync(&g_image);  // on the card before acknowledged
  if (result != FR_OK || moved != size) {
    FailLocked(write ? "write" : "read", result != FR_OK ? result : FR_DISK_ERR);
    Unlock();
    return -1;
  }
  Unlock();
  (write ? g_written : g_read).fetch_add(size);
  g_last_io.store(esp_timer_get_time());
  return static_cast<int32_t>(size);
}

// The computer ejected the disk: everything it wrote is synced; the session ends cleanly.
void Eject() {
  Lock();
  if (g_open) {
    const FRESULT synced = f_sync(&g_image);
    const FRESULT closed = f_close(&g_image);
    g_open = false;
    if (g_writable) {
      const FRESULT cleared = synced == FR_OK && closed == FR_OK ? f_unlink(g_marker) : FR_DISK_ERR;
      if (cleared != FR_OK) ESP_LOGW(kTag, "eject: marker kept (%d %d %d)", synced, closed, cleared);
    }
  }
  if (g_export.load() == ExportState::kServing) g_export.store(ExportState::kEjected);
  Unlock();
  ESP_LOGI(kTag, "ejected by the computer");
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
  std::snprintf(g_create_message, sizeof(g_create_message), "%s", message);
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

bool CreateImage(std::uint64_t bytes) {
  if (g_free.load() < bytes + (1ULL << 20)) {
    Progress(0, "Not enough space on the card");
    return false;
  }
  // The next free DRIVEn.IMG, built as DRIVEn.TMP and renamed only when complete.
  char final_path[64] = {};
  char temp_path[64] = {};
  char name[16] = {};
  FIL file;
  bool opened = false;
  for (int n = 1; n < 100 && !opened; ++n) {
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
    Progress(0, "Cannot create a file on the card");
    return false;
  }
  void* buffer = heap_caps_calloc(1, kFillChunk, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
  bool ok = buffer != nullptr;
  if (ok && f_expand(&file, static_cast<FSIZE_t>(bytes), 1) != FR_OK) {
    ESP_LOGI(kTag, "no contiguous space: the image will be fragmented");
  }
  // Zero the whole image so nothing left on the card shows through it.
  std::uint64_t written = 0;
  ok = ok && f_lseek(&file, 0) == FR_OK;
  while (ok && written < bytes) {
    if (g_cancel.load()) {
      Progress(0, "Cancelled");
      ok = false;
      break;
    }
    const UINT size = static_cast<UINT>(std::min<std::uint64_t>(kFillChunk, bytes - written));
    UINT moved = 0;
    ok = f_write(&file, buffer, size, &moved) == FR_OK && moved == size;
    written += size;
    const int percent = static_cast<int>(written * 90 / bytes);
    if (percent != g_percent.load()) Progress(percent, "Preparing...");
  }
  ok = ok && f_sync(&file) == FR_OK;
  if (ok) {
    Progress(92, "Formatting...");
    ok = FormatImage(&file, bytes, buffer, kFillChunk);
    if (!ok) Progress(0, "Formatting failed");
  } else if (!g_cancel.load()) {
    Progress(0, "Card write failed");
  }
  heap_caps_free(buffer);
  ok = f_close(&file) == FR_OK && ok;
  ok = ok && f_rename(temp_path, final_path) == FR_OK;
  if (!ok) {
    f_unlink(temp_path);
    return false;
  }
  char done[48];
  std::snprintf(done, sizeof(done), "Created %s", name);
  Progress(100, done);
  ESP_LOGI(kTag, "created %s (%llu MiB)", name, static_cast<unsigned long long>(bytes >> 20));
  return true;
}

void CreateTask(void* argument) {
  const auto mib = static_cast<std::uint64_t>(reinterpret_cast<std::intptr_t>(argument));
  const bool created = CreateImage(mib << 20);
  Lock();
  ScanLocked();
  Unlock();
  g_create_result.store(created ? 1 : -1);
  g_creating.store(false);
  vTaskDelete(nullptr);
}

}  // namespace

void DriveScan() {
  EnsureLock();
  g_card.store(CardState::kChecking);
  if (xTaskCreate(ScanTask, "kf_drive_scan", 6144, nullptr, 3, nullptr) != pdPASS) {
    g_card.store(CardState::kError);
  }
}

CardState DriveCard() { return g_card.load(); }

int DriveList(DriveInfo* out, int max, std::uint32_t* serial) {
  EnsureLock();
  Lock();
  const int count = std::min(max, g_count);
  std::copy(g_drives, g_drives + count, out);
  *serial = g_serial.load();
  Unlock();
  return count;
}

std::uint64_t DriveFreeBytes() { return g_free.load(); }

bool DriveExport(int index, bool writable) {
  EnsureLock();
  if (g_creating.load() || g_card.load() != CardState::kReady) return false;
  Lock();
  if (g_export.load() != ExportState::kNone || index < 0 || index >= g_count) {
    Unlock();
    return false;
  }
  const DriveInfo drive = g_drives[index];
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
  if (f_lseek(&g_image, CREATE_LINKMAP) != FR_OK) {
    g_image.cltbl = nullptr;  // too fragmented for the map: correct, only slower seeks
    ESP_LOGW(kTag, "%s is fragmented: seeks walk the cluster chain", drive.name);
  }
  MarkerPath(g_marker, sizeof(g_marker), drive.name);
  if (writable) {
    // Recorded before the computer can write; fail closed when the card refuses it.
    FIL marker;
    UINT moved = 0;
    const bool marked = f_open(&marker, g_marker, FA_CREATE_ALWAYS | FA_WRITE) == FR_OK &&
                        f_write(&marker, "1", 1, &moved) == FR_OK && moved == 1 &&
                        f_close(&marker) == FR_OK;
    if (!marked) {
      f_close(&g_image);
      Unlock();
      ESP_LOGE(kTag, "cannot record the writable session for %s", drive.name);
      return false;
    }
  }
  g_open = true;
  g_writable = writable;
  g_bytes = drive.bytes;
  g_export.store(ExportState::kServing);
  Unlock();
  ESP_LOGI(kTag, "exporting %s (%llu MiB, %s)", drive.name,
           static_cast<unsigned long long>(drive.bytes >> 20), writable ? "writable" : "read-only");
  if (!UsbDeviceStart(UsbPersonality::kDrive)) {
    DriveStop();
    return false;
  }
  return true;
}

ExportStatus DriveExportStatus() {
  ExportStatus status;
  status.state = g_export.load();
  status.writable = g_writable;
  status.connected = status.state != ExportState::kNone && UsbDeviceMounted();
  status.busy = esp_timer_get_time() - g_last_io.load() < kBusyUs && g_last_io.load() != 0;
  status.read_bytes = g_read.load();
  status.written_bytes = g_written.load();
  return status;
}

void DriveStop() {
  if (g_lock == nullptr) return;
  Lock();
  if (g_open) {
    f_sync(&g_image);
    f_close(&g_image);  // a writable session's marker stays: the computer never ejected it
    g_open = false;
  }
  if (g_export.load() == ExportState::kServing) g_export.store(ExportState::kStopped);
  Unlock();
}

bool DriveCreate(int mib) {
  if (g_card.load() != CardState::kReady || g_export.load() != ExportState::kNone ||
      g_creating.exchange(true)) {
    return false;
  }
  g_cancel.store(false);
  g_create_result.store(0);
  Progress(0, "Preparing...");
  if (xTaskCreate(CreateTask, "kf_drive_new", 6144, reinterpret_cast<void*>(static_cast<std::intptr_t>(mib)),
                  3, nullptr) != pdPASS) {
    g_creating.store(false);
    return false;
  }
  return true;
}

void DriveCancelCreate() { g_cancel.store(true); }

CreateStatus DriveCreateStatus() {
  CreateStatus status;
  status.busy = g_creating.load();
  status.percent = g_percent.load();
  status.result = g_create_result.load();
  std::snprintf(status.message, sizeof(status.message), "%s", g_create_message);
  return status;
}

}  // namespace keyferry::handheld

// --- TinyUSB mass-storage callbacks (TinyUSB task). One LUN; the bridge defines none in this
// board's builds and Espressif's flash/SD adapter is left out of the link (handheld CMake).

extern "C" void msc_storage_mount_to_usb(void) {}
extern "C" void msc_storage_mount_to_app(void) {}

extern "C" std::uint8_t tud_msc_get_maxlun_cb(void) { return 1; }

extern "C" void tud_msc_inquiry_cb(std::uint8_t, std::uint8_t vendor[8], std::uint8_t product[16],
                                   std::uint8_t revision[4]) {
  std::memcpy(vendor, "Keyferry", 8);
  std::memcpy(product, "USB Drive       ", 16);
  std::memcpy(revision, "1.0 ", 4);
}

extern "C" bool tud_msc_test_unit_ready_cb(std::uint8_t lun) {
  using keyferry::handheld::ExportState;
  if (lun == 0 && keyferry::handheld::DriveExportStatus().state == ExportState::kServing) return true;
  tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, 0x3A, 0x00);  // medium not present
  return false;
}

extern "C" void tud_msc_capacity_cb(std::uint8_t, std::uint32_t* block_count, std::uint16_t* block_size) {
  *block_count = static_cast<std::uint32_t>(keyferry::handheld::g_bytes / keyferry::handheld::kSector);
  *block_size = keyferry::handheld::kSector;
}

extern "C" bool tud_msc_is_writable_cb(std::uint8_t) {
  return keyferry::handheld::g_writable &&
         keyferry::handheld::g_export.load() == keyferry::handheld::ExportState::kServing;
}

extern "C" bool tud_msc_start_stop_cb(std::uint8_t lun, std::uint8_t, bool start, bool load_eject) {
  if (lun == 0 && load_eject && !start) keyferry::handheld::Eject();
  return true;
}

extern "C" std::int32_t tud_msc_read10_cb(std::uint8_t lun, std::uint32_t lba, std::uint32_t offset,
                                          void* buffer, std::uint32_t size) {
  return lun == 0 ? keyferry::handheld::Transfer(lba, offset, buffer, size, false) : -1;
}

extern "C" std::int32_t tud_msc_write10_cb(std::uint8_t lun, std::uint32_t lba, std::uint32_t offset,
                                           std::uint8_t* buffer, std::uint32_t size) {
  return lun == 0 ? keyferry::handheld::Transfer(lba, offset, buffer, size, true) : -1;
}

extern "C" std::int32_t tud_msc_scsi_cb(std::uint8_t lun, std::uint8_t const command[16], void* buffer,
                                        std::uint16_t size) {
  switch (command[0]) {
    case 0x35:  // SYNCHRONIZE CACHE(10): every acknowledged write is already synced
    case 0x2F:  // VERIFY(10)
      return 0;
    case 0x5A: {  // MODE SENSE(10): header only, with the write-protect bit
      if (size < 8) break;
      auto* response = static_cast<std::uint8_t*>(buffer);
      std::memset(response, 0, 8);
      response[1] = 6;
      response[3] = tud_msc_is_writable_cb(lun) ? 0x00 : 0x80;
      return 8;
    }
    default: break;
  }
  tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, 0x20, 0x00);  // invalid command
  return -1;
}
