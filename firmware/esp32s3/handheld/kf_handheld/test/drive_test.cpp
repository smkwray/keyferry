// Host test of the handheld USB Drive. Production drive.cpp runs unchanged on
// ESP-IDF v6.0.3's own FatFs over a simulated SD card. The test plays the board's screen (the
// public API in drive.h) and the computer (the TinyUSB MSC callbacks, with a FatFs of its own
// mounted through READ(10)/WRITE(10)). An export is once per boot by design, so each boot runs as
// a fresh process of this program, with the card kept in a file between boots.
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "drive.h"
#include "drive_test_stubs.h"
#include "usb_device.h"
// ESP-IDF FatFs (ff.h last: on Windows it defines isnan/isinf macros).
#include "diskio_impl.h"
#include "ff.h"

namespace hh = keyferry::handheld;

namespace {

void Check(bool ok, const char* what, int line) {
  if (ok) return;
  std::fprintf(stderr, "drive_test.cpp:%d: CHECK failed: %s\n", line, what);
  std::fflush(stderr);
  std::_Exit(1);  // task threads may still be running
}
#define CHECK(condition) Check(static_cast<bool>(condition), #condition, __LINE__)

constexpr std::uint32_t kSector = 512;
constexpr std::uint32_t kCardSectors = 8u * 1024 * 1024;  // a 4 GiB card
constexpr std::uint32_t kUsbChunk = 4096;                 // CONFIG_TINYUSB_MSC_BUFSIZE
constexpr std::uint64_t kMiB = 1ULL << 20;
constexpr int kBoots = 6;

// --- Platform -------------------------------------------------------------------------------------

std::recursive_mutex g_critical;
std::atomic<int> g_tasks{0};
struct TaskDeleted {};
const auto g_start = std::chrono::steady_clock::now();

// The SD card: sparse sectors (absent reads as zero), with injected faults.
using Sector = std::array<std::uint8_t, kSector>;
using Sectors = std::map<std::uint32_t, Sector>;
std::mutex g_card_mutex;
Sectors g_sectors;
int g_fail_writes = 0;              // that many next writes fail outright
bool g_corrupt_next_multi = false;  // the next multi-block write stores other data, reports success
sdmmc_card_t g_card = {{static_cast<int>(kCardSectors), static_cast<int>(kSector)}};
BYTE g_card_pdrv = 0xFF;
FATFS g_card_fs;

std::atomic<std::uint32_t> g_session{1};
std::atomic<int> g_usb_starts{0};
struct Sense {
  std::uint8_t key, asc, ascq;
} g_sense{};

void Store(std::uint32_t sector, const std::uint8_t* data) {
  if (std::all_of(data, data + kSector, [](std::uint8_t byte) { return byte == 0; })) {
    g_sectors.erase(sector);
  } else {
    std::copy(data, data + kSector, g_sectors[sector].begin());
  }
}

// The card's plain disk driver, as the BSP mounts it (drive.cpp then replaces it).
DSTATUS RawInit(unsigned char) { return 0; }
DSTATUS RawStatus(unsigned char) { return 0; }
DRESULT RawRead(unsigned char, unsigned char* buffer, uint32_t sector, unsigned count) {
  return sdmmc_read_sectors(&g_card, buffer, sector, count) == ESP_OK ? RES_OK : RES_ERROR;
}
DRESULT RawWrite(unsigned char, const unsigned char* buffer, uint32_t sector, unsigned count) {
  return sdmmc_write_sectors(&g_card, buffer, sector, count) == ESP_OK ? RES_OK : RES_ERROR;
}
DRESULT RawIoctl(unsigned char, unsigned char command, void* buffer) {
  switch (command) {
    case CTRL_SYNC: return RES_OK;
    case GET_SECTOR_COUNT: *static_cast<LBA_t*>(buffer) = kCardSectors; return RES_OK;
    case GET_SECTOR_SIZE: *static_cast<WORD*>(buffer) = static_cast<WORD>(kSector); return RES_OK;
    case GET_BLOCK_SIZE: *static_cast<DWORD*>(buffer) = 1; return RES_OK;
    default: return RES_PARERR;
  }
}
const ff_diskio_impl_t kRawCard = {RawInit, RawStatus, RawRead, RawWrite, RawIoctl};

}  // namespace

struct KfTestSemaphore {
  std::timed_mutex mutex;
};

extern "C" {

const char* esp_err_to_name(esp_err_t code) { return code == ESP_OK ? "ESP_OK" : "ESP_FAIL"; }

void kf_test_log(char level, const char* tag, const char* format, ...) {
  std::va_list arguments;
  va_start(arguments, format);
  std::fprintf(stderr, "    [%c %s] ", level, tag);
  std::vfprintf(stderr, format, arguments);
  std::fputc('\n', stderr);
  va_end(arguments);
}

int64_t esp_timer_get_time(void) {
  return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - g_start)
      .count();
}

void* heap_caps_malloc(size_t size, uint32_t) { return std::malloc(size); }
void* heap_caps_calloc(size_t count, size_t size, uint32_t) { return std::calloc(count, size); }
void* heap_caps_malloc_prefer(size_t size, size_t count, ...) {
  (void)count;
  return std::malloc(size);
}
void heap_caps_free(void* block) { std::free(block); }

SemaphoreHandle_t xSemaphoreCreateMutex(void) { return new KfTestSemaphore; }
SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t*) { return new KfTestSemaphore; }
BaseType_t xSemaphoreTake(SemaphoreHandle_t semaphore, TickType_t ticks) {
  if (ticks == portMAX_DELAY) {
    semaphore->mutex.lock();
    return pdTRUE;
  }
  return semaphore->mutex.try_lock_for(std::chrono::milliseconds(ticks)) ? pdTRUE : pdFALSE;
}
BaseType_t xSemaphoreGive(SemaphoreHandle_t semaphore) {
  semaphore->mutex.unlock();
  return pdTRUE;
}
void vSemaphoreDelete(SemaphoreHandle_t semaphore) { delete semaphore; }

void kf_test_critical(int enter) {
  if (enter) {
    g_critical.lock();
  } else {
    g_critical.unlock();
  }
}

esp_err_t sdmmc_read_sectors(sdmmc_card_t* card, void* dst, size_t start, size_t count) {
  if (card != &g_card || start + count > kCardSectors) return ESP_ERR_INVALID_SIZE;
  std::lock_guard<std::mutex> lock(g_card_mutex);
  auto* out = static_cast<std::uint8_t*>(dst);
  for (size_t i = 0; i < count; ++i) {
    const auto found = g_sectors.find(static_cast<std::uint32_t>(start + i));
    if (found == g_sectors.end()) {
      std::memset(out + i * kSector, 0, kSector);
    } else {
      std::memcpy(out + i * kSector, found->second.data(), kSector);
    }
  }
  return ESP_OK;
}

esp_err_t sdmmc_write_sectors(sdmmc_card_t* card, const void* src, size_t start, size_t count) {
  if (card != &g_card || start + count > kCardSectors) return ESP_ERR_INVALID_SIZE;
  std::lock_guard<std::mutex> lock(g_card_mutex);
  if (g_fail_writes > 0) {
    --g_fail_writes;
    return ESP_FAIL;
  }
  const auto* in = static_cast<const std::uint8_t*>(src);
  for (size_t i = 0; i < count; ++i) Store(static_cast<std::uint32_t>(start + i), in + i * kSector);
  if (g_corrupt_next_multi && count > 1) {
    // What ESP-IDF v6.0.3 can do: success reported for a multi-block write that did not land.
    g_corrupt_next_multi = false;
    g_sectors[static_cast<std::uint32_t>(start + count - 1)][0] ^= 0x5A;
  }
  return ESP_OK;
}

sdmmc_card_t* bsp_sdcard = nullptr;

// As the BSP does through esp_vfs_fat_sdmmc_mount(): first free drive, mounted, never formatted.
esp_err_t bsp_sdcard_mount(void) {
  BYTE pdrv = 0xFF;
  if (ff_diskio_get_drive(&pdrv) != ESP_OK) return ESP_FAIL;
  ff_diskio_register(pdrv, &kRawCard);
  const char drive[3] = {static_cast<char>('0' + pdrv), ':', '\0'};
  if (f_mount(&g_card_fs, drive, 1) != FR_OK) {
    ff_diskio_unregister(pdrv);
    return ESP_FAIL;
  }
  g_card_pdrv = pdrv;
  bsp_sdcard = &g_card;
  return ESP_OK;
}

BYTE ff_diskio_get_pdrv_card(const sdmmc_card_t* card) { return card == &g_card ? g_card_pdrv : 0xFF; }

bool tud_msc_set_sense(uint8_t, uint8_t sense_key, uint8_t add_sense_code, uint8_t add_sense_qualifier) {
  g_sense = {sense_key, add_sense_code, add_sense_qualifier};
  return true;
}

}  // extern "C"

namespace {
// ESP-IDF's FreeRTOS fills every new task stack with 0xA5; stack objects start out as that, not
// zero. Painting the stack below the caller gives the code under test the same start.
#if defined(_MSC_VER)
__declspec(noinline)
#else
__attribute__((noinline))
#endif
void PaintStack() {
  volatile std::uint8_t paint[32 * 1024];
  for (std::size_t i = 0; i < sizeof(paint); ++i) paint[i] = 0xA5;
}
}  // namespace

BaseType_t xTaskCreate(TaskFunction_t task, const char*, uint32_t, void* argument, UBaseType_t, TaskHandle_t*) {
  g_tasks.fetch_add(1);
  std::thread([task, argument] {
    PaintStack();
    bool deleted = false;
    try {
      task(argument);
    } catch (const TaskDeleted&) {
      deleted = true;
    }
    Check(deleted, "a task returned instead of deleting itself", __LINE__);
    g_tasks.fetch_sub(1);
  }).detach();
  return pdPASS;
}

void vTaskDelete(TaskHandle_t) { throw TaskDeleted{}; }

namespace keyferry::handheld {
bool UsbDeviceStart(UsbPersonality personality) {
  if (personality == UsbPersonality::kDrive) g_usb_starts.fetch_add(1);
  return true;
}
bool UsbDeviceMounted() { return true; }
std::uint32_t UsbDeviceSession() { return g_session.load(); }
}  // namespace keyferry::handheld

namespace {

// --- Drive 1: the computer's view of the USB disk, or (board side) an image file's volume -------

FIL* g_image_file = nullptr;  // set: drive 1 is that image file; otherwise the USB disk
FATFS g_drive1_fs;

DSTATUS ComputerInit(unsigned char) { return 0; }
DSTATUS ComputerStatus(unsigned char) { return tud_msc_test_unit_ready_cb(0) ? 0 : STA_NOINIT; }

// TinyUSB hands READ(10)/WRITE(10) to the callbacks in endpoint-buffer chunks of whole blocks.
DRESULT ComputerRead(unsigned char, unsigned char* buffer, uint32_t sector, unsigned count) {
  for (unsigned done = 0; done < count;) {
    const unsigned now = std::min(count - done, kUsbChunk / kSector);
    if (tud_msc_read10_cb(0, sector + done, 0, buffer + done * kSector, now * kSector) !=
        static_cast<std::int32_t>(now * kSector)) {
      return RES_ERROR;
    }
    done += now;
  }
  return RES_OK;
}

DRESULT ComputerWrite(unsigned char, const unsigned char* buffer, uint32_t sector, unsigned count) {
  std::uint8_t chunk[kUsbChunk];
  for (unsigned done = 0; done < count;) {
    const unsigned now = std::min(count - done, kUsbChunk / kSector);
    std::memcpy(chunk, buffer + done * kSector, now * kSector);
    if (tud_msc_write10_cb(0, sector + done, 0, chunk, now * kSector) != static_cast<std::int32_t>(now * kSector)) {
      return RES_ERROR;
    }
    done += now;
  }
  return RES_OK;
}

DRESULT ComputerIoctl(unsigned char, unsigned char command, void* buffer) {
  switch (command) {
    case CTRL_SYNC: {
      const std::uint8_t synchronize_cache[16] = {0x35};
      return tud_msc_scsi_cb(0, synchronize_cache, nullptr, 0) == 0 ? RES_OK : RES_ERROR;
    }
    case GET_SECTOR_COUNT: {
      std::uint32_t blocks = 0;
      std::uint16_t block_size = 0;
      tud_msc_capacity_cb(0, &blocks, &block_size);
      *static_cast<LBA_t*>(buffer) = blocks;
      return blocks != 0 && block_size == kSector ? RES_OK : RES_NOTRDY;
    }
    case GET_SECTOR_SIZE: *static_cast<WORD*>(buffer) = static_cast<WORD>(kSector); return RES_OK;
    case GET_BLOCK_SIZE: *static_cast<DWORD*>(buffer) = 1; return RES_OK;
    default: return RES_PARERR;
  }
}
const ff_diskio_impl_t kComputerDisk = {ComputerInit, ComputerStatus, ComputerRead, ComputerWrite, ComputerIoctl};

DRESULT ImageRead(unsigned char, unsigned char* buffer, uint32_t sector, unsigned count) {
  UINT moved = 0;
  return f_lseek(g_image_file, static_cast<FSIZE_t>(sector) * kSector) == FR_OK &&
                 f_read(g_image_file, buffer, count * kSector, &moved) == FR_OK && moved == count * kSector
             ? RES_OK
             : RES_ERROR;
}
DRESULT ImageWrite(unsigned char, const unsigned char*, uint32_t, unsigned) { return RES_WRPRT; }
DRESULT ImageIoctl(unsigned char, unsigned char command, void* buffer) {
  switch (command) {
    case CTRL_SYNC: return RES_OK;
    case GET_SECTOR_COUNT: *static_cast<LBA_t*>(buffer) = f_size(g_image_file) / kSector; return RES_OK;
    case GET_SECTOR_SIZE: *static_cast<WORD*>(buffer) = static_cast<WORD>(kSector); return RES_OK;
    default: return RES_PARERR;
  }
}
const ff_diskio_impl_t kImageDisk = {RawInit, RawStatus, ImageRead, ImageWrite, ImageIoctl};

void MountDrive1(const ff_diskio_impl_t& disk) {
  BYTE pdrv = 0xFF;
  CHECK(ff_diskio_get_drive(&pdrv) == ESP_OK && pdrv == 1);  // the card holds drive 0
  ff_diskio_register(pdrv, &disk);
  CHECK(f_mount(&g_drive1_fs, "1:", 1) == FR_OK);
}

void UnmountDrive1() {
  f_mount(nullptr, "1:", 0);
  ff_diskio_unregister(1);
}

std::vector<std::uint8_t> Pattern(std::size_t size, std::uint8_t seed) {
  std::vector<std::uint8_t> data(size);
  for (std::size_t i = 0; i < size; ++i) data[i] = static_cast<std::uint8_t>(i * 31 + seed + (i >> 9));
  return data;
}

void WriteFile(const char* path, const std::vector<std::uint8_t>& data) {
  FIL file{};
  UINT moved = 0;
  CHECK(f_open(&file, path, FA_CREATE_ALWAYS | FA_WRITE) == FR_OK);
  CHECK(f_write(&file, data.data(), static_cast<UINT>(data.size()), &moved) == FR_OK && moved == data.size());
  CHECK(f_sync(&file) == FR_OK);
  CHECK(f_close(&file) == FR_OK);
}

std::vector<std::uint8_t> ReadFile(const char* path) {
  FIL file{};
  UINT moved = 0;
  CHECK(f_open(&file, path, FA_READ) == FR_OK);
  std::vector<std::uint8_t> data(f_size(&file));
  CHECK(f_read(&file, data.data(), static_cast<UINT>(data.size()), &moved) == FR_OK && moved == data.size());
  CHECK(f_close(&file) == FR_OK);
  return data;
}

// --- The board's side ------------------------------------------------------------------------------

template <typename Done>
bool WaitFor(Done done, int seconds) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  while (!done()) {
    if (std::chrono::steady_clock::now() > deadline) return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return true;
}

void WaitIdle() { CHECK(WaitFor([] { return hh::DriveIdle() && g_tasks.load() == 0; }, 60)); }

void Scan() {
  hh::DriveScan();
  WaitIdle();
  CHECK(g_card_pdrv == 0);  // the paths below name the card as drive 0
}

hh::CreateStatus WaitCreated(std::uint32_t finished) {
  CHECK(WaitFor([finished] { return hh::DriveCreateStatus().finished >= finished; }, 300));
  WaitIdle();
  return hh::DriveCreateStatus();
}

std::vector<hh::DriveInfo> List() {
  hh::DriveInfo drives[hh::kMaxDrives];
  std::uint32_t serial = 0;
  const int count = hh::DriveList(drives, hh::kMaxDrives, &serial);
  return std::vector<hh::DriveInfo>(drives, drives + count);
}

FRESULT Stat(const std::string& name) {
  FILINFO info;
  return f_stat(("0:/DRIVES/" + name).c_str(), &info);
}

void MakeCardFile(const std::string& name, FSIZE_t size) {
  FIL file{};
  CHECK(f_open(&file, ("0:/DRIVES/" + name).c_str(), FA_CREATE_NEW | FA_WRITE) == FR_OK);
  CHECK(f_lseek(&file, size) == FR_OK && f_size(&file) == size);
  CHECK(f_close(&file) == FR_OK);
}

hh::ExportState State() { return hh::DriveExportStatus().state; }

// From the screen's task, whose stack holds whatever ran there before.
bool Export(int index, bool writable) {
  PaintStack();
  return hh::DriveExport(index, writable);
}

// --- The computer's side ---------------------------------------------------------------------------

void MountComputer() {
  g_image_file = nullptr;
  MountDrive1(kComputerDisk);
}

bool Eject() { return tud_msc_start_stop_cb(0, 0, false, true); }

bool WriteProtected() {
  std::uint8_t mode_sense[16] = {0x5A};
  mode_sense[8] = 8;
  std::uint8_t header[8] = {};
  CHECK(tud_msc_scsi_cb(0, mode_sense, header, sizeof(header)) == 8);
  return (header[3] & 0x80) != 0;
}

std::int32_t Verify(std::uint32_t lba, std::uint16_t count) {
  const std::uint8_t verify[16] = {0x2F, 0, static_cast<std::uint8_t>(lba >> 24), static_cast<std::uint8_t>(lba >> 16),
                                   static_cast<std::uint8_t>(lba >> 8), static_cast<std::uint8_t>(lba), 0,
                                   static_cast<std::uint8_t>(count >> 8), static_cast<std::uint8_t>(count)};
  return tud_msc_scsi_cb(0, verify, nullptr, 0);
}

// --- Boots -------------------------------------------------------------------------------------------

void FormatCard() {
  // The board never formats the card: the computer (here, the test) did, with SD-style clusters.
  ff_diskio_register(0, &kRawCard);
  const MKFS_PARM options = {FM_FAT32, 2, 0, 0, 32768};
  std::vector<std::uint8_t> work(32768);
  CHECK(f_mkfs("0:", &options, work.data(), static_cast<UINT>(work.size())) == FR_OK);
  ff_diskio_unregister(0);
}

void CheckBlankFat32Image(const char* path, std::uint64_t bytes) {
  FIL image{};
  CHECK(f_open(&image, path, FA_READ) == FR_OK);
  CHECK(f_size(&image) == bytes);
  std::uint8_t sector[kSector];
  UINT moved = 0;
  CHECK(f_read(&image, sector, kSector, &moved) == FR_OK && moved == kSector);
  CHECK(sector[510] == 0x55 && sector[511] == 0xAA);          // an MBR...
  CHECK(sector[446 + 4] == 0x0C || sector[446 + 4] == 0x0B);  // ...with one FAT32 partition
  g_image_file = &image;
  MountDrive1(kImageDisk);
  DWORD free_clusters = 0;
  FATFS* fs = nullptr;
  CHECK(f_getfree("1:", &free_clusters, &fs) == FR_OK && fs != nullptr);
  CHECK(fs->fs_type == FS_FAT32);
  CHECK(free_clusters == fs->n_fatent - 3);  // everything free but the root directory
  FF_DIR root{};
  FILINFO info;
  CHECK(f_opendir(&root, "1:/") == FR_OK && f_readdir(&root, &info) == FR_OK && info.fname[0] == '\0');
  CHECK(f_closedir(&root) == FR_OK);
  UnmountDrive1();
  g_image_file = nullptr;
  // Zero-filled: nothing earlier on the card shows through the free space.
  CHECK(f_lseek(&image, static_cast<FSIZE_t>(bytes - kSector)) == FR_OK);
  CHECK(f_read(&image, sector, kSector, &moved) == FR_OK && moved == kSector);
  CHECK(std::all_of(sector, sector + kSector, [](std::uint8_t byte) { return byte == 0; }));
  CHECK(f_close(&image) == FR_OK);
}

// a, b, c, g: empty card, creation, a writable session ended by the computer's eject.
void BootCreateWriteEject() {
  FormatCard();
  Scan();
  CHECK(hh::DriveCard() == hh::CardState::kReady);
  CHECK(List().empty());
  CHECK(hh::DriveFreeBytes() > 3000 * kMiB);
  FILINFO info;
  CHECK(f_stat("0:/DRIVES", &info) == FR_OK && (info.fattrib & AM_DIR) != 0);

  // Only this module's own unfinished images are removed; only sector-aligned images of
  // 1 MiB or more are listed.
  MakeCardFile("DRIVE7.TMP", kSector);
  MakeCardFile("DRIVE0.TMP", 0);
  MakeCardFile("NOTES.TMP", 0);
  MakeCardFile("SMALL.IMG", 512 * 1024);
  MakeCardFile("ODD.IMG", kMiB + 100);
  CHECK(f_mkdir("0:/DRIVES/DIR.IMG") == FR_OK);
  Scan();
  CHECK(hh::DriveCard() == hh::CardState::kReady && List().empty());
  CHECK(Stat("DRIVE7.TMP") == FR_NO_FILE);
  CHECK(Stat("DRIVE0.TMP") == FR_OK && Stat("NOTES.TMP") == FR_OK);

  // Creation refused for lack of space, and cancelled part-way: nothing is left behind.
  CHECK(hh::DriveCreate(8192));
  hh::CreateStatus created = WaitCreated(1);
  CHECK(created.result == -1 && std::strcmp(created.message, "Not enough space on the card") == 0);
  CHECK(hh::DriveCreate(256));
  CHECK(WaitFor([] { return hh::DriveCreateStatus().percent >= 1; }, 60));
  hh::DriveCancelCreate();
  created = WaitCreated(2);
  CHECK(created.result == -1 && std::strcmp(created.message, "Cancelled") == 0);
  CHECK(Stat("DRIVE1.TMP") == FR_NO_FILE && Stat("DRIVE1.IMG") == FR_NO_FILE && List().empty());

  // b. A 64 MiB drive: zero-filled, FAT32 with an MBR, verified, then published.
  CHECK(hh::DriveCreate(64));
  created = WaitCreated(3);
  CHECK(created.result == 1 && created.percent == 100 && std::strcmp(created.message, "Created DRIVE1.IMG") == 0);
  std::vector<hh::DriveInfo> drives = List();
  CHECK(drives.size() == 1 && std::strcmp(drives[0].name, "DRIVE1.IMG") == 0);
  CHECK(drives[0].bytes == 64 * kMiB && !drives[0].dirty);
  CHECK(Stat("DRIVE1.TMP") == FR_NO_FILE);
  CheckBlankFat32Image("0:/DRIVES/DRIVE1.IMG", 64 * kMiB);

  // c. Writable export: the marker is on the card before the computer can write.
  CHECK(Export(0, true));
  CHECK(g_usb_starts.load() == 1);
  hh::ExportStatus exported = hh::DriveExportStatus();
  CHECK(exported.state == hh::ExportState::kServing && exported.writable && exported.connected);
  CHECK(Stat("DRIVE1.DRT") == FR_OK);
  CHECK(!hh::DriveCreate(1));  // never while a drive is exported

  CHECK(tud_msc_get_maxlun_cb() == 1);
  std::uint32_t blocks = 0;
  std::uint16_t block_size = 0;
  tud_msc_capacity_cb(0, &blocks, &block_size);
  CHECK(blocks == 64 * kMiB / kSector && block_size == kSector);
  CHECK(tud_msc_is_writable_cb(0) && !WriteProtected() && tud_msc_test_unit_ready_cb(0));
  scsi_inquiry_resp_t inquiry{};
  CHECK(tud_msc_inquiry2_cb(0, &inquiry, sizeof(inquiry)) == 36 && std::memcmp(inquiry.vendor_id, "Keyferry", 8) == 0);
  inquiry = {};
  CHECK(tud_msc_inquiry2_cb(1, &inquiry, sizeof(inquiry)) == 36);
  CHECK(inquiry.peripheral_qualifier == 3 && inquiry.peripheral_device_type == 0x1F);  // no device

  // g. The computer reaches only the image's own blocks, on LUN 0 only.
  std::vector<std::uint8_t> buffer(2 * kSector);
  constexpr std::int32_t kBlock = kSector;  // a callback's result for one block
  CHECK(tud_msc_read10_cb(0, blocks - 1, 0, buffer.data(), kSector) == kBlock);
  CHECK(tud_msc_write10_cb(0, blocks - 1, 0, buffer.data(), kSector) == kBlock);
  CHECK(tud_msc_read10_cb(0, blocks, 0, buffer.data(), kSector) == -1);
  CHECK(tud_msc_read10_cb(0, blocks - 1, 0, buffer.data(), 2 * kSector) == -1);
  CHECK(tud_msc_write10_cb(0, blocks, 0, buffer.data(), kSector) == -1);
  CHECK(tud_msc_read10_cb(0, 0xFFFFFFFFu, 0, buffer.data(), kSector) == -1);
  CHECK(tud_msc_read10_cb(0, 0, 256, buffer.data(), kSector) == -1 && g_sense.asc == 0x24);
  CHECK(tud_msc_read10_cb(0, 0, 0, buffer.data(), 100) == -1 && g_sense.asc == 0x24);
  CHECK(Verify(blocks - 8, 8) == 0);
  CHECK(Verify(blocks - 8, 9) == -1 && g_sense.asc == 0x21);
  const std::uint8_t unknown[16] = {0xC0};
  CHECK(tud_msc_scsi_cb(0, unknown, buffer.data(), 16) == -1 && g_sense.asc == 0x20);
  g_sense = {};
  CHECK(tud_msc_read10_cb(1, 0, 0, buffer.data(), kSector) == -1 && g_sense.asc == 0x25);
  CHECK(tud_msc_write10_cb(1, 0, 0, buffer.data(), kSector) == -1);
  CHECK(!tud_msc_test_unit_ready_cb(1) && !tud_msc_is_writable_cb(1));
  tud_msc_capacity_cb(1, &blocks, &block_size);
  CHECK(blocks == 0);
  CHECK(!tud_msc_start_stop_cb(1, 0, false, true) && !tud_msc_prevent_allow_medium_removal_cb(1, 1, 0));
  CHECK(State() == hh::ExportState::kServing);  // refused requests are not card faults

  // The computer stores a file and flushes it.
  MountComputer();
  WriteFile("1:/HELLO.BIN", Pattern(20000, 7));
  UnmountDrive1();
  const std::uint8_t synchronize_cache[16] = {0x35};
  CHECK(tud_msc_scsi_cb(0, synchronize_cache, nullptr, 0) == 0);
  CHECK(hh::DriveExportStatus().written_bytes >= 20000);

  // PREVENT MEDIUM REMOVAL blocks an eject for its USB session only.
  CHECK(tud_msc_prevent_allow_medium_removal_cb(0, 1, 0));
  CHECK(!Eject() && g_sense.asc == 0x53 && g_sense.ascq == 0x02);
  CHECK(State() == hh::ExportState::kServing && Stat("DRIVE1.DRT") == FR_OK);
  g_session.fetch_add(1);  // unplugged and plugged back in

  // The computer's eject after a clean sync: everything is on the card and the marker goes.
  CHECK(Eject());
  exported = hh::DriveExportStatus();
  CHECK(exported.state == hh::ExportState::kEjected && !exported.marker_kept);
  CHECK(Stat("DRIVE1.DRT") == FR_NO_FILE);
  CHECK(Eject());  // repeating a clean eject succeeds
  CHECK(!tud_msc_test_unit_ready_cb(0) && g_sense.asc == 0x3A);
  tud_msc_capacity_cb(0, &blocks, &block_size);
  CHECK(blocks == 0 && tud_msc_read10_cb(0, 0, 0, buffer.data(), kSector) == -1);
  Scan();
  drives = List();
  CHECK(drives.size() == 1 && !drives[0].dirty);
  CHECK(!Export(0, false));  // one export per boot
  hh::DriveClose();
}

// d. Read back read-only: the file is intact and nothing can be written.
void BootReadOnly() {
  Scan();
  const std::vector<hh::DriveInfo> drives = List();
  CHECK(drives.size() == 1 && !drives[0].dirty);
  CHECK(Export(0, false));
  CHECK(State() == hh::ExportState::kServing && !hh::DriveExportStatus().writable);
  CHECK(Stat("DRIVE1.DRT") == FR_NO_FILE);
  CHECK(!tud_msc_is_writable_cb(0) && WriteProtected());
  MountComputer();
  CHECK(ReadFile("1:/HELLO.BIN") == Pattern(20000, 7));
  UnmountDrive1();
  std::uint8_t block[kSector] = {};
  CHECK(tud_msc_write10_cb(0, 0, 0, block, kSector) == -1);
  const hh::ExportStatus exported = hh::DriveExportStatus();
  CHECK(exported.state == hh::ExportState::kServing && exported.written_bytes == 0 && exported.read_bytes > 0);
  CHECK(Eject() && State() == hh::ExportState::kEjected);
  CHECK(Stat("DRIVE1.DRT") == FR_NO_FILE);
  hh::DriveClose();
}

// e. Unplugged without an eject. Returns the card as it was the moment the computer's last
// write was acknowledged, standing for power lost there: the next boot sees only that.
Sectors BootUnplugged() {
  Scan();
  CHECK(Export(0, true));
  CHECK(Stat("DRIVE1.DRT") == FR_OK);
  MountComputer();
  WriteFile("1:/PLUG.BIN", Pattern(5000, 3));
  Sectors pulled;
  {
    std::lock_guard<std::mutex> lock(g_card_mutex);
    pulled = g_sectors;
  }
  UnmountDrive1();  // the computer is gone
  hh::DriveClose();
  WaitIdle();
  CHECK(State() == hh::ExportState::kStopped);
  CHECK(Stat("DRIVE1.DRT") == FR_OK);  // never ejected: the marker stays
  const std::uint32_t serial = hh::DriveListSerial();
  hh::DriveScan();
  CHECK(hh::DriveListSerial() == serial && hh::DriveIdle());  // closed: no new scans,
  CHECK(!Export(0, true) && !hh::DriveCreate(1));    // exports or creations
  return pulled;
}

// e (next boot) and f: a dirty drive may be repaired writable; a card fault stops everything.
void BootDirtyThenCardFault() {
  Scan();
  std::vector<hh::DriveInfo> drives = List();
  CHECK(drives.size() == 1 && drives[0].dirty);
  CHECK(Export(0, true));
  MountComputer();
  CHECK(ReadFile("1:/PLUG.BIN") == Pattern(5000, 3));  // acknowledged writes outlived the power cut
  CHECK(ReadFile("1:/HELLO.BIN") == Pattern(20000, 7));
  UnmountDrive1();

  std::uint32_t blocks = 0;
  std::uint16_t block_size = 0;
  tud_msc_capacity_cb(0, &blocks, &block_size);
  std::vector<std::uint8_t> data = Pattern(kUsbChunk, 9);
  {
    std::lock_guard<std::mutex> lock(g_card_mutex);
    g_corrupt_next_multi = true;
  }
  CHECK(tud_msc_write10_cb(0, blocks - 8, 0, data.data(), kUsbChunk) == -1);
  {
    std::lock_guard<std::mutex> lock(g_card_mutex);
    CHECK(!g_corrupt_next_multi);  // that write was the one that did not land
  }
  CHECK(State() == hh::ExportState::kFailed);
  CHECK(!tud_msc_test_unit_ready_cb(0) && tud_msc_read10_cb(0, 0, 0, data.data(), kSector) == -1);
  CHECK(!Eject() && State() == hh::ExportState::kFailed);  // a failed drive never ejects clean
  Scan();
  CHECK(hh::DriveCard() == hh::CardState::kError);
  CHECK(!Export(0, false) && !hh::DriveCreate(1));
  hh::DriveClose();
}

// Leaving mid-creation cancels it and waits for it; nothing is left behind.
void BootLeaveWhileCreating() {
  Scan();
  CHECK(hh::DriveCard() == hh::CardState::kReady && List().size() == 1);
  CHECK(hh::DriveCreate(128));
  CHECK(WaitFor([] { return hh::DriveCreateStatus().percent >= 1; }, 60));
  hh::DriveClose();
  WaitIdle();
  const hh::CreateStatus created = hh::DriveCreateStatus();
  CHECK(created.finished == 1 && created.result == -1);
  CHECK(Stat("DRIVE2.TMP") == FR_NO_FILE && Stat("DRIVE2.IMG") == FR_NO_FILE);
}

// A writable export whose marker cannot be written fails closed, and the fault is latched.
void BootMarkerWriteFails() {
  Scan();
  CHECK(List().size() == 1);
  {
    std::lock_guard<std::mutex> lock(g_card_mutex);
    g_fail_writes = 1;
  }
  CHECK(!Export(0, true));
  {
    std::lock_guard<std::mutex> lock(g_card_mutex);
    CHECK(g_fail_writes == 0);
  }
  CHECK(State() == hh::ExportState::kNone && g_usb_starts.load() == 0);
  CHECK(!Export(0, false));
  Scan();
  CHECK(hh::DriveCard() == hh::CardState::kError);
}

void SaveCard(const Sectors& sectors, const char* path) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  for (const auto& entry : sectors) {
    out.write(reinterpret_cast<const char*>(&entry.first), sizeof(entry.first));
    out.write(reinterpret_cast<const char*>(entry.second.data()), kSector);
  }
  CHECK(out.good());
}

void LoadCard(const char* path) {
  std::ifstream in(path, std::ios::binary);
  std::uint32_t sector = 0;
  Sector data;
  while (in.read(reinterpret_cast<char*>(&sector), sizeof(sector)) &&
         in.read(reinterpret_cast<char*>(data.data()), kSector)) {
    g_sectors[sector] = data;
  }
}

int RunBoot(int boot, const char* card) {
  LoadCard(card);
  Sectors pulled;
  bool power_cut = false;
  switch (boot) {
    case 1: BootCreateWriteEject(); break;
    case 2: BootReadOnly(); break;
    case 3:
      pulled = BootUnplugged();
      power_cut = true;
      break;
    case 4: BootDirtyThenCardFault(); break;
    case 5: BootLeaveWhileCreating(); break;
    case 6: BootMarkerWriteFails(); break;
    default: Check(false, "unknown boot", __LINE__);
  }
  WaitIdle();
  std::lock_guard<std::mutex> lock(g_card_mutex);
  SaveCard(power_cut ? pulled : g_sectors, card);
  std::printf("  boot %d: PASS (%zu card sectors in use)\n", boot, g_sectors.size());
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 4 && std::strcmp(argv[1], "boot") == 0) return RunBoot(std::atoi(argv[2]), argv[3]);
  const std::string self = argv[0];
  const std::string card = self + ".card";
  std::remove(card.c_str());
  for (int boot = 1; boot <= kBoots; ++boot) {
    std::string command = "\"" + self + "\" boot " + std::to_string(boot) + " \"" + card + "\"";
#ifdef _WIN32
    command = "\"" + command + "\"";  // cmd.exe /c strips one outer pair of quotes
#endif
    std::fflush(stdout);
    const int status = std::system(command.c_str());
    if (status != 0) {
      std::fprintf(stderr, "handheld drive test: boot %d failed (%d)\n", boot, status);
      std::remove(card.c_str());
      return 1;
    }
  }
  std::remove(card.c_str());
  std::printf("handheld drive test: PASS (%d boots)\n", kBoots);
  return 0;
}
