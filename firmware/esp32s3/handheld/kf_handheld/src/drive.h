#pragma once
#include <cstdint>

namespace keyferry::handheld {

// USB Drive (ADR 0018 rule 4): fixed-size image files in DRIVES/ on the SD card, one exported at
// a time as a USB disk. Read-only unless chosen writable; writes reach the card before the
// computer is told they succeeded.

constexpr int kMaxDrives = 8;

struct DriveInfo {
  char name[32];        // file name, e.g. DRIVE1.IMG
  std::uint64_t bytes;
  bool dirty;           // last writable session did not end with an eject
};

enum class CardState : std::uint8_t { kChecking, kReady, kNoCard, kError };

// Mounts the card (never formats it) and lists the images, on a worker task.
void DriveScan();
CardState DriveCard();
// Copies the list; *serial changes whenever it does.
int DriveList(DriveInfo* out, int max, std::uint32_t* serial);
std::uint64_t DriveFreeBytes();

enum class ExportState : std::uint8_t {
  kNone,      // nothing exported this boot
  kServing,   // exported; the computer may read (and, if writable, write)
  kEjected,   // the computer ejected it: everything is on the card, safe to unplug
  kStopped,   // stopped from the board
  kFailed,    // a card error: no longer served
};

struct ExportStatus {
  ExportState state = ExportState::kNone;
  bool writable = false;
  bool connected = false;          // a computer has configured the USB device
  bool busy = false;               // read or write in the last second
  std::uint64_t read_bytes = 0;
  std::uint64_t written_bytes = 0;
};

// Opens images[index] and attaches it as a USB disk. A writable export first records an
// outstanding-session marker on the card and fails closed if it cannot.
bool DriveExport(int index, bool writable);
ExportStatus DriveExportStatus();
// Stops serving and closes the image (any task). The marker stays unless the computer ejected it.
void DriveStop();

// Creates a blank FAT32 image of `mib` MiB on a worker task: zero-filled, formatted, verified,
// then published as the next free DRIVEn.IMG.
bool DriveCreate(int mib);
void DriveCancelCreate();
struct CreateStatus {
  bool busy = false;
  int percent = 0;
  int result = 0;  // 0 none yet, 1 created, -1 failed or cancelled
  char message[48] = {};
};
CreateStatus DriveCreateStatus();

}  // namespace keyferry::handheld
