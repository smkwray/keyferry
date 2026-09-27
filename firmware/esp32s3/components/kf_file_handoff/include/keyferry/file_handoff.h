#pragma once

#include <cstddef>
#include <cstdint>
#include "keyferry_protocol_generated.h"

namespace keyferry::file_handoff {

constexpr std::size_t kMaximumFileBytes = protocol::kFileHandoffMaxFileBytes;
constexpr std::size_t kMaximumChunkBytes = protocol::kFileHandoffMaxChunkBytes;
constexpr std::size_t kMaximumFiles = protocol::kFileHandoffMaxFiles;
constexpr std::size_t kMaximumNameBytes = protocol::kFileHandoffMaxNameBytes;
constexpr std::size_t kMaximumBundleBytes = protocol::kFileHandoffMaxBundleBytes;
constexpr std::uint32_t kBlockBytes = 512;
static_assert(kMaximumFileBytes > 0 && kMaximumFileBytes <= 4084ULL * kBlockBytes,
              "file capacity must fit FAT12 without geometry overflow");
constexpr std::uint32_t kDataSectors =
    static_cast<std::uint32_t>((kMaximumFileBytes + kBlockBytes - 1) / kBlockBytes +
                               kMaximumFiles - 1);
constexpr std::uint32_t kFatEntries = kDataSectors + 2;
constexpr std::uint32_t kFatBytes = (kFatEntries * 3 + 1) / 2;
constexpr std::uint32_t kFatSectors = (kFatBytes + kBlockBytes - 1) / kBlockBytes;
constexpr std::uint32_t kRootSector = 1 + 2 * kFatSectors;
constexpr std::uint32_t kMaxLfnEntries = (kMaximumNameBytes + 12) / 13;
constexpr std::uint32_t kRootEntries =
    ((1 + kMaximumFiles * (kMaxLfnEntries + 1) + 15) / 16) * 16;
constexpr std::uint32_t kRootSectors = kRootEntries / 16;
constexpr std::uint32_t kDataStartSector = kRootSector + kRootSectors;
constexpr std::uint32_t kBlockCount = kDataStartSector + kDataSectors;
static_assert(kMaximumFileBytes > 0 && kDataSectors < 4085,
              "file volume must remain FAT12");
static_assert(kFatSectors > 0 && kFatSectors <= UINT16_MAX &&
                  kBlockCount <= UINT16_MAX,
              "FAT12 geometry exceeds boot-sector fields");
static_assert(kMaximumFiles > 0 && kMaximumFiles <= UINT8_MAX &&
                  kMaximumNameBytes > 0 && kMaximumNameBytes <= UINT8_MAX &&
                  kMaxLfnEntries <= 31 &&
                  kMaximumBundleBytes == kMaximumFileBytes +
                                             1 + kMaximumFiles * (1 + kMaximumNameBytes + 4) &&
                  kRootEntries <= UINT16_MAX,
              "file set geometry must match the wire registry");

enum class State : std::uint8_t { kEmpty = 0, kReceiving = 1, kPublished = 2 };
enum class Error : std::uint8_t {
  kOk = 0, kBusy = 1, kLimit = 2, kOrder = 3,
  kDigest = 4, kMemory = 5, kUnavailable = 6,
};

struct FileStatus {
  State state{State::kEmpty};
  Error error{Error::kOk};
  std::uint32_t size{};
  std::uint32_t received{};
};

struct FileSetStatus {
  State state{State::kEmpty};
  Error error{Error::kOk};
  std::uint32_t wire_size{};
  std::uint32_t received{};
  std::uint8_t count{};
  bool has_entry{};
  std::uint8_t index{};
  std::uint8_t name_length{};
  const std::uint8_t* name{};  // Valid while the caller holds the volume lock.
  std::uint32_t size{};
};

// The caller owns the digest implementation, buffer, serialization lock, and
// media-change signaling. The digest callback writes exactly 32 SHA-256 bytes.
using DigestFn = bool (*)(const std::uint8_t* data, std::size_t length,
                          std::uint8_t output[32], void* context);

class Volume final {
 public:
  Volume(std::uint8_t* buffer, std::size_t capacity, DigestFn digest,
         void* digest_context = nullptr);
  ~Volume();
  Volume(const Volume&) = delete;
  Volume& operator=(const Volume&) = delete;

  Error Begin(std::uint32_t length, const std::uint8_t expected_sha256[32]);
  Error BeginSet(std::uint32_t length, const std::uint8_t expected_sha256[32]);
  Error Chunk(std::uint32_t offset, const std::uint8_t* bytes,
              std::size_t length);
  Error Commit();
  Error CommitSet();
  Error Clear();
  void Disconnect();

  FileStatus Status() const { return status_; }
  FileSetStatus SetStatus(std::uint8_t index) const;
  bool IsSet() const { return file_set_; }
  bool Ready() const { return status_.state == State::kPublished; }
  // Partial-sector reads match TinyUSB READ(10) callbacks. False means no
  // medium or an out-of-range request; no content is copied on failure.
  bool Read(std::uint32_t lba, std::uint32_t offset, std::uint8_t* output,
            std::size_t length) const;

 private:
  Error Fail(Error error);
  Error BeginRaw(std::uint32_t length, const std::uint8_t expected_sha256[32],
                 bool file_set);
  Error CommitRaw(bool file_set);
  bool ParseManifest();
  void Wipe();
  void Sector(std::uint32_t lba, std::uint8_t output[kBlockBytes]) const;
  std::uint16_t FatValue(std::uint32_t cluster) const;
  void RootEntry(std::uint32_t index, std::uint8_t output[32]) const;

  struct Entry {
    std::uint32_t name_offset{};
    std::uint32_t data_offset{};
    std::uint32_t size{};
    std::uint16_t first_cluster{};
    std::uint16_t clusters{};
    std::uint8_t name_length{};
    std::uint8_t lfn_entries{};
    std::uint8_t alias[11]{};
  };

  std::uint8_t* buffer_{};
  std::size_t capacity_{};
  DigestFn digest_{};
  void* digest_context_{};
  std::uint8_t expected_sha256_[32]{};
  FileStatus status_{};
  Entry entries_[kMaximumFiles]{};
  std::uint8_t entry_count_{};
  bool file_set_{};
};

}  // namespace keyferry::file_handoff
