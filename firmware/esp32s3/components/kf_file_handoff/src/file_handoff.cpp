#include "keyferry/file_handoff.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace keyferry::file_handoff {
namespace {

void Put16(std::uint8_t* at, std::uint16_t value) {
  at[0] = static_cast<std::uint8_t>(value);
  at[1] = static_cast<std::uint8_t>(value >> 8);
}

void Put32(std::uint8_t* at, std::uint32_t value) {
  for (std::size_t i = 0; i < 4; ++i) at[i] = static_cast<std::uint8_t>(value >> (8 * i));
}

std::uint32_t Get32(const std::uint8_t* at) {
  return std::uint32_t{at[0]} | (std::uint32_t{at[1]} << 8) |
         (std::uint32_t{at[2]} << 16) | (std::uint32_t{at[3]} << 24);
}

std::uint8_t Upper(std::uint8_t c) {
  return c >= 'a' && c <= 'z' ? static_cast<std::uint8_t>(c - 'a' + 'A') : c;
}

bool AllowedName(const std::uint8_t* name, std::uint8_t length) {
  if (length == 0 || length > kMaximumNameBytes ||
      name[0] == '.' || name[0] == ' ' ||
      name[length - 1] == '.' || name[length - 1] == ' ') return false;
  for (std::uint8_t i = 0; i < length; ++i) {
    const auto c = name[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == ' ' || c == '.' ||
          c == '_' || c == '-')) return false;
  }
  std::uint8_t base = 0;
  while (base < length && name[base] != '.') ++base;
  while (base != 0 && name[base - 1] == ' ') --base;
  auto equals = [&](const char* literal, std::uint8_t size) {
    if (base != size) return false;
    for (std::uint8_t i = 0; i < size; ++i)
      if (Upper(name[i]) != static_cast<std::uint8_t>(literal[i])) return false;
    return true;
  };
  if (equals("CON", 3) || equals("PRN", 3) || equals("AUX", 3) ||
      equals("NUL", 3)) return false;
  if (base == 4 && ((Upper(name[0]) == 'C' && Upper(name[1]) == 'O' &&
                     Upper(name[2]) == 'M') ||
                    (Upper(name[0]) == 'L' && Upper(name[1]) == 'P' &&
                     Upper(name[2]) == 'T')) &&
      name[3] >= '1' && name[3] <= '9') return false;
  return true;
}

std::uint8_t AliasChecksum(const std::uint8_t alias[11]) {
  std::uint8_t result = 0;
  for (unsigned i = 0; i < 11; ++i)
    result = static_cast<std::uint8_t>(((result & 1) << 7) +
                                       (result >> 1) + alias[i]);
  return result;
}

}  // namespace

Volume::Volume(std::uint8_t* buffer, std::size_t capacity, DigestFn digest,
               void* digest_context)
    : buffer_(buffer), capacity_(capacity), digest_(digest),
      digest_context_(digest_context) {}

Volume::~Volume() { Wipe(); }

void Volume::Wipe() {
  if (buffer_ != nullptr) {
    volatile std::uint8_t* bytes = buffer_;
    for (std::size_t i = 0; i < capacity_; ++i) bytes[i] = 0;
  }
  volatile std::uint8_t* digest = expected_sha256_;
  for (std::size_t i = 0; i < sizeof(expected_sha256_); ++i) digest[i] = 0;
  status_.state = State::kEmpty;
  status_.size = 0;
  status_.received = 0;
  volatile std::uint8_t* metadata = reinterpret_cast<volatile std::uint8_t*>(entries_);
  for (std::size_t i = 0; i < sizeof(entries_); ++i) metadata[i] = 0;
  entry_count_ = 0;
  file_set_ = false;
}

Error Volume::Fail(Error error) {
  Wipe();
  status_.error = error;
  return error;
}

Error Volume::Begin(std::uint32_t length,
                    const std::uint8_t expected_sha256[32]) {
  return BeginRaw(length, expected_sha256, false);
}

Error Volume::BeginSet(std::uint32_t length,
                       const std::uint8_t expected_sha256[32]) {
  return BeginRaw(length, expected_sha256, true);
}

Error Volume::BeginRaw(std::uint32_t length,
                       const std::uint8_t expected_sha256[32], bool file_set) {
  if (status_.state == State::kReceiving) return Fail(Error::kBusy);
  Wipe();  // Clear-before-replace: previous published bytes are withdrawn.
  if (length > (file_set ? kMaximumBundleBytes : kMaximumFileBytes) ||
      (file_set && length == 0)) return Fail(Error::kLimit);
  if (buffer_ == nullptr || capacity_ < length) return Fail(Error::kMemory);
  if (digest_ == nullptr || expected_sha256 == nullptr) return Fail(Error::kUnavailable);
  std::memcpy(expected_sha256_, expected_sha256, sizeof(expected_sha256_));
  status_ = {State::kReceiving, Error::kOk, length, 0};
  file_set_ = file_set;
  return Error::kOk;
}

Error Volume::Chunk(std::uint32_t offset, const std::uint8_t* bytes,
                    std::size_t length) {
  if (status_.state == State::kPublished) {
    status_.error = Error::kOrder;
    return Error::kOrder;
  }
  if (status_.state != State::kReceiving || offset != status_.received)
    return Fail(Error::kOrder);
  if (length == 0 || length > kMaximumChunkBytes ||
      length > status_.size - status_.received || bytes == nullptr)
    return Fail(Error::kLimit);
  std::memcpy(buffer_ + offset, bytes, length);
  status_.received += static_cast<std::uint32_t>(length);
  return Error::kOk;
}

Error Volume::Commit() {
  return CommitRaw(false);
}

Error Volume::CommitSet() {
  return CommitRaw(true);
}

bool Volume::ParseManifest() {
  if (status_.size == 0) return false;
  const std::uint8_t count = buffer_[0];
  if (count == 0 || count > kMaximumFiles) return false;
  std::uint32_t cursor = 1;
  std::uint32_t content_bytes = 0;
  std::uint32_t next_cluster = 2;
  for (std::uint8_t i = 0; i < count; ++i) {
    if (cursor >= status_.size) return false;
    const std::uint8_t name_length = buffer_[cursor++];
    if (name_length == 0 || name_length > kMaximumNameBytes ||
        static_cast<std::uint64_t>(cursor) + name_length + 4 > status_.size ||
        !AllowedName(buffer_ + cursor, name_length)) return false;
    for (std::uint8_t j = 0; j < i; ++j) {
      const Entry& previous = entries_[j];
      if (previous.name_length != name_length) continue;
      bool duplicate = true;
      for (std::uint8_t n = 0; n < name_length; ++n)
        duplicate &= Upper(buffer_[previous.name_offset + n]) ==
                     Upper(buffer_[cursor + n]);
      if (duplicate) return false;
    }
    Entry& entry = entries_[i];
    entry.name_offset = cursor;
    entry.name_length = name_length;
    entry.lfn_entries = static_cast<std::uint8_t>((name_length + 12) / 13);
    cursor += name_length;
    entry.size = Get32(buffer_ + cursor);
    cursor += 4;
    if (entry.size > kMaximumFileBytes - content_bytes) return false;
    content_bytes += entry.size;
    entry.clusters = static_cast<std::uint16_t>((entry.size + 511) / 512);
    if (entry.clusters != 0) {
      entry.first_cluster = static_cast<std::uint16_t>(next_cluster);
      next_cluster += entry.clusters;
    }
    // The tilde cannot occur in an accepted long name, so these aliases can
    // neither collide with each other nor with an accepted 8.3 name.
    const std::uint8_t serial = static_cast<std::uint8_t>(i + 1);
    std::memcpy(entry.alias, "KF00~000DAT", 11);
    entry.alias[5] = static_cast<std::uint8_t>('0' + serial / 100);
    entry.alias[6] = static_cast<std::uint8_t>('0' + (serial / 10) % 10);
    entry.alias[7] = static_cast<std::uint8_t>('0' + serial % 10);
  }
  if (status_.size - cursor != content_bytes ||
      next_cluster > kDataSectors + 2) return false;
  for (std::uint8_t i = 0; i < count; ++i) {
    entries_[i].data_offset = cursor;
    cursor += entries_[i].size;
  }
  entry_count_ = count;
  return true;
}

Error Volume::CommitRaw(bool file_set) {
  if (status_.state == State::kPublished) {
    status_.error = Error::kOrder;
    return Error::kOrder;
  }
  if (status_.state != State::kReceiving || status_.received != status_.size ||
      file_set_ != file_set)
    return Fail(Error::kOrder);
  std::array<std::uint8_t, 32> actual{};
  if (!digest_(buffer_, status_.size, actual.data(), digest_context_)) {
    actual.fill(0);
    return Fail(Error::kUnavailable);
  }
  std::uint8_t difference = 0;
  for (std::size_t i = 0; i < actual.size(); ++i)
    difference |= actual[i] ^ expected_sha256_[i];
  actual.fill(0);
  if (difference != 0) return Fail(Error::kDigest);
  if (file_set) {
    if (!ParseManifest()) return Fail(Error::kLimit);
  } else {
    entry_count_ = 1;
    entries_[0].size = status_.size;
    entries_[0].name_length = 11;
    entries_[0].clusters = static_cast<std::uint16_t>((status_.size + 511) / 512);
    entries_[0].first_cluster = entries_[0].clusters == 0 ? 0 : 2;
    std::memcpy(entries_[0].alias, "MESSAGE TXT", 11);
  }
  volatile std::uint8_t* expected = expected_sha256_;
  for (std::size_t i = 0; i < sizeof(expected_sha256_); ++i) expected[i] = 0;
  status_.state = State::kPublished;
  status_.error = Error::kOk;
  return Error::kOk;
}

FileSetStatus Volume::SetStatus(std::uint8_t index) const {
  FileSetStatus result{};
  result.state = status_.state;
  result.error = status_.error;
  result.wire_size = status_.size;
  result.received = status_.received;
  result.count = status_.state == State::kPublished ? entry_count_ : 0;
  if (index != 255) {
    if (status_.state != State::kPublished || index >= entry_count_) {
      result.error = Error::kLimit;
    } else {
      const Entry& entry = entries_[index];
      result.has_entry = true;
      result.index = index;
      result.name_length = entry.name_length;
      result.name = file_set_ ? buffer_ + entry.name_offset
                              : reinterpret_cast<const std::uint8_t*>("MESSAGE.TXT");
      result.size = entry.size;
    }
  }
  return result;
}

Error Volume::Clear() {
  Wipe();
  status_.error = Error::kOk;
  return Error::kOk;
}

void Volume::Disconnect() { Clear(); }

std::uint16_t Volume::FatValue(std::uint32_t cluster) const {
  if (cluster == 0) return 0xFF8;
  if (cluster == 1) return 0xFFF;
  for (std::uint8_t i = 0; i < entry_count_; ++i) {
    const Entry& entry = entries_[i];
    if (entry.clusters != 0 && cluster >= entry.first_cluster &&
        cluster < static_cast<std::uint32_t>(entry.first_cluster) + entry.clusters)
      return cluster + 1 == static_cast<std::uint32_t>(entry.first_cluster) +
                                    entry.clusters
                 ? 0xFFF : static_cast<std::uint16_t>(cluster + 1);
  }
  return 0;
}

void Volume::RootEntry(std::uint32_t index, std::uint8_t output[32]) const {
  std::memset(output, 0, 32);
  if (index == 0) {
    std::memcpy(output, "KEYFERRY   ", 11);
    output[11] = 0x08;
    return;
  }
  --index;
  for (std::uint8_t i = 0; i < entry_count_; ++i) {
    const Entry& entry = entries_[i];
    const std::uint32_t count = file_set_ ? entry.lfn_entries + 1 : 1;
    if (index >= count) {
      index -= count;
      continue;
    }
    if (index == count - 1) {
      std::memcpy(output, entry.alias, 11);
      output[11] = 0x20;
      Put16(output + 16, 0x0021);  // Fixed valid 1980-01-01 date.
      Put16(output + 18, 0x0021);
      Put16(output + 24, 0x0021);
      Put16(output + 26, entry.first_cluster);
      Put32(output + 28, entry.size);
      return;
    }
    const std::uint32_t ordinal = entry.lfn_entries - index;
    output[0] = static_cast<std::uint8_t>(ordinal |
                    (index == 0 ? 0x40 : 0));
    output[11] = 0x0F;
    output[13] = AliasChecksum(entry.alias);
    constexpr std::uint8_t offsets[13] = {
        1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
    for (std::uint32_t n = 0; n < 13; ++n) {
      const std::uint32_t name_index = (ordinal - 1) * 13 + n;
      const std::uint16_t character =
          name_index < entry.name_length
              ? buffer_[entry.name_offset + name_index]
              : name_index == entry.name_length ? 0 : 0xFFFF;
      Put16(output + offsets[n], character);
    }
    return;
  }
}

void Volume::Sector(std::uint32_t lba, std::uint8_t output[kBlockBytes]) const {
  std::memset(output, 0, kBlockBytes);
  if (lba == 0) {
    output[0] = 0xEB; output[1] = 0x3C; output[2] = 0x90;
    std::memcpy(output + 3, "KEYFERRY", 8);
    Put16(output + 11, kBlockBytes);
    output[13] = 1;  // One sector per cluster.
    Put16(output + 14, 1);  // Reserved sectors.
    output[16] = 2;  // Identical FAT copies.
    Put16(output + 17, static_cast<std::uint16_t>(kRootEntries));
    Put16(output + 19, kBlockCount);
    output[21] = 0xF8;
    Put16(output + 22, static_cast<std::uint16_t>(kFatSectors));
    Put16(output + 24, 1);
    Put16(output + 26, 1);
    output[36] = 0x80; output[38] = 0x29;
    Put32(output + 39, 0x4B465259);
    std::memcpy(output + 43, "KEYFERRY   ", 11);
    std::memcpy(output + 54, "FAT12   ", 8);
    output[510] = 0x55; output[511] = 0xAA;
  } else if (lba >= 1 && lba < kRootSector) {
    const std::uint32_t fat_sector = (lba - 1) % kFatSectors;
    for (std::uint32_t i = 0; i < kBlockBytes; ++i) {
      const std::uint32_t fat_index = fat_sector * kBlockBytes + i;
      if (fat_index >= kFatBytes) break;
      const std::uint32_t even_cluster = (fat_index / 3) * 2;
      const auto even = FatValue(even_cluster);
      const auto odd = FatValue(even_cluster + 1);
      switch (fat_index % 3) {
        case 0: output[i] = static_cast<std::uint8_t>(even); break;
        case 1: output[i] = static_cast<std::uint8_t>((even >> 8) | (odd << 4)); break;
        default: output[i] = static_cast<std::uint8_t>(odd >> 4); break;
      }
    }
  } else if (lba >= kRootSector && lba < kDataStartSector) {
    const std::uint32_t start = (lba - kRootSector) * 16;
    for (std::uint32_t i = 0; i < 16; ++i)
      RootEntry(start + i, output + 32 * i);
  } else {
    const std::uint32_t cluster = lba - kDataStartSector + 2;
    for (std::uint8_t i = 0; i < entry_count_; ++i) {
      const Entry& entry = entries_[i];
      if (entry.clusters == 0 || cluster < entry.first_cluster ||
          cluster >= static_cast<std::uint32_t>(entry.first_cluster) +
                         entry.clusters) continue;
      const std::uint32_t offset = (cluster - entry.first_cluster) * kBlockBytes;
      if (offset < entry.size) {
        const std::size_t count = std::min<std::size_t>(kBlockBytes,
                                                       entry.size - offset);
        std::memcpy(output, buffer_ + entry.data_offset + offset, count);
      }
      break;
    }
  }
}

bool Volume::Read(std::uint32_t lba, std::uint32_t offset,
                  std::uint8_t* output, std::size_t length) const {
  if (!Ready() || output == nullptr || lba >= kBlockCount ||
      offset >= kBlockBytes || length == 0 || length > kBlockBytes - offset)
    return false;
  std::array<std::uint8_t, kBlockBytes> sector{};
  Sector(lba, sector.data());
  std::memcpy(output, sector.data() + offset, length);
  return true;
}

}  // namespace keyferry::file_handoff
