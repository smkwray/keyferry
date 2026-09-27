#include "keyferry/file_handoff.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace file = keyferry::file_handoff;

bool TestDigest(const std::uint8_t* data, std::size_t length,
                std::uint8_t output[32], void* context) {
  if (*static_cast<bool*>(context)) return false;
  std::memset(output, 0, 32);
  for (std::size_t i = 0; i < length; ++i) {
    output[i % 32] ^= static_cast<std::uint8_t>(data[i] + i);
  }
  output[31] ^= static_cast<std::uint8_t>(length);
  return true;
}

std::array<std::uint8_t, 32> Digest(const std::vector<std::uint8_t>& data) {
  bool fail = false;
  std::array<std::uint8_t, 32> digest{};
  assert(TestDigest(data.data(), data.size(), digest.data(), &fail));
  return digest;
}

std::uint16_t Le16(const std::uint8_t* bytes) {
  return static_cast<std::uint16_t>(bytes[0] | bytes[1] << 8);
}

std::uint32_t Le32(const std::uint8_t* bytes) {
  return static_cast<std::uint32_t>(bytes[0]) |
         static_cast<std::uint32_t>(bytes[1]) << 8 |
         static_cast<std::uint32_t>(bytes[2]) << 16 |
         static_cast<std::uint32_t>(bytes[3]) << 24;
}

std::uint16_t FatEntry(const std::uint8_t* fat, std::size_t cluster) {
  const std::size_t at = cluster + cluster / 2;
  return cluster & 1U ? static_cast<std::uint16_t>((fat[at] >> 4) | fat[at + 1] << 4)
                      : static_cast<std::uint16_t>(fat[at] | (fat[at + 1] & 0x0F) << 8);
}

void CheckPublished(file::Volume& volume, const std::vector<std::uint8_t>& expected) {
  assert(volume.Ready());
  assert(volume.Status().state == file::State::kPublished);
  assert(volume.Status().size == expected.size());
  std::array<std::uint8_t, file::kBlockBytes> boot{}, root{}, sector{};
  std::vector<std::uint8_t> fat1(file::kFatSectors * file::kBlockBytes);
  std::vector<std::uint8_t> fat2(fat1.size());
  assert(volume.Read(0, 0, boot.data(), boot.size()));
  for (std::uint32_t i = 0; i < file::kFatSectors; ++i) {
    assert(volume.Read(1 + i, 0, fat1.data() + i * file::kBlockBytes,
                       file::kBlockBytes));
    assert(volume.Read(1 + file::kFatSectors + i, 0,
                       fat2.data() + i * file::kBlockBytes, file::kBlockBytes));
  }
  assert(volume.Read(file::kRootSector, 0, root.data(), root.size()));
  assert(boot[0] == 0xEB && boot[510] == 0x55 && boot[511] == 0xAA);
  assert(Le16(boot.data() + 11) == 512 && boot[13] == 1 &&
         Le16(boot.data() + 14) == 1 && boot[16] == 2 &&
         Le16(boot.data() + 17) == file::kRootEntries &&
         Le16(boot.data() + 19) == file::kBlockCount &&
         boot[21] == 0xF8 &&
         Le16(boot.data() + 22) == file::kFatSectors);
  assert(std::memcmp(boot.data() + 43, "KEYFERRY   ", 11) == 0);
  assert(std::memcmp(boot.data() + 54, "FAT12   ", 8) == 0);
  assert(fat1 == fat2);
  assert(fat1[0] == 0xF8 && FatEntry(fat1.data(), 0) == 0xFF8 &&
         FatEntry(fat1.data(), 1) == 0xFFF);
  assert(std::memcmp(root.data(), "KEYFERRY   ", 11) == 0 && root[11] == 0x08);
  assert(std::memcmp(root.data() + 32, "MESSAGE TXT", 11) == 0 && root[43] == 0x20);
  assert(Le32(root.data() + 60) == expected.size());
  const std::size_t clusters = (expected.size() + 511) / 512;
  assert(Le16(root.data() + 58) == (clusters == 0 ? 0 : 2));
  for (std::size_t i = 0; i < clusters; ++i) {
    assert(FatEntry(fat1.data(), i + 2) ==
           (i + 1 == clusters ? 0xFFF : i + 3));
  }
  if (clusters < file::kDataSectors) assert(FatEntry(fat1.data(), clusters + 2) == 0);
  if (clusters >= 340) {
    // Cluster 341's packed FAT12 entry crosses the 512-byte sector boundary.
    assert(FatEntry(fat1.data(), 341) ==
           (clusters == 340 ? 0xFFF : 342));
  }
  for (std::size_t i = 0; i < expected.size(); i += file::kBlockBytes) {
    const auto count = std::min<std::size_t>(file::kBlockBytes, expected.size() - i);
    assert(volume.Read(file::kDataStartSector + static_cast<std::uint32_t>(i / 512),
                       0, sector.data(), sector.size()));
    assert(std::equal(expected.begin() + i, expected.begin() + i + count,
                      sector.begin()));
    assert(std::all_of(sector.begin() + count, sector.end(),
                       [](auto value) { return value == 0; }));
  }
  std::array<std::uint8_t, 16> edge{};
  assert(volume.Read(file::kDataStartSector, 496, edge.data(), edge.size()));
  assert(!volume.Read(file::kBlockCount, 0, edge.data(), edge.size()));
  assert(!volume.Read(file::kDataStartSector, 500, edge.data(), edge.size()));
  if (!expected.empty()) {
    const auto last = expected.size() - 1;
    std::uint8_t value = 0;
    assert(volume.Read(file::kDataStartSector + static_cast<std::uint32_t>(last / 512),
                       static_cast<std::uint32_t>(last % 512), &value, 1));
    assert(value == expected[last]);
  }
}

void TestBoundariesAndWipe() {
  std::array<std::uint8_t, file::kMaximumFileBytes> storage{};
  bool digest_fails = false;
  file::Volume volume(storage.data(), storage.size(), TestDigest, &digest_fails);
  std::uint8_t byte = 0xA5;
  assert(!volume.Ready() && !volume.Read(0, 0, &byte, 1));
  assert(byte == 0xA5);
  for (const std::size_t length : std::array<std::size_t, 8>{
           0, 1, 511, 512, 513, 340 * 512, 341 * 512, file::kMaximumFileBytes}) {
    std::vector<std::uint8_t> data(length);
    for (std::size_t i = 0; i < length; ++i)
      data[i] = static_cast<std::uint8_t>(i * 17 + 3);
    const auto digest = Digest(data);
    assert(volume.Begin(static_cast<std::uint32_t>(length), digest.data()) == file::Error::kOk);
    assert(!volume.Ready() && !volume.Read(0, 0, &byte, 1));
    for (std::size_t i = 0; i < length;) {
      const std::size_t count = std::min<std::size_t>(200, length - i);
      assert(volume.Chunk(static_cast<std::uint32_t>(i), data.data() + i, count) ==
             file::Error::kOk);
      i += count;
    }
    assert(volume.Commit() == file::Error::kOk);
    CheckPublished(volume, data);
    assert(volume.Chunk(0, data.data(), 1) == file::Error::kOrder);
    assert(volume.Commit() == file::Error::kOrder);
    CheckPublished(volume, data);
  }
  assert(volume.Clear() == file::Error::kOk);
  assert(!volume.Ready());
  assert(std::all_of(storage.begin(), storage.end(), [](auto value) { return value == 0; }));
}

void TestFailurePaths() {
  std::array<std::uint8_t, file::kMaximumFileBytes> storage{};
  bool digest_fails = false;
  file::Volume volume(storage.data(), storage.size(), TestDigest, &digest_fails);
  const std::vector<std::uint8_t> data{1, 2, 3};
  auto digest = Digest(data);
  file::Volume too_small(storage.data(), storage.size() - 1, TestDigest,
                         &digest_fails);
  assert(too_small.Begin(storage.size(), digest.data()) == file::Error::kMemory);
  assert(too_small.Begin(1, digest.data()) == file::Error::kOk);
  too_small.Clear();
  assert(volume.Begin(file::kMaximumFileBytes + 1, digest.data()) == file::Error::kLimit);
  assert(volume.Status().error == file::Error::kLimit && !volume.Ready());
  assert(volume.Begin(3, digest.data()) == file::Error::kOk);
  assert(volume.Begin(3, digest.data()) == file::Error::kBusy);
  assert(volume.Begin(3, digest.data()) == file::Error::kOk);
  assert(volume.Chunk(1, data.data(), data.size()) == file::Error::kOrder);
  assert(volume.Status().received == 0 && !volume.Ready());
  assert(volume.Begin(3, digest.data()) == file::Error::kOk);
  assert(volume.Chunk(0, data.data(), 2) == file::Error::kOk);
  assert(volume.Commit() == file::Error::kOrder);
  assert(std::all_of(storage.begin(), storage.end(), [](auto value) { return value == 0; }));
  digest[0] ^= 1;
  assert(volume.Begin(3, digest.data()) == file::Error::kOk);
  assert(volume.Chunk(0, data.data(), 3) == file::Error::kOk);
  assert(volume.Commit() == file::Error::kDigest);
  assert(!volume.Ready() && volume.Status().error == file::Error::kDigest);
  digest = Digest(data);
  assert(volume.Begin(3, digest.data()) == file::Error::kOk);
  assert(volume.Chunk(0, data.data(), 3) == file::Error::kOk);
  digest_fails = true;
  assert(volume.Commit() == file::Error::kUnavailable);
  digest_fails = false;
  assert(volume.Begin(3, digest.data()) == file::Error::kOk);
  assert(volume.Chunk(0, data.data(), 3) == file::Error::kOk);
  assert(volume.Commit() == file::Error::kOk);
  assert(volume.Begin(3, digest.data()) == file::Error::kOk);  // Replaces old snapshot.
  assert(!volume.Ready());
  volume.Disconnect();
  assert(!volume.Ready());
  assert(std::all_of(storage.begin(), storage.end(), [](auto value) { return value == 0; }));
}

struct SetFile {
  std::string name;
  std::vector<std::uint8_t> bytes;
};

std::vector<std::uint8_t> Bundle(const std::vector<SetFile>& files) {
  std::vector<std::uint8_t> bundle{static_cast<std::uint8_t>(files.size())};
  for (const auto& item : files) {
    bundle.push_back(static_cast<std::uint8_t>(item.name.size()));
    bundle.insert(bundle.end(), item.name.begin(), item.name.end());
    const auto size = static_cast<std::uint32_t>(item.bytes.size());
    for (unsigned i = 0; i < 4; ++i)
      bundle.push_back(static_cast<std::uint8_t>(size >> (8 * i)));
  }
  for (const auto& item : files)
    bundle.insert(bundle.end(), item.bytes.begin(), item.bytes.end());
  return bundle;
}

void UploadSet(file::Volume& volume, const std::vector<std::uint8_t>& bundle) {
  const auto digest = Digest(bundle);
  assert(volume.BeginSet(static_cast<std::uint32_t>(bundle.size()), digest.data()) ==
         file::Error::kOk);
  for (std::size_t offset = 0; offset < bundle.size();) {
    const auto length = std::min<std::size_t>(200, bundle.size() - offset);
    assert(volume.Chunk(static_cast<std::uint32_t>(offset), bundle.data() + offset,
                        length) == file::Error::kOk);
    offset += length;
  }
  assert(volume.CommitSet() == file::Error::kOk);
}

void TestSetManifestRejections() {
  std::vector<std::uint8_t> storage(file::kMaximumBundleBytes);
  bool fails = false;
  file::Volume volume(storage.data(), storage.size(), TestDigest, &fails);
  for (const std::string& name : std::vector<std::string>{
           "CON .txt", "lpt1.cfg", "a/b", " a", "a.",
           "bad~name", "", std::string(65, 'z')}) {
    const auto bundle = Bundle({{name, {0xA5}}});
    const auto digest = Digest(bundle);
    assert(volume.BeginSet(bundle.size(), digest.data()) == file::Error::kOk);
    for (std::size_t at = 0; at < bundle.size();) {
      const auto n = std::min<std::size_t>(200, bundle.size() - at);
      assert(volume.Chunk(at, bundle.data() + at, n) == file::Error::kOk);
      at += n;
    }
    assert(volume.CommitSet() == file::Error::kLimit);
    assert(!volume.Ready() && std::all_of(storage.begin(), storage.end(),
                                          [](auto value) { return value == 0; }));
  }
  for (const auto& files : {std::vector<SetFile>{{"abc.txt", {1}}, {"ABC.TXT", {2}}},
                            std::vector<SetFile>{},
                            std::vector<SetFile>(file::kMaximumFiles + 1,
                                                 {"ok.txt", {1}}),
                            std::vector<SetFile>{{"big.bin",
                                                  std::vector<std::uint8_t>(
                                                      file::kMaximumFileBytes + 1)}}}) {
    const auto bundle = Bundle(files);
    const auto digest = Digest(bundle);
    assert(volume.BeginSet(bundle.size(), digest.data()) == file::Error::kOk);
    for (std::size_t at = 0; at < bundle.size();) {
      const auto n = std::min<std::size_t>(200, bundle.size() - at);
      assert(volume.Chunk(at, bundle.data() + at, n) == file::Error::kOk);
      at += n;
    }
    assert(volume.CommitSet() == file::Error::kLimit);
  }
  auto truncated = Bundle({{"good.txt", {1, 2}}});
  truncated.pop_back();
  const auto truncated_digest = Digest(truncated);
  assert(volume.BeginSet(truncated.size(), truncated_digest.data()) == file::Error::kOk);
  assert(volume.Chunk(0, truncated.data(), truncated.size()) == file::Error::kOk);
  assert(volume.CommitSet() == file::Error::kLimit);
  const auto good = Bundle({{"config.yaml", {}}, {"note.txt", {1, 2}}});
  auto wrong_digest = Digest(good);
  wrong_digest[0] ^= 1;
  assert(volume.BeginSet(good.size(), wrong_digest.data()) == file::Error::kOk);
  assert(volume.Chunk(0, good.data(), good.size()) == file::Error::kOk);
  assert(volume.CommitSet() == file::Error::kDigest);
  UploadSet(volume, good);
  assert(volume.SetStatus(0).size == 0 && volume.SetStatus(1).size == 2);
  assert(volume.SetStatus(2).error == file::Error::kLimit);
  assert(volume.Chunk(0, good.data(), 1) == file::Error::kOrder);
  assert(volume.Commit() == file::Error::kOrder);
  assert(volume.Ready());
  const std::vector<std::uint8_t> legacy{9, 8, 7};
  const auto legacy_digest = Digest(legacy);
  assert(volume.Begin(legacy.size(), legacy_digest.data()) == file::Error::kOk);
  assert(volume.Chunk(0, legacy.data(), legacy.size()) == file::Error::kOk);
  assert(volume.Commit() == file::Error::kOk);
  const auto v2_view = volume.SetStatus(0);
  assert(v2_view.count == 1 && v2_view.has_entry &&
         v2_view.name_length == 11 &&
         std::memcmp(v2_view.name, "MESSAGE.TXT", 11) == 0 &&
         v2_view.size == legacy.size());
  assert(volume.Clear() == file::Error::kOk);
}

void TestGoldenBundle() {
  const auto bundle = Bundle({{"Note 1.txt", {'a', 'b', 'c'}},
                              {"blank.bin", {}}});
  const std::vector<std::uint8_t> expected{
      2, 10, 'N', 'o', 't', 'e', ' ', '1', '.', 't', 'x', 't',
      3, 0, 0, 0, 9, 'b', 'l', 'a', 'n', 'k', '.', 'b', 'i', 'n',
      0, 0, 0, 0, 'a', 'b', 'c'};
  assert(bundle == expected && bundle.size() == 33);
  std::vector<std::uint8_t> storage(bundle.size());
  bool fails = false;
  file::Volume volume(storage.data(), storage.size(), TestDigest, &fails);
  UploadSet(volume, bundle);
  assert(volume.SetStatus(255).count == 2);
  assert(volume.SetStatus(0).size == 3 && volume.SetStatus(1).size == 0);
  const auto single_empty = Bundle({{"A", {}}});
  assert(single_empty.size() == 7);
  UploadSet(volume, single_empty);
  const auto status = volume.SetStatus(0);
  assert(status.state == file::State::kPublished && status.error == file::Error::kOk &&
         status.wire_size == 7 && status.received == 7 && status.count == 1 &&
         status.has_entry && status.index == 0 && status.name_length == 1 &&
         status.name[0] == 'A' && status.size == 0);
}

void TestSetFilesystem(const char* bundle_path, const char* image_path) {
  std::vector<SetFile> files;
  for (unsigned i = 0; i < file::kMaximumFiles; ++i) {
    const std::size_t name_length =
        std::array<std::size_t, 5>{13, 26, 39, 52, 64}[i % 5];
    std::string name = "F" + std::to_string(i / 10) + std::to_string(i % 10) + "_";
    name.append(name_length - name.size() - 4, static_cast<char>('a' + i));
    name += ".txt";
    const std::size_t size = i == 0 ? file::kMaximumFileBytes - 15 : 1;
    std::vector<std::uint8_t> bytes(size);
    for (std::size_t j = 0; j < size; ++j)
      bytes[j] = static_cast<std::uint8_t>(i * 17 + j * 31);
    files.push_back({name, std::move(bytes)});
  }
  const auto bundle = Bundle(files);
  assert(bundle.size() <= file::kMaximumBundleBytes);
  std::vector<std::uint8_t> storage(file::kMaximumBundleBytes);
  bool fails = false;
  file::Volume volume(storage.data(), storage.size(), TestDigest, &fails);
  UploadSet(volume, bundle);
  const auto summary = volume.SetStatus(255);
  assert(summary.count == 16 && summary.wire_size == bundle.size());
  std::vector<std::uint8_t> image(file::kBlockCount * file::kBlockBytes);
  for (std::uint32_t lba = 0; lba < file::kBlockCount; ++lba)
    assert(volume.Read(lba, 0, image.data() + lba * file::kBlockBytes,
                       file::kBlockBytes));
  std::array<std::uint8_t, 17> partial{};
  for (const auto lba : {std::uint32_t{0}, std::uint32_t{1},
                         file::kRootSector + 1, file::kDataStartSector + 340,
                         file::kBlockCount - 1}) {
    assert(volume.Read(lba, 493, partial.data(), partial.size()));
    assert(std::memcmp(partial.data(),
                       image.data() + lba * file::kBlockBytes + 493,
                       partial.size()) == 0);
  }
  const auto* boot = image.data();
  assert(Le16(boot + 17) == file::kRootEntries);
  assert(Le16(boot + 19) == file::kBlockCount);
  const auto* fat = image.data() + file::kBlockBytes;
  const auto* root = image.data() + file::kRootSector * file::kBlockBytes;
  assert(FatEntry(fat, 341) == 342);
  std::size_t root_at = 1;
  std::uint32_t next_cluster = 2;
  for (unsigned i = 0; i < files.size(); ++i) {
    const auto entry = volume.SetStatus(static_cast<std::uint8_t>(i));
    assert(entry.has_entry && entry.index == i &&
           entry.name_length == files[i].name.size() &&
           std::memcmp(entry.name, files[i].name.data(), entry.name_length) == 0);
    const auto lfn_count = (files[i].name.size() + 12) / 13;
    std::string recovered(files[i].name.size(), '?');
    const auto* short_entry = root + (root_at + lfn_count) * 32;
    std::uint8_t checksum = 0;
    for (unsigned n = 0; n < 11; ++n)
      checksum = static_cast<std::uint8_t>(((checksum & 1) << 7) +
                                           (checksum >> 1) + short_entry[n]);
    for (std::size_t j = 0; j < lfn_count; ++j) {
      const auto* lfn = root + (root_at + j) * 32;
      const auto ordinal = static_cast<std::size_t>(lfn[0] & 0x1F);
      assert(ordinal == lfn_count - j && lfn[11] == 0x0F &&
             lfn[12] == 0 && lfn[13] == checksum && Le16(lfn + 26) == 0);
      assert((lfn[0] & 0x40) == (j == 0 ? 0x40 : 0));
      constexpr std::uint8_t at[13] =
          {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
      for (std::size_t k = 0; k < 13; ++k) {
        const auto name_at = (ordinal - 1) * 13 + k;
        const auto character = Le16(lfn + at[k]);
        if (name_at < recovered.size()) recovered[name_at] = static_cast<char>(character);
        else assert(character == (name_at == recovered.size() ? 0 : 0xFFFF));
      }
    }
    assert(recovered == files[i].name);
    assert(short_entry[11] == 0x20 && short_entry[4] == '~');
    assert(Le16(short_entry + 16) == 0x21 &&
           Le16(short_entry + 18) == 0x21 &&
           Le16(short_entry + 24) == 0x21);
    assert(Le32(short_entry + 28) == files[i].bytes.size());
    assert(Le16(short_entry + 26) == next_cluster);
    const auto clusters = (files[i].bytes.size() + 511) / 512;
    for (std::size_t c = 0; c < clusters; ++c) {
      const auto cluster = next_cluster + c;
      assert(FatEntry(fat, cluster) == (c + 1 == clusters ? 0xFFF : cluster + 1));
      const auto* data = image.data() +
                         (file::kDataStartSector + cluster - 2) * file::kBlockBytes;
      const auto offset = c * file::kBlockBytes;
      const auto length = std::min<std::size_t>(512, files[i].bytes.size() - offset);
      assert(std::memcmp(data, files[i].bytes.data() + offset, length) == 0);
      assert(std::all_of(data + length, data + 512,
                         [](auto value) { return value == 0; }));
    }
    next_cluster += clusters;
    root_at += lfn_count + 1;
  }
  assert(next_cluster == file::kDataSectors + 2);
  assert(root_at <= file::kRootEntries);
  auto save = [](const char* path, const std::vector<std::uint8_t>& bytes) {
    if (path == nullptr) return;
    FILE* output = std::fopen(path, "wb");
    assert(output != nullptr);
    assert(std::fwrite(bytes.data(), 1, bytes.size(), output) == bytes.size());
    assert(std::fclose(output) == 0);
  };
  save(bundle_path, bundle);
  save(image_path, image);
}

int main(int argc, char** argv) {
  TestBoundariesAndWipe();
  TestFailurePaths();
  TestSetManifestRejections();
  TestGoldenBundle();
  TestSetFilesystem(argc == 3 ? argv[1] : nullptr,
                    argc == 3 ? argv[2] : nullptr);
  std::puts("file_handoff_test: ok");
}
