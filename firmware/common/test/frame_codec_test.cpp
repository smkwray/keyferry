#include "frame_codec.h"
#include "keyferry_protocol_generated.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using keyferry::protocol::CodecError;
using keyferry::protocol::DecodedFrame;
namespace fs = std::filesystem;

static void require(bool ok, const std::string& msg) {
  if (!ok) {
    std::cerr << "frame_codec_test: FAIL: " << msg << "\n";
    std::exit(1);
  }
}

static std::string read_file(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// Value of "key" as a quoted string. Keys are unique across a vector file.
static std::string json_string(const std::string& s, const std::string& key) {
  const std::string anchor = "\"" + key + "\"";
  const auto at = s.find(anchor);
  require(at != std::string::npos, "missing key " + key);
  const auto q1 = s.find('"', at + anchor.size());
  const auto q2 = s.find('"', q1 + 1);
  require(q1 != std::string::npos && q2 != std::string::npos, "unterminated string for " + key);
  return s.substr(q1 + 1, q2 - q1 - 1);
}

// Value of "key" as an unquoted integer.
static std::uint64_t json_u64(const std::string& s, const std::string& key) {
  const std::string anchor = "\"" + key + "\"";
  const auto at = s.find(anchor);
  require(at != std::string::npos, "missing key " + key);
  const auto colon = s.find(':', at + anchor.size());
  return std::strtoull(s.c_str() + colon + 1, nullptr, 10);
}

static std::uint8_t hex_byte_field(const std::string& v) {
  return static_cast<std::uint8_t>(std::strtoul(v.c_str(), nullptr, 16));
}

static std::vector<std::uint8_t> parse_hex(const std::string& s) {
  require(s.size() % 2 == 0, "odd hex length");
  std::vector<std::uint8_t> out;
  out.reserve(s.size() / 2);
  for (std::size_t i = 0; i < s.size(); i += 2) {
    out.push_back(static_cast<std::uint8_t>(std::strtoul(s.substr(i, 2).c_str(), nullptr, 16)));
  }
  return out;
}

static std::string to_hex(const std::uint8_t* p, std::size_t n) {
  static const char* d = "0123456789abcdef";
  std::string out;
  out.reserve(n * 2);
  for (std::size_t i = 0; i < n; ++i) {
    out.push_back(d[p[i] >> 4]);
    out.push_back(d[p[i] & 0xf]);
  }
  return out;
}

static void check_primitives() {
  static_assert(keyferry::protocol::kMagic == 0x4248);
  static_assert(keyferry::protocol::kMaxDecodedFrame == 256);

  const std::array<std::uint8_t, 9> known = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
  require(keyferry::protocol::Crc16CcittFalse(known.data(), known.size()) == 0x29b1, "crc KAT");

  const std::array<std::uint8_t, 8> input = {0, 1, 2, 0, 0xff, 0, 3, 0};
  std::array<std::uint8_t, 32> encoded{};
  std::size_t encoded_length = 0;
  require(keyferry::protocol::CobsEncode(input.data(), input.size(), encoded.data(), encoded.size(),
                                         &encoded_length) == CodecError::kOk,
          "cobs encode");
  for (std::size_t i = 0; i < encoded_length; ++i) {
    require(encoded[i] != 0, "cobs output has zero");
  }
  std::array<std::uint8_t, 32> decoded{};
  std::size_t decoded_length = 0;
  require(keyferry::protocol::CobsDecode(encoded.data(), encoded_length, decoded.data(),
                                         decoded.size(), &decoded_length) == CodecError::kOk,
          "cobs decode");
  require(decoded_length == input.size(), "cobs roundtrip length");
  for (std::size_t i = 0; i < input.size(); ++i) {
    require(decoded[i] == input[i], "cobs roundtrip byte");
  }
}

static fs::path vectors_dir() {
  // __FILE__ = .../firmware/common/test/frame_codec_test.cpp
  fs::path self(__FILE__);
  return self.parent_path().parent_path().parent_path().parent_path() / "protocol" / "vectors";
}

static int check_vectors() {
  const fs::path dir = vectors_dir();
  require(fs::exists(dir), "vectors dir not found: " + dir.string());
  int checked = 0;
  for (const auto& entry : fs::directory_iterator(dir)) {
    if (entry.path().extension() != ".json") {
      continue;
    }
    const std::string src = read_file(entry.path());
    const std::string name = json_string(src, "name");

    const std::uint8_t major = static_cast<std::uint8_t>(json_u64(src, "major"));
    const std::uint8_t minor = static_cast<std::uint8_t>(json_u64(src, "minor"));
    const std::uint8_t mtype = hex_byte_field(json_string(src, "message_type"));
    const std::uint8_t flags = hex_byte_field(json_string(src, "flags"));
    const std::uint32_t seq = static_cast<std::uint32_t>(json_u64(src, "sequence"));
    const std::vector<std::uint8_t> payload = parse_hex(json_string(src, "payload_hex"));
    const std::string decoded_hex = json_string(src, "decoded_hex");
    const std::string wire_hex = json_string(src, "wire_hex");

    std::array<std::uint8_t, 256> dbuf{};
    std::size_t dlen = 0;
    require(keyferry::protocol::EncodeDecodedFrame(major, minor, mtype, flags, seq, payload.data(),
                                                   payload.size(), dbuf.data(), dbuf.size(),
                                                   &dlen) == CodecError::kOk,
            "encode decoded " + name);
    require(to_hex(dbuf.data(), dlen) == decoded_hex, "decoded_hex mismatch " + name);

    std::array<std::uint8_t, 300> wbuf{};
    std::size_t wlen = 0;
    require(keyferry::protocol::EncodeWireFrame(major, minor, mtype, flags, seq, payload.data(),
                                                payload.size(), wbuf.data(), wbuf.size(),
                                                &wlen) == CodecError::kOk,
            "encode wire " + name);
    require(to_hex(wbuf.data(), wlen) == wire_hex, "wire_hex mismatch " + name);

    const std::vector<std::uint8_t> wire = parse_hex(wire_hex);
    std::array<std::uint8_t, 256> scratch{};
    DecodedFrame out{};
    require(keyferry::protocol::DecodeWireFrame(wire.data(), wire.size(), scratch.data(),
                                                scratch.size(), &out) == CodecError::kOk,
            "decode wire " + name);
    require(out.major == major && out.minor == minor && out.message_type == mtype &&
                out.flags == flags && out.sequence == seq && out.payload_length == payload.size(),
            "decoded fields " + name);
    for (std::size_t i = 0; i < payload.size(); ++i) {
      require(out.payload[i] == payload[i], "decoded payload byte " + name);
    }
    ++checked;
  }
  return checked;
}

// The C++ decoders are what run on the ESP/AVR, so a malformed UART frame must
// never crash or overflow the fixed buffers. Deterministic xorshift, no deps.
static void fuzz_frame_decoders() {
  std::uint64_t state = 0x0BADF00DCAFE1111ull;
  auto next = [&state]() {
    std::uint64_t x = state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state = x;
    return x * 0x2545F4914F6CDD1Dull;
  };
  std::array<std::uint8_t, 320> raw{};
  std::array<std::uint8_t, 256> scratch{};
  for (int iter = 0; iter < 1000000; ++iter) {
    const std::size_t len = static_cast<std::size_t>(next() % (raw.size() + 1));
    for (std::size_t i = 0; i < len; ++i) {
      raw[i] = (next() & 3) == 0 ? 0 : static_cast<std::uint8_t>(next() >> 24);
    }
    DecodedFrame out{};
    if (keyferry::protocol::DecodeWireFrame(raw.data(), len, scratch.data(), scratch.size(), &out) ==
        CodecError::kOk) {
      require(out.payload_length <= 242, "fuzz wire payload bound");
    }
    if (keyferry::protocol::DecodeDecodedFrame(raw.data(), len, &out) == CodecError::kOk) {
      require(out.payload_length <= 242, "fuzz decoded payload bound");
    }
  }
}

int main() {
  check_primitives();
  const int n = check_vectors();
  require(n >= 4, "expected at least the seed vectors");
  fuzz_frame_decoders();
  std::cout << "frame_codec_test: ok (" << n << " vectors, 1M fuzz)\n";
  return 0;
}
