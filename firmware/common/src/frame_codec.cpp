#include "frame_codec.h"

namespace keyferry::protocol {

std::uint16_t Crc16CcittFalse(const std::uint8_t* data, std::size_t length) {
  std::uint16_t crc = 0xffff;
  for (std::size_t i = 0; i < length; ++i) {
    crc ^= static_cast<std::uint16_t>(data[i]) << 8;
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc & 0x8000) != 0
                ? static_cast<std::uint16_t>((crc << 1) ^ 0x1021)
                : static_cast<std::uint16_t>(crc << 1);
    }
  }
  return crc;
}

CodecError CobsEncode(const std::uint8_t* input,
                      std::size_t input_length,
                      std::uint8_t* output,
                      std::size_t output_capacity,
                      std::size_t* output_length) {
  if (output_capacity == 0 || output == nullptr || output_length == nullptr) {
    return CodecError::kOutputTooSmall;
  }

  std::size_t read_index = 0;
  std::size_t write_index = 1;
  std::size_t code_index = 0;
  std::uint8_t code = 1;

  while (read_index < input_length) {
    const std::uint8_t value = input[read_index++];
    if (value == 0) {
      output[code_index] = code;
      code_index = write_index;
      if (write_index >= output_capacity) {
        return CodecError::kOutputTooSmall;
      }
      output[write_index++] = 0;
      code = 1;
      continue;
    }

    if (write_index >= output_capacity) {
      return CodecError::kOutputTooSmall;
    }
    output[write_index++] = value;
    ++code;
    if (code == 0xff) {
      output[code_index] = code;
      code_index = write_index;
      if (write_index >= output_capacity) {
        return CodecError::kOutputTooSmall;
      }
      output[write_index++] = 0;
      code = 1;
    }
  }

  output[code_index] = code;
  *output_length = write_index;
  return CodecError::kOk;
}

CodecError CobsDecode(const std::uint8_t* input,
                      std::size_t input_length,
                      std::uint8_t* output,
                      std::size_t output_capacity,
                      std::size_t* output_length) {
  if (input_length == 0 || input == nullptr || output_length == nullptr) {
    return CodecError::kEmptyCobs;
  }

  std::size_t read_index = 0;
  std::size_t write_index = 0;
  while (read_index < input_length) {
    const std::uint8_t code = input[read_index++];
    if (code == 0) {
      return CodecError::kMalformedCobs;
    }
    const std::size_t copy_length = static_cast<std::size_t>(code - 1);
    if (read_index + copy_length > input_length) {
      return CodecError::kMalformedCobs;
    }
    if (write_index + copy_length > output_capacity) {
      return CodecError::kOutputTooSmall;
    }
    for (std::size_t i = 0; i < copy_length; ++i) {
      output[write_index++] = input[read_index++];
    }
    if (code != 0xff && read_index < input_length) {
      if (write_index >= output_capacity) {
        return CodecError::kOutputTooSmall;
      }
      output[write_index++] = 0;
    }
  }

  *output_length = write_index;
  return CodecError::kOk;
}


namespace {
constexpr std::size_t kHeader = 12;
constexpr std::size_t kCrc = 2;
constexpr std::size_t kMinDecoded = kHeader + kCrc;             // 14
constexpr std::size_t kMaxDecoded = 256;
constexpr std::size_t kMaxPayload = kMaxDecoded - kMinDecoded;  // 242

std::uint32_t ReadLe32(const std::uint8_t* p) {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}
void WriteLe32(std::uint8_t* p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>(v);
  p[1] = static_cast<std::uint8_t>(v >> 8);
  p[2] = static_cast<std::uint8_t>(v >> 16);
  p[3] = static_cast<std::uint8_t>(v >> 24);
}
}  // namespace

CodecError EncodeDecodedFrame(std::uint8_t major, std::uint8_t minor, std::uint8_t message_type,
                              std::uint8_t flags, std::uint32_t sequence, const std::uint8_t* payload,
                              std::size_t payload_length, std::uint8_t* output,
                              std::size_t output_capacity, std::size_t* output_length) {
  if (payload_length > kMaxPayload) {
    return CodecError::kPayloadTooLarge;
  }
  const std::size_t total = kHeader + payload_length + kCrc;
  if (output == nullptr || output_length == nullptr || output_capacity < total) {
    return CodecError::kOutputTooSmall;
  }
  output[0] = 0x48;  // 'H'
  output[1] = 0x42;  // 'B'
  output[2] = major;
  output[3] = minor;
  output[4] = message_type;
  output[5] = flags;
  WriteLe32(output + 6, sequence);
  output[10] = static_cast<std::uint8_t>(payload_length);
  output[11] = static_cast<std::uint8_t>(payload_length >> 8);
  for (std::size_t i = 0; i < payload_length; ++i) {
    output[kHeader + i] = payload[i];
  }
  const std::uint16_t crc = Crc16CcittFalse(output, kHeader + payload_length);
  output[kHeader + payload_length] = static_cast<std::uint8_t>(crc);
  output[kHeader + payload_length + 1] = static_cast<std::uint8_t>(crc >> 8);
  *output_length = total;
  return CodecError::kOk;
}

CodecError DecodeDecodedFrame(const std::uint8_t* input, std::size_t input_length, DecodedFrame* out) {
  if (out == nullptr) {
    return CodecError::kOutputTooSmall;
  }
  if (input_length < kMinDecoded) {
    return CodecError::kFrameTooShort;
  }
  if (input_length > kMaxDecoded) {
    return CodecError::kFrameTooLarge;
  }
  if (!(input[0] == 0x48 && input[1] == 0x42)) {
    return CodecError::kBadMagic;
  }
  const std::size_t declared =
      static_cast<std::size_t>(input[10]) | (static_cast<std::size_t>(input[11]) << 8);
  const std::size_t actual = input_length - kHeader - kCrc;
  if (declared != actual) {
    return CodecError::kLengthMismatch;
  }
  const std::uint16_t expected = Crc16CcittFalse(input, input_length - kCrc);
  const std::uint16_t found = static_cast<std::uint16_t>(input[input_length - 2]) |
                              (static_cast<std::uint16_t>(input[input_length - 1]) << 8);
  if (expected != found) {
    return CodecError::kCrcMismatch;
  }
  out->major = input[2];
  out->minor = input[3];
  out->message_type = input[4];
  out->flags = input[5];
  out->sequence = ReadLe32(input + 6);
  out->payload = input + kHeader;
  out->payload_length = declared;
  return CodecError::kOk;
}

CodecError EncodeWireFrame(std::uint8_t major, std::uint8_t minor, std::uint8_t message_type,
                           std::uint8_t flags, std::uint32_t sequence, const std::uint8_t* payload,
                           std::size_t payload_length, std::uint8_t* output,
                           std::size_t output_capacity, std::size_t* output_length) {
  std::uint8_t decoded[kMaxDecoded];
  std::size_t decoded_len = 0;
  const CodecError e = EncodeDecodedFrame(major, minor, message_type, flags, sequence, payload,
                                          payload_length, decoded, sizeof(decoded), &decoded_len);
  if (e != CodecError::kOk) {
    return e;
  }
  if (output == nullptr || output_length == nullptr || output_capacity == 0) {
    return CodecError::kOutputTooSmall;
  }
  std::size_t enc_len = 0;
  const CodecError c = CobsEncode(decoded, decoded_len, output, output_capacity - 1, &enc_len);
  if (c != CodecError::kOk) {
    return c;
  }
  output[enc_len] = 0;  // zero delimiter
  *output_length = enc_len + 1;
  return CodecError::kOk;
}

CodecError DecodeWireFrame(const std::uint8_t* input, std::size_t input_length, std::uint8_t* scratch,
                           std::size_t scratch_capacity, DecodedFrame* out) {
  if (input_length == 0) {
    return CodecError::kFrameTooShort;
  }
  if (input[input_length - 1] != 0) {
    return CodecError::kMissingDelimiter;
  }
  const std::size_t body_len = input_length - 1;
  for (std::size_t i = 0; i < body_len; ++i) {
    if (input[i] == 0) {
      return CodecError::kInteriorDelimiter;
    }
  }
  std::size_t decoded_len = 0;
  const CodecError c = CobsDecode(input, body_len, scratch, scratch_capacity, &decoded_len);
  if (c != CodecError::kOk) {
    return c;
  }
  return DecodeDecodedFrame(scratch, decoded_len, out);
}

}  // namespace keyferry::protocol
