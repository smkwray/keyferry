#pragma once

#include <cstddef>
#include <cstdint>

namespace keyferry::protocol {

enum class CodecError : std::uint8_t {
  kOk = 0,
  kOutputTooSmall,
  kEmptyCobs,
  kMalformedCobs,
  kPayloadTooLarge,
  kFrameTooShort,
  kFrameTooLarge,
  kBadMagic,
  kLengthMismatch,
  kCrcMismatch,
  kMissingDelimiter,
  kInteriorDelimiter,
};

// Decoded view of a frame. `payload` points into the caller-owned buffer that
// was decoded; it is not copied.
struct DecodedFrame {
  std::uint8_t major;
  std::uint8_t minor;
  std::uint8_t message_type;
  std::uint8_t flags;
  std::uint32_t sequence;
  const std::uint8_t* payload;
  std::size_t payload_length;
};

std::uint16_t Crc16CcittFalse(const std::uint8_t* data, std::size_t length);

CodecError CobsEncode(const std::uint8_t* input,
                      std::size_t input_length,
                      std::uint8_t* output,
                      std::size_t output_capacity,
                      std::size_t* output_length);

CodecError CobsDecode(const std::uint8_t* input,
                      std::size_t input_length,
                      std::uint8_t* output,
                      std::size_t output_capacity,
                      std::size_t* output_length);

// Build the decoded frame (magic, header, payload, CRC) into `output`.
CodecError EncodeDecodedFrame(std::uint8_t major,
                              std::uint8_t minor,
                              std::uint8_t message_type,
                              std::uint8_t flags,
                              std::uint32_t sequence,
                              const std::uint8_t* payload,
                              std::size_t payload_length,
                              std::uint8_t* output,
                              std::size_t output_capacity,
                              std::size_t* output_length);

// Validate and parse a decoded frame. On success `out->payload` points into
// `input`.
CodecError DecodeDecodedFrame(const std::uint8_t* input,
                              std::size_t input_length,
                              DecodedFrame* out);

// Build the COBS-framed wire form (decoded frame, COBS-encoded, plus one 0x00).
CodecError EncodeWireFrame(std::uint8_t major,
                           std::uint8_t minor,
                           std::uint8_t message_type,
                           std::uint8_t flags,
                           std::uint32_t sequence,
                           const std::uint8_t* payload,
                           std::size_t payload_length,
                           std::uint8_t* output,
                           std::size_t output_capacity,
                           std::size_t* output_length);

// Parse a COBS-framed wire frame. `scratch` holds the decoded frame that
// `out->payload` then points into, so it must outlive `out`.
CodecError DecodeWireFrame(const std::uint8_t* input,
                           std::size_t input_length,
                           std::uint8_t* scratch,
                           std::size_t scratch_capacity,
                           DecodedFrame* out);

}  // namespace keyferry::protocol
