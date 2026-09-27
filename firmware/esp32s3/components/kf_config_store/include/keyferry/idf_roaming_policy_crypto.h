#pragma once

#include "keyferry/roaming_config.h"

namespace keyferry::config {

class IdfRoamingPolicyCrypto final : public RoamingPolicyCrypto {
 public:
  bool Sha256(const std::uint8_t* input, std::size_t length,
              std::uint8_t output[32]) override;
  bool HkdfSha256(const std::uint8_t* input_key,
                  std::size_t input_key_length, const std::uint8_t* salt,
                  std::size_t salt_length, const std::uint8_t* info,
                  std::size_t info_length, std::uint8_t output[32]) override;
  bool HmacSha256(const std::uint8_t key[32], const std::uint8_t* input,
                  std::size_t input_length,
                  std::uint8_t output[32]) override;
};

}  // namespace keyferry::config
