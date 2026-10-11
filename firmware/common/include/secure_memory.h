#pragma once

#include <cstddef>
#include <cstdint>

namespace keyferry {

// Volatile stores keep cleanup of owned payload storage from being optimized away.
inline void SecureClear(void* data, std::size_t length) noexcept {
    auto* output = static_cast<volatile std::uint8_t*>(data);
    while (length-- != 0) {
        *output++ = 0;
    }
}

class SecureClearOnExit final {
  public:
    SecureClearOnExit(void* data, std::size_t length) noexcept : data_(data), length_(length) {}
    ~SecureClearOnExit() { SecureClear(data_, length_); }
    SecureClearOnExit(const SecureClearOnExit&) = delete;
    SecureClearOnExit& operator=(const SecureClearOnExit&) = delete;

  private:
    void* data_;
    std::size_t length_;
};

}  // namespace keyferry
