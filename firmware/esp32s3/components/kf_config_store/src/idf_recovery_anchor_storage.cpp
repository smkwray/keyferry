#include "keyferry/idf_recovery_anchor_storage.h"

#include "nvs.h"

namespace keyferry::config {
namespace {

constexpr char kNamespace[] = "kf_recovery";
constexpr char kAnchorKey[] = "anchor";

class Handle final {
 public:
  explicit Handle(const nvs_open_mode_t mode) {
    result_ = nvs_open(kNamespace, mode, &handle_);
    valid_ = result_ == ESP_OK;
  }

  ~Handle() {
    if (valid_) {
      nvs_close(handle_);
    }
  }

  bool valid() const { return valid_; }
  esp_err_t result() const { return result_; }
  nvs_handle_t get() const { return handle_; }

 private:
  nvs_handle_t handle_{0};
  esp_err_t result_{ESP_FAIL};
  bool valid_{false};
};

}  // namespace

AnchorReadStatus IdfRecoveryAnchorStorage::Read(std::uint8_t* output,
                                                const std::size_t length) {
  if (output == nullptr || length != kRecoveryAnchorBytes) {
    return AnchorReadStatus::kIoError;
  }
  Handle handle(NVS_READONLY);
  if (!handle.valid()) {
    return handle.result() == ESP_ERR_NVS_NOT_FOUND
               ? AnchorReadStatus::kNotFound
               : AnchorReadStatus::kIoError;
  }
  std::size_t stored_length = length;
  const esp_err_t result =
      nvs_get_blob(handle.get(), kAnchorKey, output, &stored_length);
  if (result == ESP_ERR_NVS_NOT_FOUND) {
    return AnchorReadStatus::kNotFound;
  }
  return result == ESP_OK && stored_length == length ? AnchorReadStatus::kOk
                                                     : AnchorReadStatus::kIoError;
}

bool IdfRecoveryAnchorStorage::Write(const std::uint8_t* data,
                                     const std::size_t length) {
  if (data == nullptr || length != kRecoveryAnchorBytes) {
    return false;
  }
  Handle handle(NVS_READWRITE);
  return handle.valid() &&
         nvs_set_blob(handle.get(), kAnchorKey, data, length) == ESP_OK &&
         nvs_commit(handle.get()) == ESP_OK;
}

}  // namespace keyferry::config
