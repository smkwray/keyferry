#include "keyferry/idf_local_management_receipts.h"

#include "nvs.h"

namespace keyferry::local_management {
namespace {

constexpr char kNamespace[] = "kf_local_mgmt";
constexpr char kKeys[2][3] = {"ra", "rb"};

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
  [[nodiscard]] bool valid() const { return valid_; }
  [[nodiscard]] esp_err_t result() const { return result_; }
  [[nodiscard]] nvs_handle_t get() const { return handle_; }

 private:
  nvs_handle_t handle_{};
  esp_err_t result_{ESP_FAIL};
  bool valid_{};
};

}  // namespace

ReceiptBlobReadStatus IdfReceiptBlobStorage::Read(
    const std::uint8_t slot, ReceiptJournalBlob* output) {
  if (slot > 1 || output == nullptr) {
    return ReceiptBlobReadStatus::kIoError;
  }
  Handle handle(NVS_READONLY);
  if (!handle.valid()) {
    return handle.result() == ESP_ERR_NVS_NOT_FOUND
               ? ReceiptBlobReadStatus::kNotFound
               : ReceiptBlobReadStatus::kIoError;
  }
  std::size_t length = output->size();
  const auto result =
      nvs_get_blob(handle.get(), kKeys[slot], output->data(), &length);
  if (result == ESP_ERR_NVS_NOT_FOUND) {
    return ReceiptBlobReadStatus::kNotFound;
  }
  return result == ESP_OK && length == output->size()
             ? ReceiptBlobReadStatus::kOk
             : ReceiptBlobReadStatus::kIoError;
}

bool IdfReceiptBlobStorage::Write(const std::uint8_t slot,
                                  const ReceiptJournalBlob& data) {
  if (slot > 1) {
    return false;
  }
  Handle handle(NVS_READWRITE);
  return handle.valid() &&
         nvs_set_blob(handle.get(), kKeys[slot], data.data(), data.size()) ==
             ESP_OK &&
         nvs_commit(handle.get()) == ESP_OK;
}

}  // namespace keyferry::local_management
