#include "keyferry/idf_output_mode_storage.h"

#include "esp_err.h"

namespace keyferry::output_mode {
namespace {

constexpr char kNamespace[] = "kf_output";
constexpr char kModeKey[] = "mode_v1";

}  // namespace

IdfStorage::IdfStorage() {
  ready_ = nvs_open(kNamespace, NVS_READWRITE, &handle_) == ESP_OK;
}

IdfStorage::~IdfStorage() {
  if (ready_) {
    nvs_close(handle_);
  }
}

bool IdfStorage::ready() const noexcept { return ready_; }

ReadResult IdfStorage::Read(Record* const output) {
  if (!ready_ || output == nullptr) {
    return ReadResult::kError;
  }
  output->fill(0);
  std::size_t length = output->size();
  const esp_err_t result = nvs_get_blob(handle_, kModeKey, output->data(), &length);
  if (result == ESP_ERR_NVS_NOT_FOUND) {
    return ReadResult::kAbsent;
  }
  if (result != ESP_OK) {
    return ReadResult::kError;
  }
  // A wrong-length value is present but malformed; preserve that distinction
  // while keeping the boot result safely in USB mode.
  if (length != output->size()) {
    output->fill(0);
  }
  return ReadResult::kPresent;
}

bool IdfStorage::Write(const Record& record) {
  return ready_ && nvs_set_blob(handle_, kModeKey, record.data(), record.size()) == ESP_OK &&
         nvs_commit(handle_) == ESP_OK;
}

}  // namespace keyferry::output_mode
