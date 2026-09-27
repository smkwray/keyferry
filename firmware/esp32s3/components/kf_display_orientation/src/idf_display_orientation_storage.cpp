#include "keyferry/idf_display_orientation_storage.h"

#include "esp_err.h"

namespace keyferry::display_orientation {
namespace {

constexpr char kNamespace[] = "kf_display";
constexpr char kOrientationKey[] = "orient_v1";
constexpr char kPowerKey[] = "power_v1";

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
  const esp_err_t result =
      nvs_get_blob(handle_, kOrientationKey, output->data(), &length);
  if (result == ESP_ERR_NVS_NOT_FOUND) {
    return ReadResult::kAbsent;
  }
  if (result != ESP_OK) {
    return ReadResult::kError;
  }
  if (length != output->size()) {
    output->fill(0);
  }
  return ReadResult::kPresent;
}

bool IdfStorage::Write(const Record& record) {
  return ready_ &&
         nvs_set_blob(handle_, kOrientationKey, record.data(), record.size()) ==
             ESP_OK &&
         nvs_commit(handle_) == ESP_OK;
}

ReadResult IdfStorage::ReadPower(std::uint8_t* const output) {
  if (!ready_ || output == nullptr) return ReadResult::kError;
  *output = 0;
  const esp_err_t result = nvs_get_u8(handle_, kPowerKey, output);
  if (result == ESP_ERR_NVS_NOT_FOUND) return ReadResult::kAbsent;
  return result == ESP_OK ? ReadResult::kPresent : ReadResult::kError;
}

bool IdfStorage::WritePower(const std::uint8_t power) {
  return ready_ && nvs_set_u8(handle_, kPowerKey, power) == ESP_OK &&
         nvs_commit(handle_) == ESP_OK;
}

}  // namespace keyferry::display_orientation
