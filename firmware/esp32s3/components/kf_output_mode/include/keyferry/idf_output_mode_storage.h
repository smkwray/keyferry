#pragma once

#include "keyferry/output_mode.h"
#include "nvs.h"

namespace keyferry::output_mode {

class IdfStorage final : public Storage {
 public:
  IdfStorage();
  ~IdfStorage() override;

  IdfStorage(const IdfStorage&) = delete;
  IdfStorage& operator=(const IdfStorage&) = delete;

  [[nodiscard]] bool ready() const noexcept;
  ReadResult Read(Record* output) override;
  bool Write(const Record& record) override;

 private:
  nvs_handle_t handle_{0};
  bool ready_{false};
};

}  // namespace keyferry::output_mode
