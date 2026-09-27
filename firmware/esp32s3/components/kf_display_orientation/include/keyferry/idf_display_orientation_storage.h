#pragma once

#include "keyferry/display_orientation.h"
#include "nvs.h"

namespace keyferry::display_orientation {

class IdfStorage final : public Storage {
 public:
  IdfStorage();
  ~IdfStorage() override;

  IdfStorage(const IdfStorage&) = delete;
  IdfStorage& operator=(const IdfStorage&) = delete;

  [[nodiscard]] bool ready() const noexcept;
  ReadResult Read(Record* output) override;
  bool Write(const Record& record) override;
  ReadResult ReadPower(std::uint8_t* output) override;
  bool WritePower(std::uint8_t power) override;

 private:
  nvs_handle_t handle_{0};
  bool ready_{false};
};

}  // namespace keyferry::display_orientation
