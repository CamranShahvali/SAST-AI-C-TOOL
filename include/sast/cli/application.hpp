#pragma once

#include <vector>

#include <string>

namespace sast::cli {

class Application {
 public:
  int run(const std::vector<std::string>& args) const;

 private:
  [[nodiscard]] int run_facts(const std::vector<std::string>& args) const;
  [[nodiscard]] int run_scan(const std::vector<std::string>& args) const;
  [[nodiscard]] int run_demo(const std::vector<std::string>& args) const;
};

}  // namespace sast::cli
