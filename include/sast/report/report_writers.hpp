#pragma once

#include <string>

#include "sast/ir/facts.hpp"

namespace sast::report {

class ReportWriters {
 public:
  static std::string to_json(const ir::ValidatedScanResult& result);
  static std::string to_sarif(const ir::ValidatedScanResult& result);
  static std::string to_text(const ir::ValidatedScanResult& result);
};

}  // namespace sast::report
