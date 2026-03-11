#pragma once

#include <string>

#include "sast/ir/facts.hpp"

namespace sast::report {

class CandidateJsonWriter {
 public:
  static std::string render(const ir::CandidateScanResult& result);
  static std::string render(const ir::ValidatedScanResult& result);
};

}  // namespace sast::report
