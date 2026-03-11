#pragma once

#include <string>

#include "sast/ir/facts.hpp"

namespace sast::report {

class FactsJsonWriter {
 public:
  static std::string render(const ir::FactDatabase& facts);
};

}  // namespace sast::report

