#pragma once

#include "sast/ir/facts.hpp"

namespace sast::validators {

class DecisionEngine {
 public:
  static ir::ValidationResult decide(
    const ir::CandidateFinding& candidate,
    ir::ValidationResult validation);
};

}  // namespace sast::validators
