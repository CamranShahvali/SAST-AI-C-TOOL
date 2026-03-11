#pragma once

#include "sast/ir/facts.hpp"
#include "sast/validators/validator_registry.hpp"

namespace sast::validators {

class FindingValidator {
 public:
  explicit FindingValidator(const ValidatorRegistry& registry);

  [[nodiscard]] ir::ValidationResult validate(const ir::CandidateFinding& candidate) const;

 private:
  const ValidatorRegistry& registry_;
};

}  // namespace sast::validators
