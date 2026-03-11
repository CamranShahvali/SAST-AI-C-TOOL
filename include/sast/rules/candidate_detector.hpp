#pragma once

#include <vector>

#include "sast/ir/facts.hpp"
#include "sast/rules/rule_registry.hpp"
#include "sast/rules/source_sink_registry.hpp"

namespace sast::rules {

class CandidateDetector {
 public:
  CandidateDetector(
    const RuleRegistry& rules,
    const SourceSinkRegistry& registry);

  [[nodiscard]] ir::CandidateScanResult detect(const ir::FactDatabase& facts) const;

 private:
  const RuleRegistry& rules_;
  const SourceSinkRegistry& registry_;
};

}  // namespace sast::rules
