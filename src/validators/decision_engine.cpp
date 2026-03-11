#include "sast/validators/decision_engine.hpp"

namespace sast::validators {

namespace {

void set_result(
  ir::ValidationResult& validation,
  const ir::Decision decision,
  const double confidence,
  const bool deterministic,
  const std::string& explanation) {
  validation.final_decision = decision;
  validation.confidence = confidence;
  validation.deterministic = deterministic;
  validation.explanation = explanation;
}

}  // namespace

ir::ValidationResult DecisionEngine::decide(
  const ir::CandidateFinding& candidate,
  ir::ValidationResult validation) {
  (void)candidate;

  if (!validation.suppressions.empty()) {
    set_result(
      validation,
      ir::Decision::safe_suppressed,
      1.0,
      true,
      "suppression matched the candidate location");
    return validation;
  }

  const auto positive_count = validation.matched_positive_conditions.size();
  const auto negative_count = validation.matched_negative_conditions.size();
  const auto ambiguous_count = validation.matched_ambiguous_conditions.size();

  const auto has_strong_negative =
    !validation.safe_reasoning.empty() ||
    negative_count > 0;
  const auto has_positive = positive_count > 0;
  const auto has_ambiguity = ambiguous_count > 0 || !validation.ambiguous_reasoning.empty();

  if (has_strong_negative && !has_positive && !has_ambiguity) {
    set_result(
      validation,
      ir::Decision::safe_suppressed,
      0.98,
      true,
      validation.safe_reasoning.empty()
        ? "safety barrier was proven"
        : validation.safe_reasoning.front());
    return validation;
  }

  if (has_strong_negative && has_positive && !has_ambiguity) {
    set_result(
      validation,
      ir::Decision::safe_suppressed,
      0.96,
      true,
      validation.safe_reasoning.empty()
        ? "safety barrier proved stronger than the candidate signal"
        : validation.safe_reasoning.front());
    return validation;
  }

  if (has_strong_negative && has_ambiguity && !has_positive) {
    set_result(
      validation,
      ir::Decision::likely_safe,
      0.78,
      false,
      validation.safe_reasoning.empty()
        ? "safety evidence exists but proof is incomplete"
        : validation.safe_reasoning.front());
    return validation;
  }

  if (has_positive && has_ambiguity) {
    set_result(
      validation,
      ir::Decision::likely_issue,
      0.76,
      false,
      validation.ambiguous_reasoning.empty()
        ? "untrusted flow reaches the sink through unresolved logic"
        : validation.ambiguous_reasoning.front());
    return validation;
  }

  if (has_positive && !has_strong_negative && !has_ambiguity) {
    set_result(
      validation,
      ir::Decision::confirmed_issue,
      0.94,
      true,
      "positive vulnerability conditions were satisfied without a safety barrier");
    return validation;
  }

  if (has_ambiguity) {
    set_result(
      validation,
      ir::Decision::needs_review,
      0.58,
      false,
      validation.ambiguous_reasoning.empty()
        ? "the candidate could not be proven safe or vulnerable"
        : validation.ambiguous_reasoning.front());
    return validation;
  }

  set_result(
    validation,
    ir::Decision::likely_safe,
    0.60,
    false,
    "no positive vulnerability condition survived validation");
  return validation;
}

}  // namespace sast::validators
