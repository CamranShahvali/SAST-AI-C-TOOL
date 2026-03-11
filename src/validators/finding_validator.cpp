#include "sast/validators/finding_validator.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <regex>

#include "sast/validators/decision_engine.hpp"

namespace sast::validators {

namespace {

bool trace_contains(
  const ir::CandidateFinding& candidate,
  const std::string& needle) {
  return std::any_of(
    candidate.trace_steps.begin(),
    candidate.trace_steps.end(),
    [&](const std::string& step) {
      return step.find(needle) != std::string::npos;
    });
}

void add_evidence(
  std::vector<ir::ValidationEvidence>& destination,
  const std::string& condition,
  const std::string& explanation,
  const ir::CandidateFinding& candidate) {
  const auto already_present = std::find_if(
    destination.begin(),
    destination.end(),
    [&](const ir::ValidationEvidence& evidence) {
      return evidence.condition == condition && evidence.explanation == explanation;
    });
  if (already_present != destination.end()) {
    return;
  }

  ir::ValidationEvidence evidence;
  evidence.condition = condition;
  evidence.explanation = explanation;
  if (!candidate.evidence_locations.empty()) {
    evidence.location = candidate.evidence_locations.front();
  }
  destination.push_back(std::move(evidence));
}

bool has_string_literal(const std::string& value) {
  const auto first_quote = value.find('"');
  const auto last_quote = value.rfind('"');
  return first_quote != std::string::npos && last_quote != std::string::npos && first_quote != last_quote;
}

bool uses_untrusted_input(const ir::CandidateFinding& candidate) {
  return trace_contains(candidate, "expression depends on parameter") ||
         trace_contains(candidate, "expression references argv") ||
         candidate.source_summary.find("argv[") != std::string::npos ||
         candidate.source_summary.find("getenv(") != std::string::npos;
}

bool has_unresolved_wrapper(const ir::CandidateFinding& candidate) {
  return trace_contains(candidate, "unmodeled helper call");
}

bool has_allowlist_guard(const ir::CandidateFinding& candidate) {
  return trace_contains(candidate, "allowlist predicate");
}

bool has_trusted_wrapper(const ir::CandidateFinding& candidate) {
  return trace_contains(candidate, "trusted wrapper");
}

bool has_path_sanitizer(const ir::CandidateFinding& candidate) {
  return trace_contains(candidate, "sanitizer canonicalize_under_root") ||
         candidate.source_summary.find("canonicalize_under_root(") != std::string::npos;
}

bool canonicalized_under_fixed_root(const ir::CandidateFinding& candidate) {
  static const std::regex root_regex(
    R"(canonicalize_under_root\s*\([^,]+,\s*"[^"]+"\s*\))");
  return std::regex_search(candidate.source_summary, root_regex);
}

bool is_unbounded_string_sink(const std::string& sink_name) {
  const auto last_component = sink_name.rfind("::");
  const auto unqualified = last_component == std::string::npos
                             ? sink_name
                             : sink_name.substr(last_component + 2);
  return unqualified == "strcpy" || unqualified == "strcat" ||
         unqualified == "sprintf" || unqualified == "vsprintf";
}

bool is_bounded_copy_sink(const std::string& sink_name) {
  const auto last_component = sink_name.rfind("::");
  const auto unqualified = last_component == std::string::npos
                             ? sink_name
                             : sink_name.substr(last_component + 2);
  return unqualified == "memcpy" || unqualified == "memmove" ||
         unqualified == "snprintf" || unqualified == "vsnprintf";
}

std::optional<std::size_t> parse_integral_bound(const std::string& expression) {
  std::size_t value = 0;
  const auto normalized = std::string(
    expression.begin(),
    std::find_if(expression.begin(), expression.end(), [](unsigned char ch) {
      return !std::isspace(ch);
    }));
  (void)normalized;
  try {
    std::size_t index = 0;
    const auto parsed = std::stoull(expression, &index, 10);
    if (index == expression.size()) {
      return static_cast<std::size_t>(parsed);
    }
  } catch (...) {
  }
  return std::nullopt;
}

bool bound_matches_destination(
  const ir::CandidateFinding& candidate) {
  if (!candidate.destination_extent || candidate.bound_expression.empty()) {
    return false;
  }

  if (const auto integral = parse_integral_bound(candidate.bound_expression)) {
    return *integral <= *candidate.destination_extent;
  }

  if (!candidate.sink_arguments.empty()) {
    const auto& destination = candidate.sink_arguments.front();
    const auto pattern = "sizeof(" + destination + ")";
    if (candidate.bound_expression == pattern) {
      return true;
    }
  }

  return false;
}

std::vector<std::string> load_lines(const std::filesystem::path& path) {
  std::vector<std::string> lines;
  std::ifstream input(path);
  std::string line;
  while (std::getline(input, line)) {
    lines.push_back(line);
  }
  return lines;
}

bool is_dead_branch_context(const ir::CandidateFinding& candidate) {
  if (!std::filesystem::exists(candidate.file) || candidate.line <= 0) {
    return false;
  }

  const auto lines = load_lines(candidate.file);
  const auto line_index = static_cast<std::size_t>(candidate.line - 1);
  if (line_index >= lines.size()) {
    return false;
  }

  const auto start = line_index > 4 ? line_index - 4 : 0;
  for (std::size_t index = start; index <= line_index; ++index) {
    const auto& line = lines[index];
    if (line.find("if (false)") != std::string::npos ||
        line.find("if constexpr (false)") != std::string::npos ||
        line.find("#if 0") != std::string::npos) {
      return true;
    }
  }
  return false;
}

void validate_command(
  const ir::CandidateFinding& candidate,
  ir::ValidationResult& validation) {
  const auto strict_allowlist = has_allowlist_guard(candidate);
  const auto trusted_wrapper = has_trusted_wrapper(candidate);
  const auto unresolved_wrapper = has_unresolved_wrapper(candidate);
  const auto untrusted_input = uses_untrusted_input(candidate);

  if (strict_allowlist) {
    add_evidence(
      validation.matched_negative_conditions,
      "strict command allowlist proved",
      "allowlist predicate observed before command execution sink",
      candidate);
    validation.safe_reasoning.push_back("strict allowlist guard protects the command sink");
  }
  if (trusted_wrapper) {
    add_evidence(
      validation.matched_negative_conditions,
      "trusted wrapper constructs fixed argv",
      "configured trusted wrapper participates in the command flow",
      candidate);
    validation.safe_reasoning.push_back("trusted wrapper from config constrains command execution");
  }
  if (has_string_literal(candidate.source_summary)) {
    add_evidence(
      validation.matched_negative_conditions,
      "command is compile-time constant",
      "command argument is a string literal",
      candidate);
    validation.safe_reasoning.push_back("command value is compile-time constant");
  }
  if (!strict_allowlist && !trusted_wrapper && untrusted_input) {
    add_evidence(
      validation.matched_positive_conditions,
      "untrusted input reaches process execution sink",
      "candidate trace shows caller-controlled data reaching command execution",
      candidate);
  }
  if (!has_string_literal(candidate.source_summary)) {
    add_evidence(
      validation.matched_positive_conditions,
      "command string is dynamically composed",
      "command argument is not compile-time constant",
      candidate);
  }
  if (unresolved_wrapper) {
    add_evidence(
      validation.matched_ambiguous_conditions,
      "wrapper semantics are unknown",
      "unmodeled helper call appears in the command data flow",
      candidate);
    validation.ambiguous_reasoning.push_back("wrapper semantics are unknown");
  }
}

void validate_path(
  const ir::CandidateFinding& candidate,
  ir::ValidationResult& validation) {
  const auto allowlist = has_allowlist_guard(candidate);
  const auto trusted_wrapper = has_trusted_wrapper(candidate);
  const auto sanitized = has_path_sanitizer(candidate);
  const auto fixed_root = canonicalized_under_fixed_root(candidate);
  const auto unresolved_wrapper = has_unresolved_wrapper(candidate);

  if (fixed_root) {
    add_evidence(
      validation.matched_negative_conditions,
      "path canonicalized under trusted root",
      "path is canonicalized under a fixed literal root before file access",
      candidate);
    validation.safe_reasoning.push_back("canonicalized path is confined under a fixed root");
  } else if (allowlist) {
    add_evidence(
      validation.matched_negative_conditions,
      "strict path allowlist proved",
      "path allowlist predicate was observed before file access",
      candidate);
    validation.safe_reasoning.push_back("path allowlist predicate constrains user input");
    add_evidence(
      validation.matched_ambiguous_conditions,
      "normalization exists without root proof",
      "path allowlist was observed but fixed-root confinement was not proven",
      candidate);
    validation.ambiguous_reasoning.push_back("path allowlist exists but root confinement proof is incomplete");
  } else if (trusted_wrapper) {
    add_evidence(
      validation.matched_negative_conditions,
      "trusted wrapper controls root directory",
      "configured trusted wrapper participates in the path flow",
      candidate);
    validation.safe_reasoning.push_back("trusted wrapper constrains the file access root");
  }

  if (!allowlist && !fixed_root && uses_untrusted_input(candidate)) {
    add_evidence(
      validation.matched_positive_conditions,
      "user-controlled path reaches file sink",
      "candidate trace shows caller-controlled path data reaching file access",
      candidate);
  }
  if (sanitized && !fixed_root) {
    add_evidence(
      validation.matched_ambiguous_conditions,
      "normalization exists without root proof",
      "path sanitization is present but the fixed root is not proven",
      candidate);
    validation.ambiguous_reasoning.push_back("path normalization exists without fixed-root proof");
  }
  if (unresolved_wrapper) {
    add_evidence(
      validation.matched_ambiguous_conditions,
      "path validation wrapper is not modeled",
      "unmodeled helper call appears in the path flow",
      candidate);
    validation.ambiguous_reasoning.push_back("path validation wrapper is not modeled");
  }
}

void validate_string(
  const ir::CandidateFinding& candidate,
  const ValidatorRegistry& registry,
  ir::ValidationResult& validation) {
  const auto bounded_write = bound_matches_destination(candidate);
  const auto unbounded_sink = is_unbounded_string_sink(candidate.sink_name);
  const auto bounded_sink = is_bounded_copy_sink(candidate.sink_name);

  if (registry.is_safe_string_function(candidate.sink_name) && bounded_write) {
    add_evidence(
      validation.matched_negative_conditions,
      "bounded API is used correctly",
      "bounded snprintf-style write fits within the destination extent",
      candidate);
    validation.safe_reasoning.push_back("bounded snprintf-style write fits within the destination extent");
  } else if (bounded_sink && bounded_write) {
    add_evidence(
      validation.matched_negative_conditions,
      "destination extent is compile-time known and respected",
      "copy length is bounded by the destination extent",
      candidate);
    validation.safe_reasoning.push_back("copy length is bounded by the destination extent");
  }

  if (unbounded_sink) {
    add_evidence(
      validation.matched_positive_conditions,
      "dangerous copy or format sink is used",
      "unbounded string sink is used directly",
      candidate);
    if (uses_untrusted_input(candidate)) {
      add_evidence(
        validation.matched_positive_conditions,
        "source length is uncontrolled",
        "candidate trace shows caller-controlled data in the string operation",
        candidate);
    }
  }

  if (bounded_sink && !bounded_write) {
    const auto condition = candidate.destination_extent
                             ? "length expression bound is unknown"
                             : "destination extent cannot be proven";
    const auto explanation = candidate.destination_extent
                               ? "copy bound expression could not be proven against the destination extent"
                               : "destination extent is not known for the bounded write";
    add_evidence(
      validation.matched_ambiguous_conditions,
      condition,
      explanation,
      candidate);
    validation.ambiguous_reasoning.push_back(explanation);
  }
}

}  // namespace

FindingValidator::FindingValidator(const ValidatorRegistry& registry)
    : registry_(registry) {}

ir::ValidationResult FindingValidator::validate(const ir::CandidateFinding& candidate) const {
  ir::ValidationResult validation;

  validation.suppressions =
    registry_.configured_suppressions(candidate.rule_id, candidate.file);
  const auto inline_suppressions =
    registry_.inline_suppressions(candidate.rule_id, {.file = candidate.file, .line = candidate.line, .column = 1});
  validation.suppressions.insert(
    validation.suppressions.end(),
    inline_suppressions.begin(),
    inline_suppressions.end());

  if (!validation.suppressions.empty()) {
    validation.safe_reasoning.push_back("suppression matched the finding location");
    return DecisionEngine::decide(candidate, std::move(validation));
  }

  if (is_dead_branch_context(candidate)) {
    validation.safe_reasoning.push_back("sink is guarded by a compile-time false branch");
    return DecisionEngine::decide(candidate, std::move(validation));
  }

  if (registry_.is_test_artifact(candidate.file)) {
    validation.safe_reasoning.push_back("finding is limited to a test-only translation unit");
    return DecisionEngine::decide(candidate, std::move(validation));
  }

  if (candidate.rule_family == "command_injection") {
    validate_command(candidate, validation);
  } else if (candidate.rule_family == "path_traversal") {
    validate_path(candidate, validation);
  } else if (candidate.rule_family == "dangerous_string") {
    validate_string(candidate, registry_, validation);
  }

  return DecisionEngine::decide(candidate, std::move(validation));
}

}  // namespace sast::validators
