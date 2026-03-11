#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace sast::ir {

enum class RuleKind {
  command_injection,
  path_traversal,
  dangerous_string
};

enum class Severity {
  low,
  medium,
  high,
  critical
};

enum class Decision {
  confirmed_issue,
  likely_issue,
  needs_review,
  likely_safe,
  safe_suppressed
};

enum class SymbolicKind {
  unknown,
  parameter,
  variable,
  string_literal,
  integer_literal,
  boolean_literal,
  source,
  call_result,
  sanitized,
  allowlisted,
  trusted,
  concatenation
};

enum class GuardKind {
  unknown,
  allowlist,
  path_allowlist,
  sanitizer,
  trusted_wrapper,
  dead_branch
};

struct SourceLocation {
  std::string file;
  int line = 0;
  int column = 0;

  [[nodiscard]] bool valid() const { return !file.empty() && line > 0; }
};

struct SymbolicValue {
  SymbolicKind kind = SymbolicKind::unknown;
  std::string label;
  int parameter_index = -1;
  std::optional<long long> integer_value;
  std::optional<bool> boolean_value;
  std::vector<SymbolicValue> inputs;
  std::optional<SourceLocation> location;
  bool bounded = false;
  bool compile_time_constant = false;

  [[nodiscard]] std::string describe() const;
  [[nodiscard]] bool depends_on_parameter() const;
  [[nodiscard]] std::set<int> parameter_dependencies() const;
  [[nodiscard]] bool has_kind(SymbolicKind expected) const;
  [[nodiscard]] bool is_literal() const;
  [[nodiscard]] bool is_unknown_like() const;
};

struct GuardCondition {
  GuardKind kind = GuardKind::unknown;
  std::string predicate;
  SymbolicValue subject;
  bool positive = true;
  bool compile_time_known = false;
  bool compile_time_value = false;
  SourceLocation location;
};

struct CallArgument {
  SymbolicValue value;
  std::string expression_text;
  std::optional<std::size_t> static_extent;
  SourceLocation location;
};

struct CallRecord {
  std::string function_name;
  std::vector<CallArgument> arguments;
  std::vector<GuardCondition> active_guards;
  SourceLocation location;
  bool is_member_call = false;
  bool is_constructor = false;
};

struct FunctionSummary {
  std::string qualified_name;
  std::vector<std::string> parameter_names;
  std::unordered_map<std::string, std::optional<std::size_t>> variable_extents;
  std::vector<CallRecord> calls;
  std::optional<SymbolicValue> return_value;
  SourceLocation location;
  std::size_t cfg_blocks = 0;
  std::size_t cfg_edges = 0;
  bool is_entrypoint = false;
  bool is_test_only = false;
};

struct TranslationUnitSummary {
  std::string file_path;
  std::vector<FunctionSummary> functions;
  std::vector<std::string> diagnostics;
};

struct TraceStep {
  std::string message;
  SourceLocation location;
};

struct CandidateFinding {
  std::string rule_id;
  RuleKind kind = RuleKind::command_injection;
  Severity severity = Severity::medium;
  std::string title;
  std::string function_name;
  std::string sink_name;
  std::vector<CallArgument> sink_arguments;
  std::string source_summary;
  std::string sink_summary;
  std::vector<TraceStep> trace;
  std::vector<GuardCondition> guards;
  std::vector<std::string> positive_conditions;
  std::vector<std::string> negative_conditions;
  std::vector<std::string> ambiguous_conditions;
  SymbolicValue sink_value;
  std::optional<SourceLocation> source_location;
  SourceLocation sink_location;
  bool from_test_only = false;
  bool llm_review_candidate = false;
};

struct ValidationResult {
  Decision decision = Decision::needs_review;
  double confidence = 0.0;
  std::vector<std::string> reasons;
  std::vector<std::string> suppressions;
  std::vector<std::string> validator_tags;
  bool llm_review_recommended = false;
};

struct FinalFinding {
  CandidateFinding candidate;
  ValidationResult validation;
};

struct ScanStats {
  std::size_t translation_units_total = 0;
  std::size_t translation_units_analyzed = 0;
  std::size_t translation_units_from_cache = 0;
  std::size_t function_count = 0;
  std::size_t finding_count = 0;
};

struct ScanResult {
  std::vector<TranslationUnitSummary> summaries;
  std::vector<FinalFinding> findings;
  ScanStats stats;
};

std::string to_string(RuleKind kind);
std::string to_string(Severity severity);
std::string to_string(Decision decision);
std::string to_string(SymbolicKind kind);
std::string to_string(GuardKind kind);

RuleKind rule_kind_from_string(std::string_view value);
Severity severity_from_string(std::string_view value);
Decision decision_from_string(std::string_view value);
SymbolicKind symbolic_kind_from_string(std::string_view value);
GuardKind guard_kind_from_string(std::string_view value);

void to_json(nlohmann::json& json, const SourceLocation& value);
void from_json(const nlohmann::json& json, SourceLocation& value);
void to_json(nlohmann::json& json, const SymbolicValue& value);
void from_json(const nlohmann::json& json, SymbolicValue& value);
void to_json(nlohmann::json& json, const GuardCondition& value);
void from_json(const nlohmann::json& json, GuardCondition& value);
void to_json(nlohmann::json& json, const CallArgument& value);
void from_json(const nlohmann::json& json, CallArgument& value);
void to_json(nlohmann::json& json, const CallRecord& value);
void from_json(const nlohmann::json& json, CallRecord& value);
void to_json(nlohmann::json& json, const FunctionSummary& value);
void from_json(const nlohmann::json& json, FunctionSummary& value);
void to_json(nlohmann::json& json, const TranslationUnitSummary& value);
void from_json(const nlohmann::json& json, TranslationUnitSummary& value);
void to_json(nlohmann::json& json, const TraceStep& value);
void from_json(const nlohmann::json& json, TraceStep& value);
void to_json(nlohmann::json& json, const CandidateFinding& value);
void from_json(const nlohmann::json& json, CandidateFinding& value);
void to_json(nlohmann::json& json, const ValidationResult& value);
void from_json(const nlohmann::json& json, ValidationResult& value);
void to_json(nlohmann::json& json, const FinalFinding& value);
void from_json(const nlohmann::json& json, FinalFinding& value);
void to_json(nlohmann::json& json, const ScanStats& value);
void from_json(const nlohmann::json& json, ScanStats& value);
void to_json(nlohmann::json& json, const ScanResult& value);
void from_json(const nlohmann::json& json, ScanResult& value);

inline std::string to_string(const RuleKind kind) {
  switch (kind) {
    case RuleKind::command_injection:
      return "command_injection";
    case RuleKind::path_traversal:
      return "path_traversal";
    case RuleKind::dangerous_string:
      return "dangerous_string";
  }
  return "command_injection";
}

inline std::string to_string(const Severity severity) {
  switch (severity) {
    case Severity::low:
      return "low";
    case Severity::medium:
      return "medium";
    case Severity::high:
      return "high";
    case Severity::critical:
      return "critical";
  }
  return "medium";
}

inline std::string to_string(const Decision decision) {
  switch (decision) {
    case Decision::confirmed_issue:
      return "confirmed_issue";
    case Decision::likely_issue:
      return "likely_issue";
    case Decision::needs_review:
      return "needs_review";
    case Decision::likely_safe:
      return "likely_safe";
    case Decision::safe_suppressed:
      return "safe_suppressed";
  }
  return "needs_review";
}

inline std::string to_string(const SymbolicKind kind) {
  switch (kind) {
    case SymbolicKind::unknown:
      return "unknown";
    case SymbolicKind::parameter:
      return "parameter";
    case SymbolicKind::variable:
      return "variable";
    case SymbolicKind::string_literal:
      return "string_literal";
    case SymbolicKind::integer_literal:
      return "integer_literal";
    case SymbolicKind::boolean_literal:
      return "boolean_literal";
    case SymbolicKind::source:
      return "source";
    case SymbolicKind::call_result:
      return "call_result";
    case SymbolicKind::sanitized:
      return "sanitized";
    case SymbolicKind::allowlisted:
      return "allowlisted";
    case SymbolicKind::trusted:
      return "trusted";
    case SymbolicKind::concatenation:
      return "concatenation";
  }
  return "unknown";
}

inline std::string to_string(const GuardKind kind) {
  switch (kind) {
    case GuardKind::unknown:
      return "unknown";
    case GuardKind::allowlist:
      return "allowlist";
    case GuardKind::path_allowlist:
      return "path_allowlist";
    case GuardKind::sanitizer:
      return "sanitizer";
    case GuardKind::trusted_wrapper:
      return "trusted_wrapper";
    case GuardKind::dead_branch:
      return "dead_branch";
  }
  return "unknown";
}

inline RuleKind rule_kind_from_string(const std::string_view value) {
  if (value == "command_injection") {
    return RuleKind::command_injection;
  }
  if (value == "path_traversal") {
    return RuleKind::path_traversal;
  }
  return RuleKind::dangerous_string;
}

inline Severity severity_from_string(const std::string_view value) {
  if (value == "low") {
    return Severity::low;
  }
  if (value == "high") {
    return Severity::high;
  }
  if (value == "critical") {
    return Severity::critical;
  }
  return Severity::medium;
}

inline Decision decision_from_string(const std::string_view value) {
  if (value == "confirmed_issue") {
    return Decision::confirmed_issue;
  }
  if (value == "likely_issue") {
    return Decision::likely_issue;
  }
  if (value == "likely_safe") {
    return Decision::likely_safe;
  }
  if (value == "safe_suppressed") {
    return Decision::safe_suppressed;
  }
  return Decision::needs_review;
}

inline SymbolicKind symbolic_kind_from_string(const std::string_view value) {
  if (value == "parameter") {
    return SymbolicKind::parameter;
  }
  if (value == "variable") {
    return SymbolicKind::variable;
  }
  if (value == "string_literal") {
    return SymbolicKind::string_literal;
  }
  if (value == "integer_literal") {
    return SymbolicKind::integer_literal;
  }
  if (value == "boolean_literal") {
    return SymbolicKind::boolean_literal;
  }
  if (value == "source") {
    return SymbolicKind::source;
  }
  if (value == "call_result") {
    return SymbolicKind::call_result;
  }
  if (value == "sanitized") {
    return SymbolicKind::sanitized;
  }
  if (value == "allowlisted") {
    return SymbolicKind::allowlisted;
  }
  if (value == "trusted") {
    return SymbolicKind::trusted;
  }
  if (value == "concatenation") {
    return SymbolicKind::concatenation;
  }
  return SymbolicKind::unknown;
}

inline GuardKind guard_kind_from_string(const std::string_view value) {
  if (value == "allowlist") {
    return GuardKind::allowlist;
  }
  if (value == "path_allowlist") {
    return GuardKind::path_allowlist;
  }
  if (value == "sanitizer") {
    return GuardKind::sanitizer;
  }
  if (value == "trusted_wrapper") {
    return GuardKind::trusted_wrapper;
  }
  if (value == "dead_branch") {
    return GuardKind::dead_branch;
  }
  return GuardKind::unknown;
}

inline std::string SymbolicValue::describe() const {
  switch (kind) {
    case SymbolicKind::parameter:
      return "parameter(" + std::to_string(parameter_index) + ":" + label + ")";
    case SymbolicKind::variable:
      return "variable(" + label + ")";
    case SymbolicKind::string_literal:
      return "\"" + label + "\"";
    case SymbolicKind::integer_literal:
      return integer_value ? std::to_string(*integer_value) : label;
    case SymbolicKind::boolean_literal:
      return boolean_value && *boolean_value ? "true" : "false";
    case SymbolicKind::source:
      return "source(" + label + ")";
    case SymbolicKind::call_result:
      return "call(" + label + ")";
    case SymbolicKind::sanitized:
      return "sanitized(" + label + ")";
    case SymbolicKind::allowlisted:
      return "allowlisted(" + label + ")";
    case SymbolicKind::trusted:
      return "trusted(" + label + ")";
    case SymbolicKind::concatenation:
      return "concat(" + label + ")";
    case SymbolicKind::unknown:
      break;
  }
  return label.empty() ? "unknown" : label;
}

inline std::set<int> SymbolicValue::parameter_dependencies() const {
  std::set<int> dependencies;
  if (kind == SymbolicKind::parameter && parameter_index >= 0) {
    dependencies.insert(parameter_index);
  }
  for (const auto& input : inputs) {
    const auto child = input.parameter_dependencies();
    dependencies.insert(child.begin(), child.end());
  }
  return dependencies;
}

inline bool SymbolicValue::depends_on_parameter() const {
  return !parameter_dependencies().empty();
}

inline bool SymbolicValue::has_kind(const SymbolicKind expected) const {
  if (kind == expected) {
    return true;
  }
  for (const auto& input : inputs) {
    if (input.has_kind(expected)) {
      return true;
    }
  }
  return false;
}

inline bool SymbolicValue::is_literal() const {
  return kind == SymbolicKind::string_literal || kind == SymbolicKind::integer_literal ||
         kind == SymbolicKind::boolean_literal;
}

inline bool SymbolicValue::is_unknown_like() const {
  return kind == SymbolicKind::unknown || kind == SymbolicKind::variable ||
         kind == SymbolicKind::call_result;
}

inline void to_json(nlohmann::json& json, const SourceLocation& value) {
  json = nlohmann::json{
    {"file", value.file},
    {"line", value.line},
    {"column", value.column},
  };
}

inline void from_json(const nlohmann::json& json, SourceLocation& value) {
  value.file = json.value("file", "");
  value.line = json.value("line", 0);
  value.column = json.value("column", 0);
}

inline void to_json(nlohmann::json& json, const SymbolicValue& value) {
  json = nlohmann::json{
    {"kind", to_string(value.kind)},
    {"label", value.label},
    {"parameter_index", value.parameter_index},
    {"integer_value", value.integer_value},
    {"boolean_value", value.boolean_value},
    {"inputs", value.inputs},
    {"location", value.location},
    {"bounded", value.bounded},
    {"compile_time_constant", value.compile_time_constant},
  };
}

inline void from_json(const nlohmann::json& json, SymbolicValue& value) {
  value.kind = symbolic_kind_from_string(json.value("kind", "unknown"));
  value.label = json.value("label", "");
  value.parameter_index = json.value("parameter_index", -1);
  value.integer_value = json.contains("integer_value") && !json.at("integer_value").is_null()
                          ? std::optional<long long>(json.at("integer_value").get<long long>())
                          : std::nullopt;
  value.boolean_value = json.contains("boolean_value") && !json.at("boolean_value").is_null()
                          ? std::optional<bool>(json.at("boolean_value").get<bool>())
                          : std::nullopt;
  value.inputs = json.value("inputs", std::vector<SymbolicValue>{});
  value.location = json.contains("location") && !json.at("location").is_null()
                     ? std::optional<SourceLocation>(json.at("location").get<SourceLocation>())
                     : std::nullopt;
  value.bounded = json.value("bounded", false);
  value.compile_time_constant = json.value("compile_time_constant", false);
}

inline void to_json(nlohmann::json& json, const GuardCondition& value) {
  json = nlohmann::json{
    {"kind", to_string(value.kind)},
    {"predicate", value.predicate},
    {"subject", value.subject},
    {"positive", value.positive},
    {"compile_time_known", value.compile_time_known},
    {"compile_time_value", value.compile_time_value},
    {"location", value.location},
  };
}

inline void from_json(const nlohmann::json& json, GuardCondition& value) {
  value.kind = guard_kind_from_string(json.value("kind", "unknown"));
  value.predicate = json.value("predicate", "");
  value.subject = json.at("subject").get<SymbolicValue>();
  value.positive = json.value("positive", true);
  value.compile_time_known = json.value("compile_time_known", false);
  value.compile_time_value = json.value("compile_time_value", false);
  value.location = json.value("location", SourceLocation{});
}

inline void to_json(nlohmann::json& json, const CallArgument& value) {
  json = nlohmann::json{
    {"value", value.value},
    {"expression_text", value.expression_text},
    {"static_extent", value.static_extent},
    {"location", value.location},
  };
}

inline void from_json(const nlohmann::json& json, CallArgument& value) {
  value.value = json.at("value").get<SymbolicValue>();
  value.expression_text = json.value("expression_text", "");
  value.static_extent = json.contains("static_extent") && !json.at("static_extent").is_null()
                          ? std::optional<std::size_t>(json.at("static_extent").get<std::size_t>())
                          : std::nullopt;
  value.location = json.value("location", SourceLocation{});
}

inline void to_json(nlohmann::json& json, const CallRecord& value) {
  json = nlohmann::json{
    {"function_name", value.function_name},
    {"arguments", value.arguments},
    {"active_guards", value.active_guards},
    {"location", value.location},
    {"is_member_call", value.is_member_call},
    {"is_constructor", value.is_constructor},
  };
}

inline void from_json(const nlohmann::json& json, CallRecord& value) {
  value.function_name = json.value("function_name", "");
  value.arguments = json.value("arguments", std::vector<CallArgument>{});
  value.active_guards = json.value("active_guards", std::vector<GuardCondition>{});
  value.location = json.value("location", SourceLocation{});
  value.is_member_call = json.value("is_member_call", false);
  value.is_constructor = json.value("is_constructor", false);
}

inline void to_json(nlohmann::json& json, const FunctionSummary& value) {
  json = nlohmann::json{
    {"qualified_name", value.qualified_name},
    {"parameter_names", value.parameter_names},
    {"variable_extents", value.variable_extents},
    {"calls", value.calls},
    {"return_value", value.return_value},
    {"location", value.location},
    {"cfg_blocks", value.cfg_blocks},
    {"cfg_edges", value.cfg_edges},
    {"is_entrypoint", value.is_entrypoint},
    {"is_test_only", value.is_test_only},
  };
}

inline void from_json(const nlohmann::json& json, FunctionSummary& value) {
  value.qualified_name = json.value("qualified_name", "");
  value.parameter_names = json.value("parameter_names", std::vector<std::string>{});
  value.variable_extents =
    json.value("variable_extents", std::unordered_map<std::string, std::optional<std::size_t>>{});
  value.calls = json.value("calls", std::vector<CallRecord>{});
  value.return_value = json.contains("return_value") && !json.at("return_value").is_null()
                         ? std::optional<SymbolicValue>(json.at("return_value").get<SymbolicValue>())
                         : std::nullopt;
  value.location = json.value("location", SourceLocation{});
  value.cfg_blocks = json.value("cfg_blocks", static_cast<std::size_t>(0));
  value.cfg_edges = json.value("cfg_edges", static_cast<std::size_t>(0));
  value.is_entrypoint = json.value("is_entrypoint", false);
  value.is_test_only = json.value("is_test_only", false);
}

inline void to_json(nlohmann::json& json, const TranslationUnitSummary& value) {
  json = nlohmann::json{
    {"file_path", value.file_path},
    {"functions", value.functions},
    {"diagnostics", value.diagnostics},
  };
}

inline void from_json(const nlohmann::json& json, TranslationUnitSummary& value) {
  value.file_path = json.value("file_path", "");
  value.functions = json.value("functions", std::vector<FunctionSummary>{});
  value.diagnostics = json.value("diagnostics", std::vector<std::string>{});
}

inline void to_json(nlohmann::json& json, const TraceStep& value) {
  json = nlohmann::json{
    {"message", value.message},
    {"location", value.location},
  };
}

inline void from_json(const nlohmann::json& json, TraceStep& value) {
  value.message = json.value("message", "");
  value.location = json.value("location", SourceLocation{});
}

inline void to_json(nlohmann::json& json, const CandidateFinding& value) {
  json = nlohmann::json{
    {"rule_id", value.rule_id},
    {"kind", to_string(value.kind)},
    {"severity", to_string(value.severity)},
    {"title", value.title},
    {"function_name", value.function_name},
    {"sink_name", value.sink_name},
    {"sink_arguments", value.sink_arguments},
    {"source_summary", value.source_summary},
    {"sink_summary", value.sink_summary},
    {"trace", value.trace},
    {"guards", value.guards},
    {"positive_conditions", value.positive_conditions},
    {"negative_conditions", value.negative_conditions},
    {"ambiguous_conditions", value.ambiguous_conditions},
    {"sink_value", value.sink_value},
    {"source_location", value.source_location},
    {"sink_location", value.sink_location},
    {"from_test_only", value.from_test_only},
    {"llm_review_candidate", value.llm_review_candidate},
  };
}

inline void from_json(const nlohmann::json& json, CandidateFinding& value) {
  value.rule_id = json.value("rule_id", "");
  value.kind = rule_kind_from_string(json.value("kind", "command_injection"));
  value.severity = severity_from_string(json.value("severity", "medium"));
  value.title = json.value("title", "");
  value.function_name = json.value("function_name", "");
  value.sink_name = json.value("sink_name", "");
  value.sink_arguments = json.value("sink_arguments", std::vector<CallArgument>{});
  value.source_summary = json.value("source_summary", "");
  value.sink_summary = json.value("sink_summary", "");
  value.trace = json.value("trace", std::vector<TraceStep>{});
  value.guards = json.value("guards", std::vector<GuardCondition>{});
  value.positive_conditions = json.value("positive_conditions", std::vector<std::string>{});
  value.negative_conditions = json.value("negative_conditions", std::vector<std::string>{});
  value.ambiguous_conditions = json.value("ambiguous_conditions", std::vector<std::string>{});
  value.sink_value = json.at("sink_value").get<SymbolicValue>();
  value.source_location = json.contains("source_location") && !json.at("source_location").is_null()
                            ? std::optional<SourceLocation>(json.at("source_location").get<SourceLocation>())
                            : std::nullopt;
  value.sink_location = json.value("sink_location", SourceLocation{});
  value.from_test_only = json.value("from_test_only", false);
  value.llm_review_candidate = json.value("llm_review_candidate", false);
}

inline void to_json(nlohmann::json& json, const ValidationResult& value) {
  json = nlohmann::json{
    {"decision", to_string(value.decision)},
    {"confidence", value.confidence},
    {"reasons", value.reasons},
    {"suppressions", value.suppressions},
    {"validator_tags", value.validator_tags},
    {"llm_review_recommended", value.llm_review_recommended},
  };
}

inline void from_json(const nlohmann::json& json, ValidationResult& value) {
  value.decision = decision_from_string(json.value("decision", "needs_review"));
  value.confidence = json.value("confidence", 0.0);
  value.reasons = json.value("reasons", std::vector<std::string>{});
  value.suppressions = json.value("suppressions", std::vector<std::string>{});
  value.validator_tags = json.value("validator_tags", std::vector<std::string>{});
  value.llm_review_recommended = json.value("llm_review_recommended", false);
}

inline void to_json(nlohmann::json& json, const FinalFinding& value) {
  json = nlohmann::json{
    {"candidate", value.candidate},
    {"validation", value.validation},
  };
}

inline void from_json(const nlohmann::json& json, FinalFinding& value) {
  value.candidate = json.at("candidate").get<CandidateFinding>();
  value.validation = json.at("validation").get<ValidationResult>();
}

inline void to_json(nlohmann::json& json, const ScanStats& value) {
  json = nlohmann::json{
    {"translation_units_total", value.translation_units_total},
    {"translation_units_analyzed", value.translation_units_analyzed},
    {"translation_units_from_cache", value.translation_units_from_cache},
    {"function_count", value.function_count},
    {"finding_count", value.finding_count},
  };
}

inline void from_json(const nlohmann::json& json, ScanStats& value) {
  value.translation_units_total = json.value("translation_units_total", static_cast<std::size_t>(0));
  value.translation_units_analyzed =
    json.value("translation_units_analyzed", static_cast<std::size_t>(0));
  value.translation_units_from_cache =
    json.value("translation_units_from_cache", static_cast<std::size_t>(0));
  value.function_count = json.value("function_count", static_cast<std::size_t>(0));
  value.finding_count = json.value("finding_count", static_cast<std::size_t>(0));
}

inline void to_json(nlohmann::json& json, const ScanResult& value) {
  json = nlohmann::json{
    {"summaries", value.summaries},
    {"findings", value.findings},
    {"stats", value.stats},
  };
}

inline void from_json(const nlohmann::json& json, ScanResult& value) {
  value.summaries = json.value("summaries", std::vector<TranslationUnitSummary>{});
  value.findings = json.value("findings", std::vector<FinalFinding>{});
  value.stats = json.value("stats", ScanStats{});
}

}  // namespace sast::ir
