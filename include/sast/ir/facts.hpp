#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace sast::ir {

enum class Decision {
  confirmed_issue,
  likely_issue,
  needs_review,
  likely_safe,
  safe_suppressed
};

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

struct SourceLocation {
  std::string file;
  int line = 0;
  int column = 0;

  [[nodiscard]] bool valid() const { return !file.empty() && line > 0; }
};

struct VariableRef {
  std::string name;
  std::string referenced_kind;
  SourceLocation location;
};

struct VariableDef {
  std::string name;
  std::string initializer_text;
  std::optional<std::size_t> static_extent;
  SourceLocation location;
};

struct CallSite {
  std::string callee;
  std::vector<std::string> argument_texts;
  SourceLocation location;
};

struct Function {
  std::string qualified_name;
  std::string return_type;
  SourceLocation location;
  std::vector<std::string> parameter_names;
  std::vector<CallSite> call_sites;
  std::vector<VariableRef> variable_refs;
  std::vector<VariableDef> variable_defs;
};

struct TranslationUnit {
  std::string file_path;
  std::vector<Function> functions;
  std::vector<std::string> diagnostics;
};

struct FactDatabase {
  std::string compilation_database_path;
  std::vector<TranslationUnit> translation_units;
};

struct CandidateFinding {
  std::string id;
  std::string rule_id;
  std::string rule_family;
  std::string file;
  int line = 0;
  std::string function_name;
  std::string sink_name;
  std::vector<std::string> sink_arguments;
  std::string source_expression;
  std::string source_summary;
  std::string sink_summary;
  std::vector<std::string> trace_steps;
  std::string provisional_severity;
  std::vector<SourceLocation> evidence_locations;
  std::vector<std::string> positive_conditions;
  std::vector<std::string> negative_conditions;
  std::vector<std::string> ambiguous_conditions;
  std::optional<std::size_t> destination_extent;
  std::string bound_expression;
  bool from_test_path = false;
};

struct CandidateScanResult {
  std::string mode = "candidate_scan";
  bool candidate_only = true;
  std::string notice =
    "Candidate findings are preliminary only. A candidate must be validated before it is treated as an issue.";
  std::string compilation_database_path;
  std::vector<CandidateFinding> candidates;
};

struct ValidationEvidence {
  std::string condition;
  std::string explanation;
  std::optional<SourceLocation> location;
};

struct LlmReview {
  Decision judgment = Decision::needs_review;
  double confidence = 0.0;
  std::optional<std::string> cwe;
  std::string exploitability = "unknown";
  std::string reasoning_summary;
  std::optional<std::string> remediation;
  std::optional<std::string> safe_reasoning;
  std::string provider_status = "fallback";
};

struct ValidationResult {
  Decision final_decision = Decision::needs_review;
  double confidence = 0.0;
  bool deterministic = false;
  std::string explanation;
  std::vector<ValidationEvidence> matched_positive_conditions;
  std::vector<ValidationEvidence> matched_negative_conditions;
  std::vector<ValidationEvidence> matched_ambiguous_conditions;
  std::vector<std::string> safe_reasoning;
  std::vector<std::string> ambiguous_reasoning;
  std::vector<std::string> suppressions;
  std::optional<LlmReview> llm_review;
};

struct FinalFinding {
  CandidateFinding candidate;
  ValidationResult validation;
};

struct ValidatedScanResult {
  std::string mode = "validated_scan";
  bool candidate_only = false;
  std::string philosophy = "candidate -> validate -> prove vulnerable or dismiss";
  std::string compilation_database_path;
  std::vector<FinalFinding> findings;
};

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

inline void to_json(nlohmann::json& json, const VariableRef& value) {
  json = nlohmann::json{
    {"name", value.name},
    {"referenced_kind", value.referenced_kind},
    {"location", value.location},
  };
}

inline void from_json(const nlohmann::json& json, VariableRef& value) {
  value.name = json.value("name", "");
  value.referenced_kind = json.value("referenced_kind", "");
  value.location = json.value("location", SourceLocation{});
}

inline void to_json(nlohmann::json& json, const VariableDef& value) {
  json = nlohmann::json{
    {"name", value.name},
    {"initializer_text", value.initializer_text},
    {"location", value.location},
  };
  json["static_extent"] = value.static_extent
                            ? nlohmann::json(*value.static_extent)
                            : nlohmann::json(nullptr);
}

inline void from_json(const nlohmann::json& json, VariableDef& value) {
  value.name = json.value("name", "");
  value.initializer_text = json.value("initializer_text", "");
  value.static_extent = json.contains("static_extent") && !json.at("static_extent").is_null()
                          ? std::optional<std::size_t>(json.at("static_extent").get<std::size_t>())
                          : std::nullopt;
  value.location = json.value("location", SourceLocation{});
}

inline void to_json(nlohmann::json& json, const CallSite& value) {
  json = nlohmann::json{
    {"callee", value.callee},
    {"argument_texts", value.argument_texts},
    {"location", value.location},
  };
}

inline void from_json(const nlohmann::json& json, CallSite& value) {
  value.callee = json.value("callee", "");
  value.argument_texts = json.value("argument_texts", std::vector<std::string>{});
  value.location = json.value("location", SourceLocation{});
}

inline void to_json(nlohmann::json& json, const Function& value) {
  json = nlohmann::json{
    {"qualified_name", value.qualified_name},
    {"return_type", value.return_type},
    {"location", value.location},
    {"parameter_names", value.parameter_names},
    {"call_sites", value.call_sites},
    {"variable_refs", value.variable_refs},
    {"variable_defs", value.variable_defs},
  };
}

inline void from_json(const nlohmann::json& json, Function& value) {
  value.qualified_name = json.value("qualified_name", "");
  value.return_type = json.value("return_type", "");
  value.location = json.value("location", SourceLocation{});
  value.parameter_names = json.value("parameter_names", std::vector<std::string>{});
  value.call_sites = json.value("call_sites", std::vector<CallSite>{});
  value.variable_refs = json.value("variable_refs", std::vector<VariableRef>{});
  value.variable_defs = json.value("variable_defs", std::vector<VariableDef>{});
}

inline void to_json(nlohmann::json& json, const TranslationUnit& value) {
  json = nlohmann::json{
    {"file_path", value.file_path},
    {"functions", value.functions},
    {"diagnostics", value.diagnostics},
  };
}

inline void from_json(const nlohmann::json& json, TranslationUnit& value) {
  value.file_path = json.value("file_path", "");
  value.functions = json.value("functions", std::vector<Function>{});
  value.diagnostics = json.value("diagnostics", std::vector<std::string>{});
}

inline void to_json(nlohmann::json& json, const FactDatabase& value) {
  json = nlohmann::json{
    {"compilation_database_path", value.compilation_database_path},
    {"translation_units", value.translation_units},
  };
}

inline void from_json(const nlohmann::json& json, FactDatabase& value) {
  value.compilation_database_path = json.value("compilation_database_path", "");
  value.translation_units = json.value("translation_units", std::vector<TranslationUnit>{});
}

inline void to_json(nlohmann::json& json, const CandidateFinding& value) {
  json = nlohmann::json{
    {"id", value.id},
    {"rule_id", value.rule_id},
    {"rule_family", value.rule_family},
    {"file", value.file},
    {"line", value.line},
    {"function_name", value.function_name},
    {"sink_name", value.sink_name},
    {"sink_arguments", value.sink_arguments},
    {"source_expression", value.source_expression},
    {"source_summary", value.source_summary},
    {"sink_summary", value.sink_summary},
    {"trace_steps", value.trace_steps},
    {"provisional_severity", value.provisional_severity},
    {"evidence_locations", value.evidence_locations},
    {"positive_conditions", value.positive_conditions},
    {"negative_conditions", value.negative_conditions},
    {"ambiguous_conditions", value.ambiguous_conditions},
    {"bound_expression", value.bound_expression},
    {"from_test_path", value.from_test_path},
  };
  json["destination_extent"] = value.destination_extent
                                 ? nlohmann::json(*value.destination_extent)
                                 : nlohmann::json(nullptr);
}

inline void from_json(const nlohmann::json& json, CandidateFinding& value) {
  value.id = json.value("id", "");
  value.rule_id = json.value("rule_id", "");
  value.rule_family = json.value("rule_family", "");
  value.file = json.value("file", "");
  value.line = json.value("line", 0);
  value.function_name = json.value("function_name", "");
  value.sink_name = json.value("sink_name", "");
  value.sink_arguments = json.value("sink_arguments", std::vector<std::string>{});
  value.source_expression = json.value("source_expression", "");
  value.source_summary = json.value("source_summary", "");
  value.sink_summary = json.value("sink_summary", "");
  value.trace_steps = json.value("trace_steps", std::vector<std::string>{});
  value.provisional_severity = json.value("provisional_severity", "");
  value.evidence_locations = json.value("evidence_locations", std::vector<SourceLocation>{});
  value.positive_conditions = json.value("positive_conditions", std::vector<std::string>{});
  value.negative_conditions = json.value("negative_conditions", std::vector<std::string>{});
  value.ambiguous_conditions = json.value("ambiguous_conditions", std::vector<std::string>{});
  value.destination_extent =
    json.contains("destination_extent") && !json.at("destination_extent").is_null()
      ? std::optional<std::size_t>(json.at("destination_extent").get<std::size_t>())
      : std::nullopt;
  value.bound_expression = json.value("bound_expression", "");
  value.from_test_path = json.value("from_test_path", false);
}

inline void to_json(nlohmann::json& json, const CandidateScanResult& value) {
  json = nlohmann::json{
    {"mode", value.mode},
    {"candidate_only", value.candidate_only},
    {"notice", value.notice},
    {"compilation_database_path", value.compilation_database_path},
    {"candidates", value.candidates},
  };
}

inline void from_json(const nlohmann::json& json, CandidateScanResult& value) {
  value.mode = json.value("mode", "candidate_scan");
  value.candidate_only = json.value("candidate_only", true);
  value.notice = json.value("notice", "");
  value.compilation_database_path = json.value("compilation_database_path", "");
  value.candidates = json.value("candidates", std::vector<CandidateFinding>{});
}

inline void to_json(nlohmann::json& json, const ValidationEvidence& value) {
  json = nlohmann::json{
    {"condition", value.condition},
    {"explanation", value.explanation},
  };
  json["location"] = value.location
                       ? nlohmann::json(*value.location)
                       : nlohmann::json(nullptr);
}

inline void from_json(const nlohmann::json& json, ValidationEvidence& value) {
  value.condition = json.value("condition", "");
  value.explanation = json.value("explanation", "");
  value.location = json.contains("location") && !json.at("location").is_null()
                     ? std::optional<SourceLocation>(json.at("location").get<SourceLocation>())
                     : std::nullopt;
}

inline void to_json(nlohmann::json& json, const LlmReview& value) {
  json = nlohmann::json{
    {"judgment", to_string(value.judgment)},
    {"confidence", value.confidence},
    {"exploitability", value.exploitability},
    {"reasoning_summary", value.reasoning_summary},
    {"provider_status", value.provider_status},
  };
  json["cwe"] = value.cwe ? nlohmann::json(*value.cwe) : nlohmann::json(nullptr);
  json["remediation"] = value.remediation ? nlohmann::json(*value.remediation) : nlohmann::json(nullptr);
  json["safe_reasoning"] = value.safe_reasoning ? nlohmann::json(*value.safe_reasoning) : nlohmann::json(nullptr);
}

inline void from_json(const nlohmann::json& json, LlmReview& value) {
  value.judgment = decision_from_string(json.value("judgment", "needs_review"));
  value.confidence = json.value("confidence", 0.0);
  value.cwe = json.contains("cwe") && !json.at("cwe").is_null()
                ? std::optional<std::string>(json.at("cwe").get<std::string>())
                : std::nullopt;
  value.exploitability = json.value("exploitability", "unknown");
  value.reasoning_summary = json.value("reasoning_summary", "");
  value.remediation = json.contains("remediation") && !json.at("remediation").is_null()
                        ? std::optional<std::string>(json.at("remediation").get<std::string>())
                        : std::nullopt;
  value.safe_reasoning = json.contains("safe_reasoning") && !json.at("safe_reasoning").is_null()
                           ? std::optional<std::string>(json.at("safe_reasoning").get<std::string>())
                           : std::nullopt;
  value.provider_status = json.value("provider_status", "fallback");
}

inline void to_json(nlohmann::json& json, const ValidationResult& value) {
  json = nlohmann::json{
    {"final_decision", to_string(value.final_decision)},
    {"confidence", value.confidence},
    {"deterministic", value.deterministic},
    {"explanation", value.explanation},
    {"matched_positive_conditions", value.matched_positive_conditions},
    {"matched_negative_conditions", value.matched_negative_conditions},
    {"matched_ambiguous_conditions", value.matched_ambiguous_conditions},
    {"safe_reasoning", value.safe_reasoning},
    {"ambiguous_reasoning", value.ambiguous_reasoning},
    {"suppressions", value.suppressions},
  };
  if (value.llm_review) {
    json["llm_review"] = *value.llm_review;
  }
}

inline void from_json(const nlohmann::json& json, ValidationResult& value) {
  value.final_decision = decision_from_string(json.value("final_decision", "needs_review"));
  value.confidence = json.value("confidence", 0.0);
  value.deterministic = json.value("deterministic", false);
  value.explanation = json.value("explanation", "");
  value.matched_positive_conditions =
    json.value("matched_positive_conditions", std::vector<ValidationEvidence>{});
  value.matched_negative_conditions =
    json.value("matched_negative_conditions", std::vector<ValidationEvidence>{});
  value.matched_ambiguous_conditions =
    json.value("matched_ambiguous_conditions", std::vector<ValidationEvidence>{});
  value.safe_reasoning = json.value("safe_reasoning", std::vector<std::string>{});
  value.ambiguous_reasoning = json.value("ambiguous_reasoning", std::vector<std::string>{});
  value.suppressions = json.value("suppressions", std::vector<std::string>{});
  value.llm_review = json.contains("llm_review") && !json.at("llm_review").is_null()
                       ? std::optional<LlmReview>(json.at("llm_review").get<LlmReview>())
                       : std::nullopt;
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

inline void to_json(nlohmann::json& json, const ValidatedScanResult& value) {
  json = nlohmann::json{
    {"mode", value.mode},
    {"candidate_only", value.candidate_only},
    {"philosophy", value.philosophy},
    {"compilation_database_path", value.compilation_database_path},
    {"findings", value.findings},
  };
}

inline void from_json(const nlohmann::json& json, ValidatedScanResult& value) {
  value.mode = json.value("mode", "validated_scan");
  value.candidate_only = json.value("candidate_only", false);
  value.philosophy = json.value("philosophy", "");
  value.compilation_database_path = json.value("compilation_database_path", "");
  value.findings = json.value("findings", std::vector<FinalFinding>{});
}

}  // namespace sast::ir
