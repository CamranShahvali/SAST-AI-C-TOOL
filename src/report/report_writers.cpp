#include "sast/report/report_writers.hpp"

#include <algorithm>
#include <filesystem>
#include <sstream>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace sast::report {

namespace {

struct SortedFinding {
  std::size_t index = 0;
  const ir::FinalFinding* finding = nullptr;
};

std::vector<SortedFinding> sorted_findings(const ir::ValidatedScanResult& result) {
  std::vector<SortedFinding> findings;
  findings.reserve(result.findings.size());
  for (std::size_t index = 0; index < result.findings.size(); ++index) {
    findings.push_back({.index = index, .finding = &result.findings[index]});
  }

  std::sort(
    findings.begin(),
    findings.end(),
    [](const SortedFinding& lhs, const SortedFinding& rhs) {
      const auto& left = lhs.finding->candidate;
      const auto& right = rhs.finding->candidate;
      if (left.file != right.file) {
        return left.file < right.file;
      }
      if (left.line != right.line) {
        return left.line < right.line;
      }
      if (left.rule_id != right.rule_id) {
        return left.rule_id < right.rule_id;
      }
      return lhs.index < rhs.index;
    });
  return findings;
}

std::string sarif_level(const ir::Decision decision) {
  switch (decision) {
    case ir::Decision::confirmed_issue:
      return "error";
    case ir::Decision::likely_issue:
      return "warning";
    case ir::Decision::needs_review:
      return "note";
    case ir::Decision::likely_safe:
    case ir::Decision::safe_suppressed:
      return "none";
  }
  return "note";
}

std::string rule_name_from_id(const std::string& rule_id) {
  if (rule_id == "command_injection.system") {
    return "Command Execution Misuse";
  }
  if (rule_id == "path_traversal.file_open") {
    return "Path Traversal / Unsafe File Access";
  }
  if (rule_id == "dangerous_string.unbounded_copy") {
    return "Dangerous Buffer Or String Handling";
  }
  return rule_id;
}

std::string joined_or_empty(const std::vector<std::string>& values) {
  if (values.empty()) {
    return "";
  }

  std::ostringstream stream;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index > 0) {
      stream << "; ";
    }
    stream << values[index];
  }
  return stream.str();
}

std::string stable_uri(const std::string& path) {
  return std::filesystem::path(path).generic_string();
}

}  // namespace

std::string ReportWriters::to_json(const ir::ValidatedScanResult& result) {
  ir::ValidatedScanResult sorted = result;
  sorted.findings.clear();
  for (const auto& entry : sorted_findings(result)) {
    sorted.findings.push_back(*entry.finding);
  }

  const nlohmann::json json = sorted;
  return json.dump(2);
}

std::string ReportWriters::to_sarif(const ir::ValidatedScanResult& result) {
  nlohmann::json rules = nlohmann::json::array();
  nlohmann::json sarif_results = nlohmann::json::array();

  std::unordered_map<std::string, bool> seen_rules;
  for (const auto& entry : sorted_findings(result)) {
    const auto& finding = *entry.finding;
    if (!seen_rules.contains(finding.candidate.rule_id)) {
      seen_rules.emplace(finding.candidate.rule_id, true);
      rules.push_back({
        {"id", finding.candidate.rule_id},
        {"name", rule_name_from_id(finding.candidate.rule_id)},
        {"shortDescription", {{"text", rule_name_from_id(finding.candidate.rule_id)}}},
        {"fullDescription", {{"text", "Deterministic ai_sast rule with validator-backed final classification."}}},
        {"properties", {
          {"rule_family", finding.candidate.rule_family},
          {"decision_values", nlohmann::json::array({
            "confirmed_issue",
            "likely_issue",
            "needs_review",
            "likely_safe",
            "safe_suppressed",
          })},
        }},
      });
    }

    sarif_results.push_back({
      {"ruleId", finding.candidate.rule_id},
      {"level", sarif_level(finding.validation.final_decision)},
      {"message", {{"text", finding.validation.explanation}}},
      {"locations", nlohmann::json::array({
        {
          {"physicalLocation", {
            {"artifactLocation", {{"uri", stable_uri(finding.candidate.file)}}},
            {"region", {
              {"startLine", finding.candidate.line},
              {"startColumn", finding.candidate.evidence_locations.empty()
                                  ? 1
                                  : finding.candidate.evidence_locations.front().column},
            }},
          }},
        },
      })},
      {"properties", {
        {"decision", ir::to_string(finding.validation.final_decision)},
        {"confidence", finding.validation.confidence},
        {"deterministic", finding.validation.deterministic},
        {"source_summary", finding.candidate.source_summary},
        {"sink_summary", finding.candidate.sink_summary},
        {"safe_reasoning", finding.validation.safe_reasoning},
        {"ambiguous_reasoning", finding.validation.ambiguous_reasoning},
        {"positive_conditions", finding.validation.matched_positive_conditions},
        {"negative_conditions", finding.validation.matched_negative_conditions},
        {"ambiguous_conditions", finding.validation.matched_ambiguous_conditions},
      }},
    });
    if (finding.validation.llm_review) {
      sarif_results.back()["properties"]["llm_review"] = *finding.validation.llm_review;
    }
  }

  const nlohmann::json sarif{
    {"version", "2.1.0"},
    {"$schema", "https://json.schemastore.org/sarif-2.1.0.json"},
    {"runs", nlohmann::json::array({
      {
        {"tool", {
          {"driver", {
            {"name", "ai_sast"},
            {"version", SAST_VERSION},
            {"informationUri", "https://example.com/ai_sast"},
            {"rules", rules},
          }},
        }},
        {"invocations", nlohmann::json::array({
          {
            {"executionSuccessful", true},
          },
        })},
        {"properties", {
          {"mode", result.mode},
          {"candidate_only", result.candidate_only},
          {"philosophy", result.philosophy},
        }},
        {"results", sarif_results},
      },
    })},
  };

  return sarif.dump(2);
}

std::string ReportWriters::to_text(const ir::ValidatedScanResult& result) {
  std::ostringstream output;
  output << "ai_sast " << SAST_VERSION << '\n';
  output << "mode: " << result.mode << '\n';
  output << "philosophy: " << result.philosophy << '\n';
  output << "compilation_database: " << result.compilation_database_path << '\n';
  output << "findings: " << result.findings.size() << "\n\n";

  for (const auto& entry : sorted_findings(result)) {
    const auto& finding = *entry.finding;
    output << "[" << ir::to_string(finding.validation.final_decision) << "] "
           << finding.candidate.rule_id << ' '
           << finding.candidate.file << ':' << finding.candidate.line << '\n';
    output << "  confidence: " << finding.validation.confidence
           << " deterministic=" << (finding.validation.deterministic ? "true" : "false") << '\n';
    output << "  source: " << finding.candidate.source_summary << '\n';
    output << "  sink:   " << finding.candidate.sink_summary << '\n';
    output << "  explanation: " << finding.validation.explanation << '\n';

    if (!finding.validation.safe_reasoning.empty()) {
      output << "  safe_reasoning: " << joined_or_empty(finding.validation.safe_reasoning) << '\n';
    }
    if (!finding.validation.ambiguous_reasoning.empty()) {
      output << "  ambiguous_reasoning: " << joined_or_empty(finding.validation.ambiguous_reasoning) << '\n';
    }
    if (!finding.validation.suppressions.empty()) {
      output << "  suppressions: " << joined_or_empty(finding.validation.suppressions) << '\n';
    }
    if (finding.validation.llm_review) {
      output << "  llm_review: provider_status=" << finding.validation.llm_review->provider_status
             << " judgment=" << ir::to_string(finding.validation.llm_review->judgment)
             << " confidence=" << finding.validation.llm_review->confidence << '\n';
      output << "  llm_reasoning: " << finding.validation.llm_review->reasoning_summary << '\n';
      if (finding.validation.llm_review->safe_reasoning) {
        output << "  llm_safe_reasoning: " << *finding.validation.llm_review->safe_reasoning << '\n';
      }
      if (finding.validation.llm_review->remediation) {
        output << "  llm_remediation: " << *finding.validation.llm_review->remediation << '\n';
      }
    }
    output << '\n';
  }

  return output.str();
}

}  // namespace sast::report
