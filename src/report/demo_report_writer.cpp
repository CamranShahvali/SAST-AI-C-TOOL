#include "sast/report/demo_report_writer.hpp"

#include <sstream>

#include <nlohmann/json.hpp>

namespace sast::report {

namespace {

nlohmann::json finding_to_json(const ir::FinalFinding& finding) {
  nlohmann::json json{
    {"rule_id", finding.candidate.rule_id},
    {"file", finding.candidate.file},
    {"line", finding.candidate.line},
    {"source_summary", finding.candidate.source_summary},
    {"sink_summary", finding.candidate.sink_summary},
    {"trace_steps", finding.candidate.trace_steps},
    {"judgment", ir::to_string(finding.validation.final_decision)},
    {"confidence", finding.validation.confidence},
    {"deterministic", finding.validation.deterministic},
    {"explanation", finding.validation.explanation},
    {"safe_reasoning", finding.validation.safe_reasoning},
    {"ambiguous_reasoning", finding.validation.ambiguous_reasoning},
  };
  json["llm_review"] = finding.validation.llm_review
                         ? nlohmann::json(*finding.validation.llm_review)
                         : nlohmann::json(nullptr);
  return json;
}

std::string joined(const std::vector<std::string>& values) {
  std::ostringstream output;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index > 0) {
      output << "; ";
    }
    output << values[index];
  }
  return output.str();
}

}  // namespace

std::string DemoReportWriter::to_json(const DemoReport& report) {
  nlohmann::json cases = nlohmann::json::array();
  for (const auto& item : report.cases) {
    cases.push_back({
      {"slug", item.slug},
      {"title", item.title},
      {"story", item.story},
      {"takeaway", item.takeaway},
      {"finding", finding_to_json(item.finding)},
    });
  }

  const nlohmann::json json{
    {"mode", report.mode},
    {"title", report.title},
    {"philosophy", report.philosophy},
    {"honesty_note", report.honesty_note},
    {"case_count", report.cases.size()},
    {"cases", cases},
  };
  return json.dump(2);
}

std::string DemoReportWriter::to_text(const DemoReport& report) {
  std::ostringstream output;
  output << report.title << " " << SAST_VERSION << '\n';
  output << "cases: " << report.cases.size() << '\n';
  output << "philosophy: " << report.philosophy << '\n';
  output << "note: " << report.honesty_note << "\n\n";

  for (std::size_t index = 0; index < report.cases.size(); ++index) {
    const auto& item = report.cases[index];
    const auto& finding = item.finding;
    output << (index + 1) << ". " << item.title << '\n';
    output << "   story: " << item.story << '\n';
    output << "   takeaway: " << item.takeaway << '\n';
    output << "   deterministic:\n";
    output << "     file: " << finding.candidate.file << ':' << finding.candidate.line << '\n';
    output << "     rule: " << finding.candidate.rule_id << '\n';
    output << "     judgment: " << ir::to_string(finding.validation.final_decision)
           << " confidence=" << finding.validation.confidence
           << " deterministic=" << (finding.validation.deterministic ? "true" : "false") << '\n';
    output << "     source: " << finding.candidate.source_summary << '\n';
    output << "     sink:   " << finding.candidate.sink_summary << '\n';
    output << "     evidence: " << joined(finding.candidate.trace_steps) << '\n';
    output << "     explanation: " << finding.validation.explanation << '\n';
    if (!finding.validation.safe_reasoning.empty()) {
      output << "     safe_reasoning: " << joined(finding.validation.safe_reasoning) << '\n';
    }
    if (!finding.validation.ambiguous_reasoning.empty()) {
      output << "     ambiguous_reasoning: " << joined(finding.validation.ambiguous_reasoning) << '\n';
    }

    if (finding.validation.llm_review) {
      output << "   llm_review:\n";
      output << "     provider_status: " << finding.validation.llm_review->provider_status << '\n';
      output << "     judgment: " << ir::to_string(finding.validation.llm_review->judgment)
             << " confidence=" << finding.validation.llm_review->confidence << '\n';
      output << "     reasoning: " << finding.validation.llm_review->reasoning_summary << '\n';
      if (finding.validation.llm_review->safe_reasoning) {
        output << "     safe_reasoning: " << *finding.validation.llm_review->safe_reasoning << '\n';
      }
      if (finding.validation.llm_review->remediation) {
        output << "     remediation: " << *finding.validation.llm_review->remediation << '\n';
      }
    } else {
      output << "   llm_review: not requested or not eligible\n";
    }
    output << '\n';
  }

  output << "takeaway:\n";
  output << "- confirmed_issue: direct untrusted input reaches a dangerous sink without a safety barrier.\n";
  output << "- likely_issue: risk evidence is strong, but proof is still incomplete.\n";
  output << "- needs_review: the engine cannot yet prove the code safe or unsafe.\n";
  output << "- likely_safe: safety evidence exists, but it is not yet a full proof.\n";
  output << "- safe_suppressed: the validator proved a concrete safety barrier and dismissed the candidate.\n";
  return output.str();
}

}  // namespace sast::report
