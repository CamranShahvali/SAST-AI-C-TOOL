#include "sast/report/demo_report_writer.hpp"

#include <sstream>

#include <nlohmann/json.hpp>

namespace sast::report {

namespace {

nlohmann::json finding_to_json(const ir::FinalFinding& finding) {
  return nlohmann::json{
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
    output << "   file: " << finding.candidate.file << ':' << finding.candidate.line << '\n';
    output << "   rule: " << finding.candidate.rule_id << '\n';
    output << "   judgment: " << ir::to_string(finding.validation.final_decision)
           << " confidence=" << finding.validation.confidence
           << " deterministic=" << (finding.validation.deterministic ? "true" : "false") << '\n';
    output << "   takeaway: " << item.takeaway << '\n';
    output << "   evidence: " << joined(finding.candidate.trace_steps) << '\n';
    output << "   explanation: " << finding.validation.explanation << '\n';
    if (!finding.validation.safe_reasoning.empty()) {
      output << "   safe_reasoning: " << joined(finding.validation.safe_reasoning) << '\n';
    }
    if (!finding.validation.ambiguous_reasoning.empty()) {
      output << "   ambiguous_reasoning: " << joined(finding.validation.ambiguous_reasoning) << '\n';
    }
    output << '\n';
  }

  output << "takeaway:\n";
  output << "- The deterministic engine can confirm a direct issue.\n";
  output << "- It can dismiss a lookalike when the validator proves a safety barrier.\n";
  output << "- It can still make a deterministic call on a helper-boundary case in the current MVP.\n";
  return output.str();
}

}  // namespace sast::report
