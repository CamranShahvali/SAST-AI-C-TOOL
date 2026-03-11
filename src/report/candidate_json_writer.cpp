#include "sast/report/candidate_json_writer.hpp"

#include <algorithm>
#include <type_traits>

#include <nlohmann/json.hpp>

namespace sast::report {

namespace {

template <typename Container>
void sort_by_file_line_rule(Container& items) {
  std::sort(
    items.begin(),
    items.end(),
    [](const auto& lhs, const auto& rhs) {
      const auto& left = [&]() -> const ir::CandidateFinding& {
        if constexpr (std::is_same_v<typename Container::value_type, ir::CandidateFinding>) {
          return lhs;
        } else {
          return lhs.candidate;
        }
      }();
      const auto& right = [&]() -> const ir::CandidateFinding& {
        if constexpr (std::is_same_v<typename Container::value_type, ir::CandidateFinding>) {
          return rhs;
        } else {
          return rhs.candidate;
        }
      }();
      if (left.file != right.file) {
        return left.file < right.file;
      }
      if (left.line != right.line) {
        return left.line < right.line;
      }
      return left.rule_id < right.rule_id;
    });
}

}  // namespace

std::string CandidateJsonWriter::render(const ir::CandidateScanResult& result) {
  ir::CandidateScanResult sorted = result;
  sort_by_file_line_rule(sorted.candidates);

  const nlohmann::json json = sorted;
  return json.dump(2);
}

std::string CandidateJsonWriter::render(const ir::ValidatedScanResult& result) {
  ir::ValidatedScanResult sorted = result;
  sort_by_file_line_rule(sorted.findings);

  const nlohmann::json json = sorted;
  return json.dump(2);
}

}  // namespace sast::report
