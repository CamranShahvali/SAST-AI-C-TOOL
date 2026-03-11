#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "sast/triage/scan_service.hpp"

namespace {

std::string require_value(const std::vector<std::string>& args, const std::size_t index) {
  if (index + 1 >= args.size()) {
    throw std::runtime_error("missing value for " + args[index]);
  }
  return args[index + 1];
}

struct ParsedArgs {
  std::filesystem::path repo_root = std::filesystem::path(SAST_SOURCE_ROOT) / "benchmarks" / "fixtures" / "mixed_repo";
  std::optional<std::filesystem::path> changed_files;
  bool llm_review = false;
};

ParsedArgs parse_args(const std::vector<std::string>& args) {
  ParsedArgs parsed;
  for (std::size_t index = 0; index < args.size(); ++index) {
    const auto& arg = args[index];
    if (arg == "--repo") {
      parsed.repo_root = require_value(args, index);
      ++index;
    } else if (arg == "--changed-files") {
      parsed.changed_files = require_value(args, index);
      ++index;
    } else if (arg == "--llm-review") {
      parsed.llm_review = true;
    }
  }
  return parsed;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const std::vector<std::string> args(argv + 1, argv + argc);
    const auto parsed = parse_args(args);

    sast::triage::ScanService service;
    const auto bundle = service.scan({
      .repo_root = std::filesystem::absolute(parsed.repo_root),
      .explicit_compdb = std::nullopt,
      .changed_files = parsed.changed_files,
      .jobs = 1,
      .llm_review = parsed.llm_review,
    });

    std::map<std::string, std::size_t> decisions;
    for (const auto& finding : bundle.validated.findings) {
      ++decisions[sast::ir::to_string(finding.validation.final_decision)];
    }

    const nlohmann::json report{
      {"repo_root", std::filesystem::absolute(parsed.repo_root).string()},
      {"metrics", bundle.metrics},
      {"decision_counts", decisions},
      {"candidate_count", bundle.candidates.candidates.size()},
      {"finding_count", bundle.validated.findings.size()},
    };
    std::cout << report.dump(2) << '\n';
    return 0;
  } catch (const std::exception& exception) {
    std::cerr << "sast-benchmarks failed: " << exception.what() << '\n';
    return 1;
  }
}
