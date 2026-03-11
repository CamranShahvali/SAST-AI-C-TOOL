#include "sast/triage/scan_service.hpp"

#include <chrono>
#include <fstream>
#include <sstream>
#include <string>

#include "sast/build/compilation_database_locator.hpp"
#include "sast/frontend_cpp/tooling_runner.hpp"
#include "sast/ingest/file_inventory.hpp"
#include "sast/llm_gateway/review_client.hpp"
#include "sast/rules/candidate_detector.hpp"
#include "sast/rules/rule_registry.hpp"
#include "sast/rules/source_sink_registry.hpp"
#include "sast/validators/finding_validator.hpp"
#include "sast/validators/validator_registry.hpp"

namespace sast::triage {

namespace {

using Clock = std::chrono::steady_clock;

double milliseconds_since(const Clock::time_point start, const Clock::time_point end) {
  return std::chrono::duration<double, std::milli>(end - start).count();
}

std::optional<std::uint64_t> current_rss_bytes() {
#if defined(__linux__)
  std::ifstream input("/proc/self/status");
  if (!input) {
    return std::nullopt;
  }

  std::string line;
  while (std::getline(input, line)) {
    if (!line.starts_with("VmRSS:")) {
      continue;
    }

    std::istringstream stream(line);
    std::string label;
    std::uint64_t value = 0;
    std::string unit;
    if (!(stream >> label >> value >> unit)) {
      return std::nullopt;
    }

    if (unit == "kB") {
      return value * 1024;
    }
    return value;
  }
#endif
  return std::nullopt;
}

}  // namespace

ScanBundle ScanService::scan(const ScanOptions& options) const {
  const auto full_start = Clock::now();
  const auto repo_root = std::filesystem::absolute(options.repo_root);

  const auto compilation_database =
    build::CompilationDatabaseLocator::locate(repo_root, options.explicit_compdb);

  std::vector<build::CompileCommandInfo> commands;
  std::filesystem::path compilation_database_path = "synthetic";
  if (compilation_database) {
    commands = build::CompilationDatabaseLocator::read_commands(*compilation_database);
    compilation_database_path = *compilation_database;
  } else {
    commands = build::CompilationDatabaseLocator::build_synthetic(
      repo_root,
      ingest::FileInventory::list_source_files(repo_root));
  }

  const auto changed_files = options.changed_files
                               ? ingest::FileInventory::read_changed_files(*options.changed_files, repo_root)
                               : std::vector<std::filesystem::path>{};

  const auto selected_commands = changed_files.empty()
                                   ? commands
                                   : build::CompilationDatabaseLocator::filter_commands(commands, changed_files);

  ScanBundle bundle;
  bundle.metrics.translation_units_total = commands.size();
  bundle.metrics.translation_units_selected = selected_commands.size();
  bundle.metrics.translation_units_skipped = commands.size() - selected_commands.size();
  bundle.metrics.effective_skip_rate =
    commands.empty()
      ? 0.0
      : static_cast<double>(bundle.metrics.translation_units_skipped) /
          static_cast<double>(commands.size());
  bundle.metrics.llm_review_enabled = options.llm_review;
  bundle.candidates.compilation_database_path = compilation_database_path.string();
  bundle.validated.compilation_database_path = compilation_database_path.string();

  if (selected_commands.empty()) {
    bundle.metrics.memory_rss_bytes = current_rss_bytes();
    bundle.metrics.full_scan_time_ms = milliseconds_since(full_start, Clock::now());
    return bundle;
  }

  frontend_cpp::ToolingRunner runner;
  const auto parse_start = Clock::now();
  const auto facts = runner.analyze(
    selected_commands,
    compilation_database_path,
    {.jobs = options.jobs, .project_root = repo_root});
  bundle.metrics.parse_time_ms = milliseconds_since(parse_start, Clock::now());

  const auto rule_registry = rules::RuleRegistry::load(repo_root);
  const auto registry = rules::SourceSinkRegistry::load(repo_root);
  rules::CandidateDetector detector(rule_registry, registry);

  const auto candidate_start = Clock::now();
  bundle.candidates = detector.detect(facts);
  bundle.metrics.candidate_generation_time_ms = milliseconds_since(candidate_start, Clock::now());
  bundle.metrics.candidate_count = bundle.candidates.candidates.size();

  const auto validator_registry = validators::ValidatorRegistry::load(repo_root);
  const validators::FindingValidator validator(validator_registry);

  const auto validation_start = Clock::now();
  bundle.validated.compilation_database_path = bundle.candidates.compilation_database_path;
  for (const auto& candidate : bundle.candidates.candidates) {
    bundle.validated.findings.push_back({
      .candidate = candidate,
      .validation = validator.validate(candidate),
    });
  }
  bundle.metrics.validation_time_ms = milliseconds_since(validation_start, Clock::now());
  bundle.metrics.finding_count = bundle.validated.findings.size();

  if (options.llm_review && !bundle.validated.findings.empty()) {
    const auto llm_start = Clock::now();
    const llm_gateway::ReviewClient review_client(
      {
        .gateway_url = options.llm_gateway_url,
        .timeout_seconds = options.llm_timeout_seconds,
      },
      options.llm_transport);
    for (auto& finding : bundle.validated.findings) {
      if (const auto review = review_client.review(finding)) {
        finding.validation.llm_review = *review;
      }
    }
    bundle.metrics.llm_latency_ms = milliseconds_since(llm_start, Clock::now());
  }

  bundle.metrics.memory_rss_bytes = current_rss_bytes();
  bundle.metrics.full_scan_time_ms = milliseconds_since(full_start, Clock::now());

  return bundle;
}

}  // namespace sast::triage
