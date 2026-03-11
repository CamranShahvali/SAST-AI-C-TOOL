#include "test_support.hpp"

#include <chrono>
#include <cstdlib>
#include <sstream>
#include <stdexcept>

#include "sast/build/compilation_database_locator.hpp"
#include "sast/frontend_cpp/tooling_runner.hpp"
#include "sast/ingest/file_inventory.hpp"
#include "sast/triage/scan_service.hpp"

namespace sast::testsupport {

namespace {

int run_command(const std::string& command) {
  return std::system(command.c_str());
}

void copy_fixture_sources(
  const std::filesystem::path& source_root,
  const std::filesystem::path& destination_root) {
  std::filesystem::create_directories(destination_root);

  std::filesystem::recursive_directory_iterator iterator(source_root);
  const std::filesystem::recursive_directory_iterator end;
  while (iterator != end) {
    const auto relative = std::filesystem::relative(iterator->path(), source_root);
    if (relative.empty()) {
      ++iterator;
      continue;
    }
    if (relative.begin() != relative.end() && *relative.begin() == "build") {
      if (iterator->is_directory()) {
        iterator.disable_recursion_pending();
      }
      ++iterator;
      continue;
    }

    const auto destination = destination_root / relative;
    if (iterator->is_directory()) {
      std::filesystem::create_directories(destination);
    } else if (iterator->is_regular_file()) {
      std::filesystem::create_directories(destination.parent_path());
      std::filesystem::copy_file(
        iterator->path(),
        destination,
        std::filesystem::copy_options::overwrite_existing);
    }
    ++iterator;
  }
}

}  // namespace

std::filesystem::path source_root() {
  return std::filesystem::path(SAST_SOURCE_ROOT);
}

std::filesystem::path fixture_root(const std::string& name) {
  return source_root() / "tests" / "fixtures" / name;
}

PreparedFixture configure_fixture_copy(const std::string& name) {
  const auto fixture_source = fixture_root(name);
  const auto unique_id = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto scratch_root =
    std::filesystem::temp_directory_path() / ("ai_sast_fixture_" + std::to_string(unique_id));

  std::filesystem::create_directories(scratch_root);
  const auto destination = scratch_root / name;
  copy_fixture_sources(fixture_source, destination);

  const auto build_dir = destination / "build";
  std::ostringstream command;
  command << "cmake -S \"" << destination.string() << "\""
          << " -B \"" << build_dir.string() << "\""
          << " -G Ninja"
          << " -DCMAKE_BUILD_TYPE=Debug"
          << " -DCMAKE_CXX_COMPILER=clang++-18"
          << " -DCMAKE_EXPORT_COMPILE_COMMANDS=ON";
  if (run_command(command.str()) != 0) {
    throw std::runtime_error("fixture configuration failed for " + name);
  }

  const auto compilation_database =
    sast::build::CompilationDatabaseLocator::locate(destination, std::nullopt);
  if (!compilation_database) {
    throw std::runtime_error("compile_commands.json not found for fixture " + name);
  }

  return {
    .root = destination,
    .build_dir = build_dir,
    .compilation_database = *compilation_database,
  };
}

ir::FactDatabase extract_fixture_facts(const std::string& name) {
  const auto prepared = configure_fixture_copy(name);
  const auto commands =
    sast::build::CompilationDatabaseLocator::read_commands(prepared.compilation_database);
  sast::frontend_cpp::ToolingRunner runner;
  return runner.analyze(
    commands,
    prepared.compilation_database,
    {.jobs = 1, .project_root = prepared.root});
}

ir::CandidateScanResult scan_candidate_repo(
  const std::filesystem::path& repo_root,
  const std::optional<std::filesystem::path>& explicit_compdb,
  const std::optional<std::filesystem::path>& changed_files) {
  sast::triage::ScanService service;
  return service.scan({
    .repo_root = std::filesystem::absolute(repo_root),
    .explicit_compdb = explicit_compdb,
    .changed_files = changed_files,
    .jobs = 1,
    .llm_review = false,
  }).candidates;
}

const ir::CandidateFinding* find_candidate(
  const ir::CandidateScanResult& result,
  const std::string& file_suffix) {
  for (const auto& candidate : result.candidates) {
    if (candidate.file.ends_with(file_suffix)) {
      return &candidate;
    }
  }
  return nullptr;
}

ir::ValidatedScanResult scan_validated_repo(
  const std::filesystem::path& repo_root,
  const std::optional<std::filesystem::path>& explicit_compdb,
  const std::optional<std::filesystem::path>& changed_files) {
  sast::triage::ScanService service;
  return service.scan({
    .repo_root = std::filesystem::absolute(repo_root),
    .explicit_compdb = explicit_compdb,
    .changed_files = changed_files,
    .jobs = 1,
    .llm_review = false,
  }).validated;
}

const ir::FinalFinding* find_finding(
  const ir::ValidatedScanResult& result,
  const std::string& file_suffix) {
  for (const auto& finding : result.findings) {
    if (finding.candidate.file.ends_with(file_suffix)) {
      return &finding;
    }
  }
  return nullptr;
}

}  // namespace sast::testsupport
