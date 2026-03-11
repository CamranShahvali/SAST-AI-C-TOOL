#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "sast/ir/facts.hpp"

namespace sast::testsupport {

struct PreparedFixture {
  std::filesystem::path root;
  std::filesystem::path build_dir;
  std::filesystem::path compilation_database;
};

std::filesystem::path source_root();
std::filesystem::path fixture_root(const std::string& name);
PreparedFixture configure_fixture_copy(const std::string& name);
ir::FactDatabase extract_fixture_facts(const std::string& name);
ir::CandidateScanResult scan_candidate_repo(
  const std::filesystem::path& repo_root,
  const std::optional<std::filesystem::path>& explicit_compdb = std::nullopt,
  const std::optional<std::filesystem::path>& changed_files = std::nullopt);
const ir::CandidateFinding* find_candidate(
  const ir::CandidateScanResult& result,
  const std::string& file_suffix);
ir::ValidatedScanResult scan_validated_repo(
  const std::filesystem::path& repo_root,
  const std::optional<std::filesystem::path>& explicit_compdb = std::nullopt,
  const std::optional<std::filesystem::path>& changed_files = std::nullopt);
const ir::FinalFinding* find_finding(
  const ir::ValidatedScanResult& result,
  const std::string& file_suffix);

}  // namespace sast::testsupport
