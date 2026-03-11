#include "sast/validators/validator_registry.hpp"

#include <fstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

namespace sast::validators {

namespace {

constexpr int kExpectedConfigVersion = 1;

std::filesystem::path resolve_config(
  const std::filesystem::path& repo_root,
  const std::string& filename) {
  const auto repo_path = repo_root / "config" / filename;
  if (std::filesystem::exists(repo_path)) {
    return repo_path;
  }
  return std::filesystem::path(SAST_SOURCE_ROOT) / "config" / filename;
}

nlohmann::json read_json(const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input.good()) {
    throw std::runtime_error("failed to open config file " + path.string());
  }

  nlohmann::json json;
  input >> json;
  if (json.value("version", -1) != kExpectedConfigVersion) {
    throw std::runtime_error(
      "unsupported config version in " + path.string() + ", expected version 1");
  }
  return json;
}

void insert_all(
  std::unordered_set<std::string>& destination,
  const nlohmann::json& values) {
  for (const auto& value : values) {
    destination.insert(value.get<std::string>());
  }
}

}  // namespace

ValidatorRegistry ValidatorRegistry::load(const std::filesystem::path& repo_root) {
  ValidatorRegistry registry;

  const auto sanitizers_json = read_json(resolve_config(repo_root, "sanitizers.json"));
  insert_all(registry.allowlist_predicates_, sanitizers_json.at("allowlist_predicates"));
  insert_all(registry.path_sanitizers_, sanitizers_json.at("path_sanitizers"));
  insert_all(registry.safe_string_functions_, sanitizers_json.at("string_safe_functions"));

  const auto wrappers_json = read_json(resolve_config(repo_root, "wrappers.json"));
  insert_all(registry.trusted_wrappers_, wrappers_json.at("trusted_wrappers"));
  registry.test_path_markers_ =
    wrappers_json.value("test_path_markers", std::vector<std::string>{});

  std::ifstream suppression_input(resolve_config(repo_root, "suppressions.example.json"));
  if (suppression_input.good()) {
    nlohmann::json suppressions_json;
    suppression_input >> suppressions_json;
    for (const auto& item : suppressions_json.value("suppressions", nlohmann::json::array())) {
      registry.suppressions_.push_back({
        .rule_id = item.value("rule_id", ""),
        .path_contains = item.value("path_contains", ""),
      });
    }
  }

  return registry;
}

bool ValidatorRegistry::is_allowlist_predicate(const std::string_view name) const {
  return allowlist_predicates_.contains(std::string(name));
}

bool ValidatorRegistry::is_path_sanitizer(const std::string_view name) const {
  return path_sanitizers_.contains(std::string(name));
}

bool ValidatorRegistry::is_safe_string_function(const std::string_view name) const {
  return safe_string_functions_.contains(std::string(name));
}

bool ValidatorRegistry::is_trusted_wrapper(const std::string_view name) const {
  return trusted_wrappers_.contains(std::string(name));
}

bool ValidatorRegistry::is_test_artifact(const std::filesystem::path& path) const {
  const auto normalized = path.generic_string();
  for (const auto& marker : test_path_markers_) {
    if (marker.starts_with("_") && normalized.ends_with(marker)) {
      return true;
    }
  }
  return false;
}

std::vector<std::string> ValidatorRegistry::configured_suppressions(
  const std::string_view rule_id,
  const std::filesystem::path& file) const {
  std::vector<std::string> matches;
  const auto normalized = file.generic_string();
  for (const auto& suppression : suppressions_) {
    if (suppression.rule_id == rule_id &&
        normalized.find(suppression.path_contains) != std::string::npos) {
      matches.push_back("config suppression matched " + suppression.path_contains);
    }
  }
  return matches;
}

std::vector<std::string> ValidatorRegistry::inline_suppressions(
  const std::string_view rule_id,
  const ir::SourceLocation& location) const {
  std::vector<std::string> matches;
  if (!location.valid() || !std::filesystem::exists(location.file)) {
    return matches;
  }

  std::ifstream input(location.file);
  std::vector<std::string> lines;
  std::string line;
  while (std::getline(input, line)) {
    lines.push_back(line);
  }

  const auto rule = std::string(rule_id);
  const auto check_line = [&](int index) {
    if (index < 0 || index >= static_cast<int>(lines.size())) {
      return;
    }
    const auto pattern_a = "sast-ignore-next-line " + rule;
    const auto pattern_b = "sast-ignore-line " + rule;
    if (lines[static_cast<std::size_t>(index)].find(pattern_a) != std::string::npos ||
        lines[static_cast<std::size_t>(index)].find(pattern_b) != std::string::npos) {
      matches.push_back("inline suppression at line " + std::to_string(index + 1));
    }
  };

  check_line(location.line - 2);
  check_line(location.line - 1);
  return matches;
}

}  // namespace sast::validators
