#include "sast/rules/source_sink_registry.hpp"

#include <fstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

namespace sast::rules {

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

SourceSinkRegistry SourceSinkRegistry::load(const std::filesystem::path& repo_root) {
  SourceSinkRegistry registry;

  const auto sources_json = read_json(resolve_config(repo_root, "sources.json"));
  insert_all(registry.source_functions_, sources_json.at("functions"));
  insert_all(registry.entrypoints_, sources_json.at("entrypoint_functions"));

  const auto sinks_json = read_json(resolve_config(repo_root, "sinks.json"));
  insert_all(registry.command_sinks_, sinks_json.at("command_injection"));
  insert_all(registry.path_sinks_, sinks_json.at("path_traversal"));
  insert_all(registry.string_sinks_, sinks_json.at("dangerous_string"));

  const auto sanitizers_json = read_json(resolve_config(repo_root, "sanitizers.json"));
  insert_all(registry.sanitizer_functions_, sanitizers_json.at("sanitizer_functions"));
  insert_all(registry.allowlist_predicates_, sanitizers_json.at("allowlist_predicates"));
  insert_all(registry.path_sanitizers_, sanitizers_json.at("path_sanitizers"));
  insert_all(registry.string_safe_functions_, sanitizers_json.at("string_safe_functions"));

  const auto wrappers_json = read_json(resolve_config(repo_root, "wrappers.json"));
  insert_all(registry.trusted_wrappers_, wrappers_json.at("trusted_wrappers"));
  insert_all(registry.trusted_accessors_, wrappers_json.at("trusted_accessors"));
  registry.test_path_markers_ =
    wrappers_json.value("test_path_markers", std::vector<std::string>{});

  return registry;
}

bool SourceSinkRegistry::is_source_function(const std::string_view name) const {
  return source_functions_.contains(std::string(name));
}

bool SourceSinkRegistry::is_entrypoint(const std::string_view name) const {
  return entrypoints_.contains(std::string(name));
}

bool SourceSinkRegistry::is_command_sink(const std::string_view callee) const {
  return command_sinks_.contains(std::string(callee));
}

bool SourceSinkRegistry::is_path_sink(const std::string_view callee) const {
  return path_sinks_.contains(std::string(callee));
}

bool SourceSinkRegistry::is_string_sink(const std::string_view callee) const {
  return string_sinks_.contains(std::string(callee));
}

bool SourceSinkRegistry::is_sanitizer_function(const std::string_view callee) const {
  return sanitizer_functions_.contains(std::string(callee));
}

bool SourceSinkRegistry::is_allowlist_predicate(const std::string_view callee) const {
  return allowlist_predicates_.contains(std::string(callee));
}

bool SourceSinkRegistry::is_path_sanitizer(const std::string_view callee) const {
  return path_sanitizers_.contains(std::string(callee));
}

bool SourceSinkRegistry::is_string_safe_function(const std::string_view callee) const {
  return string_safe_functions_.contains(std::string(callee));
}

bool SourceSinkRegistry::is_trusted_wrapper(const std::string_view callee) const {
  return trusted_wrappers_.contains(std::string(callee));
}

bool SourceSinkRegistry::is_trusted_accessor(const std::string_view name) const {
  return trusted_accessors_.contains(std::string(name));
}

bool SourceSinkRegistry::is_test_path(const std::filesystem::path& file) const {
  const auto normalized = file.generic_string();
  for (const auto& marker : test_path_markers_) {
    if (normalized.find(marker) != std::string::npos) {
      return true;
    }
  }
  return false;
}

}  // namespace sast::rules
