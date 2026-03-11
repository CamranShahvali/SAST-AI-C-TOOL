#include "sast/rules/rule_registry.hpp"

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

}  // namespace

RuleRegistry RuleRegistry::load(const std::filesystem::path& repo_root) {
  RuleRegistry registry;

  const auto rules_json = read_json(resolve_config(repo_root, "rules.json"));
  for (const auto& rule_json : rules_json.at("rules")) {
    RuleSpec rule;
    rule.id = rule_json.value("id", "");
    rule.family = rule_json.value("kind", "");
    rule.title = rule_json.value("title", "");
    rule.severity = rule_json.value("severity", "medium");
    rule.positive_conditions =
      rule_json.value("positive_conditions", std::vector<std::string>{});
    rule.negative_conditions =
      rule_json.value("negative_conditions", std::vector<std::string>{});
    rule.ambiguous_conditions =
      rule_json.value("ambiguous_conditions", std::vector<std::string>{});
    registry.rules_.push_back(std::move(rule));
  }

  return registry;
}

std::optional<RuleSpec> RuleRegistry::rule_for_family(const std::string_view family) const {
  for (const auto& rule : rules_) {
    if (rule.family == family) {
      return rule;
    }
  }
  return std::nullopt;
}

}  // namespace sast::rules
