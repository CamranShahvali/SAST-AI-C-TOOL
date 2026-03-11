#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "sast/ir/facts.hpp"

namespace sast::validators {

class ValidatorRegistry {
 public:
  static ValidatorRegistry load(const std::filesystem::path& repo_root);

  [[nodiscard]] bool is_allowlist_predicate(std::string_view name) const;
  [[nodiscard]] bool is_path_sanitizer(std::string_view name) const;
  [[nodiscard]] bool is_safe_string_function(std::string_view name) const;
  [[nodiscard]] bool is_trusted_wrapper(std::string_view name) const;
  [[nodiscard]] bool is_test_artifact(const std::filesystem::path& path) const;
  [[nodiscard]] std::vector<std::string> configured_suppressions(
    std::string_view rule_id,
    const std::filesystem::path& file) const;
  [[nodiscard]] std::vector<std::string> inline_suppressions(
    std::string_view rule_id,
    const ir::SourceLocation& location) const;

 private:
  struct SuppressionRule {
    std::string rule_id;
    std::string path_contains;
  };

  std::unordered_set<std::string> allowlist_predicates_;
  std::unordered_set<std::string> path_sanitizers_;
  std::unordered_set<std::string> safe_string_functions_;
  std::unordered_set<std::string> trusted_wrappers_;
  std::vector<std::string> test_path_markers_;
  std::vector<SuppressionRule> suppressions_;
};

}  // namespace sast::validators
