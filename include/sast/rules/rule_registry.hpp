#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sast::rules {

struct RuleSpec {
  std::string id;
  std::string family;
  std::string title;
  std::string severity;
  std::vector<std::string> positive_conditions;
  std::vector<std::string> negative_conditions;
  std::vector<std::string> ambiguous_conditions;
};

class RuleRegistry {
 public:
  static RuleRegistry load(const std::filesystem::path& repo_root);

  [[nodiscard]] const std::vector<RuleSpec>& rules() const { return rules_; }
  [[nodiscard]] std::optional<RuleSpec> rule_for_family(std::string_view family) const;

 private:
  std::vector<RuleSpec> rules_;
};

}  // namespace sast::rules
