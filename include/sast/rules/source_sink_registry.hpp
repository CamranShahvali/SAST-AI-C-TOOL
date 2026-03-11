#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace sast::rules {

class SourceSinkRegistry {
 public:
  static SourceSinkRegistry load(const std::filesystem::path& repo_root);

  [[nodiscard]] bool is_source_function(std::string_view name) const;
  [[nodiscard]] bool is_entrypoint(std::string_view name) const;
  [[nodiscard]] bool is_command_sink(std::string_view callee) const;
  [[nodiscard]] bool is_path_sink(std::string_view callee) const;
  [[nodiscard]] bool is_string_sink(std::string_view callee) const;
  [[nodiscard]] bool is_sanitizer_function(std::string_view callee) const;
  [[nodiscard]] bool is_allowlist_predicate(std::string_view callee) const;
  [[nodiscard]] bool is_path_sanitizer(std::string_view callee) const;
  [[nodiscard]] bool is_string_safe_function(std::string_view callee) const;
  [[nodiscard]] bool is_trusted_wrapper(std::string_view callee) const;
  [[nodiscard]] bool is_trusted_accessor(std::string_view name) const;
  [[nodiscard]] bool is_test_path(const std::filesystem::path& file) const;

  [[nodiscard]] const std::vector<std::string>& test_path_markers() const {
    return test_path_markers_;
  }

 private:
  std::unordered_set<std::string> source_functions_;
  std::unordered_set<std::string> entrypoints_;
  std::unordered_set<std::string> command_sinks_;
  std::unordered_set<std::string> path_sinks_;
  std::unordered_set<std::string> string_sinks_;
  std::unordered_set<std::string> sanitizer_functions_;
  std::unordered_set<std::string> allowlist_predicates_;
  std::unordered_set<std::string> path_sanitizers_;
  std::unordered_set<std::string> string_safe_functions_;
  std::unordered_set<std::string> trusted_wrappers_;
  std::unordered_set<std::string> trusted_accessors_;
  std::vector<std::string> test_path_markers_;
};

}  // namespace sast::rules
