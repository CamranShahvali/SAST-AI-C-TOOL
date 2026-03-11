#include <gtest/gtest.h>

#include <algorithm>

#include "test_support.hpp"

namespace {

bool trace_contains(
  const sast::ir::CandidateFinding& finding,
  const std::string& needle) {
  return std::any_of(
    finding.trace_steps.begin(),
    finding.trace_steps.end(),
    [&](const std::string& step) {
      return step.find(needle) != std::string::npos;
    });
}

TEST(CandidateScanTest, CommandExecutionCasesEmitCandidateOnlyFindings) {
  const auto result = sast::testsupport::scan_candidate_repo(
    sast::testsupport::source_root() / "tests" / "cases" / "command_injection");

  EXPECT_TRUE(result.candidate_only);
  EXPECT_EQ(result.mode, "candidate_scan");

  const auto* vulnerable = sast::testsupport::find_candidate(
    result,
    "command_injection/vulnerable.cpp");
  const auto* safe = sast::testsupport::find_candidate(
    result,
    "command_injection/safe.cpp");
  const auto* ambiguous = sast::testsupport::find_candidate(
    result,
    "command_injection/ambiguous.cpp");

  ASSERT_NE(vulnerable, nullptr);
  ASSERT_NE(safe, nullptr);
  ASSERT_NE(ambiguous, nullptr);

  EXPECT_EQ(vulnerable->rule_id, "command_injection.system");
  EXPECT_EQ(vulnerable->provisional_severity, "high");
  EXPECT_EQ(vulnerable->line, 9);
  EXPECT_TRUE(trace_contains(*vulnerable, "candidate only"));

  EXPECT_EQ(safe->rule_id, "command_injection.system");
  EXPECT_TRUE(trace_contains(*safe, "allowlist predicate is_allowed_command"));

  EXPECT_EQ(ambiguous->rule_id, "command_injection.system");
  EXPECT_TRUE(trace_contains(*ambiguous, "unmodeled helper call normalize_command"));
}

TEST(CandidateScanTest, PathTraversalCasesEmitCandidateOnlyFindings) {
  const auto result = sast::testsupport::scan_candidate_repo(
    sast::testsupport::source_root() / "tests" / "cases" / "path_traversal");

  const auto* vulnerable = sast::testsupport::find_candidate(
    result,
    "path_traversal/vulnerable.cpp");
  const auto* safe = sast::testsupport::find_candidate(
    result,
    "path_traversal/safe.cpp");
  const auto* ambiguous = sast::testsupport::find_candidate(
    result,
    "path_traversal/ambiguous.cpp");

  ASSERT_NE(vulnerable, nullptr);
  ASSERT_NE(safe, nullptr);
  ASSERT_NE(ambiguous, nullptr);

  EXPECT_EQ(vulnerable->rule_id, "path_traversal.file_open");
  EXPECT_EQ(vulnerable->line, 9);

  EXPECT_EQ(safe->rule_id, "path_traversal.file_open");
  EXPECT_TRUE(trace_contains(*safe, "allowlist predicate is_safe_path"));

  EXPECT_EQ(ambiguous->rule_id, "path_traversal.file_open");
  EXPECT_TRUE(trace_contains(*ambiguous, "unmodeled helper call normalize_path"));
}

TEST(CandidateScanTest, StringHandlingCasesEmitCandidateOnlyFindings) {
  const auto result = sast::testsupport::scan_candidate_repo(
    sast::testsupport::source_root() / "tests" / "cases" / "string_handling");

  const auto* vulnerable = sast::testsupport::find_candidate(
    result,
    "string_handling/vulnerable.cpp");
  const auto* safe = sast::testsupport::find_candidate(
    result,
    "string_handling/safe.cpp");
  const auto* ambiguous = sast::testsupport::find_candidate(
    result,
    "string_handling/ambiguous.cpp");

  ASSERT_NE(vulnerable, nullptr);
  ASSERT_NE(safe, nullptr);
  ASSERT_NE(ambiguous, nullptr);

  EXPECT_EQ(vulnerable->rule_id, "dangerous_string.unbounded_copy");
  EXPECT_EQ(vulnerable->line, 9);
  EXPECT_TRUE(trace_contains(*vulnerable, "expression references argv"));

  EXPECT_EQ(safe->rule_id, "dangerous_string.unbounded_copy");
  EXPECT_TRUE(trace_contains(*safe, "copy length expression sizeof(destination)"));

  EXPECT_EQ(ambiguous->rule_id, "dangerous_string.unbounded_copy");
  EXPECT_TRUE(trace_contains(*ambiguous, "copy length expression get_length(argc)"));
}

}  // namespace
