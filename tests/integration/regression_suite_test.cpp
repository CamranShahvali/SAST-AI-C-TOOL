#include <gtest/gtest.h>

#include "test_support.hpp"

namespace {

TEST(RegressionSuiteTest, FalsePositiveFixesStaySafe) {
  const auto root = sast::testsupport::source_root() / "tests" / "regression" / "false_positives";
  const auto result = sast::testsupport::scan_validated_repo(root);

  const auto* command = sast::testsupport::find_finding(result, "false_positives/command_allowlist.cpp");
  const auto* path = sast::testsupport::find_finding(result, "false_positives/path_under_root.cpp");
  const auto* bounded = sast::testsupport::find_finding(result, "false_positives/bounded_snprintf.cpp");

  ASSERT_NE(command, nullptr);
  ASSERT_NE(path, nullptr);
  ASSERT_NE(bounded, nullptr);

  EXPECT_EQ(command->validation.final_decision, sast::ir::Decision::safe_suppressed);
  EXPECT_EQ(path->validation.final_decision, sast::ir::Decision::safe_suppressed);
  EXPECT_EQ(bounded->validation.final_decision, sast::ir::Decision::safe_suppressed);
}

TEST(RegressionSuiteTest, FalseNegativeFixesStayDetected) {
  const auto root = sast::testsupport::source_root() / "tests" / "regression" / "false_negatives";
  const auto result = sast::testsupport::scan_validated_repo(root);

  const auto* direct = sast::testsupport::find_finding(result, "false_negatives/direct_exec.cpp");
  const auto* cross_function =
    sast::testsupport::find_finding(result, "false_negatives/cross_function_exec.cpp");

  ASSERT_NE(direct, nullptr);
  ASSERT_NE(cross_function, nullptr);

  EXPECT_EQ(direct->validation.final_decision, sast::ir::Decision::confirmed_issue);
  EXPECT_EQ(cross_function->validation.final_decision, sast::ir::Decision::confirmed_issue);
}

}  // namespace
