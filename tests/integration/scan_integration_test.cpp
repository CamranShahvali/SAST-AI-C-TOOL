#include <gtest/gtest.h>

#include <set>

#include "test_support.hpp"

namespace {

TEST(ValidatedScanTest, CommandInjectionCasesCoverConfirmedSafeAndLikelyIssue) {
  const auto root = sast::testsupport::source_root() / "tests" / "cases" / "command_injection";
  const auto result = sast::testsupport::scan_validated_repo(root);

  const auto* vulnerable = sast::testsupport::find_finding(result, "command_injection/vulnerable.cpp");
  const auto* safe = sast::testsupport::find_finding(result, "command_injection/safe.cpp");
  const auto* ambiguous = sast::testsupport::find_finding(result, "command_injection/ambiguous.cpp");
  const auto* suppressed = sast::testsupport::find_finding(result, "command_injection/suppressed.cpp");

  ASSERT_NE(vulnerable, nullptr);
  ASSERT_NE(safe, nullptr);
  ASSERT_NE(ambiguous, nullptr);
  ASSERT_NE(suppressed, nullptr);

  EXPECT_EQ(vulnerable->validation.final_decision, sast::ir::Decision::confirmed_issue);
  EXPECT_EQ(safe->validation.final_decision, sast::ir::Decision::safe_suppressed);
  EXPECT_EQ(ambiguous->validation.final_decision, sast::ir::Decision::likely_issue);
  EXPECT_EQ(suppressed->validation.final_decision, sast::ir::Decision::safe_suppressed);
}

TEST(ValidatedScanTest, PathTraversalCasesCoverLikelySafeAndLikelyIssue) {
  const auto root = sast::testsupport::source_root() / "tests" / "cases" / "path_traversal";
  const auto result = sast::testsupport::scan_validated_repo(root);

  const auto* vulnerable = sast::testsupport::find_finding(result, "path_traversal/vulnerable.cpp");
  const auto* safe = sast::testsupport::find_finding(result, "path_traversal/safe.cpp");
  const auto* ambiguous = sast::testsupport::find_finding(result, "path_traversal/ambiguous.cpp");

  ASSERT_NE(vulnerable, nullptr);
  ASSERT_NE(safe, nullptr);
  ASSERT_NE(ambiguous, nullptr);

  EXPECT_EQ(vulnerable->validation.final_decision, sast::ir::Decision::confirmed_issue);
  EXPECT_EQ(safe->validation.final_decision, sast::ir::Decision::likely_safe);
  EXPECT_EQ(ambiguous->validation.final_decision, sast::ir::Decision::likely_issue);
}

TEST(ValidatedScanTest, StringHandlingCasesCoverSafeAndNeedsReview) {
  const auto root = sast::testsupport::source_root() / "tests" / "cases" / "string_handling";
  const auto result = sast::testsupport::scan_validated_repo(root);

  const auto* vulnerable = sast::testsupport::find_finding(result, "string_handling/vulnerable.cpp");
  const auto* safe = sast::testsupport::find_finding(result, "string_handling/safe.cpp");
  const auto* ambiguous = sast::testsupport::find_finding(result, "string_handling/ambiguous.cpp");

  ASSERT_NE(vulnerable, nullptr);
  ASSERT_NE(safe, nullptr);
  ASSERT_NE(ambiguous, nullptr);

  EXPECT_EQ(vulnerable->validation.final_decision, sast::ir::Decision::confirmed_issue);
  EXPECT_EQ(safe->validation.final_decision, sast::ir::Decision::safe_suppressed);
  EXPECT_EQ(ambiguous->validation.final_decision, sast::ir::Decision::needs_review);
}

TEST(ValidatedScanTest, DemoCasesCoverConfirmedSafeAndNeedsReview) {
  const auto root = sast::testsupport::source_root() / "tests" / "cases" / "demo";
  const auto result = sast::testsupport::scan_validated_repo(root);

  const auto* confirmed = sast::testsupport::find_finding(result, "demo/confirmed_command.cpp");
  const auto* dismissed = sast::testsupport::find_finding(result, "demo/safe_dismissed.cpp");
  const auto* review = sast::testsupport::find_finding(result, "demo/needs_review_string.cpp");

  ASSERT_NE(confirmed, nullptr);
  ASSERT_NE(dismissed, nullptr);
  ASSERT_NE(review, nullptr);

  EXPECT_EQ(confirmed->validation.final_decision, sast::ir::Decision::confirmed_issue);
  EXPECT_EQ(dismissed->validation.final_decision, sast::ir::Decision::safe_suppressed);
  EXPECT_EQ(review->validation.final_decision, sast::ir::Decision::needs_review);
}

TEST(ValidatedScanTest, AllFiveOutcomesAppearAcrossFixtures) {
  std::set<sast::ir::Decision> decisions;

  for (const auto& root : {
         sast::testsupport::source_root() / "tests" / "cases" / "command_injection",
         sast::testsupport::source_root() / "tests" / "cases" / "path_traversal",
         sast::testsupport::source_root() / "tests" / "cases" / "string_handling",
       }) {
    const auto result = sast::testsupport::scan_validated_repo(root);
    for (const auto& finding : result.findings) {
      decisions.insert(finding.validation.final_decision);
    }
  }

  EXPECT_TRUE(decisions.contains(sast::ir::Decision::confirmed_issue));
  EXPECT_TRUE(decisions.contains(sast::ir::Decision::likely_issue));
  EXPECT_TRUE(decisions.contains(sast::ir::Decision::needs_review));
  EXPECT_TRUE(decisions.contains(sast::ir::Decision::likely_safe));
  EXPECT_TRUE(decisions.contains(sast::ir::Decision::safe_suppressed));
}

}  // namespace
