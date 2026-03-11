#include <gtest/gtest.h>

#include <set>

#include "test_support.hpp"

namespace {

TEST(MixedDemoCaseTest, SingleFileProducesConfirmedSafeAndAmbiguousOutcomes) {
  const auto root = sast::testsupport::source_root() / "tests" / "demo" / "mixed_case";
  const auto result = sast::testsupport::scan_validated_repo(root);

  EXPECT_EQ(result.findings.size(), 3u);

  std::set<sast::ir::Decision> decisions;
  for (const auto& finding : result.findings) {
    EXPECT_TRUE(finding.candidate.file.ends_with("mixed_paths.cpp"));
    decisions.insert(finding.validation.final_decision);
  }

  EXPECT_TRUE(decisions.contains(sast::ir::Decision::confirmed_issue));
  EXPECT_TRUE(decisions.contains(sast::ir::Decision::needs_review));
  EXPECT_TRUE(decisions.contains(sast::ir::Decision::safe_suppressed));
}

}  // namespace
