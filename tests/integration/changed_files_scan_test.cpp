#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "sast/triage/scan_service.hpp"
#include "test_support.hpp"

namespace {

TEST(ChangedFilesScanTest, LimitsAnalysisToRequestedFiles) {
  const auto repo_root = sast::testsupport::source_root() / "tests" / "cases" / "demo";
  const auto changed_file_list =
    std::filesystem::temp_directory_path() / "ai_sast_changed_files_demo.txt";

  std::ofstream output(changed_file_list);
  output << "needs_review_string.cpp\n";
  output.close();

  sast::triage::ScanService service;
  const auto bundle = service.scan({
    .repo_root = repo_root,
    .explicit_compdb = std::nullopt,
    .changed_files = changed_file_list,
    .jobs = 1,
    .llm_review = false,
  });

  EXPECT_EQ(bundle.metrics.translation_units_total, 4u);
  EXPECT_EQ(bundle.metrics.translation_units_selected, 1u);
  EXPECT_EQ(bundle.metrics.translation_units_skipped, 3u);
  ASSERT_EQ(bundle.validated.findings.size(), 1u);

  const auto* finding =
    sast::testsupport::find_finding(bundle.validated, "demo/needs_review_string.cpp");
  ASSERT_NE(finding, nullptr);
  EXPECT_EQ(finding->validation.final_decision, sast::ir::Decision::needs_review);
}

}  // namespace
