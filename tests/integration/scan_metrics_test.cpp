#include <gtest/gtest.h>

#include "sast/triage/scan_service.hpp"
#include "test_support.hpp"

namespace {

TEST(ScanMetricsTest, CollectsPhaseMetricsForValidatedScan) {
  const auto repo_root = sast::testsupport::source_root() / "tests" / "cases" / "demo";

  sast::triage::ScanService service;
  const auto bundle = service.scan({
    .repo_root = repo_root,
    .explicit_compdb = std::nullopt,
    .changed_files = std::nullopt,
    .jobs = 1,
    .llm_review = false,
  });

  EXPECT_EQ(bundle.metrics.translation_units_total, 4u);
  EXPECT_EQ(bundle.metrics.translation_units_selected, 4u);
  EXPECT_EQ(bundle.metrics.translation_units_skipped, 0u);
  EXPECT_GT(bundle.metrics.parse_time_ms, 0.0);
  EXPECT_GE(bundle.metrics.candidate_generation_time_ms, 0.0);
  EXPECT_GE(bundle.metrics.validation_time_ms, 0.0);
  EXPECT_GT(bundle.metrics.full_scan_time_ms, 0.0);
  EXPECT_EQ(bundle.metrics.cache_hit_rate, 0.0);
  EXPECT_FALSE(bundle.metrics.llm_latency_ms.has_value());
#if defined(__linux__)
  ASSERT_TRUE(bundle.metrics.memory_rss_bytes.has_value());
  EXPECT_GT(*bundle.metrics.memory_rss_bytes, 0u);
#else
  EXPECT_TRUE(!bundle.metrics.memory_rss_bytes.has_value() || *bundle.metrics.memory_rss_bytes > 0);
#endif
  EXPECT_EQ(bundle.metrics.finding_count, bundle.validated.findings.size());
}

}  // namespace
