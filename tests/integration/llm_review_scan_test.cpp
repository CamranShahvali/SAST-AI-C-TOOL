#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "sast/llm_gateway/review_client.hpp"
#include "sast/triage/scan_service.hpp"
#include "test_support.hpp"

namespace {

class RecordingTransport final : public sast::llm_gateway::ReviewTransport {
 public:
  bool should_succeed = true;
  std::string response_body = R"({
    "judgment": "needs_review",
    "confidence": 0.66,
    "cwe": "CWE-120",
    "exploitability": "medium",
    "reasoning_summary": "Local review kept the deterministic needs_review decision.",
    "remediation": "Bind the copy length to sizeof(destination).",
    "safe_reasoning": null,
    "provider_status": "ok"
  })";
  std::string error = "gateway unavailable";
  mutable int calls = 0;

  bool post_json(
    const std::string& base_url,
    const std::string& path,
    const std::string& body,
    const double timeout_seconds,
    std::string& response,
    std::string& error_message) const override {
    (void)base_url;
    (void)path;
    (void)body;
    (void)timeout_seconds;
    ++calls;
    if (!should_succeed) {
      error_message = error;
      return false;
    }
    response = response_body;
    return true;
  }
};

TEST(LlmReviewScanTest, EnrichesOnlyEligibleFindingsWhenGatewayIsEnabled) {
  auto transport = std::make_shared<RecordingTransport>();
  sast::triage::ScanService service;
  const auto bundle = service.scan({
    .repo_root = sast::testsupport::source_root() / "tests" / "cases" / "demo",
    .jobs = 1,
    .llm_review = true,
    .llm_gateway_url = "http://127.0.0.1:8081",
    .llm_timeout_seconds = 1.0,
    .llm_transport = transport,
  });

  EXPECT_EQ(transport->calls, 1);
  ASSERT_TRUE(bundle.metrics.llm_latency_ms.has_value());

  int enriched_count = 0;
  for (const auto& finding : bundle.validated.findings) {
    if (finding.candidate.file.ends_with("needs_review_string.cpp")) {
      ASSERT_TRUE(finding.validation.llm_review.has_value());
      EXPECT_EQ(finding.validation.llm_review->provider_status, "ok");
      ++enriched_count;
    } else if (finding.candidate.file.ends_with("confirmed_command.cpp") ||
               finding.candidate.file.ends_with("cross_function_command.cpp") ||
               finding.candidate.file.ends_with("safe_dismissed.cpp")) {
      EXPECT_FALSE(finding.validation.llm_review.has_value());
    }
  }

  EXPECT_EQ(enriched_count, 1);
}

}  // namespace
