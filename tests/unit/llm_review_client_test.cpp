#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>

#include "sast/llm_gateway/review_client.hpp"
#include "test_support.hpp"

namespace {

class FakeTransport final : public sast::llm_gateway::ReviewTransport {
 public:
  bool should_succeed = true;
  std::string response_body;
  std::string error = "connection refused";
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

TEST(LlmReviewClientTest, DoesNotRouteConfirmedOrSuppressedFindings) {
  const auto result = sast::testsupport::scan_validated_repo(
    sast::testsupport::source_root() / "tests" / "cases" / "demo");
  const auto* confirmed = sast::testsupport::find_finding(result, "demo/confirmed_command.cpp");
  const auto* suppressed = sast::testsupport::find_finding(result, "demo/safe_dismissed.cpp");

  ASSERT_NE(confirmed, nullptr);
  ASSERT_NE(suppressed, nullptr);

  auto transport = std::make_shared<FakeTransport>();
  sast::llm_gateway::ReviewClient client({}, transport);

  EXPECT_FALSE(client.review(*confirmed).has_value());
  EXPECT_FALSE(client.review(*suppressed).has_value());
  EXPECT_EQ(transport->calls, 0);
}

TEST(LlmReviewClientTest, RoutesLikelySafeAndNeedsReviewFindings) {
  auto transport = std::make_shared<FakeTransport>();
  transport->response_body = R"({
    "judgment": "likely_safe",
    "confidence": 0.81,
    "cwe": "CWE-22",
    "exploitability": "low",
    "reasoning_summary": "The local root guard looks effective but should be kept explicit.",
    "remediation": "Keep the canonicalization guard and add regression coverage.",
    "safe_reasoning": "The compact context shows a constrained file-open path.",
    "provider_status": "ok"
  })";
  sast::llm_gateway::ReviewClient client({}, transport);

  const auto likely_safe_result = sast::testsupport::scan_validated_repo(
    sast::testsupport::source_root() / "tests" / "cases" / "path_traversal");
  const auto* likely_safe =
    sast::testsupport::find_finding(likely_safe_result, "path_traversal/safe.cpp");
  ASSERT_NE(likely_safe, nullptr);
  ASSERT_EQ(likely_safe->validation.final_decision, sast::ir::Decision::likely_safe);

  const auto review_result = sast::testsupport::scan_validated_repo(
    sast::testsupport::source_root() / "tests" / "cases" / "demo");
  const auto* review = sast::testsupport::find_finding(review_result, "demo/needs_review_string.cpp");
  ASSERT_NE(review, nullptr);
  ASSERT_EQ(review->validation.final_decision, sast::ir::Decision::needs_review);

  const auto likely_safe_llm = client.review(*likely_safe);
  const auto needs_review_llm = client.review(*review);

  ASSERT_TRUE(likely_safe_llm.has_value());
  ASSERT_TRUE(needs_review_llm.has_value());
  EXPECT_EQ(likely_safe_llm->provider_status, "ok");
  EXPECT_EQ(needs_review_llm->provider_status, "ok");
  EXPECT_EQ(transport->calls, 2);
}

TEST(LlmReviewClientTest, FallsBackWhenGatewayReturnsInvalidJson) {
  const auto result = sast::testsupport::scan_validated_repo(
    sast::testsupport::source_root() / "tests" / "cases" / "demo");
  const auto* review = sast::testsupport::find_finding(result, "demo/needs_review_string.cpp");
  ASSERT_NE(review, nullptr);

  auto transport = std::make_shared<FakeTransport>();
  transport->response_body = "{not-json";
  sast::llm_gateway::ReviewClient client({}, transport);

  const auto llm = client.review(*review);

  ASSERT_TRUE(llm.has_value());
  EXPECT_EQ(llm->provider_status, "fallback");
  EXPECT_EQ(llm->judgment, sast::ir::Decision::needs_review);
  EXPECT_NE(llm->reasoning_summary.find("invalid JSON"), std::string::npos);
}

TEST(LlmReviewClientTest, FallsBackWhenGatewayRequestFails) {
  const auto result = sast::testsupport::scan_validated_repo(
    sast::testsupport::source_root() / "tests" / "cases" / "demo");
  const auto* review = sast::testsupport::find_finding(result, "demo/needs_review_string.cpp");
  ASSERT_NE(review, nullptr);

  auto transport = std::make_shared<FakeTransport>();
  transport->should_succeed = false;
  transport->error = "timeout";
  sast::llm_gateway::ReviewClient client({}, transport);

  const auto llm = client.review(*review);

  ASSERT_TRUE(llm.has_value());
  EXPECT_EQ(llm->provider_status, "fallback");
  EXPECT_EQ(llm->judgment, sast::ir::Decision::needs_review);
  EXPECT_NE(llm->reasoning_summary.find("timeout"), std::string::npos);
}

}  // namespace
