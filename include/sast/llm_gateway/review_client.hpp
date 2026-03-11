#pragma once

#include <memory>
#include <optional>
#include <string>

#include "sast/ir/facts.hpp"

namespace sast::llm_gateway {

class ReviewTransport {
 public:
  virtual ~ReviewTransport() = default;

  virtual bool post_json(
    const std::string& base_url,
    const std::string& path,
    const std::string& body,
    double timeout_seconds,
    std::string& response_body,
    std::string& error) const = 0;
};

class ReviewClient {
 public:
  struct Options {
    std::string gateway_url = "http://127.0.0.1:8081";
    double timeout_seconds = 25.0;
  };

  explicit ReviewClient(
    Options options,
    std::shared_ptr<ReviewTransport> transport = nullptr);

  [[nodiscard]] static bool should_review(ir::Decision decision);
  [[nodiscard]] std::optional<ir::LlmReview> review(const ir::FinalFinding& finding) const;

 private:
  Options options_;
  std::shared_ptr<ReviewTransport> transport_;
};

}  // namespace sast::llm_gateway
