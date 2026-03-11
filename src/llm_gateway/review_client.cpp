#include "sast/llm_gateway/review_client.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>
#include <vector>

#include <httplib.h>
#include <nlohmann/json.hpp>

namespace sast::llm_gateway {

namespace {

struct ParsedHttpUrl {
  std::string host;
  int port = 80;
};

std::optional<ParsedHttpUrl> parse_http_url(const std::string& base_url) {
  constexpr std::string_view prefix = "http://";
  if (!base_url.starts_with(prefix)) {
    return std::nullopt;
  }

  auto authority = base_url.substr(prefix.size());
  const auto path_start = authority.find('/');
  if (path_start != std::string::npos) {
    authority = authority.substr(0, path_start);
  }
  if (authority.empty()) {
    return std::nullopt;
  }

  ParsedHttpUrl parsed;
  const auto port_separator = authority.rfind(':');
  if (port_separator == std::string::npos) {
    parsed.host = authority;
    return parsed;
  }

  parsed.host = authority.substr(0, port_separator);
  if (parsed.host.empty()) {
    return std::nullopt;
  }

  try {
    parsed.port = std::stoi(authority.substr(port_separator + 1));
  } catch (...) {
    return std::nullopt;
  }
  return parsed;
}

class HttplibReviewTransport final : public ReviewTransport {
 public:
  bool post_json(
    const std::string& base_url,
    const std::string& path,
    const std::string& body,
    const double timeout_seconds,
    std::string& response_body,
    std::string& error) const override {
    const auto parsed = parse_http_url(base_url);
    if (!parsed) {
      error = "gateway URL must use http://host:port";
      return false;
    }

    httplib::Client client(parsed->host, parsed->port);
    const auto timeout_ms = static_cast<int>(std::ceil(timeout_seconds * 1000.0));
    client.set_connection_timeout(std::chrono::milliseconds(timeout_ms));
    client.set_read_timeout(std::chrono::milliseconds(timeout_ms));
    client.set_write_timeout(std::chrono::milliseconds(timeout_ms));

    const auto response = client.Post(path.c_str(), body, "application/json");
    if (!response) {
      error = "gateway request failed";
      return false;
    }
    if (response->status < 200 || response->status >= 300) {
      error = "gateway returned HTTP " + std::to_string(response->status);
      return false;
    }

    response_body = response->body;
    return true;
  }
};

struct CodeWindowPayload {
  std::string file_path;
  int start_line = 0;
  int end_line = 0;
  std::string snippet;
};

std::string join(const std::vector<std::string>& values, const std::string_view delimiter) {
  std::ostringstream stream;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index > 0) {
      stream << delimiter;
    }
    stream << values[index];
  }
  return stream.str();
}

std::string truncate_to(std::string value, const std::size_t max_size) {
  if (value.size() <= max_size) {
    return value;
  }
  if (max_size <= 3) {
    return value.substr(0, max_size);
  }
  value.resize(max_size - 3);
  value += "...";
  return value;
}

std::vector<std::string> load_lines(const std::string& file_path) {
  std::vector<std::string> lines;
  std::ifstream input(file_path);
  std::string line;
  while (std::getline(input, line)) {
    lines.push_back(line);
  }
  return lines;
}

std::optional<CodeWindowPayload> build_window(const ir::SourceLocation& location) {
  if (!location.valid()) {
    return std::nullopt;
  }

  const auto lines = load_lines(location.file);
  if (lines.empty()) {
    return std::nullopt;
  }

  const auto sink_index = std::clamp(location.line - 1, 0, static_cast<int>(lines.size()) - 1);
  const auto start_index = std::max(0, sink_index - 2);
  const auto end_index = std::min(static_cast<int>(lines.size()) - 1, start_index + 4);

  std::ostringstream snippet;
  for (int index = start_index; index <= end_index; ++index) {
    if (index > start_index) {
      snippet << '\n';
    }
    snippet << lines[static_cast<std::size_t>(index)];
  }

  const auto compact_snippet = truncate_to(snippet.str(), 1200);
  if (compact_snippet.empty()) {
    return std::nullopt;
  }

  return CodeWindowPayload{
    .file_path = location.file,
    .start_line = start_index + 1,
    .end_line = end_index + 1,
    .snippet = compact_snippet,
  };
}

std::vector<CodeWindowPayload> build_code_windows(const ir::FinalFinding& finding) {
  std::vector<CodeWindowPayload> windows;
  std::set<std::tuple<std::string, int, int>> seen;

  std::vector<ir::SourceLocation> locations = finding.candidate.evidence_locations;
  if (locations.empty()) {
    locations.push_back({
      .file = finding.candidate.file,
      .line = finding.candidate.line,
      .column = 1,
    });
  }

  for (const auto& location : locations) {
    if (windows.size() >= 2) {
      break;
    }
    const auto window = build_window(location);
    if (!window) {
      continue;
    }
    const auto key = std::make_tuple(window->file_path, window->start_line, window->end_line);
    if (!seen.insert(key).second) {
      continue;
    }
    windows.push_back(*window);
  }

  return windows;
}

std::string guard_summary(const ir::FinalFinding& finding) {
  std::vector<std::string> parts;
  if (!finding.validation.safe_reasoning.empty()) {
    parts.push_back("safe: " + join(finding.validation.safe_reasoning, "; "));
  }
  if (!finding.validation.ambiguous_reasoning.empty()) {
    parts.push_back("ambiguous: " + join(finding.validation.ambiguous_reasoning, "; "));
  }
  if (!finding.validation.matched_positive_conditions.empty()) {
    std::vector<std::string> positive;
    positive.reserve(finding.validation.matched_positive_conditions.size());
    for (const auto& evidence : finding.validation.matched_positive_conditions) {
      positive.push_back(evidence.condition);
    }
    parts.push_back("positive: " + join(positive, "; "));
  }
  if (parts.empty()) {
    parts.push_back(finding.validation.explanation);
  }
  return truncate_to(join(parts, " | "), 1000);
}

std::optional<nlohmann::json> build_request_payload(const ir::FinalFinding& finding) {
  const auto windows = build_code_windows(finding);
  if (windows.empty()) {
    return std::nullopt;
  }

  nlohmann::json code_windows = nlohmann::json::array();
  std::size_t total_chars = 0;
  for (const auto& window : windows) {
    total_chars += window.snippet.size();
    code_windows.push_back({
      {"file_path", window.file_path},
      {"start_line", window.start_line},
      {"end_line", window.end_line},
      {"snippet", window.snippet},
    });
  }
  if (total_chars > 1600) {
    return std::nullopt;
  }

  return nlohmann::json{
    {"candidate_id", finding.candidate.id},
    {"rule_id", finding.candidate.rule_id},
    {"current_judgment", ir::to_string(finding.validation.final_decision)},
    {"provisional_severity", finding.candidate.provisional_severity},
    {"confidence", finding.validation.confidence},
    {"source_summary", truncate_to(finding.candidate.source_summary, 600)},
    {"sink_summary", truncate_to(finding.candidate.sink_summary, 600)},
    {"path_summary", truncate_to(join(finding.candidate.trace_steps, " | "), 1000)},
    {"guard_summary", guard_summary(finding)},
    {"code_windows", code_windows},
  };
}

bool is_valid_judgment(const std::string& value) {
  return value == "confirmed_issue" || value == "likely_issue" ||
         value == "needs_review" || value == "likely_safe" ||
         value == "safe_suppressed";
}

bool is_valid_exploitability(const std::string& value) {
  return value == "high" || value == "medium" || value == "low" || value == "unknown";
}

bool is_valid_provider_status(const std::string& value) {
  return value == "ok" || value == "mock" || value == "fallback" || value == "error";
}

bool has_only_expected_keys(const nlohmann::json& json) {
  static const std::set<std::string> expected{
    "judgment",
    "confidence",
    "cwe",
    "exploitability",
    "reasoning_summary",
    "remediation",
    "safe_reasoning",
    "provider_status",
  };
  for (const auto& item : json.items()) {
    if (!expected.contains(item.key())) {
      return false;
    }
  }
  return true;
}

std::optional<std::string> optional_string_field(
  const nlohmann::json& json,
  const std::string& key,
  std::string& error) {
  if (!json.contains(key) || json.at(key).is_null()) {
    return std::nullopt;
  }
  if (!json.at(key).is_string()) {
    error = "gateway field " + key + " must be string or null";
    return std::nullopt;
  }
  return json.at(key).get<std::string>();
}

std::optional<ir::LlmReview> parse_review_body(
  const std::string& response_body,
  std::string& error) {
  const auto json = nlohmann::json::parse(response_body, nullptr, false);
  if (json.is_discarded() || !json.is_object()) {
    error = "gateway returned invalid JSON";
    return std::nullopt;
  }
  if (!has_only_expected_keys(json)) {
    error = "gateway returned unexpected response fields";
    return std::nullopt;
  }

  const auto judgment = json.value("judgment", "");
  const auto confidence_json = json.find("confidence");
  const auto exploitability = json.value("exploitability", "");
  const auto reasoning_summary = json.value("reasoning_summary", "");
  const auto provider_status = json.value("provider_status", "");

  if (!is_valid_judgment(judgment)) {
    error = "gateway returned invalid judgment";
    return std::nullopt;
  }
  if (confidence_json == json.end() || !confidence_json->is_number()) {
    error = "gateway confidence is missing or invalid";
    return std::nullopt;
  }
  const auto confidence = confidence_json->get<double>();
  if (confidence < 0.0 || confidence > 1.0) {
    error = "gateway confidence is out of range";
    return std::nullopt;
  }
  if (!is_valid_exploitability(exploitability)) {
    error = "gateway returned invalid exploitability";
    return std::nullopt;
  }
  if (reasoning_summary.empty()) {
    error = "gateway reasoning summary is missing";
    return std::nullopt;
  }
  if (!is_valid_provider_status(provider_status)) {
    error = "gateway returned invalid provider status";
    return std::nullopt;
  }

  auto review = ir::LlmReview{
    .judgment = ir::decision_from_string(judgment),
    .confidence = confidence,
    .exploitability = exploitability,
    .reasoning_summary = reasoning_summary,
    .provider_status = provider_status,
  };

  review.cwe = optional_string_field(json, "cwe", error);
  if (!error.empty()) {
    return std::nullopt;
  }
  review.remediation = optional_string_field(json, "remediation", error);
  if (!error.empty()) {
    return std::nullopt;
  }
  review.safe_reasoning = optional_string_field(json, "safe_reasoning", error);
  if (!error.empty()) {
    return std::nullopt;
  }

  return review;
}

ir::LlmReview fallback_review(const ir::FinalFinding& finding, const std::string& reason) {
  ir::LlmReview review;
  review.judgment = finding.validation.final_decision;
  review.confidence = finding.validation.confidence;
  review.exploitability = "unknown";
  review.reasoning_summary = "LLM review unavailable. " + reason;
  if (finding.validation.final_decision == ir::Decision::likely_safe) {
    review.safe_reasoning =
      "deterministic engine retained control because LLM review was skipped or failed";
  }
  review.provider_status = "fallback";
  return review;
}

}  // namespace

ReviewClient::ReviewClient(
  Options options,
  std::shared_ptr<ReviewTransport> transport)
    : options_(std::move(options)),
      transport_(transport ? std::move(transport) : std::make_shared<HttplibReviewTransport>()) {}

bool ReviewClient::should_review(const ir::Decision decision) {
  return decision == ir::Decision::needs_review ||
         decision == ir::Decision::likely_issue ||
         decision == ir::Decision::likely_safe;
}

std::optional<ir::LlmReview> ReviewClient::review(const ir::FinalFinding& finding) const {
  if (!should_review(finding.validation.final_decision)) {
    return std::nullopt;
  }

  const auto payload = build_request_payload(finding);
  if (!payload) {
    return fallback_review(finding, "compact review context could not be built");
  }

  std::string response_body;
  std::string error;
  if (!transport_->post_json(
        options_.gateway_url,
        "/review",
        payload->dump(),
        options_.timeout_seconds,
        response_body,
        error)) {
    return fallback_review(finding, error);
  }

  auto review = parse_review_body(response_body, error);
  if (!review) {
    return fallback_review(finding, error);
  }
  return review;
}

}  // namespace sast::llm_gateway
