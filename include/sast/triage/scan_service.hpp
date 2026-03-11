#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include "sast/ir/facts.hpp"

namespace sast::llm_gateway {
class ReviewTransport;
}

namespace sast::triage {

struct ScanOptions {
  std::filesystem::path repo_root = ".";
  std::optional<std::filesystem::path> explicit_compdb;
  std::optional<std::filesystem::path> changed_files;
  std::size_t jobs = 1;
  bool llm_review = false;
  std::string llm_gateway_url = "http://127.0.0.1:8081";
  double llm_timeout_seconds = 25.0;
  std::shared_ptr<sast::llm_gateway::ReviewTransport> llm_transport;
};

struct ScanMetrics {
  std::size_t translation_units_total = 0;
  std::size_t translation_units_selected = 0;
  std::size_t translation_units_skipped = 0;
  std::size_t candidate_count = 0;
  std::size_t finding_count = 0;
  double parse_time_ms = 0.0;
  double candidate_generation_time_ms = 0.0;
  double validation_time_ms = 0.0;
  double full_scan_time_ms = 0.0;
  double cache_hit_rate = 0.0;
  double effective_skip_rate = 0.0;
  std::optional<std::uint64_t> memory_rss_bytes;
  std::optional<double> llm_latency_ms;
  bool llm_review_enabled = false;
  std::string cache_note = "summary cache is not implemented in the active pipeline";
};

struct ScanBundle {
  ir::CandidateScanResult candidates;
  ir::ValidatedScanResult validated;
  ScanMetrics metrics;
};

inline void to_json(nlohmann::json& json, const ScanMetrics& value) {
  json = nlohmann::json{
    {"translation_units_total", value.translation_units_total},
    {"translation_units_selected", value.translation_units_selected},
    {"translation_units_skipped", value.translation_units_skipped},
    {"candidate_count", value.candidate_count},
    {"finding_count", value.finding_count},
    {"parse_time_ms", value.parse_time_ms},
    {"candidate_generation_time_ms", value.candidate_generation_time_ms},
    {"validation_time_ms", value.validation_time_ms},
    {"full_scan_time_ms", value.full_scan_time_ms},
    {"cache_hit_rate", value.cache_hit_rate},
    {"effective_skip_rate", value.effective_skip_rate},
    {"llm_review_enabled", value.llm_review_enabled},
    {"cache_note", value.cache_note},
  };
  json["memory_rss_bytes"] = value.memory_rss_bytes
                               ? nlohmann::json(*value.memory_rss_bytes)
                               : nlohmann::json(nullptr);
  json["llm_latency_ms"] = value.llm_latency_ms
                             ? nlohmann::json(*value.llm_latency_ms)
                             : nlohmann::json(nullptr);
}

class ScanService {
 public:
  [[nodiscard]] ScanBundle scan(const ScanOptions& options) const;
};

}  // namespace sast::triage
