#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "sast/ir/models.hpp"

namespace sast::ingest {

struct CacheEntry {
  std::string fingerprint;
  ir::TranslationUnitSummary summary;
};

class CacheStore {
 public:
  explicit CacheStore(std::filesystem::path root);

  [[nodiscard]] std::string fingerprint(
    const std::filesystem::path& file,
    const std::vector<std::string>& compile_arguments) const;

  [[nodiscard]] std::optional<CacheEntry> load(const std::filesystem::path& file) const;
  void save(const std::filesystem::path& file, const CacheEntry& entry) const;

 private:
  std::filesystem::path root_;

  [[nodiscard]] std::filesystem::path key_path(const std::filesystem::path& file) const;
};

}  // namespace sast::ingest

