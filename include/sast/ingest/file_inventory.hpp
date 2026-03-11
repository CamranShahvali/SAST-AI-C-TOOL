#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace sast::ingest {

class FileInventory {
 public:
  static std::vector<std::filesystem::path> list_source_files(const std::filesystem::path& root);
  static std::vector<std::filesystem::path> read_changed_files(
    const std::filesystem::path& file,
    const std::filesystem::path& base_root = std::filesystem::current_path());
  static bool is_test_path(const std::filesystem::path& file);
};

}  // namespace sast::ingest
