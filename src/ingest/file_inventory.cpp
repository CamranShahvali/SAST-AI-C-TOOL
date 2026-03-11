#include "sast/ingest/file_inventory.hpp"

#include <algorithm>
#include <fstream>
#include <unordered_set>

namespace sast::ingest {

namespace {

bool is_source_extension(const std::filesystem::path& file) {
  static const std::unordered_set<std::string> kExtensions{
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
  };
  return kExtensions.contains(file.extension().string());
}

}  // namespace

std::vector<std::filesystem::path> FileInventory::list_source_files(
  const std::filesystem::path& root) {
  std::vector<std::filesystem::path> files;
  if (!std::filesystem::exists(root)) {
    return files;
  }

  for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
    if (!entry.is_regular_file()) {
      continue;
    }
    if (is_source_extension(entry.path())) {
      files.push_back(std::filesystem::absolute(entry.path()));
    }
  }
  std::sort(files.begin(), files.end());
  return files;
}

std::vector<std::filesystem::path> FileInventory::read_changed_files(
  const std::filesystem::path& file,
  const std::filesystem::path& base_root) {
  std::vector<std::filesystem::path> files;
  std::ifstream input(file);
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty()) {
      const std::filesystem::path changed_path(line);
      files.push_back(
        changed_path.is_absolute()
          ? std::filesystem::weakly_canonical(changed_path)
          : std::filesystem::weakly_canonical(base_root / changed_path));
    }
  }
  std::sort(files.begin(), files.end());
  return files;
}

bool FileInventory::is_test_path(const std::filesystem::path& file) {
  const auto normalized = file.generic_string();
  return normalized.find("/tests/") != std::string::npos ||
         normalized.ends_with("_test.cpp") ||
         normalized.ends_with("_tests.cpp");
}

}  // namespace sast::ingest
