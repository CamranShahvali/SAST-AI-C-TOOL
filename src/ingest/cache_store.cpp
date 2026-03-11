#include "sast/ingest/cache_store.hpp"

#include <fstream>
#include <iomanip>
#include <sstream>

namespace sast::ingest {

namespace {

constexpr std::uint64_t kFnvOffset = 14695981039346656037ull;
constexpr std::uint64_t kFnvPrime = 1099511628211ull;

std::string fnv1a(const std::string& input) {
  std::uint64_t hash = kFnvOffset;
  for (const auto byte : input) {
    hash ^= static_cast<unsigned char>(byte);
    hash *= kFnvPrime;
  }
  std::ostringstream stream;
  stream << std::hex << std::setw(16) << std::setfill('0') << hash;
  return stream.str();
}

}  // namespace

CacheStore::CacheStore(std::filesystem::path root)
    : root_(std::move(root)) {
  std::filesystem::create_directories(root_);
}

std::string CacheStore::fingerprint(
  const std::filesystem::path& file,
  const std::vector<std::string>& compile_arguments) const {
  std::ostringstream material;
  const auto absolute = std::filesystem::absolute(file);
  material << absolute.string();
  if (std::filesystem::exists(absolute)) {
    material << std::filesystem::file_size(absolute);
    material << std::filesystem::last_write_time(absolute).time_since_epoch().count();
  }
  for (const auto& argument : compile_arguments) {
    material << '\n' << argument;
  }
  return fnv1a(material.str());
}

std::optional<CacheEntry> CacheStore::load(const std::filesystem::path& file) const {
  const auto path = key_path(file);
  if (!std::filesystem::exists(path)) {
    return std::nullopt;
  }

  std::ifstream input(path);
  nlohmann::json json;
  input >> json;

  CacheEntry entry;
  entry.fingerprint = json.value("fingerprint", "");
  entry.summary = json.at("summary").get<ir::TranslationUnitSummary>();
  return entry;
}

void CacheStore::save(const std::filesystem::path& file, const CacheEntry& entry) const {
  std::filesystem::create_directories(root_);
  const auto path = key_path(file);
  std::ofstream output(path);
  nlohmann::json json{
    {"fingerprint", entry.fingerprint},
    {"summary", entry.summary},
  };
  output << std::setw(2) << json << '\n';
}

std::filesystem::path CacheStore::key_path(const std::filesystem::path& file) const {
  return root_ / (fnv1a(std::filesystem::absolute(file).string()) + ".json");
}

}  // namespace sast::ingest

