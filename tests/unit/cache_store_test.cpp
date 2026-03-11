#include <gtest/gtest.h>

#include <fstream>

#include "sast/ingest/cache_store.hpp"
#include "test_support.hpp"

namespace {

TEST(CacheStoreTest, FingerprintChangesWhenArgumentsChange) {
  const auto directory = sast::testsupport::make_temp_dir("cache_store");
  const auto file = directory / "sample.cpp";
  {
    std::ofstream output(file);
    output << "int main() { return 0; }\n";
  }

  const sast::ingest::CacheStore cache(directory / ".sast/cache");
  const auto first = cache.fingerprint(file, {"clang++", "-std=c++20"});
  const auto second = cache.fingerprint(file, {"clang++", "-std=c++20", "-DSAFE=1"});

  EXPECT_NE(first, second);
}

TEST(CacheStoreTest, RoundTripsSummary) {
  const auto directory = sast::testsupport::make_temp_dir("cache_roundtrip");
  const auto file = directory / "sample.cpp";
  {
    std::ofstream output(file);
    output << "int main() { return 0; }\n";
  }

  sast::ingest::CacheStore cache(directory / ".sast/cache");
  sast::ir::TranslationUnitSummary summary;
  summary.file_path = file.string();
  summary.diagnostics.push_back("ok");
  cache.save(file, {.fingerprint = "abc123", .summary = summary});

  const auto loaded = cache.load(file);
  ASSERT_TRUE(loaded.has_value());
  EXPECT_EQ(loaded->fingerprint, "abc123");
  EXPECT_EQ(loaded->summary.file_path, file.string());
}

}  // namespace
