#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include <nlohmann/json.hpp>

#include "sast/cli/application.hpp"
#include "test_support.hpp"

namespace {

TEST(CliFactsTest, EmitsFactsJsonForRelativeRepoPath) {
  const auto prepared = sast::testsupport::configure_fixture_copy("cmake_cpp_sample");
  const auto output_path = prepared.root / "facts.json";
  const auto relative_repo =
    std::filesystem::relative(prepared.root, std::filesystem::current_path());

  sast::cli::Application application;
  const auto exit_code = application.run({
    "facts",
    "--repo",
    relative_repo.string(),
    "--auto-compdb",
    "--out",
    output_path.string(),
  });

  ASSERT_EQ(exit_code, 0);

  std::ifstream input(output_path);
  ASSERT_TRUE(input.good());

  nlohmann::json json;
  input >> json;
  ASSERT_TRUE(json.contains("translation_units"));
  ASSERT_EQ(json["translation_units"].size(), 2u);

  bool saw_main = false;
  for (const auto& translation_unit : json["translation_units"]) {
    for (const auto& function : translation_unit["functions"]) {
      if (function.value("qualified_name", "") == "main") {
        saw_main = true;
      }
    }
  }
  EXPECT_TRUE(saw_main);
}

}  // namespace
