#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include <nlohmann/json.hpp>

#include "sast/cli/application.hpp"
#include "test_support.hpp"

namespace {

TEST(CliScanTest, EmitsValidatedJsonForRelativeRepoPath) {
  const auto repo_root =
    sast::testsupport::source_root() / "tests" / "cases" / "command_injection";
  const auto output_path = std::filesystem::temp_directory_path() / "ai_sast_validated_scan.json";
  const auto relative_repo =
    std::filesystem::relative(repo_root, std::filesystem::current_path());

  sast::cli::Application application;
  const auto exit_code = application.run({
    "scan",
    "--repo",
    relative_repo.string(),
    "--out",
    output_path.string(),
  });

  ASSERT_EQ(exit_code, 0);

  std::ifstream input(output_path);
  ASSERT_TRUE(input.good());

  nlohmann::json json;
  input >> json;
  EXPECT_FALSE(json.value("candidate_only", true));
  ASSERT_TRUE(json.contains("findings"));
  EXPECT_GE(json["findings"].size(), 3u);
  EXPECT_EQ(json.value("philosophy", ""), "candidate -> validate -> prove vulnerable or dismiss");
}

}  // namespace
