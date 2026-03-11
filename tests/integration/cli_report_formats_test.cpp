#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include <nlohmann/json.hpp>

#include "sast/cli/application.hpp"
#include "test_support.hpp"

namespace {

std::string read_file(const std::filesystem::path& path) {
  std::ifstream input(path);
  std::ostringstream stream;
  stream << input.rdbuf();
  return stream.str();
}

TEST(CliReportFormatsTest, EmitsJsonAndSarifFiles) {
  const auto repo_root =
    sast::testsupport::source_root() / "tests" / "cases" / "demo";
  const auto relative_repo =
    std::filesystem::relative(repo_root, std::filesystem::current_path());
  const auto json_path = std::filesystem::temp_directory_path() / "ai_sast_report.json";
  const auto sarif_path = std::filesystem::temp_directory_path() / "ai_sast_report.sarif";

  sast::cli::Application application;

  ASSERT_EQ(application.run({
              "scan",
              "--repo",
              relative_repo.string(),
              "--format",
              "json",
              "--out",
              json_path.string(),
            }),
            0);
  ASSERT_EQ(application.run({
              "scan",
              "--repo",
              relative_repo.string(),
              "--format",
              "sarif",
              "--out",
              sarif_path.string(),
            }),
            0);

  nlohmann::json json_output;
  {
    std::ifstream input(json_path);
    input >> json_output;
  }
  EXPECT_EQ(json_output.value("mode", ""), "validated_scan");
  EXPECT_FALSE(json_output.value("candidate_only", true));
  ASSERT_TRUE(json_output.contains("findings"));
  EXPECT_GE(json_output["findings"].size(), 3u);

  nlohmann::json sarif_output;
  {
    std::ifstream input(sarif_path);
    input >> sarif_output;
  }
  EXPECT_EQ(sarif_output.value("version", ""), "2.1.0");
  ASSERT_TRUE(sarif_output.contains("runs"));
  ASSERT_FALSE(sarif_output["runs"].empty());
}

TEST(CliReportFormatsTest, EmitsTextFile) {
  const auto repo_root =
    sast::testsupport::source_root() / "tests" / "cases" / "demo";
  const auto relative_repo =
    std::filesystem::relative(repo_root, std::filesystem::current_path());
  const auto text_path = std::filesystem::temp_directory_path() / "ai_sast_report.txt";

  sast::cli::Application application;
  ASSERT_EQ(application.run({
              "scan",
              "--repo",
              relative_repo.string(),
              "--format",
              "text",
              "--out",
              text_path.string(),
            }),
            0);

  const auto text = read_file(text_path);
  EXPECT_NE(text.find("[confirmed_issue]"), std::string::npos);
  EXPECT_NE(text.find("[safe_suppressed]"), std::string::npos);
  EXPECT_NE(text.find("[needs_review]"), std::string::npos);
}

}  // namespace
