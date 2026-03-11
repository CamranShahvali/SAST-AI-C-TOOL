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

std::string normalize_output(std::string text) {
  const auto root = sast::testsupport::source_root().generic_string();
  std::size_t position = text.find(root);
  while (position != std::string::npos) {
    text.replace(position, root.size(), "$ROOT");
    position = text.find(root, position + 5);
  }
  while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
    text.pop_back();
  }
  return text;
}

TEST(CliDemoTest, EmitsGoldenTextOutputForBuiltinDemo) {
  const auto output_path = std::filesystem::temp_directory_path() / "ai_sast_demo_output.txt";

  sast::cli::Application application;
  const auto exit_code = application.run({
    "demo",
    "--out",
    output_path.string(),
  });

  ASSERT_EQ(exit_code, 0);

  const auto actual = normalize_output(read_file(output_path));
  const auto expected = normalize_output(read_file(
    sast::testsupport::source_root() / "tests" / "golden" / "demo_cli.txt"));

  EXPECT_EQ(actual, expected);
}

TEST(CliDemoTest, EmitsGoldenJsonOutputForBuiltinDemo) {
  const auto output_path = std::filesystem::temp_directory_path() / "ai_sast_demo_output.json";

  sast::cli::Application application;
  const auto exit_code = application.run({
    "demo",
    "--format",
    "json",
    "--out",
    output_path.string(),
  });

  ASSERT_EQ(exit_code, 0);

  const auto actual = normalize_output(read_file(output_path));
  const auto expected = normalize_output(read_file(
    sast::testsupport::source_root() / "tests" / "golden" / "demo_cli.json"));

  EXPECT_EQ(actual, expected);

  nlohmann::json json;
  std::ifstream input(output_path);
  input >> json;
  EXPECT_EQ(json.value("mode", ""), "demo");
  EXPECT_EQ(json.value("case_count", 0), 5);
  ASSERT_TRUE(json.contains("cases"));
  ASSERT_EQ(json["cases"].size(), 5u);

  auto case_for_slug = [&json](const std::string& slug) -> const nlohmann::json* {
    for (const auto& item : json["cases"]) {
      if (item.value("slug", "") == slug) {
        return &item;
      }
    }
    return nullptr;
  };

  const auto* likely_issue = case_for_slug("likely_issue");
  const auto* likely_safe = case_for_slug("likely_safe");
  ASSERT_NE(likely_issue, nullptr);
  ASSERT_NE(likely_safe, nullptr);
  EXPECT_EQ(likely_issue->at("finding").value("judgment", ""), "likely_issue");
  EXPECT_EQ(likely_safe->at("finding").value("judgment", ""), "likely_safe");
}

}  // namespace
