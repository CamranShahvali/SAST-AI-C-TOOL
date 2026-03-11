#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include "sast/report/candidate_json_writer.hpp"
#include "sast/report/report_writers.hpp"
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
  position = text.find("$ROOT/build/synthetic");
  while (position != std::string::npos) {
    text.replace(position, std::string("$ROOT/build/synthetic").size(), "$ROOT/synthetic");
    position = text.find("$ROOT/build/synthetic", position + 15);
  }
  while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
    text.pop_back();
  }
  return text;
}

TEST(ReportWriterGoldenTest, CandidateJsonMatchesGolden) {
  const auto result = sast::testsupport::scan_candidate_repo(
    sast::testsupport::source_root() / "tests" / "cases" / "demo");

  const auto actual = normalize_output(sast::report::CandidateJsonWriter::render(result));
  const auto expected = normalize_output(read_file(
    sast::testsupport::source_root() / "tests" / "golden" / "candidate_demo.json"));

  EXPECT_EQ(actual, expected);
}

TEST(ReportWriterGoldenTest, ValidatedJsonMatchesGolden) {
  const auto result = sast::testsupport::scan_validated_repo(
    sast::testsupport::source_root() / "tests" / "cases" / "demo");

  const auto actual = normalize_output(sast::report::ReportWriters::to_json(result));
  const auto expected = normalize_output(read_file(
    sast::testsupport::source_root() / "tests" / "golden" / "validated_demo.json"));

  EXPECT_EQ(actual, expected);
}

TEST(ReportWriterGoldenTest, SarifMatchesGolden) {
  const auto result = sast::testsupport::scan_validated_repo(
    sast::testsupport::source_root() / "tests" / "cases" / "demo");

  const auto actual = normalize_output(sast::report::ReportWriters::to_sarif(result));
  const auto expected = normalize_output(read_file(
    sast::testsupport::source_root() / "tests" / "golden" / "validated_demo.sarif"));

  EXPECT_EQ(actual, expected);
}

TEST(ReportWriterGoldenTest, TextMatchesGolden) {
  const auto result = sast::testsupport::scan_validated_repo(
    sast::testsupport::source_root() / "tests" / "cases" / "demo");

  const auto actual = normalize_output(sast::report::ReportWriters::to_text(result));
  const auto expected = normalize_output(read_file(
    sast::testsupport::source_root() / "tests" / "golden" / "validated_demo.txt"));

  EXPECT_EQ(actual, expected);
}

}  // namespace
