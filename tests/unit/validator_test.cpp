#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "sast/validators/finding_validator.hpp"
#include "sast/validators/validator_registry.hpp"
#include "test_support.hpp"

namespace {

sast::ir::CandidateFinding make_candidate(const std::string& family) {
  sast::ir::CandidateFinding candidate;
  candidate.rule_family = family;
  candidate.rule_id =
    family == "command_injection" ? "command_injection.system"
    : family == "path_traversal"  ? "path_traversal.file_open"
                                  : "dangerous_string.unbounded_copy";
  candidate.file = "/tmp/example.cpp";
  candidate.line = 7;
  candidate.function_name = "main";
  candidate.sink_name =
    family == "command_injection" ? "system"
    : family == "path_traversal"  ? "fopen"
                                  : "snprintf";
  candidate.sink_arguments =
    family == "dangerous_string"
      ? std::vector<std::string>{"buffer", "sizeof(buffer)", "\"%s\"", "argv[1]"}
      : std::vector<std::string>{"argv[1]"};
  candidate.source_expression = "argv[1]";
  candidate.source_summary = "argv[1]";
  candidate.sink_summary = candidate.sink_name;
  candidate.trace_steps = {
    "candidate only: configured sink matched rule family",
    "expression depends on parameter argv",
    "expression references argv",
  };
  candidate.provisional_severity = "high";
  candidate.evidence_locations = {{
    .file = candidate.file,
    .line = candidate.line,
    .column = 3,
  }};
  candidate.destination_extent = std::size_t{8};
  candidate.bound_expression = "sizeof(buffer)";
  return candidate;
}

TEST(FindingValidatorTest, TrustedWrapperBecomesSafeSuppressed) {
  const auto registry = sast::validators::ValidatorRegistry::load(sast::testsupport::source_root());
  const sast::validators::FindingValidator validator(registry);
  auto candidate = make_candidate("command_injection");
  candidate.trace_steps.push_back("trusted wrapper run_allowlisted_command observed for cmd");

  const auto result = validator.validate(candidate);
  EXPECT_EQ(result.final_decision, sast::ir::Decision::safe_suppressed);
}

TEST(FindingValidatorTest, TestArtifactIsDismissed) {
  const auto registry = sast::validators::ValidatorRegistry::load(sast::testsupport::source_root());
  const sast::validators::FindingValidator validator(registry);
  auto candidate = make_candidate("command_injection");
  candidate.file = "/tmp/example_test.cpp";

  const auto result = validator.validate(candidate);
  EXPECT_EQ(result.final_decision, sast::ir::Decision::safe_suppressed);
}

TEST(FindingValidatorTest, DeadBranchIsDismissed) {
  const auto registry = sast::validators::ValidatorRegistry::load(sast::testsupport::source_root());
  const sast::validators::FindingValidator validator(registry);

  const auto file = std::filesystem::temp_directory_path() / "ai_sast_dead_branch.cpp";
  std::ofstream output(file);
  output << "#include <cstdlib>\n"
            "int main(int argc, char** argv) {\n"
            "  if (false) {\n"
            "    return system(argv[1]);\n"
            "  }\n"
            "  return 0;\n"
            "}\n";
  output.close();

  auto candidate = make_candidate("command_injection");
  candidate.file = file.string();
  candidate.line = 4;
  candidate.evidence_locations = {{
    .file = candidate.file,
    .line = candidate.line,
    .column = 12,
  }};

  const auto result = validator.validate(candidate);
  EXPECT_EQ(result.final_decision, sast::ir::Decision::safe_suppressed);
}

TEST(FindingValidatorTest, CanonicalizedPathUnderRootBecomesSafeSuppressed) {
  const auto registry = sast::validators::ValidatorRegistry::load(sast::testsupport::source_root());
  const sast::validators::FindingValidator validator(registry);
  auto candidate = make_candidate("path_traversal");
  candidate.sink_name = "fopen";
  candidate.sink_arguments = {"path.c_str()", "\"r\""};
  candidate.source_expression = "path.c_str()";
  candidate.source_summary = "canonicalize_under_root(argv[1], \"/srv/data\")";
  candidate.trace_steps.push_back("sanitizer canonicalize_under_root observed for path");

  const auto result = validator.validate(candidate);
  EXPECT_EQ(result.final_decision, sast::ir::Decision::safe_suppressed);
}

TEST(FindingValidatorTest, BoundedSnprintfCanBeProvenSafe) {
  const auto registry = sast::validators::ValidatorRegistry::load(sast::testsupport::source_root());
  const sast::validators::FindingValidator validator(registry);
  auto candidate = make_candidate("dangerous_string");
  candidate.sink_name = "snprintf";

  const auto result = validator.validate(candidate);
  EXPECT_EQ(result.final_decision, sast::ir::Decision::safe_suppressed);
}

}  // namespace
