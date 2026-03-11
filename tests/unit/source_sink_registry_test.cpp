#include <gtest/gtest.h>

#include "sast/rules/source_sink_registry.hpp"
#include "test_support.hpp"

namespace {

TEST(SourceSinkRegistryTest, LoadsVersionedDefaultConfig) {
  const auto registry = sast::rules::SourceSinkRegistry::load(sast::testsupport::source_root());

  EXPECT_TRUE(registry.is_source_function("getenv"));
  EXPECT_TRUE(registry.is_entrypoint("main"));
  EXPECT_TRUE(registry.is_command_sink("system"));
  EXPECT_TRUE(registry.is_path_sink("fopen"));
  EXPECT_TRUE(registry.is_string_sink("strcpy"));
  EXPECT_TRUE(registry.is_allowlist_predicate("is_allowed_command"));
  EXPECT_TRUE(registry.is_path_sanitizer("canonicalize_under_root"));
  EXPECT_TRUE(registry.is_trusted_wrapper("run_allowlisted_command"));
  EXPECT_TRUE(registry.is_trusted_accessor("c_str"));
  EXPECT_TRUE(registry.is_test_path(
    sast::testsupport::source_root() / "tests" / "cases" / "command_injection" / "vulnerable.cpp"));
}

}  // namespace
