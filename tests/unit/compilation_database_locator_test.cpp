#include <gtest/gtest.h>

#include <algorithm>

#include "sast/build/compilation_database_locator.hpp"
#include "test_support.hpp"

namespace {

TEST(CompilationDatabaseLocatorTest, FindsBuildDirectoryCompilationDatabase) {
  const auto prepared = sast::testsupport::configure_fixture_copy("cmake_cpp_sample");
  const auto located = sast::build::CompilationDatabaseLocator::locate(prepared.root, std::nullopt);

  ASSERT_TRUE(located.has_value());
  EXPECT_EQ(std::filesystem::weakly_canonical(*located),
            std::filesystem::weakly_canonical(prepared.compilation_database));
}

TEST(CompilationDatabaseLocatorTest, ReadsCommandsFromCompilationDatabase) {
  const auto prepared = sast::testsupport::configure_fixture_copy("cmake_cpp_sample");
  const auto commands =
    sast::build::CompilationDatabaseLocator::read_commands(prepared.compilation_database);

  ASSERT_GE(commands.size(), 2u);
  EXPECT_TRUE(std::any_of(
    commands.begin(),
    commands.end(),
    [](const sast::build::CompileCommandInfo& command) {
      return command.file.filename() == "main.cpp";
    }));
}

}  // namespace
