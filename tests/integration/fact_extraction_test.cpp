#include <gtest/gtest.h>

#include <algorithm>

#include "test_support.hpp"

namespace {

const sast::ir::TranslationUnit* find_translation_unit(
  const sast::ir::FactDatabase& facts,
  const std::string& suffix) {
  for (const auto& translation_unit : facts.translation_units) {
    if (translation_unit.file_path.ends_with(suffix)) {
      return &translation_unit;
    }
  }
  return nullptr;
}

const sast::ir::Function* find_function(
  const sast::ir::TranslationUnit& translation_unit,
  const std::string& name) {
  for (const auto& function : translation_unit.functions) {
    if (function.qualified_name == name || function.qualified_name.ends_with("::" + name)) {
      return &function;
    }
  }
  return nullptr;
}

TEST(FactExtractionTest, ExtractsFunctionsCallsAndVariableReferences) {
  const auto facts = sast::testsupport::extract_fixture_facts("cmake_cpp_sample");

  ASSERT_GE(facts.translation_units.size(), 2u);
  const auto* main_translation_unit = find_translation_unit(facts, "src/main.cpp");
  ASSERT_NE(main_translation_unit, nullptr);

  const auto* main_function = find_function(*main_translation_unit, "main");
  ASSERT_NE(main_function, nullptr);
  EXPECT_TRUE(main_function->location.valid());
  EXPECT_GE(main_function->call_sites.size(), 2u);
  EXPECT_GE(main_function->variable_refs.size(), 4u);

  EXPECT_TRUE(std::any_of(
    main_function->call_sites.begin(),
    main_function->call_sites.end(),
    [](const sast::ir::CallSite& call_site) {
      return call_site.callee.ends_with("make_message");
    }));
  EXPECT_TRUE(std::any_of(
    main_function->call_sites.begin(),
    main_function->call_sites.end(),
    [](const sast::ir::CallSite& call_site) {
      return call_site.callee.ends_with("print_message");
    }));

  EXPECT_TRUE(std::any_of(
    main_function->variable_refs.begin(),
    main_function->variable_refs.end(),
    [](const sast::ir::VariableRef& reference) {
      return reference.name == "argc" && reference.referenced_kind == "parameter";
    }));
  EXPECT_TRUE(std::any_of(
    main_function->variable_refs.begin(),
    main_function->variable_refs.end(),
    [](const sast::ir::VariableRef& reference) {
      return reference.name == "name";
    }));
}

TEST(FactExtractionTest, ExtractsHelperFunctionFacts) {
  const auto facts = sast::testsupport::extract_fixture_facts("cmake_cpp_sample");
  const auto* helper_translation_unit = find_translation_unit(facts, "src/helpers.cpp");
  ASSERT_NE(helper_translation_unit, nullptr);

  const auto* helper_function = find_function(*helper_translation_unit, "sample::make_message");
  ASSERT_NE(helper_function, nullptr);
  EXPECT_TRUE(helper_function->location.valid());
  EXPECT_TRUE(std::any_of(
    helper_function->variable_refs.begin(),
    helper_function->variable_refs.end(),
    [](const sast::ir::VariableRef& reference) {
      return reference.name == "prefix";
    }));
}

}  // namespace
