cmake_minimum_required(VERSION 3.28)

project(
  ai_sast
  VERSION 0.2.0
  DESCRIPTION "C++-first AI-assisted SAST engine"
  LANGUAGES CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)
include(GoogleTest)

if(DEFINED LLVM_DIR)
  find_package(LLVM REQUIRED CONFIG PATHS "${LLVM_DIR}" NO_DEFAULT_PATH)
else()
  find_package(LLVM REQUIRED CONFIG)
endif()

if(DEFINED Clang_DIR)
  find_package(Clang REQUIRED CONFIG PATHS "${Clang_DIR}" NO_DEFAULT_PATH)
else()
  find_package(Clang REQUIRED CONFIG)
endif()

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION} at ${LLVM_DIR}")
message(STATUS "Found Clang ${LLVM_PACKAGE_VERSION} at ${Clang_DIR}")

if(LLVM_DEFINITIONS)
  separate_arguments(SAST_LLVM_DEFINITIONS NATIVE_COMMAND "${LLVM_DEFINITIONS}")
endif()

FetchContent_Declare(
  nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz)

FetchContent_MakeAvailable(nlohmann_json googletest)

add_library(
  sast_core
  src/build/compilation_database_capture.cpp
  src/build/compilation_database_locator.cpp
  src/frontend_cpp/tooling_runner.cpp
  src/ingest/file_inventory.cpp
  src/report/candidate_json_writer.cpp
  src/report/demo_report_writer.cpp
  src/report/facts_json_writer.cpp
  src/report/report_writers.cpp
  src/rules/candidate_detector.cpp
  src/rules/rule_registry.cpp
  src/rules/source_sink_registry.cpp
  src/triage/scan_service.cpp
  src/validators/decision_engine.cpp
  src/validators/finding_validator.cpp
  src/validators/validator_registry.cpp)

target_include_directories(
  sast_core
  PUBLIC
    ${PROJECT_SOURCE_DIR}/include
  SYSTEM PRIVATE
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS})

target_compile_options(
  sast_core
  PRIVATE
    ${SAST_LLVM_DEFINITIONS})

target_compile_definitions(
  sast_core
  PUBLIC
    SAST_VERSION="${PROJECT_VERSION}"
    SAST_SOURCE_ROOT="${PROJECT_SOURCE_DIR}")

target_link_libraries(
  sast_core
  PUBLIC
    nlohmann_json::nlohmann_json
    clang-cpp
    LLVM)

add_library(
  sast_cli_lib
  src/cli/application.cpp)

target_link_libraries(sast_cli_lib PUBLIC sast_core)

add_executable(
  sast_cli
  src/cli/main.cpp)

target_link_libraries(sast_cli PRIVATE sast_cli_lib)
set_target_properties(sast_cli PROPERTIES OUTPUT_NAME "sast-cli")

add_executable(
  sast_benchmarks
  benchmarks/scan_benchmark.cpp)

target_link_libraries(sast_benchmarks PRIVATE sast_core)
set_target_properties(sast_benchmarks PROPERTIES OUTPUT_NAME "sast-benchmarks")

add_library(
  sast_test_support
  tests/test_support.cpp)

target_include_directories(
  sast_test_support
  PUBLIC
    ${PROJECT_SOURCE_DIR}/tests
    ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(
  sast_test_support
  PUBLIC
    sast_core
    nlohmann_json::nlohmann_json)

add_executable(
  sast_tests
  tests/integration/candidate_scan_test.cpp
  tests/integration/changed_files_scan_test.cpp
  tests/integration/cli_demo_test.cpp
  tests/integration/cli_report_formats_test.cpp
  tests/integration/cli_scan_test.cpp
  tests/integration/cli_facts_test.cpp
  tests/integration/scan_integration_test.cpp
  tests/integration/scan_metrics_test.cpp
  tests/integration/regression_suite_test.cpp
  tests/unit/compilation_database_locator_test.cpp
  tests/integration/fact_extraction_test.cpp
  tests/unit/report_writer_golden_test.cpp
  tests/unit/source_sink_registry_test.cpp
  tests/unit/validator_test.cpp)

target_link_libraries(
  sast_tests
  PRIVATE
    sast_cli_lib
    sast_test_support
    GTest::gtest_main)

gtest_discover_tests(sast_tests)
