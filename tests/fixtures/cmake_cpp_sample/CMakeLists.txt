cmake_minimum_required(VERSION 3.20)

project(cmake_cpp_sample LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(
  sample_lib
  src/helpers.cpp)

target_include_directories(
  sample_lib
  PUBLIC
    ${PROJECT_SOURCE_DIR}/include)

add_executable(
  sample_app
  src/main.cpp)

target_link_libraries(sample_app PRIVATE sample_lib)

