#pragma once

#include <cstddef>
#include <filesystem>
#include <vector>

#include "sast/build/compilation_database_locator.hpp"
#include "sast/ir/facts.hpp"

namespace sast::frontend_cpp {

struct ToolingOptions {
  std::size_t jobs = 1;
  std::filesystem::path project_root;
};

class ToolingRunner {
 public:
  [[nodiscard]] ir::FactDatabase analyze(
    const std::vector<build::CompileCommandInfo>& commands,
    const std::filesystem::path& compilation_database_path,
    const ToolingOptions& options = {}) const;
};

}  // namespace sast::frontend_cpp
