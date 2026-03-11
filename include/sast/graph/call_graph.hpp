#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "sast/index/symbol_index.hpp"

namespace sast::graph {

class CallGraph {
 public:
  CallGraph(
    const std::vector<ir::TranslationUnitSummary>& summaries,
    const index::SymbolIndex& symbols);

  [[nodiscard]] std::vector<const ir::FunctionSummary*> callees(
    const ir::FunctionSummary& function) const;
  [[nodiscard]] std::size_t indegree(const ir::FunctionSummary& function) const;

 private:
  std::unordered_map<std::string, std::vector<const ir::FunctionSummary*>> adjacency_;
  std::unordered_map<std::string, std::size_t> indegrees_;
};

}  // namespace sast::graph

