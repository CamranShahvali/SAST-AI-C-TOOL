#include "sast/graph/call_graph.hpp"

namespace sast::graph {

CallGraph::CallGraph(
  const std::vector<ir::TranslationUnitSummary>& summaries,
  const index::SymbolIndex& symbols) {
  for (const auto& summary : summaries) {
    for (const auto& function : summary.functions) {
      auto& edges = adjacency_[function.qualified_name];
      for (const auto& call : function.calls) {
        if (const auto* callee = symbols.find_function(call.function_name)) {
          edges.push_back(callee);
          ++indegrees_[callee->qualified_name];
        }
      }
      indegrees_.try_emplace(function.qualified_name, 0);
    }
  }
}

std::vector<const ir::FunctionSummary*> CallGraph::callees(
  const ir::FunctionSummary& function) const {
  const auto found = adjacency_.find(function.qualified_name);
  if (found == adjacency_.end()) {
    return {};
  }
  return found->second;
}

std::size_t CallGraph::indegree(const ir::FunctionSummary& function) const {
  const auto found = indegrees_.find(function.qualified_name);
  return found == indegrees_.end() ? 0 : found->second;
}

}  // namespace sast::graph

