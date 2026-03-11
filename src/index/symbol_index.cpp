#include "sast/index/symbol_index.hpp"

namespace sast::index {

namespace {

std::string short_name(const std::string& value) {
  const auto index = value.rfind("::");
  if (index == std::string::npos) {
    return value;
  }
  return value.substr(index + 2);
}

}  // namespace

SymbolIndex::SymbolIndex(const std::vector<ir::TranslationUnitSummary>& summaries) {
  for (const auto& summary : summaries) {
    for (const auto& function : summary.functions) {
      functions_.push_back(&function);
      by_name_.emplace(function.qualified_name, &function);
      by_name_.emplace(short_name(function.qualified_name), &function);
    }
  }
}

const ir::FunctionSummary* SymbolIndex::find_function(std::string_view qualified_name) const {
  const auto found = by_name_.find(std::string(qualified_name));
  if (found == by_name_.end()) {
    return nullptr;
  }
  return found->second;
}

std::vector<const ir::FunctionSummary*> SymbolIndex::functions() const {
  return functions_;
}

}  // namespace sast::index

