#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "sast/ir/models.hpp"

namespace sast::index {

class SymbolIndex {
 public:
  explicit SymbolIndex(const std::vector<ir::TranslationUnitSummary>& summaries);

  [[nodiscard]] const ir::FunctionSummary* find_function(std::string_view qualified_name) const;
  [[nodiscard]] std::vector<const ir::FunctionSummary*> functions() const;

 private:
  std::vector<const ir::FunctionSummary*> functions_;
  std::unordered_map<std::string, const ir::FunctionSummary*> by_name_;
};

}  // namespace sast::index

