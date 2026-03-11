#include "sast/report/facts_json_writer.hpp"

namespace sast::report {

std::string FactsJsonWriter::render(const ir::FactDatabase& facts) {
  nlohmann::json json = facts;
  return json.dump(2);
}

}  // namespace sast::report
