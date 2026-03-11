#pragma once

#include <string>
#include <vector>

#include "sast/ir/facts.hpp"

namespace sast::report {

struct DemoCaseReport {
  std::string slug;
  std::string title;
  std::string story;
  std::string takeaway;
  ir::FinalFinding finding;
};

struct DemoReport {
  std::string mode = "demo";
  std::string title = "ai_sast curated demo";
  std::string philosophy = "candidate -> validate -> prove vulnerable or dismiss";
  std::string honesty_note =
    "This is a small curated demo scanned with the deterministic engine. "
    "It shows confirmed and dismissed outcomes on representative examples, "
    "not complete proof across arbitrary code bases.";
  std::vector<DemoCaseReport> cases;
};

class DemoReportWriter {
 public:
  static std::string to_json(const DemoReport& report);
  static std::string to_text(const DemoReport& report);
};

}  // namespace sast::report
