#include "sast/cli/application.hpp"

#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string_view>

#include "sast/build/compilation_database_locator.hpp"
#include "sast/frontend_cpp/tooling_runner.hpp"
#include "sast/ingest/file_inventory.hpp"
#include "sast/report/candidate_json_writer.hpp"
#include "sast/report/demo_report_writer.hpp"
#include "sast/report/facts_json_writer.hpp"
#include "sast/report/report_writers.hpp"
#include "sast/triage/scan_service.hpp"

namespace sast::cli {

namespace {

struct ParsedFactsArgs {
  std::filesystem::path repo_root = std::filesystem::current_path();
  std::optional<std::filesystem::path> explicit_compdb;
  std::optional<std::filesystem::path> changed_files;
  bool auto_compdb = false;
  bool candidates_only = false;
  bool llm_review = false;
  std::size_t jobs = 1;
  std::string format = "json";
  std::optional<std::filesystem::path> out;
  std::string llm_gateway_url = "http://127.0.0.1:8081";
  double llm_timeout_seconds = 25.0;
};

struct ParsedDemoArgs {
  std::optional<std::filesystem::path> repo_root;
  std::string format = "text";
  std::optional<std::filesystem::path> out;
  std::size_t jobs = 1;
};

struct DemoCaseSpec {
  std::string_view slug;
  std::string_view title;
  std::string_view file_name;
  std::string_view story;
  std::string_view takeaway;
};

std::string require_value(const std::vector<std::string>& args, const std::size_t index) {
  if (index + 1 >= args.size()) {
    throw std::runtime_error("missing value for " + args[index]);
  }
  return args[index + 1];
}

std::string env_or_default(const char* name, const std::string_view fallback) {
  if (const auto* value = std::getenv(name)) {
    return value;
  }
  return std::string(fallback);
}

ParsedFactsArgs parse_facts_args(const std::vector<std::string>& args) {
  ParsedFactsArgs parsed;
  parsed.llm_gateway_url = env_or_default("SAST_LLM_GATEWAY_URL", parsed.llm_gateway_url);
  parsed.llm_timeout_seconds = std::stod(env_or_default("SAST_LLM_GATEWAY_TIMEOUT", "25"));
  for (std::size_t index = 0; index < args.size(); ++index) {
    const auto& arg = args[index];
    if (arg == "--repo") {
      parsed.repo_root = require_value(args, index);
      ++index;
    } else if (arg == "--compdb") {
      parsed.explicit_compdb = require_value(args, index);
      ++index;
    } else if (arg == "--changed-files") {
      parsed.changed_files = require_value(args, index);
      ++index;
    } else if (arg == "--auto-compdb") {
      parsed.auto_compdb = true;
    } else if (arg == "--candidates-only") {
      parsed.candidates_only = true;
    } else if (arg == "--llm-review") {
      parsed.llm_review = true;
    } else if (arg == "--llm-gateway") {
      parsed.llm_gateway_url = require_value(args, index);
      ++index;
    } else if (arg == "--jobs") {
      parsed.jobs = static_cast<std::size_t>(std::stoul(require_value(args, index)));
      ++index;
    } else if (arg == "--format") {
      parsed.format = require_value(args, index);
      ++index;
    } else if (arg == "--out") {
      parsed.out = require_value(args, index);
      ++index;
    }
  }
  return parsed;
}

ParsedDemoArgs parse_demo_args(const std::vector<std::string>& args) {
  ParsedDemoArgs parsed;
  for (std::size_t index = 0; index < args.size(); ++index) {
    const auto& arg = args[index];
    if (arg == "--repo") {
      parsed.repo_root = require_value(args, index);
      ++index;
    } else if (arg == "--format") {
      parsed.format = require_value(args, index);
      ++index;
    } else if (arg == "--out") {
      parsed.out = require_value(args, index);
      ++index;
    } else if (arg == "--jobs") {
      parsed.jobs = static_cast<std::size_t>(std::stoul(require_value(args, index)));
      ++index;
    }
  }
  return parsed;
}

std::filesystem::path builtin_demo_repo() {
  return std::filesystem::path(SAST_SOURCE_ROOT) / "tests" / "demo" / "curated";
}

const std::vector<DemoCaseSpec>& demo_specs() {
  static const std::vector<DemoCaseSpec> specs{
    {
      .slug = "confirmed_vulnerability",
      .title = "Confirmed vulnerability",
      .file_name = "confirmed_command.cpp",
      .story = "Direct user-controlled input reaches a command execution sink.",
      .takeaway = "The deterministic engine confirms the issue instead of just pattern matching a sink.",
    },
    {
      .slug = "dismissed_false_positive",
      .title = "Dismissed false positive",
      .file_name = "safe_dismissed.cpp",
      .story = "User input reaches file-open code, but the validator proves the path is constrained under a fixed root.",
      .takeaway = "A lookalike path traversal pattern is dismissed because the safety barrier is explicit and provable.",
    },
    {
      .slug = "cross_function_propagation",
      .title = "Cross-function case",
      .file_name = "cross_function_command.cpp",
      .story = "The sink sits behind a helper function, so the demo is not limited to a single inline expression.",
      .takeaway = "The current MVP still reaches a deterministic decision on a helper-boundary case without claiming unlimited whole-program proof.",
    },
  };
  return specs;
}

const ir::FinalFinding* find_demo_finding(
  const ir::ValidatedScanResult& result,
  const std::string_view file_name) {
  for (const auto& finding : result.findings) {
    if (std::filesystem::path(finding.candidate.file).filename() == file_name) {
      return &finding;
    }
  }
  return nullptr;
}

void write_output(
  const std::optional<std::filesystem::path>& out,
  const std::string& content) {
  if (!out) {
    std::cout << content << '\n';
    return;
  }
  std::ofstream output(*out);
  output << content << '\n';
}

}  // namespace

int Application::run(const std::vector<std::string>& args) const {
  if (args.empty()) {
    std::cerr << "usage: sast-cli <facts|scan|demo> ...\n";
    return 1;
  }

  if (args.front() == "facts") {
    return run_facts(std::vector<std::string>(args.begin() + 1, args.end()));
  }
  if (args.front() == "scan") {
    return run_scan(std::vector<std::string>(args.begin() + 1, args.end()));
  }
  if (args.front() == "demo") {
    return run_demo(std::vector<std::string>(args.begin() + 1, args.end()));
  }

  std::cerr << "unknown command: " << args.front() << '\n';
  return 1;
}

int Application::run_facts(const std::vector<std::string>& args) const {
  const auto parsed = parse_facts_args(args);
  const auto repo_root = std::filesystem::absolute(parsed.repo_root);
  if (!parsed.explicit_compdb && !parsed.auto_compdb) {
    std::cerr << "use --compdb <path> or --auto-compdb\n";
    return 2;
  }
  if (parsed.format != "json") {
    std::cerr << "facts only supports --format json\n";
    return 2;
  }

  const auto compilation_database =
    build::CompilationDatabaseLocator::locate(repo_root, parsed.explicit_compdb);

  if (!compilation_database) {
    std::cerr << "compile_commands.json not found. Use --compdb or generate one with CMake and --auto-compdb.\n";
    return 2;
  }

  const auto commands = build::CompilationDatabaseLocator::read_commands(*compilation_database);
  frontend_cpp::ToolingRunner runner;
  const auto facts = runner.analyze(
    commands,
    *compilation_database,
    {.jobs = parsed.jobs, .project_root = repo_root});

  write_output(parsed.out, report::FactsJsonWriter::render(facts));
  return 0;
}

int Application::run_scan(const std::vector<std::string>& args) const {
  const auto parsed = parse_facts_args(args);
  const auto repo_root = std::filesystem::absolute(parsed.repo_root);

  if (parsed.explicit_compdb && !std::filesystem::exists(*parsed.explicit_compdb)) {
    std::cerr << "explicit compile database not found: " << parsed.explicit_compdb->string() << '\n';
    return 2;
  }

  const auto source_files = ingest::FileInventory::list_source_files(repo_root);
  if (source_files.empty()) {
    std::cerr << "no C/C++ source files found under " << repo_root.string() << '\n';
    return 2;
  }

  triage::ScanService service;
  const auto bundle = service.scan({
    .repo_root = repo_root,
    .explicit_compdb = parsed.explicit_compdb,
    .changed_files = parsed.changed_files,
    .jobs = parsed.jobs,
    .llm_review = parsed.llm_review,
    .llm_gateway_url = parsed.llm_gateway_url,
    .llm_timeout_seconds = parsed.llm_timeout_seconds,
  });

  if (parsed.candidates_only) {
    if (parsed.format != "json") {
      std::cerr << "--candidates-only only supports --format json\n";
      return 2;
    }
    write_output(parsed.out, report::CandidateJsonWriter::render(bundle.candidates));
    return 0;
  }

  std::string output;
  if (parsed.format == "json") {
    output = report::ReportWriters::to_json(bundle.validated);
  } else if (parsed.format == "sarif") {
    output = report::ReportWriters::to_sarif(bundle.validated);
  } else if (parsed.format == "text") {
    output = report::ReportWriters::to_text(bundle.validated);
  } else {
    std::cerr << "unsupported format: " << parsed.format << ". Use json, sarif, or text.\n";
    return 2;
  }

  write_output(parsed.out, output);
  return 0;
}

int Application::run_demo(const std::vector<std::string>& args) const {
  const auto parsed = parse_demo_args(args);
  const auto repo_root = std::filesystem::absolute(parsed.repo_root.value_or(builtin_demo_repo()));

  const auto source_files = ingest::FileInventory::list_source_files(repo_root);
  if (source_files.empty()) {
    std::cerr << "no demo source files found under " << repo_root.string() << '\n';
    return 2;
  }

  triage::ScanService service;
  const auto bundle = service.scan({
    .repo_root = repo_root,
    .explicit_compdb = std::nullopt,
    .changed_files = std::nullopt,
    .jobs = parsed.jobs,
    .llm_review = false,
  });

  report::DemoReport report;
  for (const auto& spec : demo_specs()) {
    const auto* finding = find_demo_finding(bundle.validated, spec.file_name);
    if (finding == nullptr) {
      std::cerr << "demo case missing expected finding for " << spec.file_name << '\n';
      return 2;
    }

    report.cases.push_back({
      .slug = std::string(spec.slug),
      .title = std::string(spec.title),
      .story = std::string(spec.story),
      .takeaway = std::string(spec.takeaway),
      .finding = *finding,
    });
  }

  std::string output;
  if (parsed.format == "text") {
    output = report::DemoReportWriter::to_text(report);
  } else if (parsed.format == "json") {
    output = report::DemoReportWriter::to_json(report);
  } else {
    std::cerr << "demo only supports --format text or json\n";
    return 2;
  }

  write_output(parsed.out, output);
  return 0;
}

}  // namespace sast::cli
