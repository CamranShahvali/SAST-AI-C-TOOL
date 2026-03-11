#include "sast/cli/interactive_terminal.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string_view>

#include <httplib.h>
#include <nlohmann/json.hpp>

#if defined(_WIN32)
#include <io.h>
#define SAST_ISATTY _isatty
#define SAST_FILENO _fileno
#else
#include <unistd.h>
#define SAST_ISATTY isatty
#define SAST_FILENO fileno
#endif

namespace sast::cli {

namespace {

struct ParsedHttpUrl {
  std::string host;
  int port = 80;
};

std::optional<ParsedHttpUrl> parse_http_url(const std::string& base_url) {
  constexpr std::string_view prefix = "http://";
  if (!base_url.starts_with(prefix)) {
    return std::nullopt;
  }

  auto authority = base_url.substr(prefix.size());
  const auto path_start = authority.find('/');
  if (path_start != std::string::npos) {
    authority = authority.substr(0, path_start);
  }
  if (authority.empty()) {
    return std::nullopt;
  }

  ParsedHttpUrl parsed;
  const auto port_separator = authority.rfind(':');
  if (port_separator == std::string::npos) {
    parsed.host = authority;
    return parsed;
  }

  parsed.host = authority.substr(0, port_separator);
  if (parsed.host.empty()) {
    return std::nullopt;
  }

  try {
    parsed.port = std::stoi(authority.substr(port_separator + 1));
  } catch (...) {
    return std::nullopt;
  }
  return parsed;
}

bool env_truthy(const char* name) {
  const auto* value = std::getenv(name);
  if (value == nullptr) {
    return false;
  }

  std::string normalized(value);
  std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return normalized != "0" && normalized != "false" && normalized != "no" && normalized != "off";
}

std::string trim(std::string value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) {
    return "";
  }
  const auto last = value.find_last_not_of(" \t\r\n");
  return value.substr(first, last - first + 1);
}

bool looks_like_cpp_file(const std::filesystem::path& path) {
  const auto extension = path.extension().string();
  return extension == ".c" || extension == ".cc" || extension == ".cpp" || extension == ".cxx" ||
         extension == ".h" || extension == ".hh" || extension == ".hpp" || extension == ".hxx";
}

std::filesystem::path normalized_path(const std::filesystem::path& path) {
  std::error_code error;
  const auto canonical = std::filesystem::weakly_canonical(path, error);
  if (!error) {
    return canonical;
  }
  return std::filesystem::absolute(path).lexically_normal();
}

bool is_repo_root(const std::filesystem::path& path) {
  return normalized_path(path) == normalized_path(std::filesystem::path(SAST_SOURCE_ROOT));
}

std::filesystem::path temporary_changed_files_path() {
  const auto timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
  return std::filesystem::temp_directory_path() /
         ("ai_sast_interactive_changed_" + std::to_string(timestamp) + ".txt");
}

}  // namespace

InteractiveTerminal::InteractiveTerminal(
  std::istream& input,
  std::ostream& output,
  std::ostream& error,
  CommandRunner command_runner,
  GatewayProbe gateway_probe)
  : input_(input),
    output_(output),
    error_(error),
    command_runner_(std::move(command_runner)),
    gateway_probe_(std::move(gateway_probe)) {}

InteractiveTerminal::Environment InteractiveTerminal::detect_environment() {
  return Environment{
    .stdin_is_terminal = SAST_ISATTY(SAST_FILENO(stdin)) == 1,
    .stdout_is_terminal = SAST_ISATTY(SAST_FILENO(stdout)) == 1,
    .ci = env_truthy("CI"),
  };
}

bool InteractiveTerminal::supported(
  const std::string_view format,
  const Environment& environment) {
  if (format == "json" || format == "sarif") {
    return false;
  }
  return environment.stdin_is_terminal && environment.stdout_is_terminal && !environment.ci;
}

InteractiveTerminal::GatewayStatus InteractiveTerminal::detect_gateway_status(
  const Options& options) {
  const auto parsed = parse_http_url(options.gateway_url);
  if (!parsed) {
    return {};
  }

  httplib::Client client(parsed->host, parsed->port);
  const auto timeout_ms = static_cast<int>(std::ceil(options.gateway_timeout_seconds * 1000.0));
  client.set_connection_timeout(std::chrono::milliseconds(timeout_ms));
  client.set_read_timeout(std::chrono::milliseconds(timeout_ms));
  client.set_write_timeout(std::chrono::milliseconds(timeout_ms));

  const auto response = client.Get("/health");
  if (!response || response->status < 200 || response->status >= 300) {
    return {};
  }

  try {
    const auto json = nlohmann::json::parse(response->body);
    return GatewayStatus{
      .connected = json.value("status", "") == "ok",
      .model = json.value("model", ""),
    };
  } catch (...) {
    return {};
  }
}

std::string InteractiveTerminal::render_banner(
  const GatewayStatus& status,
  const Options& options) {
  std::ostringstream output;
  output << "+------------------------------------------------------+\n";
  output << "| ai_sast interactive terminal                         |\n";
  output << "+------------------------------------------------------+\n";
  output << "| Camran Shahvali                                      |\n";
  output << "| GitHub: https://github.com/CamranShahvali            |\n";
  output << "| LinkedIn: https://linkedin.com/in/camran-shahvali-9409b61a6 |\n";
  output << "+------------------------------------------------------+\n";
  output << "Engine: Ready\n";
  output << "Gateway: " << (status.connected ? "Connected" : "Not detected") << '\n';
  output << "Model: " << (status.connected && !status.model.empty() ? status.model : options.default_model)
         << '\n';
  return output.str();
}

std::string InteractiveTerminal::render_menu() {
  return
    "\n"
    "1. Scan repository\n"
    "2. Scan single C++ file\n"
    "3. Scan with engine only (choose target)\n"
    "4. Scan with engine + LLM review (choose target)\n"
    "5. Run demo case\n"
    "6. Setup & tutorials\n"
    "7. Exit\n";
}

std::string InteractiveTerminal::render_tutorial(const Options& options) {
  std::ostringstream output;
  output << "\nSetup & tutorials\n";
  output << "-----------------\n";
  output << "Engine-only mode\n";
  output << "  Use deterministic scanning when you want the engine to remain the only source of truth.\n";
  output << "  Example:\n";
  output << "    ./build/sast-cli scan --repo tests/cases/demo --format text\n\n";
  output << "  Safer first interactive runs:\n";
  output << "    - Curated five-outcome demo\n";
  output << "    - Mixed single-file demo at tests/demo/mixed_case\n\n";

  output << "Connecting local AI with Ollama\n";
  output << "  1. Start Ollama locally.\n";
  output << "  2. Pull a local model if you do not already have one.\n";
  output << "  3. Start llm_gateway and point it at your local Ollama endpoint.\n\n";

  output << "Recommended models\n";
  output << "  - Start with " << options.default_model << " (the current repo default).\n";
  output << "  - If you try alternatives, prefer code-focused local models that can follow strict JSON output reliably.\n\n";

  output << "Starting the gateway\n";
  output << "  source .venv/bin/activate\n";
  output << "  export SAST_LLM_ENABLED=1\n";
  output << "  export SAST_LLM_PROVIDER=ollama\n";
  output << "  export SAST_LLM_BASE_URL=http://127.0.0.1:11434\n";
  output << "  export SAST_LLM_MODEL=" << options.default_model << '\n';
  output << "  uvicorn llm_gateway.app.main:app --host 127.0.0.1 --port 8081\n\n";

  output << "Troubleshooting LLM detection\n";
  output << "  - If Gateway shows 'Not detected', make sure llm_gateway is running on " << options.gateway_url << ".\n";
  output << "  - Check: curl " << options.gateway_url << "/health\n";
  output << "  - If the gateway is up but the model is wrong, verify SAST_LLM_MODEL in the gateway shell.\n";
  output << "  - If scans hang, test the engine-only path first and then bring the gateway back.\n";
  return output.str();
}

int InteractiveTerminal::run(const Options& options) {
  const auto status = gateway_probe_(options);
  output_ << render_banner(status, options) << '\n';

  while (true) {
    output_ << render_menu();
    const auto choice = prompt("Select an option [1-7]: ");

    if (choice == "1") {
      scan_repository(false, options);
    } else if (choice == "2") {
      scan_single_file(false, options);
    } else if (choice == "3") {
      scan_target_prompt(false, options);
    } else if (choice == "4") {
      scan_target_prompt(true, options);
    } else if (choice == "5") {
      run_demo_menu(options);
    } else if (choice == "6") {
      output_ << render_tutorial(options) << '\n';
      (void)prompt("Press Enter to return to the menu...");
    } else if (choice == "7") {
      output_ << "Exiting interactive terminal.\n";
      return 0;
    } else {
      error_ << "Invalid selection. Choose 1-7.\n";
    }
  }
}

std::string InteractiveTerminal::prompt(const std::string& label) {
  output_ << label;
  output_.flush();
  std::string value;
  std::getline(input_, value);
  return trim(value);
}

int InteractiveTerminal::scan_repository(bool llm_review, const Options& options) {
  while (true) {
    const auto value = prompt("Repository path [press Enter for current directory]: ");
    const auto repo_root = std::filesystem::absolute(
      value.empty() || value == "." ? std::filesystem::current_path() : std::filesystem::path(value));

    if ((value.empty() || value == ".") && is_repo_root(repo_root)) {
      output_ << "\nYou are at the ai_sast repository root.\n";
      output_ << "Scanning '.' here is valid, but it is a noisy first run.\n";
      output_ << "Safer choices:\n";
      output_ << "1. Curated five-outcome demo\n";
      output_ << "2. Mixed single-file demo\n";
      output_ << "3. Scan the current repository anyway\n";
      output_ << "4. Enter a different repository path\n";
      output_ << "5. Back\n";

      const auto guard_choice = prompt("Choose a safer starting point [1-5]: ");
      if (guard_choice == "1" || guard_choice == "2") {
        return run_demo_selection(guard_choice, llm_review, options);
      }
      if (guard_choice == "3") {
        // Continue below and scan the current repository.
      } else if (guard_choice == "4") {
        output_ << '\n';
        continue;
      } else if (guard_choice == "5" || guard_choice.empty()) {
        output_ << '\n';
        return 0;
      } else {
        error_ << "Invalid selection. Choose 1-5.\n\n";
        continue;
      }
    }

    std::vector<std::string> args{
      "scan",
      "--repo",
      repo_root.string(),
      "--format",
      "text",
    };
    if (llm_review) {
      args.push_back("--llm-review");
      args.push_back("--llm-gateway");
      args.push_back(options.gateway_url);
    }

    output_ << '\n';
    const auto exit_code = run_command(args);
    if (exit_code != 0) {
      error_ << "Scan exited with code " << exit_code << ".\n";
    }
    output_ << '\n';
    return exit_code;
  }
}

int InteractiveTerminal::scan_single_file(bool llm_review, const Options& options) {
  const auto value = prompt("C++ file path [for a quick demo try tests/demo/mixed_case/mixed_paths.cpp]: ");
  if (value.empty()) {
    error_ << "No file path provided.\n";
    return 2;
  }
  if (value == ".") {
    error_ << "'.' is a directory. Use 'Scan repository' for a full tree, or point to a single file such as tests/demo/mixed_case/mixed_paths.cpp.\n";
    return 2;
  }

  const auto file_path = std::filesystem::absolute(std::filesystem::path(value));
  if (!std::filesystem::exists(file_path)) {
    error_ << "File not found: " << file_path.string() << '\n';
    return 2;
  }
  if (std::filesystem::is_directory(file_path)) {
    error_ << "Path is a directory, not a single C++ file: " << file_path.string()
           << ". Use 'Scan repository' or choose tests/demo/mixed_case/mixed_paths.cpp.\n";
    return 2;
  }
  if (!std::filesystem::is_regular_file(file_path)) {
    error_ << "Path is not a regular file: " << file_path.string() << '\n';
    return 2;
  }
  if (!looks_like_cpp_file(file_path)) {
    error_ << "File does not look like a C/C++ source file: " << file_path.string() << '\n';
    return 2;
  }

  const auto repo_root = file_path.parent_path();
  const auto changed_files = temporary_changed_files_path();
  {
    std::ofstream output(changed_files);
    output << file_path.filename().string() << '\n';
  }

  std::vector<std::string> args{
    "scan",
    "--repo",
    repo_root.string(),
    "--changed-files",
    changed_files.string(),
    "--format",
    "text",
  };
  if (llm_review) {
    args.push_back("--llm-review");
    args.push_back("--llm-gateway");
    args.push_back(options.gateway_url);
  }

  output_ << '\n';
  const auto exit_code = run_command(args);
  std::filesystem::remove(changed_files);
  if (exit_code != 0) {
    error_ << "Scan exited with code " << exit_code << ".\n";
  }
  output_ << '\n';
  return exit_code;
}

int InteractiveTerminal::scan_target_prompt(bool llm_review, const Options& options) {
  output_ << "\nScan target\n";
  output_ << "1. Repository path\n";
  output_ << "2. Single C++ file\n";
  output_ << "3. Curated five-outcome demo\n";
  output_ << "4. Mixed single-file demo\n";
  output_ << "5. Back\n";

  const auto target = prompt("Choose a target [1-5]: ");
  if (target == "1") {
    return scan_repository(llm_review, options);
  }
  if (target == "2") {
    return scan_single_file(llm_review, options);
  }
  if (target == "3" || target == "4") {
    return run_demo_selection(target, llm_review, options);
  }
  if (target == "5" || target.empty()) {
    return 0;
  }
  error_ << "Invalid selection. Choose 1-5.\n";
  return 2;
}

int InteractiveTerminal::run_demo_selection(
  std::string_view selection,
  bool llm_review,
  const Options& options) {
  std::vector<std::string> args;
  if (selection == "1") {
    args = {"demo"};
  } else if (selection == "2") {
    args = {
      "scan",
      "--repo",
      (std::filesystem::path(SAST_SOURCE_ROOT) / "tests" / "demo" / "mixed_case").string(),
      "--format",
      "text",
    };
  } else {
    error_ << "Unknown demo selection.\n";
    return 2;
  }

  if (llm_review) {
    args.push_back("--llm-review");
    args.push_back("--llm-gateway");
    args.push_back(options.gateway_url);
  }

  output_ << '\n';
  const auto exit_code = run_command(args);
  if (exit_code != 0) {
    error_ << "Demo exited with code " << exit_code << ".\n";
  }
  output_ << '\n';
  return exit_code;
}

int InteractiveTerminal::run_demo_menu(const Options& options) {
  output_ << "\n1. Curated five-outcome demo\n";
  output_ << "2. Mixed single-file demo\n";
  output_ << "3. Back\n";
  const auto selection = prompt("Choose a demo [1-3]: ");
  if (selection == "3" || selection.empty()) {
    return 0;
  }

  const auto llm = prompt("Enable LLM review? [y/N]: ");
  const auto llm_review = llm == "y" || llm == "Y" || llm == "yes" || llm == "YES";
  return run_demo_selection(selection, llm_review, options);
}

int InteractiveTerminal::run_command(const std::vector<std::string>& args) const {
  return command_runner_(args);
}

}  // namespace sast::cli
