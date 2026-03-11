#pragma once

#include <functional>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

namespace sast::cli {

class InteractiveTerminal {
 public:
  struct Options {
    std::string gateway_url = "http://127.0.0.1:8081";
    double gateway_timeout_seconds = 2.0;
    std::string default_model = "deepseek-coder:6.7b";
  };

  struct Environment {
    bool stdin_is_terminal = true;
    bool stdout_is_terminal = true;
    bool ci = false;
  };

  struct GatewayStatus {
    bool connected = false;
    std::string model;
  };

  using CommandRunner = std::function<int(const std::vector<std::string>&)>;
  using GatewayProbe = std::function<GatewayStatus(const Options&)>;

  InteractiveTerminal(
    std::istream& input,
    std::ostream& output,
    std::ostream& error,
    CommandRunner command_runner,
    GatewayProbe gateway_probe = detect_gateway_status);

  [[nodiscard]] static Environment detect_environment();
  [[nodiscard]] static bool supported(std::string_view format, const Environment& environment);
  [[nodiscard]] static GatewayStatus detect_gateway_status(const Options& options);
  [[nodiscard]] static std::string render_banner(const GatewayStatus& status, const Options& options);
  [[nodiscard]] static std::string render_menu();
  [[nodiscard]] static std::string render_tutorial(const Options& options);

  int run(const Options& options);

 private:
  [[nodiscard]] std::string prompt(const std::string& label);
  int scan_repository(bool llm_review, const Options& options);
  int scan_single_file(bool llm_review, const Options& options);
  int scan_target_prompt(bool llm_review, const Options& options);
  int run_demo_menu(const Options& options);
  int run_command(const std::vector<std::string>& args) const;

  std::istream& input_;
  std::ostream& output_;
  std::ostream& error_;
  CommandRunner command_runner_;
  GatewayProbe gateway_probe_;
};

}  // namespace sast::cli
