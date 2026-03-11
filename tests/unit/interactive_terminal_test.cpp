#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "sast/cli/application.hpp"
#include "sast/cli/interactive_terminal.hpp"

namespace {

TEST(InteractiveTerminalTest, SupportedRejectsJsonSarifCiAndNonTerminal) {
  const sast::cli::InteractiveTerminal::Environment interactive{
    .stdin_is_terminal = true,
    .stdout_is_terminal = true,
    .ci = false,
  };
  EXPECT_TRUE(sast::cli::InteractiveTerminal::supported("text", interactive));
  EXPECT_FALSE(sast::cli::InteractiveTerminal::supported("json", interactive));
  EXPECT_FALSE(sast::cli::InteractiveTerminal::supported("sarif", interactive));

  EXPECT_FALSE(sast::cli::InteractiveTerminal::supported(
    "text",
    {.stdin_is_terminal = true, .stdout_is_terminal = false, .ci = false}));
  EXPECT_FALSE(sast::cli::InteractiveTerminal::supported(
    "text",
    {.stdin_is_terminal = true, .stdout_is_terminal = true, .ci = true}));
}

TEST(InteractiveTerminalTest, BannerIncludesBrandingAndEngineStatus) {
  const auto banner = sast::cli::InteractiveTerminal::render_banner(
    {.connected = true, .model = "deepseek-coder:6.7b"},
    {.gateway_url = "http://127.0.0.1:8081", .gateway_timeout_seconds = 2.0, .default_model = "deepseek-coder:6.7b"});

  EXPECT_NE(banner.find("Camran Shahvali"), std::string::npos);
  EXPECT_NE(banner.find("GitHub: https://github.com/CamranShahvali"), std::string::npos);
  EXPECT_NE(banner.find("LinkedIn: https://linkedin.com/in/camran-shahvali-9409b61a6"), std::string::npos);
  EXPECT_NE(banner.find("Engine: Ready"), std::string::npos);
  EXPECT_NE(banner.find("Gateway: Connected"), std::string::npos);
  EXPECT_NE(banner.find("Model: deepseek-coder:6.7b"), std::string::npos);
}

TEST(InteractiveTerminalTest, TutorialCoversSetupTopics) {
  const auto tutorial = sast::cli::InteractiveTerminal::render_tutorial(
    {.gateway_url = "http://127.0.0.1:8081", .gateway_timeout_seconds = 2.0, .default_model = "deepseek-coder:6.7b"});

  EXPECT_NE(tutorial.find("Engine-only mode"), std::string::npos);
  EXPECT_NE(tutorial.find("Connecting local AI with Ollama"), std::string::npos);
  EXPECT_NE(tutorial.find("Recommended models"), std::string::npos);
  EXPECT_NE(tutorial.find("Starting the gateway"), std::string::npos);
  EXPECT_NE(tutorial.find("Troubleshooting LLM detection"), std::string::npos);
}

TEST(InteractiveTerminalTest, ScriptedSessionBuildsExpectedCommands) {
  const auto temp_root = std::filesystem::temp_directory_path() / "ai_sast_interactive_test";
  std::filesystem::create_directories(temp_root);
  const auto repo_root = temp_root / "repo";
  std::filesystem::create_directories(repo_root);
  const auto file_path = repo_root / "single.cpp";
  {
    std::ofstream output(file_path);
    output << "int main() { return 0; }\n";
  }

  std::istringstream input(
    "1\n" + repo_root.string() + "\n"
    "2\n" + file_path.string() + "\n"
    "4\nrepo\n" + repo_root.string() + "\n"
    "5\n2\nn\n"
    "6\n\n"
    "7\n");
  std::ostringstream output;
  std::ostringstream error;
  std::vector<std::vector<std::string>> commands;

  sast::cli::InteractiveTerminal terminal(
    input,
    output,
    error,
    [&commands](const std::vector<std::string>& args) {
      commands.push_back(args);
      if (args.size() >= 6 && args[0] == "scan" && args[3] == "--changed-files") {
        std::ifstream changed(args[4]);
        std::string line;
        std::getline(changed, line);
        EXPECT_EQ(line, "single.cpp");
      }
      return 0;
    },
    [](const sast::cli::InteractiveTerminal::Options&) {
      return sast::cli::InteractiveTerminal::GatewayStatus{
        .connected = false,
        .model = "",
      };
    });

  const auto exit_code = terminal.run({
    .gateway_url = "http://127.0.0.1:8081",
    .gateway_timeout_seconds = 2.0,
    .default_model = "deepseek-coder:6.7b",
  });

  ASSERT_EQ(exit_code, 0);
  ASSERT_EQ(commands.size(), 4u);

  EXPECT_EQ(commands[0], (std::vector<std::string>{
    "scan", "--repo", repo_root.string(), "--format", "text"}));

  EXPECT_EQ(commands[1][0], "scan");
  EXPECT_EQ(commands[1][1], "--repo");
  EXPECT_EQ(commands[1][2], repo_root.string());
  EXPECT_EQ(commands[1][3], "--changed-files");
  EXPECT_EQ(commands[1][5], "--format");
  EXPECT_EQ(commands[1][6], "text");

  EXPECT_EQ(commands[2], (std::vector<std::string>{
    "scan", "--repo", repo_root.string(), "--format", "text",
    "--llm-review", "--llm-gateway", "http://127.0.0.1:8081"}));

  EXPECT_EQ(commands[3], (std::vector<std::string>{
    "scan",
    "--repo",
    (std::filesystem::path(SAST_SOURCE_ROOT) / "tests" / "demo" / "mixed_case").string(),
    "--format",
    "text"}));

  const auto rendered = output.str();
  EXPECT_NE(rendered.find("Camran Shahvali"), std::string::npos);
  EXPECT_NE(rendered.find("1. Scan repository"), std::string::npos);
  EXPECT_NE(rendered.find("Setup & tutorials"), std::string::npos);
  EXPECT_NE(rendered.find("Exiting interactive terminal."), std::string::npos);
}

TEST(InteractiveTerminalTest, ApplicationRejectsInteractiveJsonMode) {
  const sast::cli::Application application;
  const auto exit_code = application.run({"interactive", "--format", "json"});
  EXPECT_EQ(exit_code, 2);
}

}  // namespace
