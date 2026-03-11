#include <cstdlib>
#include <string>

bool is_allowed_command(const std::string& command) {
  return command == "date" || command == "uptime";
}

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  std::string cmd = argv[1];
  if (!is_allowed_command(cmd)) {
    return 0;
  }
  return std::system(cmd.c_str());
}
