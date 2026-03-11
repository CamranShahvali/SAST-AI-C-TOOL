#include <cstdlib>
#include <string>

bool is_allowed_command(const std::string& cmd) {
  return cmd == "help" || cmd == "status";
}

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  std::string cmd(argv[1]);
  if (is_allowed_command(cmd)) {
    return system(cmd.c_str());
  }
  return 0;
}

