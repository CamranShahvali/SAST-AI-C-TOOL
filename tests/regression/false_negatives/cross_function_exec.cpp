#include <cstdlib>

int run_process(const char* cmd) {
  return std::system(cmd);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  const char* cmd = argv[1];
  return run_process(cmd);
}
