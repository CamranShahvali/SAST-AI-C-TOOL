#include <cstdlib>

int run_process(const char* cmd) {
  return std::system(cmd);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }
  return run_process(argv[1]);
}
