#include <cstdlib>

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  const char* cmd = argv[1];
  // sast-ignore-next-line command_injection.system
  return system(cmd);
}

