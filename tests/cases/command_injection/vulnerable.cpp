#include <cstdlib>

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  const char* cmd = argv[1];
  return system(cmd);
}

