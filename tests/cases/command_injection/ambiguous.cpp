#include <cstdlib>

const char* normalize_command(const char* cmd);

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  const char* cmd = normalize_command(argv[1]);
  return system(cmd);
}

