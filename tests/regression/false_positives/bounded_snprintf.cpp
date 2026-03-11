#include <cstdio>

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  char destination[32];
  std::snprintf(destination, sizeof(destination), "%s", argv[1]);
  return destination[0];
}
