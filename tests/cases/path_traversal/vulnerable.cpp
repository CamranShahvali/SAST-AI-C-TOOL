#include <cstdio>

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  const char* path = argv[1];
  auto* file = fopen(path, "r");
  if (file != nullptr) {
    fclose(file);
  }
  return 0;
}

