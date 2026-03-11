#include <cstdio>

const char* normalize_path(const char* path);

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  auto* file = fopen(normalize_path(argv[1]), "r");
  if (file != nullptr) {
    fclose(file);
  }
  return 0;
}

