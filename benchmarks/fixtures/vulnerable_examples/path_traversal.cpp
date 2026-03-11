#include <cstdio>

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  auto* file = std::fopen(argv[1], "r");
  if (file != nullptr) {
    std::fclose(file);
  }
  return 0;
}
