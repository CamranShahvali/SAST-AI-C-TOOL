#include <cstdio>
#include <string>

std::string normalize_path(const char* path) {
  return std::string(path);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  const auto path = normalize_path(argv[1]);
  auto* file = std::fopen(path.c_str(), "r");
  if (file != nullptr) {
    std::fclose(file);
  }
  return 0;
}
