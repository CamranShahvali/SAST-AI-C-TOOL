#include <cstdio>
#include <string>

std::string canonicalize_under_root(const char* path, const char* root) {
  return std::string(root) + "/" + path;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  const auto path = canonicalize_under_root(argv[1], "/srv/demo-root");
  auto* file = std::fopen(path.c_str(), "r");
  if (file != nullptr) {
    std::fclose(file);
  }
  return 0;
}
