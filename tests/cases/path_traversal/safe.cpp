#include <cstdio>
#include <string>

bool is_safe_path(const std::string& path) {
  return path.find("..") == std::string::npos;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  std::string path(argv[1]);
  if (is_safe_path(path)) {
    auto* file = fopen(path.c_str(), "r");
    if (file != nullptr) {
      fclose(file);
    }
  }
  return 0;
}

