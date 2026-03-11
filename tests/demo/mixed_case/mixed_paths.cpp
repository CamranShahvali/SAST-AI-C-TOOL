#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

int run_process(const char* command) {
  return system(command);
}

std::string canonicalize_under_root(const char* path, const char* root) {
  return std::string(root) + "/" + path;
}

std::size_t choose_length(int argc) {
  return static_cast<std::size_t>(argc * 3);
}

int main(int argc, char** argv) {
  if (argc < 4) {
    return 0;
  }

  const char* command = argv[1];
  const auto safe_path = canonicalize_under_root(argv[2], "/srv/demo-root");
  const auto length = choose_length(argc);

  auto process_status = run_process(command);

  auto* file = std::fopen(safe_path.c_str(), "r");
  if (file != nullptr) {
    std::fclose(file);
  }

  char scratch[8];
  std::memcpy(scratch, argv[3], length);

  return process_status + scratch[0];
}
