#include <cstddef>
#include <cstring>

std::size_t get_length(int argc) {
  return static_cast<std::size_t>(argc * 8);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  char destination[8];
  const auto length = get_length(argc);
  std::memcpy(destination, argv[1], length);
  return destination[0];
}
