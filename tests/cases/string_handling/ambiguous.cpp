#include <cstring>

int get_length(int argc);

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  char destination[8];
  std::memcpy(destination, argv[1], get_length(argc));
  return destination[0];
}

