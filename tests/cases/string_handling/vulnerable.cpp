#include <cstring>

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }

  char buffer[8];
  std::strcpy(buffer, argv[1]);
  return buffer[0];
}

