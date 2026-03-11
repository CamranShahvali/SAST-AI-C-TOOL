#include <cstdlib>

int main(int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }
  return system(argv[1]);
}
