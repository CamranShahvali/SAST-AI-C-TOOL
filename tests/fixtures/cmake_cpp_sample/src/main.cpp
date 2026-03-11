#include "sample/helpers.hpp"

#include <string>

int main(int argc, char** argv) {
  std::string name = argc > 1 ? argv[1] : "world";
  std::string message = sample::make_message(name);
  sample::print_message(message);
  return 0;
}
