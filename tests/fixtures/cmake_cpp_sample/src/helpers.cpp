#include "sample/helpers.hpp"

#include <iostream>
#include <string>

namespace sample {

std::string make_message(const std::string& name) {
  std::string prefix = "hello, ";
  return prefix + name;
}

void print_message(const std::string& message) {
  std::cout << message << '\n';
}

}  // namespace sample

