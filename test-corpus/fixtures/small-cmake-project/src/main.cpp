#include <iostream>
#include <iterator>
#include <string>

#include "parser.h"

int main() {
  std::string text((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
  for (const auto& [key, value] : parse(text)) std::cout << key << " -> " << value << "\n";
}
