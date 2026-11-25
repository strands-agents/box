#pragma once
#include <map>
#include <string>

// Parses "key=value" lines. Blank lines and lines that start with '#' are skipped.
std::map<std::string, std::string> parse(const std::string& text);
