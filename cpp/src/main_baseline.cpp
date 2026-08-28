// Baseline gate: substring matching over the raw command string.
// Reads JSON Lines on stdin, writes JSON Lines on stdout. See SPEC.md.

#include <iostream>

#include "agentgate/agentgate.hpp"

int main() {
  std::ios::sync_with_stdio(false);
  return agentgate::run_stream(std::cin, std::cout, &agentgate::analyze_baseline);
}
