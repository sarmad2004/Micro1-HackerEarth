// Advanced gate: structural analysis over a parsed shell AST.
// Reads JSON Lines on stdin, writes JSON Lines on stdout. See SPEC.md.

#include <iostream>

#ifdef _WIN32
// MSVC opens stdout in text mode, which rewrites every '\n' as CRLF. SPEC.md
// section 2.2 requires byte-identical output across implementations, and Rust
// writes raw LF, so the stream must be put into binary mode before any output.
#include <fcntl.h>
#include <io.h>
#endif

#include "agentgate/agentgate.hpp"

namespace {
void use_binary_stdout() {
#ifdef _WIN32
  _setmode(_fileno(stdout), _O_BINARY);
#endif
}
}  // namespace

int main() {
  use_binary_stdout();
  std::ios::sync_with_stdio(false);
  return agentgate::run_stream(std::cin, std::cout, &agentgate::analyze_advanced);
}
