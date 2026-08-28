// JSON Lines driver shared by both binaries.
// Port of rust/crates/agentgate-core/src/stream.rs.

#include "agentgate/agentgate.hpp"

#include <istream>
#include <ostream>
#include <string>

namespace agentgate {
namespace {

// Matches Rust's `u8::is_ascii_whitespace`, which excludes the vertical tab.
bool is_ascii_ws(unsigned char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == 0x0c || c == '\r';
}

bool valid_utf8(const std::string& s) {
  std::size_t i = 0;
  const std::size_t n = s.size();
  while (i < n) {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    std::size_t len;
    unsigned cp;
    if (c < 0x80) { ++i; continue; }
    else if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1Fu; }
    else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0Fu; }
    else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07u; }
    else return false;
    if (i + len > n) return false;
    for (std::size_t k = 1; k < len; ++k) {
      const unsigned char cc = static_cast<unsigned char>(s[i + k]);
      if ((cc & 0xC0) != 0x80) return false;
      cp = (cp << 6) | (cc & 0x3Fu);
    }
    if (len == 2 && cp < 0x80) return false;
    if (len == 3 && cp < 0x800) return false;
    if (len == 4 && cp < 0x10000) return false;
    if (cp > 0x10FFFF) return false;
    if (cp >= 0xD800 && cp <= 0xDFFF) return false;
    i += len;
  }
  return true;
}

void emit(std::ostream& out, const std::string& id, const Verdict& v) {
  out << render_record(id, v) << '\n';
}

}  // namespace

int run_stream(std::istream& in, std::ostream& out, Analyzer analyze) {
  std::string raw;
  unsigned long long lineno = 0;

  while (std::getline(in, raw)) {
    ++lineno;
    // getline strips the '\n'; a CRLF stream leaves the '\r'.
    while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r')) raw.pop_back();

    bool all_ws = true;
    for (char rc : raw) {
      const unsigned char c = static_cast<unsigned char>(rc);
      if (!is_ascii_ws(c)) { all_ws = false; break; }
    }
    if (all_ws) continue;

    const std::string fallback_id = std::to_string(lineno);

    if (raw.size() > limits::kMaxLineBytes) {
      emit(out, fallback_id,
           make_verdict(Rule::MalformedInput, "input line exceeds maximum length"));
      continue;
    }
    if (!valid_utf8(raw)) {
      emit(out, fallback_id,
           make_verdict(Rule::MalformedInput, "input line is not valid UTF-8"));
      continue;
    }

    auto rec = json::parse_record(raw);
    if (!rec.has_value()) {
      emit(out, fallback_id, make_verdict(Rule::MalformedInput, "line is not a JSON object"));
      continue;
    }

    const std::string id = rec->has_id ? rec->id : fallback_id;
    if (!rec->has_cmd) {
      emit(out, id, make_verdict(Rule::MalformedInput, "record has no \"cmd\" field"));
      continue;
    }
    emit(out, id, analyze(rec->cmd));
  }

  if (in.bad()) return 2;
  out.flush();
  return out.good() ? 0 : 2;
}

}  // namespace agentgate
