// Shell tokenizer. Byte-for-byte port of rust/crates/agentgate-core/src/lexer.rs.
//
// Iteration is over bytes rather than Unicode scalars. That is safe and exactly
// equivalent here because UTF-8 never encodes an ASCII byte inside a multi-byte
// sequence, so no operator or quote character can be misread, and non-ASCII
// bytes are copied through untouched.

#include "agentgate/agentgate.hpp"

namespace agentgate {

std::optional<std::string> Word::literal() const {
  std::string s;
  for (const Segment& seg : segs) {
    if (seg.kind != Segment::Kind::Lit) return std::nullopt;
    s += seg.text;
  }
  return s;
}

bool Word::has_expansion() const {
  for (const Segment& seg : segs) {
    if (seg.kind != Segment::Kind::Lit) return true;
  }
  return false;
}

namespace {

bool is_blank(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

bool is_ascii_alpha(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool is_ascii_alnum(char c) {
  return is_ascii_alpha(c) || (c >= '0' && c <= '9');
}

bool is_ascii_digit(char c) { return c >= '0' && c <= '9'; }

// Accumulates the word currently being read.
struct WordBuf {
  std::vector<Segment> segs;
  std::string cur;
  bool started = false;
  bool quoted = false;

  void push_char(char c) {
    cur += c;
    started = true;
  }
  void push_text(const std::string& s) {
    cur += s;
    started = true;
  }
  void flush_lit() {
    if (!cur.empty()) {
      Segment s;
      s.kind = Segment::Kind::Lit;
      s.text = cur;
      segs.push_back(std::move(s));
      cur.clear();
    }
  }
  void push_seg(Segment s) {
    flush_lit();
    segs.push_back(std::move(s));
    started = true;
  }
  bool take(Word& out) {
    flush_lit();
    if (!started) {
      segs.clear();
      quoted = false;
      return false;
    }
    out.segs = std::move(segs);
    out.quoted = quoted;
    segs.clear();
    started = false;
    quoted = false;
    return true;
  }
};

struct Lexer {
  const std::string& b;
  std::size_t i = 0;
  std::size_t n;
  std::vector<Tok> toks;
  WordBuf wb;
  std::string error;

  explicit Lexer(const std::string& src) : b(src), n(src.size()) {}

  bool fail(const char* msg) {
    error = msg;
    return false;
  }

  bool flush_word() {
    Word w;
    if (wb.take(w)) {
      Tok t;
      t.kind = Tok::Kind::Word;
      t.word = std::move(w);
      toks.push_back(std::move(t));
      if (toks.size() > limits::kMaxTokens) return fail("token limit exceeded");
    }
    return true;
  }

  void push_op(Tok::Kind k) {
    Tok t;
    t.kind = k;
    toks.push_back(std::move(t));
  }

  void push_redir(int fd, RedirOp op) {
    Tok t;
    t.kind = Tok::Kind::Redir;
    t.fd = fd;
    t.op = op;
    toks.push_back(std::move(t));
  }

  // If the pending word is entirely digits, consume it as a redirect fd.
  int take_fd() {
    if (!wb.segs.empty() || wb.cur.empty() || wb.quoted) return -1;
    for (char c : wb.cur) {
      if (!is_ascii_digit(c)) return -1;
    }
    long v = 0;
    for (char c : wb.cur) {
      v = v * 10 + (c - '0');
      if (v > 2147483647L) return -1;
    }
    wb.cur.clear();
    wb.started = false;
    return static_cast<int>(v);
  }

  void read_redir_op(RedirOp& op, std::size_t& next) {
    const char c = b[i];
    auto at = [&](std::size_t k) -> int { return k < n ? b[k] : -1; };
    if (c == '>') {
      if (at(i + 1) == '>') { op = RedirOp::Append; next = i + 2; return; }
      if (at(i + 1) == '&') { op = RedirOp::DupOut; next = i + 2; return; }
      if (at(i + 1) == '|') { op = RedirOp::Clobber; next = i + 2; return; }
      op = RedirOp::Out; next = i + 1; return;
    }
    if (at(i + 1) == '<') {
      if (at(i + 2) == '<') { op = RedirOp::HereString; next = i + 3; return; }
      op = RedirOp::HereDoc; next = i + 2; return;
    }
    if (at(i + 1) == '&') { op = RedirOp::DupIn; next = i + 2; return; }
    if (at(i + 1) == '>') { op = RedirOp::ReadWrite; next = i + 2; return; }
    op = RedirOp::In; next = i + 1;
  }

  // Read a `$( ... )` body honouring nesting and quotes.
  bool read_paren_sub(std::size_t start, std::string& out, std::size_t& next) {
    int depth = 1;
    std::size_t j = start;
    out.clear();
    while (j < n) {
      const char c = b[j];
      if (c == '\\' && j + 1 < n) {
        out += c;
        out += b[j + 1];
        j += 2;
        continue;
      }
      if (c == '\'') {
        out += c;
        ++j;
        while (j < n && b[j] != '\'') { out += b[j]; ++j; }
        if (j >= n) return fail("unterminated quote in substitution");
        out += '\'';
        ++j;
        continue;
      }
      if (c == '"') {
        out += c;
        ++j;
        while (j < n && b[j] != '"') {
          if (b[j] == '\\' && j + 1 < n) { out += b[j]; ++j; }
          out += b[j];
          ++j;
        }
        if (j >= n) return fail("unterminated quote in substitution");
        out += '"';
        ++j;
        continue;
      }
      if (c == '(') ++depth;
      else if (c == ')') {
        --depth;
        if (depth == 0) { next = j + 1; return true; }
      }
      out += c;
      ++j;
    }
    return fail("unterminated command substitution");
  }

  bool read_backtick(std::size_t start, std::string& out, std::size_t& next) {
    std::size_t j = start;
    out.clear();
    while (j < n) {
      if (b[j] == '\\' && j + 1 < n) { out += b[j + 1]; j += 2; continue; }
      if (b[j] == '`') { next = j + 1; return true; }
      out += b[j];
      ++j;
    }
    return fail("unterminated backtick substitution");
  }

  // Lex a `$`-expansion. `handled` is false when the `$` is a literal.
  bool lex_dollar(std::size_t at, bool quoted, bool& handled, std::size_t& next) {
    handled = false;
    if (at + 1 >= n) return true;
    const char c1 = b[at + 1];

    if (c1 == '(' && at + 2 < n && b[at + 2] == '(') {
      int depth = 1;
      std::size_t j = at + 3;
      while (j < n) {
        if (b[j] == '(') ++depth;
        else if (b[j] == ')') {
          --depth;
          if (depth == 0 && j + 1 < n && b[j + 1] == ')') {
            Segment s;
            s.kind = Segment::Kind::Arith;
            s.quoted = quoted;
            wb.push_seg(std::move(s));
            handled = true;
            next = j + 2;
            return true;
          }
        }
        ++j;
      }
      return fail("unterminated arithmetic expansion");
    }

    if (c1 == '(') {
      std::string src;
      std::size_t after = 0;
      if (!read_paren_sub(at + 2, src, after)) return false;
      Segment s;
      s.kind = Segment::Kind::CmdSub;
      s.text = src;
      s.quoted = quoted;
      wb.push_seg(std::move(s));
      handled = true;
      next = after;
      return true;
    }

    if (c1 == '{') {
      std::size_t j = at + 2;
      std::string name;
      while (j < n && b[j] != '}') { name += b[j]; ++j; }
      if (j >= n) return fail("unterminated parameter expansion");
      Segment s;
      s.kind = Segment::Kind::Var;
      s.text = name;
      s.quoted = quoted;
      wb.push_seg(std::move(s));
      handled = true;
      next = j + 1;
      return true;
    }

    if (is_ascii_alpha(c1) || c1 == '_') {
      std::size_t j = at + 1;
      std::string name;
      while (j < n && (is_ascii_alnum(b[j]) || b[j] == '_')) { name += b[j]; ++j; }
      Segment s;
      s.kind = Segment::Kind::Var;
      s.text = name;
      s.quoted = quoted;
      wb.push_seg(std::move(s));
      handled = true;
      next = j;
      return true;
    }

    if (c1 == '?' || c1 == '$' || c1 == '!' || c1 == '@' || c1 == '*' || c1 == '#' ||
        is_ascii_digit(c1)) {
      Segment s;
      s.kind = Segment::Kind::Var;
      s.text = std::string(1, c1);
      s.quoted = quoted;
      wb.push_seg(std::move(s));
      handled = true;
      next = at + 2;
      return true;
    }

    return true;  // literal `$`
  }

  bool lex_double_quoted(std::size_t start, std::size_t& next) {
    std::size_t j = start;
    wb.started = true;
    for (;;) {
      if (j >= n) return fail("unterminated double quote");
      const char c = b[j];
      if (c == '"') { next = j + 1; return true; }
      if (c == '\\') {
        if (j + 1 >= n) return fail("unterminated double quote");
        const char e = b[j + 1];
        if (e == '"' || e == '\\' || e == '$' || e == '`' || e == '\n') {
          if (e != '\n') wb.push_char(e);
          j += 2;
          continue;
        }
        wb.push_char('\\');
        ++j;
        continue;
      }
      if (c == '`') {
        std::string src;
        std::size_t after = 0;
        if (!read_backtick(j + 1, src, after)) return false;
        Segment s;
        s.kind = Segment::Kind::CmdSub;
        s.text = src;
        s.quoted = true;
        wb.push_seg(std::move(s));
        j = after;
        continue;
      }
      if (c == '$') {
        bool handled = false;
        std::size_t after = 0;
        if (!lex_dollar(j, true, handled, after)) return false;
        if (handled) { j = after; continue; }
        wb.push_char('$');
        ++j;
        continue;
      }
      wb.push_char(c);
      ++j;
    }
  }

  bool run() {
    while (i < n) {
      const char c = b[i];

      if (c == '#' && !wb.started) {
        while (i < n && b[i] != '\n') ++i;
        continue;
      }

      if (c == '\n') {
        if (!flush_word()) return false;
        push_op(Tok::Kind::Newline);
        ++i;
        continue;
      }

      if (c == ' ' || c == '\t' || c == '\r') {
        if (!flush_word()) return false;
        ++i;
        continue;
      }

      if (c == '\\' && i + 1 < n && b[i + 1] == '\n') { i += 2; continue; }

      if (c == '\\') {
        if (i + 1 >= n) return fail("trailing backslash");
        wb.push_char(b[i + 1]);
        wb.quoted = true;
        i += 2;
        continue;
      }

      if (c == '\'') {
        std::size_t j = i + 1;
        std::string s;
        for (;;) {
          if (j >= n) return fail("unterminated single quote");
          if (b[j] == '\'') break;
          s += b[j];
          ++j;
        }
        wb.push_text(s);
        wb.started = true;
        wb.quoted = true;
        i = j + 1;
        continue;
      }

      if (c == '"') {
        std::size_t after = 0;
        if (!lex_double_quoted(i + 1, after)) return false;
        wb.quoted = true;
        i = after;
        continue;
      }

      if (c == '`') {
        std::string src;
        std::size_t after = 0;
        if (!read_backtick(i + 1, src, after)) return false;
        Segment s;
        s.kind = Segment::Kind::CmdSub;
        s.text = src;
        s.quoted = false;
        wb.push_seg(std::move(s));
        i = after;
        continue;
      }

      if (c == '$') {
        bool handled = false;
        std::size_t after = 0;
        if (!lex_dollar(i, false, handled, after)) return false;
        if (handled) { i = after; continue; }
        wb.push_char('$');
        ++i;
        continue;
      }

      // Process substitution `<( … )` / `>( … )` is a word, not a redirect:
      // the shell replaces it with a /dev/fd path and runs the inner command.
      if ((c == '<' || c == '>') && i + 1 < n && b[i + 1] == '(') {
        std::string src;
        std::size_t after = 0;
        if (!read_paren_sub(i + 2, src, after)) return false;
        Segment s;
        s.kind = Segment::Kind::ProcSub;
        s.text = src;
        wb.push_seg(std::move(s));
        i = after;
        continue;
      }

      if (c == '<' || c == '>') {
        const int fd = take_fd();
        if (fd < 0) {
          if (!flush_word()) return false;
        }
        RedirOp op = RedirOp::In;
        std::size_t after = 0;
        read_redir_op(op, after);
        push_redir(fd, op);
        i = after;
        continue;
      }

      if (c == '&') {
        if (i + 1 < n && b[i + 1] == '>') {
          if (!flush_word()) return false;
          std::size_t after = i + 2;
          if (after < n && b[after] == '>') ++after;
          push_redir(-1, RedirOp::DupOut);
          i = after;
          continue;
        }
        if (!flush_word()) return false;
        if (i + 1 < n && b[i + 1] == '&') { push_op(Tok::Kind::AndIf); i += 2; }
        else { push_op(Tok::Kind::Amp); ++i; }
        continue;
      }

      if (c == '|') {
        if (!flush_word()) return false;
        if (i + 1 < n && b[i + 1] == '|') { push_op(Tok::Kind::OrIf); i += 2; }
        else { push_op(Tok::Kind::Pipe); ++i; }
        continue;
      }

      if (c == ';') {
        if (!flush_word()) return false;
        push_op(Tok::Kind::Semi);
        ++i;
        continue;
      }

      if (c == '(') {
        if (!flush_word()) return false;
        push_op(Tok::Kind::LParen);
        ++i;
        continue;
      }

      if (c == ')') {
        if (!flush_word()) return false;
        push_op(Tok::Kind::RParen);
        ++i;
        continue;
      }

      // `{`/`}` are operators only when they stand alone, so brace expansion
      // like `file{1,2}.txt` remains a single word.
      if (c == '{' && !wb.started && i + 1 < n && is_blank(b[i + 1])) {
        push_op(Tok::Kind::LBrace);
        ++i;
        continue;
      }
      if (c == '}' && !wb.started) {
        const bool follows_end =
            i + 1 >= n || is_blank(b[i + 1]) || b[i + 1] == ';' || b[i + 1] == '&' ||
            b[i + 1] == ')' || b[i + 1] == '|';
        if (follows_end) {
          push_op(Tok::Kind::RBrace);
          ++i;
          continue;
        }
      }

      wb.push_char(c);
      ++i;
    }
    return flush_word();
  }
};

}  // namespace

LexResult tokenize(const std::string& src) {
  LexResult r;
  if (src.size() > limits::kMaxCmdBytes) {
    r.ok = false;
    r.error = "command exceeds maximum length";
    return r;
  }
  Lexer lx(src);
  if (!lx.run()) {
    r.ok = false;
    r.error = lx.error;
    return r;
  }
  r.ok = true;
  r.toks = std::move(lx.toks);
  return r;
}

}  // namespace agentgate
