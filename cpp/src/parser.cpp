// AST construction. Port of rust/crates/agentgate-core/src/parser.rs.

#include "agentgate/agentgate.hpp"

namespace agentgate {
namespace {

struct Parser {
  const std::vector<Tok>& t;
  std::size_t i = 0;
  std::string error;

  explicit Parser(const std::vector<Tok>& toks) : t(toks) {}

  bool fail(const char* msg) {
    if (error.empty()) error = msg;
    return false;
  }

  bool eof() const { return i >= t.size(); }
  const Tok* peek() const { return eof() ? nullptr : &t[i]; }
  const Tok* at(std::size_t k) const { return k < t.size() ? &t[k] : nullptr; }

  bool at_separator() const {
    const Tok* p = peek();
    if (p == nullptr) return false;
    return p->kind == Tok::Kind::Semi || p->kind == Tok::Kind::Amp ||
           p->kind == Tok::Kind::Newline || p->kind == Tok::Kind::AndIf ||
           p->kind == Tok::Kind::OrIf;
  }

  void skip_newlines() {
    while (!eof() && t[i].kind == Tok::Kind::Newline) ++i;
  }

  bool at_stop(bool has_stop, Tok::Kind stop) const {
    if (!has_stop) return false;
    const Tok* p = peek();
    return p != nullptr && p->kind == stop;
  }

  // NAME=value at the head of a word.
  static bool try_split_assignment(const Word& w, std::string& name, Word& value) {
    if (w.segs.empty()) return false;
    if (w.segs[0].kind != Segment::Kind::Lit) return false;
    const std::string& first = w.segs[0].text;
    const std::size_t eq = first.find('=');
    if (eq == std::string::npos || eq == 0) return false;
    const std::string candidate = first.substr(0, eq);
    const char c0 = candidate[0];
    const bool alpha = (c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') || c0 == '_';
    if (!alpha) return false;
    for (std::size_t k = 1; k < candidate.size(); ++k) {
      const char c = candidate[k];
      const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '_';
      if (!ok) return false;
    }
    name = candidate;
    value.segs.clear();
    value.quoted = w.quoted;
    const std::string rest = first.substr(eq + 1);
    if (!rest.empty()) {
      Segment s;
      s.kind = Segment::Kind::Lit;
      s.text = rest;
      value.segs.push_back(std::move(s));
    }
    for (std::size_t k = 1; k < w.segs.size(); ++k) value.segs.push_back(w.segs[k]);
    return true;
  }

  static bool is_reserved(const Word& w) {
    auto lit = w.literal();
    return lit.has_value() && tables::is_reserved_word(*lit);
  }

  bool parse_script(unsigned depth, bool has_stop, Tok::Kind stop, Script& out) {
    if (depth > limits::kMaxNestDepth) return fail("nesting too deep");
    for (;;) {
      skip_newlines();
      if (eof() || at_stop(has_stop, stop)) break;

      Pipeline pl;
      if (!parse_pipeline(depth, pl)) return false;
      if (pl.cmds.empty()) return fail("empty command");
      out.pipelines.push_back(std::move(pl));

      if (at_separator()) { ++i; continue; }
      if (eof() || at_stop(has_stop, stop)) break;
      return fail("unexpected token after command");
    }
    return true;
  }

  bool parse_pipeline(unsigned depth, Pipeline& out) {
    for (;;) {
      Cmd c;
      bool produced = false;
      if (!parse_command(depth, c, produced)) return false;
      if (!produced) {
        if (!out.cmds.empty()) return fail("empty pipeline stage");
        return true;
      }
      out.cmds.push_back(std::move(c));
      if (!eof() && t[i].kind == Tok::Kind::Pipe) {
        ++i;
        skip_newlines();
        continue;
      }
      return true;
    }
  }

  bool parse_command(unsigned depth, Cmd& out, bool& produced) {
    produced = false;
    const Tok* p = peek();
    if (p != nullptr && (p->kind == Tok::Kind::LParen || p->kind == Tok::Kind::LBrace)) {
      const bool paren = p->kind == Tok::Kind::LParen;
      ++i;
      auto inner = std::make_shared<Script>();
      if (!parse_script(depth + 1, true, paren ? Tok::Kind::RParen : Tok::Kind::RBrace, *inner)) {
        return false;
      }
      const Tok* closer = peek();
      if (closer == nullptr ||
          closer->kind != (paren ? Tok::Kind::RParen : Tok::Kind::RBrace)) {
        return fail(paren ? "unclosed subshell" : "unclosed brace group");
      }
      ++i;
      out.kind = Cmd::Kind::Nested;
      out.nested = inner;
      produced = true;
      return true;
    }
    return parse_simple(depth, out, produced);
  }

  bool parse_simple(unsigned depth, Cmd& out, bool& produced) {
    SimpleCmd cmd;
    bool saw_any = false;

    for (;;) {
      const Tok* p = peek();
      if (p == nullptr) break;

      if (p->kind == Tok::Kind::Word) {
        // Function definition: NAME ( ) body
        const Tok* n1 = at(i + 1);
        const Tok* n2 = at(i + 2);
        if (cmd.words.empty() && n1 != nullptr && n1->kind == Tok::Kind::LParen &&
            n2 != nullptr && n2->kind == Tok::Kind::RParen) {
          auto lit = p->word.literal();
          if (!lit.has_value()) return fail("dynamic function name");
          const std::string name = *lit;
          i += 3;
          skip_newlines();
          Cmd body_cmd;
          bool body_produced = false;
          if (!parse_command(depth + 1, body_cmd, body_produced)) return false;
          if (!body_produced) return fail("function without a body");
          auto body = std::make_shared<Script>();
          if (body_cmd.kind == Cmd::Kind::Nested) {
            body = body_cmd.nested;
          } else {
            Pipeline pl;
            pl.cmds.push_back(std::move(body_cmd));
            body->pipelines.push_back(std::move(pl));
          }
          out.kind = Cmd::Kind::FuncDef;
          out.func_name = name;
          out.nested = body;
          produced = true;
          return true;
        }

        if (cmd.words.empty() && is_reserved(p->word)) {
          ++i;
          saw_any = true;
          continue;
        }

        if (cmd.words.empty()) {
          std::string name;
          Word value;
          if (try_split_assignment(p->word, name, value)) {
            cmd.assigns.emplace_back(name, value);
            ++i;
            saw_any = true;
            continue;
          }
        }

        cmd.words.push_back(p->word);
        ++i;
        saw_any = true;
        continue;
      }

      if (p->kind == Tok::Kind::Redir) {
        Redirect rd;
        rd.fd = p->fd;
        rd.op = p->op;
        ++i;
        const Tok* target = peek();
        if (target == nullptr || target->kind != Tok::Kind::Word) {
          return fail("redirection without a target");
        }
        rd.target = target->word;
        ++i;
        cmd.redirects.push_back(std::move(rd));
        saw_any = true;
        continue;
      }

      break;
    }

    if (!saw_any) return true;
    out.kind = Cmd::Kind::Simple;
    out.simple = std::move(cmd);
    produced = true;
    return true;
  }
};

}  // namespace

ParseResult parse(const std::vector<Tok>& toks) {
  ParseResult r;
  Parser p(toks);
  if (!p.parse_script(0, false, Tok::Kind::Word, r.script)) {
    r.ok = false;
    r.error = p.error;
    return r;
  }
  if (p.i < toks.size()) {
    r.ok = false;
    r.error = "unexpected trailing token";
    return r;
  }
  r.ok = true;
  return r;
}

ParseResult parse_source(const std::string& src) {
  LexResult lex = tokenize(src);
  if (!lex.ok) {
    ParseResult r;
    r.ok = false;
    r.error = lex.error;
    return r;
  }
  return parse(lex.toks);
}

}  // namespace agentgate
