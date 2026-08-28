// agentgate - shell command safety analysis for autonomous coding agents.
//
// This is an independent implementation of the contract in SPEC.md. It must
// agree byte-for-byte with the Rust implementation under rust/ for every input;
// eval/differential.py enforces that.
//
// The two implementations are deliberately written separately rather than one
// being generated from the other, so that a mistake has to be made twice in the
// same way to escape detection.

#ifndef AGENTGATE_AGENTGATE_HPP
#define AGENTGATE_AGENTGATE_HPP

#include <cstdint>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace agentgate {

// --- Resource bounds (SPEC.md section 7) -----------------------------------

namespace limits {
constexpr std::size_t kMaxLineBytes = 1u << 20;      // 1 MiB
constexpr std::size_t kMaxCmdBytes = 256u * 1024u;
constexpr unsigned kMaxRecursionDepth = 8;
constexpr std::size_t kMaxTokens = 100000;
constexpr std::size_t kMaxB64Output = 64u * 1024u;
constexpr unsigned kMaxNestDepth = 64;
}  // namespace limits

// --- Decision lattice ------------------------------------------------------

enum class Decision { Allow = 0, Ask = 1, Deny = 2 };

// Declaration order is the spec's tie-break order: on equal severity the lower
// enumerator wins.
enum class Rule {
  ForkBomb = 0,
  ReverseShell,
  RemoteExec,
  FsDestructive,
  DeviceOverwrite,
  SystemFileWrite,
  Exfiltration,
  ContainerEscape,
  CredentialAccess,
  PrivilegeEscalation,
  PermissionWeakening,
  Persistence,
  ServiceDisruption,
  ContainerPrivilege,
  HistoryTamper,
  SystemPower,
  PkgInstall,
  GitDestructive,
  NetworkListener,
  Obfuscation,
  MalformedInput,
  ParseError,
  Ok,
};

const char* to_string(Decision d);
const char* to_string(Rule r);
Decision severity(Rule r);

struct Verdict {
  Decision decision = Decision::Allow;
  Rule rule = Rule::Ok;
  std::string detail;
};

Verdict make_allow();
Verdict make_verdict(Rule r, std::string detail);

// Accumulates findings, resolving by highest severity then lowest rule index.
class Findings {
 public:
  void add(Rule r, std::string detail);
  bool empty() const { return !has_; }
  Verdict resolve() const;

 private:
  bool has_ = false;
  Verdict best_;
};

// Serialise one JSON Lines output record with the spec's fixed key order.
std::string render_record(const std::string& id, const Verdict& v);

// --- Minimal JSON ----------------------------------------------------------

namespace json {

void escape_into(const std::string& s, std::string& out);

struct Record {
  bool has_id = false;
  bool has_cmd = false;
  std::string id;
  std::string cmd;
};

std::optional<Record> parse_record(const std::string& line);

}  // namespace json

// --- Base64 ----------------------------------------------------------------

namespace b64 {
std::optional<std::string> decode(const std::string& s);
bool looks_like_base64(const std::string& s);
}  // namespace b64

// --- Classification tables (SPEC.md section 6) ------------------------------

namespace tables {

std::string basename(const std::string& path);
bool is_interpreter(const std::string& n);
bool is_shell_interpreter(const std::string& n);
bool is_downloader(const std::string& n);
bool is_network_sink(const std::string& n);
bool is_inert(const std::string& n);
bool is_data_command(const std::string& n);
bool is_pattern_first(const std::string& n);
bool is_wrapper(const std::string& n);
bool is_priv_wrapper(const std::string& n);
bool is_package_manager(const std::string& n);
bool is_package_mutation(const std::string& n);
bool is_reserved_word(const std::string& n);
bool is_block_device(const std::string& p);
bool is_network_device(const std::string& p);
bool is_protected_path(const std::string& p);
bool is_credential_path(const std::string& p);
bool is_system_path(const std::string& p);
bool is_system_write_target(const std::string& p);
bool is_credential_dir(const std::string& p);
bool is_persistence_path(const std::string& p);
bool is_history_path(const std::string& p);
bool is_service_command(const std::string& n);
bool is_container_runtime(const std::string& n);
bool is_program_flag(const std::string& a);
bool is_find_value_flag(const std::string& a);

}  // namespace tables

// --- Lexer -----------------------------------------------------------------

struct Segment {
  enum class Kind { Lit, Var, CmdSub, Arith, ProcSub };
  Kind kind = Kind::Lit;
  // Lit: the text. Var: the name. CmdSub / ProcSub: the inner source.
  // Arith: unused.
  std::string text;
  bool quoted = false;
};

struct Word {
  std::vector<Segment> segs;
  bool quoted = false;

  // The word's text when every segment is a literal.
  std::optional<std::string> literal() const;
  bool has_expansion() const;
};

enum class RedirOp { In, Out, Append, HereString, HereDoc, DupOut, DupIn, ReadWrite, Clobber };

struct Tok {
  enum class Kind {
    Word, Semi, Amp, AndIf, OrIf, Pipe, Newline, LParen, RParen, LBrace, RBrace, Redir
  };
  Kind kind = Kind::Word;
  Word word;
  int fd = -1;  // -1 means "no explicit file descriptor"
  RedirOp op = RedirOp::In;
};

struct LexResult {
  bool ok = false;
  std::vector<Tok> toks;
  std::string error;
};

LexResult tokenize(const std::string& src);

// --- Parser ----------------------------------------------------------------

struct Redirect {
  int fd = -1;
  RedirOp op = RedirOp::In;
  Word target;
};

struct SimpleCmd {
  std::vector<std::pair<std::string, Word>> assigns;
  std::vector<Word> words;
  std::vector<Redirect> redirects;
  bool is_empty() const { return words.empty() && redirects.empty() && assigns.empty(); }
};

struct Script;

struct Cmd {
  enum class Kind { Simple, Nested, FuncDef };
  Kind kind = Kind::Simple;
  SimpleCmd simple;
  std::shared_ptr<Script> nested;  // Nested body, or FuncDef body
  std::string func_name;
};

struct Pipeline {
  std::vector<Cmd> cmds;
};

struct Script {
  std::vector<Pipeline> pipelines;
};

struct ParseResult {
  bool ok = false;
  Script script;
  std::string error;
};

ParseResult parse(const std::vector<Tok>& toks);
ParseResult parse_source(const std::string& src);

// --- Analyzers -------------------------------------------------------------

// Baseline tier: substring matching over the raw command string.
Verdict analyze_baseline(const std::string& cmd);

// Advanced tier: structural analysis over the parsed AST.
Verdict analyze_advanced(const std::string& cmd);

// --- Stream driver ---------------------------------------------------------

using Analyzer = Verdict (*)(const std::string&);

// Read JSON Lines from `in`, write verdicts to `out`. Returns a process exit
// code: 0 on success, 2 on an unusable stream.
int run_stream(std::istream& in, std::ostream& out, Analyzer analyze);

}  // namespace agentgate

#endif  // AGENTGATE_AGENTGATE_HPP
