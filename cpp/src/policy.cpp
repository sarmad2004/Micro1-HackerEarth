// Advanced tier: structural analysis over the parsed AST.
// Port of rust/crates/agentgate-core/src/policy.rs.
//
// Detail strings are reproduced exactly, including Rust's `{:?}` quoting where
// it is used, because eval/differential.py compares whole output lines.

#include "agentgate/agentgate.hpp"

#include <cstring>
#include <map>
#include <set>
#include <utility>

namespace agentgate {
namespace {

struct Ctx {
  std::map<std::string, std::string> env;
  std::set<std::string> tainted;

  Ctx() {
    // `${IFS}` defaults to whitespace, which is exactly what makes it an
    // evasion: `rm${IFS}-rf` field-splits back into `rm -rf`.
    env["IFS"] = " ";
    // The real home directory is unknowable here, but `~` denotes it and is
    // already classified as protected.
    env["HOME"] = "~";
  }
};

struct RedirView {
  RedirOp op = RedirOp::In;
  std::string target;
  bool resolved = false;
};

struct RCmd {
  std::vector<std::string> argv;
  bool name_unresolved = false;
  bool arg_unresolved = false;
  std::vector<RedirView> redirs;
  // Inner sources of any `<(...)` / `>(...)` arguments. These run.
  std::vector<std::string> proc_subs;
  // Every substitution body in the command, including `$(...)` and backticks.
  // All of them execute, so all of them are analyzed.
  std::vector<std::string> subs;
};

struct Unwrapped {
  bool has_name = false;
  std::string name;
  std::vector<std::string> args;
  bool privileged = false;
  std::string priv_name;
};

void walk_script(const Script& s, Ctx& ctx, Findings& f, unsigned depth);
void analyze_nested(const std::string& src, Ctx& ctx, Findings& f, unsigned depth);
bool expand(const Word& w, const Ctx& ctx, unsigned depth, std::vector<std::string>& fields);

bool is_field_sep(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0x0b || c == 0x0c;
}

bool starts_with(const std::string& s, const std::string& p) {
  return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

// --- Expansion -------------------------------------------------------------

// Resolve a command substitution when its result is statically knowable.
// Only `echo`/`printf` of literal arguments qualifies; anything else stays
// unresolved, which escalates rather than guesses.
bool try_resolve_cmdsub(const std::string& src, const Ctx& ctx, unsigned depth, std::string& out) {
  if (depth >= limits::kMaxRecursionDepth) return false;
  ParseResult pr = parse_source(src);
  if (!pr.ok) return false;
  if (pr.script.pipelines.size() != 1 || pr.script.pipelines[0].cmds.size() != 1) return false;
  const Cmd& c = pr.script.pipelines[0].cmds[0];
  if (c.kind != Cmd::Kind::Simple) return false;
  if (c.simple.words.empty()) return false;
  auto head = c.simple.words[0].literal();
  if (!head.has_value()) return false;
  const std::string name = tables::basename(*head);
  if (name != "echo" && name != "printf") return false;

  std::vector<std::string> parts;
  for (std::size_t k = 1; k < c.simple.words.size(); ++k) {
    std::vector<std::string> fields;
    if (!expand(c.simple.words[k], ctx, depth + 1, fields)) return false;
    for (auto& fld : fields) parts.push_back(std::move(fld));
  }
  out.clear();
  for (std::size_t k = 0; k < parts.size(); ++k) {
    if (k > 0) out += ' ';
    out += parts[k];
  }
  return true;
}

// Expand a word into fields with constant propagation and field splitting.
// Returns true when every segment resolved.
bool expand(const Word& w, const Ctx& ctx, unsigned depth, std::vector<std::string>& fields) {
  std::vector<std::pair<std::string, bool>> pieces;  // (text, splittable)
  bool resolved = true;

  for (const Segment& seg : w.segs) {
    switch (seg.kind) {
      case Segment::Kind::Lit:
        pieces.emplace_back(seg.text, false);
        break;
      case Segment::Kind::Var: {
        auto it = ctx.env.find(seg.text);
        if (it == ctx.env.end()) {
          resolved = false;
        } else {
          pieces.emplace_back(it->second, !seg.quoted);
        }
        break;
      }
      case Segment::Kind::CmdSub: {
        std::string v;
        if (try_resolve_cmdsub(seg.text, ctx, depth, v)) {
          pieces.emplace_back(v, !seg.quoted);
        } else {
          resolved = false;
        }
        break;
      }
      case Segment::Kind::Arith:
        // Arithmetic expansion always yields a number, which cannot become a
        // dangerous path or command name; a fixed stand-in is sound.
        pieces.emplace_back("0", false);
        break;
      case Segment::Kind::ProcSub:
        // The shell substitutes a /dev/fd path; the inner command is analyzed
        // separately by the caller.
        pieces.emplace_back("/dev/fd/63", false);
        break;
    }
  }

  fields.clear();
  std::string cur;
  auto flush = [&]() {
    if (!cur.empty()) {
      fields.push_back(cur);
      cur.clear();
    }
  };
  for (const auto& piece : pieces) {
    const std::string& text = piece.first;
    if (!piece.second) {
      cur += text;
      continue;
    }
    const bool lead = !text.empty() && is_field_sep(text.front());
    const bool trail = !text.empty() && is_field_sep(text.back());
    std::vector<std::string> parts;
    std::string acc;
    for (char c : text) {
      if (is_field_sep(c)) {
        if (!acc.empty()) { parts.push_back(acc); acc.clear(); }
      } else {
        acc += c;
      }
    }
    if (!acc.empty()) parts.push_back(acc);

    if (lead) flush();
    for (std::size_t k = 0; k < parts.size(); ++k) {
      if (k > 0) flush();
      cur += parts[k];
    }
    if (trail) flush();
  }
  flush();
  if (fields.empty() && w.quoted) fields.push_back(std::string());
  return resolved;
}

// The command name of the first simple command in `src`, when it is literal.
bool first_command_name(const std::string& src, std::string& out) {
  ParseResult pr = parse_source(src);
  if (!pr.ok || pr.script.pipelines.empty()) return false;
  for (const Cmd& c : pr.script.pipelines[0].cmds) {
    if (c.kind != Cmd::Kind::Simple || c.simple.words.empty()) continue;
    auto lit = c.simple.words[0].literal();
    if (lit.has_value()) {
      out = tables::basename(*lit);
      return true;
    }
  }
  return false;
}

// Every command name appearing anywhere in `src`, for pipeline-shape checks.
std::vector<std::string> all_command_names(const std::string& src) {
  std::vector<std::string> out;
  ParseResult pr = parse_source(src);
  if (!pr.ok) return out;
  for (const Pipeline& pl : pr.script.pipelines) {
    for (const Cmd& c : pl.cmds) {
      if (c.kind != Cmd::Kind::Simple || c.simple.words.empty()) continue;
      auto lit = c.simple.words[0].literal();
      if (lit.has_value()) out.push_back(tables::basename(*lit));
    }
  }
  return out;
}

// --- Helpers ---------------------------------------------------------------

// Strip wrapper commands to reach the command that actually runs. Only the
// command position is inspected, so `grep -rn "sudo" …` is not misread as a
// privileged invocation.
Unwrapped unwrap_command(const std::vector<std::string>& argv) {
  Unwrapped u;
  std::size_t i = 0;
  unsigned guard = 0;
  while (i < argv.size()) {
    if (++guard > 16) break;
    const std::string name = tables::basename(argv[i]);
    if (!tables::is_wrapper(name) && name != "pkexec") break;
    if (tables::is_priv_wrapper(name) || name == "pkexec") {
      u.privileged = true;
      u.priv_name = name;
    }
    ++i;
    while (i < argv.size() && !argv[i].empty() && argv[i][0] == '-' && argv[i] != "--") {
      const bool takes_value = argv[i] == "-u" || argv[i] == "--user" || argv[i] == "-g" ||
                               argv[i] == "--group" || argv[i] == "-U";
      ++i;
      if (takes_value && i < argv.size()) ++i;
    }
    if (i < argv.size() && argv[i] == "--") ++i;
    if (name == "env") {
      while (i < argv.size() && argv[i].find('=') != std::string::npos) ++i;
    }
    if (name == "timeout" && i < argv.size() && !argv[i].empty() && argv[i][0] >= '0' &&
        argv[i][0] <= '9') {
      ++i;
    }
  }
  if (i >= argv.size()) return u;
  u.has_name = true;
  u.name = tables::basename(argv[i]);
  for (std::size_t k = i + 1; k < argv.size(); ++k) u.args.push_back(argv[k]);
  return u;
}

// Operands that name filesystem paths.
std::vector<std::string> operand_paths(const std::string& name,
                                       const std::vector<std::string>& args) {
  std::vector<std::string> out;
  if (tables::is_data_command(name)) return out;
  bool skip_first = tables::is_pattern_first(name);
  const bool is_find = name == "find";
  const bool git_message =
      name == "git" && !args.empty() &&
      (args[0] == "commit" || args[0] == "tag" || args[0] == "merge" || args[0] == "notes" ||
       args[0] == "stash");
  std::size_t i = 0;
  while (i < args.size()) {
    const std::string& a = args[i];
    if (a == "--") { ++i; continue; }
    if (!a.empty() && a[0] == '-') {
      if (git_message && (a == "-m" || a == "--message" || a == "-F" || a == "--file")) {
        i += 2;
        continue;
      }
      // `find -name '*.key'` names a glob, not a file on disk.
      if (is_find && tables::is_find_value_flag(a)) {
        i += 2;
        continue;
      }
      ++i;
      continue;
    }
    if (skip_first) { skip_first = false; ++i; continue; }
    out.push_back(a);
    ++i;
  }
  return out;
}

void flags_of(const std::vector<std::string>& args, std::set<char>& shortf,
              std::set<std::string>& longf) {
  for (const std::string& a : args) {
    if (a == "--") break;
    if (starts_with(a, "--")) {
      const std::string rest = a.substr(2);
      if (!rest.empty()) longf.insert(rest);
    } else if (!a.empty() && a[0] == '-') {
      for (std::size_t k = 1; k < a.size(); ++k) shortf.insert(a[k]);
    }
  }
}

bool is_decode_flag(const std::string& a) {
  if (a == "-d" || a == "-D" || a == "--decode") return true;
  return !a.empty() && a[0] == '-' && !starts_with(a, "--") &&
         a.find('d') != std::string::npos;
}

bool is_world_writable_mode(const std::string& a) {
  if (!a.empty() && a[0] == '-') return false;
  bool all_digits = a.size() >= 3;
  for (char c : a) {
    if (c < '0' || c > '9') { all_digits = false; break; }
  }
  if (all_digits) {
    const char last = a.back();
    if (last >= '0' && last <= '7' && ((last - '0') & 2) != 0) return true;
  }
  const bool symbolic = a.find("a+") != std::string::npos ||
                        a.find("o+") != std::string::npos ||
                        a.find("ugo+") != std::string::npos;
  if (!symbolic) return false;
  const std::size_t plus = a.find('+');
  if (plus == std::string::npos) return false;
  const std::size_t next_plus = a.find('+', plus + 1);
  const std::string part = a.substr(plus + 1, next_plus == std::string::npos
                                                  ? std::string::npos
                                                  : next_plus - plus - 1);
  return part.find('w') != std::string::npos;
}

// The inline program passed to an interpreter, when it is a literal.
//
// Covers `-c` (sh, python), `-e` / `--eval` (perl, ruby, node) and clustered
// short flags ending in `c`. Missing `-e` was the single largest source of
// held-out misses in v1.0.
bool program_payload(const std::vector<std::string>& args, std::string& out) {
  for (std::size_t i = 0; i < args.size(); ++i) {
    const std::string& a = args[i];
    if (tables::is_program_flag(a)) {
      if (i + 1 < args.size()) { out = args[i + 1]; return true; }
      return false;
    }
    if (a.size() > 1 && a[0] == '-' && !starts_with(a, "--")) {
      const char last = a.back();
      if (last == 'c' || last == 'e') {
        if (i + 1 < args.size()) { out = args[i + 1]; return true; }
        return false;
      }
    }
  }
  return false;
}

// Read a single- or double-quoted string at the start of `s`.
bool read_quoted(const std::string& s, std::string& out) {
  if (s.empty()) return false;
  const char q = s[0];
  if (q != '\'' && q != '"') return false;
  out.clear();
  bool escaped = false;
  for (std::size_t i = 1; i < s.size(); ++i) {
    const char c = s[i];
    if (escaped) { out += c; escaped = false; continue; }
    if (c == '\\') { escaped = true; continue; }
    if (c == q) return true;
    out += c;
  }
  return false;
}

// Pull shell command strings out of a non-shell interpreter payload.
std::vector<std::string> extract_embedded_shell(const std::string& payload) {
  static const char* const kCalls[] = {
      "os.system(", "os.popen(", "subprocess.call(", "subprocess.run(",
      "subprocess.Popen(", "subprocess.check_output(", "commands.getoutput(",
      "exec(", "execSync(", "spawnSync(", "child_process.exec(",
      "child_process.execSync(", "system(", "qx(", "popen(", "IO.popen(",
      "Kernel.system("};
  std::vector<std::string> out;
  for (const char* call : kCalls) {
    const std::size_t call_len = std::strlen(call);
    std::size_t from = 0;
    for (;;) {
      const std::size_t pos = payload.find(call, from);
      if (pos == std::string::npos) break;
      const std::size_t start = pos + call_len;
      std::string s;
      if (start <= payload.size() && read_quoted(payload.substr(start), s)) out.push_back(s);
      from = start;
      if (from >= payload.size()) break;
    }
  }
  return out;
}

// --- Rule application ------------------------------------------------------

// Commands that stop services, flush firewalls or remount filesystems.
void service_rules(const std::string& name, const std::vector<std::string>& args,
                   const std::vector<std::string>& operands, Findings& f) {
  std::set<char> shortf;
  std::set<std::string> longf;
  flags_of(args, shortf, longf);
  const std::string sub = operands.empty() ? std::string() : operands[0];

  auto has_operand = [&](std::initializer_list<const char*> names) {
    for (const std::string& o : operands) {
      for (const char* nm : names) {
        if (o == nm) return true;
      }
    }
    return false;
  };

  if (name == "systemctl" || name == "service" || name == "sv" || name == "rc-service" ||
      name == "launchctl") {
    if (has_operand({"stop", "disable", "mask", "kill", "unload", "poweroff", "halt"})) {
      f.add(Rule::ServiceDisruption, name + " stops or disables a service");
    }
  } else if (name == "killall" || name == "pkill") {
    f.add(Rule::ServiceDisruption, name + " terminates processes by name");
  } else if (name == "iptables" || name == "ip6tables" || name == "nft") {
    if (shortf.count('F') || shortf.count('X') || shortf.count('P') || longf.count("flush") ||
        sub == "flush") {
      f.add(Rule::ServiceDisruption, name + " flushes firewall rules");
    }
  } else if (name == "ufw") {
    if (has_operand({"disable", "reset"})) {
      f.add(Rule::ServiceDisruption, "ufw disables the host firewall");
    }
  } else if (name == "firewall-cmd") {
    for (const std::string& a : args) {
      if (a.find("remove") != std::string::npos || a.find("panic-off") != std::string::npos) {
        f.add(Rule::ServiceDisruption, "firewall-cmd weakens the host firewall");
        break;
      }
    }
  } else if (name == "mount") {
    for (const std::string& a : args) {
      if (a.find("remount") != std::string::npos) {
        f.add(Rule::ServiceDisruption, "remounts a filesystem with new options");
        break;
      }
    }
  } else if (name == "umount") {
    for (const std::string& p : operands) {
      if (tables::is_protected_path(p) || tables::is_system_path(p)) {
        f.add(Rule::ServiceDisruption, "unmounts system path " + p);
      }
    }
  } else if (name == "swapoff") {
    f.add(Rule::ServiceDisruption, "disables swap");
  } else if (name == "sysctl") {
    bool assigns = shortf.count('w') != 0;
    if (!assigns) {
      for (const std::string& a : args) {
        if (a.find('=') != std::string::npos) { assigns = true; break; }
      }
    }
    if (assigns) f.add(Rule::ServiceDisruption, "changes kernel parameters at runtime");
  }
}

// Container invocations that hand the container host-level authority.
void container_rules(const std::string& name, const std::vector<std::string>& args, Findings& f) {
  bool running = false;
  for (const std::string& a : args) {
    if (a == "run" || a == "create" || a == "exec" || a == "start") { running = true; break; }
  }
  if (!running) return;

  for (std::size_t i = 0; i < args.size(); ++i) {
    const std::string& a = args[i];
    if (a == "--privileged") {
      f.add(Rule::ContainerEscape, name + " grants the container full host privileges");
    }
    if (a == "--pid=host" || a == "--network=host" || a == "--net=host" || a == "--ipc=host") {
      f.add(Rule::ContainerPrivilege, name + " shares a host namespace with the container");
    }
    if (starts_with(a, "--cap-add")) {
      f.add(Rule::ContainerPrivilege, name + " adds kernel capabilities");
    }
    bool have_mount = false;
    std::string spec;
    if ((a == "-v" || a == "--volume" || a == "--mount") && i + 1 < args.size()) {
      ++i;
      spec = args[i];
      have_mount = true;
    } else if (starts_with(a, "--volume=")) {
      spec = a.substr(9);
      have_mount = true;
    }
    if (have_mount) {
      const std::size_t colon = spec.find(':');
      const std::string src = colon == std::string::npos ? spec : spec.substr(0, colon);
      if (src == "/" || tables::is_protected_path(src)) {
        f.add(Rule::ContainerEscape, name + " bind-mounts host path " + src);
      } else if (src.find("docker.sock") != std::string::npos ||
                 src.find("containerd.sock") != std::string::npos) {
        f.add(Rule::ContainerPrivilege, name + " mounts the container runtime socket");
      } else if (tables::is_system_path(src)) {
        f.add(Rule::ContainerPrivilege, name + " bind-mounts system path " + src);
      }
    }
  }
}

void git_rules(const std::vector<std::string>& args, Findings& f) {
  const std::string* sub = nullptr;
  for (const std::string& a : args) {
    if (a.empty() || a[0] != '-') { sub = &a; break; }
  }
  if (sub == nullptr) return;
  std::set<char> shortf;
  std::set<std::string> longf;
  flags_of(args, shortf, longf);

  if (*sub == "push" &&
      (longf.count("force") || longf.count("force-with-lease") || shortf.count('f'))) {
    f.add(Rule::GitDestructive, "force push rewrites published history");
  } else if (*sub == "reset" && longf.count("hard")) {
    f.add(Rule::GitDestructive, "hard reset discards uncommitted work");
  } else if (*sub == "clean" && (shortf.count('f') || longf.count("force"))) {
    f.add(Rule::GitDestructive, "clean removes untracked files");
  } else if (*sub == "branch" && shortf.count('D')) {
    f.add(Rule::GitDestructive, "force-deletes a branch");
  }
}

RCmd resolve_cmd(const SimpleCmd& sc, const Ctx& ctx, unsigned depth) {
  RCmd rc;
  {
    // `proc_subs` drives the "interpreter runs a downloader's output" rule, so
    // it collects only argument-position substitutions: in `bash <(curl …)` the
    // interpreter executes that file, whereas in `ruby <<< <(curl …)` the
    // redirect hands over the /dev/fd path as text.
    std::vector<const Word*> arg_words;
    for (const Word& w : sc.words) arg_words.push_back(&w);
    // Assignment values run their substitutions too: `X=$(rm -rf /)`.
    for (const auto& kv : sc.assigns) arg_words.push_back(&kv.second);
    for (const Word* w : arg_words) {
      for (const Segment& seg : w->segs) {
        if (seg.kind == Segment::Kind::ProcSub) {
          rc.proc_subs.push_back(seg.text);
          rc.subs.push_back(seg.text);
        } else if (seg.kind == Segment::Kind::CmdSub) {
          rc.subs.push_back(seg.text);
        }
      }
    }
    // Redirection targets still execute their substitution bodies.
    for (const Redirect& rd : sc.redirects) {
      for (const Segment& seg : rd.target.segs) {
        if (seg.kind == Segment::Kind::ProcSub || seg.kind == Segment::Kind::CmdSub) {
          rc.subs.push_back(seg.text);
        }
      }
    }
  }
  for (std::size_t i = 0; i < sc.words.size(); ++i) {
    std::vector<std::string> fields;
    const bool ok = expand(sc.words[i], ctx, depth, fields);
    if (!ok) {
      if (i == 0) rc.name_unresolved = true;
      else rc.arg_unresolved = true;
    }
    for (auto& fld : fields) rc.argv.push_back(std::move(fld));
  }
  for (const Redirect& rd : sc.redirects) {
    std::vector<std::string> fields;
    const bool ok = expand(rd.target, ctx, depth, fields);
    RedirView rv;
    rv.op = rd.op;
    rv.resolved = ok;
    for (std::size_t k = 0; k < fields.size(); ++k) {
      if (k > 0) rv.target += ' ';
      rv.target += fields[k];
    }
    rc.redirs.push_back(std::move(rv));
  }
  return rc;
}

void apply_assignments(const SimpleCmd& sc, Ctx& ctx, unsigned depth) {
  for (const auto& kv : sc.assigns) {
    std::vector<std::string> fields;
    const bool ok = expand(kv.second, ctx, depth, fields);
    if (ok && fields.size() <= 1) {
      ctx.env[kv.first] = fields.empty() ? std::string() : fields[0];
    } else {
      ctx.env.erase(kv.first);
    }
  }
}

// Drop the schedule fields from a crontab line, leaving the command.
//
// `* * * * * curl … | sh` is not a shell command until its five schedule
// fields (or a single `@daily`-style shorthand) are removed.
std::string strip_cron_schedule(const std::string& payload) {
  std::size_t start = 0;
  while (start < payload.size() && is_field_sep(payload[start])) ++start;
  const std::string trimmed = payload.substr(start);
  if (!trimmed.empty() && trimmed[0] == '@') {
    std::size_t pos = 1;
    while (pos < trimmed.size() && !is_field_sep(trimmed[pos])) ++pos;
    while (pos < trimmed.size() && is_field_sep(trimmed[pos])) ++pos;
    return pos >= trimmed.size() ? std::string() : trimmed.substr(pos);
  }
  std::vector<std::string> fields;
  std::string acc;
  for (char c : trimmed) {
    if (is_field_sep(c)) {
      if (!acc.empty()) { fields.push_back(acc); acc.clear(); }
    } else {
      acc += c;
    }
  }
  if (!acc.empty()) fields.push_back(acc);
  if (fields.size() < 6) return payload;
  for (std::size_t k = 0; k < 5; ++k) {
    const std::string& fl = fields[k];
    if (fl.empty()) return payload;
    for (char c : fl) {
      const bool ok = (c >= '0' && c <= '9') || c == '*' || c == ',' || c == '-' || c == '/';
      if (!ok) return payload;
    }
  }
  std::string out;
  for (std::size_t k = 5; k < fields.size(); ++k) {
    if (k > 5) out += ' ';
    out += fields[k];
  }
  return out;
}

// The literal text a single `echo`/`printf` command would emit.
bool literal_command_payload(const RCmd& rc, std::string& out) {
  const Unwrapped u = unwrap_command(rc.argv);
  if (!u.has_name) return false;
  if (u.name != "echo" && u.name != "printf") return false;
  std::vector<std::string> joined;
  for (const std::string& a : u.args) {
    if (a.empty() || a[0] != '-') joined.push_back(a);
  }
  if (joined.empty()) return false;
  out.clear();
  for (std::size_t k = 0; k < joined.size(); ++k) {
    if (k > 0) out += ' ';
    out += joined[k];
  }
  return true;
}

// The literal text emitted by a leading `echo`/`printf` stage, if any.
bool literal_pipeline_payload(const std::vector<RCmd*>& stages, std::string& out) {
  if (stages.empty() || stages[0] == nullptr) return false;
  const Unwrapped u = unwrap_command(stages[0]->argv);
  if (!u.has_name) return false;
  if (u.name != "echo" && u.name != "printf") return false;
  std::vector<std::string> joined;
  for (const std::string& a : u.args) {
    if (a.empty() || a[0] != '-') joined.push_back(a);
  }
  if (joined.empty()) return false;
  out.clear();
  for (std::size_t k = 0; k < joined.size(); ++k) {
    if (k > 0) out += ' ';
    out += joined[k];
  }
  return true;
}

void pipeline_rules(const std::vector<RCmd*>& stages, Ctx& ctx, Findings& f, unsigned depth) {
  bool have_downloader = false, have_b64 = false, have_interp = false;
  std::size_t downloader_at = 0, b64_at = 0, interp_at = 0;
  bool has_network_sink = false;
  std::vector<std::string> credential_reads;
  std::vector<std::string> credential_dir_reads;
  bool dumps_environment = false;
  bool crontab_sink = false;

  for (std::size_t i = 0; i < stages.size(); ++i) {
    RCmd* rc = stages[i];
    if (rc == nullptr) continue;
    // Checked on the raw argv: `env` is also a wrapper, so unwrapping a bare
    // `env` yields no command at all and would skip this stage.
    if (!rc->argv.empty() && rc->argv.size() == 1) {
      const std::string head = tables::basename(rc->argv[0]);
      if (head == "env" || head == "printenv") dumps_environment = true;
    }

    const Unwrapped u = unwrap_command(rc->argv);
    if (!u.has_name) continue;

    if (tables::is_downloader(u.name) && !have_downloader) {
      have_downloader = true;
      downloader_at = i;
    }
    if (u.name == "base64" && !have_b64) {
      for (const std::string& a : u.args) {
        if (is_decode_flag(a)) { have_b64 = true; b64_at = i; break; }
      }
    }
    if (tables::is_interpreter(u.name) && !have_interp) {
      have_interp = true;
      interp_at = i;
    }
    if (tables::is_network_sink(u.name)) has_network_sink = true;
    for (const RedirView& rv : rc->redirs) {
      if (rv.resolved && tables::is_network_device(rv.target)) has_network_sink = true;
    }
    if (u.name == "crontab") crontab_sink = true;
    for (const std::string& p : operand_paths(u.name, u.args)) {
      if (tables::is_credential_path(p)) {
        credential_reads.push_back(p);
      } else if (tables::is_credential_dir(p)) {
        // Reading the directory only matters when it can leave the host.
        credential_dir_reads.push_back(p);
      }
    }
    for (const RedirView& rv : rc->redirs) {
      if (rv.resolved && (rv.op == RedirOp::In || rv.op == RedirOp::HereString) &&
          tables::is_credential_path(rv.target)) {
        credential_reads.push_back(rv.target);
      }
    }
  }

  if (have_downloader && have_interp && interp_at > downloader_at) {
    f.add(Rule::RemoteExec, "downloaded content is piped into an interpreter");
  }
  if (have_b64 && have_interp && interp_at > b64_at) {
    f.add(Rule::RemoteExec, "base64-decoded content is piped into an interpreter");
    std::string payload;
    if (literal_pipeline_payload(stages, payload) && b64::looks_like_base64(payload)) {
      auto plain = b64::decode(payload);
      if (plain.has_value()) {
        analyze_nested(*plain, ctx, f, depth + 1);
      } else {
        f.add(Rule::Obfuscation, "encoded payload could not be decoded");
      }
    }
  }
  if (!credential_reads.empty()) {
    std::string what;
    for (std::size_t k = 0; k < credential_reads.size(); ++k) {
      if (k > 0) what += ", ";
      what += credential_reads[k];
    }
    if (has_network_sink) {
      f.add(Rule::Exfiltration, "credential material " + what + " reaches a network sink");
    } else {
      f.add(Rule::CredentialAccess, "reads credential material " + what);
    }
  }
  if (has_network_sink && !credential_dir_reads.empty()) {
    std::string what;
    for (std::size_t k = 0; k < credential_dir_reads.size(); ++k) {
      if (k > 0) what += ", ";
      what += credential_dir_reads[k];
    }
    f.add(Rule::Exfiltration, "credential directory " + what + " reaches a network sink");
  }
  if (has_network_sink && dumps_environment) {
    f.add(Rule::Exfiltration, "environment variables reach a network sink");
  }
  // `echo '<job>' | crontab -` installs whatever the leading stage emits.
  if (crontab_sink) {
    f.add(Rule::Persistence, "installs or replaces scheduled jobs");
    std::string payload;
    if (literal_pipeline_payload(stages, payload)) {
      analyze_nested(strip_cron_schedule(payload), ctx, f, depth + 1);
    }
  }
}

void command_rules(const RCmd& rc, Ctx& ctx, Findings& f, unsigned depth) {
  for (const RedirView& rv : rc.redirs) {
    if (!rv.resolved) continue;
    const bool writes = rv.op == RedirOp::Out || rv.op == RedirOp::Append ||
                        rv.op == RedirOp::Clobber || rv.op == RedirOp::DupOut;
    if (!writes) continue;
    if (tables::is_block_device(rv.target)) {
      f.add(Rule::DeviceOverwrite, "redirects output onto block device " + rv.target);
    }
    if (tables::is_system_write_target(rv.target)) {
      f.add(Rule::SystemFileWrite, "writes to system path " + rv.target);
    }
    if (tables::is_history_path(rv.target)) {
      f.add(Rule::HistoryTamper, "rewrites shell history file " + rv.target);
    }
    if (tables::is_persistence_path(rv.target)) {
      f.add(Rule::Persistence, "writes to startup file " + rv.target);
      // Whatever is written will execute in a future shell, so analyze it.
      std::string payload;
      if (literal_command_payload(rc, payload)) analyze_nested(payload, ctx, f, depth + 1);
    }
  }

  // Every substitution body executes, whether or not its value could be
  // resolved: `$(rm -rf /)` runs `rm` even though nothing consumes its output.
  for (const std::string& src : rc.subs) {
    analyze_nested(src, ctx, f, depth + 1);
  }

  if (rc.argv.empty()) return;

  if (rc.name_unresolved) {
    f.add(Rule::Obfuscation, "command name depends on an unresolved expansion");
    return;
  }

  const Unwrapped u = unwrap_command(rc.argv);
  if (u.privileged) f.add(Rule::PrivilegeEscalation, "runs under " + u.priv_name);
  if (!u.has_name) return;

  const std::string& name = u.name;
  const std::vector<std::string>& args = u.args;
  std::set<char> shortf;
  std::set<std::string> longf;
  flags_of(args, shortf, longf);
  const std::vector<std::string> operands = operand_paths(name, args);

  if (tables::is_interpreter(name)) {
    for (const RedirView& rv : rc.redirs) {
      if (rv.resolved && tables::is_network_device(rv.target)) {
        f.add(Rule::ReverseShell, name + " stdio bound to " + rv.target);
      }
    }
  }

  if (name == "rm") {
    const bool recursive =
        shortf.count('r') || shortf.count('R') || longf.count("recursive");
    if (recursive) {
      if (rc.arg_unresolved) {
        f.add(Rule::Obfuscation, "recursive delete target is an unresolved expansion");
      }
      for (const std::string& p : operands) {
        if (tables::is_protected_path(p)) {
          f.add(Rule::FsDestructive, "recursive delete of protected path " + p);
        } else if (tables::is_system_path(p)) {
          f.add(Rule::FsDestructive, "recursive delete of system path " + p);
        }
      }
    }
  } else if (name == "dd") {
    for (const std::string& a : args) {
      if (starts_with(a, "of=")) {
        const std::string v = a.substr(3);
        if (tables::is_block_device(v) || tables::is_protected_path(v)) {
          f.add(Rule::FsDestructive, "dd writes directly to " + v);
        }
      }
    }
  } else if (name == "shred") {
    for (const std::string& p : operands) {
      if (tables::is_block_device(p) || tables::is_protected_path(p)) {
        f.add(Rule::FsDestructive, "shred targets " + p);
      }
    }
  } else if (name == "chmod") {
    bool world_writable = false;
    for (const std::string& a : args) {
      if (is_world_writable_mode(a)) { world_writable = true; break; }
    }
    for (const std::string& p : operands) {
      if (!tables::is_protected_path(p)) continue;
      if (world_writable) {
        f.add(Rule::PermissionWeakening, "world-writable permissions on protected path " + p);
      } else {
        // Any mode change on a protected root is disruptive, not only a
        // permissive one: `chmod 000 /` bricks the host.
        f.add(Rule::PermissionWeakening, "permission change on protected path " + p);
      }
    }
  } else if (name == "chown" || name == "chgrp") {
    const bool recursive =
        shortf.count('R') || shortf.count('r') || longf.count("recursive");
    if (recursive) {
      for (const std::string& p : operands) {
        if (tables::is_protected_path(p)) {
          f.add(Rule::PermissionWeakening, "recursive ownership change on " + p);
        }
      }
    }
  } else if (name == "su") {
    f.add(Rule::PrivilegeEscalation, "switches user");
  } else if (name == "history") {
    if (shortf.count('c') || shortf.count('w') || shortf.count('d')) {
      f.add(Rule::HistoryTamper, "clears or rewrites shell history");
    }
  } else if (name == "unset" || name == "export") {
    for (const std::string& a : args) {
      if (starts_with(a, "HISTFILE")) {
        f.add(Rule::HistoryTamper, "disables shell history recording");
        break;
      }
    }
  } else if (name == "shutdown" || name == "reboot" || name == "halt" || name == "poweroff") {
    f.add(Rule::SystemPower, name + " changes host power state");
  } else if (name == "init" || name == "telinit") {
    for (const std::string& o : operands) {
      if (o == "0" || o == "6") {
        f.add(Rule::SystemPower, "changes runlevel to halt or reboot");
        break;
      }
    }
  } else if (name == "nc" || name == "ncat" || name == "netcat" || name == "socat") {
    bool exec_flag = shortf.count('e') || shortf.count('c');
    if (!exec_flag) {
      for (const std::string& a : args) {
        if (starts_with(a, "EXEC:")) { exec_flag = true; break; }
      }
    }
    if (exec_flag) {
      f.add(Rule::ReverseShell, name + " binds a command to a socket");
    } else if (shortf.count('l') || longf.count("listen")) {
      f.add(Rule::NetworkListener, name + " listens for inbound connections");
    }
  } else if (name == "git") {
    git_rules(args, f);
  } else if (name == "mv" || name == "cp" || name == "install" || name == "truncate" ||
             name == "tee" || name == "ln" || name == "rsync") {
    for (const std::string& p : operands) {
      if (tables::is_system_write_target(p)) {
        f.add(Rule::SystemFileWrite, name + " modifies system path " + p);
      }
      if (tables::is_history_path(p)) {
        f.add(Rule::HistoryTamper, name + " replaces shell history file " + p);
      } else if (tables::is_persistence_path(p)) {
        f.add(Rule::Persistence, name + " modifies startup file " + p);
      }
    }
  } else if (name == "find") {
    bool deletes = false;
    for (const std::string& a : args) {
      if (a == "-delete" || a == "-exec" || a == "-execdir" || a == "-ok") { deletes = true; break; }
    }
    if (deletes) {
      for (const std::string& p : operands) {
        if (tables::is_protected_path(p) || tables::is_system_path(p)) {
          f.add(Rule::FsDestructive, "find deletes or executes beneath " + p);
        }
      }
    }
  } else if (name == "crontab") {
    f.add(Rule::Persistence, "installs or replaces scheduled jobs");
  } else if (name == "at" || name == "batch") {
    f.add(Rule::Persistence, "schedules deferred command execution");
  } else if (tables::is_service_command(name)) {
    service_rules(name, args, operands, f);
  } else if (tables::is_container_runtime(name)) {
    container_rules(name, args, f);
  } else if (name == "eval") {
    std::string payload;
    for (std::size_t k = 0; k < args.size(); ++k) {
      if (k > 0) payload += ' ';
      payload += args[k];
    }
    if (!payload.empty()) analyze_nested(payload, ctx, f, depth + 1);
  } else {
    if (starts_with(name, "mkfs")) {
      f.add(Rule::FsDestructive, name + " creates a filesystem, destroying existing data");
    } else if (tables::is_package_manager(name)) {
      for (const std::string& a : args) {
        if (!a.empty() && a[0] == '-') continue;
        if (tables::is_package_mutation(a)) {
          f.add(Rule::PkgInstall, name + " " + a + " mutates installed packages");
        }
        break;
      }
    }
  }

  if (tables::is_downloader(name)) {
    std::size_t i = 0;
    while (i < args.size()) {
      const std::string& a = args[i];
      if ((a == "-o" || a == "-O" || a == "--output") && i + 1 < args.size()) {
        ctx.tainted.insert(args[i + 1]);
        i += 2;
        continue;
      }
      if (starts_with(a, "--output=")) ctx.tainted.insert(a.substr(9));
      ++i;
    }
    for (const RedirView& rv : rc.redirs) {
      if (rv.resolved &&
          (rv.op == RedirOp::Out || rv.op == RedirOp::Append || rv.op == RedirOp::Clobber)) {
        ctx.tainted.insert(rv.target);
      }
    }
  }

  // A downloaded file executed directly, with no interpreter named.
  if (!rc.argv.empty() && ctx.tainted.count(rc.argv[0])) {
    f.add(Rule::RemoteExec, "executes " + rc.argv[0] + ", which was downloaded earlier");
  }

  if (tables::is_interpreter(name)) {
    for (const std::string& p : operands) {
      if (ctx.tainted.count(p)) {
        f.add(Rule::RemoteExec, "executes " + p + ", which was downloaded earlier");
      }
    }
    std::string payload;
    if (program_payload(args, payload)) {
      if (tables::is_shell_interpreter(name)) {
        analyze_nested(payload, ctx, f, depth + 1);
      } else {
        for (const std::string& inner : extract_embedded_shell(payload)) {
          analyze_nested(inner, ctx, f, depth + 1);
        }
      }
    }
    // `bash <(curl …)` executes whatever the substitution produces.
    for (const std::string& src : rc.proc_subs) {
      std::string inner;
      if (first_command_name(src, inner)) {
        if (tables::is_downloader(inner)) {
          f.add(Rule::RemoteExec,
                "interpreter executes the output of a downloader via process substitution");
        }
      } else {
        f.add(Rule::Obfuscation, "interpreter payload could not be resolved");
      }
      for (const std::string& cn : all_command_names(src)) {
        if (tables::is_downloader(cn)) {
          f.add(Rule::RemoteExec,
                "interpreter executes the output of a downloader via process substitution");
          break;
        }
      }
    }
    for (const RedirView& rv : rc.redirs) {
      if (rv.op == RedirOp::HereString) {
        if (rv.resolved && tables::is_shell_interpreter(name)) {
          analyze_nested(rv.target, ctx, f, depth + 1);
        } else if (!rv.resolved) {
          f.add(Rule::Obfuscation, "interpreter payload could not be resolved");
        }
      }
    }
  }
}

bool is_fork_bomb(const std::string& name, const Script& body) {
  for (const Pipeline& pl : body.pipelines) {
    int self_refs = 0;
    for (const Cmd& c : pl.cmds) {
      if (c.kind != Cmd::Kind::Simple) continue;
      if (c.simple.words.empty()) continue;
      auto lit = c.simple.words[0].literal();
      if (lit.has_value() && *lit == name) ++self_refs;
    }
    if (self_refs >= 2) return true;
  }
  return false;
}

void walk_pipeline(const Pipeline& pl, Ctx& ctx, Findings& f, unsigned depth) {
  std::vector<RCmd> storage(pl.cmds.size());
  std::vector<RCmd*> stages(pl.cmds.size(), nullptr);
  for (std::size_t i = 0; i < pl.cmds.size(); ++i) {
    if (pl.cmds[i].kind == Cmd::Kind::Simple) {
      apply_assignments(pl.cmds[i].simple, ctx, depth);
      storage[i] = resolve_cmd(pl.cmds[i].simple, ctx, depth);
      stages[i] = &storage[i];
    }
  }

  pipeline_rules(stages, ctx, f, depth);

  for (std::size_t i = 0; i < pl.cmds.size(); ++i) {
    const Cmd& c = pl.cmds[i];
    switch (c.kind) {
      case Cmd::Kind::Simple:
        if (stages[i] != nullptr) command_rules(*stages[i], ctx, f, depth);
        break;
      case Cmd::Kind::Nested:
        if (c.nested) walk_script(*c.nested, ctx, f, depth + 1);
        break;
      case Cmd::Kind::FuncDef:
        if (c.nested) {
          if (is_fork_bomb(c.func_name, *c.nested)) {
            f.add(Rule::ForkBomb,
                  "function \"" + c.func_name + "\" recursively pipes into itself");
          }
          walk_script(*c.nested, ctx, f, depth + 1);
        }
        break;
    }
  }
}

void walk_script(const Script& s, Ctx& ctx, Findings& f, unsigned depth) {
  if (depth > limits::kMaxRecursionDepth) {
    f.add(Rule::Obfuscation, "nesting exceeded the analysis depth limit");
    return;
  }
  for (const Pipeline& pl : s.pipelines) walk_pipeline(pl, ctx, f, depth);
}

void analyze_nested(const std::string& src, Ctx& ctx, Findings& f, unsigned depth) {
  if (depth > limits::kMaxRecursionDepth) {
    f.add(Rule::Obfuscation, "nesting exceeded the analysis depth limit");
    return;
  }
  ParseResult pr = parse_source(src);
  if (!pr.ok) {
    f.add(Rule::Obfuscation, "nested payload could not be parsed");
    return;
  }
  walk_script(pr.script, ctx, f, depth);
}

}  // namespace

Verdict analyze_advanced(const std::string& cmd) {
  if (cmd.size() > limits::kMaxCmdBytes) {
    return make_verdict(Rule::Obfuscation, "command exceeds maximum analyzable length");
  }
  ParseResult pr = parse_source(cmd);
  if (!pr.ok) return make_verdict(Rule::ParseError, pr.error);

  Ctx ctx;
  Findings f;
  walk_script(pr.script, ctx, f, 0);
  return f.resolve();
}

}  // namespace agentgate
