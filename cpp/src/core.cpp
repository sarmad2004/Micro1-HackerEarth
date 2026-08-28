// Decision lattice, findings resolution, JSON framing, base64 and the
// classification tables. Mirrors the Rust modules of the same names.

#include "agentgate/agentgate.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace agentgate {

const char* to_string(Decision d) {
  switch (d) {
    case Decision::Allow: return "ALLOW";
    case Decision::Ask: return "ASK";
    case Decision::Deny: return "DENY";
  }
  return "ALLOW";
}

const char* to_string(Rule r) {
  switch (r) {
    case Rule::ForkBomb: return "FORK_BOMB";
    case Rule::ReverseShell: return "REVERSE_SHELL";
    case Rule::RemoteExec: return "REMOTE_EXEC";
    case Rule::FsDestructive: return "FS_DESTRUCTIVE";
    case Rule::DeviceOverwrite: return "DEVICE_OVERWRITE";
    case Rule::SystemFileWrite: return "SYSTEM_FILE_WRITE";
    case Rule::Exfiltration: return "EXFILTRATION";
    case Rule::ContainerEscape: return "CONTAINER_ESCAPE";
    case Rule::CredentialAccess: return "CREDENTIAL_ACCESS";
    case Rule::PrivilegeEscalation: return "PRIVILEGE_ESCALATION";
    case Rule::PermissionWeakening: return "PERMISSION_WEAKENING";
    case Rule::Persistence: return "PERSISTENCE";
    case Rule::ServiceDisruption: return "SERVICE_DISRUPTION";
    case Rule::ContainerPrivilege: return "CONTAINER_PRIVILEGE";
    case Rule::HistoryTamper: return "HISTORY_TAMPER";
    case Rule::SystemPower: return "SYSTEM_POWER";
    case Rule::PkgInstall: return "PKG_INSTALL";
    case Rule::GitDestructive: return "GIT_DESTRUCTIVE";
    case Rule::NetworkListener: return "NETWORK_LISTENER";
    case Rule::Obfuscation: return "OBFUSCATION";
    case Rule::MalformedInput: return "MALFORMED_INPUT";
    case Rule::ParseError: return "PARSE_ERROR";
    case Rule::Ok: return "OK";
  }
  return "OK";
}

Decision severity(Rule r) {
  switch (r) {
    case Rule::ForkBomb:
    case Rule::ReverseShell:
    case Rule::RemoteExec:
    case Rule::FsDestructive:
    case Rule::DeviceOverwrite:
    case Rule::SystemFileWrite:
    case Rule::Exfiltration:
    case Rule::ContainerEscape:
      return Decision::Deny;
    case Rule::Ok:
      return Decision::Allow;
    default:
      return Decision::Ask;
  }
}

Verdict make_allow() { return Verdict{Decision::Allow, Rule::Ok, "no rule matched"}; }

Verdict make_verdict(Rule r, std::string detail) {
  return Verdict{severity(r), r, std::move(detail)};
}

void Findings::add(Rule r, std::string detail) {
  Verdict cand = make_verdict(r, std::move(detail));
  bool replace;
  if (!has_) {
    replace = true;
  } else if (cand.decision != best_.decision) {
    replace = static_cast<int>(cand.decision) > static_cast<int>(best_.decision);
  } else {
    replace = static_cast<int>(cand.rule) < static_cast<int>(best_.rule);
  }
  if (replace) {
    best_ = std::move(cand);
    has_ = true;
  }
}

Verdict Findings::resolve() const { return has_ ? best_ : make_allow(); }

std::string render_record(const std::string& id, const Verdict& v) {
  std::string out;
  out.reserve(96);
  out += "{\"id\":";
  json::escape_into(id, out);
  out += ",\"decision\":\"";
  out += to_string(v.decision);
  out += "\",\"rule\":\"";
  out += to_string(v.rule);
  out += "\",\"detail\":";
  json::escape_into(v.detail, out);
  out += "}";
  return out;
}

// --- JSON ------------------------------------------------------------------

namespace json {

void escape_into(const std::string& s, std::string& out) {
  static const char* kHex = "0123456789abcdef";
  out += '"';
  for (char raw : s) {
    const unsigned char c = static_cast<unsigned char>(raw);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case 0x08: out += "\\b"; break;
      case 0x0c: out += "\\f"; break;
      default:
        if (c < 0x20) {
          out += "\\u00";
          out += kHex[(c >> 4) & 0xF];
          out += kHex[c & 0xF];
        } else {
          // Bytes >= 0x80 are UTF-8 continuation/lead bytes and pass through
          // unchanged, which is what the Rust implementation produces too.
          out += static_cast<char>(c);
        }
    }
  }
  out += '"';
}

namespace {

struct Cursor {
  const std::string& b;
  std::size_t i = 0;
  explicit Cursor(const std::string& s) : b(s) {}
  bool eof() const { return i >= b.size(); }
  int peek() const { return eof() ? -1 : static_cast<unsigned char>(b[i]); }
  int bump() { return eof() ? -1 : static_cast<unsigned char>(b[i++]); }
  void skip_ws() {
    while (!eof() && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r')) ++i;
  }
};

bool parse_hex4(Cursor& c, unsigned& out) {
  unsigned v = 0;
  for (int k = 0; k < 4; ++k) {
    int d = c.bump();
    unsigned n;
    if (d >= '0' && d <= '9') n = static_cast<unsigned>(d - '0');
    else if (d >= 'a' && d <= 'f') n = static_cast<unsigned>(d - 'a' + 10);
    else if (d >= 'A' && d <= 'F') n = static_cast<unsigned>(d - 'A' + 10);
    else return false;
    v = v * 16 + n;
  }
  out = v;
  return true;
}

void encode_utf8(unsigned cp, std::string& out) {
  if (cp < 0x80) {
    out += static_cast<char>(cp);
  } else if (cp < 0x800) {
    out += static_cast<char>(0xC0 | (cp >> 6));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  } else if (cp < 0x10000) {
    out += static_cast<char>(0xE0 | (cp >> 12));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  } else {
    out += static_cast<char>(0xF0 | (cp >> 18));
    out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  }
}

bool parse_string(Cursor& c, std::string& out) {
  if (c.bump() != '"') return false;
  out.clear();
  for (;;) {
    int ch = c.bump();
    if (ch < 0) return false;
    if (ch == '"') return true;
    if (ch != '\\') {
      out += static_cast<char>(ch);
      continue;
    }
    int e = c.bump();
    switch (e) {
      case '"': out += '"'; break;
      case '\\': out += '\\'; break;
      case '/': out += '/'; break;
      case 'b': out += static_cast<char>(0x08); break;
      case 'f': out += static_cast<char>(0x0c); break;
      case 'n': out += '\n'; break;
      case 'r': out += '\r'; break;
      case 't': out += '\t'; break;
      case 'u': {
        unsigned hi = 0;
        if (!parse_hex4(c, hi)) return false;
        unsigned cp = hi;
        if (hi >= 0xD800 && hi < 0xDC00) {
          if (c.bump() != '\\' || c.bump() != 'u') return false;
          unsigned lo = 0;
          if (!parse_hex4(c, lo)) return false;
          if (lo < 0xDC00 || lo >= 0xE000) return false;
          cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
        } else if (hi >= 0xDC00 && hi < 0xE000) {
          return false;  // lone trailing surrogate
        }
        encode_utf8(cp, out);
        break;
      }
      default:
        return false;
    }
  }
}

bool skip_composite(Cursor& c) {
  int open = c.bump();
  if (open < 0) return false;
  const int close = (open == '{') ? '}' : ']';
  int depth = 1;
  std::string scratch;
  while (depth > 0) {
    int p = c.peek();
    if (p < 0) return false;
    if (p == '"') {
      if (!parse_string(c, scratch)) return false;
      continue;
    }
    if (p == open) ++depth;
    else if (p == close) --depth;
    ++c.i;
  }
  return true;
}

// Parse any value. `is_string` reports whether it was a string.
bool parse_value(Cursor& c, std::string& out, bool& is_string) {
  is_string = false;
  int p = c.peek();
  if (p < 0) return false;
  if (p == '"') {
    is_string = true;
    return parse_string(c, out);
  }
  if (p == '{' || p == '[') return skip_composite(c);
  if (p == 't') { if (c.b.compare(c.i, 4, "true") != 0) return false; c.i += 4; return true; }
  if (p == 'f') { if (c.b.compare(c.i, 5, "false") != 0) return false; c.i += 5; return true; }
  if (p == 'n') { if (c.b.compare(c.i, 4, "null") != 0) return false; c.i += 4; return true; }
  std::size_t start = c.i;
  while (!c.eof()) {
    char ch = c.b[c.i];
    if ((ch >= '0' && ch <= '9') || ch == '-' || ch == '+' || ch == '.' || ch == 'e' || ch == 'E') {
      ++c.i;
    } else {
      break;
    }
  }
  return c.i != start;
}

}  // namespace

std::optional<Record> parse_record(const std::string& line) {
  Cursor c(line);
  c.skip_ws();
  if (c.bump() != '{') return std::nullopt;
  Record rec;
  c.skip_ws();
  if (c.peek() == '}') return rec;
  for (;;) {
    c.skip_ws();
    std::string key;
    if (!parse_string(c, key)) return std::nullopt;
    c.skip_ws();
    if (c.bump() != ':') return std::nullopt;
    c.skip_ws();
    std::string value;
    bool is_string = false;
    if (!parse_value(c, value, is_string)) return std::nullopt;
    // A non-string value clears the field, matching the Rust implementation
    // where `rec.id = value` assigns `None` for a non-string.
    if (key == "id") {
      rec.id = is_string ? value : std::string();
      rec.has_id = is_string;
    } else if (key == "cmd") {
      rec.cmd = is_string ? value : std::string();
      rec.has_cmd = is_string;
    }
    c.skip_ws();
    int t = c.bump();
    if (t == ',') continue;
    if (t == '}') break;
    return std::nullopt;
  }
  return rec;
}

}  // namespace json

// --- Base64 ----------------------------------------------------------------

namespace b64 {
namespace {
int value_of(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}
bool is_ws(unsigned char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0x0b || c == 0x0c;
}
// Reject decoded output that is not valid UTF-8, matching Rust's
// String::from_utf8 check, so both implementations refuse the same payloads.
bool valid_utf8(const std::string& s) {
  std::size_t i = 0, n = s.size();
  while (i < n) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    std::size_t len;
    unsigned cp;
    if (c < 0x80) { ++i; continue; }
    else if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1Fu; }
    else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0Fu; }
    else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07u; }
    else return false;
    if (i + len > n) return false;
    for (std::size_t k = 1; k < len; ++k) {
      unsigned char cc = static_cast<unsigned char>(s[i + k]);
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
}  // namespace

std::optional<std::string> decode(const std::string& s) {
  std::string out;
  std::uint32_t acc = 0;
  unsigned nbits = 0;
  std::size_t padding = 0;
  std::size_t symbols = 0;

  for (char raw : s) {
    const unsigned char c = static_cast<unsigned char>(raw);
    if (is_ws(c)) continue;
    if (c == '=') { ++padding; continue; }
    if (padding > 0) return std::nullopt;
    int v = value_of(c);
    if (v < 0) return std::nullopt;
    acc = (acc << 6) | static_cast<std::uint32_t>(v);
    nbits += 6;
    ++symbols;
    if (nbits >= 8) {
      nbits -= 8;
      out += static_cast<char>((acc >> nbits) & 0xFF);
      if (out.size() > limits::kMaxB64Output) return std::nullopt;
    }
  }
  if (symbols == 0) return std::nullopt;
  if (symbols % 4 == 1) return std::nullopt;
  if (padding > 2) return std::nullopt;
  if (nbits > 0 && (acc & ((1u << nbits) - 1u)) != 0) return std::nullopt;
  if (!valid_utf8(out)) return std::nullopt;
  return out;
}

bool looks_like_base64(const std::string& s) {
  std::string t;
  for (char raw : s) {
    const unsigned char c = static_cast<unsigned char>(raw);
    if (!is_ws(c)) t += static_cast<char>(c);
  }
  if (t.size() < 8) return false;
  std::size_t body = 0;
  while (body < t.size() && t[body] != '=') ++body;
  for (char raw : t) {
    const unsigned char c = static_cast<unsigned char>(raw);
    if (value_of(c) < 0 && c != '=') return false;
  }
  return body >= 8;
}

}  // namespace b64

// --- Tables ----------------------------------------------------------------

namespace tables {
namespace {

const char* const kProtectedPaths[] = {
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64",
    "/opt", "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var", "~", "$HOME"};

const char* const kSystemRoots[] = {
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/opt",
    "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var"};

const char* const kSystemWriteExceptions[] = {"/var/tmp", "/var/cache", "/var/folders"};

const char* const kCredentialDirs[] = {".ssh", ".aws", ".gnupg", ".kube", ".docker"};

const char* const kPersistenceFiles[] = {
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
    ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".cshrc", ".kshrc",
    "authorized_keys", "crontab"};

const char* const kPersistenceFragments[] = {
    "/etc/profile", "/etc/bash.bashrc", "/etc/cron", "/var/spool/cron",
    "/etc/systemd/system", "/etc/init.d", "/etc/rc.local", "/config/fish/config.fish",
    "/etc/sudoers", "/Library/LaunchAgents", "/Library/LaunchDaemons"};

const char* const kHistoryFiles[] = {
    ".bash_history", ".zsh_history", ".sh_history", ".history", ".python_history"};

const char* const kServiceCommands[] = {
    "systemctl", "service", "killall", "pkill", "launchctl", "sv", "rc-service",
    "iptables", "ip6tables", "nft", "ufw", "firewall-cmd", "mount", "umount",
    "swapoff", "sysctl"};

const char* const kContainerRuntimes[] = {"docker", "podman", "nerdctl", "ctr", "lima"};

const char* const kProgramFlags[] = {"-c", "-e", "--eval", "--command"};

const char* const kFindValueFlags[] = {
    "-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-wholename",
    "-perm", "-size", "-type", "-maxdepth", "-mindepth", "-newer", "-user",
    "-group", "-mtime", "-ctime", "-atime", "-printf", "-prune"};

const char* const kDevicePrefixes[] = {
    "/dev/sd", "/dev/nvme", "/dev/hd", "/dev/vd", "/dev/xvd", "/dev/mmcblk",
    "/dev/disk", "/dev/loop", "/dev/md", "/dev/dm-"};

const char* const kCredentialBasenames[] = {
    ".env", ".netrc", ".npmrc", ".pypirc", ".htpasswd", "credentials",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "shadow", "gshadow"};

const char* const kCredentialFragments[] = {
    "/.ssh/", "/.aws/credentials", "/.gnupg/", "/.kube/config",
    "/.docker/config.json", "/etc/shadow", "/etc/gshadow", "/.netrc"};

const char* const kCredentialSuffixes[] = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"};

const char* const kNetworkSinks[] = {
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp",
    "rsync", "ftp", "telnet", "http", "httpie", "xh"};

const char* const kDownloaders[] = {"curl", "wget", "fetch", "aria2c", "httpie", "http", "xh"};

const char* const kInterpreters[] = {
    "sh", "bash", "zsh", "ksh", "dash", "fish", "csh", "tcsh", "ash",
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php",
    "lua", "Rscript", "osascript", "deno", "bun"};

const char* const kShellInterpreters[] = {"sh", "bash", "zsh", "ksh", "dash", "fish", "csh", "tcsh", "ash"};

const char* const kInertCommands[] = {
    "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "comm",
    "diff", "cat", "less", "more", "head", "tail", "wc", "sort", "uniq",
    "test", "[", "true", "false", ":", "tee", "column", "nl", "rev"};

const char* const kDataCommands[] = {"echo", "printf", "true", "false", ":"};

const char* const kPatternFirst[] = {"grep", "egrep", "fgrep", "rg", "ag", "ack"};

const char* const kWrappers[] = {
    "sudo", "doas", "env", "nohup", "time", "timeout", "nice", "ionice",
    "stdbuf", "setsid", "command", "builtin", "exec", "xargs", "proot"};

const char* const kPrivWrappers[] = {"sudo", "doas", "pkexec"};

const char* const kPackageManagers[] = {
    "apt", "apt-get", "aptitude", "yum", "dnf", "pacman", "zypper", "apk",
    "brew", "pip", "pip3", "npm", "pnpm", "yarn", "gem", "cargo", "go",
    "composer", "conda"};

const char* const kPackageMutations[] = {
    "install", "uninstall", "remove", "purge", "upgrade", "update", "add",
    "erase", "reinstall"};

const char* const kReservedWords[] = {
    "if", "then", "else", "elif", "fi", "do", "done", "while", "until",
    "for", "case", "esac", "in", "function", "select", "time", "!"};

template <std::size_t N>
bool contains(const char* const (&list)[N], const std::string& needle) {
  for (std::size_t i = 0; i < N; ++i) {
    if (needle == list[i]) return true;
  }
  return false;
}

bool starts_with(const std::string& s, const char* prefix) {
  const std::size_t n = std::strlen(prefix);
  return s.size() >= n && s.compare(0, n, prefix) == 0;
}

bool ends_with(const std::string& s, const char* suffix) {
  const std::size_t n = std::strlen(suffix);
  return s.size() >= n && s.compare(s.size() - n, n, suffix) == 0;
}

std::string normalise_path(const std::string& path) {
  std::string p = path;
  if (p.size() >= 2 && p.compare(p.size() - 2, 2, "/*") == 0) {
    p.erase(p.size() - 2);
    if (p.empty()) p = "/";
  }
  while (p.size() > 1 && p.back() == '/') p.pop_back();
  if (p.empty()) p = "/";
  return p;
}

}  // namespace

std::string basename(const std::string& path) {
  const std::size_t pos = path.rfind('/');
  return pos == std::string::npos ? path : path.substr(pos + 1);
}

bool is_interpreter(const std::string& n) { return contains(kInterpreters, n); }
bool is_shell_interpreter(const std::string& n) { return contains(kShellInterpreters, n); }
bool is_downloader(const std::string& n) { return contains(kDownloaders, n); }
bool is_network_sink(const std::string& n) { return contains(kNetworkSinks, n); }
bool is_inert(const std::string& n) { return contains(kInertCommands, n); }
bool is_data_command(const std::string& n) { return contains(kDataCommands, n); }
bool is_pattern_first(const std::string& n) { return contains(kPatternFirst, n); }
bool is_wrapper(const std::string& n) { return contains(kWrappers, n); }
bool is_priv_wrapper(const std::string& n) { return contains(kPrivWrappers, n); }
bool is_package_manager(const std::string& n) { return contains(kPackageManagers, n); }
bool is_package_mutation(const std::string& n) { return contains(kPackageMutations, n); }
bool is_reserved_word(const std::string& n) { return contains(kReservedWords, n); }

bool is_block_device(const std::string& p) {
  for (const char* prefix : kDevicePrefixes) {
    if (starts_with(p, prefix)) return true;
  }
  return false;
}

bool is_network_device(const std::string& p) {
  return starts_with(p, "/dev/tcp/") || starts_with(p, "/dev/udp/");
}

bool is_protected_path(const std::string& path) {
  if (path.empty()) return false;
  const std::string p = normalise_path(path);
  for (const char* entry : kProtectedPaths) {
    if (normalise_path(entry) == p) return true;
  }
  return p == "$HOME" || p == "~";
}

bool is_system_path(const std::string& path) {
  if (path.empty()) return false;
  const std::string p = normalise_path(path);
  if (p == "/") return true;
  for (const char* ex : kSystemWriteExceptions) {
    const std::string e(ex);
    if (p == e || starts_with(p, (e + "/").c_str())) return false;
  }
  for (const char* root : kSystemRoots) {
    const std::string r(root);
    if (p == r || starts_with(p, (r + "/").c_str())) return true;
  }
  return false;
}

bool is_system_write_target(const std::string& path) {
  if (starts_with(path, "/dev/") || starts_with(path, "/proc/") || starts_with(path, "/sys/")) {
    return false;
  }
  return is_system_path(path);
}

bool is_credential_dir(const std::string& path) {
  const std::string base = basename(normalise_path(path));
  return contains(kCredentialDirs, base);
}

bool is_persistence_path(const std::string& path) {
  if (contains(kPersistenceFiles, basename(path))) return true;
  for (const char* fragment : kPersistenceFragments) {
    if (path.find(fragment) != std::string::npos) return true;
  }
  return false;
}

bool is_history_path(const std::string& path) {
  return contains(kHistoryFiles, basename(path));
}

bool is_service_command(const std::string& n) { return contains(kServiceCommands, n); }
bool is_container_runtime(const std::string& n) { return contains(kContainerRuntimes, n); }
bool is_program_flag(const std::string& a) { return contains(kProgramFlags, a); }
bool is_find_value_flag(const std::string& a) { return contains(kFindValueFlags, a); }

bool is_credential_path(const std::string& path) {
  if (path.empty()) return false;
  const std::string base = basename(path);
  if (contains(kCredentialBasenames, base)) return true;
  for (const char* suffix : kCredentialSuffixes) {
    if (ends_with(base, suffix)) return true;
  }
  for (const char* fragment : kCredentialFragments) {
    if (path.find(fragment) != std::string::npos) return true;
  }
  return false;
}

}  // namespace tables

}  // namespace agentgate
