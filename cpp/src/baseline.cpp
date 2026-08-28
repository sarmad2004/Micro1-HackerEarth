// Baseline tier: substring matching over the raw command string.
// Port of rust/crates/agentgate-core/src/baseline.rs.
//
// Kept deliberately faithful to the Rust version, including its one refinement
// (a bare downloader is not remote execution), so the measured gap between the
// tiers is a property of the approach rather than of either transcription.

#include "agentgate/agentgate.hpp"

#include <utility>

namespace agentgate {
namespace {

struct Pattern {
  const char* needle;
  Rule rule;
};

const Pattern kPatterns[] = {
    {"rm -rf /", Rule::FsDestructive},
    {"rm -fr /", Rule::FsDestructive},
    {"rm -rf ~", Rule::FsDestructive},
    {"rm -rf $home", Rule::FsDestructive},
    {"rm -rf /*", Rule::FsDestructive},
    {"mkfs", Rule::FsDestructive},
    {"dd if=", Rule::FsDestructive},
    {"shred ", Rule::FsDestructive},
    {"curl", Rule::RemoteExec},
    {"wget", Rule::RemoteExec},
    {"/dev/tcp/", Rule::ReverseShell},
    {"nc -e", Rule::ReverseShell},
    {":(){", Rule::ForkBomb},
    {"sudo", Rule::PrivilegeEscalation},
    {"su -", Rule::PrivilegeEscalation},
    {"chmod 777", Rule::PermissionWeakening},
    {"chmod -r 777", Rule::PermissionWeakening},
    {"chown -r", Rule::PermissionWeakening},
    {"id_rsa", Rule::CredentialAccess},
    {"/etc/shadow", Rule::CredentialAccess},
    {".ssh/", Rule::CredentialAccess},
    {"history -c", Rule::HistoryTamper},
    {"unset histfile", Rule::HistoryTamper},
    {"shutdown", Rule::SystemPower},
    {"reboot", Rule::SystemPower},
    {"poweroff", Rule::SystemPower},
    {"apt-get install", Rule::PkgInstall},
    {"apt-get remove", Rule::PkgInstall},
    {"apt install", Rule::PkgInstall},
    {"yum install", Rule::PkgInstall},
    {"pip install", Rule::PkgInstall},
    {"npm install", Rule::PkgInstall},
    {"git push --force", Rule::GitDestructive},
    {"git push -f", Rule::GitDestructive},
    {"git reset --hard", Rule::GitDestructive},
    {"git clean -f", Rule::GitDestructive},
    {"nc -l", Rule::NetworkListener},
    {"netcat -l", Rule::NetworkListener},
};

const char* const kDevicePatterns[] = {"> /dev/sd", ">/dev/sd", "> /dev/nvme", ">/dev/nvme"};

std::string ascii_lower(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    out += (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
  }
  return out;
}

bool contains(const std::string& hay, const char* needle) {
  return hay.find(needle) != std::string::npos;
}

// Reproduces Rust's `format!("matched pattern {needle:?}")`.
std::string matched(const char* needle) {
  return std::string("matched pattern \"") + needle + "\"";
}

bool looks_like_pipe_to_shell(const std::string& lower) {
  static const char* const kSinks[] = {"| sh", "|sh", "| bash", "|bash",
                                       "| zsh", "|zsh", "| python", "|python"};
  for (const char* s : kSinks) {
    if (contains(lower, s)) return true;
  }
  return false;
}

}  // namespace

Verdict analyze_baseline(const std::string& cmd) {
  const std::string lower = ascii_lower(cmd);
  Findings f;

  for (const Pattern& p : kPatterns) {
    if (contains(lower, p.needle)) f.add(p.rule, matched(p.needle));
  }
  for (const char* needle : kDevicePatterns) {
    if (contains(lower, needle)) f.add(Rule::DeviceOverwrite, matched(needle));
  }

  if (f.empty()) return make_allow();

  const Verdict v = f.resolve();
  if (v.rule == Rule::RemoteExec && !looks_like_pipe_to_shell(lower)) {
    Findings g;
    for (const Pattern& p : kPatterns) {
      if (p.rule != Rule::RemoteExec && contains(lower, p.needle)) g.add(p.rule, matched(p.needle));
    }
    for (const char* needle : kDevicePatterns) {
      if (contains(lower, needle)) g.add(Rule::DeviceOverwrite, matched(needle));
    }
    return g.resolve();
  }
  return v;
}

}  // namespace agentgate
