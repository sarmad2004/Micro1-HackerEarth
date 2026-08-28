//! Shell command safety analysis for autonomous coding agents.
//!
//! Two analysis tiers share one decision lattice and one output format:
//!
//! * [`baseline`] — substring matching over the raw command string.
//! * [`policy`] — structural analysis over a parsed shell AST.
//!
//! See `SPEC.md` at the repository root for the normative contract. The C++
//! implementation under `cpp/` must agree byte-for-byte with this one.

pub mod b64;
pub mod baseline;
pub mod json;
pub mod lexer;
pub mod limits;
pub mod parser;
pub mod policy;
pub mod stream;
pub mod tables;

/// The decision lattice. `Ord` is the severity order: `Allow < Ask < Deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "ALLOW",
            Decision::Ask => "ASK",
            Decision::Deny => "DENY",
        }
    }
}

/// A rule identifier. The discriminant order is the spec's tie-break order:
/// when two rules of equal severity fire, the lower discriminant wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    ForkBomb,
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
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::ForkBomb => "FORK_BOMB",
            Rule::ReverseShell => "REVERSE_SHELL",
            Rule::RemoteExec => "REMOTE_EXEC",
            Rule::FsDestructive => "FS_DESTRUCTIVE",
            Rule::DeviceOverwrite => "DEVICE_OVERWRITE",
            Rule::SystemFileWrite => "SYSTEM_FILE_WRITE",
            Rule::Exfiltration => "EXFILTRATION",
            Rule::ContainerEscape => "CONTAINER_ESCAPE",
            Rule::CredentialAccess => "CREDENTIAL_ACCESS",
            Rule::PrivilegeEscalation => "PRIVILEGE_ESCALATION",
            Rule::PermissionWeakening => "PERMISSION_WEAKENING",
            Rule::Persistence => "PERSISTENCE",
            Rule::ServiceDisruption => "SERVICE_DISRUPTION",
            Rule::ContainerPrivilege => "CONTAINER_PRIVILEGE",
            Rule::HistoryTamper => "HISTORY_TAMPER",
            Rule::SystemPower => "SYSTEM_POWER",
            Rule::PkgInstall => "PKG_INSTALL",
            Rule::GitDestructive => "GIT_DESTRUCTIVE",
            Rule::NetworkListener => "NETWORK_LISTENER",
            Rule::Obfuscation => "OBFUSCATION",
            Rule::MalformedInput => "MALFORMED_INPUT",
            Rule::ParseError => "PARSE_ERROR",
            Rule::Ok => "OK",
        }
    }

    /// The severity this rule carries when it fires.
    pub fn severity(self) -> Decision {
        match self {
            Rule::ForkBomb
            | Rule::ReverseShell
            | Rule::RemoteExec
            | Rule::FsDestructive
            | Rule::DeviceOverwrite
            | Rule::SystemFileWrite
            | Rule::Exfiltration
            | Rule::ContainerEscape => Decision::Deny,
            Rule::Ok => Decision::Allow,
            _ => Decision::Ask,
        }
    }
}

/// One analysis result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    pub rule: Rule,
    pub detail: String,
}

impl Verdict {
    pub fn allow() -> Self {
        Verdict { decision: Decision::Allow, rule: Rule::Ok, detail: String::from("no rule matched") }
    }

    pub fn of(rule: Rule, detail: impl Into<String>) -> Self {
        Verdict { decision: rule.severity(), rule, detail: detail.into() }
    }
}

/// Accumulates findings and resolves them per the spec's precedence rules:
/// highest severity wins; ties broken by lowest rule discriminant.
#[derive(Debug, Default)]
pub struct Findings {
    best: Option<Verdict>,
}

impl Findings {
    pub fn new() -> Self {
        Findings { best: None }
    }

    pub fn add(&mut self, rule: Rule, detail: impl Into<String>) {
        let candidate = Verdict::of(rule, detail);
        let replace = match &self.best {
            None => true,
            Some(cur) => match candidate.decision.cmp(&cur.decision) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => candidate.rule < cur.rule,
            },
        };
        if replace {
            self.best = Some(candidate);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.best.is_none()
    }

    pub fn resolve(self) -> Verdict {
        self.best.unwrap_or_else(Verdict::allow)
    }
}

/// Serialise a verdict as one JSON Lines record. Key order is fixed by the
/// spec so that C++ and Rust output compares byte-for-byte.
pub fn render_record(id: &str, v: &Verdict) -> String {
    let mut out = String::with_capacity(96);
    out.push_str("{\"id\":");
    json::escape_into(id, &mut out);
    out.push_str(",\"decision\":\"");
    out.push_str(v.decision.as_str());
    out.push_str("\",\"rule\":\"");
    out.push_str(v.rule.as_str());
    out.push_str("\",\"detail\":");
    json::escape_into(&v.detail, &mut out);
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_beats_order() {
        let mut f = Findings::new();
        f.add(Rule::PrivilegeEscalation, "sudo");
        f.add(Rule::FsDestructive, "rm -rf /");
        let v = f.resolve();
        assert_eq!(v.rule, Rule::FsDestructive);
        assert_eq!(v.decision, Decision::Deny);
    }

    #[test]
    fn ties_break_on_rule_order() {
        let mut f = Findings::new();
        f.add(Rule::PkgInstall, "apt");
        f.add(Rule::PrivilegeEscalation, "sudo");
        assert_eq!(f.resolve().rule, Rule::PrivilegeEscalation);
    }

    #[test]
    fn insertion_order_does_not_matter() {
        let mut a = Findings::new();
        a.add(Rule::PrivilegeEscalation, "x");
        a.add(Rule::PkgInstall, "y");
        let mut b = Findings::new();
        b.add(Rule::PkgInstall, "y");
        b.add(Rule::PrivilegeEscalation, "x");
        assert_eq!(a.resolve().rule, b.resolve().rule);
    }

    #[test]
    fn empty_findings_allow() {
        assert_eq!(Findings::new().resolve().decision, Decision::Allow);
    }
}
