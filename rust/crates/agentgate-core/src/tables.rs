//! Classification tables from SPEC.md section 6.
//!
//! These lists are duplicated in `cpp/src/tables.cpp`. That duplication is
//! deliberate: two independent transcriptions checked against each other by
//! `eval/differential.py` catch transcription errors that a single shared
//! source would silently propagate.

/// Paths whose recursive deletion or ownership change is destructive.
pub const PROTECTED_PATHS: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64",
    "/opt", "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var",
    "~", "$HOME",
];

/// Roots beneath which any path is system state. Distinct from
/// [`PROTECTED_PATHS`], which lists only the roots themselves: `rm -rf /usr`
/// and `rm -rf /usr/lib` are both catastrophic, and only the first is an exact
/// match. Added in v1.1 after the held-out set showed subtree deletion slipping
/// through (see docs/RESULTS.md).
pub const SYSTEM_ROOTS: &[&str] = &[
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/opt",
    "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var",
];

/// Paths under a system root that agents legitimately write and delete.
pub const SYSTEM_WRITE_EXCEPTIONS: &[&str] = &["/var/tmp", "/var/cache", "/var/folders"];

/// Directories that hold credential material. Reading one is only reportable
/// when it also reaches a network sink: `ls ~/.ssh` is routine, while
/// `tar czf - ~/.ssh | curl ...` is exfiltration.
pub const CREDENTIAL_DIRS: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube", ".docker"];

/// Files whose contents are executed on every new shell.
pub const PERSISTENCE_FILES: &[&str] = &[
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
    ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".cshrc", ".kshrc",
    "authorized_keys", "crontab",
];

/// Path fragments that indicate boot or scheduling persistence.
pub const PERSISTENCE_FRAGMENTS: &[&str] = &[
    "/etc/profile", "/etc/bash.bashrc", "/etc/cron", "/var/spool/cron",
    "/etc/systemd/system", "/etc/init.d", "/etc/rc.local", "/config/fish/config.fish",
    "/etc/sudoers", "/Library/LaunchAgents", "/Library/LaunchDaemons",
];

/// Shell history files.
pub const HISTORY_FILES: &[&str] =
    &[".bash_history", ".zsh_history", ".sh_history", ".history", ".python_history"];

/// Commands that stop or disable running services.
pub const SERVICE_COMMANDS: &[&str] = &[
    "systemctl", "service", "killall", "pkill", "launchctl", "sv", "rc-service",
    "iptables", "ip6tables", "nft", "ufw", "firewall-cmd", "mount", "umount",
    "swapoff", "sysctl",
];

/// Container runtimes.
pub const CONTAINER_RUNTIMES: &[&str] = &["docker", "podman", "nerdctl", "ctr", "lima"];

/// Interpreter flags that introduce an inline program.
pub const PROGRAM_FLAGS: &[&str] = &["-c", "-e", "--eval", "--command"];

/// `find` predicates whose following argument is a pattern, not a path.
pub const FIND_VALUE_FLAGS: &[&str] = &[
    "-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-wholename",
    "-perm", "-size", "-type", "-maxdepth", "-mindepth", "-newer", "-user",
    "-group", "-mtime", "-ctime", "-atime", "-printf", "-prune",
];

/// Block-device path prefixes.
pub const DEVICE_PREFIXES: &[&str] = &[
    "/dev/sd", "/dev/nvme", "/dev/hd", "/dev/vd", "/dev/xvd", "/dev/mmcblk",
    "/dev/disk", "/dev/loop", "/dev/md", "/dev/dm-",
];

/// Exact basenames that identify a credential file.
pub const CREDENTIAL_BASENAMES: &[&str] = &[
    ".env", ".netrc", ".npmrc", ".pypirc", ".htpasswd", "credentials",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "shadow", "gshadow",
];

/// Path fragments that identify credential material wherever they appear.
pub const CREDENTIAL_FRAGMENTS: &[&str] = &[
    "/.ssh/", "/.aws/credentials", "/.gnupg/", "/.kube/config",
    "/.docker/config.json", "/etc/shadow", "/etc/gshadow", "/.netrc",
];

/// File extensions that identify key material.
pub const CREDENTIAL_SUFFIXES: &[&str] = &[".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"];

/// Commands that move data off the machine.
pub const NETWORK_SINKS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp",
    "rsync", "ftp", "telnet", "http", "httpie", "xh",
];

/// Commands that fetch remote content.
pub const DOWNLOADERS: &[&str] = &["curl", "wget", "fetch", "aria2c", "httpie", "http", "xh"];

/// Commands that execute code supplied to them.
pub const INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "ksh", "dash", "fish", "csh", "tcsh", "ash",
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php",
    "lua", "Rscript", "osascript", "deno", "bun",
];

/// Shell interpreters whose `-c` payload is itself shell source.
pub const SHELL_INTERPRETERS: &[&str] =
    &["sh", "bash", "zsh", "ksh", "dash", "fish", "csh", "tcsh", "ash"];

/// Commands whose word arguments are data, never code (SPEC.md section 5.1).
pub const INERT_COMMANDS: &[&str] = &[
    "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "comm",
    "diff", "cat", "less", "more", "head", "tail", "wc", "sort", "uniq",
    "test", "[", "true", "false", ":", "tee", "column", "nl", "rev",
];


/// Commands whose arguments are pure text, never paths and never code.
/// Distinguished from [`INERT_COMMANDS`] because `cat ~/.ssh/id_rsa` reads a
/// path while `echo ~/.ssh/id_rsa` merely prints one.
pub const DATA_COMMANDS: &[&str] = &["echo", "printf", "true", "false", ":"];

/// Readers whose first non-flag operand is a search pattern, not a path.
pub const PATTERN_FIRST: &[&str] = &["grep", "egrep", "fgrep", "rg", "ag", "ack"];

/// Wrappers that run another command; the analyzer unwraps to the inner one.
pub const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "nohup", "time", "timeout", "nice", "ionice",
    "stdbuf", "setsid", "command", "builtin", "exec", "xargs", "proot",
];

/// Wrappers that additionally imply a privilege change.
pub const PRIV_WRAPPERS: &[&str] = &["sudo", "doas", "pkexec"];

/// Package managers whose mutating subcommands need approval.
pub const PACKAGE_MANAGERS: &[&str] = &[
    "apt", "apt-get", "aptitude", "yum", "dnf", "pacman", "zypper", "apk",
    "brew", "pip", "pip3", "npm", "pnpm", "yarn", "gem", "cargo", "go",
    "composer", "conda",
];

/// Subcommands of a package manager that mutate installed state.
pub const PACKAGE_MUTATIONS: &[&str] = &[
    "install", "uninstall", "remove", "purge", "upgrade", "update", "add",
    "erase", "reinstall",
];

/// Reserved shell words the parser treats as command boundaries.
pub const RESERVED_WORDS: &[&str] = &[
    "if", "then", "else", "elif", "fi", "do", "done", "while", "until",
    "for", "case", "esac", "in", "function", "select", "time", "!",
];

/// Return the basename of a command path, so `/bin/rm` matches `rm`.
pub fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

fn contains(list: &[&str], needle: &str) -> bool {
    list.contains(&needle)
}

pub fn is_interpreter(name: &str) -> bool {
    contains(INTERPRETERS, name)
}

pub fn is_shell_interpreter(name: &str) -> bool {
    contains(SHELL_INTERPRETERS, name)
}

pub fn is_downloader(name: &str) -> bool {
    contains(DOWNLOADERS, name)
}

pub fn is_network_sink(name: &str) -> bool {
    contains(NETWORK_SINKS, name)
}

pub fn is_inert(name: &str) -> bool {
    contains(INERT_COMMANDS, name)
}

pub fn is_data_command(name: &str) -> bool {
    contains(DATA_COMMANDS, name)
}

pub fn is_pattern_first(name: &str) -> bool {
    contains(PATTERN_FIRST, name)
}

pub fn is_wrapper(name: &str) -> bool {
    contains(WRAPPERS, name)
}

pub fn is_priv_wrapper(name: &str) -> bool {
    contains(PRIV_WRAPPERS, name)
}

pub fn is_package_manager(name: &str) -> bool {
    contains(PACKAGE_MANAGERS, name)
}

pub fn is_package_mutation(sub: &str) -> bool {
    contains(PACKAGE_MUTATIONS, sub)
}

pub fn is_reserved_word(w: &str) -> bool {
    contains(RESERVED_WORDS, w)
}

/// True when `path` is a block device.
pub fn is_block_device(path: &str) -> bool {
    DEVICE_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// True when `path` is a bash network pseudo-device (`/dev/tcp/host/port`).
pub fn is_network_device(path: &str) -> bool {
    path.starts_with("/dev/tcp/") || path.starts_with("/dev/udp/")
}

/// Strip trailing slashes and a trailing `/*` glob, so `/usr/` and `/*`
/// normalise onto the protected entries they denote.
fn normalise_path(path: &str) -> String {
    let mut p = path.to_string();
    if p.ends_with("/*") {
        p.truncate(p.len() - 2);
        if p.is_empty() {
            p.push('/');
        }
    }
    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    if p.is_empty() {
        p.push('/');
    }
    p
}

/// True when deleting `path` recursively would destroy system or home state.
///
/// Deliberately conservative in the safe direction: a path under `/tmp`, a
/// relative path, or a deeper path under a protected root (`/var/log/app`)
/// is *not* protected, because deleting build output is routine agent work.
pub fn is_protected_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let p = normalise_path(path);
    PROTECTED_PATHS.iter().any(|e| {
        let n = normalise_path(e);
        n == p
    }) || p == "$HOME"
        || p == "~"
}

/// True when `path` lies under a system root and is not one of the
/// conventionally writable exceptions.
pub fn is_system_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let p = normalise_path(path);
    if p == "/" {
        return true;
    }
    for ex in SYSTEM_WRITE_EXCEPTIONS {
        if p == *ex || p.starts_with(&format!("{ex}/")) {
            return false;
        }
    }
    SYSTEM_ROOTS
        .iter()
        .any(|root| p == *root || p.starts_with(&format!("{root}/")))
}

/// True when writing `path` would modify system state. Device, `/proc` and
/// `/sys` paths are excluded because dedicated rules cover them.
pub fn is_system_write_target(path: &str) -> bool {
    if path.starts_with("/dev/") || path.starts_with("/proc/") || path.starts_with("/sys/") {
        return false;
    }
    is_system_path(path)
}

/// True when `path` is a directory holding credential material.
pub fn is_credential_dir(path: &str) -> bool {
    let norm = normalise_path(path);
    let base = basename(&norm);
    CREDENTIAL_DIRS.contains(&base)
}

/// True when writing `path` would survive into future shells or boots.
pub fn is_persistence_path(path: &str) -> bool {
    let base = basename(path);
    if PERSISTENCE_FILES.contains(&base) {
        return true;
    }
    PERSISTENCE_FRAGMENTS.iter().any(|f| path.contains(f))
}

/// True when `path` is a shell history file.
pub fn is_history_path(path: &str) -> bool {
    let base = basename(path);
    HISTORY_FILES.contains(&base)
}

pub fn is_service_command(name: &str) -> bool {
    contains(SERVICE_COMMANDS, name)
}

pub fn is_container_runtime(name: &str) -> bool {
    contains(CONTAINER_RUNTIMES, name)
}

pub fn is_program_flag(a: &str) -> bool {
    contains(PROGRAM_FLAGS, a)
}

pub fn is_find_value_flag(a: &str) -> bool {
    contains(FIND_VALUE_FLAGS, a)
}

/// True when `path` names credential material.
pub fn is_credential_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let base = basename(path);
    if CREDENTIAL_BASENAMES.contains(&base) {
        return true;
    }
    if CREDENTIAL_SUFFIXES.iter().any(|s| base.ends_with(s)) {
        return true;
    }
    CREDENTIAL_FRAGMENTS.iter().any(|f| path.contains(f))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_strips_directories() {
        assert_eq!(basename("/bin/rm"), "rm");
        assert_eq!(basename("rm"), "rm");
        assert_eq!(basename("/usr/local/bin/curl"), "curl");
    }

    #[test]
    fn protected_paths_cover_glob_and_trailing_slash() {
        assert!(is_protected_path("/"));
        assert!(is_protected_path("/*"));
        assert!(is_protected_path("/etc"));
        assert!(is_protected_path("/etc/"));
        assert!(is_protected_path("~"));
        assert!(is_protected_path("$HOME"));
    }

    #[test]
    fn ordinary_work_paths_are_not_protected() {
        assert!(!is_protected_path("build/"));
        assert!(!is_protected_path("./node_modules"));
        assert!(!is_protected_path("/tmp/build-cache"));
        assert!(!is_protected_path("/var/log/app"));
        assert!(!is_protected_path(""));
    }

    #[test]
    fn credential_matching_is_precise() {
        assert!(is_credential_path("/home/u/.ssh/id_rsa"));
        assert!(is_credential_path(".env"));
        assert!(is_credential_path("/etc/shadow"));
        assert!(is_credential_path("server.pem"));
        // The decisive precision case: a template is not a secret.
        assert!(!is_credential_path(".env.example"));
        assert!(!is_credential_path("README.md"));
    }

    #[test]
    fn device_and_network_devices() {
        assert!(is_block_device("/dev/sda"));
        assert!(is_block_device("/dev/nvme0n1"));
        assert!(!is_block_device("/dev/null"));
        assert!(is_network_device("/dev/tcp/10.0.0.1/443"));
    }
}
