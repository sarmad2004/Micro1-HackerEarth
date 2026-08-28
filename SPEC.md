# agentgate — Specification v1.1

Normative contract for the command-safety gate. Both the C++ and Rust
implementations MUST satisfy this document exactly. Where this spec and an
implementation disagree, the spec wins.

Changes in v1.1 are marked **[1.1]** and were driven by measurement, not
speculation: each one closes a failure the held-out evaluation set or the
robustness harness actually produced. See `docs/RESULTS.md` for the evidence
and `IMPROVEMENT_CHANGELOG.md` for the sequence.

## 1. Purpose

An autonomous coding agent proposes shell commands. `agentgate` decides, for
each proposed command, whether it may run unattended.

## 2. I/O contract

### 2.1 Input

JSON Lines on stdin. One JSON object per line. Required fields:

| field | type   | meaning                        |
|-------|--------|--------------------------------|
| `id`  | string | opaque record identifier       |
| `cmd` | string | the shell command to evaluate  |

Unknown fields MUST be ignored (forward compatibility). Blank lines and lines
consisting solely of whitespace MUST be skipped silently.

A line that is not a valid JSON object, or that lacks `id` or `cmd`, is a
**malformed record**. The gate MUST NOT abort. It MUST emit a record with
`decision: "ASK"` and `rule: "MALFORMED_INPUT"`, using the 1-based input line
number as `id` when `id` is unrecoverable.

### 2.2 Output

JSON Lines on stdout, exactly one output record per input record, in input
order. Fields, in this exact key order:

```json
{"id":"...","decision":"ALLOW","rule":"OK","detail":"..."}
```

| field      | type   | meaning                                   |
|------------|--------|-------------------------------------------|
| `id`       | string | echoed from input                         |
| `decision` | string | `ALLOW` \| `ASK` \| `DENY`                |
| `rule`     | string | identifier of the highest-severity rule   |
| `detail`   | string | short human-readable justification        |

Output MUST be byte-identical between the C++ and Rust implementations of the
same tier for any input. This is enforced by `eval/differential.py`.

### 2.3 Exit codes

`0` on success (including when records were denied). `2` on unusable
invocation (e.g. unreadable stdin). Never non-zero merely because a command
was denied — the verdict travels in the payload, not the exit status.

## 3. Decision lattice

```
ALLOW  <  ASK  <  DENY
```

`ASK` means "a qualified human must approve before execution", per the
challenge rulebook's human-approval requirement.

When several rules fire, the gate reports the **maximum** severity. Ties at
equal severity are broken by the rule's declaration order in §5 (lower index
wins), so output is deterministic and independent of evaluation order.

**Fail-closed principle.** Any condition the analyzer cannot resolve —
a parse error, an unresolvable expansion, an undecodable payload, exhausted
recursion depth — escalates to `ASK`, never `ALLOW`. Silence is never consent.

This is a property of the **advanced** tier. The baseline performs no parsing
and therefore has no notion of "could not resolve"; `eval/robustness.py`
asserts fail-closed only for tiers that claim it.

## 4. Tiers

### 4.1 Baseline (`agentgate-baseline`)

Case-insensitive substring and simple-pattern matching over the **raw command
string**. No parsing. This is the naive approach that production agent
harnesses commonly ship first, and it is included as an honest control, not a
straw man: its pattern list covers every dangerous construct in the evaluation
corpus in its canonical form.

### 4.2 Advanced (`agentgate-advanced`)

Structural analysis:

1. **Tokenize** with POSIX quoting rules — single quotes, double quotes,
   backslash escapes, operators, comments, here-strings, and **[1.1]** process
   substitution `<(...)` / `>(...)`.
2. **Parse** into an AST of and-or lists, pipelines, simple commands,
   subshells, brace groups and function definitions, retaining redirects and
   assignments.
3. **Expand** words with constant propagation over literal variable
   assignments, resolving `${IFS}` to a space and `$HOME` to `~`.
4. **Recurse** into:
   - command substitutions `$(...)` and backticks — **[1.1]** every
     substitution body is analyzed, not merely resolved, because
     `$(rm -rf /)` executes `rm` whether or not anything consumes its output;
   - literal inline programs of known interpreters — **[1.1]** `-e` and
     `--eval` as well as `-c`, since `perl -e`, `ruby -e` and `node -e` take
     their program that way;
   - **[1.1]** process-substitution bodies, and crontab payloads after their
     schedule fields are stripped.
5. **Decode** literal base64 payloads and re-analyze the plaintext.
6. **Taint-track** filesystem paths written by network downloaders, and flag
   any later interpreter invocation — **[1.1]** or direct execution — that
   reads a tainted path.
7. **Apply** the §5 rule set to the resulting structure.

## 5. Rule set

Listed in tie-break order. `S` is the severity.

| # | rule | S | fires when |
|---|------|---|-----------|
| 1 | `FORK_BOMB` | DENY | a function whose body pipes itself into itself |
| 2 | `REVERSE_SHELL` | DENY | an interpreter's stdio is bound to a network socket, or `nc`/`socat` binds a command to one |
| 3 | `REMOTE_EXEC` | DENY | downloaded or decoded content reaches an interpreter — by pipe, by process substitution, or via a tainted intermediate file — or a tainted file is executed directly **[1.1]** |
| 4 | `FS_DESTRUCTIVE` | DENY | recursive deletion of a protected or system path (§6), `mkfs`/`shred`/`dd` onto a block device, or **[1.1]** `find … -delete`/`-exec` rooted at one |
| 5 | `DEVICE_OVERWRITE` | DENY | a redirect whose target is a block-device path |
| 6 | `SYSTEM_FILE_WRITE` **[1.1]** | DENY | a redirect, or `mv`/`cp`/`ln`/`tee`/`install`/`truncate`/`rsync`, writes to a system path |
| 7 | `EXFILTRATION` | DENY | credential material, a credential directory **[1.1]**, or the environment **[1.1]** reaches a network sink |
| 8 | `CONTAINER_ESCAPE` **[1.1]** | DENY | a container is run `--privileged` or with a protected host path bind-mounted |
| 9 | `CREDENTIAL_ACCESS` | ASK | a credential file is read with no network sink present |
| 10 | `PRIVILEGE_ESCALATION` | ASK | `sudo`, `su`, `doas`, `pkexec` in command position |
| 11 | `PERMISSION_WEAKENING` | ASK | world-writable mode, recursive ownership change, or **[1.1]** any mode change on a protected root |
| 12 | `PERSISTENCE` **[1.1]** | ASK | writes to a startup file, installs a cron/at job, or modifies `authorized_keys` |
| 13 | `SERVICE_DISRUPTION` **[1.1]** | ASK | stops or disables a service, flushes firewall rules, remounts a filesystem, or kills processes by name |
| 14 | `CONTAINER_PRIVILEGE` **[1.1]** | ASK | a container shares a host namespace, adds capabilities, or mounts the runtime socket |
| 15 | `HISTORY_TAMPER` | ASK | shell-history truncation, `HISTFILE` unsetting, or **[1.1]** replacing a history file |
| 16 | `SYSTEM_POWER` | ASK | `shutdown`, `reboot`, `halt`, `poweroff`, `init 0/6` |
| 17 | `PKG_INSTALL` | ASK | a package manager performs a mutating operation |
| 18 | `GIT_DESTRUCTIVE` | ASK | `push --force`, `reset --hard`, `clean -f`, `branch -D` |
| 19 | `NETWORK_LISTENER` | ASK | a process binds a listening socket |
| 20 | `OBFUSCATION` | ASK | an encoded or dynamically-constructed payload could not be resolved |
| 21 | `MALFORMED_INPUT` | ASK | the input record was not a usable JSON object (§2.1) |
| 22 | `PARSE_ERROR` | ASK | the command could not be tokenized or parsed |
| 23 | `OK` | ALLOW | no rule fired |

### 5.1 Inert-argument commands

Two distinct notions, separated in v1.0 after a false positive:

**Data commands** — `echo`, `printf`, `true`, `false`, `:` — take arguments
that are neither code nor paths. Their word arguments MUST NOT be scanned at
all. This is why `echo "rm -rf /"` is allowed.

**Inert commands** — `cat`, `grep`, `head`, `tail`, `diff`, `sort`, … — do not
*execute* their arguments, but those arguments are still paths. `cat .env` is
`CREDENTIAL_ACCESS`; `echo .env` is not.

**Pattern-first commands** — `grep`, `rg`, `ag`, … — take a search pattern as
their first operand, which is not a path. `grep -r "id_rsa" .` is allowed.

`git commit`/`tag`/`merge` message payloads (`-m`, `-F`) are prose, not paths.
**[1.1]** `find` predicate values (`-name`, `-path`, `-perm`, …) are patterns,
not paths, so `find . -name '*.key' -delete` is allowed.

Redirects on any of these are still analyzed: `echo x > /dev/sda` is
`DEVICE_OVERWRITE` regardless of `echo` being a data command.

## 6. Path classification

**Protected paths** — the roots themselves: `/`, `/bin`, `/boot`, `/dev`,
`/etc`, `/home`, `/lib`, `/lib32`, `/lib64`, `/opt`, `/proc`, `/root`,
`/sbin`, `/srv`, `/sys`, `/usr`, `/var`, `~`, `$HOME`. A trailing `/` or `/*`
normalises onto the root it denotes.

**System paths [1.1]** — anything *beneath* a system root (the list above
minus `/home`), excluding `/var/tmp`, `/var/cache` and `/var/folders`.
`rm -rf /usr` and `rm -rf /usr/lib` are both catastrophic and only the first
is an exact match, which is why this category exists.

Deletion under `/tmp`, the conventionally writable exceptions, the current
directory, or an explicit relative path is **not** destructive — deleting
build output is routine agent work.

**Block devices** — `/dev/sd*`, `/dev/nvme*`, `/dev/hd*`, `/dev/vd*`,
`/dev/xvd*`, `/dev/mmcblk*`, `/dev/disk*`, `/dev/loop*`, `/dev/md*`,
`/dev/dm-*`.

**Network pseudo-devices** — `/dev/tcp/*`, `/dev/udp/*`.

**Credential files** — basenames `.env`, `.netrc`, `.npmrc`, `.pypirc`,
`.htpasswd`, `credentials`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`,
`shadow`, `gshadow`; fragments `/.ssh/`, `/.aws/credentials`, `/.gnupg/`,
`/.kube/config`, `/.docker/config.json`, `/etc/shadow`, `/etc/gshadow`,
`/.netrc`; suffixes `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`.

Matching is on the exact basename, so `.env.example` is not a credential.

**Credential directories [1.1]** — `.ssh`, `.aws`, `.gnupg`, `.kube`,
`.docker`. Reading one is reportable *only* when a network sink is present:
`ls ~/.ssh` is routine, `tar czf - ~/.ssh | curl …` is exfiltration.

**Startup files [1.1]** — `.bashrc`, `.bash_profile`, `.profile`, `.zshrc`,
`authorized_keys`, `crontab`, and fragments `/etc/cron`, `/var/spool/cron`,
`/etc/systemd/system`, `/etc/rc.local`, `/etc/sudoers`, `/Library/LaunchAgents`.

**History files [1.1]** — `.bash_history`, `.zsh_history`, `.sh_history`,
`.history`, `.python_history`.

**Network sinks** — `curl`, `wget`, `nc`, `ncat`, `netcat`, `socat`, `ssh`,
`scp`, `sftp`, `rsync`, `ftp`, `telnet`, `http`, `httpie`, `xh`.

**Downloaders** — `curl`, `wget`, `fetch`, `aria2c`, `httpie`, `http`, `xh`.

**Interpreters** — `sh`, `bash`, `zsh`, `ksh`, `dash`, `fish`, `csh`, `tcsh`,
`ash`, `python*`, `perl`, `ruby`, `node`, `nodejs`, `php`, `lua`, `Rscript`,
`osascript`, `deno`, `bun`.

Command names are matched on the **basename** after stripping any directory
prefix, so `/bin/rm`, `/usr/bin/env rm` and `rm` are equivalent.

## 7. Resource bounds

A hostile input must not be able to exhaust the gate.

| bound | limit | on breach |
|-------|-------|-----------|
| input line length | 1 MiB | `ASK` / `MALFORMED_INPUT` |
| command length | 256 KiB | `ASK` / `OBFUSCATION` |
| recursion depth (substitution, inline program, base64) | 8 | stop recursing, `ASK` / `OBFUSCATION` |
| parser nesting depth | 64 | `ASK` / `PARSE_ERROR` |
| tokens per command | 100 000 | `ASK` / `PARSE_ERROR` |
| base64 decode output | 64 KiB | `ASK` / `OBFUSCATION` |

Parsing MUST be depth-bounded; no input may provoke a native stack overflow.
The tokenizer and parser MUST be linear in input length. `eval/robustness.py`
attacks every bound in this table.

## 8. Determinism

For identical input bytes, both implementations MUST produce identical output
bytes, on every run, independent of locale, environment variables, hash
iteration order, filesystem state, or wall-clock time.

Consequently both implementations restrict character classification to ASCII:
Rust's Unicode-aware `is_alphanumeric` and `char::is_whitespace` would disagree
with the C++ byte-wise equivalents on non-ASCII input. Shell variable names are
ASCII by definition, so this is also the correct shell semantics.

The gate performs no I/O beyond stdin/stdout and never executes, resolves, or
stats the command it analyzes.
