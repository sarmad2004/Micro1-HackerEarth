# Improvement Changelog

Each entry records what changed, **the evidence that prompted it**, and what
the measurement showed afterwards. Entries are in the order the work happened.

The through-line: every rule in the shipped gate exists because something got
past an earlier version, not because it seemed like a good idea at design time.
Three of the entries below are bugs found by tooling rather than by inspection.

---

## 0. Baseline established

**Change.** Implemented the baseline tier: case-insensitive substring matching
over the raw command string, with ~40 patterns covering destructive filesystem
operations, remote execution, reverse shells, fork bombs, privilege escalation,
credential access and destructive git operations.

**Why it is a fair control, not a straw man.** The pattern list catches every
dangerous construct in the development corpus in its canonical spelling. One
refinement is deliberately included: a bare `curl` is not treated as remote
execution unless the command also pipes into a shell — without it the baseline
would flag every download and score implausibly badly on benign traffic, which
would have made the comparison dishonest in our favour.

**Measurement.** Development corpus: **F1 75.63%**, 21 misses, 8 false alarms.

---

## 1. Advanced tier v1.0 — structural analysis

**Change.** POSIX tokenizer (quoting, escapes, expansions, redirects, comments,
here-strings), recursive-descent parser producing an AST of pipelines,
subshells, brace groups and function definitions, then 18 rules applied to that
structure. Plus constant propagation over literal assignments, recursion into
`$(...)` and `sh -c` payloads, base64 decoding, and taint tracking from
downloaders into interpreters.

**Evidence that prompted it.** The baseline's 29 misclassifications, which fall
into two clean groups: 21 evasions it cannot see (`rm    -rf    /`,
`rm${IFS}-rf${IFS}/`, `R=rm; $R -rf /`) and 8 false alarms it cannot avoid
(`git commit -m "fix the rm -rf bug"`). Both groups have the same cause —
matching text rather than modelling execution — so both needed the same fix.

**Measurement.** Development corpus: **F1 100.00%**, 0 misses, 0 false alarms.

**What this number was actually worth: very little.** The corpus and the rules
were written together. Scoring one against the other measures self-consistency.
That realisation drove the next entry.

---

## 2. Held-out set — measuring generalization honestly

**Change.** Wrote `corpus/build_heldout.py`, 48 records, *after* freezing the
v1.0 rules. Authored adversarially: what would a competent attacker try that
these rules do not look for, and what routine command might they wrongly flag?
Labels are what a security reviewer would say, not what the code did.

**Evidence that prompted it.** A 100% score on a self-authored corpus is not
evidence of capability, and shipping it as though it were would have been the
most dishonest thing in the project.

**Measurement — the pivotal result of the whole build:**

| tier | dev corpus F1 | held-out F1 |
|---|---|---|
| baseline | 75.63% | 51.28% |
| advanced v1.0 | 100.00% | **28.57%** |

**The advanced tier scored roughly half the baseline on unfamiliar input.**

The mechanism is worth stating precisely. The baseline caught
`perl -e 'system("rm -rf /")'` because it ignores structure and saw the
substring. The advanced tier parsed it correctly, identified `perl` as an
interpreter, looked for a `-c` flag, found none, understood the command
perfectly, and allowed it.

*Understanding the input is not the same as knowing what to look for.* Parsing
buys precision. Recall still comes entirely from the completeness of the rule
set — and where a substring matcher fails loudly, a structural analyzer fails
silently.

---

## 3. Advanced tier v1.1 — closing the measured gaps

**Change.** Ten failure classes, each traced to a specific held-out record:

| # | fix | evidence (held-out id) |
|---|---|---|
| 1 | system *subtrees* protected, not only exact roots | `ho-006` `rm -rf /usr/lib` |
| 2 | new `SYSTEM_FILE_WRITE` rule for redirects and `mv`/`cp`/`ln`/`truncate`/`tee` onto system paths | `ho-002`…`ho-005` |
| 3 | inline-program flags `-e` / `--eval`, not just `-c` | `ho-009`…`ho-011` (`perl`, `ruby`, `node`) |
| 4 | `find … -delete` / `-exec` rooted at a protected path | `ho-001` |
| 5 | new `PERSISTENCE` rule: crontab, shell rc files, `authorized_keys` | `ho-013`…`ho-016` |
| 6 | new `SERVICE_DISRUPTION` rule: `systemctl stop`, `killall`, `iptables -F`, `mount -o remount` | `ho-008`, `ho-017`…`ho-019` |
| 7 | new `CONTAINER_ESCAPE` / `CONTAINER_PRIVILEGE` rules | `ho-020`, `ho-021` |
| 8 | process substitution `<(...)` lexed as a word, and analyzed | `ho-022`, `ho-120` |
| 9 | taint check extended to direct execution, not just interpreter operands | `ho-025` |
| 10 | credential *directories*, and environment dumps, when a network sink is present | `ho-026`, `ho-027` |

Two of these also fixed false alarms: `find -name '*.key'` was reading a glob
as a key file, and `diff <(sort a) <(sort b)` was a parse error.

**Measurement.**

| | before | after |
|---|---|---|
| held-out F1 | 28.57% | **100.00%** |
| held-out misses | 23 | **0** |
| held-out false alarms | 2 | **0** |
| dev corpus F1 | 100.00% | 100.00% (no regression) |

**Stated plainly: the post-fix held-out number is no longer a clean
generalization estimate.** The rules were changed in response to those records.
It measures "did the fixes land". The 28.57% is the honest generalization
evidence; a fresh estimate needs a third corpus this project has not seen.

---

## 4. Cross-language conformance found two real bugs

**Change.** `eval/differential.py` runs both implementations over the corpus
plus a seeded fuzzer (random fragment assembly and corpus mutation) and
requires byte-identical output.

**Evidence.** Two divergences, neither of which either test suite caught, and
neither of which looked wrong in isolation:

1. **Unicode variable names.** `$HOMEé-u` — Rust's `is_alphanumeric` accepted
   `é` inside a `$VAR` name; the C++ byte-wise scan stopped at ASCII, resolved
   `$HOME`, and produced a different verdict. **C++ was right on the merits:**
   bash variable names are ASCII. Both were pinned to ASCII-only classification
   and `SPEC.md` §8 now requires it.

   *Also caught here:* the Rust release binary was stale, built before that
   change. `make verify` now always rebuilds, because a stale binary produced a
   phantom divergence that cost real debugging time.

2. **Process substitution in a redirect target.** `ruby <<< <(curl …)` — C++
   treated the substitution as executable, Rust did not. **Rust was right:** a
   redirect hands over the `/dev/fd` path as text, whereas an argument position
   is executed. Scoped to argument position in both.

**Measurement.** Byte-identical across seeds 1, 5, 7, 99, 424242 and 20260828 —
over 100,000 generated inputs plus the full corpus plus 30 pinned structural
edge cases.

---

## 5. Robustness harness found a real escape

**Change.** `eval/robustness.py` attacks every bound in `SPEC.md` §7 with 26
hostile inputs: 5,000-deep nesting, 20,000-stage pipelines, 200 KB tokens, a
1 MiB line, unterminated quotes, a 120 KB base64 payload, 20,000 `${IFS}`
expansions in one word. It asserts no crash, one verdict per input, completion
within budget, and — for the advanced tier only — that no destructive payload
is allowed.

**Evidence.** `$(rm -rf /)` returned **ALLOW**.

The analyzer treated command substitutions as values to *resolve*: it succeeded
for `$(echo rm)` and gave up otherwise, never considering that the body
*executes* regardless of whether anything consumes its output. The development
corpus missed this entirely because `ob-016` only ever tested the resolvable
case.

**Fix.** Every substitution body — in words, assignment values and redirect
targets — is now analyzed. `echo $(date)` and
`cd $(git rev-parse --show-toplevel)` remain allowed.

**Measurement.** All four gates: 26/26 verdicts, exit 0, no hangs, fail-closed
satisfied. Regression tests added to both suites.

### Two harness bugs found in the same pass

Worth recording because the harness is also code, and a test that asserts the
wrong thing is worse than no test:

- `sh -c sh -c sh -c … 'rm -rf /'` does **not** nest — only the first word
  after `-c` is the program, the rest become positional parameters. `ALLOW` was
  correct; the test case was wrong. Replaced with genuine nesting.
- `rm${IFS}…${IFS}/` expands to `rm /`, which without `-r` deletes nothing.
  Also correctly allowed. Replaced with a genuinely destructive payload.

Fail-closed was additionally scoped to the advanced tier: the baseline does no
parsing, so "could not resolve" is not a state it can be in. Asserting it there
would have been asserting the tier's documented weakness as a failure.

---

## 6. Precision fixes found during development

Smaller corrections, each from a failing test rather than from review:

- **`grep -rn "sudo" /etc/sudoers.d` escalated as privilege escalation.** The
  privilege check scanned the whole argument vector, so a search *pattern*
  matched. Now only the command position is inspected, via the wrapper-unwrap
  path.
- **`cat .env.example` escalated as credential access.** Credential matching
  moved to exact basenames.
- **`cat ~/.ssh/id_rsa` vs `echo ~/.ssh/id_rsa`.** Split "inert" into *data
  commands* (`echo`, `printf` — arguments are neither code nor paths) and *file
  readers* (`cat`, `grep` — arguments are still paths). `cat .env` escalates;
  `echo .env` does not.
- **Cron schedule fields.** `* * * * * curl … | sh` is not a shell command
  until the five schedule fields are stripped; without that the payload parsed
  as a glob invocation and the `curl … | sh` inside was invisible.

---

## Experiment removed

**Scanning `PATH` to distinguish real binaries from unknown command names.**

The idea was to reduce false positives: if `foo` is not on `PATH`, the command
probably fails harmlessly, so escalating it is friction for nothing.

Removed before it shipped, for a reason that outranks the benefit: it would
have made the verdict depend on the machine the gate runs on. The same command
would be allowed on one host and escalated on another, `make differential`
could no longer assert byte-identical output, and every result in
`docs/RESULTS.md` would become environment-specific.

**Determinism is worth more than the false positives it would have saved.** A
gate whose answer depends on its environment cannot be tested, cannot be
reproduced, and cannot be reasoned about — and `SPEC.md` §8 now forbids it
outright. The gate performs no I/O beyond stdin and stdout.
