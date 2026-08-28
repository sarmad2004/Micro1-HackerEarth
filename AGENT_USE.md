# Coding-agent disclosure and trajectories

The challenge requires coding-agent use and disclosure of the tools involved.
This document records what was used, how the work was actually driven, and
where the trajectory evidence lives.

---

## Tools used

| tool | role |
|---|---|
| **Claude Code** (Anthropic, Opus-class model), run in a remote sandboxed Linux session | the sole coding agent; wrote the specification, both implementations, the corpora, the evaluation harness and this documentation |
| g++ 13.3.0, CMake 3.28.3 | C++ build |
| rustc / cargo 1.94.1 | Rust build |
| Python 3.11.15 | evaluation harness (standard library only) |

No other AI tool was used. No API keys, credentials, or private data appear
anywhere in this submission.

**Everything in this repository was written during the hackathon.** The
repository was empty — no commits — at the start. The only pre-existing
components are the language standard libraries and the build tools above.

---

## How the agent was directed

The agent was given a single standing instruction at the outset, which shaped
every subsequent turn:

> Do not blindly implement the task. Do not modify files until you fully
> understand the requirements. We need a robust solution that can pass hidden
> tests, not just the visible examples. I will make the final decisions, so
> clearly explain important assumptions and risks.

with an explicit seven-phase workflow: understand, investigate, plan, implement,
verify, **adversarial review**, final review.

Two things about that instruction did most of the work:

1. **"Hidden tests, not just the visible examples."** This is what produced the
   held-out corpus. Without it the natural stopping point is 100% on the
   development corpus — a number that turned out to mean almost nothing.
2. **A named adversarial phase.** Giving "try to break your own solution" its
   own step, rather than leaving it as a nice-to-have at the end, is what
   produced `eval/robustness.py`, which found the `$(rm -rf /)` escape.

---

## Human checkpoints

Three points where the human directed rather than the agent:

1. **Session start.** The agent found the repository empty and the referenced
   problem PDF absent from the sandbox. It **stopped and reported the blocker**
   rather than inventing a plausible task — the correct call, since any guessed
   problem statement would have been wasted work.
2. **Scope decision.** The human supplied the actual challenge overview, which
   revealed the problem is open-ended ("apply it to any industry you like").
   The agent proposed four candidate projects with trade-offs; the human's
   direction settled the language choice (C++ and Rust).
3. **Approval gate.** The agent presented its problem framing and measurement
   design before writing implementation code.

---

## Trajectory: the shape of the work

The full session transcript is the primary trajectory artifact. The summary
below maps each phase to the evidence it produced, so a reviewer can check any
claim against a file in the repository.

### Phase 1–2 — understand and investigate

- Inspected the environment; found an empty repository and no problem statement.
- Reported the blocker instead of proceeding on a guess.
- On receiving the challenge overview, identified the operative constraints:
  baseline **and** advanced solution, measured improvement, reproducibility as
  a **qualification gate**, every claim tied to evidence.
- Noted that the rulebook's own language — *"keep consequential actions
  controlled through a sandbox or simulation, add human approval before the
  action happens"* — describes the problem this project solves.

**Artifact:** `SPEC.md`, written before any implementation code.

### Phase 3 — plan

- Chose the two-tier design so improvement is measured *within* each language,
  preventing the C++/Rust choice from confounding the baseline/advanced
  comparison.
- Chose zero external dependencies so the build needs no network — the
  strongest available answer to a reproducibility gate.
- Chose byte-identical cross-language output as a testable invariant.

### Phase 4 — implement

Order was deliberate: specification → corpus → Rust core → **compile and test
early** → policy engine → C++ port.

The agent compiled and ran the lexer and parser tests (47 passing) before
writing the policy engine, rather than writing everything and debugging a
mountain of code at once.

**Artifacts:** `rust/`, `cpp/`, `corpus/`.

### Phase 5 — verify

- 75 Rust tests, 224 C++ assertions.
- First differential run: `IDENTICAL` on 4,154 inputs.
- Raising the fuzz volume to 20,000 exposed **three divergences** — the Unicode
  variable-name issue, compounded by a stale release binary.

**Artifact:** `eval/differential.py`, `docs/results/differential.txt`.

### Phase 6 — adversarial review

The phase that changed the project.

- Built the held-out corpus **after** freezing the v1.0 rules.
- Advanced tier scored **28.57%** — worse than the baseline's 51.28%.
- Diagnosed why: structural analysis has a *narrower* catch surface than
  substring matching wherever the rule set is incomplete.
- Implemented v1.1 across ten failure classes; re-measured; confirmed no
  regression on the development corpus.
- Built the robustness harness, which found `$(rm -rf /)` returning **ALLOW** —
  a real escape the corpus had never probed.
- Found and fixed two bugs in the harness itself, where the test asserted the
  wrong thing.

**Artifacts:** `corpus/build_heldout.py`, `eval/robustness.py`,
`docs/RESULTS.md` §3 and §5.

### Phase 7 — final review

Full diff review, complete test suite, all evidence artifacts regenerated from
the shipped binaries.

---

## Retries and corrections worth recording

Honest agent trajectories include the parts that went wrong. These are the ones
that changed the outcome:

| what happened | how it surfaced | resolution |
|---|---|---|
| Rust release binary was stale, built before the ASCII determinism fix | differential reported 3 divergences that made no sense against the source | rebuilt; `make verify` now always rebuilds |
| Privilege check scanned the whole argv, so `grep -rn "sudo" …` escalated | a failing unit test | restricted to the command position |
| Baseline unit test asserted `rm -rf build/` was escalated; it is not | test failure on first run | corrected the assertion to `rm -rf /tmp/build-cache`, which genuinely is a baseline false positive |
| Two robustness cases asserted the wrong behaviour (`sh -c sh -c …` does not nest; `rm${IFS}/` is not destructive) | both gates "failed" on inputs that were in fact safe | rewrote the cases; the gates were right |
| `PATH`-scanning experiment would have made verdicts environment-dependent | recognised before shipping | removed; determinism preferred (see `IMPROVEMENT_CHANGELOG.md`) |
| Heredoc quoting collision corrupted a Python patch script | syntax error on execution | rewrote the file wholesale rather than patching |

The pattern across all six: **the tooling caught things review did not.** The
differential harness and the robustness harness each found a real bug that both
test suites had passed over, which is the argument for building them at all.

---

## Reproducing the agent's verification

Everything the agent asserted is re-runnable:

```bash
make verify     # ~60 s, no network, no cost
```

Individual stages, expected output, and troubleshooting are documented in
[`REPRODUCTION.md`](REPRODUCTION.md).

---

## Safety and ethics

The rulebook requires a legal and ethical use case, sandboxed consequential
actions, and human approval before impactful ones. This project is squarely
aligned with all three, being a tool that *implements* them:

- **It is defensive by construction.** It detects dangerous commands to protect
  the operator of an AI agent. It is a guard, not an exploit.
- **It never executes anything.** The gate performs no I/O beyond stdin and
  stdout. It does not run, resolve, stat, or shell out to the commands it
  analyzes — `SPEC.md` §8 requires this, and the tests enforce it.
- **`ASK` exists precisely to put a human in the loop**, which is the rulebook's
  human-approval requirement expressed as a decision value.
- **The corpus contains no real targets.** Every attacker endpoint is
  `evil.example`, a reserved name that cannot resolve. The dangerous commands
  are well-known public patterns, included so that detection can be measured.
- **No credentials or private data** appear anywhere in the repository. The
  credential *paths* in `SPEC.md` §6 are filename patterns used for detection;
  no secret values are present.
