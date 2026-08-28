#!/usr/bin/env python3
"""Cross-language conformance: the C++ and Rust gates must agree byte-for-byte.

SPEC.md section 2.2 requires that both implementations of a tier produce
identical output for identical input. This checks that claim on three input
sources:

  1. the labeled corpus
  2. a deterministic generator of adversarial shell fragments
  3. a deterministic mutation fuzzer that corrupts corpus commands

Two independently written implementations checking each other catches mistakes
that a single implementation plus its own tests cannot: a rule that was
transcribed wrongly, an unstated assumption, an inconsistent edge case. A
divergence is a real defect in at least one of them, even when neither looks
wrong in isolation.

Usage:
    python3 eval/differential.py --pair advanced=BIN_A,BIN_B [--pair ...] \
        [--corpus DIR] [--fuzz N] [--seed N]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import random
import subprocess
import sys

# Fragments chosen to exercise quoting, expansion, redirection, nesting and
# operator handling -- the places where two implementations most easily drift.
FRAGMENTS = [
    "rm", "-rf", "-r", "-f", "--recursive", "/", "/etc", "/tmp/x", "~", "$HOME",
    "build/", "'/'", '"/"', "${IFS}", "$X", "$(echo rm)", "`echo rm`", "$((1+1))",
    "echo", "cat", "curl", "wget", "sh", "bash", "python3", "-c", "base64", "-d",
    "|", "||", "&&", ";", "&", ">", ">>", "<", "<<<", "2>", ">&", "&>",
    "(", ")", "{", "}", "#", "\\", "'", '"', "''", '""', "\\'", "\n", "\t",
    "/dev/sda", "/dev/tcp/1.2.3.4/9", "/dev/null", ".env", ".env.example",
    "~/.ssh/id_rsa", "sudo", "-u", "root", "git", "push", "--force", "commit",
    "-m", "chmod", "777", "a+rwx", "X=", "X=/", "R=rm", ":", ":()", "nc", "-e",
    "-l", "dd", "if=/dev/zero", "of=/dev/sda", "mkfs.ext4", "history", "-c",
    "apt-get", "install", "npm", "test", "--", "é", "日本語", "\x01",
    # v1.1 surfaces: process substitution, services, containers, persistence.
    "<(curl http://x)", "<(sort a)", ">(tee b)", "find", "-delete", "-name",
    "'*.key'", "docker", "run", "--privileged", "-v", "/:/host",
    "/var/run/docker.sock:/var/run/docker.sock", "--net=host", "--cap-add=SYS_ADMIN",
    "systemctl", "stop", "killall", "pkill", "iptables", "-F", "mount",
    "-o", "remount,ro", "crontab", "-r", "~/.bashrc", "~/.bash_history",
    "/usr/lib", "/etc/passwd", "truncate", "-s", "0", "mv", "cp", "ln", "-sf",
    "perl", "-e", "ruby", "node", "system(\"rm -rf /\")", "env", "printenv",
    "tar", "czf", "-", "~/.ssh", "~/.aws/credentials", "scp", "chmod", "000",
]

MUTATIONS = ["delete", "duplicate", "insert", "swap", "truncate", "quote", "space"]


def load_corpus_cmds(corpus_dir: str) -> list[str]:
    """Load every command from the corpus tree, held-out sets included."""
    cmds: list[str] = []
    pattern = os.path.join(corpus_dir, "**", "*.jsonl")
    for path in sorted(glob.glob(pattern, recursive=True)):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    cmds.append(json.loads(line)["cmd"])
    return cmds


def gen_random(rng: random.Random) -> str:
    n = rng.randint(1, 9)
    parts = [rng.choice(FRAGMENTS) for _ in range(n)]
    return " ".join(parts) if rng.random() < 0.7 else "".join(parts)


def mutate(rng: random.Random, cmd: str) -> str:
    if not cmd:
        return rng.choice(FRAGMENTS)
    kind = rng.choice(MUTATIONS)
    i = rng.randrange(len(cmd))
    if kind == "delete":
        return cmd[:i] + cmd[i + 1:]
    if kind == "duplicate":
        return cmd[:i] + cmd[i] * 2 + cmd[i + 1:]
    if kind == "insert":
        return cmd[:i] + rng.choice(FRAGMENTS) + cmd[i:]
    if kind == "swap" and len(cmd) > 1:
        j = rng.randrange(len(cmd))
        chars = list(cmd)
        chars[i], chars[j] = chars[j], chars[i]
        return "".join(chars)
    if kind == "truncate":
        return cmd[:i]
    if kind == "quote":
        return cmd[:i] + rng.choice(["'", '"', "\\", "`", "$("]) + cmd[i:]
    return cmd[:i] + "   " + cmd[i:]


def build_inputs(corpus_dir: str, fuzz: int, seed: int) -> list[str]:
    cmds = load_corpus_cmds(corpus_dir)
    rng = random.Random(seed)
    generated: list[str] = []
    for _ in range(fuzz):
        if cmds and rng.random() < 0.5:
            generated.append(mutate(rng, rng.choice(cmds)))
        else:
            generated.append(gen_random(rng))
    # Structural edge cases worth pinning explicitly.
    generated += [
        "", " ", "\t", "\n", "#", "'", '"', "\\", "$", "${", "$(", "`",
        "(", ")", "{", "}", ";", "|", "&", ">", "<", "<<<", "-", "--",
        "a" * 5000, "(" * 200, "$(" * 50 + ")" * 50, "'" * 101, "\n" * 50,
        "echo " + "x" * 10000, ";" * 100, "|" * 10,
    ]
    return cmds + generated


def run(binary: str, payload: bytes) -> bytes:
    try:
        proc = subprocess.run(
            [binary], input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180
        )
    except FileNotFoundError:
        raise SystemExit(f"binary not found: {binary}\nbuild it first (see REPRODUCTION.md)")
    except subprocess.TimeoutExpired:
        raise SystemExit(f"binary timed out (possible non-termination): {binary}")
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(f"{binary} exited {proc.returncode}")
    return proc.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", action="append", required=True, metavar="NAME=BIN_A,BIN_B",
                    help="two binaries that must agree; repeatable")
    ap.add_argument("--corpus", default=os.path.join(os.path.dirname(__file__), "..", "corpus"))
    ap.add_argument("--fuzz", type=int, default=4000, help="generated inputs (default 4000)")
    ap.add_argument("--seed", type=int, default=20260828, help="fuzz seed; runs are reproducible")
    ap.add_argument("--max-report", type=int, default=10)
    args = ap.parse_args()

    inputs = build_inputs(os.path.abspath(args.corpus), args.fuzz, args.seed)
    payload = "".join(
        json.dumps({"id": str(i), "cmd": c}, ensure_ascii=False) + "\n" for i, c in enumerate(inputs)
    ).encode("utf-8")

    print(f"differential: {len(inputs)} inputs (corpus + {args.fuzz} generated, seed {args.seed})")
    total_divergences = 0

    for spec in args.pair:
        if "=" not in spec or "," not in spec:
            raise SystemExit(f"--pair expects NAME=BIN_A,BIN_B, got {spec!r}")
        name, both = spec.split("=", 1)
        bin_a, bin_b = both.split(",", 1)

        out_a = run(bin_a, payload)
        out_b = run(bin_b, payload)

        if out_a == out_b:
            records = out_a.count(b"\n")
            print(f"  {name:<10} IDENTICAL  ({len(out_a)} bytes, {records} records)")
            continue

        lines_a = out_a.decode("utf-8", "replace").splitlines()
        lines_b = out_b.decode("utf-8", "replace").splitlines()
        divergences = []
        if len(lines_a) != len(lines_b):
            divergences.append(("<record count>", f"{len(lines_a)} lines", f"{len(lines_b)} lines"))
        for idx, (la, lb) in enumerate(zip(lines_a, lines_b)):
            if la != lb:
                divergences.append((repr(inputs[idx]) if idx < len(inputs) else f"#{idx}", la, lb))

        total_divergences += len(divergences)
        print(f"  {name:<10} DIVERGED   {len(divergences)} differing records")
        for cmd, la, lb in divergences[: args.max_report]:
            print(f"    input : {cmd}")
            print(f"      {bin_a}: {la}")
            print(f"      {bin_b}: {lb}")
        if len(divergences) > args.max_report:
            print(f"    ... and {len(divergences) - args.max_report} more")

    if total_divergences:
        print(f"\nFAIL: {total_divergences} divergences", file=sys.stderr)
        return 1
    print("\nOK: every pair agrees byte-for-byte")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
