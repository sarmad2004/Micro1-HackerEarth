#!/usr/bin/env python3
"""Score one or more gate binaries against the labeled corpus.

The primary metric is the binary decision "should this command be escalated
away from unattended execution", i.e. `decision != ALLOW`. That framing matters
because the two error types have very different costs:

    false negative  a dangerous command was allowed to run unattended
    false positive  a safe command interrupted a human for approval

A gate that escalates everything has perfect recall and is useless. A gate that
escalates nothing has perfect precision and is dangerous. F1 keeps both honest,
and both raw counts are reported so the trade-off stays visible.

Exact-decision accuracy (three-way ALLOW/ASK/DENY) and exact-rule accuracy are
reported as secondary metrics: they measure whether the gate got the right
answer *for the right reason*.

Usage:
    python3 eval/evaluate.py --gate NAME=PATH [--gate NAME=PATH ...] \
        [--corpus DIR] [--json OUT.json] [--fail-under-f1 F]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import time

# Bucket names are discovered from the corpus so held-out sets slot in
# without editing this file.
BUCKET_ORDER = ["benign", "dangerous", "obfuscated", "edge"]


def load_corpus(corpus_dir: str) -> list[dict]:
    records: list[dict] = []
    for path in sorted(glob.glob(os.path.join(corpus_dir, "*.jsonl"))):
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise SystemExit(f"{path}:{lineno}: corpus is not valid JSON: {exc}")
    if not records:
        raise SystemExit(f"no corpus records found under {corpus_dir!r}")
    return records


def gate_path(spec: str) -> str:
    """Normalise a gate path for the host platform.

    Windows cannot launch a *relative* path written with forward slashes:
    subprocess.run(["rust/target/release/agentgate-baseline"]) raises
    FileNotFoundError there, while the backslash spelling works with or without
    the .exe suffix. normpath converts separators on Windows and is a no-op on
    POSIX, so a single documented command line works on both.
    """
    return os.path.normpath(spec)


def run_gate(binary: str, records: list[dict]) -> tuple[dict[str, dict], float]:
    """Feed the corpus to a gate binary and collect its verdicts."""
    binary = gate_path(binary)
    payload = "".join(
        json.dumps({"id": r["id"], "cmd": r["cmd"]}, ensure_ascii=False) + "\n" for r in records
    )
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            [binary],
            input=payload.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except FileNotFoundError:
        raise SystemExit(f"gate binary not found: {binary}\nbuild it first (see REPRODUCTION.md)")
    except subprocess.TimeoutExpired:
        raise SystemExit(f"gate binary timed out: {binary}")
    elapsed = time.perf_counter() - started

    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(f"{binary} exited {proc.returncode}")

    out: dict[str, dict] = {}
    for lineno, line in enumerate(proc.stdout.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{binary}: output line {lineno} is not JSON: {exc}")
        out[rec["id"]] = rec
    return out, elapsed


def score(records: list[dict], verdicts: dict[str, dict]) -> dict:
    tp = fp = tn = fn = 0
    exact_decision = 0
    exact_rule = 0
    rule_labelled = 0
    missing = 0
    per_bucket: dict[str, dict] = {}
    failures: list[dict] = []

    for r in records:
        got = verdicts.get(r["id"])
        bucket = r["bucket"]
        per_bucket.setdefault(bucket, {"n": 0, "correct": 0, "fn": 0, "fp": 0})
        per_bucket[bucket]["n"] += 1
        if got is None:
            missing += 1
            continue

        want_escalate = r["expect"] != "ALLOW"
        got_escalate = got["decision"] != "ALLOW"

        if want_escalate and got_escalate:
            tp += 1
        elif want_escalate and not got_escalate:
            fn += 1
            per_bucket[bucket]["fn"] += 1
            failures.append({"id": r["id"], "kind": "false_negative", "cmd": r["cmd"],
                             "expect": r["expect"], "got": got["decision"], "rule": got["rule"]})
        elif not want_escalate and got_escalate:
            fp += 1
            per_bucket[bucket]["fp"] += 1
            failures.append({"id": r["id"], "kind": "false_positive", "cmd": r["cmd"],
                             "expect": r["expect"], "got": got["decision"], "rule": got["rule"]})
        else:
            tn += 1

        if want_escalate == got_escalate:
            per_bucket[bucket]["correct"] += 1
        if got["decision"] == r["expect"]:
            exact_decision += 1
        # An empty ground-truth rule means several rule ids are defensible, so
        # the record is excluded from the exact-rule denominator rather than
        # counted as a failure.
        if r["rule"]:
            rule_labelled += 1
            if got["rule"] == r["rule"]:
                exact_rule += 1

    n = len(records)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "n": n,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "missing": missing,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "escalation_accuracy": (tp + tn) / n if n else 0.0,
        "exact_decision_accuracy": exact_decision / n if n else 0.0,
        "exact_rule_accuracy": exact_rule / rule_labelled if rule_labelled else 0.0,
        "per_bucket": per_bucket,
        "failures": failures,
    }


def pct(x: float) -> str:
    return f"{100 * x:6.2f}%"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gate", action="append", required=True, metavar="NAME=PATH",
                    help="a gate to score; repeatable")
    ap.add_argument("--corpus", default=os.path.join(os.path.dirname(__file__), "..", "corpus"))
    ap.add_argument("--json", dest="json_out", help="write full results here")
    ap.add_argument("--show-failures", action="store_true", help="list every misclassified record")
    ap.add_argument("--fail-under-f1", type=float, default=None, metavar="F",
                    help="exit non-zero if any gate scores below this F1")
    args = ap.parse_args()

    records = load_corpus(os.path.abspath(args.corpus))
    results: dict[str, dict] = {}

    for spec in args.gate:
        if "=" not in spec:
            raise SystemExit(f"--gate expects NAME=PATH, got {spec!r}")
        name, path = spec.split("=", 1)
        verdicts, elapsed = run_gate(path, records)
        s = score(records, verdicts)
        s["elapsed_s"] = elapsed
        s["throughput_cmds_per_s"] = len(records) / elapsed if elapsed else 0.0
        s["binary"] = path
        results[name] = s

    print(f"corpus: {len(records)} records from {os.path.relpath(args.corpus)}")
    print()
    header = f"{'gate':<12}{'F1':>9}{'precis':>9}{'recall':>9}{'miss':>7}{'false-al':>10}{'exact-dec':>11}{'exact-rule':>12}"
    print(header)
    print("-" * len(header))
    for name, s in results.items():
        print(f"{name:<12}{pct(s['f1'])}{pct(s['precision'])}{pct(s['recall'])}"
              f"{s['fn']:>7}{s['fp']:>10}{pct(s['exact_decision_accuracy']):>11}"
              f"{pct(s['exact_rule_accuracy']):>12}")
    print()
    print("miss     = dangerous command allowed to run unattended (false negative)")
    print("false-al = safe command sent for human approval (false positive)")
    print()

    seen_buckets = []
    for s_ in results.values():
        for b in s_["per_bucket"]:
            if b not in seen_buckets:
                seen_buckets.append(b)
    seen_buckets.sort(key=lambda b: (BUCKET_ORDER.index(b) if b in BUCKET_ORDER else 99, b))

    print(f"{'bucket':<20}" + "".join(f"{n:>22}" for n in results))
    print("-" * (20 + 22 * len(results)))
    for b in seen_buckets:
        row = f"{b:<20}"
        for _, s in results.items():
            pb = s["per_bucket"].get(b, {"n": 0, "correct": 0})
            row += f"{pb['correct']:>14}/{pb['n']:<7}"
        print(row)
    print()

    if args.show_failures:
        for name, s in results.items():
            if not s["failures"]:
                continue
            print(f"--- {name}: {len(s['failures'])} misclassified ---")
            for fail in s["failures"]:
                mark = "MISS" if fail["kind"] == "false_negative" else "FALSE-ALARM"
                print(f"  [{mark:<11}] {fail['id']}  want={fail['expect']:<5} got={fail['got']:<5} "
                      f"({fail['rule']})\n      {fail['cmd']!r}")
            print()

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, sort_keys=True)
        print(f"wrote {args.json_out}")

    if args.fail_under_f1 is not None:
        for name, s in results.items():
            if s["f1"] < args.fail_under_f1:
                print(f"FAIL: {name} F1 {s['f1']:.4f} < threshold {args.fail_under_f1}", file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
