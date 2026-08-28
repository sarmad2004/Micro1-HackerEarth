#!/usr/bin/env python3
"""Throughput benchmark for the gate binaries.

A gate sits in the agent's critical path: every proposed command waits on it.
Latency that a human would not notice still matters when an agent issues
thousands of commands in a session, so throughput is a first-class property,
not a footnote.

The workload is built by repeating the corpus, so it mixes cheap commands
(`ls -la`) with the expensive ones (nested `sh -c`, base64 payloads, deep
pipelines) in realistic proportion.

Usage:
    python3 eval/bench.py --gate NAME=PATH [--gate ...] [--repeat N] [--rounds N]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import subprocess
import sys
import time


def load_corpus(corpus_dir: str) -> list[str]:
    cmds: list[str] = []
    for path in sorted(glob.glob(os.path.join(corpus_dir, "**", "*.jsonl"), recursive=True)):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    cmds.append(json.loads(line)["cmd"])
    if not cmds:
        raise SystemExit(f"no corpus records under {corpus_dir!r}")
    return cmds


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gate", action="append", required=True, metavar="NAME=PATH")
    ap.add_argument("--corpus", default=os.path.join(os.path.dirname(__file__), "..", "corpus"))
    ap.add_argument("--repeat", type=int, default=500, help="corpus repetitions per round")
    ap.add_argument("--rounds", type=int, default=5, help="timed rounds; the median is reported")
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args()

    cmds = load_corpus(os.path.abspath(args.corpus))
    workload = cmds * args.repeat
    payload = "".join(
        json.dumps({"id": str(i), "cmd": c}, ensure_ascii=False) + "\n"
        for i, c in enumerate(workload)
    ).encode("utf-8")

    print(f"workload: {len(workload)} commands ({len(payload) / 1e6:.1f} MB), "
          f"{args.rounds} rounds, median reported")
    print()
    header = f"{'gate':<14}{'cmds/sec':>14}{'MB/sec':>10}{'median s':>11}{'min s':>9}{'max s':>9}"
    print(header)
    print("-" * len(header))

    results: dict[str, dict] = {}
    for spec in args.gate:
        name, path = spec.split("=", 1)
        times: list[float] = []
        out_len = 0
        for _ in range(args.rounds):
            started = time.perf_counter()
            try:
                proc = subprocess.run(
                    [path], input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=600,
                )
            except FileNotFoundError:
                raise SystemExit(f"gate binary not found: {path}")
            elapsed = time.perf_counter() - started
            if proc.returncode != 0:
                sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
                raise SystemExit(f"{path} exited {proc.returncode}")
            out_len = len(proc.stdout)
            times.append(elapsed)

        median = statistics.median(times)
        rate = len(workload) / median
        mb = (len(payload) / 1e6) / median
        results[name] = {
            "binary": path,
            "commands": len(workload),
            "median_s": median,
            "min_s": min(times),
            "max_s": max(times),
            "cmds_per_s": rate,
            "mb_per_s": mb,
            "output_bytes": out_len,
        }
        print(f"{name:<14}{rate:>14,.0f}{mb:>10.1f}{median:>11.3f}{min(times):>9.3f}{max(times):>9.3f}")

    print()
    print("Includes process startup and full JSON Lines encode/decode on both sides,")
    print("so these are end-to-end figures, not analyzer-only microbenchmarks.")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, sort_keys=True)
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
