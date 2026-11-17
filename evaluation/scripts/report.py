#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Phase 7 evaluation report generator.

Reads the results.tsv written by run-benchmark.sh and produces Markdown tables
for capture accuracy, performance and logging performance.

Usage:
    scripts/eval/report.py [results.tsv]      # default: scripts/eval/results.tsv
"""
import sys
import os
import csv


def load(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def fmt_int(s):
    try:
        return f"{int(s):,}"
    except (ValueError, TypeError):
        return str(s)


def is_native(r):
    return r["pattern"].lower().startswith("native")


def num(s):
    """Convert a string to float. NA, empty and non-numeric give None."""
    try:
        return float(s)
    except (ValueError, TypeError):
        return None


def native_base(rows, pattern):
    """Return the native baseline ns/op for pattern X.
    Prefer pattern==native-X, else the generic native. None if neither exists."""
    want = f"native-{pattern}".lower()
    row = next((r for r in rows if r["pattern"].lower() == want), None)
    if row is None:
        row = next((r for r in rows if r["pattern"].lower() == "native"), None)
    return num(row["ns_per_op"]) if row else None


def capture_table(rows):
    out = ["### 24.1 Capture accuracy", "",
           "| Test | Instruction | Count | Host Log | Drop | Match Rate |",
           "| ---- | ----------- | ----: | -------: | ---: | ---------: |"]
    for r in rows:
        out.append("| {p} | {i} | {c} | {h} | {d} | {m}% |".format(
            p=r["pattern"], i=r["inst"], c=fmt_int(r["count"]),
            h=fmt_int(r["host_lines"]), d=r["drop_count"], m=r["match_rate"]))
    return "\n".join(out)


def perf_table(eval_rows, all_rows):
    out = ["### 24.2 Performance", "",
           "| Pattern | Instruction | Count | Time(s) | ns/op | Slowdown |",
           "| ------- | ----------- | ----: | ------: | ----: | -------: |"]
    for r in eval_rows:
        ns = num(r["ns_per_op"])
        base = native_base(all_rows, r["pattern"])
        slow = f"{ns / base:.1f}x" if (ns and base) else "—"
        out.append("| {p} | {i} | {c} | {t} | {n} | {s} |".format(
            p=r["pattern"], i=r["inst"], c=fmt_int(r["count"]),
            t=r["time_s"], n=r["ns_per_op"], s=slow))
    return "\n".join(out)


def breakdown_table(eval_rows, all_rows, env=""):
    """§24.4 overhead breakdown (three parts): monitored / native / handler(ii) / roundtrip(i) / slowdown.
    Single-threaded (threads==1): roundtrip(i) = monitored - native - handler.
    Multi-threaded (D): ns/op is a parallel aggregate and cannot simply be subtracted,
    so roundtrip is "— (parallel)".
    env: label of the measurement environment ("nested", "bare-metal", ...), shown in the heading."""
    title = "### 24.4 Overhead breakdown (three parts" + (f", {env}" if env else "") + ")"
    out = [title, "",
           "| Pattern | monitored ns/op | native ns/op | handler(ii) ns | roundtrip(i) ns | slowdown |",
           "| ------- | --------------: | -----------: | -------------: | --------------: | -------: |"]
    for r in eval_rows:
        mon = num(r["ns_per_op"])
        nat = native_base(all_rows, r["pattern"])
        hnd = num(r.get("handler_ns"))
        threads = r.get("threads", "1")
        nat_s = f"{nat:.1f}" if nat else "—"
        hnd_s = f"{hnd:.1f}" if hnd else "—"
        slow = f"{mon / nat:.1f}x" if (mon and nat) else "—"
        if threads not in ("1", 1):
            rt_s = "— (parallel)"
        elif mon and nat is not None and hnd is not None:
            rt_s = f"{mon - nat - hnd:.1f}"
        else:
            rt_s = "—"
        out.append("| {p} | {m} | {nv} | {h} | {rt} | {s} |".format(
            p=r["pattern"], m=r["ns_per_op"], nv=nat_s, h=hnd_s, rt=rt_s, s=slow))
    out.append("")
    out.append("> roundtrip(i) = monitored − native − handler(ii) (single thread). "
               "For D, ns/op is an aggregate parallel throughput and cannot simply be broken down. "
               "handler(ii) is measured per call with rdtsc (for D it includes lock contention).")
    return "\n".join(out)


def log_table(rows):
    out = ["### 24.3 Logging performance", "",
           "| Pattern | Count | Drop | Host Log lines |",
           "| ------- | ----: | ---: | -------------: |"]
    for r in rows:
        out.append("| {p} | {c} | {d} | {h} |".format(
            p=r["pattern"], c=fmt_int(r["count"]),
            d=r["drop_count"], h=fmt_int(r["host_lines"])))
    return "\n".join(out)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(os.path.dirname(__file__), "results.tsv")
    # Second argument: measurement environment label shown with the breakdown table (optional, e.g. nested / bare-metal)
    env = sys.argv[2] if len(sys.argv) > 2 else ""
    if not os.path.exists(path):
        sys.exit(f"results not found: {path} (run run-benchmark.sh first)")
    rows = load(path)
    if not rows:
        sys.exit("results are empty")

    # native (OFF) rows (native / native-X) are only a reference; leave them out of capture accuracy, logging performance and the summary.
    eval_rows = [r for r in rows if not is_native(r)]

    print("# KVM RDRAND/RDSEED monitoring PoC — evaluation report\n")
    print(capture_table(eval_rows))
    print()
    print(perf_table(eval_rows, rows))
    print()
    print(breakdown_table(eval_rows, rows, env))
    print()
    print(log_table(eval_rows))
    print()
    # Summary (excluding native rows)
    miss = sum(0 if r["missing"] in ("0", "NA", "") else 1 for r in eval_rows)
    drops = sum(0 if r["drop_count"] in ("0", "?", "NA", "") else 1 for r in eval_rows)
    print("---")
    print(f"- Patterns: {len(eval_rows)}")
    print(f"- Patterns with missed captures (missing>0): {miss}")
    print(f"- Patterns with drop_count>0: {drops}")
    if eval_rows and miss == 0 and drops == 0:
        print("- **Overall: capture rate 100% / drop_count 0 for every pattern**")


if __name__ == "__main__":
    main()
