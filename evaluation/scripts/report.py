#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Phase 7 評価レポート生成。

run-benchmark.sh が出力する results.tsv を読み、捕捉精度・性能・ログ性能の
Markdown 表を生成する。

使い方:
    scripts/eval/report.py [results.tsv]      # 既定: scripts/eval/results.tsv
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
    """文字列を float 化。NA/空/非数値は None。"""
    try:
        return float(s)
    except (ValueError, TypeError):
        return None


def native_base(rows, pattern):
    """pattern X の native baseline ns/op を返す。
    優先: pattern==native-X、なければ汎用 native。無ければ None。"""
    want = f"native-{pattern}".lower()
    row = next((r for r in rows if r["pattern"].lower() == want), None)
    if row is None:
        row = next((r for r in rows if r["pattern"].lower() == "native"), None)
    return num(row["ns_per_op"]) if row else None


def capture_table(rows):
    out = ["### 24.1 捕捉精度", "",
           "| Test | Instruction | Count | Host Log | Drop | Match Rate |",
           "| ---- | ----------- | ----: | -------: | ---: | ---------: |"]
    for r in rows:
        out.append("| {p} | {i} | {c} | {h} | {d} | {m}% |".format(
            p=r["pattern"], i=r["inst"], c=fmt_int(r["count"]),
            h=fmt_int(r["host_lines"]), d=r["drop_count"], m=r["match_rate"]))
    return "\n".join(out)


def perf_table(eval_rows, all_rows):
    out = ["### 24.2 性能", "",
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
    """§24.4 オーバーヘッド内訳（3分解）: monitored / native / handler(ii) / roundtrip(i) / slowdown。
    単一スレッド（threads==1）は roundtrip(i)=monitored−native−handler。
    多スレッド（D）は ns/op が並列集約のため単純減算不可 → roundtrip は「—（並列）」。
    env: 測定環境ラベル（"nested" / "bare-metal" 等）。見出しに併記する。"""
    title = "### 24.4 オーバーヘッド内訳（3分解" + (f", {env}" if env else "") + "）"
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
            rt_s = "—（並列）"
        elif mon and nat is not None and hnd is not None:
            rt_s = f"{mon - nat - hnd:.1f}"
        else:
            rt_s = "—"
        out.append("| {p} | {m} | {nv} | {h} | {rt} | {s} |".format(
            p=r["pattern"], m=r["ns_per_op"], nv=nat_s, h=hnd_s, rt=rt_s, s=slow))
    out.append("")
    out.append("> roundtrip(i) = monitored − native − handler(ii)（単一スレッド）。"
               "D は ns/op が並列集約スループットのため単純分解不可。"
               "handler(ii) は per-call の rdtsc 実測（D は lock 競合を含む）。")
    return "\n".join(out)


def log_table(rows):
    out = ["### 24.3 ログ性能", "",
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
    # 第 2 引数: 内訳表に併記する測定環境ラベル（任意。例: nested / bare-metal）
    env = sys.argv[2] if len(sys.argv) > 2 else ""
    if not os.path.exists(path):
        sys.exit(f"results not found: {path}（先に run-benchmark.sh を実行）")
    rows = load(path)
    if not rows:
        sys.exit("results が空です")

    # native(OFF) 行（native / native-X）は基準専用。捕捉精度/ログ性能/総括からは除外する。
    eval_rows = [r for r in rows if not is_native(r)]

    print("# KVM RDRAND/RDSEED 監視 PoC — 評価レポート\n")
    print(capture_table(eval_rows))
    print()
    print(perf_table(eval_rows, rows))
    print()
    print(breakdown_table(eval_rows, rows, env))
    print()
    print(log_table(eval_rows))
    print()
    # 総括（native 行は除く）
    miss = sum(0 if r["missing"] in ("0", "NA", "") else 1 for r in eval_rows)
    drops = sum(0 if r["drop_count"] in ("0", "?", "NA", "") else 1 for r in eval_rows)
    print("---")
    print(f"- パターン数: {len(eval_rows)}")
    print(f"- 捕捉漏れ(missing>0)のパターン: {miss}")
    print(f"- drop_count>0 のパターン: {drops}")
    if eval_rows and miss == 0 and drops == 0:
        print("- **総合: 全パターンで捕捉率 100% / drop_count 0**")


if __name__ == "__main__":
    main()
