#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Phase 7 評価実行スクリプト
#
# 1 パターン分の評価を自動実行する:
#   ホスト JSONL を退避 → rndlogd 起動 → ゲストで rdrand_bench 実行 →
#   ゲストログ回収 → rndlogd 停止 → drop_count 取得 → rndlog-verify で照合 →
#   結果を TSV に追記。
#
# 前提:
#   - 改造 kvm-intel が実乱数モード（rndlog_deterministic=0）でロード済み
#   - ゲスト VM が起動済みで SSH 可能（既定 ubuntu@localhost:2222）
#   - root 権限（debugfs / /var/log / rndlogd）。sudo で実行すること
#   - ゲスト SSH 認証: SSH 鍵を推奨。パスワード認証の場合は環境変数 SSHPASS を設定し
#     sshpass を導入（`SSHPASS=ubuntu sudo -E scripts/eval/run-benchmark.sh ...`）
#
# 使い方:
#   sudo -E scripts/eval/run-benchmark.sh --pattern A --count 1000000
#   sudo -E scripts/eval/run-benchmark.sh --pattern D --count 1000000 --threads 4

set -euo pipefail

PATTERN=""
COUNT=1000000
THREADS=4
SSH_PORT=2222
GUEST=ubuntu@localhost
HOST_LOG=/var/log/kvm-rndlog/vm1-prn.jsonl
DEBUGFS=/sys/kernel/debug/kvm_rndlog
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
RESULTS="${REPO_DIR}/scripts/eval/results.tsv"
WORK=/tmp/kvm-rndlog-eval
NATIVE=0   # --native: 監視なし(stock kvm-intel)で同パターンを測り native baseline 行を出す
RATE=0     # --rate R: 発行レート上限 ops/sec（0=無制限=性能 run / >0=捕捉精度 run）

usage() { echo "usage: sudo -E $0 --pattern A|B|C|D [--native] [--rate OPS] [--count N] [--threads T] [--results FILE]"; }

while [[ $# -gt 0 ]]; do
	case "$1" in
		--pattern) PATTERN="$2"; shift 2;;
		--native)  NATIVE=1; shift;;
		--rate)    RATE="$2"; shift 2;;
		--count)   COUNT="$2"; shift 2;;
		--threads) THREADS="$2"; shift 2;;
		--port)    SSH_PORT="$2"; shift 2;;
		--guest)   GUEST="$2"; shift 2;;
		--host-log) HOST_LOG="$2"; shift 2;;
		--results) RESULTS="$2"; shift 2;;
		-h|--help) usage; exit 0;;
		*) echo "unknown arg: $1"; usage; exit 2;;
	esac
done
[[ -n "$PATTERN" ]] || { usage; exit 2; }

# results.tsv ヘッダ（handler_ns 列を末尾に追加）。両パス共通で使う。
RESULTS_HEADER='pattern\tinst\tcount\tthreads\ttime_s\tns_per_op\thost_lines\tdrop_count\tmatched\tmissing\tmatch_rate\thandler_ns'

# パターン → rdrand_bench 引数。RUN_THREADS は results.tsv へ記録する実スレッド数
# （A/B/C は単一スレッド固定。$THREADS をそのまま書くと報告の並列判定を誤るため分ける）。
case "$PATTERN" in
	A) BENCH_ARGS=(--inst rdrand --bits 64 --threads 1); INST_LABEL="RDRAND r64"; RUN_THREADS=1;;
	B) BENCH_ARGS=(--inst rdseed --bits 64 --threads 1); INST_LABEL="RDSEED r64"; RUN_THREADS=1;;
	C) BENCH_ARGS=(--inst both   --bits all --threads 1); INST_LABEL="mixed"; RUN_THREADS=1;;
	D) BENCH_ARGS=(--inst both   --bits 64 --threads "$THREADS"); INST_LABEL="multithread(${THREADS})"; RUN_THREADS="$THREADS";;
	native) BENCH_ARGS=(--inst rdrand --bits 64 --threads 1); INST_LABEL="native RDRAND r64"; THREADS=1; RUN_THREADS=1; NATIVE=1;;
	*) echo "bad --pattern (A|B|C|D[, --native]|native)"; exit 2;;
esac
BENCH_ARGS+=(--count "$COUNT" --output /tmp/guest_values.bin)
# レート指定時のみ bench へ渡す（未指定=全力=性能 run。bench 既定は無制限）。
[[ "$RATE" != 0 ]] && BENCH_ARGS+=(--rate "$RATE")

# SSH/SCP ラッパ（SSHPASS があれば sshpass 経由）。native/監視の両パスで使うため先に定義する。
ssh_cmd() { if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null; then sshpass -e ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "$@"; else ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "$@"; fi; }
scp_cmd() { if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null; then sshpass -e scp -o StrictHostKeyChecking=no -P "$SSH_PORT" "$@"; else scp -o StrictHostKeyChecking=no -P "$SSH_PORT" "$@"; fi; }

# native(OFF) モード: 監視なし（stock kvm-intel）でゲストの素の RDRAND 遅延を測る。
# 記録/verify は行わず ns/op のみ取得し、results.tsv に baseline 行（verify/handler 系列は NA）を追記する。
# report.py はこの行を per-pattern slowdown / 3 分解の基準（pattern=native[-X]）として使う。
if [[ "$NATIVE" == 1 ]]; then
	# 行ラベル: 単独 `--pattern native` は "native"、`--pattern X --native` は "native-X"
	[[ "$PATTERN" == native ]] && NLABEL="native" || NLABEL="native-${PATTERN}"
	if [[ -e "$DEBUGFS/buffer" ]]; then
		echo "WARN: $DEBUGFS が存在＝改造モジュールがロード中。真の native(パススルー) 測定には"
		echo "      stock kvm-intel をロードすること: sudo rmmod kvm_intel kvm && sudo modprobe kvm_intel"
	fi
	make -C "$REPO_DIR/guest/rdrand_test" bench >/dev/null
	echo "-- guest(${NLABEL}): rdrand_bench ${BENCH_ARGS[*]}"
	scp_cmd "$REPO_DIR/guest/rdrand_test/rdrand_bench" "${GUEST}:/tmp/rdrand_bench" >/dev/null
	BENCH_OUT=$(ssh_cmd "$GUEST" "/tmp/rdrand_bench ${BENCH_ARGS[*]}")
	echo "   $BENCH_OUT"
	TIME_S=$(sed -n 's/.*time_s=\([0-9.]*\).*/\1/p' <<<"$BENCH_OUT")
	NSOP=$(sed -n 's/.*ns_per_op=\([0-9.]*\).*/\1/p' <<<"$BENCH_OUT")
	[[ -f "$RESULTS" ]] || printf "${RESULTS_HEADER}\n" > "$RESULTS"
	printf '%s\t%s\t%s\t%s\t%s\t%s\tNA\tNA\tNA\tNA\tNA\tNA\n' \
		"$NLABEL" "$INST_LABEL" "$COUNT" "$RUN_THREADS" "${TIME_S:-NA}" "${NSOP:-NA}" >> "$RESULTS"
	echo "== ${NLABEL} baseline: ns/op=${NSOP:-?} → $RESULTS =="
	exit 0
fi

mkdir -p "$WORK"

echo "== Phase 7 benchmark: pattern=$PATTERN count=$COUNT rate=${RATE} =="
if [[ "$RATE" != 0 ]]; then
	echo "   [捕捉精度 run] rate=${RATE} ops/s。missing=0/drop=0 を期待（§24.1）。"
else
	echo "   [性能 run] full-rate。ns/op と handler(ii) が目的（§24.2/§5.2）。"
	echo "   注: 全力時は捕捉スループット上限で missing>0 になり得る（§24.1 には用いない）。"
fi

# 0) 前提チェック
[[ -e "$DEBUGFS/buffer" ]] || { echo "ERROR: $DEBUGFS が無い（改造モジュール未ロード？）"; exit 1; }
det=$(cat /sys/module/kvm_intel/parameters/rndlog_deterministic 2>/dev/null || echo "?")
[[ "$det" == "N" || "$det" == "0" ]] || echo "WARN: rndlog_deterministic=$det（実乱数モードでない可能性）"
echo 1 > "$DEBUGFS/enabled"

# stats の 1 フィールドを取り出す（無ければ空）
stat_get() { sed -n "s/^$1:[[:space:]]*\([0-9]*\).*/\1/p" "$DEBUGFS/stats" 2>/dev/null; }

# ハンドラ計時は累積のため、bench 前後の delta で per-pattern 値を出す（§5.2 内訳）。
HCALL0=$(stat_get handler_calls)
HCYC0=$(stat_get handler_cycles_total)

# 1) ツールをビルド
make -C "$REPO_DIR/guest/rdrand_test" bench >/dev/null
make -C "$REPO_DIR/tools/rndlog-verify" >/dev/null

# 2) ホスト JSONL を退避（このランを分離）
[[ -f "$HOST_LOG" ]] && mv -f "$HOST_LOG" "${HOST_LOG}.$(date +%s).bak" 2>/dev/null || true
mkdir -p "$(dirname "$HOST_LOG")"; chmod 0700 "$(dirname "$HOST_LOG")"
: > "$HOST_LOG"; chmod 0600 "$HOST_LOG"

# 3) rndlogd 起動
"$REPO_DIR/host/rndlogd/rndlogd" -o "$HOST_LOG" -i 20 &
RNDLOGD_PID=$!
sleep 1

# 4) ゲストで bench 実行
echo "-- guest: rdrand_bench ${BENCH_ARGS[*]}"
scp_cmd "$REPO_DIR/guest/rdrand_test/rdrand_bench" "${GUEST}:/tmp/rdrand_bench" >/dev/null
BENCH_OUT=$(ssh_cmd "$GUEST" "/tmp/rdrand_bench ${BENCH_ARGS[*]}")
echo "   $BENCH_OUT"
TIME_S=$(sed -n 's/.*time_s=\([0-9.]*\).*/\1/p' <<<"$BENCH_OUT")
NSOP=$(sed -n 's/.*ns_per_op=\([0-9.]*\).*/\1/p' <<<"$BENCH_OUT")

# 5) ゲストログ回収
scp_cmd "${GUEST}:/tmp/guest_values.bin" "$WORK/guest_values.bin" >/dev/null

# 6) リングバッファが空になる（rndlogd が全レコードを排出）まで待ってから停止する。
#    固定 sleep だと排出前に kill して取りこぼすため、buffer_used==0 を最大 30s ポーリング。
for _ in $(seq 1 300); do
	used=$(stat_get buffer_used)
	[[ "${used:-1}" == "0" ]] && break
	sleep 0.1
done
used=$(stat_get buffer_used)
[[ "${used:-0}" == "0" ]] || echo "WARN: buffer_used=${used}（30s 経過後も未排出。取りこぼしの可能性）"
kill "$RNDLOGD_PID" 2>/dev/null || true
wait "$RNDLOGD_PID" 2>/dev/null || true

# 7) drop_count / host 件数
DROP=$(cat "$DEBUGFS/drop_count" 2>/dev/null || echo "?")
HOST_LINES=$(wc -l < "$HOST_LOG" | tr -d ' ')

# 7a) 捕捉整合性: enqueue(total_records) / 配信(consumed) / host 行数 を表示。
#     consumed が無い旧モジュールでは空欄。total==consumed==host & drop0 が真の 100%。
TOTAL_REC=$(stat_get total_records)
CONSUMED=$(stat_get consumed)
echo "-- capture: total_records=${TOTAL_REC:-?} consumed=${CONSUMED:-NA} host_lines=${HOST_LINES} drop=${DROP}"

# 7b) ハンドラ内処理(ii) を bench 前後 delta から per-pattern 算出（往復(i)=monitored−native−(ii)）
HCALL1=$(stat_get handler_calls)
HCYC1=$(stat_get handler_cycles_total)
TSCKHZ=$(stat_get tsc_khz)
HANDLER_NS=NA
if [[ -n "$HCALL0" && -n "$HCALL1" && -n "$HCYC0" && -n "$HCYC1" && -n "$TSCKHZ" ]]; then
	DCALLS=$(( HCALL1 - HCALL0 )); DCYC=$(( HCYC1 - HCYC0 ))
	if (( DCALLS > 0 && TSCKHZ > 0 )); then
		# handler_ns = (dcyc/dcalls) cycles → ns:  *1e6/tsc_khz。bc が無ければ整数近似。
		HANDLER_NS=$(awk -v c="$DCYC" -v n="$DCALLS" -v k="$TSCKHZ" 'BEGIN{printf "%.1f", (c/n)*1000000.0/k}')
		echo "-- handler(ii): Δcalls=${DCALLS} Δcyc=${DCYC} → ${HANDLER_NS} ns/命令（ns/op=${NSOP:-?} の内訳）"
	fi
fi
[[ "$HANDLER_NS" == NA ]] && echo "-- handler(ii): 計測不可（stats に handler_cycles_total が無い＝旧モジュール？）"

# 8) 照合
echo "-- verify"
VERIFY=$("$REPO_DIR/tools/rndlog-verify/rndlog-verify" --guest-log "$WORK/guest_values.bin" --host-log "$HOST_LOG" || true)
echo "$VERIFY" | sed 's/^/   /'
MATCHED=$(sed -n 's/^matched:\s*\([0-9]*\).*/\1/p' <<<"$VERIFY")
MISSING=$(sed -n 's/^missing:\s*\([0-9]*\).*/\1/p' <<<"$VERIFY")
RATE=$(sed -n 's/^match rate:\s*\([0-9.]*\)%.*/\1/p' <<<"$VERIFY")

# 9) 結果 TSV へ追記
[[ -f "$RESULTS" ]] || printf "${RESULTS_HEADER}\n" > "$RESULTS"
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
	"$PATTERN" "$INST_LABEL" "$COUNT" "$RUN_THREADS" "${TIME_S:-NA}" "${NSOP:-NA}" \
	"$HOST_LINES" "$DROP" "${MATCHED:-NA}" "${MISSING:-NA}" "${RATE:-NA}" "${HANDLER_NS:-NA}" >> "$RESULTS"

echo "== done: drop_count=$DROP missing=${MISSING:-?} match_rate=${RATE:-?}% → $RESULTS =="
[[ "${MISSING:-1}" == "0" && "$DROP" == "0" ]] && echo "RESULT: PASS（捕捉率100% / drop 0）" || echo "RESULT: CHECK（missing/drop を確認）"
