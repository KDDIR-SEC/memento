#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Phase 7 evaluation runner
#
# Runs the evaluation for one pattern automatically:
#   set the host JSONL aside -> start rndlogd -> run rdrand_bench in the guest ->
#   collect the guest log -> stop rndlogd -> read drop_count -> match with
#   rndlog-verify -> append the result to the TSV.
#
# Prerequisites:
#   - the modified kvm-intel is loaded in real-random mode (rndlog_deterministic=0)
#   - the guest VM is running and reachable over SSH (default ubuntu@localhost:2222)
#   - root privileges (debugfs, /var/log, rndlogd); run with sudo
#   - guest SSH authentication: SSH keys are recommended. For password
#     authentication set the SSHPASS environment variable and install sshpass
#     (`SSHPASS=ubuntu sudo -E scripts/eval/run-benchmark.sh ...`)
#
# Usage:
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
NATIVE=0   # --native: measure the same pattern unmonitored (stock kvm-intel) and emit a native baseline row
RATE=0     # --rate R: issue rate cap in ops/sec (0 = unlimited = performance run / >0 = capture accuracy run)

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

# results.tsv header (handler_ns column appended at the end). Shared by both paths.
RESULTS_HEADER='pattern\tinst\tcount\tthreads\ttime_s\tns_per_op\thost_lines\tdrop_count\tmatched\tmissing\tmatch_rate\thandler_ns'

# Pattern -> rdrand_bench arguments. RUN_THREADS is the actual thread count recorded in
# results.tsv (A/B/C are fixed to a single thread; kept separate because writing $THREADS
# as is would make the report misjudge parallelism).
case "$PATTERN" in
	A) BENCH_ARGS=(--inst rdrand --bits 64 --threads 1); INST_LABEL="RDRAND r64"; RUN_THREADS=1;;
	B) BENCH_ARGS=(--inst rdseed --bits 64 --threads 1); INST_LABEL="RDSEED r64"; RUN_THREADS=1;;
	C) BENCH_ARGS=(--inst both   --bits all --threads 1); INST_LABEL="mixed"; RUN_THREADS=1;;
	D) BENCH_ARGS=(--inst both   --bits 64 --threads "$THREADS"); INST_LABEL="multithread(${THREADS})"; RUN_THREADS="$THREADS";;
	native) BENCH_ARGS=(--inst rdrand --bits 64 --threads 1); INST_LABEL="native RDRAND r64"; THREADS=1; RUN_THREADS=1; NATIVE=1;;
	*) echo "bad --pattern (A|B|C|D[, --native]|native)"; exit 2;;
esac
BENCH_ARGS+=(--count "$COUNT" --output /tmp/guest_values.bin)
# Pass the rate to bench only when given (unset = full speed = performance run; bench defaults to unlimited).
[[ "$RATE" != 0 ]] && BENCH_ARGS+=(--rate "$RATE")

# SSH/SCP wrappers (through sshpass when SSHPASS is set). Defined first because both the native and monitored paths use them.
ssh_cmd() { if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null; then sshpass -e ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "$@"; else ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "$@"; fi; }
scp_cmd() { if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null; then sshpass -e scp -o StrictHostKeyChecking=no -P "$SSH_PORT" "$@"; else scp -o StrictHostKeyChecking=no -P "$SSH_PORT" "$@"; fi; }

# native (OFF) mode: measure the guest's bare RDRAND latency unmonitored (stock kvm-intel).
# No recording or verify; only ns/op is taken and a baseline row (verify/handler columns NA)
# is appended to results.tsv. report.py uses this row as the reference for the per-pattern
# slowdown and the three-way breakdown (pattern=native[-X]).
if [[ "$NATIVE" == 1 ]]; then
	# Row label: plain `--pattern native` is "native", `--pattern X --native` is "native-X"
	[[ "$PATTERN" == native ]] && NLABEL="native" || NLABEL="native-${PATTERN}"
	if [[ -e "$DEBUGFS/buffer" ]]; then
		echo "WARN: $DEBUGFS exists, so the modified module is loaded. For a true native (pass-through) run"
		echo "      load the stock kvm-intel: sudo rmmod kvm_intel kvm && sudo modprobe kvm_intel"
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
	echo "   [capture accuracy run] rate=${RATE} ops/s. Expect missing=0/drop=0 (§24.1)."
else
	echo "   [performance run] full rate. The goal is ns/op and handler(ii) (§24.2/§5.2)."
	echo "   Note: at full speed missing>0 can occur at the capture throughput limit (not used for §24.1)."
fi

# 0) Prerequisite checks
[[ -e "$DEBUGFS/buffer" ]] || { echo "ERROR: $DEBUGFS is missing (modified module not loaded?)"; exit 1; }
det=$(cat /sys/module/kvm_intel/parameters/rndlog_deterministic 2>/dev/null || echo "?")
[[ "$det" == "N" || "$det" == "0" ]] || echo "WARN: rndlog_deterministic=$det (possibly not in real-random mode)"
echo 1 > "$DEBUGFS/enabled"

# Extract one stats field (empty if absent)
stat_get() { sed -n "s/^$1:[[:space:]]*\([0-9]*\).*/\1/p" "$DEBUGFS/stats" 2>/dev/null; }

# Handler timing is cumulative, so derive the per-pattern value from the delta around the bench (§5.2 breakdown).
HCALL0=$(stat_get handler_calls)
HCYC0=$(stat_get handler_cycles_total)

# 1) Build the tools
make -C "$REPO_DIR/guest/rdrand_test" bench >/dev/null
make -C "$REPO_DIR/tools/rndlog-verify" >/dev/null

# 2) Set the host JSONL aside (isolate this run)
[[ -f "$HOST_LOG" ]] && mv -f "$HOST_LOG" "${HOST_LOG}.$(date +%s).bak" 2>/dev/null || true
mkdir -p "$(dirname "$HOST_LOG")"; chmod 0700 "$(dirname "$HOST_LOG")"
: > "$HOST_LOG"; chmod 0600 "$HOST_LOG"

# 3) Start rndlogd
"$REPO_DIR/host/rndlogd/rndlogd" -o "$HOST_LOG" -i 20 &
RNDLOGD_PID=$!
sleep 1

# 4) Run the bench in the guest
echo "-- guest: rdrand_bench ${BENCH_ARGS[*]}"
scp_cmd "$REPO_DIR/guest/rdrand_test/rdrand_bench" "${GUEST}:/tmp/rdrand_bench" >/dev/null
BENCH_OUT=$(ssh_cmd "$GUEST" "/tmp/rdrand_bench ${BENCH_ARGS[*]}")
echo "   $BENCH_OUT"
TIME_S=$(sed -n 's/.*time_s=\([0-9.]*\).*/\1/p' <<<"$BENCH_OUT")
NSOP=$(sed -n 's/.*ns_per_op=\([0-9.]*\).*/\1/p' <<<"$BENCH_OUT")

# 5) Collect the guest log
scp_cmd "${GUEST}:/tmp/guest_values.bin" "$WORK/guest_values.bin" >/dev/null

# 6) Wait until the ring buffer is empty (rndlogd has drained every record), then stop.
#    A fixed sleep could kill it before draining and lose records, so poll buffer_used==0 for up to 30s.
for _ in $(seq 1 300); do
	used=$(stat_get buffer_used)
	[[ "${used:-1}" == "0" ]] && break
	sleep 0.1
done
used=$(stat_get buffer_used)
[[ "${used:-0}" == "0" ]] || echo "WARN: buffer_used=${used} (still not drained after 30s; records may be lost)"
kill "$RNDLOGD_PID" 2>/dev/null || true
wait "$RNDLOGD_PID" 2>/dev/null || true

# 7) drop_count / host record count
DROP=$(cat "$DEBUGFS/drop_count" 2>/dev/null || echo "?")
HOST_LINES=$(wc -l < "$HOST_LOG" | tr -d ' ')

# 7a) Capture consistency: show enqueued (total_records) / delivered (consumed) / host line count.
#     Empty on old modules without consumed. total==consumed==host with drop 0 is a true 100%.
TOTAL_REC=$(stat_get total_records)
CONSUMED=$(stat_get consumed)
echo "-- capture: total_records=${TOTAL_REC:-?} consumed=${CONSUMED:-NA} host_lines=${HOST_LINES} drop=${DROP}"

# 7b) Derive in-handler processing (ii) per pattern from the delta around the bench (round trip (i) = monitored-native-(ii))
HCALL1=$(stat_get handler_calls)
HCYC1=$(stat_get handler_cycles_total)
TSCKHZ=$(stat_get tsc_khz)
HANDLER_NS=NA
if [[ -n "$HCALL0" && -n "$HCALL1" && -n "$HCYC0" && -n "$HCYC1" && -n "$TSCKHZ" ]]; then
	DCALLS=$(( HCALL1 - HCALL0 )); DCYC=$(( HCYC1 - HCYC0 ))
	if (( DCALLS > 0 && TSCKHZ > 0 )); then
		# handler_ns = (dcyc/dcalls) cycles -> ns: *1e6/tsc_khz. Integer approximation without bc.
		HANDLER_NS=$(awk -v c="$DCYC" -v n="$DCALLS" -v k="$TSCKHZ" 'BEGIN{printf "%.1f", (c/n)*1000000.0/k}')
		echo "-- handler(ii): Δcalls=${DCALLS} Δcyc=${DCYC} → ${HANDLER_NS} ns/instruction (part of ns/op=${NSOP:-?})"
	fi
fi
[[ "$HANDLER_NS" == NA ]] && echo "-- handler(ii): not measurable (no handler_cycles_total in stats; old module?)"

# 8) Match
echo "-- verify"
VERIFY=$("$REPO_DIR/tools/rndlog-verify/rndlog-verify" --guest-log "$WORK/guest_values.bin" --host-log "$HOST_LOG" || true)
echo "$VERIFY" | sed 's/^/   /'
MATCHED=$(sed -n 's/^matched:\s*\([0-9]*\).*/\1/p' <<<"$VERIFY")
MISSING=$(sed -n 's/^missing:\s*\([0-9]*\).*/\1/p' <<<"$VERIFY")
RATE=$(sed -n 's/^match rate:\s*\([0-9.]*\)%.*/\1/p' <<<"$VERIFY")

# 9) Append to the results TSV
[[ -f "$RESULTS" ]] || printf "${RESULTS_HEADER}\n" > "$RESULTS"
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
	"$PATTERN" "$INST_LABEL" "$COUNT" "$RUN_THREADS" "${TIME_S:-NA}" "${NSOP:-NA}" \
	"$HOST_LINES" "$DROP" "${MATCHED:-NA}" "${MISSING:-NA}" "${RATE:-NA}" "${HANDLER_NS:-NA}" >> "$RESULTS"

echo "== done: drop_count=$DROP missing=${MISSING:-?} match_rate=${RATE:-?}% → $RESULTS =="
[[ "${MISSING:-1}" == "0" && "$DROP" == "0" ]] && echo "RESULT: PASS (capture rate 100% / drop 0)" || echo "RESULT: CHECK (check missing/drop)"
