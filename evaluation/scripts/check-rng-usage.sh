#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# check-rng-usage.sh - 監視対象プロセスが RDRAND/RDSEED を駆動するかの事前検証
#
# ストレージ評価の前提として、nginx/ssh 等が「RDRAND/RDSEED 経由」で乱数を取得しているかを
# 二方式で確認する:
#   (1) 静的: バイナリ/共有ライブラリに rdrand/rdseed 命令が含まれるか（objdump、ゲスト内）。
#       ※ 含まれていても実行されるとは限らない（あくまで可能性）。
#   (2) 動的: カーネル debugfs stats の total_records 差分を短窓で比較し、idle 比で各負荷が
#       実際に捕捉数を増やすか（＝ゲストで RDRAND/RDSEED を実行しているか）を確定する。
#
# 前提: 改造 kvm-intel ロード済み・ゲスト起動済み・provision-guest-server.sh 実行済み。
# 使い方（root 必須: debugfs 読み出し）:
#   SSHPASS=ubuntu sudo -E ./scripts/eval/check-rng-usage.sh [--window 30]
set -euo pipefail

SSH_PORT=2222
GUEST=ubuntu@localhost
DEBUGFS=/sys/kernel/debug/kvm_rndlog
WIN=30

while [[ $# -gt 0 ]]; do
	case "$1" in
		--port)   SSH_PORT="$2"; shift 2;;
		--guest)  GUEST="$2"; shift 2;;
		--window) WIN="$2"; shift 2;;
		-h|--help) echo "usage: SSHPASS=ubuntu sudo -E $0 [--window 30]"; exit 0;;
		*) echo "unknown arg: $1"; exit 2;;
	esac
done

ssh_cmd() { if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null; then sshpass -e ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "$@"; else ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "$@"; fi; }
stat_get() { sed -n "s/^$1:[[:space:]]*\([0-9]*\).*/\1/p" "$DEBUGFS/stats" 2>/dev/null; }

[[ -e "$DEBUGFS/stats" ]] || { echo "ERROR: $DEBUGFS が無い（改造モジュール未ロード？）"; exit 1; }
echo 1 > "$DEBUGFS/enabled"

echo "=========================================================="
echo " (1) 静的解析: rdrand/rdseed 命令の有無（ゲスト内 objdump）"
echo "=========================================================="
ssh_cmd "$GUEST" 'bash -s' <<'REMOTE'
set -e
command -v objdump >/dev/null || { echo "objdump 不在（binutils 未導入）。provision-guest-server.sh を先に実行してください。"; exit 0; }
libs=$(ldconfig -p | sed -n 's/.* => //p' | grep -E '/libcrypto\.so|/libssl\.so|/libc\.so' | sort -u)
for f in /usr/sbin/sshd /usr/sbin/nginx $libs; do
	[ -r "$f" ] || continue
	n=$(objdump -d "$f" 2>/dev/null | grep -icE '\<rdrand\>|\<rdseed\>' || true)
	printf '  %-48s rdrand/rdseed 命令数: %s\n' "$f" "$n"
done
REMOTE

echo
echo "=========================================================="
echo " (2) 動的解析: idle 比の total_records 増分（各 ${WIN}s）"
echo "=========================================================="

start_load() { # $1 = guest shell command (loop body)
	ssh_cmd "$GUEST" "nohup bash -c '$1 # RNDLOG_CHK_LOAD' >/dev/null 2>&1 & echo started" >/dev/null || true
}
stop_load() {
	ssh_cmd "$GUEST" 'pkill -f RNDLOG_CHK_LOAD 2>/dev/null; pkill -f "curl -sk https://localhost" 2>/dev/null; pkill -f "localhost true" 2>/dev/null; true' >/dev/null 2>&1 || true
	sleep 1
}

probe() { # $1 = label   $2 = loop body (空文字なら idle)
	local before after delta rate
	[[ -n "$2" ]] && start_load "$2"
	before=$(stat_get total_records)
	sleep "$WIN"
	after=$(stat_get total_records)
	[[ -n "$2" ]] && stop_load
	delta=$(( ${after:-0} - ${before:-0} ))
	rate=$(awk -v d="$delta" -v w="$WIN" 'BEGIN{printf "%.1f", (w>0 ? d/w : 0)}')
	printf '  %-12s : Δtotal_records=%-10s (~%s rec/s)\n' "$1" "$delta" "$rate"
}

probe_rngd() { # rngd（rng-tools5）はデーモンのため loop ではなく start/stop で計る。起動バーストを含む。
	local before after delta rate
	ssh_cmd "$GUEST" 'sudo pkill -x rngd 2>/dev/null; true' >/dev/null 2>&1 || true
	sleep 1
	before=$(stat_get total_records)
	ssh_cmd "$GUEST" 'sudo nohup rngd -f >/dev/null 2>&1 & echo started' >/dev/null 2>&1 || true
	sleep "$WIN"
	ssh_cmd "$GUEST" 'sudo pkill -x rngd 2>/dev/null; true' >/dev/null 2>&1 || true
	after=$(stat_get total_records)
	delta=$(( ${after:-0} - ${before:-0} ))
	rate=$(awk -v d="$delta" -v w="$WIN" 'BEGIN{printf "%.1f", (w>0 ? d/w : 0)}')
	printf '  %-12s : Δtotal_records=%-10s (~%s rec/s, 起動バースト含む)\n' "rngd" "$delta" "$rate"
}

probe "idle"      ""
probe "nginx-tls" 'while :; do curl -sk https://localhost/ -o /dev/null; done'
probe "ssh-kex"   'while :; do sshpass -p ubuntu ssh -o StrictHostKeyChecking=no localhost true; done'
probe_rngd        # RDRAND を駆動する想定のデーモン（rng-tools5）

echo
echo "rngd が Δ≈0 の場合: 既定で jitter 等が選ばれている可能性。'rngd -f -x jitter' 等で rdrand を"
echo "明示し再確認する（rng-tools5 のソース名は版差あり）。起動バーストのみで定常 0 なら近代カーネルの"
echo "プール満杯による（§ ドキュメント参照）。"
echo
echo "判定の目安: idle 比で増分が有意なら、その負荷はゲストで RDRAND/RDSEED を実行している"
echo "（＝ストレージに寄与）。idle と同等なら getrandom 等のカーネル経路で取得しており、"
echo "ハイパーバイザー層では追加捕捉されない（ストレージはカーネル CRNG 由来が支配的）。"
