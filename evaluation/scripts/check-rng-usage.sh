#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# check-rng-usage.sh - pre-check whether monitored processes drive RDRAND/RDSEED
#
# As a prerequisite for the storage evaluation, check in two ways whether
# nginx, ssh and similar obtain random numbers "via RDRAND/RDSEED":
#   (1) Static: whether the binaries/shared libraries contain rdrand/rdseed
#       instructions (objdump, inside the guest).
#       Note: containing them does not mean they are executed (only possible).
#   (2) Dynamic: compare the total_records delta of the kernel debugfs stats
#       over a short window, and establish whether each load actually raises
#       the capture count relative to idle (that is, whether the guest
#       executes RDRAND/RDSEED).
#
# Prerequisites: modified kvm-intel loaded, guest running,
# provision-guest-server.sh already run.
# Usage (root required: reads debugfs):
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

[[ -e "$DEBUGFS/stats" ]] || { echo "ERROR: $DEBUGFS is missing (modified module not loaded?)"; exit 1; }
echo 1 > "$DEBUGFS/enabled"

echo "=========================================================="
echo " (1) Static analysis: rdrand/rdseed instructions present? (objdump in the guest)"
echo "=========================================================="
ssh_cmd "$GUEST" 'bash -s' <<'REMOTE'
set -e
command -v objdump >/dev/null || { echo "objdump not found (binutils not installed). Run provision-guest-server.sh first."; exit 0; }
libs=$(ldconfig -p | sed -n 's/.* => //p' | grep -E '/libcrypto\.so|/libssl\.so|/libc\.so' | sort -u)
for f in /usr/sbin/sshd /usr/sbin/nginx $libs; do
	[ -r "$f" ] || continue
	n=$(objdump -d "$f" 2>/dev/null | grep -icE '\<rdrand\>|\<rdseed\>' || true)
	printf '  %-48s rdrand/rdseed instructions: %s\n' "$f" "$n"
done
REMOTE

echo
echo "=========================================================="
echo " (2) Dynamic analysis: total_records increase relative to idle (${WIN}s each)"
echo "=========================================================="

start_load() { # $1 = guest shell command (loop body)
	ssh_cmd "$GUEST" "nohup bash -c '$1 # RNDLOG_CHK_LOAD' >/dev/null 2>&1 & echo started" >/dev/null || true
}
stop_load() {
	ssh_cmd "$GUEST" 'pkill -f RNDLOG_CHK_LOAD 2>/dev/null; pkill -f "curl -sk https://localhost" 2>/dev/null; pkill -f "localhost true" 2>/dev/null; true' >/dev/null 2>&1 || true
	sleep 1
}

probe() { # $1 = label   $2 = loop body (empty string means idle)
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

probe_rngd() { # rngd (rng-tools5) is a daemon, so measure with start/stop rather than a loop. Includes the startup burst.
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
	printf '  %-12s : Δtotal_records=%-10s (~%s rec/s, incl. startup burst)\n' "rngd" "$delta" "$rate"
}

probe "idle"      ""
probe "nginx-tls" 'while :; do curl -sk https://localhost/ -o /dev/null; done'
probe "ssh-kex"   'while :; do sshpass -p ubuntu ssh -o StrictHostKeyChecking=no localhost true; done'
probe_rngd        # Daemon expected to drive RDRAND (rng-tools5)

echo
echo "If rngd shows Δ≈0: jitter or another source may be selected by default. Name rdrand"
echo "explicitly (e.g. 'rngd -f -x jitter') and check again (rng-tools5 source names differ by"
echo "version). If there is only a startup burst and 0 in steady state, the pool of a modern"
echo "kernel is full (see the documentation)."
echo
echo "Rule of thumb: if the increase over idle is significant, that load executes RDRAND/RDSEED"
echo "in the guest (it contributes to storage). If it equals idle, it obtains randomness through a"
echo "kernel path such as getrandom and nothing extra is captured at the hypervisor layer (storage"
echo "is dominated by data derived from the kernel CRNG)."
