#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -u

if [[ $# -lt 1 || $# -gt 2 ]]; then
	echo "usage: $0 failed-init|loaded-initial|loaded|absent [DMESG_DELTA]" >&2
	exit 2
fi

mode=$1
dmesg_delta=${2:-}
debugfs_root=/sys/kernel/debug/kvm_rndlog
repo_root=$(realpath "$(dirname "$0")/..")
failures=0

pass() {
	printf '[PASS] %s\n' "$1"
}

fail() {
	printf '[FAIL] %s\n' "$1" >&2
	failures=$((failures + 1))
}

check_intel_absent() {
	if [[ ! -e /sys/module/kvm_intel ]]; then
		pass "kvm_intel is not loaded"
	else
		fail "kvm_intel remains loaded"
	fi
	if [[ ! -e "$debugfs_root" ]]; then
		pass "kvm_rndlog debugfs state is absent"
	else
		fail "kvm_rndlog debugfs state remains"
	fi
}

check_loaded() {
	if [[ -d /sys/module/kvm_intel ]]; then
		pass "kvm_intel is loaded"
	else
		fail "kvm_intel is not loaded"
	fi
	if [[ -d "$debugfs_root" ]]; then
		pass "kvm_rndlog debugfs directory exists"
	else
		fail "kvm_rndlog debugfs directory is absent"
		return
	fi
	for entry in enabled:644 buffer:400 stats:400 drop_count:400; do
		name=${entry%%:*}
		expected_mode=${entry##*:}
		path="$debugfs_root/$name"
		actual_mode=$(stat -c '%a' "$path" 2>/dev/null || true)
		if [[ -f "$path" && "$actual_mode" == "$expected_mode" ]]; then
			pass "$name mode is $expected_mode"
		else
			fail "$name is missing or mode is ${actual_mode:-unknown}, expected $expected_mode"
		fi
	done
	if "$repo_root/build/memento" doctor cpu; then
		pass "memento doctor cpu passed"
	else
		fail "memento doctor cpu failed"
	fi
}

case "$mode" in
failed-init)
	check_intel_absent
	;;
absent)
	check_intel_absent
	if [[ ! -e /sys/module/kvm ]]; then
		pass "kvm is not loaded"
	else
		fail "kvm remains loaded"
	fi
	;;
loaded-initial)
	check_loaded
	if [[ -r "$debugfs_root/enabled" ]] &&
		grep -Eq '^(Y|1)$' "$debugfs_root/enabled"; then
		pass "initial logging state is enabled"
	else
		fail "initial logging state is not enabled"
	fi
	if [[ -r "$debugfs_root/stats" ]]; then
		for stat in total_records consumed drop_count buffer_used handler_calls; do
			value=$(awk -F: -v name="$stat" '$1 == name {gsub(/[[:space:]]/, "", $2); print $2}' \
				"$debugfs_root/stats")
			if [[ "$value" == 0 ]]; then
				pass "initial $stat is zero"
			else
				fail "initial $stat is ${value:-missing}, expected zero"
			fi
		done
	else
		fail "stats is not readable"
	fi
	;;
loaded)
	check_loaded
	;;
*)
	echo "unknown mode: $mode" >&2
	exit 2
	;;
esac

if [[ -n "$dmesg_delta" ]]; then
	if [[ ! -f "$dmesg_delta" || -L "$dmesg_delta" ]]; then
		fail "DMESG_DELTA is not a regular non-symlink file"
	elif grep -Eiq 'BUG:|WARNING:|Oops:|kernel panic|general protection fault' "$dmesg_delta"; then
		fail "DMESG_DELTA contains a kernel fault marker"
	else
		pass "DMESG_DELTA has no kernel fault marker"
	fi
fi

if (( failures != 0 )); then
	printf 'runtime-state failures: %d\n' "$failures" >&2
	exit 1
fi
echo "runtime state passed: $mode"
