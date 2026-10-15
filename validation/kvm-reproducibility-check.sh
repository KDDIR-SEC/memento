#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 KVM_ARTIFACT_DIR_A KVM_ARTIFACT_DIR_B" >&2
	exit 2
fi

artifact_a=$(realpath "$1")
artifact_b=$(realpath "$2")
if [[ ! -d "$artifact_a" || ! -d "$artifact_b" || -L "$1" || -L "$2" ]]; then
	echo "artifact inputs must be non-symlink directories" >&2
	exit 2
fi

failures=0
for relative in \
	normal/kvm.ko \
	normal/kvm-intel.ko \
	fault/kvm.ko \
	fault/kvm-intel.ko; do
	path_a="$artifact_a/$relative"
	path_b="$artifact_b/$relative"
	if [[ ! -f "$path_a" || ! -f "$path_b" || -L "$path_a" || -L "$path_b" ]]; then
		echo "[FAIL] missing regular artifact: $relative" >&2
		failures=$((failures + 1))
		continue
	fi
	if cmp -s "$path_a" "$path_b"; then
		echo "[PASS] reproducible artifact: $relative"
	else
		echo "[FAIL] artifact differs: $relative" >&2
		sha256sum "$path_a" "$path_b" >&2
		failures=$((failures + 1))
	fi
done

if (( failures != 0 )); then
	printf 'KVM reproducibility failures: %d\n' "$failures" >&2
	exit 1
fi

echo "KVM module artifacts are byte reproducible"
