#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT

mock_bin="$test_root/bin"
artifact_dir="$test_root/artifacts"
mkdir -p "$mock_bin" "$artifact_dir/normal" "$artifact_dir/fault"
touch "$artifact_dir/normal/kvm.ko" "$artifact_dir/normal/kvm-intel.ko"
touch "$artifact_dir/fault/kvm.ko" "$artifact_dir/fault/kvm-intel.ko"

printf '%s\n' \
	'#!/usr/bin/env bash' \
	'if [[ "$*" == *"db:Status-Status"* ]]; then' \
	'    printf "6.17.0-35.35~24.04.1\\tconfig-files"' \
	'else' \
	'    printf "6.17.0-35.35~24.04.1"' \
	'fi' >"$mock_bin/dpkg-query"
chmod 0755 "$mock_bin/dpkg-query"

output=$(PATH="$mock_bin:$PATH" \
	"$repo_root/validation/reference-preflight.sh" "$artifact_dir" 2>&1 || true)

expected='[FAIL] linux-image-6.17.0-35-generic is version 6.17.0-35.35~24.04.1 with package state config-files, expected version 6.17.0-35.35~24.04.1 with package state installed'
if ! grep -Fqx "$expected" <<<"$output"; then
	printf 'preflight did not reject a config-files-only package:\n%s\n' "$output" >&2
	exit 1
fi

echo 'reference-preflight package-state regression test passed'
