#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
wrapper="$repo/scripts/memento-container.sh"
dockerfile="$repo/containers/lab/Dockerfile"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

fail() {
  printf 'container wrapper policy test: %s\n' "$*" >&2
  exit 1
}

contains() {
  local haystack=$1 needle=$2
  [[ "$haystack" == *"$needle"* ]] || fail "missing policy marker: $needle"
}

not_contains() {
  local haystack=$1 needle=$2
  [[ "$haystack" != *"$needle"* ]] || fail "forbidden policy marker: $needle"
}

bash -n "$wrapper"
# shellcheck source=../scripts/memento-container.sh
source "$wrapper"
is_rootless_security '["name=seccomp,profile=builtin","name=rootless"]' || fail "rootless security option was not recognized"
if is_rootless_security '["name=seccomp,profile=builtin"]'; then
  fail "rootful security options were accepted"
fi
is_supported_cgroup systemd 2 || fail "supported cgroup configuration was rejected"
if is_supported_cgroup none 2 || is_supported_cgroup cgroupfs 2 || is_supported_cgroup systemd 1; then
  fail "unsupported cgroup configuration was accepted"
fi

state="$tmp/state"
scenario="$state/lab/safe"
work="$scenario/work"
plans="$scenario/plans"
encrypted="$scenario/encrypted"
mkdir -p -- "$work" "$plans" "$encrypted"
chmod 0700 "$state" "$state/lab" "$scenario" "$work" "$plans" "$encrypted"
manifest="$plans/encryption-$(printf '0%.0s' {1..64}).json"
printf '{}\n' >"$manifest"
chmod 0600 "$manifest"

input="$tmp/sample.babyk"
log="$tmp/lab-prn.jsonl"
output="$tmp/output"
printf 'ciphertext\n' >"$input"
printf '{"schema":"memento.prn/v1"}\n' >"$log"
mkdir -m 0700 "$output"
chmod 0600 "$input" "$log"

decrypt_output=$(MEMENTO_CONTAINER_POLICY_ONLY=1 "$wrapper" decrypt babuk \
  --input "$input" --output-dir "$output" --prn-log "$log")
for marker in \
  'POLICY-ONLY; Docker was not executed.' \
  '--pull=never' \
	'--init' \
  '--runtime=runc' \
  '--network=none' \
  '--read-only' \
  '--cap-drop=ALL' \
  '--security-opt=no-new-privileges:true' \
  '--pids-limit=64' \
  '--memory=1g' \
  '--cpus=2' \
  '--user 0:0' \
  'MEMENTO_ROOTLESS_CONTAINER=1' \
  'MEMENTO_HOST_UID=' \
  'MEMENTO_HOST_GID=' \
  'readonly' \
  '/run/memento-state'; do
  contains "$decrypt_output" "$marker"
done
not_contains "$decrypt_output" '--in-place'
not_contains "$decrypt_output" '/var/run/docker.sock'

printf -v encrypt_command 'MEMENTO_CONTAINER_POLICY_ONLY=1 %q encrypt babuk --state-dir %q --scenario safe --manifest %q' \
  "$wrapper" "$state" "$manifest"
encrypt_output=$(script -qfec "$encrypt_command" /dev/null | tr -d '\r')
normalized_encrypt_output=$(printf '%s' "$encrypt_output" | sed 's/\\,/,/g')
contains "$normalized_encrypt_output" 'POLICY-ONLY; Docker was not executed.'
contains "$normalized_encrypt_output" '--interactive --tty'
contains "$normalized_encrypt_output" "src=$scenario,dst=$scenario,readonly"
contains "$normalized_encrypt_output" "src=$work,dst=$work,readonly"
contains "$normalized_encrypt_output" "src=$plans,dst=$plans,readonly"
contains "$normalized_encrypt_output" "src=$encrypted,dst=$encrypted"
contains "$normalized_encrypt_output" "dst=$state/log"
contains "$normalized_encrypt_output" 'requires an exact YES or NO response'
not_contains "$normalized_encrypt_output" 'ENCRYPT '

printf -v validation_encrypt_command 'MEMENTO_CONTAINER_POLICY_ONLY=1 %q encrypt babuk --state-dir %q --scenario safe --manifest %q --validation-stop-after-prn' \
  "$wrapper" "$state" "$manifest"
validation_encrypt_output=$(script -qfec "$validation_encrypt_command" /dev/null | tr -d '\r')
contains "$validation_encrypt_output" '--validation-stop-after-prn'

printf -v qilin_encrypt_command 'MEMENTO_CONTAINER_POLICY_ONLY=1 %q encrypt qilin --state-dir %q --scenario safe --manifest %q' \
  "$wrapper" "$state" "$manifest"
qilin_encrypt_output=$(script -qfec "$qilin_encrypt_command" /dev/null | tr -d '\r')
qilin_encrypt_word=encrypt
contains "$qilin_encrypt_output" "lab $qilin_encrypt_word qilin"
not_contains "$qilin_encrypt_output" '--public-key'

printf -v qilin_validation_command 'MEMENTO_CONTAINER_POLICY_ONLY=1 %q encrypt qilin --state-dir %q --scenario safe --manifest %q --validation-stop-after-prn' \
  "$wrapper" "$state" "$manifest"
if script -qfec "$qilin_validation_command" /dev/null >"$tmp/qilin-validation.out" 2>&1; then
  fail "Qilin accepted the Babuk validation PRN stop"
fi
grep -q 'only valid for Babuk' "$tmp/qilin-validation.out" || fail "Qilin validation-stop rejection was not explicit"

qilin_input="$tmp/fixture-0000.memento.qilin"
printf 'ciphertext\n' >"$qilin_input"
chmod 0600 "$qilin_input"
qilin_decrypt_output=$(MEMENTO_CONTAINER_POLICY_ONLY=1 "$wrapper" decrypt qilin \
  --input "$qilin_input" --output-dir "$output" --prn-log "$log")
contains "$qilin_decrypt_output" 'decrypt qilin'
contains "$qilin_decrypt_output" "$output/fixture-0000.memento"

if MEMENTO_CONTAINER_POLICY_ONLY=1 "$wrapper" decrypt qilin \
  --input "$qilin_input" --output-dir "$output" --prn-log "$log" \
  --public-key "$(printf '0%.0s' {1..64})" >"$tmp/qilin-public-key.out" 2>&1; then
  fail "Qilin accepted a custom public key"
fi
grep -q 'only valid for Babuk' "$tmp/qilin-public-key.out" || fail "Qilin public-key rejection was not explicit"

if MEMENTO_CONTAINER_POLICY_ONLY=1 "$wrapper" encrypt babuk \
  --state-dir "$state" --scenario safe --manifest "$manifest" </dev/null >"$tmp/non-tty.out" 2>&1; then
  fail "non-TTY encryption policy was accepted"
fi
grep -q 'interactive terminal' "$tmp/non-tty.out" || fail "non-TTY rejection was not explicit"

printf 'occupied\n' >"$output/existing"
if MEMENTO_CONTAINER_POLICY_ONLY=1 "$wrapper" decrypt babuk \
  --input "$input" --output-dir "$output" --prn-log "$log" >"$tmp/nonempty.out" 2>&1; then
  fail "non-empty recovery output directory was accepted"
fi
grep -q 'must be empty' "$tmp/nonempty.out" || fail "non-empty output rejection was not explicit"
rm -f "$output/existing"

ln -s "$input" "$tmp/input-link"
if MEMENTO_CONTAINER_POLICY_ONLY=1 "$wrapper" decrypt babuk \
  --input "$tmp/input-link" --output-dir "$output" --prn-log "$log" >"$tmp/symlink.out" 2>&1; then
  fail "symlink input was accepted"
fi
grep -q 'symlink path component' "$tmp/symlink.out" || fail "symlink rejection was not explicit"

if MEMENTO_CONTAINER_POLICY_ONLY=1 "$wrapper" decrypt babuk \
  --input "$input" --output-dir "$output" --prn-log "$log" --unknown >"$tmp/unknown.out" 2>&1; then
  fail "unknown wrapper option was accepted"
fi
grep -q 'unknown decrypt argument' "$tmp/unknown.out" || fail "unknown-option rejection was not explicit"

grep -Fq 'ubuntu:24.04@sha256:f610ab94648195aa356059f5b41d6085c9d4d903c072430cdd1af7bdb646106b' "$dockerfile" \
  || fail "Dockerfile base digest is not pinned"
for forbidden in '--privileged' '/var/run/docker.sock' '--network=host' '--publish'; do
  if grep -Fq -- "$forbidden" "$wrapper"; then
    fail "manual wrapper contains forbidden marker: $forbidden"
  fi
done

printf 'container wrapper policy test passed\n'
