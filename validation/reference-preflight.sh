#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -u

expected_release='6.17.0-35-generic'
expected_package_version='6.17.0-35.35~24.04.1'
failures=0

if [[ $# -ne 1 ]]; then
	echo "usage: $0 KVM_ARTIFACT_DIR" >&2
	exit 2
fi

artifact_dir=$(realpath "$1")
if [[ ! -d "$artifact_dir" || -L "$1" ]]; then
	echo "KVM_ARTIFACT_DIR must be a non-symlink directory" >&2
	exit 2
fi

pass() {
	printf '[PASS] %s\n' "$1"
}

fail() {
	printf '[FAIL] %s\n' "$1" >&2
	failures=$((failures + 1))
}

for command in virsh modinfo findmnt mokutil sha256sum; do
	if command -v "$command" >/dev/null 2>&1; then
		pass "required command $command is available"
	else
		fail "required command $command is unavailable"
	fi
done

for package in \
	linux-image-6.17.0-35-generic \
	linux-modules-6.17.0-35-generic \
	linux-modules-extra-6.17.0-35-generic \
	linux-hwe-6.17-headers-6.17.0-35 \
	linux-headers-6.17.0-35-generic; do
	package_record=$(dpkg-query -W \
		-f='${Version}\t${db:Status-Status}' "$package" 2>/dev/null || true)
	IFS=$'\t' read -r version package_state <<<"$package_record"
	if [[ "$version" == "$expected_package_version" && "$package_state" == installed ]]; then
		pass "$package is version $expected_package_version with package state installed"
	else
		fail "$package is version ${version:-not installed} with package state ${package_state:-not installed}, expected version $expected_package_version with package state installed"
	fi
done

if [[ -f "$artifact_dir/sha256.txt" ]] &&
	sha256sum -c "$artifact_dir/sha256.txt" >/dev/null 2>&1; then
	pass "KVM artifact hash manifest is valid"
else
	fail "KVM artifact hash manifest is missing or invalid"
fi
if cmp -s "$artifact_dir/normal/kvm.ko" "$artifact_dir/fault/kvm.ko"; then
	pass "normal and fault base kvm.ko hashes match"
else
	fail "normal and fault base kvm.ko hashes differ"
fi
if [[ "$(uname -r)" == "$expected_release" ]]; then
	pass "running kernel is $expected_release"
else
	fail "running kernel is $(uname -r), expected $expected_release"
fi

flags=$(awk -F: '/^flags/{print $2; exit}' /proc/cpuinfo)
for flag in vmx rdrand rdseed; do
	if grep -qw "$flag" <<<"$flags"; then
		pass "CPU flag $flag is present"
	else
		fail "CPU flag $flag is absent"
	fi
done

if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
	pass "/dev/kvm is accessible"
else
	fail "/dev/kvm is not accessible"
fi

if findmnt -rn -t debugfs /sys/kernel/debug >/dev/null; then
	pass "debugfs is mounted"
else
	fail "debugfs is not mounted"
fi

if command -v mokutil >/dev/null 2>&1 &&
	mokutil --sb-state 2>&1 | grep -qi 'disabled'; then
	pass "Secure Boot is disabled"
else
	fail "Secure Boot state is not disabled"
fi

if running_domains=$(virsh list --state-running --name 2>/dev/null); then
	running_domains=$(sed '/^[[:space:]]*$/d' <<<"$running_domains")
	if [[ -z "$running_domains" ]]; then
		pass "no running libvirt domains"
	else
		fail "running libvirt domains: $(tr '\n' ' ' <<<"$running_domains")"
	fi
else
	fail "unable to query running libvirt domains"
fi

if pgrep -a qemu >/dev/null 2>&1; then
	fail "a QEMU process is running"
else
	pass "no QEMU process is running"
fi

for variant in normal fault; do
	for module in kvm.ko kvm-intel.ko; do
		path="$artifact_dir/$variant/$module"
		if [[ ! -f "$path" || -L "$path" ]]; then
			fail "missing regular artifact $path"
			continue
		fi
		release=$(modinfo -F vermagic "$path" 2>/dev/null | awk '{print $1}')
		if [[ "$release" == "$expected_release" ]]; then
			pass "$variant/$module vermagic is $expected_release"
		else
			fail "$variant/$module vermagic is $release"
		fi
	done
done

if modinfo -p "$artifact_dir/normal/kvm-intel.ko" 2>/dev/null |
	grep -q '^rndlog_fail_init_after:'; then
	fail "normal module exposes validation fault injection"
else
	pass "normal module excludes validation fault injection"
fi
if modinfo -p "$artifact_dir/fault/kvm-intel.ko" 2>/dev/null |
	grep -q '^rndlog_fail_init_after:'; then
	pass "fault module exposes validation-only injection"
else
	fail "fault module lacks validation-only injection"
fi
for variant in normal fault; do
	if modinfo -p "$artifact_dir/$variant/kvm-intel.ko" 2>/dev/null |
		grep -q '^rndlog_deterministic:'; then
		pass "$variant module exposes deterministic validation mode"
	else
		fail "$variant module lacks deterministic validation mode"
	fi
done

if (( failures != 0 )); then
	printf 'preflight failures: %d\n' "$failures" >&2
	exit 1
fi
echo "reference-host preflight passed"
