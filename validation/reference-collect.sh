#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -u
umask 077

if [[ $# -lt 1 || $# -gt 3 ]]; then
	echo "usage: $0 OUTPUT_DIR [KVM_ARTIFACT_DIR] [VM_NAME]" >&2
	exit 2
fi

output_input=$1
artifact_input=${2:-}
vm_name=${3:-rdrand-monitor}
repo_root=$(realpath "$(dirname "$0")/..")
output_dir=$(realpath -m "$output_input")

if [[ -L "$output_input" || "$output_dir" == "/" ]]; then
	echo "OUTPUT_DIR must be a non-symlink, non-root path" >&2
	exit 2
fi
if [[ -d "$output_dir" ]] &&
	[[ -n "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
	echo "OUTPUT_DIR must be absent or empty: $output_dir" >&2
	exit 2
fi
install -d -m 0700 "$output_dir"
status_file="$output_dir/exit-status.txt"
: >"$status_file"

capture() {
	local name=$1
	shift
	{
		printf 'command:'
		printf ' %q' "$@"
		printf '\n'
		"$@"
	} >"$output_dir/$name.txt" 2>&1
	local status=$?
	printf '%s=%d\n' "$name" "$status" >>"$status_file"
	return 0
}

capture environment bash -c '
	set -e
	date -u --iso-8601=seconds
	uname -a
	printf "uid="; id -u
	printf "user="; id -un
	cat /etc/os-release
	go version
	clang --version
	bpftool version
	gcc --version
	make --version
'
capture repository git -C "$repo_root" status --short
git -C "$repo_root" rev-parse HEAD >"$output_dir/validated-revision.txt" 2>&1
printf 'validated_revision=%d\n' "$?" >>"$status_file"

capture cpu lscpu
capture cpu_flags bash -c \
	'awk -F: "/^flags/{print \$2; exit}" /proc/cpuinfo'
capture kernel_cmdline cat /proc/cmdline
capture secure_boot mokutil --sb-state
capture mounts findmnt /sys/kernel/debug
capture packages dpkg-query -W \
	'linux-image-6.17.0-35-generic' \
	'linux-modules-6.17.0-35-generic' \
	'linux-modules-extra-6.17.0-35-generic' \
	'linux-hwe-6.17-headers-6.17.0-35' \
	'linux-headers-6.17.0-35-generic'
capture domains virsh list --all
capture validation_vm virsh dumpxml "$vm_name"
capture validation_disks virsh domblklist "$vm_name" --details
capture processes pgrep -a qemu
capture loaded_modules lsmod
capture stock_kvm bash -c '
	for name in kvm kvm_intel; do
		path=$(modinfo -n "$name" 2>/dev/null || true)
		printf "%s path=%s\n" "$name" "$path"
		if [[ -n "$path" && -f "$path" ]]; then
			sha256sum "$path"
			modinfo "$path"
		fi
	done
'
capture debugfs bash -c '
	root=/sys/kernel/debug/kvm_rndlog
	if [[ -d "$root" ]]; then
		find "$root" -maxdepth 1 -printf "%m %y %p\n" | sort
		for file in stats drop_count enabled; do
			if [[ -r "$root/$file" ]]; then
				printf "[%s]\n" "$file"
				cat "$root/$file"
			fi
		done
	else
		echo "kvm_rndlog debugfs directory absent"
	fi
'
capture doctors bash -c "
	set -e
	if [[ -x '$repo_root/build/memento' ]]; then
		'$repo_root/build/memento' doctor cpu
		'$repo_root/build/memento' doctor syscall
		'$repo_root/build/memento' doctor vdso
	else
		echo 'build/memento is absent'
		exit 1
	fi
"
capture kernel_messages dmesg --ctime

if [[ -n "$artifact_input" ]]; then
	artifact_dir=$(realpath "$artifact_input")
	capture artifact_hashes find "$artifact_dir" -type f -exec sha256sum '{}' +
fi

find "$output_dir" -type f -exec chmod 0600 '{}' +
printf 'evidence=%s\n' "$output_dir"
