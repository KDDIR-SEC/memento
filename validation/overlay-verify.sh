#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: $0 DOMAIN_XML OVERLAY_QCOW2 BACKING_QCOW2" >&2
	exit 2
fi

xml_input=$1
overlay_input=$2
backing_input=$3
xml=$(realpath "$xml_input")
overlay=$(realpath "$overlay_input")
backing=$(realpath "$backing_input")

for input in "$xml" "$overlay" "$backing"; do
	if [[ ! -f "$input" || -L "$input" ]]; then
		echo "input must be a non-symlink regular file: $input" >&2
		exit 2
	fi
done

vcpu=$(xmllint --xpath 'normalize-space(string(/domain/vcpu))' "$xml")
cpu_mode=$(xmllint --xpath 'string(/domain/cpu/@mode)' "$xml")
disk_count=$(xmllint --xpath 'count(/domain/devices/disk[@device="disk"])' "$xml")
disk_source=$(xmllint --xpath 'string(/domain/devices/disk[@device="disk"]/source/@file)' "$xml")
disk_source=$(realpath "$disk_source")

if [[ "$vcpu" != 4 ]]; then
	echo "transient domain has $vcpu vCPUs, expected 4" >&2
	exit 1
fi
if [[ "$cpu_mode" != host-passthrough ]]; then
	echo "transient domain CPU mode is $cpu_mode, expected host-passthrough" >&2
	exit 1
fi
if [[ "$disk_count" != 1 || "$disk_source" != "$overlay" ]]; then
	echo "transient domain must use only the named overlay disk" >&2
	exit 1
fi

chain=$(qemu-img info --output=json --backing-chain "$overlay")
if ! jq -e --arg overlay "$overlay" --arg backing "$backing" '
	length == 2 and
	.[0].filename == $overlay and
	.[0].format == "qcow2" and
	.[0]["full-backing-filename"] == $backing and
	.[1].filename == $backing
' <<<"$chain" >/dev/null; then
	echo "overlay backing chain does not exactly match the expected base" >&2
	exit 1
fi

echo "transient overlay definition passed"
