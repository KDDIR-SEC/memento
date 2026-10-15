#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail
umask 077

if [[ $# -lt 3 ]]; then
	echo "usage: $0 RUN_DIR LABEL STATUS [COMMAND...]" >&2
	exit 2
fi

run_input=$1
label=$2
status=$3
shift 3

run_dir=$(realpath "$run_input")
if [[ ! -d "$run_dir" || -L "$run_input" ]]; then
	echo "RUN_DIR must be an existing non-symlink directory" >&2
	exit 2
fi
if [[ ! "$label" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
	echo "LABEL must contain only letters, digits, dot, underscore, or hyphen" >&2
	exit 2
fi
if [[ ! "$status" =~ ^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
	echo "STATUS must be an integer from 0 through 255" >&2
	exit 2
fi

output="$run_dir/command-status.tsv"
if [[ -L "$output" || ( -e "$output" && ! -f "$output" ) ]]; then
	echo "refusing unsafe status output: $output" >&2
	exit 2
fi
touch "$output"
chmod 0600 "$output"

{
	printf '%s\t%s\t%s\t' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$label" "$status"
	printf '%q ' "$@"
	printf '\n'
} >>"$output"
