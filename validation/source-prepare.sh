#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail
umask 077

expected_dsc='linux-hwe-6.17_6.17.0-35.35~24.04.1.dsc'
expected_orig='linux-hwe-6.17_6.17.0.orig.tar.gz'
expected_diff='linux-hwe-6.17_6.17.0-35.35~24.04.1.diff.gz'
expected_fingerprint='30FFCDCD071F1659ACEC972A20F88172E14F6784'
expected_version='6.17.0-35.35~24.04.1'

if [[ $# -ne 4 ]]; then
	echo "usage: $0 DSC SIGNER_KEYRING KERNEL_TREE SOURCE_EVIDENCE_DIR" >&2
	exit 2
fi

dsc=$(realpath "$1")
keyring=$(realpath "$2")
kernel_tree=$(realpath -m "$3")
evidence_dir=$(realpath -m "$4")
package_dir=$(dirname "$dsc")
orig="$package_dir/$expected_orig"
diff="$package_dir/$expected_diff"

if [[ $(basename "$dsc") != "$expected_dsc" ]]; then
	echo "DSC must be $expected_dsc" >&2
	exit 2
fi
for input in "$dsc" "$keyring" "$orig" "$diff"; do
	if [[ ! -f "$input" || -L "$input" ]]; then
		echo "input must be a non-symlink regular file: $input" >&2
		exit 2
	fi
done
for output in "$kernel_tree" "$evidence_dir"; do
	if [[ "$output" == / || -e "$output" ]]; then
		echo "output must be an absent, non-root path: $output" >&2
		exit 2
	fi
done

install -d -m 0700 "$evidence_dir"
key_home=$(mktemp -d /tmp/memento-source-keyring.XXXXXX)
cleanup() {
	rm -rf "$key_home"
}
trap cleanup EXIT
install -m 0600 "$keyring" "$key_home/trustedkeys.gpg"

gpgv --status-fd 1 --keyring "$key_home/trustedkeys.gpg" "$dsc" \
	>"$evidence_dir/dsc-signature.txt" 2>&1
if ! grep -Fq "VALIDSIG $expected_fingerprint " \
	"$evidence_dir/dsc-signature.txt"; then
	echo "DSC signature fingerprint mismatch" >&2
	exit 1
fi

sha256sum "$dsc" "$orig" "$diff" "$keyring" >"$evidence_dir/source-sha256.txt"
GNUPGHOME="$key_home" dpkg-source --require-valid-signature \
	--require-strong-checksums --no-overwrite-dir -x "$dsc" "$kernel_tree" \
	>"$evidence_dir/dpkg-source.txt" 2>&1

if ! grep -RqsF "$expected_version" \
	"$kernel_tree/debian.master/changelog" "$kernel_tree/debian/changelog"; then
	echo "extracted source does not identify $expected_version" >&2
	exit 1
fi

git -C "$kernel_tree" init -b pristine
git -C "$kernel_tree" config user.name 'memento validation'
git -C "$kernel_tree" config user.email 'memento-validation@localhost'
git -C "$kernel_tree" add -A
git -C "$kernel_tree" commit \
	-m "Pristine Ubuntu linux-hwe-6.17 $expected_version"
git -C "$kernel_tree" rev-parse HEAD >"$evidence_dir/pristine-source-commit.txt"
git -C "$kernel_tree" status --porcelain=v1 --untracked-files=all \
	>"$evidence_dir/pristine-source-status.txt"
if [[ -s "$evidence_dir/pristine-source-status.txt" ]]; then
	echo "pristine source snapshot is not clean" >&2
	exit 1
fi
{
	echo "source_version=$expected_version"
	echo "signer_fingerprint=$expected_fingerprint"
	echo "dsc=$dsc"
	echo "kernel_tree=$kernel_tree"
} >"$evidence_dir/manifest.txt"
chmod 0600 "$evidence_dir"/*

echo "verified source: $kernel_tree"
echo "evidence: $evidence_dir"
