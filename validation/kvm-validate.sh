#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail
umask 077

if [[ $# -ne 1 ]]; then
	echo "usage: KERNEL_CONFIG=FILE MODULE_SYMVERS=FILE KVM_ARTIFACT_DIR=DIR $0 KERNEL_TREE" >&2
	exit 2
fi

kernel_tree=$(realpath "$1")
repo_root=$(realpath "$(dirname "$0")/..")
patch_file="$repo_root/kvm/patches/0001-kvm-rdrand-rdseed-monitor.patch"
expected_package='6.17.0-35.35~24.04.1'
expected_release='6.17.0-35-generic'
kernel_config=${KERNEL_CONFIG:-}
module_symvers=${MODULE_SYMVERS:-}
artifact_input=${KVM_ARTIFACT_DIR:-}

if [[ -z "$kernel_config" || -z "$module_symvers" || -z "$artifact_input" ]]; then
	echo "KERNEL_CONFIG, MODULE_SYMVERS, and KVM_ARTIFACT_DIR are required" >&2
	exit 2
fi
kernel_config=$(realpath "$kernel_config")
module_symvers=$(realpath "$module_symvers")
artifact_dir=$(realpath -m "$artifact_input")
if [[ ! -f "$kernel_config" || ! -f "$module_symvers" ]]; then
	echo "KERNEL_CONFIG and MODULE_SYMVERS must be regular files" >&2
	exit 2
fi
if [[ -L "$artifact_input" || "$artifact_dir" == "/" ]]; then
	echo "KVM_ARTIFACT_DIR must be a non-symlink, non-root path" >&2
	exit 2
fi
if [[ -d "$artifact_dir" ]] &&
	[[ -n "$(find "$artifact_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
	echo "KVM_ARTIFACT_DIR must be absent or empty: $artifact_dir" >&2
	exit 2
fi
install -d -m 0700 "$artifact_dir" "$artifact_dir/normal" "$artifact_dir/fault"
exec > >(tee "$artifact_dir/build.log") 2>&1

if ! git -C "$kernel_tree" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "KERNEL_TREE must be a clean Git checkout of the Ubuntu kernel source" >&2
	exit 2
fi
if [[ -n "$(git -C "$kernel_tree" status --porcelain --untracked-files=all)" ]]; then
	echo "KERNEL_TREE must be clean" >&2
	exit 2
fi
if ! grep -RqsF "$expected_package" "$kernel_tree/debian.master/changelog" "$kernel_tree/debian/changelog" 2>/dev/null; then
	echo "kernel source is not Ubuntu package $expected_package" >&2
	exit 2
fi

if ! grep -q '^CONFIG_KVM=m$' "$kernel_config" ||
	! grep -q '^CONFIG_KVM_INTEL=m$' "$kernel_config" ||
	! grep -q '^CONFIG_DEBUG_FS=y$' "$kernel_config"; then
	echo "KERNEL_CONFIG must enable modular KVM/KVM_INTEL and debugfs" >&2
	exit 2
fi

if ! command -v flock >/dev/null 2>&1; then
	echo "flock is required for the reproducible KVM worktree" >&2
	exit 2
fi

worktree_root=/tmp/memento-kvm-validation
if [[ ! -e "$worktree_root" ]]; then
	mkdir -m 0700 "$worktree_root"
elif [[ ! -d "$worktree_root" || -L "$worktree_root" ||
	"$(stat -c %u "$worktree_root")" != "$(id -u)" ||
	"$(stat -c %a "$worktree_root")" != 700 ]]; then
	echo "$worktree_root must be a non-symlink directory owned by the current user with mode 0700" >&2
	exit 2
fi
exec {worktree_lock}>"$worktree_root/lock"
if ! flock -n "$worktree_lock"; then
	echo "another KVM validation build holds $worktree_root/lock" >&2
	exit 2
fi
worktree="$worktree_root/source"
if [[ -e "$worktree" || -L "$worktree" ]]; then
	echo "stale reproducible KVM worktree requires operator review: $worktree" >&2
	exit 2
fi
cleanup() {
	git -C "$kernel_tree" worktree remove --force "$worktree" >/dev/null 2>&1 || true
}
trap cleanup EXIT
git -C "$kernel_tree" worktree add --detach "$worktree" HEAD
git -C "$worktree" apply --check "$patch_file"
git -C "$worktree" apply "$patch_file"

cp "$kernel_config" "$worktree/.config"
reproducible_flags="-fdebug-prefix-map=$worktree=/usr/src/memento-kvm"
reproducible_flags+=" -fmacro-prefix-map=$worktree=/usr/src/memento-kvm"
"$worktree/scripts/config" --file "$worktree/.config" \
	--disable MODULE_COMPRESS \
	--disable MODULE_COMPRESS_ZSTD \
	--disable MODULE_COMPRESS_XZ \
	--disable MODULE_COMPRESS_GZIP

version_args=(
	SUBLEVEL=0
	EXTRAVERSION=-35-generic
	LOCALVERSION=
)
make -C "$worktree" "${version_args[@]}" \
	KCFLAGS="$reproducible_flags" KAFLAGS="$reproducible_flags" \
	KCPPFLAGS="$reproducible_flags" olddefconfig
if ! grep -q '^# CONFIG_MODULE_COMPRESS is not set$' "$worktree/.config" ||
	grep -Eq '^CONFIG_MODULE_COMPRESS_(ZSTD|XZ|GZIP)=y$' "$worktree/.config"; then
	echo "effective kernel config did not disable module compression" >&2
	exit 1
fi
make -C "$worktree" "${version_args[@]}" \
	KCFLAGS="$reproducible_flags" KAFLAGS="$reproducible_flags" \
	KCPPFLAGS="$reproducible_flags" prepare modules_prepare
make -C "$worktree" "${version_args[@]}" \
	KCFLAGS="$reproducible_flags" KAFLAGS="$reproducible_flags" \
	KCPPFLAGS="$reproducible_flags" scripts
make -C "$worktree" "${version_args[@]}" \
	KCFLAGS="$reproducible_flags" KAFLAGS="$reproducible_flags" \
	KCPPFLAGS="$reproducible_flags" scripts/module.lds
if [[ "$(cat "$worktree/include/config/kernel.release")" != "$expected_release" ]]; then
	echo "prepared kernel release is not $expected_release" >&2
	exit 1
fi

build_variant() {
	local destination=$1
	local extra_cflags=$2
	local kvm_module="$worktree/arch/x86/kvm/kvm.ko"
	local intel_module="$worktree/arch/x86/kvm/kvm-intel.ko"

	make -C "$worktree" M=arch/x86/kvm clean
	cp "$module_symvers" "$worktree/Module.symvers"
	make -C "$worktree" -j"$(nproc)" "${version_args[@]}" \
		KCFLAGS="$reproducible_flags $extra_cflags" \
		KAFLAGS="$reproducible_flags" KCPPFLAGS="$reproducible_flags" \
		M=arch/x86/kvm modules
	if [[ ! -s "$kvm_module" || ! -s "$intel_module" ]]; then
		echo "expected KVM module artifacts were not produced" >&2
		exit 1
	fi
	if [[ "$(modinfo -F vermagic "$kvm_module" | awk '{print $1}')" != "$expected_release" ]] ||
		[[ "$(modinfo -F vermagic "$intel_module" | awk '{print $1}')" != "$expected_release" ]]; then
		echo "module vermagic does not match $expected_release" >&2
		exit 1
	fi
	install -m 0600 "$kvm_module" "$artifact_dir/$destination/kvm.ko"
	install -m 0600 "$intel_module" "$artifact_dir/$destination/kvm-intel.ko"
}

build_variant normal ""
if modinfo -p "$artifact_dir/normal/kvm-intel.ko" |
	grep -q '^rndlog_fail_init_after:'; then
	echo "normal module unexpectedly exposes validation fault injection" >&2
	exit 1
fi

build_variant fault "-DMEMENTO_KVM_VALIDATION_FAULTS"
if ! modinfo -p "$artifact_dir/fault/kvm-intel.ko" |
	grep -q '^rndlog_fail_init_after:'; then
	echo "fault-injection module lacks rndlog_fail_init_after" >&2
	exit 1
fi
for variant in normal fault; do
	if ! modinfo -p "$artifact_dir/$variant/kvm-intel.ko" |
		grep -q '^rndlog_deterministic:'; then
		echo "$variant module lacks rndlog_deterministic" >&2
		exit 1
	fi
done
if ! cmp -s "$artifact_dir/normal/kvm.ko" "$artifact_dir/fault/kvm.ko"; then
	echo "normal and fault builds produced different base kvm.ko files" >&2
	exit 1
fi

install -m 0600 "$kernel_config" "$artifact_dir/kernel-input.config"
install -m 0600 "$worktree/.config" "$artifact_dir/kernel-effective.config"
install -m 0600 "$patch_file" "$artifact_dir/kvm.patch"
{
	echo "expected_package=$expected_package"
	echo "expected_release=$expected_release"
	echo "source_commit=$(git -C "$kernel_tree" rev-parse HEAD)"
	echo "source_tree=$kernel_tree"
	echo "kernel_config=$kernel_config"
	echo "module_symvers=$module_symvers"
	echo "validation_fault_macro=MEMENTO_KVM_VALIDATION_FAULTS"
} >"$artifact_dir/manifest.txt"
{
	echo "[normal kvm]"
	modinfo "$artifact_dir/normal/kvm.ko"
	echo "[normal kvm-intel]"
	modinfo "$artifact_dir/normal/kvm-intel.ko"
	echo "[fault kvm]"
	modinfo "$artifact_dir/fault/kvm.ko"
	echo "[fault kvm-intel]"
	modinfo "$artifact_dir/fault/kvm-intel.ko"
} >"$artifact_dir/modinfo.txt"
{
	sha256sum "$kernel_config" "$module_symvers" "$patch_file" \
		"$artifact_dir/kernel-input.config" \
		"$artifact_dir/kernel-effective.config"
	find "$artifact_dir/normal" "$artifact_dir/fault" -type f -name '*.ko' \
		-print0 | sort -z | xargs -0 sha256sum
} >"$artifact_dir/sha256.txt"
chmod 0600 "$artifact_dir"/*.txt "$artifact_dir/build.log"

echo "KVM patch applied and normal/fault variants built for $expected_package"
echo "vermagic: $expected_release"
echo "artifacts: $artifact_dir"
echo "The patched source enforces sizeof(struct rndlog_record) == 104."
echo "No host kernel or VM state was changed."
