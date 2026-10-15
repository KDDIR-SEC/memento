#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail
umask 077

readonly MEMENTO_IMAGE="memento-lab:0.1.0-dev"
DOCKER_BIN=""
IMAGE_ID=""
IMAGE_REVISION=""
IMAGE_BINARY_SHA256=""
declare -a DOCKER_ARGS=()

usage() {
  cat <<'EOF'
Usage:
  memento-container.sh encrypt babuk|qilin \
    --state-dir DIR --scenario NAME --manifest FILE [--public-key HEX] \
    [--validation-stop-after-prn]

  memento-container.sh decrypt babuk|qilin \
    --input FILE --output-dir DIR --prn-log FILE... \
    [--output-name NAME] [--public-key HEX]

  memento-container.sh smoke

The encrypt command requires a real terminal. The wrapper never supplies the
inner Memento YES/NO approval. Decryption always writes a separate output;
in-place recovery is not supported by this wrapper.
EOF
}

die() {
  printf 'memento-container: %s\n' "$*" >&2
  exit 2
}

require_value() {
  local option=$1
  local value=${2-}
  [[ -n "$value" ]] || die "$option requires a value"
}

reject_mount_characters() {
  local value=$1
  [[ "$value" != *','* ]] || die "mount path contains a comma: $value"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "mount path contains a newline"
}

reject_symlink_components() {
  local value=$1
  [[ "$value" == /* ]] || die "internal error: path is not absolute: $value"
  local current=""
  local component
  IFS='/' read -r -a components <<< "${value#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    current+="/$component"
    [[ ! -L "$current" ]] || die "symlink path component is forbidden: $current"
  done
}

canonical_existing() {
  local value=$1
  reject_mount_characters "$value"
  local lexical=$value
  if [[ "$lexical" != /* ]]; then
    lexical="$PWD/$lexical"
  fi
  reject_symlink_components "$lexical"
  local absolute
  absolute=$(realpath -e -- "$value") || die "path does not exist: $value"
  reject_symlink_components "$absolute"
  printf '%s\n' "$absolute"
}

require_owned_directory() {
  local value=$1
  [[ -d "$value" && ! -L "$value" ]] || die "not a real directory: $value"
  [[ $(stat -c '%u' -- "$value") == "$EUID" ]] || die "directory is not owned by uid $EUID: $value"
}

require_owned_regular_file() {
  local value=$1
  [[ -f "$value" && ! -L "$value" ]] || die "not a regular non-symlink file: $value"
  [[ $(stat -c '%u' -- "$value") == "$EUID" ]] || die "file is not owned by uid $EUID: $value"
}

require_private_directory() {
  local value=$1
  require_owned_directory "$value"
  [[ $(stat -c '%a' -- "$value") == 700 ]] || die "directory mode must be 0700: $value"
}

require_private_file() {
  local value=$1
  require_owned_regular_file "$value"
  [[ $(stat -c '%a' -- "$value") == 600 ]] || die "file mode must be 0600: $value"
}

require_empty_directory() {
  local value=$1
  if find "$value" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    die "output directory must be empty: $value"
  fi
}

is_rootless_security() {
  [[ $1 == *'name=rootless'* ]]
}

is_supported_cgroup() {
  [[ $1 == systemd && $2 == 2 ]]
}

verify_runtime_isolation() {
  "$DOCKER_BIN" run --rm --pull=never \
    --runtime=runc \
    --network=none \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges:true \
    --pids-limit=64 \
    --memory=1g \
    --cpus=2 \
    --user 65532:65532 \
    --entrypoint /bin/sh \
    "$MEMENTO_IMAGE" -eu -c '
      grep -Eq "^CapEff:[[:space:]]+0000000000000000$" /proc/self/status
      grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/self/status
      grep -Eq "^Seccomp:[[:space:]]+2$" /proc/self/status
      interfaces=$(for item in /sys/class/net/*; do basename "$item"; done | sort | paste -sd, -)
      [ "$interfaces" = lo ]
      [ "$(wc -l < /proc/net/route)" -eq 1 ]
      if [ -r /proc/net/ipv6_route ]; then
        awk '\''NF && $NF != "lo" { bad=1 } END { exit bad }'\'' /proc/net/ipv6_route
      fi
      [ "$(cat /sys/fs/cgroup/memory.max)" = 1073741824 ]
      [ "$(cat /sys/fs/cgroup/pids.max)" = 64 ]
      read -r quota period < /sys/fs/cgroup/cpu.max
      [ "$quota" != max ]
      [ "$quota" -eq "$((period * 2))" ]
    ' >/dev/null || die "Docker runtime isolation or cgroup enforcement probe failed"
}

prepare_docker() {
  (( EUID != 0 )) || die "refusing to run a container workflow as root"
  if [[ ${MEMENTO_CONTAINER_POLICY_ONLY:-0} == 1 ]]; then
    DOCKER_BIN=docker
    IMAGE_ID=policy-only
    IMAGE_REVISION=policy-only
    IMAGE_BINARY_SHA256=policy-only
    return
  fi
  DOCKER_BIN=$(command -v docker) || die "docker is not installed"
  local security
  security=$($DOCKER_BIN info --format '{{json .SecurityOptions}}') || die "cannot query Docker security options"
  is_rootless_security "$security" || die "rootless Docker is required"
  local cgroup_driver cgroup_version runc_available
  cgroup_driver=$($DOCKER_BIN info --format '{{.CgroupDriver}}') || die "cannot query Docker cgroup driver"
  cgroup_version=$($DOCKER_BIN info --format '{{.CgroupVersion}}') || die "cannot query Docker cgroup version"
  is_supported_cgroup "$cgroup_driver" "$cgroup_version" || die "rootless Docker requires cgroup v2 with the systemd driver; current driver=$cgroup_driver version=$cgroup_version"
  runc_available=$($DOCKER_BIN info --format '{{if index .Runtimes "runc"}}yes{{end}}') || die "cannot query Docker runtimes"
  [[ "$runc_available" == yes ]] || die "Docker runtime runc is required"
  IMAGE_ID=$($DOCKER_BIN image inspect --format '{{.Id}}' "$MEMENTO_IMAGE") || die "local image $MEMENTO_IMAGE is missing; run make container-image"
  IMAGE_REVISION=$($DOCKER_BIN image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$MEMENTO_IMAGE")
  IMAGE_BINARY_SHA256=$($DOCKER_BIN image inspect --format '{{index .Config.Labels "io.memento.binary.sha256"}}' "$MEMENTO_IMAGE")
  [[ "$IMAGE_REVISION" =~ ^[0-9a-f]{40}(-dirty)?$ ]] || die "container image has no valid source revision label"
  [[ "$IMAGE_BINARY_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "container image has no valid binary SHA-256 label"
  verify_runtime_isolation
}

build_common_args() {
  local tmp_uid=$1 tmp_gid=$2
  DOCKER_ARGS=(
    "$DOCKER_BIN" run --rm --pull=never
		--init
    --runtime=runc
    --network=none
    --read-only
    --cap-drop=ALL
    --security-opt=no-new-privileges:true
    --pids-limit=64
    --memory=1g
    --cpus=2
    --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=$tmp_uid,gid=$tmp_gid"
    --env HOME=/tmp
    --entrypoint /usr/local/bin/memento
  )
}

add_filesystem_identity() {
  local uid gid
  uid=$(id -u)
  gid=$(id -g)
  DOCKER_ARGS+=(
    --user 0:0
    --env MEMENTO_ROOTLESS_CONTAINER=1
    --env "MEMENTO_HOST_UID=$uid"
    --env "MEMENTO_HOST_GID=$gid"
  )
}

print_image() {
  printf 'Image: %s\nImage ID: %s\nSource revision: %s\nBinary SHA-256: %s\n' \
    "$MEMENTO_IMAGE" "$IMAGE_ID" "$IMAGE_REVISION" "$IMAGE_BINARY_SHA256"
}

execute_or_print() {
  if [[ ${MEMENTO_CONTAINER_POLICY_ONLY:-0} == 1 ]]; then
    printf 'POLICY-ONLY; Docker was not executed.\n'
    printf 'argv:'
    printf ' %q' "${DOCKER_ARGS[@]}"
    printf '\n'
    return
  fi
  exec "${DOCKER_ARGS[@]}"
}

prepare_run_log() {
  local scenario_root=$1
  local runs="$scenario_root/container-runs"
  if [[ -e "$runs" ]]; then
    runs=$(canonical_existing "$runs")
    require_private_directory "$runs"
    [[ $(dirname -- "$runs") == "$scenario_root" ]] || die "container-runs escaped the scenario"
  else
    mkdir -m 0700 -- "$runs"
  fi
  local run_dir
  run_dir=$(mktemp -d "$runs/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
  mkdir -m 0700 -- "$run_dir/log"
  printf '%s\n' "$run_dir"
}

run_encrypt() {
  local algorithm=$1
  shift
  [[ "$algorithm" == babuk || "$algorithm" == qilin ]] || die "encrypt requires babuk or qilin"
  [[ -t 0 && -t 1 ]] || die "encryption requires an interactive terminal"

	local state_dir="" scenario="" manifest="" public_key="" validation_stop_after_prn=0
  while (($#)); do
    case $1 in
      --state-dir) require_value "$1" "${2-}"; state_dir=$2; shift 2 ;;
      --scenario) require_value "$1" "${2-}"; scenario=$2; shift 2 ;;
      --manifest) require_value "$1" "${2-}"; manifest=$2; shift 2 ;;
      --public-key) require_value "$1" "${2-}"; public_key=$2; shift 2 ;;
      --validation-stop-after-prn) validation_stop_after_prn=1; shift ;;
      *) die "unknown encrypt argument: $1" ;;
    esac
  done
  [[ -n "$state_dir" && -n "$scenario" && -n "$manifest" ]] || die "encrypt requires --state-dir, --scenario, and --manifest"
  [[ "$scenario" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ && "$scenario" != . && "$scenario" != .. ]] || die "invalid scenario name"
  if [[ "$algorithm" == qilin && -n "$public_key" ]]; then
		die "--public-key is only valid for Babuk"
  fi
	if [[ "$algorithm" == qilin && $validation_stop_after_prn == 1 ]]; then
		die "--validation-stop-after-prn is only valid for Babuk"
	fi
  if [[ -n "$public_key" && ! "$public_key" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    die "Babuk public key must be 64 hexadecimal characters"
  fi
  prepare_docker

  state_dir=$(canonical_existing "$state_dir")
  require_private_directory "$state_dir"
  local scenario_root work plans encrypted
  scenario_root=$(canonical_existing "$state_dir/lab/$scenario")
  [[ "$scenario_root" == "$state_dir/lab/$scenario" ]] || die "scenario escaped the state directory"
  require_private_directory "$scenario_root"
  work=$(canonical_existing "$scenario_root/work")
  plans=$(canonical_existing "$scenario_root/plans")
  encrypted=$(canonical_existing "$scenario_root/encrypted")
  require_private_directory "$work"
  require_private_directory "$plans"
  require_private_directory "$encrypted"

  manifest=$(canonical_existing "$manifest")
  require_private_file "$manifest"
  [[ $(stat -c '%h' -- "$manifest") == 1 ]] || die "manifest must have exactly one hard link"
  [[ $(dirname -- "$manifest") == "$plans" ]] || die "manifest must be a direct child of the scenario plans directory"
  [[ $(basename -- "$manifest") =~ ^encryption-[0-9a-f]{64}\.json$ ]] || die "manifest filename does not contain a SHA-256 digest"
  local manifest_digest
  manifest_digest=${manifest##*/encryption-}
  manifest_digest=${manifest_digest%.json}

	local run_dir log_dir validation_container_name=""
  run_dir=$(prepare_run_log "$scenario_root")
  log_dir="$run_dir/log"
  build_common_args 0 0
  add_filesystem_identity
	if (( validation_stop_after_prn == 1 )); then
		validation_container_name="memento-babuk-validation-$(date -u +%Y%m%dT%H%M%SZ)-$$"
		DOCKER_ARGS+=(--name "$validation_container_name")
	fi
  DOCKER_ARGS+=(
    --interactive --tty
    --mount "type=bind,src=$scenario_root,dst=$scenario_root,readonly,bind-propagation=rprivate"
    --mount "type=bind,src=$work,dst=$work,readonly,bind-propagation=rprivate"
    --mount "type=bind,src=$plans,dst=$plans,readonly,bind-propagation=rprivate"
    --mount "type=bind,src=$encrypted,dst=$encrypted,bind-propagation=rprivate"
    --mount "type=bind,src=$log_dir,dst=$state_dir/log,bind-propagation=rprivate"
    "$MEMENTO_IMAGE"
    --state-dir "$state_dir" lab encrypt "$algorithm"
    --scenario "$scenario" --manifest "$manifest"
  )
  if [[ -n "$public_key" ]]; then
		DOCKER_ARGS+=(--public-key "$public_key")
  fi
	if (( validation_stop_after_prn == 1 )); then
		DOCKER_ARGS+=(--validation-stop-after-prn)
	fi

  print_image
	if [[ -n "$validation_container_name" ]]; then
		printf 'Validation container name: %s\n' "$validation_container_name"
	fi
  printf 'Scenario root (RO): %s\nInput work (RO): %s\nPlans (RO): %s\nEncrypted output (RW): %s\nPRN log output (RW): %s\nManifest digest: %s\nManifest contents (extensions, file list, count, and total bytes):\n' \
    "$scenario_root" "$work" "$plans" "$encrypted" "$log_dir" "$manifest_digest"
  sed -n '1,240p' "$manifest"
  printf 'The inner Memento prompt lists every target and requires an exact YES or NO response.\n'
  execute_or_print
}

run_decrypt() {
  local algorithm=$1
  shift
  [[ "$algorithm" == babuk || "$algorithm" == qilin ]] || die "decrypt requires babuk or qilin"
  local input="" output_dir="" output_name="" public_key=""
  local -a logs=()
  while (($#)); do
    case $1 in
      --input) require_value "$1" "${2-}"; input=$2; shift 2 ;;
      --output-dir) require_value "$1" "${2-}"; output_dir=$2; shift 2 ;;
      --output-name) require_value "$1" "${2-}"; output_name=$2; shift 2 ;;
      --prn-log) require_value "$1" "${2-}"; logs+=("$2"); shift 2 ;;
      --public-key) require_value "$1" "${2-}"; public_key=$2; shift 2 ;;
      *) die "unknown decrypt argument: $1" ;;
    esac
  done
  [[ -n "$input" && -n "$output_dir" && ${#logs[@]} -gt 0 ]] || die "decrypt requires --input, --output-dir, and at least one --prn-log"
  if [[ "$algorithm" == qilin && -n "$public_key" ]]; then
    die "--public-key is only valid for Babuk"
  fi
  if [[ -n "$public_key" && ! "$public_key" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    die "Babuk public key must be 64 hexadecimal characters"
  fi

  input=$(canonical_existing "$input")
  require_owned_regular_file "$input"
  output_dir=$(canonical_existing "$output_dir")
  require_private_directory "$output_dir"
  require_empty_directory "$output_dir"
  if [[ -z "$output_name" ]]; then
    output_name=$(basename -- "$input")
    if [[ "$algorithm" == babuk ]]; then
      output_name=${output_name%.babyk}
    else
      output_name=${output_name%.qilin}
    fi
  fi
  [[ "$output_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ && "$output_name" != . && "$output_name" != .. ]] || die "output name must be a visible base name"
  local output_path="$output_dir/$output_name"
  [[ ! -e "$output_path" && ! -L "$output_path" ]] || die "output already exists: $output_path"

  local -a canonical_logs=()
  declare -A seen_logs=()
  local log
  for log in "${logs[@]}"; do
    log=$(canonical_existing "$log")
    require_private_file "$log"
    if [[ -z ${seen_logs[$log]+x} ]]; then
      canonical_logs+=("$log")
      seen_logs[$log]=1
    fi
  done

  prepare_docker
  build_common_args 0 0
  add_filesystem_identity
  DOCKER_ARGS+=(
    --tmpfs "/run/memento-state:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=0,gid=0"
    --mount "type=bind,src=$input,dst=$input,readonly,bind-propagation=rprivate"
    --mount "type=bind,src=$output_dir,dst=$output_dir,bind-propagation=rprivate"
  )
  for log in "${canonical_logs[@]}"; do
    DOCKER_ARGS+=(--mount "type=bind,src=$log,dst=$log,readonly,bind-propagation=rprivate")
  done
  DOCKER_ARGS+=(
    "$MEMENTO_IMAGE"
    --state-dir /run/memento-state decrypt "$algorithm"
    --input "$input" --output "$output_path"
  )
  for log in "${canonical_logs[@]}"; do
    DOCKER_ARGS+=(--prn-log "$log")
  done
  if [[ -n "$public_key" ]]; then
    DOCKER_ARGS+=(--public-key "$public_key")
  fi

  print_image
  printf 'Encrypted input (RO): %s\nRecovered output directory (RW, initially empty): %s\nRecovered output: %s\n' \
    "$input" "$output_dir" "$output_path"
  printf 'PRN logs (RO):\n'
  printf '  %s\n' "${canonical_logs[@]}"
  execute_or_print
}

run_smoke() {
  prepare_docker
  build_common_args 65532 65532
  DOCKER_ARGS+=(--user 65532:65532 "$MEMENTO_IMAGE" version)
  print_image
  execute_or_print
}

main() {
  (($# > 0)) || { usage; exit 2; }
  local command=$1
  shift
  case $command in
    encrypt|decrypt)
      (($# > 0)) || die "$command requires babuk or qilin"
      local algorithm=$1
      shift
      "run_$command" "$algorithm" "$@"
      ;;
    smoke)
      (($# == 0)) || die "smoke accepts no arguments"
      run_smoke
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      die "unknown command: $command"
      ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
