#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail
umask 077

readonly image=memento-lab:0.1.0-dev
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

fail() {
  printf 'container mount smoke test: %s\n' "$*" >&2
  exit 1
}

((EUID != 0)) || fail "root execution is forbidden"
docker_bin=$(command -v docker) || fail "docker is not installed"
security=$($docker_bin info --format '{{json .SecurityOptions}}')
[[ "$security" == *'name=rootless'* ]] || fail "rootless Docker is required"
cgroup_driver=$($docker_bin info --format '{{.CgroupDriver}}')
cgroup_version=$($docker_bin info --format '{{.CgroupVersion}}')
[[ "$cgroup_driver" == systemd && "$cgroup_version" == 2 ]] \
  || fail "cgroup v2 with the systemd driver is required; current driver=$cgroup_driver version=$cgroup_version"
runc_available=$($docker_bin info --format '{{if index .Runtimes "runc"}}yes{{end}}')
[[ "$runc_available" == yes ]] || fail "Docker runtime runc is required"
$docker_bin image inspect "$image" >/dev/null || fail "local image $image is missing"

state="$tmp/state"
scenario="$state/lab/mount-smoke"
work="$scenario/work"
plans="$scenario/plans"
encrypted="$scenario/encrypted"
log="$scenario/container-runs/mount-smoke/log"
mkdir -p -- "$work" "$plans" "$encrypted" "$log"
chmod 0700 "$state" "$state/lab" "$scenario" "$work" "$plans" \
  "$encrypted" "$scenario/container-runs" "$scenario/container-runs/mount-smoke" "$log"

uid=$(id -u)
gid=$(id -g)
$docker_bin run --rm --pull=never \
  --runtime=runc \
  --network=none \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --pids-limit=64 \
  --memory=1g \
  --cpus=2 \
  --user 0:0 \
  --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=0,gid=0" \
  --env MEMENTO_ROOTLESS_CONTAINER=1 \
  --env "MEMENTO_HOST_UID=$uid" \
  --env "MEMENTO_HOST_GID=$gid" \
  --env "SCENARIO=$scenario" \
  --env "WORK=$work" \
  --env "PLANS=$plans" \
  --env "ENCRYPTED=$encrypted" \
  --env "LOG=$state/log" \
  --env "HOST_REPO=$repo" \
  --mount "type=bind,src=$scenario,dst=$scenario,readonly,bind-propagation=rprivate" \
  --mount "type=bind,src=$work,dst=$work,readonly,bind-propagation=rprivate" \
  --mount "type=bind,src=$plans,dst=$plans,readonly,bind-propagation=rprivate" \
  --mount "type=bind,src=$encrypted,dst=$encrypted,bind-propagation=rprivate" \
  --mount "type=bind,src=$log,dst=$state/log,bind-propagation=rprivate" \
  --entrypoint /bin/sh \
  "$image" -eu -c '
    [ "$(id -u)" -eq 0 ]
    [ "$MEMENTO_ROOTLESS_CONTAINER" = 1 ]
    awk -v expected="$MEMENTO_HOST_UID" '\''
      $1 == 0 { roots++; if ($2 != expected || $3 != 1) bad=1 }
      $2 == 0 { bad=1 }
      END { exit !(roots == 1 && !bad) }
    '\'' /proc/self/uid_map
    awk -v expected="$MEMENTO_HOST_GID" '\''
      $1 == 0 { roots++; if ($2 != expected || $3 != 1) bad=1 }
      $2 == 0 { bad=1 }
      END { exit !(roots == 1 && !bad) }
    '\'' /proc/self/gid_map
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
    if touch "$WORK/forbidden" 2>/dev/null; then exit 21; fi
    if touch "$PLANS/forbidden" 2>/dev/null; then exit 22; fi
    if touch "$SCENARIO/forbidden" 2>/dev/null; then exit 23; fi
    touch "$ENCRYPTED/encrypted-rw" "$LOG/log-rw"
    if touch /etc/forbidden 2>/dev/null; then exit 24; fi
    [ ! -e "$HOST_REPO" ]
  '

[[ ! -e "$work/forbidden" ]] || fail "work mount was writable"
[[ ! -e "$plans/forbidden" ]] || fail "plans mount was writable"
[[ ! -e "$scenario/forbidden" ]] || fail "scenario root was writable"
[[ -f "$encrypted/encrypted-rw" ]] || fail "encrypted output was not writable"
[[ -f "$log/log-rw" ]] || fail "dedicated log output was not writable"
for output in "$encrypted/encrypted-rw" "$log/log-rw"; do
  [[ $(stat -c '%u:%g' -- "$output") == "$uid:$gid" ]] || fail "container output is not owned by the host caller: $output"
done
printf 'container mount smoke test passed\n'
