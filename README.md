# Memento — ransomware PRN recovery toolkit

Memento aims to make files encrypted by ransomware decryptable after the fact.
Ransomware derives its file encryption keys from pseudo-random numbers that it obtains from the operating system and the hardware, such as `/dev/urandom`, `getrandom(2)` and the RDRAND/RDSEED instructions.
Memento records those pseudo-random numbers as they are produced, so that the keys can be rebuilt and the encrypted files recovered later.

`memento` is a Linux research prototype that records pseudo-random number (PRN) material at two boundaries and uses those records for research on recovering ransomware keys.

- Guest-side capture of `read(2)` / `getrandom(2)` with eBPF
- Host-side capture of RDRAND / RDSEED with a modified Intel KVM module
- Process memory dumps and extraction of Babuk X25519 public key candidates
- Non-destructive decryption of Babuk and Qilin
- Deliberately constrained Babuk and Qilin lab simulators

## Disclaimer

Memento is designed for authorized system administrators recovering data after a ransomware incident, and is provided for security research, technical validation and evaluation.
The project maintainers do not recommend or condone using this tool for unauthorized access to, unauthorized encryption of, or destruction of third-party systems or data, or for any other illegal or harmful purpose.

This tool is provided AS IS and does not guarantee that data or systems can be recovered.
We recommend testing it thoroughly in an isolated validation environment before deploying it in production.
We recommend using only test data with the file encryption features meant for validation.

Logs, memory dumps and other artifacts produced by this tool may contain sensitive information, including PRN values used by legitimate processes.
We recommend storing, transferring, retaining and disposing of them with controls suited to sensitive information.

## Supported environment

- Ubuntu 24.04 LTS on Intel x86-64 with VMX
- Go 1.23 or later
- A kernel that exposes BTF at `/sys/kernel/btf/vmlinux`
- clang / LLVM, bpftool, libelf development headers, GCC, GNU Make

The validated KVM reference environment is Ubuntu `6.17.0-35-generic`, source package `6.17.0-35.35~24.04.1`.
Other Linux 6.17 builds are not validated.
CPU capture also requires the modified KVM module described in the [modified KVM workflow](#modified-kvm-workflow).
Memento never loads or unloads these modules automatically.

Rootless Docker with runc, cgroup v2, the systemd cgroup driver and BuildKit (buildx) is needed only for the recommended file-based lab and decryption procedures.
It is not needed to build Memento or to run the diagnostic commands.

## Installing from source

Install the Ubuntu build dependencies, ShellCheck (used by `make check`), `jq` / `procps` (used by the E2E examples below), and Go 1.23 or later.

```sh
sudo apt-get update
sudo apt-get install -y git make gcc clang llvm linux-tools-common "linux-tools-$(uname -r)" \
  libbpf-dev libelf-dev shellcheck jq procps

git clone https://github.com/KDDIR-SEC/memento.git
cd memento
test -r /sys/kernel/btf/vmlinux
make build
sudo install -m 0755 build/memento /usr/local/bin/memento

memento version
memento --help
memento help monitor syscall
```

`make build` generates `ebpf/vmlinux.h` and the bpf2go objects, and embeds the eBPF bytecode in `build/memento`.
The generated files and binaries are deliberately kept out of Git.
To use only the binary in the checkout, skip `install` and read `memento` in the examples below as `./build/memento`.
`libbpf-dev` provides headers used by bpf2go, such as `bpf_helpers.h`, `bpf_core_read.h` and `bpf_tracing.h`.
On Ubuntu 24.04, `bpftool` is not an installable package name; the command comes from `linux-tools-common` together with the `linux-tools` package for the running kernel.

## A safe first run: system call monitoring

The following diagnostic is read-only.
On the supported Ubuntu configuration, loading eBPF normally requires root.

```sh
sudo memento doctor syscall
```

Once the diagnostic passes, start system call capture and stop it with `Ctrl-C`.

```sh
sudo memento --state-dir /var/lib/memento monitor syscall
```

The default outputs are `/var/lib/memento/log/syscall-prn.jsonl` and `/var/lib/memento/stats/syscall.json`.
The JSONL log can contain secret random values of legitimate processes, so keep the state directory private and do not publish the logs.

`memento doctor vdso` checks whether `__vdso_getrandom` may bypass the system call tracepoints.
If the guest's system call path must be observed completely, disable the vDSO path with `vdso=0`, a documented Linux kernel parameter, and check the result after rebooting.
Host-side CPU capture requires the modified KVM workflow described below before `memento doctor cpu` or `memento monitor cpu` can be used.

## Safety boundary

The simulator never treats an arbitrary directory as an encryption target.
It reads only the copies that `memento lab create` made under `<state-dir>/lab/<scenario>/work/`, and writes new files with `O_EXCL` under the scenario's `encrypted/`.
The root user, non-TTY runs, symbolic links, magic links, crossing mount boundaries, hidden paths, special files, hard links, stale manifests, and extensions outside the scenario's allow list are refused.

For file-based E2E runs, the rootless Docker wrapper is the only recommended entry point.
The wrapper adds a read-only container root filesystem, no network at run time, no Linux capabilities, enforced resource limits, and narrowly scoped bind mounts.
These reinforce the scenario and manifest checks; they do not replace them.

During simulation the scenario root, `work/` and `plans/` are mounted read-only, and only `encrypted/` and a per-run log directory are writable.
During decryption each ciphertext and pseudo-random number (PRN) log is mounted read-only, individually, and only one initially empty output directory is writable.
Temporary state lives on a dedicated tmpfs.
The wrapper does not mount the Docker socket, the host root, devices or the repository source tree, and does not offer in-place decryption.

## Recovery data flow

The same `memento` binary runs on the monitored guest and, for CPU instruction capture, on the KVM host.

```text
Guest                                      KVM host
-----                                      --------
read/getrandom -> eBPF                     RDRAND/RDSEED VM exit
       |                                          |
       +-> memento.prn/v1 JSONL                   +-> KVM ring buffer
       |                                                  |
process memory -> Babuk key candidates        memento monitor cpu
       |                                                  |
       +--------------- PRN loading <---------------------+
                              |
                       Babuk/Qilin decryption
                              |
                       new recovered file
```

Babuk decryption derives the X25519 shared secret, hashes it with SHA-512, and uses the first 32 bytes of the hash as the Sosemanuk key.
Only candidates whose ephemeral public key, derived from a PRN, matches the 32-byte public key at the end of the ciphertext are accepted for decryption.

Qilin decryption keeps the legacy OpenSSL layout.
The ChaCha20 IV is a 64-bit little-endian counter followed by a 64-bit nonce, and each RSA footer uses OAEP with SHA-1 and MGF1-SHA-1 for compatibility.
Each of the three stages obtains a 16-byte IV and a 32-byte key with `read(/dev/urandom)`, so the six captured values are the decryption input.

### PRN log format

The writers emit one JSON object with `schema: "memento.prn/v1"` per line.
Every record contains the time, source, operation, the value in lowercase hex, captured length, requested length and truncation state.
System call records add PID/TID, file descriptor, path, flags and return metadata; CPU records add the sequence number, VM/vCPU, instruction, operand width, destination register, RIP, CR3, success state, RFLAGS and host CPU metadata.

eBPF captures at most 128 bytes per event and records truncation and the number of samples lost from the perf ring.
CPU monitoring validates the magic value, version and size of the kernel records, handles partial reads, and reports the KVM ring's drop count.
The readers accept only the `memento.prn/v1` schema; the pre-rename schema and logs without a schema are deliberately rejected.

## Monitored end-to-end lab evaluation

The following examples run encryption, PID-limited eBPF observation and non-destructive decryption.
For Babuk they also do a synchronized memory dump and heuristic identification of the master public key.
Run them on a validation host, from the repository root, using only embedded fixtures.
Arbitrary input paths are not accepted, and each new scenario contains exactly one managed file, `fixture-0000.memento`.

The wrapper needs rootless Docker with runc, cgroup v2 and the systemd cgroup driver.
`make container-image` also needs BuildKit (buildx), because the Dockerfile uses `COPY --chmod`.
One way to set this up on Ubuntu 24.04 is Docker Engine from Docker's apt repository.
First add the repository as described in [Install Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/).
Then, as the user who runs the examples, install the packages and set up [rootless mode](https://docs.docker.com/engine/security/rootless/).

```bash
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-ce-rootless-extras \
  docker-buildx-plugin uidmap dbus-user-session
sudo systemctl disable --now docker.service docker.socket   # rootless only
dockerd-rootless-setuptool.sh install
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock
```

If you use Ubuntu's own `docker.io` package instead, three more steps are needed.
Install `docker-buildx`.
Take `dockerd-rootless.sh` and `dockerd-rootless-setuptool.sh` from Docker's `docker-ce-rootless-extras`, because Ubuntu's package does not ship them.
With Ubuntu's `rootlesskit` 1.x, set `DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=false` for the rootless daemon, for example in a drop-in for the `docker.service` user unit.

The following checks do not encrypt any files.

```bash
sudo memento doctor syscall
sudo memento doctor vdso
docker info --format 'driver={{.CgroupDriver}} version={{.CgroupVersion}} security={{json .SecurityOptions}}'
test -z "$(docker ps -q)"                 # require that no containers are running
make container-image
make container-smoke
cmp -- build/memento "$(command -v memento)" # host binary matches the image input
```

The wrapper uses a read-only root filesystem, `--network=none`, no Linux capabilities, enforced resource limits, and narrowly scoped mounts.
Memento shows the complete manifest and every target before it asks for an exact `YES` or `NO`.
Do not type `YES` until the PID-limited monitor has started in terminal 2.
The examples below use paths for new state directories outside the checkout.
The monitor creates root-owned directories inside them, which `go test ./...` in `make check` could not read if they were under the repository.
If any of them already exists, choose another unused path.

### Babuk: encryption, monitoring, dump, key identification, decryption

In **terminal 1**, create a per-run key and a manifest with a single file.
Review the encryption plan shown, then start the wrapper.
The wrapper stops at the approval prompt.

```bash
cd /path/to/memento
BABUK_STATE="$HOME/memento-e2e/readme-babuk-e2e"
test ! -e "$BABUK_STATE"

KEY_OUTPUT=$(memento --state-dir "$BABUK_STATE" genkey babuk \
  --output "$BABUK_STATE/keys/e2e.json")
printf '%s\n' "$KEY_OUTPUT"
PUBLIC_KEY=$(printf '%s\n' "$KEY_OUTPUT" | sed -n 's/^public key: //p')
test "${#PUBLIC_KEY}" -eq 64

memento --state-dir "$BABUK_STATE" lab init \
  --scenario babuk-e2e --allow-ext .memento
memento --state-dir "$BABUK_STATE" lab create \
  --scenario babuk-e2e --fixture sample.txt --ext .memento --count 1
PLAN_OUTPUT=$(memento --state-dir "$BABUK_STATE" lab plan-encryption \
  --scenario babuk-e2e --ext .memento)
printf '%s\n' "$PLAN_OUTPUT"
MANIFEST=$(printf '%s\n' "$PLAN_OUTPUT" | sed -n 's/^manifest: //p')
test -f "$MANIFEST"

./scripts/memento-container.sh encrypt babuk \
  --state-dir "$BABUK_STATE" \
  --scenario babuk-e2e \
  --manifest "$MANIFEST" \
  --public-key "$PUBLIC_KEY" \
  --validation-stop-after-prn
```

While terminal 1 is waiting, in **terminal 2** find the PID of the Memento child process in the only container, and start monitoring.
Leave this command running; return to terminal 1 once the monitor has printed its output paths and no startup error has followed.
Confirm that the only target is `fixture-0000.memento`, and type `YES`.
When encryption finishes, return to terminal 2 and press `Ctrl-C` once so monitoring writes its statistics.

```bash
cd /path/to/memento
BABUK_STATE="$HOME/memento-e2e/readme-babuk-e2e"
mapfile -t CIDS < <(docker ps -q)
test "${#CIDS[@]}" -eq 1
INIT_PID=$(docker inspect --format '{{.State.Pid}}' "${CIDS[0]}")
mapfile -t TARGETS < <(pgrep -P "$INIT_PID" -x memento)
test "${#TARGETS[@]}" -eq 1
TARGET_PID=${TARGETS[0]}

MONITOR_STATE="$BABUK_STATE/monitor-state"
EVIDENCE="$BABUK_STATE/evidence"
install -d -m 0700 "$MONITOR_STATE" "$EVIDENCE"
sudo memento --state-dir "$MONITOR_STATE" monitor syscall \
  --pid "$TARGET_PID" \
  --output "$EVIDENCE/syscall-prn.jsonl" \
  --stats "$EVIDENCE/syscall-stats.json" \
  --dump-on-prn --dump-operation read \
  --dump-path /dev/urandom --dump-length 32 \
  --dump-wait-stopped 20s --resume-after-dump
```

Still in terminal 2, check the capture statistics, identify the key without giving the identification the expected key, and decrypt from the eBPF log.
Only the two monitor output files are handed back to the current user for checking.
Ownership of the dump tree as a whole is not changed.

```bash
PRN_LOG="$EVIDENCE/syscall-prn.jsonl"
STATS="$EVIDENCE/syscall-stats.json"
sudo chown -- "$(id -u):$(id -g)" "$PRN_LOG" "$STATS"
chmod 0600 "$PRN_LOG" "$STATS"
jq -e '.read_events == 1 and .getrandom_events == 0 and
       .lost_samples == 0 and .truncated_events == 0' "$STATS"

mapfile -t DUMPS < <(sudo find "$MONITOR_STATE/dump/$TARGET_PID" \
  -mindepth 1 -maxdepth 1 -type d -print)
test "${#DUMPS[@]}" -eq 1
DUMP_DIR=${DUMPS[0]}
CIPHERTEXT="$BABUK_STATE/lab/babuk-e2e/encrypted/fixture-0000.memento.babyk"
IDENTIFY_OUTPUT=$(sudo memento identify babuk \
  --dump-dir "$DUMP_DIR" --input "$CIPHERTEXT" --prn-log "$PRN_LOG" \
  --output "$BABUK_STATE/babuk-identification.json")
printf '%s\n' "$IDENTIFY_OUTPUT"
SELECTED_KEY=$(printf '%s\n' "$IDENTIFY_OUTPUT" |
  sed -n 's/^Babuk master public key: //p')
EXPECTED_KEY=$(jq -r '.public_key_hex' "$BABUK_STATE/keys/e2e.json")
test "$SELECTED_KEY" = "$EXPECTED_KEY"

RECOVERED="$BABUK_STATE/recovered-e2e"
install -d -m 0700 "$RECOVERED"
./scripts/memento-container.sh decrypt babuk \
  --input "$CIPHERTEXT" --output-dir "$RECOVERED" \
  --prn-log "$PRN_LOG" --public-key "$SELECTED_KEY"
ORIGINAL="$BABUK_STATE/lab/babuk-e2e/work/fixture-0000.memento"
cmp -- "$ORIGINAL" "$RECOVERED/fixture-0000.memento"
sha256sum -- "$ORIGINAL" "$RECOVERED/fixture-0000.memento"
```

The legacy Babuk format has no authentication tag, so key identification is heuristic.
Make the independent public key match and the final byte-for-byte comparison the pass criteria, not the heuristic score.

### Qilin: encryption, monitoring, PRN classification, decryption

In **terminal 1**, create a new scenario separate from the Babuk one, and let it stop at the approval prompt.

```bash
cd /path/to/memento
QILIN_STATE="$HOME/memento-e2e/readme-qilin-e2e"
test ! -e "$QILIN_STATE"

memento --state-dir "$QILIN_STATE" lab init \
  --scenario qilin-e2e --allow-ext .memento
memento --state-dir "$QILIN_STATE" lab create \
  --scenario qilin-e2e --fixture sample.txt --ext .memento --count 1
PLAN_OUTPUT=$(memento --state-dir "$QILIN_STATE" lab plan-encryption \
  --scenario qilin-e2e --ext .memento)
printf '%s\n' "$PLAN_OUTPUT"
MANIFEST=$(printf '%s\n' "$PLAN_OUTPUT" | sed -n 's/^manifest: //p')
test -f "$MANIFEST"

./scripts/memento-container.sh encrypt qilin \
  --state-dir "$QILIN_STATE" \
  --scenario qilin-e2e \
  --manifest "$MANIFEST"
```

While terminal 1 is waiting, start the PID-limited monitor in **terminal 2**.
Once the output paths are printed and no startup error has followed, check the one target shown in terminal 1 and type `YES`.
When encryption finishes, press `Ctrl-C` once in terminal 2.

```bash
cd /path/to/memento
QILIN_STATE="$HOME/memento-e2e/readme-qilin-e2e"
mapfile -t CIDS < <(docker ps -q)
test "${#CIDS[@]}" -eq 1
INIT_PID=$(docker inspect --format '{{.State.Pid}}' "${CIDS[0]}")
mapfile -t TARGETS < <(pgrep -P "$INIT_PID" -x memento)
test "${#TARGETS[@]}" -eq 1
TARGET_PID=${TARGETS[0]}

MONITOR_STATE="$QILIN_STATE/monitor-state"
EVIDENCE="$QILIN_STATE/evidence"
install -d -m 0700 "$MONITOR_STATE" "$EVIDENCE"
sudo memento --state-dir "$MONITOR_STATE" monitor syscall \
  --pid "$TARGET_PID" \
  --output "$EVIDENCE/syscall-prn.jsonl" \
  --stats "$EVIDENCE/syscall-stats.json"
```

Check the six `/dev/urandom` reads needed for decryption, and decrypt using the PID-limited eBPF log.
How many of the `crypto/rand.Reader` calls used inside OAEP show up as OS-level `getrandom` system calls can vary with the Go toolchain, FIPS mode and vDSO use, so a fixed count is not a pass criterion.

```bash
PRN_LOG="$EVIDENCE/syscall-prn.jsonl"
STATS="$EVIDENCE/syscall-stats.json"
sudo chown -- "$(id -u):$(id -g)" "$PRN_LOG" "$STATS"
chmod 0600 "$PRN_LOG" "$STATS"
jq -e '.read_events == 6 and
       .lost_samples == 0 and .truncated_events == 0' "$STATS"
jq -s -e '
  [.[] | select(.source == "syscall" and .operation == "read" and
                .syscall.name == "read" and .syscall.path == "/dev/urandom") |
         .captured_length] == [16, 32, 16, 32, 16, 32]
' "$PRN_LOG"
jq -s '[.[] | select(.operation == "getrandom") |
        {captured_length, requested_length, truncated}]' "$PRN_LOG"

CIPHERTEXT="$QILIN_STATE/lab/qilin-e2e/encrypted/fixture-0000.memento.qilin"
RECOVERED="$QILIN_STATE/recovered-e2e"
install -d -m 0700 "$RECOVERED"
./scripts/memento-container.sh decrypt qilin \
  --input "$CIPHERTEXT" --output-dir "$RECOVERED" \
  --prn-log "$PRN_LOG"
ORIGINAL="$QILIN_STATE/lab/qilin-e2e/work/fixture-0000.memento"
cmp -- "$ORIGINAL" "$RECOVERED/fixture-0000.memento"
sha256sum -- "$ORIGINAL" "$RECOVERED/fixture-0000.memento"
```

The six reads are the three IV / key pairs used for decryption.
If 20-byte `getrandom` records are observed, they are shown for reference as randomness used inside RSA-OAEP, but are excluded from the decryption candidates.
Mixed-in 16 / 32-byte `getrandom` records do not become decryption candidates either.
Qilin decryption is also heuristic because there is no authentication tag.
Use the final `cmp` result to decide correctness, not the score.

## Commands

| Command | Purpose |
|---|---|
| `memento doctor [syscall\|cpu\|vdso]` | Read-only diagnosis of prerequisites |
| `memento monitor syscall` | Captures `/dev/random`, `/dev/urandom` and `getrandom`, optionally limited to one TGID |
| `memento monitor cpu` | Reads the modified KVM's debugfs ring |
| `memento dump --pid PID` | Dumps selected process mappings and shows a bounded number of Babuk key candidates |
| `memento identify babuk` | Heuristically ranks Babuk master public key candidates from a private dump |
| `memento decrypt babuk\|qilin` | Decrypts into `var/recovered/` without modifying the ciphertext |
| `memento lab init/create/plan-encryption/encrypt` | Managed, approved simulation |
| `memento verify cpu` | Compares guest-side binary records with host-side JSONL |
| `memento genkey babuk` | Generates evaluation key material with mode `0600` |

The state directory is chosen in the order `--state-dir`, `MEMENTO_STATE_DIR`, `./var`.
The state directory uses mode `0700`; logs, dumps, manifests, recovered files and key material use mode `0600`.

What `identify babuk` reports is heuristic, not a judgement of authenticity.
The Babuk format has no tag that can prove the chosen master public key.
When validating, compare the choice with a ground truth kept separately.

<a id="modified-kvm-workflow"></a>

## Modified KVM workflow

`kvm/patches/0001-kvm-rdrand-rdseed-monitor.patch` targets the Ubuntu source package `6.17.0-35.35~24.04.1`.
Build it only inside a disposable, unmodified source tree.

Install the tools needed to verify the source package signature and build kernel modules.
If Ubuntu's `deb-src` repositories are enabled, also install the full Ubuntu kernel build dependencies with `apt-get build-dep`.

```sh
sudo apt-get update
sudo apt-get install -y build-essential bc bison flex cpio dwarves kmod \
  libelf-dev libssl-dev rsync wget ubuntu-keyring dpkg-dev gpgv
# Run this if the Noble deb-src repositories are enabled.
sudo apt-get build-dep -y linux-hwe-6.17
```

From the repository root, fetch the exact three source package files stored on the official Launchpad into a new private working directory.
The following example does not reuse an existing directory.

```sh
REPO_ROOT=$PWD
KVM_WORK=/path/to/private/memento-kvm-6.17.0-35
test ! -e "$KVM_WORK"
install -d -m 0700 "$KVM_WORK/source-package"

SOURCE_URL='https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/linux-hwe-6.17/6.17.0-35.35~24.04.1'
wget --https-only --directory-prefix="$KVM_WORK/source-package" \
  "$SOURCE_URL/linux-hwe-6.17_6.17.0-35.35~24.04.1.dsc" \
  "$SOURCE_URL/linux-hwe-6.17_6.17.0.orig.tar.gz" \
  "$SOURCE_URL/linux-hwe-6.17_6.17.0-35.35~24.04.1.diff.gz"

cd "$REPO_ROOT"
make prepare-kvm-source \
  DSC="$KVM_WORK/source-package/linux-hwe-6.17_6.17.0-35.35~24.04.1.dsc" \
  SIGNER_KEYRING=/usr/share/keyrings/ubuntu-archive-keyring.gpg \
  KERNEL_TREE="$KVM_WORK/pristine-6.17.0-35" \
  SOURCE_EVIDENCE_DIR="$KVM_WORK/source-evidence"
```

`prepare-kvm-source` verifies the signing fingerprint of the `.dsc`, the SHA-256 values recorded in it and the package version before extracting, and creates an initial Git snapshot without changes.
Do not trust the fetched files before their signature is verified.

Specify the configuration file and `Module.symvers` from the Ubuntu kernel package of the matching version.
Build after confirming that the following two files exist and are readable.

```sh
KERNEL_CONFIG=/boot/config-6.17.0-35-generic
MODULE_SYMVERS=/usr/src/linux-headers-6.17.0-35-generic/Module.symvers
test -r "$KERNEL_CONFIG"
test -r "$MODULE_SYMVERS"

make validate-kvm \
  KERNEL_TREE="$KVM_WORK/pristine-6.17.0-35" \
  KERNEL_CONFIG="$KERNEL_CONFIG" \
  MODULE_SYMVERS="$MODULE_SYMVERS" \
  KVM_ARTIFACT_DIR="$KVM_WORK/kvm-artifacts"
```

This verifies the Ubuntu package version, applies the patch in a temporary worktree, checks the 104-byte record ABI, and then builds `kvm.ko` and `kvm-intel.ko`.
Unloading KVM interrupts running VMs and changes the host kernel state, so Memento deliberately does not automate swapping modules.
Stop all VMs, secure an out-of-band recovery path, note the paths of the packaged modules, and then load or unload the experimental modules by hand.

After the modules are loaded, `memento doctor cpu` checks the `/sys/kernel/debug/kvm_rndlog/buffer` and `stats` interfaces.
Do not install the experimental modules permanently under `/lib/modules`.
Keep it so that a normal reboot returns the host to the packaged modules.

## Limitations and release status

- The only environment where capture with the modified KVM is formally validated is Ubuntu 24.04, Intel x86-64 VMX, `6.17.0-35-generic`.
  AMD SVM and other kernels are unsupported or best effort.
- Random numbers returned only through `__vdso_getrandom` do not reach the system call tracepoints.
  Run `memento doctor vdso` before relying on system call capture.
- The legacy Babuk and Qilin formats do not authenticate the ciphertext body.
  Candidate ranking is heuristic, so verify recovered data with independent sources wherever possible.
- Ring buffer overflows are reported, but dropped CPU records cannot be recovered.
- Memento is a research prototype at version `0.1.0-dev`.
  Performance measurements do not guarantee compatibility or pass/fail.

## Validation

```sh
make check
make validate-safe
```

Neither target performs filesystem encryption.
The KVM build and the privileged reference host checks require separate approval by an operator.
Run them only on disposable validation hosts with a verified recovery path.

## License

The project code is licensed under GPL-2.0-only.
The bundled Sosemanuk implementation follows the original X-CRYPT license.
See [`internal/crypto/sosemanuk/LICENSE`](internal/crypto/sosemanuk/LICENSE) for details.
