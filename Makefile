# SPDX-License-Identifier: GPL-2.0-only

SHELLCHECK ?= shellcheck
MEMENTO_CONTAINER_IMAGE := memento-lab:0.1.0-dev

.PHONY: generate build test race vet c-tools audit safety-audit script-lint validation-tests ptrace-test container-image container-smoke container-mount-smoke check validate-safe prepare-kvm-source validate-kvm validate-kvm-reproducibility validate-reference-preflight clean

generate:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
	go generate ./ebpf

build: generate
	mkdir -p build
	go build -trimpath -o build/memento ./cmd/memento

test: generate
	go test ./...

race: generate
	go test -race ./...

vet: generate
	go vet ./...

c-tools:
	$(MAKE) -C evaluation/guest
	$(MAKE) -C evaluation/tools

audit:
	go mod verify
	go run ./tools/licensecheck
	@if ldd build/memento 2>/dev/null | grep -Eq 'libcrypto|libssl'; then echo "forbidden OpenSSL linkage" >&2; exit 1; fi

safety-audit:
	go run ./tools/safetyaudit

script-lint:
	$(SHELLCHECK) --severity=error evaluation/scripts/*.sh scripts/*.sh validation/*.sh

validation-tests:
	./validation/reference-preflight-test.sh
	./validation/container-wrapper-policy-test.sh

container-image: build
	revision="$$(git rev-parse HEAD)"; \
	if test -n "$$(git status --porcelain)"; then revision="$$revision-dirty"; fi; \
	docker build --network=none --pull=false --platform linux/amd64 \
		--build-arg MEMENTO_REVISION="$$revision" \
		--build-arg MEMENTO_BINARY_SHA256="$$(sha256sum build/memento | awk '{print $$1}')" \
		--file containers/lab/Dockerfile --tag $(MEMENTO_CONTAINER_IMAGE) .

container-mount-smoke:
	./validation/container-mount-smoke.sh

container-smoke: container-image
	./scripts/memento-container.sh smoke
	$(MAKE) container-mount-smoke

ptrace-test:
	MEMENTO_RUN_PTRACE_TEST=1 go test ./internal/memory -run '^TestDumpAndFindChildMemory$$' -count=1

check: build test race vet c-tools audit safety-audit script-lint validation-tests

validate-safe: check ptrace-test
	go test ./... -count=2

validate-kvm:
	@test -n "$(KERNEL_TREE)" || { echo "KERNEL_TREE is required" >&2; exit 2; }
	@test -n "$(KERNEL_CONFIG)" || { echo "KERNEL_CONFIG is required" >&2; exit 2; }
	@test -n "$(MODULE_SYMVERS)" || { echo "MODULE_SYMVERS is required" >&2; exit 2; }
	@test -n "$(KVM_ARTIFACT_DIR)" || { echo "KVM_ARTIFACT_DIR is required" >&2; exit 2; }
	KERNEL_CONFIG="$(KERNEL_CONFIG)" MODULE_SYMVERS="$(MODULE_SYMVERS)" \
		KVM_ARTIFACT_DIR="$(KVM_ARTIFACT_DIR)" ./validation/kvm-validate.sh "$(KERNEL_TREE)"

validate-kvm-reproducibility:
	@test -n "$(KVM_ARTIFACT_DIR_A)" || { echo "KVM_ARTIFACT_DIR_A is required" >&2; exit 2; }
	@test -n "$(KVM_ARTIFACT_DIR_B)" || { echo "KVM_ARTIFACT_DIR_B is required" >&2; exit 2; }
	./validation/kvm-reproducibility-check.sh \
		"$(KVM_ARTIFACT_DIR_A)" "$(KVM_ARTIFACT_DIR_B)"

prepare-kvm-source:
	@test -n "$(DSC)" || { echo "DSC is required" >&2; exit 2; }
	@test -n "$(SIGNER_KEYRING)" || { echo "SIGNER_KEYRING is required" >&2; exit 2; }
	@test -n "$(KERNEL_TREE)" || { echo "KERNEL_TREE is required" >&2; exit 2; }
	@test -n "$(SOURCE_EVIDENCE_DIR)" || { echo "SOURCE_EVIDENCE_DIR is required" >&2; exit 2; }
	./validation/source-prepare.sh "$(DSC)" "$(SIGNER_KEYRING)" \
		"$(KERNEL_TREE)" "$(SOURCE_EVIDENCE_DIR)"

validate-reference-preflight:
	@test -n "$(KVM_ARTIFACT_DIR)" || { echo "KVM_ARTIFACT_DIR is required" >&2; exit 2; }
	./validation/reference-preflight.sh "$(KVM_ARTIFACT_DIR)"

clean:
	rm -f build/memento ebpf/vmlinux.h ebpf/*_bpfel.go ebpf/*_bpfeb.go ebpf/*_bpfel.o ebpf/*_bpfeb.o
	$(MAKE) -C evaluation/guest clean
	$(MAKE) -C evaluation/tools clean
