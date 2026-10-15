// SPDX-License-Identifier: GPL-2.0-only

package doctor

import (
	"bufio"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const SupportedKernel = "6.17.0-35-generic"

type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail"`
	Warning bool   `json:"warning,omitempty"`
}

func Run(target string) []Check {
	if target == "" {
		target = "all"
	}
	var checks []Check
	if target == "all" || target == "syscall" {
		checks = append(checks, syscallChecks()...)
	}
	if target == "all" || target == "cpu" {
		checks = append(checks, cpuChecks()...)
	}
	if target == "all" || target == "vdso" {
		checks = append(checks, vdsoChecks()...)
	}
	return checks
}

func syscallChecks() []Check {
	checks := []Check{pathCheck("BTF", "/sys/kernel/btf/vmlinux"), pathCheck("read tracepoint", "/sys/kernel/tracing/events/syscalls/sys_enter_read")}
	if !checks[1].OK {
		checks[1] = pathCheck("read tracepoint", "/sys/kernel/debug/tracing/events/syscalls/sys_enter_read")
	}
	getrandom := pathCheck("getrandom tracepoint", "/sys/kernel/tracing/events/syscalls/sys_enter_getrandom")
	if !getrandom.OK {
		getrandom = pathCheck("getrandom tracepoint", "/sys/kernel/debug/tracing/events/syscalls/sys_enter_getrandom")
	}
	checks = append(checks, getrandom)
	privileged := os.Geteuid() == 0
	checks = append(checks, Check{Name: "eBPF privilege", OK: privileged, Detail: map[bool]string{true: "running as root", false: "not root; CAP_BPF, CAP_PERFMON and often CAP_SYS_ADMIN may be required"}[privileged], Warning: !privileged})
	return checks
}

func cpuChecks() []Check {
	flags := cpuFlags()
	checks := []Check{
		{Name: "Intel VMX", OK: flags["vmx"], Detail: flagDetail(flags["vmx"], "vmx")},
		{Name: "RDRAND", OK: flags["rdrand"], Detail: flagDetail(flags["rdrand"], "rdrand")},
		{Name: "RDSEED", OK: flags["rdseed"], Detail: flagDetail(flags["rdseed"], "rdseed"), Warning: !flags["rdseed"]},
		pathCheck("KVM random log buffer", "/sys/kernel/debug/kvm_rndlog/buffer"),
		pathCheck("KVM random log stats", "/sys/kernel/debug/kvm_rndlog/stats"),
	}
	release := kernelRelease()
	checks = append(checks, Check{Name: "supported kernel baseline", OK: release == SupportedKernel, Detail: fmt.Sprintf("running %s; validated baseline is Ubuntu %s (source package 6.17.0-35.35~24.04.1)", release, SupportedKernel), Warning: release != SupportedKernel})
	return checks
}

func vdsoChecks() []Check {
	present, hasGetrandom, err := inspectVDSO()
	if err != nil {
		return []Check{{Name: "vDSO getrandom", OK: false, Detail: err.Error(), Warning: true}}
	}
	if !present {
		return []Check{{Name: "vDSO getrandom", OK: true, Detail: "no vDSO mapping detected"}}
	}
	if hasGetrandom {
		return []Check{{Name: "vDSO getrandom", OK: false, Detail: "__vdso_getrandom is exposed and can bypass syscall tracepoints; add vdso=0 to the guest kernel command line", Warning: true}}
	}
	return []Check{{Name: "vDSO getrandom", OK: true, Detail: "vDSO is mapped but __vdso_getrandom was not found"}}
}

func pathCheck(name, path string) Check {
	_, err := os.Stat(path)
	if err == nil {
		return Check{Name: name, OK: true, Detail: path}
	}
	return Check{Name: name, OK: false, Detail: fmt.Sprintf("%s: %v", path, err)}
}

func cpuFlags() map[string]bool {
	result := make(map[string]bool)
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "flags") {
			continue
		}
		_, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		for _, flag := range strings.Fields(value) {
			result[flag] = true
		}
		break
	}
	return result
}

func flagDetail(ok bool, flag string) string {
	if ok {
		return flag + " CPU flag present"
	}
	return flag + " CPU flag missing"
}

func kernelRelease() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return runtime.GOOS + "/unknown"
	}
	return strings.TrimSpace(string(data))
}

func inspectVDSO() (bool, bool, error) {
	maps, err := os.Open("/proc/self/maps")
	if err != nil {
		return false, false, err
	}
	defer maps.Close()
	var start, end uint64
	scanner := bufio.NewScanner(maps)
	for scanner.Scan() {
		if !strings.Contains(scanner.Text(), "[vdso]") {
			continue
		}
		bounds := strings.SplitN(strings.Fields(scanner.Text())[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, _ = strconv.ParseUint(bounds[0], 16, 64)
		end, _ = strconv.ParseUint(bounds[1], 16, 64)
		break
	}
	if err := scanner.Err(); err != nil {
		return false, false, err
	}
	if start == 0 || end <= start {
		return false, false, nil
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return true, false, err
	}
	defer mem.Close()
	reader := io.NewSectionReader(mem, int64(start), int64(end-start))
	image, err := elf.NewFile(reader)
	if err != nil {
		return true, false, err
	}
	defer image.Close()
	symbols, err := image.DynamicSymbols()
	if err != nil {
		return true, false, err
	}
	for _, symbol := range symbols {
		if symbol.Name == "__vdso_getrandom" {
			return true, true, nil
		}
	}
	return true, false, nil
}
