// SPDX-License-Identifier: GPL-2.0-only

// safetyaudit prevents automated test and validation entry points from
// invoking the filesystem encryption simulator. In-memory
// TransformBabuk/TransformQilin tests remain permitted.
package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cli, err := os.ReadFile("cmd/memento/main.go")
	if err != nil {
		return err
	}
	if bytes.Contains(cli, []byte(`"yes"`)) || bytes.Contains(cli, []byte(`"force"`)) {
		return fmt.Errorf("CLI contains an approval-bypass flag marker")
	}
	if err := auditManualContainerWrapper("scripts/memento-container.sh"); err != nil {
		return err
	}
	if err := auditEncryptionApprovalGate("internal/lab/lab.go"); err != nil {
		return err
	}
	if err := auditRootlessContainerGate("internal/lab/rootless_container.go"); err != nil {
		return err
	}
	if err := auditActiveBranding(); err != nil {
		return err
	}
	return filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path == ".git" || path == "build" || path == "var" {
				return filepath.SkipDir
			}
			return nil
		}
		clean := filepath.ToSlash(path)
		if clean == "scripts/memento-container.sh" {
			return nil
		}
		automated := strings.HasSuffix(clean, "_test.go") ||
			strings.HasPrefix(clean, "evaluation/scripts/") ||
			strings.HasPrefix(clean, "scripts/") ||
			strings.HasPrefix(clean, "validation/") || clean == "Makefile"
		if !automated {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, forbidden := range [][]byte{
			[]byte("lab" + " encrypt"),
			[]byte("memento" + " encrypt"),
			[]byte(".Execute("),
			[]byte("executeApproved("),
		} {
			if bytes.Contains(data, forbidden) {
				return fmt.Errorf("automated entry point %s contains forbidden filesystem-encryption call marker %q", path, forbidden)
			}
		}
		if strings.HasPrefix(clean, "validation/") && strings.HasSuffix(clean, ".sh") {
			for _, forbidden := range [][]byte{
				[]byte("ins" + "mod"),
				[]byte("rm" + "mod"),
				[]byte("modprobe" + " -r"),
				[]byte("shut" + "down"),
				[]byte("re" + "boot"),
				[]byte("virsh" + " start"),
				[]byte("virsh" + " destroy"),
				[]byte("qemu-system"),
			} {
				if bytes.Contains(data, forbidden) {
					return fmt.Errorf("validation script %s contains forbidden host-state operation %q", path, forbidden)
				}
			}
		}
		return nil
	})
}

func auditEncryptionApprovalGate(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("encryption approval gate: %w", err)
	}
	for _, required := range []string{
		"requestEncryptionApproval",
		"Proceed with encryption? Type YES to continue or NO to cancel:",
		"case \"YES\":",
		"case \"NO\":",
		"Encryption cancelled; no files were created.",
		"approval must be exactly YES or NO; no files were encrypted",
		"file.Path",
		"file.Size",
		"file.SHA256",
		"isTerminal",
	} {
		if !bytes.Contains(data, []byte(required)) {
			return fmt.Errorf("encryption approval gate lacks required safety marker %q", required)
		}
	}
	if bytes.Count(data, []byte("m.Revalidate(options.Scenario, options.Manifest)")) < 2 {
		return fmt.Errorf("encryption approval gate must revalidate the manifest before and after approval")
	}
	if bytes.Contains(data, []byte("ENCRYPT ")) {
		return fmt.Errorf("encryption approval gate contains the removed long-form confirmation phrase")
	}
	return nil
}

func auditActiveBranding() error {
	removed := "ra" + "re"
	removedUpper := strings.ToUpper(removed)
	oldModule := "github.com/ke-kita06/" + "ransom-" + "recovery"
	forbidden := []string{
		oldModule,
		removedUpper + "_",
		removed + ".",
		removed + "-",
		"." + removed,
		"/" + removed,
		"`" + removed + "`",
		"\"" + removed + "\"",
		"'" + removed + "'",
		" " + removed + " ",
	}
	return filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		clean := filepath.ToSlash(path)
		if entry.IsDir() {
			if clean == ".git" || clean == "build" || clean == "var" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Base(clean) == "vmlinux.h" {
			return nil
		}
		extension := filepath.Ext(clean)
		basename := filepath.Base(clean)
		textFile := extension == ".go" || extension == ".c" || extension == ".h" ||
			extension == ".sh" || extension == ".py" || extension == ".md" ||
			extension == ".json" || extension == ".yml" || extension == ".yaml" ||
			extension == ".mod" || basename == "Makefile" || basename == "Dockerfile" ||
			basename == ".dockerignore"
		if !textFile {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, marker := range forbidden {
			if bytes.Contains(data, []byte(marker)) {
				return fmt.Errorf("active file %s contains removed brand marker %q", clean, marker)
			}
		}
		return nil
	})
}

func auditManualContainerWrapper(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("manual container wrapper: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("manual container wrapper must be a regular executable file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, required := range []string{
		"name=rootless",
		"(( EUID != 0 ))",
		"is_supported_cgroup",
		"verify_runtime_isolation",
		"[[ -t 0 && -t 1 ]]",
		"--pull=never",
		"--init",
		"--runtime=runc",
		"--network=none",
		"--read-only",
		"--cap-drop=ALL",
		"no-new-privileges:true",
		"--pids-limit=64",
		"--memory=1g",
		"--cpus=2",
		"--user 0:0",
		"MEMENTO_ROOTLESS_CONTAINER=1",
		"MEMENTO_HOST_UID=",
		"MEMENTO_HOST_GID=",
		"src=$scenario_root,dst=$scenario_root,readonly",
		"src=$encrypted,dst=$encrypted,bind-propagation=rprivate",
		"readonly,bind-propagation=rprivate",
		"lab encrypt",
		"requires an exact YES or NO response",
	} {
		if !bytes.Contains(data, []byte(required)) {
			return fmt.Errorf("manual container wrapper lacks required safety marker %q", required)
		}
	}
	if bytes.Count(data, []byte("lab encrypt")) != 1 {
		return fmt.Errorf("manual container wrapper must contain exactly one filesystem-encryption entry path")
	}
	for _, forbidden := range []string{
		"--privileged",
		"/var/run/docker.sock",
		"--network=host",
		"--publish",
		"--device",
		"--use-api-socket",
		"--in-place",
		"--yes",
		"--force",
		"ENCRYPT ",
	} {
		if bytes.Contains(data, []byte(forbidden)) {
			return fmt.Errorf("manual container wrapper contains forbidden safety marker %q", forbidden)
		}
	}
	return nil
}

func auditRootlessContainerGate(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("rootless container gate: %w", err)
	}
	for _, required := range []string{
		"/.dockerenv",
		"/proc/self/uid_map",
		"/proc/self/gid_map",
		"/proc/self/status",
		"/sys/class/net",
		"CapEff",
		"NoNewPrivs",
		"Seccomp",
		"MEMENTO_ROOTLESS_CONTAINER",
	} {
		if !bytes.Contains(data, []byte(required)) {
			return fmt.Errorf("rootless container gate lacks required attestation marker %q", required)
		}
	}
	return nil
}
