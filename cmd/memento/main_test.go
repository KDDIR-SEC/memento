// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
)

func TestVersionAndPositionals(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"version"}, nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout.String()) != version {
		t.Fatalf("version output = %q", stdout.String())
	}
	if err := run([]string{"version", "extra"}, nil, &stdout, &stderr); err == nil {
		t.Fatal("version accepted an extra argument")
	}
}

func TestHelpFormsAreSuccessfulAndSideEffectFree(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "must-not-exist")
			invocation := append([]string{"--state-dir", stateDir}, args...)
			var stdout, stderr bytes.Buffer
			if err := run(invocation, nil, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stdout.String(), "Usage: memento") || stderr.Len() != 0 {
				t.Fatalf("unexpected help output: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if _, err := os.Lstat(stateDir); !os.IsNotExist(err) {
				t.Fatalf("help created state: %v", err)
			}
		})
	}
}

func TestEveryHelpTopicSupportsHelpCommandAndFlag(t *testing.T) {
	for topic := range helpTopics {
		t.Run(strings.ReplaceAll(topic, " ", "_"), func(t *testing.T) {
			for _, invocation := range [][]string{
				append([]string{"help"}, strings.Fields(topic)...),
				append(strings.Fields(topic), "--help"),
				append(strings.Fields(topic), "-h"),
			} {
				stateDir := filepath.Join(t.TempDir(), "must-not-exist")
				args := append([]string{"--state-dir", stateDir}, invocation...)
				var stdout, stderr bytes.Buffer
				if err := run(args, nil, &stdout, &stderr); err != nil {
					t.Fatalf("%v: %v", invocation, err)
				}
				if !strings.Contains(stdout.String(), "Usage: memento "+topic) {
					t.Fatalf("%v: unexpected help output %q", invocation, stdout.String())
				}
				if stderr.Len() != 0 {
					t.Fatalf("%v: unexpected stderr %q", invocation, stderr.String())
				}
				if _, err := os.Lstat(stateDir); !os.IsNotExist(err) {
					t.Fatalf("%v: help created state: %v", invocation, err)
				}
			}
		})
	}
}

func TestUnknownHelpTopicFailsWithoutSideEffects(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "must-not-exist")
	for _, args := range [][]string{
		{"help", "unknown"},
		{"monitor", "syscall", "--unknown", "--help"},
		{"monitor", "syscall", "--help", "extra"},
	} {
		var stdout, stderr bytes.Buffer
		if err := run(append([]string{"--state-dir", stateDir}, args...), nil, &stdout, &stderr); err == nil {
			t.Fatalf("invalid help invocation was accepted: %v", args)
		}
	}
	if _, err := os.Lstat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("unknown help topic created state: %v", err)
	}
}

func TestDumpRecordSelector(t *testing.T) {
	record := prnlog.Record{
		Operation:       "read",
		CapturedLength:  32,
		RequestedLength: 32,
		Syscall:         &prnlog.SyscallMeta{Path: "/dev/urandom"},
	}
	if !matchesDumpRecord(record, "read", "/dev/urandom", 32) {
		t.Fatal("expected Babuk random-device event did not match")
	}
	for name, changed := range map[string]prnlog.Record{
		"operation": {Operation: "getrandom", CapturedLength: 32, RequestedLength: 32, Syscall: record.Syscall},
		"path":      {Operation: "read", CapturedLength: 32, RequestedLength: 32, Syscall: &prnlog.SyscallMeta{Path: "/dev/random"}},
		"length":    {Operation: "read", CapturedLength: 31, RequestedLength: 32, Syscall: record.Syscall},
		"truncated": {Operation: "read", CapturedLength: 32, RequestedLength: 32, Truncated: true, Syscall: record.Syscall},
	} {
		if matchesDumpRecord(changed, "read", "/dev/urandom", 32) {
			t.Fatalf("%s mismatch was accepted", name)
		}
	}
}

func TestInvalidCLIHasNoFilesystemSideEffects(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "must-not-exist")
	var stdout, stderr bytes.Buffer
	err := run([]string{"--state-dir", stateDir, "dump", "--pid", "1", "extra"}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("dump accepted an extra positional argument")
	}
	if _, statErr := os.Lstat(stateDir); !os.IsNotExist(statErr) {
		t.Fatalf("invalid command created state directory: %v", statErr)
	}
}

func TestManagedLabPlanningCLI(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	var stdout, stderr bytes.Buffer
	base := []string{"--state-dir", stateDir}
	if err := run(append(base, "lab", "init", "--scenario", "safe", "--allow-ext", ".memento"), nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := run(append(base, "lab", "create", "--scenario", "safe", "--fixture", "sample.txt", "--ext", ".memento", "--count", "1"), nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "fixture-0000.memento") {
		t.Fatalf("unexpected create output: %s", stdout.String())
	}
	stdout.Reset()
	if err := run(append(base, "lab", "plan-encryption", "--scenario", "safe", "--ext", ".memento"), nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "files: 1") || !strings.Contains(stdout.String(), "fixture-0000.memento") {
		t.Fatalf("unexpected plan output: %s", stdout.String())
	}
	if err := run(append(base, "lab", "init", "--scenario", "other", "--allow-ext", ".txt", "extra"), nil, &stdout, &stderr); err == nil {
		t.Fatal("lab init accepted an extra positional argument")
	}
}

func TestManagedLabCreateRejectsUnsafeArguments(t *testing.T) {
	for name, createArgs := range map[string][]string{
		"missing extension":  {"--scenario", "safe"},
		"allowlist mismatch": {"--scenario", "safe", "--ext", ".txt"},
		"unknown fixture":    {"--scenario", "safe", "--fixture", "missing.txt", "--ext", ".memento"},
		"zero count":         {"--scenario", "safe", "--ext", ".memento", "--count", "0"},
		"excess count":       {"--scenario", "safe", "--ext", ".memento", "--count", "1001"},
		"extra argument":     {"--scenario", "safe", "--ext", ".memento", "extra"},
	} {
		t.Run(name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			var stdout, stderr bytes.Buffer
			base := []string{"--state-dir", stateDir}
			if err := run(append(base, "lab", "init", "--scenario", "safe", "--allow-ext", ".memento"), nil, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			if err := run(append(append(base, "lab", "create"), createArgs...), nil, &stdout, &stderr); err == nil {
				t.Fatalf("unsafe create arguments were accepted: %v", createArgs)
			}
		})
	}
}

func TestManagedLabCreateRefusesExistingOutput(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	var stdout, stderr bytes.Buffer
	base := []string{"--state-dir", stateDir}
	if err := run(append(base, "lab", "init", "--scenario", "safe", "--allow-ext", ".memento"), nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	args := append(base, "lab", "create", "--scenario", "safe", "--ext", ".memento", "--count", "1")
	if err := run(args, nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if err := run(args, nil, &stdout, &stderr); err == nil {
		t.Fatal("lab create overwrote an existing managed fixture")
	}
}

func TestRemovedCompatibilityRoutesAreRejected(t *testing.T) {
	for _, args := range [][]string{
		{"create", "-t", "txt", "-n", "1"},
		{"encrypt", "babuk"},
		{"monitor", "-t", "read"},
		{"dump", "-p", "1"},
		{"decrypt", "-r", "babuk"},
		{"lab", "encrypt", "babuk", "--dry", "--type", "memento"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "must-not-exist")
			var stdout, stderr bytes.Buffer
			if err := run(append([]string{"--state-dir", stateDir}, args...), nil, &stdout, &stderr); err == nil {
				t.Fatalf("removed compatibility route was accepted: %v", args)
			}
			if _, err := os.Lstat(stateDir); !os.IsNotExist(err) {
				t.Fatalf("rejected route created state: %v", err)
			}
		})
	}
}

func TestSameFileSnapshotDetectsContentReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !sameFileSnapshot(before, before) {
		t.Fatal("identical snapshot was rejected")
	}
	if err := os.WriteFile(path, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || !os.SameFile(before, after) {
		t.Fatal("test setup did not preserve legacy identity fields")
	}
	if sameFileSnapshot(before, after) {
		t.Fatal("content replacement with restored mtime was accepted")
	}
}

func TestVerifyCPURejectsCF0AndExtraRecords(t *testing.T) {
	root := t.TempDir()
	guest := filepath.Join(root, "guest.bin")
	host := filepath.Join(root, "host.jsonl")
	record := make([]byte, 24)
	record[12], record[13], record[14] = 1, 64, 0
	binary.LittleEndian.PutUint64(record[16:24], 7)
	if err := os.WriteFile(guest, record, 0o600); err != nil {
		t.Fatal(err)
	}
	extra := `{"schema":"memento.prn/v1","source":"cpu","operation":"rdrand","value_hex":"0000000000000007","captured_length":8,"requested_length":8,"truncated":false,"vm":{"operand_bits":64}}` + "\n"
	if err := os.WriteFile(host, []byte(extra), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := runVerify([]string{"cpu", "--guest-log", guest, "--host-log", host}, &stdout, &stderr); err == nil {
		t.Fatal("verify cpu accepted cf=0 and an unmatched host record")
	}
}

func TestVerifyCPURequiresThreadAndVCPUCounts(t *testing.T) {
	root := t.TempDir()
	guest := filepath.Join(root, "guest.bin")
	host := filepath.Join(root, "host.jsonl")
	record := make([]byte, 24)
	record[12], record[13], record[14] = 1, 64, 1
	binary.LittleEndian.PutUint64(record[16:24], 7)
	if err := os.WriteFile(guest, record, 0o600); err != nil {
		t.Fatal(err)
	}
	line := `{"schema":"memento.prn/v1","source":"cpu","operation":"rdrand","value_hex":"0000000000000007","captured_length":8,"requested_length":8,"truncated":false,"vm":{"operand_bits":64,"vcpu_id":0}}` + "\n"
	if err := os.WriteFile(host, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"cpu", "--guest-log", guest, "--host-log", host, "--require-threads", "1", "--require-vcpus", "1"}
	if err := runVerify(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	wrongVCPUs := append([]string(nil), args...)
	wrongVCPUs[len(wrongVCPUs)-1] = "2"
	if err := runVerify(wrongVCPUs, &stdout, &stderr); err == nil {
		t.Fatal("verify cpu accepted the wrong required vCPU count")
	}
}
