// SPDX-License-Identifier: GPL-2.0-only

package lab

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KDDIR-SEC/memento/internal/state"
	"golang.org/x/sys/unix"
)

func testManager(t *testing.T) Manager {
	t.Helper()
	root := t.TempDir()
	layout, err := state.Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	return Manager{State: layout}
}

func TestPlanAndModificationInvalidation(t *testing.T) {
	manager := testManager(t)
	if _, err := manager.Init("safe", []string{".txt"}); err != nil {
		t.Fatal(err)
	}
	fixture, err := manager.Create("safe", "sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	manifest, _, err := manager.Plan("safe", []string{".txt"})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.TotalFiles != 1 || manifest.Files[0].Path != "sample.txt" {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	if err := os.WriteFile(fixture, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Revalidate("safe", manifest); err == nil {
		t.Fatal("modified fixture did not invalidate manifest")
	}
}

func TestPlanRejectsSymlinkAndUnallowedExtension(t *testing.T) {
	manager := testManager(t)
	if _, err := manager.Init("safe", []string{".txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create("safe", "sample.txt"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Plan("safe", []string{".pdf"}); err == nil {
		t.Fatal("unallowed extension was accepted")
	}
	link := filepath.Join(manager.State.Lab, "safe", "work", "escape.txt")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Plan("safe", []string{".txt"}); err == nil {
		t.Fatal("symlink was accepted")
	}
}

func TestExecutionGate(t *testing.T) {
	if err := checkExecutionGate(0, true); err == nil {
		t.Fatal("root execution accepted")
	}
	if err := checkExecutionGate(1000, false); err == nil {
		t.Fatal("non-TTY execution accepted")
	}
	if err := checkExecutionGate(1000, true); err != nil {
		t.Fatalf("valid execution gate rejected: %v", err)
	}
	if resolveFlags&unix.RESOLVE_NO_XDEV == 0 || resolveFlags&unix.RESOLVE_NO_SYMLINKS == 0 || resolveFlags&unix.RESOLVE_NO_MAGICLINKS == 0 || resolveFlags&unix.RESOLVE_BENEATH == 0 {
		t.Fatal("required openat2 resolution flags are missing")
	}
}

func TestEncryptionApprovalRequiresExactYES(t *testing.T) {
	manifest := Manifest{
		CanonicalRoot:      "/validation/work",
		Extensions:         []string{".memento"},
		TotalFiles:         2,
		TotalBytes:         3,
		EncryptedOutputDir: "/validation/encrypted",
		Files: []FileRecord{
			{Path: "fixture-0000.memento", Size: 1, SHA256: strings.Repeat("a", 64)},
			{Path: "fixture-0001.memento", Size: 2, SHA256: strings.Repeat("b", 64)},
		},
	}
	tests := []struct {
		name     string
		input    string
		approved bool
	}{
		{name: "yes", input: "YES\n", approved: true},
		{name: "yes CRLF", input: "YES\r\n", approved: true},
		{name: "no", input: "NO\n"},
		{name: "lowercase", input: "yes\n"},
		{name: "abbreviated", input: "Y\n"},
		{name: "empty line", input: "\n"},
		{name: "leading space", input: " YES\n"},
		{name: "trailing space", input: "YES \n"},
		{name: "unknown", input: "MAYBE\n"},
		{name: "EOF", input: ""},
		{name: "YES without newline", input: "YES"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			err := requestEncryptionApproval(strings.NewReader(test.input), &output, manifest)
			if test.approved && err != nil {
				t.Fatalf("exact YES rejected: %v", err)
			}
			if !test.approved && err == nil {
				t.Fatalf("unsafe approval input %q accepted", test.input)
			}
			if test.name == "no" && !strings.Contains(output.String(), "Encryption cancelled; no files were created.") {
				t.Fatalf("NO did not print the cancellation result: %q", output.String())
			}
		})
	}
}

func TestEncryptionApprovalListsEveryManifestTargetInOrder(t *testing.T) {
	manifest := Manifest{
		CanonicalRoot:      "/validation/work",
		Extensions:         []string{".memento"},
		TotalFiles:         2,
		TotalBytes:         30,
		EncryptedOutputDir: "/validation/encrypted",
		Files: []FileRecord{
			{Path: "fixture-0000.memento", Size: 10, SHA256: strings.Repeat("a", 64)},
			{Path: "fixture-0001.memento", Size: 20, SHA256: strings.Repeat("b", 64)},
		},
	}
	var output bytes.Buffer
	if err := requestEncryptionApproval(strings.NewReader("YES\n"), &output, manifest); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{
		"Scenario root: /validation/work",
		"Extensions: .memento",
		"Files: 2",
		"Total bytes: 30",
		"Output: /validation/encrypted",
		"fixture-0000.memento (10 bytes, SHA-256 " + strings.Repeat("a", 64) + ")",
		"fixture-0001.memento (20 bytes, SHA-256 " + strings.Repeat("b", 64) + ")",
		"Proceed with encryption? Type YES to continue or NO to cancel:",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("approval output missing %q:\n%s", expected, text)
		}
	}
	first := strings.Index(text, "fixture-0000.memento")
	second := strings.Index(text, "fixture-0001.memento")
	if first < 0 || second <= first {
		t.Fatalf("targets not listed in manifest order:\n%s", text)
	}
}

func TestApprovedManifestRejectsLateInodeReplacement(t *testing.T) {
	manager := testManager(t)
	if _, err := manager.Init("safe", []string{".memento"}); err != nil {
		t.Fatal(err)
	}
	paths, err := manager.CreateCopies("safe", "sample.txt", ".memento", 1)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _, err := manager.Plan("safe", []string{".memento"})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := requestEncryptionApproval(strings.NewReader("YES\n"), &output, manifest); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[0], contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Revalidate("safe", manifest); err == nil {
		t.Fatal("same-content inode replacement after approval was accepted")
	}
}

func TestPlanRejectsHiddenAndSpecialFiles(t *testing.T) {
	for _, test := range []struct {
		name string
		make func(string) error
	}{
		{"hidden", func(work string) error { return os.WriteFile(filepath.Join(work, ".secret.txt"), []byte("x"), 0o600) }},
		{"fifo", func(work string) error { return unix.Mkfifo(filepath.Join(work, "pipe.txt"), 0o600) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := testManager(t)
			if _, err := manager.Init("safe", []string{".txt"}); err != nil {
				t.Fatal(err)
			}
			work := filepath.Join(manager.State.Lab, "safe", "work")
			if err := test.make(work); err != nil {
				t.Fatal(err)
			}
			if _, _, err := manager.Plan("safe", []string{".txt"}); err == nil {
				t.Fatalf("%s path was accepted", test.name)
			}
		})
	}
}

func TestAddedAndDeletedTargetsInvalidateManifest(t *testing.T) {
	for _, change := range []string{"add", "delete"} {
		t.Run(change, func(t *testing.T) {
			manager := testManager(t)
			if _, err := manager.Init("safe", []string{".txt"}); err != nil {
				t.Fatal(err)
			}
			fixture, err := manager.Create("safe", "sample.txt")
			if err != nil {
				t.Fatal(err)
			}
			manifest, _, err := manager.Plan("safe", []string{".txt"})
			if err != nil {
				t.Fatal(err)
			}
			if change == "add" {
				if err := os.WriteFile(filepath.Join(filepath.Dir(fixture), "added.txt"), []byte("new"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(fixture); err != nil {
				t.Fatal(err)
			}
			if err := manager.Revalidate("safe", manifest); err == nil {
				t.Fatalf("%s did not invalidate manifest", change)
			}
		})
	}
}

func TestWorkRootReplacementIsRejected(t *testing.T) {
	manager := testManager(t)
	if _, err := manager.Init("safe", []string{".txt"}); err != nil {
		t.Fatal(err)
	}
	scenario := filepath.Join(manager.State.Lab, "safe")
	work := filepath.Join(scenario, "work")
	if err := os.Rename(work, filepath.Join(scenario, "original-work")); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, work); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Plan("safe", []string{".txt"}); err == nil {
		t.Fatal("symlink-replaced work root was accepted")
	}
}
