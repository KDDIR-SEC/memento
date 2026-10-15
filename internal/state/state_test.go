// SPDX-License-Identifier: GPL-2.0-only

package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePrecedence(t *testing.T) {
	environment := filepath.Join(t.TempDir(), "environment")
	t.Setenv(EnvName, environment)
	fromEnvironment, err := Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if fromEnvironment.Root != environment {
		t.Fatalf("environment state root = %q, want %q", fromEnvironment.Root, environment)
	}
	flagValue := filepath.Join(t.TempDir(), "flag")
	fromFlag, err := Resolve(flagValue)
	if err != nil {
		t.Fatal(err)
	}
	if fromFlag.Root != flagValue {
		t.Fatalf("flag state root = %q, want %q", fromFlag.Root, flagValue)
	}
}

func TestResolveIgnoresRemovedStateEnvironment(t *testing.T) {
	removedEnv := "RA" + "RE_STATE_DIR"
	t.Setenv(EnvName, "")
	t.Setenv(removedEnv, filepath.Join(t.TempDir(), "removed"))
	layout, err := Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if layout.Root == os.Getenv(removedEnv) {
		t.Fatalf("removed environment variable %s was accepted", removedEnv)
	}
}

func TestEnsurePermissionsAndSymlinkRejection(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	layout, err := Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{layout.Root, layout.Log, layout.Dump, layout.Recovered, layout.Lab, layout.Stats, layout.Keys} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode = %o, want 700", path, info.Mode().Perm())
		}
	}
	if err := os.Remove(layout.Log); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), layout.Log); err != nil {
		t.Fatal(err)
	}
	if err := layout.Ensure(); err == nil {
		t.Fatal("accepted a symlink state child")
	}
}

func TestOpenPrivateRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPrivate(link, os.O_WRONLY); err == nil {
		t.Fatal("opened a private output through a symlink")
	}
}
