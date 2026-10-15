// SPDX-License-Identifier: GPL-2.0-only

package prnlog

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadCurrentSchema(t *testing.T) {
	input := `{"schema":"memento.prn/v1","time":"2026-01-01T00:00:00Z","source":"syscall","operation":"getrandom","value_hex":"00ff","captured_length":2,"requested_length":4,"truncated":true}`
	records, err := Read(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || !records[0].Truncated {
		t.Fatalf("unexpected records: %#v", records)
	}
}

func TestRejectInvalid(t *testing.T) {
	oldSchema := `{"schema":"` + "ra" + `re.prn/v1","value_hex":"00","captured_length":1,"requested_length":1}`
	for _, input := range []string{
		`{"schema":"memento.prn/v2","value_hex":"00"}`,
		`{"schema":"memento.prn/v1","value_hex":"xyz","captured_length":1,"requested_length":1}`,
		`{"schema":"memento.prn/v1","value_hex":"00","captured_length":1,"requested_length":0}`,
		`{"time":"2026-01-01T00:00:01Z","message":"PRN: aabb"}`,
		oldSchema,
	} {
		if _, err := DecodeLine([]byte(input)); err == nil {
			t.Fatalf("accepted invalid input %s", input)
		}
	}
}

func TestWriterCreatesAndAppendsPrivateRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prn.jsonl")
	write := func(value string) {
		t.Helper()
		writer, err := NewWriter(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Write(Record{Schema: Schema, Source: "test", Operation: "random", ValueHex: value, CapturedLength: 1, RequestedLength: 1}); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	write("00")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	write("01")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.TrimSpace(string(data)), "\n") != 1 {
		t.Fatalf("writer did not append exactly two records: %q", data)
	}
}

func TestWriterRejectsUnsafeTargetsWithoutChangingThem(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	const content = "do not modify"
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	// Make the comparison independent of the process umask. Validation runs
	// intentionally use umask 077, while this test verifies that a rejected
	// writer does not change an already-existing 0644 target.
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	assertTargetUnchanged := func(t *testing.T) {
		t.Helper()
		data, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != content || info.Mode().Perm() != 0o644 {
			t.Fatalf("target changed: content=%q mode=%#o", data, info.Mode().Perm())
		}
	}

	t.Run("final symlink", func(t *testing.T) {
		link := filepath.Join(root, "log-link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if writer, err := NewWriter(link); err == nil {
			_ = writer.Close()
			t.Fatal("symlink PRN log was accepted")
		}
		assertTargetUnchanged(t)
	})

	t.Run("parent symlink", func(t *testing.T) {
		realParent := filepath.Join(root, "real-parent")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedParent := filepath.Join(root, "linked-parent")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatal(err)
		}
		if writer, err := NewWriter(filepath.Join(linkedParent, "log")); err == nil {
			_ = writer.Close()
			t.Fatal("PRN log below symlink parent was accepted")
		}
	})

	t.Run("hard link", func(t *testing.T) {
		link := filepath.Join(root, "hard-link")
		if err := os.Link(target, link); err != nil {
			t.Fatal(err)
		}
		if writer, err := NewWriter(link); err == nil {
			_ = writer.Close()
			t.Fatal("hard-linked PRN log was accepted")
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		assertTargetUnchanged(t)
	})

	t.Run("fifo", func(t *testing.T) {
		path := filepath.Join(root, "fifo")
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if writer, err := NewWriter(path); err == nil {
			_ = writer.Close()
			t.Fatal("FIFO PRN log was accepted")
		}
	})

	t.Run("socket", func(t *testing.T) {
		path := filepath.Join(root, "socket")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if writer, err := NewWriter(path); err == nil {
			_ = writer.Close()
			t.Fatal("socket PRN log was accepted")
		}
	})

	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(root, "directory")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if writer, err := NewWriter(path); err == nil {
			_ = writer.Close()
			t.Fatal("directory PRN log was accepted")
		}
	})
}
