// SPDX-License-Identifier: GPL-2.0-only

package prnlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFilesAndEmptyLines(t *testing.T) {
	root := t.TempDir()
	paths := []string{filepath.Join(root, "one.jsonl"), filepath.Join(root, "two.jsonl")}
	lines := []string{
		"\n" + `{"schema":"memento.prn/v1","source":"syscall","operation":"getrandom","value_hex":"00","captured_length":1,"requested_length":1,"truncated":false}` + "\n",
		`{"schema":"memento.prn/v1","source":"cpu","operation":"rdrand","value_hex":"ff","captured_length":1,"requested_length":1,"truncated":false}` + "\n\n",
	}
	for index := range paths {
		if err := os.WriteFile(paths[index], []byte(lines[index]), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	records, err := ReadFiles(paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].ValueHex != "00" || records[1].ValueHex != "ff" {
		t.Fatalf("unexpected records: %#v", records)
	}
}

func TestRejectsOversizedLine(t *testing.T) {
	if _, err := Read(strings.NewReader(strings.Repeat("x", 1024*1024+1))); err == nil {
		t.Fatal("accepted a JSONL line larger than 1 MiB")
	}
}

func FuzzDecodeLine(f *testing.F) {
	f.Add([]byte(`{"schema":"memento.prn/v1","source":"cpu","operation":"rdrand","value_hex":"0011","captured_length":2,"requested_length":2}`))
	f.Add([]byte(`{"time":"2026-01-01T00:00:00Z","message":"PRN: aabb"}`))
	f.Add([]byte(`{"schema":"memento.prn/v2","value_hex":"zz"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeLine(input)
	})
}
