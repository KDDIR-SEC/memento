// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
)

func writeJSONLines(t *testing.T, name string, values ...any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	for _, value := range values {
		if err := encoder.Encode(value); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func testStats(t *testing.T, lost uint64) string {
	t.Helper()
	return writeJSONLines(t, "stats.json", stats{
		Schema:      "memento.syscall-stats/v1",
		LostSamples: lost,
	})
}

func TestCompareMatchesReadAndGetrandom(t *testing.T) {
	readValue := strings.Repeat("ab", 128)
	randomValue := strings.Repeat("cd", 32)
	ground := writeJSONLines(t, "ground.jsonl",
		groundTruth{
			Schema: groundTruthSchema, Sequence: 1, PID: 10, TID: 11,
			Operation: "read", API: "read", Path: "/dev/urandom", FD: 4,
			RequestedLength: 256, ReturnedLength: 256, CapturedLength: 128,
			ValueHex: readValue, ExpectedObserved: true,
		},
		groundTruth{
			Schema: groundTruthSchema, Sequence: 2, PID: 10, TID: 12,
			Operation: "getrandom", API: "raw", RequestedLength: 32,
			ReturnedLength: 32, CapturedLength: 32, Flags: 1,
			ValueHex: randomValue, ExpectedObserved: true,
		},
	)
	monitor := writeJSONLines(t, "monitor.jsonl",
		prnlog.Record{
			Schema: prnlog.Schema, Source: "syscall", Operation: "read",
			ValueHex: readValue, CapturedLength: 128, RequestedLength: 256,
			Truncated: true,
			Process:   &prnlog.ProcessMeta{PID: 10, TID: 11},
			Syscall:   &prnlog.SyscallMeta{Name: "read", FD: 4, Path: "/dev/urandom"},
		},
		prnlog.Record{
			Schema: prnlog.Schema, Source: "syscall", Operation: "getrandom",
			ValueHex: randomValue, CapturedLength: 32, RequestedLength: 32,
			Process: &prnlog.ProcessMeta{PID: 10, TID: 12},
			Syscall: &prnlog.SyscallMeta{Name: "getrandom", Flags: 1},
		},
		prnlog.Record{
			Schema: prnlog.Schema, Source: "syscall", Operation: "getrandom",
			ValueHex: "ef", CapturedLength: 1, RequestedLength: 1,
			Process: &prnlog.ProcessMeta{PID: 99, TID: 99},
			Syscall: &prnlog.SyscallMeta{Name: "getrandom"},
		},
	)
	answer, err := compare([]string{ground}, []string{monitor}, testStats(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	if answer.Matched != 2 || answer.Missing != 0 ||
		answer.Unexpected != 0 || answer.LostSamples != 0 ||
		answer.MonitorIgnored != 1 || answer.MonitorTotal != 2 {
		t.Fatalf("unexpected result: %#v", answer)
	}
}

func TestCompareRejectsSuppressedEvent(t *testing.T) {
	ground := writeJSONLines(t, "ground.jsonl", groundTruth{
		Schema: groundTruthSchema, Sequence: 1, PID: 20, TID: 21,
		Operation: "read", API: "read", Path: "/tmp/random", FD: 5,
		RequestedLength: 1, ReturnedLength: 1, CapturedLength: 1,
		ValueHex: "00", ExpectedObserved: false,
	})
	monitor := writeJSONLines(t, "monitor.jsonl", prnlog.Record{
		Schema: prnlog.Schema, Source: "syscall", Operation: "read",
		ValueHex: "00", CapturedLength: 1, RequestedLength: 1,
		Process: &prnlog.ProcessMeta{PID: 20, TID: 21},
		Syscall: &prnlog.SyscallMeta{Name: "read", FD: 5, Path: "/tmp/random"},
	})
	answer, err := compare([]string{ground}, []string{monitor}, testStats(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	if answer.Unexpected != 1 {
		t.Fatalf("unexpected result: %#v", answer)
	}
}

func TestCompareKeepsOperationAndTID(t *testing.T) {
	ground := writeJSONLines(t, "ground.jsonl", groundTruth{
		Schema: groundTruthSchema, Sequence: 1, PID: 30, TID: 31,
		Operation: "getrandom", API: "raw",
		RequestedLength: 1, ReturnedLength: 1, CapturedLength: 1,
		ValueHex: "aa", ExpectedObserved: true,
	})
	monitor := writeJSONLines(t, "monitor.jsonl", prnlog.Record{
		Schema: prnlog.Schema, Source: "syscall", Operation: "getrandom",
		ValueHex: "aa", CapturedLength: 1, RequestedLength: 1,
		Process: &prnlog.ProcessMeta{PID: 30, TID: 32},
		Syscall: &prnlog.SyscallMeta{Name: "getrandom"},
	})
	answer, err := compare([]string{ground}, []string{monitor}, testStats(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	if answer.Missing != 1 || answer.Extra != 0 || answer.Matched != 0 ||
		answer.MonitorIgnored != 1 || !answer.failed() {
		t.Fatalf("unexpected result: %#v", answer)
	}
}

func TestCompareCountsExtraForScopedIdentity(t *testing.T) {
	ground := writeJSONLines(t, "ground.jsonl", groundTruth{
		Schema: groundTruthSchema, Sequence: 1, PID: 35, TID: 36,
		Operation: "getrandom", API: "raw",
		RequestedLength: 1, ReturnedLength: 1, CapturedLength: 1,
		ValueHex: "aa", ExpectedObserved: true,
	})
	monitor := writeJSONLines(t, "monitor.jsonl", prnlog.Record{
		Schema: prnlog.Schema, Source: "syscall", Operation: "getrandom",
		ValueHex: "bb", CapturedLength: 1, RequestedLength: 1,
		Process: &prnlog.ProcessMeta{PID: 35, TID: 36},
		Syscall: &prnlog.SyscallMeta{Name: "getrandom"},
	})
	answer, err := compare([]string{ground}, []string{monitor}, testStats(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	if answer.Missing != 1 || answer.Extra != 1 || answer.Matched != 0 ||
		answer.MonitorIgnored != 0 || !answer.failed() {
		t.Fatalf("unexpected result: %#v", answer)
	}
}

func TestCompareRejectsAmbiguousNegativeGroundTruth(t *testing.T) {
	positive := groundTruth{
		Schema: groundTruthSchema, Sequence: 1, PID: 40, TID: 41,
		Operation: "getrandom", API: "raw",
		RequestedLength: 1, ReturnedLength: 1, CapturedLength: 1,
		ValueHex: "aa", ExpectedObserved: true,
	}
	negative := positive
	negative.Sequence = 2
	negative.ReturnedLength = -1
	negative.CapturedLength = 0
	negative.ValueHex = ""
	negative.Errno = 14
	negative.ExpectedObserved = false
	ground := writeJSONLines(t, "ground.jsonl", positive, negative)
	monitor := writeJSONLines(t, "monitor.jsonl")
	if _, err := compare([]string{ground}, []string{monitor}, testStats(t, 0)); err == nil {
		t.Fatal("ambiguous ground truth was accepted")
	}
}

func TestCompareCarriesLostSamples(t *testing.T) {
	ground := writeJSONLines(t, "ground.jsonl", groundTruth{
		Schema: groundTruthSchema, Sequence: 1, PID: 50, TID: 51,
		Operation: "read", API: "read", Path: "/dev/random", FD: -1,
		RequestedLength: 1, ReturnedLength: -1, Errno: 9,
		ExpectedObserved: false,
	})
	monitor := writeJSONLines(t, "monitor.jsonl")
	answer, err := compare([]string{ground}, []string{monitor}, testStats(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	if answer.LostSamples != 3 {
		t.Fatalf("lost samples = %d, want 3", answer.LostSamples)
	}
}

func TestValidateGroundTruthRejectsLengthMismatch(t *testing.T) {
	record := groundTruth{
		Schema: groundTruthSchema, PID: 1, TID: 1, Operation: "read",
		RequestedLength: 2, ReturnedLength: 2, CapturedLength: 2,
		ValueHex: "00", ExpectedObserved: true,
	}
	if err := validateGroundTruth(record); err == nil {
		t.Fatal("length mismatch was accepted")
	}
}
