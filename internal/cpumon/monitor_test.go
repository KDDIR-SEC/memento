// SPDX-License-Identifier: GPL-2.0-only

package cpumon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadKernelStatsRequiresValidDropCount(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		wantErr bool
	}{
		{"valid", "total_records: 4\ndrop_count: 2\n", false},
		{"missing", "total_records: 4\n", true},
		{"malformed", "drop_count: nope\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stats")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			values, err := ReadKernelStats(path)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && values["drop_count"] != 2 {
				t.Fatalf("drop_count = %d", values["drop_count"])
			}
		})
	}
}

func TestValidateKernelAccounting(t *testing.T) {
	start := map[string]uint64{
		"total_records": 84, "consumed": 84, "drop_count": 0, "buffer_used": 0,
	}
	valid := map[string]uint64{
		"total_records": 91, "consumed": 89, "drop_count": 2, "buffer_used": 0,
	}
	dropped, err := validateKernelAccounting(start, valid, 5)
	if err != nil || dropped != 2 {
		t.Fatalf("dropped=%d err=%v", dropped, err)
	}
	for _, test := range []struct {
		name    string
		start   map[string]uint64
		end     map[string]uint64
		written uint64
	}{
		{"missing-field", start, map[string]uint64{"drop_count": 0}, 0},
		{"broken-invariant", start, map[string]uint64{"total_records": 92, "consumed": 89, "drop_count": 2, "buffer_used": 0}, 5},
		{"jsonl-count", start, map[string]uint64{"total_records": 89, "consumed": 89, "drop_count": 0, "buffer_used": 0}, 4},
		{"undrained-start", map[string]uint64{"total_records": 1, "consumed": 0, "drop_count": 0, "buffer_used": 1}, valid, 5},
		{"undrained-end", start, map[string]uint64{"total_records": 90, "consumed": 89, "drop_count": 0, "buffer_used": 1}, 5},
		{"counter-decreased", start, map[string]uint64{"total_records": 83, "consumed": 84, "drop_count": 0, "buffer_used": 0}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateKernelAccounting(test.start, test.end, test.written); err == nil {
				t.Fatal("invalid KVM accounting was accepted")
			}
		})
	}
}
