// SPDX-License-Identifier: GPL-2.0-only

package ebpf

import (
	"testing"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
)

func TestEventConversionUsesTIDAndTruncation(t *testing.T) {
	event := getrandomEvent{PID: 17, TGID: 12, Length: 256, BytesRead: 200}
	copy(event.Comm[:], "worker")
	record, err := convertGetrandom(event)
	if err != nil {
		t.Fatal(err)
	}
	if record.Process.TID != 17 || record.Process.PID != 12 || record.CapturedLength != 128 || record.RequestedLength != 256 || !record.Truncated {
		t.Fatalf("unexpected event: %#v", record)
	}
	read := readEvent{PID: 18, TGID: 12, Count: 16, BytesRead: 16, FD: 3}
	copy(read.Basename[:], "urandom")
	record, err = convertRead(read)
	if err != nil {
		t.Fatal(err)
	}
	if record.Syscall.Path != "/dev/urandom" || record.Truncated {
		t.Fatalf("unexpected read: %#v", record)
	}
}

func TestPIDFilterPrecedesLoggingAndTriggering(t *testing.T) {
	record := prnlog.Record{Process: &prnlog.ProcessMeta{PID: 42}}
	if isPIDFiltered(record, 42) {
		t.Fatal("target PID was filtered")
	}
	if !isPIDFiltered(record, 43) || !isPIDFiltered(prnlog.Record{}, 43) {
		t.Fatal("non-target PID was accepted")
	}
	if isPIDFiltered(record, 0) {
		t.Fatal("zero target unexpectedly enabled filtering")
	}
}

func TestProcessExclusion(t *testing.T) {
	excluded := map[string]struct{}{"openssl": {}}
	if !isExcluded("openssl", excluded) || isExcluded("qemu", excluded) {
		t.Fatal("process exclusion list mismatch")
	}
}
