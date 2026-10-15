// SPDX-License-Identifier: GPL-2.0-only

package ebpf

import (
	"encoding/binary"
	"testing"
)

func TestEventABISizes(t *testing.T) {
	if got := binary.Size(readEvent{}); got != 304 {
		t.Fatalf("read event size = %d, want 304", got)
	}
	if got := binary.Size(getrandomEvent{}); got != 176 {
		t.Fatalf("getrandom event size = %d, want 176", got)
	}
}

func TestEventConversionRejectsInvalidLengths(t *testing.T) {
	if _, err := convertRead(readEvent{BytesRead: -1}); err == nil {
		t.Fatal("negative read result was accepted")
	}
	if _, err := convertRead(readEvent{Count: ^uint64(0), BytesRead: 1}); err == nil {
		t.Fatal("overflowing read request was accepted")
	}
	if _, err := convertGetrandom(getrandomEvent{Length: ^uint64(0), BytesRead: 1}); err == nil {
		t.Fatal("overflowing getrandom request was accepted")
	}
}
