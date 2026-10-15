// SPDX-License-Identifier: GPL-2.0-only

package verify

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeGuestRecord(t *testing.T, path string, instruction, bits byte, value uint64) {
	t.Helper()
	data := make([]byte, guestRecordSize)
	data[12], data[13], data[14] = instruction, bits, 1
	binary.LittleEndian.PutUint64(data[16:24], value)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeHostRecord(t *testing.T, path, operation string, bits byte, value uint64) {
	t.Helper()
	line := fmt.Sprintf(`{"schema":"memento.prn/v1","source":"cpu","operation":%q,"value_hex":"%0*x","captured_length":%d,"requested_length":%d,"truncated":false,"vm":{"operand_bits":%d}}`+"\n", operation, int(bits/4), value, bits/8, bits/8, bits)
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCPURequiresInstructionIdentity(t *testing.T) {
	root := t.TempDir()
	guest := filepath.Join(root, "guest.bin")
	host := filepath.Join(root, "host.jsonl")
	writeGuestRecord(t, guest, 1, 64, 0x11223344)
	writeHostRecord(t, host, "rdseed", 64, 0x11223344)
	result, err := CPU(guest, []string{host})
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched != 0 || result.Missing != 1 || result.Extra != 1 {
		t.Fatalf("wrong instruction matched: %#v", result)
	}
	writeHostRecord(t, host, "rdrand", 64, 0x11223344)
	result, err = CPU(guest, []string{host})
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched != 1 || result.Missing != 0 || result.Extra != 0 {
		t.Fatalf("matching record failed: %#v", result)
	}
	if result.GuestThreads != 1 || result.HostVCPUs != 1 {
		t.Fatalf("topology counts = %#v", result)
	}
}

func TestCPURejectsUnknownInstruction(t *testing.T) {
	root := t.TempDir()
	guest := filepath.Join(root, "guest.bin")
	host := filepath.Join(root, "host.jsonl")
	writeGuestRecord(t, guest, 3, 64, 1)
	writeHostRecord(t, host, "rdrand", 64, 1)
	if _, err := CPU(guest, []string{host}); err == nil {
		t.Fatal("accepted an unknown guest instruction")
	}
}

func TestCPURejectsInvalidGuestStatusFields(t *testing.T) {
	root := t.TempDir()
	guest := filepath.Join(root, "guest.bin")
	host := filepath.Join(root, "host.jsonl")
	writeHostRecord(t, host, "rdrand", 64, 1)
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"unknown-instruction-with-cf0", func(data []byte) { data[12], data[14] = 3, 0 }},
		{"invalid-cf", func(data []byte) { data[14] = 2 }},
		{"nonzero-reserved", func(data []byte) { data[15] = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := make([]byte, guestRecordSize)
			data[12], data[13], data[14] = 1, 64, 1
			test.mutate(data)
			if err := os.WriteFile(guest, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := CPU(guest, []string{host}); err == nil {
				t.Fatal("accepted invalid guest status fields")
			}
		})
	}
}
