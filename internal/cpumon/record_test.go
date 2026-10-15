// SPDX-License-Identifier: GPL-2.0-only

package cpumon

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

type chunkReader struct {
	chunks [][]byte
}

func (r *chunkReader) Read(destination []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := r.chunks[0]
	r.chunks = r.chunks[1:]
	return copy(destination, chunk), nil
}

func recordBytes(inst, bits byte, value uint64) []byte {
	data := make([]byte, RecordSize)
	binary.LittleEndian.PutUint32(data[0:4], Magic)
	binary.LittleEndian.PutUint16(data[4:6], Version)
	binary.LittleEndian.PutUint16(data[6:8], RecordSize)
	data[64], data[65], data[67] = inst, bits, 1
	binary.LittleEndian.PutUint32(data[68:72], 3)
	binary.LittleEndian.PutUint64(data[88:96], value)
	return data
}

func TestDecodeWidthsAndInstructions(t *testing.T) {
	for _, test := range []struct {
		inst, bits  byte
		value, want uint64
		op          string
	}{
		{1, 16, 0x123456, 0x3456, "rdrand"},
		{1, 32, 0x123456789a, 0x3456789a, "rdrand"},
		{2, 64, 0x123456789abcdef0, 0x123456789abcdef0, "rdseed"},
	} {
		record, err := Decode(recordBytes(test.inst, test.bits, test.value))
		if err != nil {
			t.Fatal(err)
		}
		if record.Value != test.want || record.PRN().Operation != test.op {
			t.Fatalf("unexpected record: %#v", record)
		}
	}
}

func TestRejectHeaderAndPartialRead(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(b []byte) { b[0] = 0 },
		func(b []byte) { binary.LittleEndian.PutUint16(b[4:6], 2) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[6:8], 99) },
		func(b []byte) { b[67] = 2 },
		func(b []byte) { b[100] = 1 },
		func(b []byte) { b[66] = 16 },
		func(b []byte) { binary.LittleEndian.PutUint32(b[68:72], 0) },
	} {
		data := recordBytes(1, 64, 1)
		mutate(data)
		if _, err := Decode(data); err == nil {
			t.Fatal("invalid record accepted")
		}
	}
	err := Read(bytes.NewReader(make([]byte, 17)), func(Record) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "partial") {
		t.Fatalf("partial read not reported: %v", err)
	}
}

func TestPollingCarriesPartialReads(t *testing.T) {
	data := append(recordBytes(1, 16, 7), recordBytes(2, 64, 9)...)
	reader := &chunkReader{chunks: [][]byte{data[:13], data[13:117], data[117:]}}
	ctx, cancel := context.WithCancel(context.Background())
	count := 0
	err := ReadPolling(ctx, reader, func(Record) error {
		count++
		if count == 2 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || count != 2 {
		t.Fatalf("partial polling failed: count=%d err=%v", count, err)
	}
}

func TestPRNIncludesGuestRFLAGS(t *testing.T) {
	record := Record{
		Instruction: 1, OperandBits: 64, Success: true,
		InsnLength: 3, FlagsBefore: 0x8d6, FlagsAfter: 0x203,
	}
	metadata := record.PRN().VM
	if metadata == nil || metadata.GuestRFLAGSBefore != 0x8d6 ||
		metadata.GuestRFLAGSAfter != 0x203 {
		t.Fatalf("RFLAGS metadata missing: %#v", metadata)
	}
}
