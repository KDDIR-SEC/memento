// SPDX-License-Identifier: GPL-2.0-only

package cpumon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
)

const (
	Magic      = 0x524e444c
	Version    = 1
	RecordSize = 104
)

type Record struct {
	Sequence     uint64
	KtimeNS      uint64
	VMID         uint32
	VCPUID       uint32
	GuestRIP     uint64
	GuestCR3     uint64
	FlagsBefore  uint64
	FlagsAfter   uint64
	Instruction  uint8
	OperandBits  uint8
	DestRegister uint8
	Success      bool
	InsnLength   uint32
	InsnBytes    [16]byte
	Value        uint64
	HostCPU      uint32
}

func Decode(data []byte) (Record, error) {
	if len(data) != RecordSize {
		return Record{}, fmt.Errorf("KVM record has %d bytes, expected %d", len(data), RecordSize)
	}
	if got := binary.LittleEndian.Uint32(data[0:4]); got != Magic {
		return Record{}, fmt.Errorf("invalid KVM record magic %#x", got)
	}
	if got := binary.LittleEndian.Uint16(data[4:6]); got != Version {
		return Record{}, fmt.Errorf("unsupported KVM record version %d", got)
	}
	if got := binary.LittleEndian.Uint16(data[6:8]); got != RecordSize {
		return Record{}, fmt.Errorf("invalid KVM record_size %d", got)
	}
	record := Record{
		Sequence:     binary.LittleEndian.Uint64(data[8:16]),
		KtimeNS:      binary.LittleEndian.Uint64(data[16:24]),
		VMID:         binary.LittleEndian.Uint32(data[24:28]),
		VCPUID:       binary.LittleEndian.Uint32(data[28:32]),
		GuestRIP:     binary.LittleEndian.Uint64(data[32:40]),
		GuestCR3:     binary.LittleEndian.Uint64(data[40:48]),
		FlagsBefore:  binary.LittleEndian.Uint64(data[48:56]),
		FlagsAfter:   binary.LittleEndian.Uint64(data[56:64]),
		Instruction:  data[64],
		OperandBits:  data[65],
		DestRegister: data[66],
		Success:      data[67] != 0,
		InsnLength:   binary.LittleEndian.Uint32(data[68:72]),
		Value:        binary.LittleEndian.Uint64(data[88:96]),
		HostCPU:      binary.LittleEndian.Uint32(data[96:100]),
	}
	copy(record.InsnBytes[:], data[72:88])
	if data[67] > 1 {
		return Record{}, fmt.Errorf("invalid success flag %d", data[67])
	}
	if binary.LittleEndian.Uint32(data[100:104]) != 0 {
		return Record{}, errors.New("KVM record reserved field is not zero")
	}
	if record.Instruction != 1 && record.Instruction != 2 {
		return Record{}, fmt.Errorf("invalid random instruction %d", record.Instruction)
	}
	if record.DestRegister > 15 {
		return Record{}, fmt.Errorf("invalid destination register %d", record.DestRegister)
	}
	switch record.OperandBits {
	case 16:
		record.Value &= 0xffff
	case 32:
		record.Value &= 0xffffffff
	case 64:
	default:
		return Record{}, fmt.Errorf("invalid operand width %d", record.OperandBits)
	}
	if record.InsnLength < 3 || record.InsnLength > uint32(len(record.InsnBytes)) {
		return Record{}, fmt.Errorf("invalid instruction length %d", record.InsnLength)
	}
	return record, nil
}

func Read(r io.Reader, visit func(Record) error) error {
	buffer := make([]byte, RecordSize)
	for {
		n, err := io.ReadFull(r, buffer)
		if err == io.EOF && n == 0 {
			return nil
		}
		if err != nil {
			return fmt.Errorf("partial KVM record (%d/%d bytes): %w", n, RecordSize, err)
		}
		record, err := Decode(buffer)
		if err != nil {
			return err
		}
		if err := visit(record); err != nil {
			return err
		}
	}
}

// ReadPolling consumes a debugfs FIFO. An empty FIFO returns a zero-byte read,
// which os.File exposes as io.EOF even though future records may arrive.
// Pending partial records are retained across reads.
func ReadPolling(ctx context.Context, r io.Reader, visit func(Record) error) error {
	buffer := make([]byte, 32*RecordSize)
	pending := make([]byte, 0, 2*RecordSize)
	for {
		n, readErr := r.Read(buffer)
		if n > 0 {
			pending = append(pending, buffer[:n]...)
			for len(pending) >= RecordSize {
				record, err := Decode(pending[:RecordSize])
				if err != nil {
					return err
				}
				if err := visit(record); err != nil {
					return err
				}
				pending = pending[RecordSize:]
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if n == 0 || errors.Is(readErr, io.EOF) {
			select {
			case <-ctx.Done():
				if len(pending) != 0 {
					return fmt.Errorf("partial KVM record at shutdown (%d/%d bytes)", len(pending), RecordSize)
				}
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
}

func (r Record) PRN() prnlog.Record {
	operation := "rdrand"
	if r.Instruction == 2 {
		operation = "rdseed"
	}
	width := int(r.OperandBits / 4)
	return prnlog.Record{
		Schema:          prnlog.Schema,
		Time:            time.Now().UTC(),
		Source:          "cpu",
		Operation:       operation,
		ValueHex:        fmt.Sprintf("%0*x", width, r.Value),
		CapturedLength:  int(r.OperandBits / 8),
		RequestedLength: int(r.OperandBits / 8),
		VM: &prnlog.VMMeta{
			Sequence: r.Sequence, KtimeNS: r.KtimeNS, VMID: r.VMID, VCPUID: r.VCPUID,
			GuestRIP: r.GuestRIP, GuestCR3: r.GuestCR3,
			GuestRFLAGSBefore: r.FlagsBefore, GuestRFLAGSAfter: r.FlagsAfter,
			OperandBit: r.OperandBits,
			DestReg:    r.DestRegister, Success: r.Success, HostCPU: r.HostCPU,
		},
	}
}
