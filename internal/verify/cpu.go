// SPDX-License-Identifier: GPL-2.0-only

package verify

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
)

const guestRecordSize = 24

type Key struct {
	Instruction uint8
	Bits        uint8
	Value       uint64
}

type Result struct {
	GuestTotal   uint64 `json:"guest_total"`
	GuestThreads uint64 `json:"guest_threads"`
	GuestCF0     uint64 `json:"guest_cf0"`
	HostTotal    uint64 `json:"host_total"`
	HostVCPUs    uint64 `json:"host_vcpus"`
	Matched      uint64 `json:"matched"`
	Missing      uint64 `json:"missing"`
	Extra        uint64 `json:"extra"`
}

func CPU(guestPath string, hostPaths []string) (Result, error) {
	guest, total, threads, cf0, err := readGuest(guestPath)
	if err != nil {
		return Result{}, err
	}
	records, err := prnlog.ReadFiles(hostPaths)
	if err != nil {
		return Result{}, err
	}
	host := make(map[Key]uint64)
	vcpus := make(map[uint32]struct{})
	var hostTotal uint64
	for _, record := range records {
		if record.Source != "cpu" && record.Source != "legacy" {
			continue
		}
		var instruction uint8
		switch record.Operation {
		case "rdrand":
			instruction = 1
		case "rdseed":
			instruction = 2
		default:
			return Result{}, fmt.Errorf("host CPU record lacks a valid instruction: %q", record.Operation)
		}
		valueBytes, err := hex.DecodeString(record.ValueHex)
		if err != nil || len(valueBytes) == 0 || len(valueBytes) > 8 {
			return Result{}, fmt.Errorf("invalid host CPU value %q", record.ValueHex)
		}
		bits := uint8(len(valueBytes) * 8)
		if record.VM != nil {
			bits = record.VM.OperandBit
			vcpus[record.VM.VCPUID] = struct{}{}
		}
		var padded [8]byte
		copy(padded[8-len(valueBytes):], valueBytes)
		host[Key{Instruction: instruction, Bits: bits, Value: binary.BigEndian.Uint64(padded[:])}]++
		hostTotal++
	}
	result := Result{GuestTotal: total, GuestThreads: threads, GuestCF0: cf0,
		HostTotal: hostTotal, HostVCPUs: uint64(len(vcpus))}
	for key, count := range guest {
		available := host[key]
		matched := min(count, available)
		result.Matched += matched
		result.Missing += count - matched
		host[key] -= matched
	}
	for _, count := range host {
		result.Extra += count
	}
	return result, nil
}

func readGuest(path string) (map[Key]uint64, uint64, uint64, uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	defer f.Close()
	values := make(map[Key]uint64)
	threads := make(map[uint32]struct{})
	var total, cf0 uint64
	buffer := make([]byte, guestRecordSize)
	for {
		n, err := io.ReadFull(f, buffer)
		if err == io.EOF && n == 0 {
			break
		}
		if err != nil {
			return nil, total, uint64(len(threads)), cf0,
				fmt.Errorf("partial guest record: %w", err)
		}
		total++
		threads[binary.LittleEndian.Uint32(buffer[8:12])] = struct{}{}
		instruction, bits, cf, reserved := buffer[12], buffer[13], buffer[14], buffer[15]
		if instruction != 1 && instruction != 2 {
			return nil, total, uint64(len(threads)), cf0, fmt.Errorf("invalid guest instruction %d", instruction)
		}
		if bits != 16 && bits != 32 && bits != 64 {
			return nil, total, uint64(len(threads)), cf0, fmt.Errorf("invalid guest operand width %d", bits)
		}
		if cf > 1 {
			return nil, total, uint64(len(threads)), cf0, fmt.Errorf("invalid guest carry flag %d", cf)
		}
		if reserved != 0 {
			return nil, total, uint64(len(threads)), cf0, fmt.Errorf("guest reserved byte is nonzero: %d", reserved)
		}
		if cf == 0 {
			cf0++
			continue
		}
		value := binary.LittleEndian.Uint64(buffer[16:24])
		if bits == 16 {
			value &= 0xffff
		}
		if bits == 32 {
			value &= 0xffffffff
		}
		values[Key{Instruction: instruction, Bits: bits, Value: value}]++
	}
	return values, total, uint64(len(threads)), cf0, nil
}
