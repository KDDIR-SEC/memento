// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
)

const (
	fixedRDRAND = uint64(0x1122334455667788)
	fixedRDSEED = uint64(0x8877665544332211)
	rflagsCF    = uint64(1 << 0)
	rflagsPF    = uint64(1 << 2)
	rflagsAF    = uint64(1 << 4)
	rflagsZF    = uint64(1 << 6)
	rflagsSF    = uint64(1 << 7)
	rflagsOF    = uint64(1 << 11)
	rflagsClear = rflagsOF | rflagsSF | rflagsZF | rflagsAF | rflagsPF
)

type stringList []string

func (values *stringList) String() string { return fmt.Sprint([]string(*values)) }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type caseKey struct {
	Operation string
	Bits      uint8
	Register  uint8
}

type result struct {
	Schema     string `json:"schema"`
	HostTotal  int    `json:"host_total"`
	Matched    int    `json:"matched"`
	Missing    int    `json:"missing"`
	Duplicate  int    `json:"duplicate"`
	Unexpected int    `json:"unexpected"`
	Invalid    int    `json:"invalid"`
}

func expectedCases() map[caseKey]bool {
	expected := make(map[caseKey]bool, 84)
	registers := []uint8{0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	for _, operation := range []string{"rdrand", "rdseed"} {
		for _, bits := range []uint8{16, 32, 64} {
			for _, register := range registers {
				expected[caseKey{Operation: operation, Bits: bits, Register: register}] = false
			}
		}
	}
	return expected
}

func decodeValue(record prnlog.Record) (uint64, error) {
	value, err := hex.DecodeString(record.ValueHex)
	if err != nil {
		return 0, err
	}
	if len(value) != record.CapturedLength || len(value) > 8 {
		return 0, errors.New("invalid value length")
	}
	var decoded uint64
	for _, octet := range value {
		decoded = decoded<<8 | uint64(octet)
	}
	return decoded, nil
}

func expectedValue(operation string, bits uint8) uint64 {
	value := fixedRDRAND
	if operation == "rdseed" {
		value = fixedRDSEED
	}
	switch bits {
	case 16:
		return value & 0xffff
	case 32:
		return value & 0xffffffff
	default:
		return value
	}
}

func verify(paths []string) (result, error) {
	records, err := prnlog.ReadFiles(paths)
	if err != nil {
		return result{}, err
	}
	expected := expectedCases()
	answer := result{Schema: "memento.kvm-deterministic-verification/v1"}
	for _, record := range records {
		if record.Source != "cpu" {
			continue
		}
		answer.HostTotal++
		if record.VM == nil {
			answer.Invalid++
			continue
		}
		key := caseKey{
			Operation: record.Operation,
			Bits:      record.VM.OperandBit,
			Register:  record.VM.DestReg,
		}
		seen, found := expected[key]
		if !found {
			answer.Unexpected++
			continue
		}
		if seen {
			answer.Duplicate++
			continue
		}
		expected[key] = true
		value, err := decodeValue(record)
		if err != nil || value != expectedValue(key.Operation, key.Bits) ||
			!record.VM.Success ||
			record.VM.GuestRFLAGSBefore&rflagsCF != 0 ||
			record.VM.GuestRFLAGSBefore&rflagsClear != rflagsClear ||
			record.VM.GuestRFLAGSAfter&rflagsCF == 0 ||
			record.VM.GuestRFLAGSAfter&rflagsClear != 0 {
			answer.Invalid++
			continue
		}
		answer.Matched++
	}
	for _, seen := range expected {
		if !seen {
			answer.Missing++
		}
	}
	return answer, nil
}

func (value result) failed() bool {
	return value.HostTotal != 84 || value.Matched != 84 || value.Missing != 0 ||
		value.Duplicate != 0 || value.Unexpected != 0 || value.Invalid != 0
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("kvmcaseverify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var logs stringList
	flags.Var(&logs, "host-log", "deterministic host PRN JSONL (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || len(logs) == 0 {
		return errors.New("at least one --host-log is required")
	}
	answer, err := verify(logs)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdout).Encode(answer); err != nil {
		return err
	}
	if answer.failed() {
		return fmt.Errorf("deterministic KVM verification failed: matched=%d missing=%d duplicate=%d unexpected=%d invalid=%d",
			answer.Matched, answer.Missing, answer.Duplicate, answer.Unexpected, answer.Invalid)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
