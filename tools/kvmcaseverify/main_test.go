// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
)

func writeCases(t *testing.T, mutate func(*prnlog.Record)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	for key := range expectedCases() {
		bytes := int(key.Bits / 8)
		record := prnlog.Record{
			Schema: prnlog.Schema, Source: "cpu", Operation: key.Operation,
			ValueHex:        valueHex(expectedValue(key.Operation, key.Bits), key.Bits),
			CapturedLength:  bytes,
			RequestedLength: bytes,
			VM: &prnlog.VMMeta{
				OperandBit: key.Bits, DestReg: key.Register, Success: true,
				GuestRFLAGSBefore: rflagsClear,
				GuestRFLAGSAfter:  rflagsCF,
			},
		}
		if mutate != nil {
			mutate(&record)
			mutate = nil
		}
		if err := encoder.Encode(record); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func valueHex(value uint64, bits uint8) string {
	return fmt.Sprintf("%0*x", int(bits/4), value)
}

func TestVerifyAllDeterministicCases(t *testing.T) {
	answer, err := verify([]string{writeCases(t, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if answer.failed() {
		t.Fatalf("valid cases failed: %#v", answer)
	}
}

func TestVerifyRejectsWrongFlags(t *testing.T) {
	path := writeCases(t, func(record *prnlog.Record) {
		record.VM.GuestRFLAGSAfter = rflagsCF | rflagsZF
	})
	answer, err := verify([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if !answer.failed() || answer.Invalid != 1 {
		t.Fatalf("bad flags accepted: %#v", answer)
	}
}
