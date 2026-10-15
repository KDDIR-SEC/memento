// SPDX-License-Identifier: GPL-2.0-only

package recover

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
	"github.com/KDDIR-SEC/memento/internal/simcrypto"
)

type nonzeroReader struct{ value byte }

func (r *nonzeroReader) Read(destination []byte) (int, error) {
	for index := range destination {
		r.value++
		if r.value == 0 {
			r.value = 1
		}
		destination[index] = r.value
	}
	return len(destination), nil
}

// This test is intentionally memory-only. It never invokes the lab command or
// opens a filesystem encryption target.
func TestQilinMemoryRoundTrip(t *testing.T) {
	plaintext := bytes.Repeat([]byte("memento Qilin compatibility vector\n"), 100)
	keys := make(map[int][]byte)
	ivs := make(map[int][]byte)
	sink := func(operation string, value []byte) error {
		var stage int
		var kind string
		if _, err := fmt.Sscanf(operation, "qilin.stage%d.%s", &stage, &kind); err != nil {
			return err
		}
		switch kind {
		case "key":
			keys[stage] = append([]byte(nil), value...)
		case "iv":
			ivs[stage] = append([]byte(nil), value...)
		}
		return nil
	}
	var encrypted bytes.Buffer
	if err := simcrypto.TransformQilin(&encrypted, bytes.NewReader(plaintext), simcrypto.QilinOptions{
		SecretRandom:   &nonzeroReader{},
		OAEPSeedRandom: &nonzeroReader{},
		PRN:            sink,
	}); err != nil {
		t.Fatal(err)
	}
	value := encrypted.Bytes()
	for stage := 3; stage >= 1; stage-- {
		var err error
		value, err = decryptQilinStage(value, stage, keys[stage], ivs[stage])
		if err != nil {
			t.Fatalf("stage %d: %v", stage, err)
		}
	}
	if !bytes.Equal(value, plaintext) {
		t.Fatalf("round trip mismatch: got %d bytes want %d", len(value), len(plaintext))
	}
}

func TestQilinLegacyCFixture(t *testing.T) {
	input := filepath.Join("testdata", "qilin-legacy", "ciphertext.qilin")
	plaintextPath := filepath.Join("testdata", "qilin-legacy", "plaintext.bin")
	before, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	beforeHash := sha256.Sum256(before)
	want, err := os.ReadFile(plaintextPath)
	if err != nil {
		t.Fatal(err)
	}

	keys := []string{
		"7e77010979c3be5d67063c816ff210f402994e3c529ae5c183366aa12fc306ef",
		"8e77010979c3be5d67063c816ff210f402994e3c529ae5c183366aa12fc306ef",
		"9e77010979c3be5d67063c816ff210f402994e3c529ae5c183366aa12fc306ef",
	}
	ivs := []string{
		"0000000000000000d17120bfc0c34073",
		"0000000000000000d17120bfc0c34074",
		"0000000000000000d17120bfc0c34075",
	}
	logPath := filepath.Join(t.TempDir(), "prn.jsonl")
	writer, err := prnlog.NewWriter(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for stage := range keys {
		for _, item := range []struct {
			operation string
			encoded   string
		}{
			{operation: fmt.Sprintf("qilin.stage%d.iv", stage+1), encoded: ivs[stage]},
			{operation: fmt.Sprintf("qilin.stage%d.key", stage+1), encoded: keys[stage]},
		} {
			value, err := hex.DecodeString(item.encoded)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Write(prnlog.Record{
				Schema: prnlog.Schema, Source: "lab", Operation: item.operation,
				ValueHex: item.encoded, CapturedLength: len(value), RequestedLength: len(value),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(t.TempDir(), "recovered.bin")
	result, err := DecryptQilin(input, output, []string{logPath})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Heuristic {
		t.Fatal("Qilin result did not disclose heuristic candidate selection")
	}
	if result.KeyIndexes != [3]int{0, 1, 2} {
		t.Fatalf("Qilin key indexes=%v, want [0 1 2]", result.KeyIndexes)
	}
	if result.NonceIndexes != [3]int{0, 1, 2} {
		t.Fatalf("Qilin IV indexes=%v, want [0 1 2]", result.NonceIndexes)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("legacy fixture mismatch: got %x want %x", got, want)
	}
	after, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(after) != beforeHash {
		t.Fatal("legacy ciphertext fixture was modified")
	}
}

func TestQilinRecoveryExcludesGetrandomCandidates(t *testing.T) {
	input := filepath.Join("testdata", "qilin-legacy", "ciphertext.qilin")
	want, err := os.ReadFile(filepath.Join("testdata", "qilin-legacy", "plaintext.bin"))
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{
		"7e77010979c3be5d67063c816ff210f402994e3c529ae5c183366aa12fc306ef",
		"8e77010979c3be5d67063c816ff210f402994e3c529ae5c183366aa12fc306ef",
		"9e77010979c3be5d67063c816ff210f402994e3c529ae5c183366aa12fc306ef",
	}
	ivs := []string{
		"0000000000000000d17120bfc0c34073",
		"0000000000000000d17120bfc0c34074",
		"0000000000000000d17120bfc0c34075",
	}
	logPath := filepath.Join(t.TempDir(), "mixed-prn.jsonl")
	writer, err := prnlog.NewWriter(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, length := range []int{16, 20, 32} {
		value := bytes.Repeat([]byte{byte(length)}, length)
		if err := writer.Write(prnlog.Record{
			Schema: prnlog.Schema, Source: "syscall", Operation: "getrandom",
			ValueHex: hex.EncodeToString(value), CapturedLength: length, RequestedLength: length,
			Syscall: &prnlog.SyscallMeta{Name: "getrandom"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	for stage := range keys {
		for _, encoded := range []string{ivs[stage], keys[stage]} {
			value, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Write(prnlog.Record{
				Schema: prnlog.Schema, Source: "syscall", Operation: "read",
				ValueHex: encoded, CapturedLength: len(value), RequestedLength: len(value),
				Syscall: &prnlog.SyscallMeta{Name: "read", Path: "/dev/urandom"},
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(t.TempDir(), "recovered.bin")
	result, err := DecryptQilin(input, output, []string{logPath})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyIndexes != [3]int{0, 1, 2} || result.NonceIndexes != [3]int{0, 1, 2} {
		t.Fatalf("getrandom changed recovery indexes: keys=%v IVs=%v", result.KeyIndexes, result.NonceIndexes)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("recovery with mixed getrandom records did not match the fixture")
	}
}

func TestQilinRecoveryRecordPolicy(t *testing.T) {
	valid := prnlog.Record{
		Source: "syscall", Operation: "read", CapturedLength: 32, RequestedLength: 32,
		Syscall: &prnlog.SyscallMeta{Name: "read", Path: "/dev/urandom"},
	}
	if kind, ok := qilinRecoveryRecord(valid); !ok || kind != "key" {
		t.Fatalf("valid /dev/urandom key rejected: kind=%q ok=%v", kind, ok)
	}
	for name, record := range map[string]prnlog.Record{
		"getrandom":              {Source: "syscall", Operation: "getrandom", CapturedLength: 32, RequestedLength: 32, Syscall: &prnlog.SyscallMeta{Name: "getrandom"}},
		"wrong path":             {Source: "syscall", Operation: "read", CapturedLength: 32, RequestedLength: 32, Syscall: &prnlog.SyscallMeta{Name: "read", Path: "/dev/random"}},
		"truncated":              {Source: "syscall", Operation: "read", CapturedLength: 32, RequestedLength: 64, Truncated: true, Syscall: &prnlog.SyscallMeta{Name: "read", Path: "/dev/urandom"}},
		"wrong direct operation": {Source: "lab", Operation: "qilin.fixture", CapturedLength: 32, RequestedLength: 32},
		"wrong direct source":    {Source: "test", Operation: "qilin.stage1.key", CapturedLength: 32, RequestedLength: 32},
	} {
		if kind, ok := qilinRecoveryRecord(record); ok {
			t.Fatalf("%s record accepted as %q", name, kind)
		}
	}
	if kind, ok := qilinRecoveryRecord(prnlog.Record{Source: "lab", Operation: "qilin.stage3.iv", CapturedLength: 16, RequestedLength: 16}); !ok || kind != "iv" {
		t.Fatalf("valid direct IV rejected: kind=%q ok=%v", kind, ok)
	}
}

func TestQilinRecoveryRejectsGetrandomOnly(t *testing.T) {
	input := filepath.Join("testdata", "qilin-legacy", "ciphertext.qilin")
	logPath := filepath.Join(t.TempDir(), "getrandom-only.jsonl")
	writer, err := prnlog.NewWriter(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		for _, length := range []int{16, 32} {
			value := bytes.Repeat([]byte{byte(index + length)}, length)
			if err := writer.Write(prnlog.Record{
				Schema: prnlog.Schema, Source: "syscall", Operation: "getrandom",
				ValueHex: hex.EncodeToString(value), CapturedLength: length, RequestedLength: length,
				Syscall: &prnlog.SyscallMeta{Name: "getrandom"},
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "unexpected.bin")
	if _, err := DecryptQilin(input, output, []string{logPath}); err == nil {
		t.Fatal("Qilin recovery accepted getrandom-only candidates")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("getrandom-only recovery created output: %v", err)
	}
}

func TestQilinLegacyFixtureRejectsWrongPRNs(t *testing.T) {
	input := filepath.Join("testdata", "qilin-legacy", "ciphertext.qilin")
	logPath := filepath.Join(t.TempDir(), "wrong-prn.jsonl")
	writer, err := prnlog.NewWriter(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for stage := 1; stage <= 3; stage++ {
		iv := bytes.Repeat([]byte{byte(0x10 + stage)}, 16)
		key := bytes.Repeat([]byte{byte(0x20 + stage)}, 32)
		for _, item := range []struct {
			operation string
			value     []byte
		}{
			{operation: fmt.Sprintf("qilin.stage%d.iv", stage), value: iv},
			{operation: fmt.Sprintf("qilin.stage%d.key", stage), value: key},
		} {
			if err := writer.Write(prnlog.Record{
				Schema: prnlog.Schema, Source: "lab", Operation: item.operation,
				ValueHex: hex.EncodeToString(item.value), CapturedLength: len(item.value), RequestedLength: len(item.value),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "unexpected.bin")
	if _, err := DecryptQilin(input, output, []string{logPath}); err == nil {
		t.Fatal("Qilin recovery accepted three incorrect key/IV pairs")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("wrong-PRN recovery created output: %v", err)
	}
}
