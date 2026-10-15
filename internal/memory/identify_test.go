// SPDX-License-Identifier: GPL-2.0-only

package memory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
	"github.com/KDDIR-SEC/memento/internal/simcrypto"
	"golang.org/x/crypto/curve25519"
)

func TestIdentifyBabukRanksTrueMasterPublicKeyFirst(t *testing.T) {
	root := t.TempDir()
	masterPrivate := sha256.Sum256([]byte("memento Babuk identification master private fixture"))
	masterPublic, err := curve25519.X25519(masterPrivate[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if shannon(masterPublic) < defaultIdentifyEntropy {
		t.Fatal("fixed master public key does not meet the candidate entropy threshold")
	}
	rawPRN := sha256.Sum256([]byte("memento Babuk identification PRN fixture"))
	plaintext := bytes.Repeat([]byte("Readable Babuk recovery fixture line.\n"), 4)
	var ciphertext bytes.Buffer
	if err := simcrypto.TransformBabuk(&ciphertext, bytes.NewReader(plaintext), simcrypto.BabukOptions{
		MasterPublicKey: masterPublic,
		Random:          bytes.NewReader(rawPRN[:]),
	}); err != nil {
		t.Fatal(err)
	}
	ciphertextPath := filepath.Join(root, "fixture.memento.babyk")
	if err := os.WriteFile(ciphertextPath, ciphertext.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "syscall-prn.jsonl")
	writer, err := prnlog.NewWriter(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(prnlog.Record{Schema: prnlog.Schema, Source: "syscall", Operation: "read", ValueHex: hex.EncodeToString(rawPRN[:]), CapturedLength: 32, RequestedLength: 32, Syscall: &prnlog.SyscallMeta{Name: "read", Path: "/dev/urandom"}}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	dumpDirectory := filepath.Join(root, "dump")
	if err := os.Mkdir(dumpDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dumpDirectory, "maps.txt"), []byte("0000000000001000-0000000000002000 rw-p 00000000 00:00 0 [heap]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrong1 := sha256.Sum256([]byte("wrong public candidate one"))
	wrong2 := sha256.Sum256([]byte("wrong public candidate two"))
	dump := make([]byte, 96)
	copy(dump[0:32], wrong1[:])
	copy(dump[32:64], masterPublic)
	copy(dump[64:96], wrong2[:])
	if err := os.WriteFile(filepath.Join(dumpDirectory, "0000000000001000.dump"), dump, 0o600); err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(root, "identification.json")
	result, err := IdentifyBabuk(IdentifyBabukOptions{
		DumpDirectory: dumpDirectory,
		InputPath:     ciphertextPath,
		PRNLogs:       []string{logPath},
		OutputPath:    resultPath,
		Alignment:     8,
		Threshold:     4.5,
		MaxCandidates: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PublicKeyHex != hex.EncodeToString(masterPublic) || !result.Heuristic || result.PRNIndex != 0 {
		t.Fatalf("unexpected identification: %#v", result)
	}
	info, err := os.Lstat(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("result mode = %o, want 0600", info.Mode().Perm())
	}

	_, err = IdentifyBabuk(IdentifyBabukOptions{
		DumpDirectory: dumpDirectory,
		InputPath:     ciphertextPath,
		PRNLogs:       []string{logPath},
		OutputPath:    filepath.Join(root, "limited.json"),
		Alignment:     8,
		Threshold:     4.5,
		MaxCandidates: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "candidate limit exceeded") {
		t.Fatalf("candidate limit was not fail-closed: %v", err)
	}
}
