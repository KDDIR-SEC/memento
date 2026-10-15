// SPDX-License-Identifier: GPL-2.0-only

package sosemanuk

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// X-CRYPT's reference implementation vector 2, first 64 output bytes.
func TestXCryptReferenceVector2(t *testing.T) {
	key, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	iv, _ := hex.DecodeString("8899aabbccddeeff0011223344556677")
	want, _ := hex.DecodeString(
		"fa61dbeb71178131a77c714bd2eabf4e" +
			"1394207a25698aa1308f2f063a0f7606" +
			"04cf67569ba59a3dfad7f00145c78d29" +
			"c5ffe5f964950486424451952c84039d")
	var output bytes.Buffer
	n, err := xorWithIV(key, iv, &output, bytes.NewReader(make([]byte, len(want))), int64(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(want)) || !bytes.Equal(output.Bytes(), want) {
		t.Fatalf("vector mismatch: got %x want %x", output.Bytes(), want)
	}
}

func TestXORRejectsInvalidParameters(t *testing.T) {
	if _, err := XOR(make([]byte, 31), bytes.NewBuffer(nil), bytes.NewReader(nil), 0); err == nil {
		t.Fatal("short Babuk key was accepted")
	}
	if _, err := xorWithIV([]byte{1}, make([]byte, 17), bytes.NewBuffer(nil), bytes.NewReader(nil), 0); err == nil {
		t.Fatal("oversized IV was accepted")
	}
}
