// SPDX-License-Identifier: GPL-2.0-only

package simcrypto

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/KDDIR-SEC/memento/internal/crypto/babukkdf"
	"github.com/KDDIR-SEC/memento/internal/crypto/sosemanuk"
)

type oneRead struct {
	value []byte
	calls int
}

func (r *oneRead) Read(destination []byte) (int, error) {
	r.calls++
	if r.calls > 1 {
		return 0, errors.New("unexpected second read")
	}
	return copy(destination, r.value), nil
}

func TestBabukMemoryVectorRoundTrip(t *testing.T) {
	prn := bytes.Repeat([]byte{0x42}, 32)
	plaintext := bytes.Repeat([]byte("Babuk SHA-512 memory vector\n"), 32)
	var encrypted bytes.Buffer
	var logged []byte
	err := TransformBabuk(&encrypted, bytes.NewReader(plaintext), BabukOptions{
		MasterPublicKey: DefaultBabukPublicKey,
		Random:          bytes.NewReader(prn),
		MaxEncryptBytes: int64(len(plaintext)),
		PRN: func(_ string, value []byte) error {
			logged = append([]byte(nil), value...)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(logged, prn) {
		t.Fatal("raw PRN was not logged before X25519 clamping")
	}
	material, err := babukkdf.Derive(prn, DefaultBabukPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	value := encrypted.Bytes()
	if !bytes.Equal(value[len(value)-32:], material.EphemeralPublic[:]) {
		t.Fatal("Babuk public-key footer mismatch")
	}
	var recovered bytes.Buffer
	if _, err := sosemanuk.XOR(material.Key[:], &recovered, bytes.NewReader(value[:len(value)-32]), int64(len(plaintext))); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.Bytes(), plaintext) {
		t.Fatal("Babuk memory round-trip mismatch")
	}
}

func TestBabukUsesOneExactRandomDeviceRead(t *testing.T) {
	random := &oneRead{value: bytes.Repeat([]byte{0x51}, 32)}
	var encrypted bytes.Buffer
	if err := TransformBabuk(&encrypted, bytes.NewReader([]byte("fixture")), BabukOptions{
		MasterPublicKey: DefaultBabukPublicKey,
		Random:          random,
	}); err != nil {
		t.Fatal(err)
	}
	if random.calls != 1 {
		t.Fatalf("random read calls = %d, want 1", random.calls)
	}

	short := &oneRead{value: bytes.Repeat([]byte{0x52}, 31)}
	if err := TransformBabuk(io.Discard, bytes.NewReader([]byte("fixture")), BabukOptions{
		MasterPublicKey: DefaultBabukPublicKey,
		Random:          short,
	}); err == nil {
		t.Fatal("short random-device read was accepted")
	}
}
