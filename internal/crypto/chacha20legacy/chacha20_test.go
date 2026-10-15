// SPDX-License-Identifier: GPL-2.0-only

package chacha20legacy

import (
	"encoding/hex"
	"testing"
)

// This vector is the RFC 8439 ChaCha20 example expressed through OpenSSL's
// 64-bit-counter + 64-bit-nonce IV layout. It also serves as the fixed vector
// for the former EVP_chacha20 implementation.
func TestOpenSSLLayoutGoldenVector(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	iv, _ := hex.DecodeString("01000000000000000000004a00000000")
	plaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	want, _ := hex.DecodeString("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d")
	c, err := New(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plaintext))
	c.XORKeyStream(got, plaintext)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("ciphertext mismatch\n got %x\nwant %x", got, want)
	}
}

func TestRejectSizes(t *testing.T) {
	if _, err := New(make([]byte, 31), make([]byte, 16)); err == nil {
		t.Fatal("accepted short key")
	}
	if _, err := New(make([]byte, 32), make([]byte, 12)); err == nil {
		t.Fatal("accepted IETF nonce in legacy wrapper")
	}
}
