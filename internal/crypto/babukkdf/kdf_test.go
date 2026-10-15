// SPDX-License-Identifier: GPL-2.0-only

package babukkdf

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestRFC7748AndSHA512Vector(t *testing.T) {
	raw := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	master := mustHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	material, err := Derive(raw, master)
	if err != nil {
		t.Fatal(err)
	}
	wantPublic := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	wantKey := "3efdfd26b71935c26e478db0de1188df085a91d0c670c3522904d311cc554004"
	if got := hex.EncodeToString(material.EphemeralPublic[:]); got != wantPublic {
		t.Fatalf("public key mismatch: got %s want %s", got, wantPublic)
	}
	if got := hex.EncodeToString(material.Key[:]); got != wantKey {
		t.Fatalf("derived key mismatch: got %s want %s", got, wantKey)
	}
}

func TestRejectsInvalidLengths(t *testing.T) {
	if _, err := Derive(make([]byte, 31), make([]byte, 32)); err == nil {
		t.Fatal("accepted a short PRN")
	}
	if _, err := Derive(make([]byte, 32), make([]byte, 31)); err == nil {
		t.Fatal("accepted a short master public key")
	}
}
