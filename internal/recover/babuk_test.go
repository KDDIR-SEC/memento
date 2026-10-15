// SPDX-License-Identifier: GPL-2.0-only

package recover

import (
	"bytes"
	"testing"

	"github.com/KDDIR-SEC/memento/internal/crypto/babukkdf"
	"github.com/KDDIR-SEC/memento/internal/simcrypto"
)

func TestBabukCandidateRequiresPublicKeyFooterMatch(t *testing.T) {
	correct := bytes.Repeat([]byte{0x42}, 32)
	wrong := bytes.Repeat([]byte{0x43}, 32)
	material, err := babukkdf.Derive(correct, simcrypto.DefaultBabukPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, matched := babukCandidate(wrong, simcrypto.DefaultBabukPublicKey, material.EphemeralPublic[:]); matched {
		t.Fatal("wrong PRN matched the Babuk public-key footer")
	}
	key, matched := babukCandidate(correct, simcrypto.DefaultBabukPublicKey, material.EphemeralPublic[:])
	if !matched || key != material.Key {
		t.Fatal("correct PRN did not match the Babuk public-key footer")
	}
}
