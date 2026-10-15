// SPDX-License-Identifier: GPL-2.0-only

// Package babukkdf implements the Babuk-compatible X25519 key derivation.
package babukkdf

import (
	"crypto/sha512"
	"errors"

	"golang.org/x/crypto/curve25519"
)

const Size = curve25519.ScalarSize

// Material contains the values derived from a raw 32-byte PRN and the
// attacker's master public key. The raw PRN is clamped according to X25519
// before either value is derived. Babuk uses the first 32 bytes of SHA-512 of
// the shared secret as its Sosemanuk key.
type Material struct {
	Key             [Size]byte
	EphemeralPublic [Size]byte
}

func Derive(rawPRN, masterPublic []byte) (Material, error) {
	var material Material
	if len(rawPRN) != Size {
		return material, errors.New("Babuk PRN must be 32 bytes")
	}
	if len(masterPublic) != curve25519.PointSize {
		return material, errors.New("Babuk master public key must be 32 bytes")
	}

	private := append([]byte(nil), rawPRN...)
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	defer clear(private)

	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return material, err
	}
	copy(material.EphemeralPublic[:], public)
	clear(public)

	secret, err := curve25519.X25519(private, masterPublic)
	if err != nil {
		return Material{}, err
	}
	digest := sha512.Sum512(secret)
	clear(secret)
	copy(material.Key[:], digest[:Size])
	clear(digest[:])
	return material, nil
}
