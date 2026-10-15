// SPDX-License-Identifier: GPL-2.0-only

package simcrypto

import (
	"fmt"
	"io"

	"github.com/KDDIR-SEC/memento/internal/crypto/babukkdf"
	"github.com/KDDIR-SEC/memento/internal/crypto/sosemanuk"
	"golang.org/x/crypto/curve25519"
)

const BabukSuffix = ".babyk"

var DefaultBabukPublicKey = []byte{
	0xc2, 0xf5, 0xa8, 0xee, 0x98, 0x65, 0xfe, 0x32,
	0x7a, 0xf0, 0xff, 0xd0, 0xf9, 0xc1, 0x30, 0x13,
	0xd5, 0x69, 0x66, 0x6d, 0xa7, 0x27, 0x39, 0xe5,
	0x48, 0xd2, 0xf5, 0x39, 0x24, 0x64, 0x2c, 0x54,
}

type PRNSink func(operation string, value []byte) error

type BabukOptions struct {
	MasterPublicKey []byte
	Random          io.Reader
	MaxEncryptBytes int64
	PRN             PRNSink
}

// TransformBabuk writes a Babuk-compatible encrypted stream without ever
// seeking or mutating the input. Path policy is deliberately outside this
// package and is enforced by internal/lab.
func TransformBabuk(dst io.Writer, src io.Reader, options BabukOptions) error {
	if len(options.MasterPublicKey) != curve25519.PointSize {
		return fmt.Errorf("Babuk master public key must be 32 bytes")
	}
	var device io.Closer
	if options.Random == nil {
		urandom, err := openVerifiedUrandom()
		if err != nil {
			return fmt.Errorf("open Babuk random source: %w", err)
		}
		device = urandom
		options.Random = urandom
	}
	if device != nil {
		defer device.Close()
	}
	if options.MaxEncryptBytes == 0 {
		options.MaxEncryptBytes = 512 * 1024 * 1024
	}
	rawPRN := make([]byte, curve25519.ScalarSize)
	if err := readRandomDevice(options.Random, rawPRN); err != nil {
		return fmt.Errorf("generate Babuk ephemeral key: %w", err)
	}
	defer clear(rawPRN)
	if options.PRN != nil {
		if err := options.PRN("babuk.ephemeral_private", append([]byte(nil), rawPRN...)); err != nil {
			return err
		}
	}
	material, err := babukkdf.Derive(rawPRN, options.MasterPublicKey)
	if err != nil {
		return fmt.Errorf("derive Babuk key material: %w", err)
	}
	defer clear(material.Key[:])
	if _, err := sosemanuk.XOR(material.Key[:], dst, src, options.MaxEncryptBytes); err != nil {
		return fmt.Errorf("Babuk stream transform: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy Babuk unencrypted tail: %w", err)
	}
	if _, err := dst.Write(material.EphemeralPublic[:]); err != nil {
		return fmt.Errorf("append Babuk public key: %w", err)
	}
	return nil
}
