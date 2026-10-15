// SPDX-License-Identifier: GPL-2.0-only

package keygen

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"

	"golang.org/x/crypto/curve25519"
)

type BabukKey struct {
	Schema     string    `json:"schema"`
	CreatedAt  time.Time `json:"created_at"`
	PrivateHex string    `json:"private_key_hex"`
	PublicHex  string    `json:"public_key_hex"`
}

func Babuk(path string) (BabukKey, error) {
	private := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(private); err != nil {
		return BabukKey{}, err
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return BabukKey{}, err
	}
	key := BabukKey{Schema: "memento.babuk-key/v1", CreatedAt: time.Now().UTC(), PrivateHex: hex.EncodeToString(private), PublicHex: hex.EncodeToString(public)}
	clear(private)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return BabukKey{}, err
	}
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(key)
	return key, errors.Join(writeErr, f.Close())
}
