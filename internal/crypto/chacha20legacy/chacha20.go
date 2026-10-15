// SPDX-License-Identifier: GPL-2.0-only

// Package chacha20legacy implements the OpenSSL EVP_chacha20 stream layout.
// OpenSSL uses a 16-byte IV consisting of a 64-bit little-endian block counter
// followed by an eight-byte nonce. The x/crypto implementation uses an IETF
// 32-bit counter and a twelve-byte nonce, so the upper counter word is mapped
// into the first four nonce bytes and the stream is restarted when it wraps.
package chacha20legacy

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
)

const (
	KeySize = 32
	IVSize  = 16
)

type Cipher struct {
	key       [KeySize]byte
	nonce     [8]byte
	counter   uint64
	remaining uint64
	stream    *chacha20.Cipher
}

func New(key, iv []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, errors.New("ChaCha20 key must be 32 bytes")
	}
	if len(iv) != IVSize {
		return nil, errors.New("OpenSSL ChaCha20 IV must be 16 bytes")
	}
	c := &Cipher{counter: binary.LittleEndian.Uint64(iv[:8])}
	copy(c.key[:], key)
	copy(c.nonce[:], iv[8:])
	if err := c.reset(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cipher) reset() error {
	var nonce12 [chacha20.NonceSize]byte
	binary.LittleEndian.PutUint32(nonce12[:4], uint32(c.counter>>32))
	copy(nonce12[4:], c.nonce[:])
	stream, err := chacha20.NewUnauthenticatedCipher(c.key[:], nonce12[:])
	if err != nil {
		return err
	}
	low := uint32(c.counter)
	stream.SetCounter(low)
	c.stream = stream
	c.remaining = (uint64(1)<<32 - uint64(low)) * 64
	return nil
}

func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("chacha20legacy: output smaller than input")
	}
	for len(src) > 0 {
		n := uint64(len(src))
		if n > c.remaining {
			n = c.remaining
		}
		c.stream.XORKeyStream(dst[:int(n)], src[:int(n)])
		dst, src = dst[int(n):], src[int(n):]
		c.remaining -= n
		if c.remaining == 0 && len(src) > 0 {
			c.counter = (c.counter &^ 0xffffffff) + (uint64(1) << 32)
			if err := c.reset(); err != nil {
				panic(err)
			}
		}
	}
}
