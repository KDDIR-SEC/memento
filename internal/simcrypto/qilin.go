// SPDX-License-Identifier: GPL-2.0-only

package simcrypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- OpenSSL OAEP compatibility requires SHA-1.
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/KDDIR-SEC/memento/internal/crypto/chacha20legacy"
	"github.com/KDDIR-SEC/memento/internal/crypto/qilinlayout"
)

const (
	QilinSuffix       = ".qilin"
	qilinBufferSize   = 0x80000
	qilinMaxStartCopy = qilinlayout.MaxStartCopy
	qilinRSABytes     = 0x200
)

var qilinEndBlock = []byte("-----END CIPHERTEXT BLOCK-----")

const QilinPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArmcsYwrCGChKt2IJZzlq
BWoBpn7UuSF1oGi/D+MbjHPDEWfERFKYZhhJzufdg1lZgCC1vRMy22lg4559nh2Y
vTVizYQoxieYR6mMxdeGHFFD1mWriisXIU4a7DpAbKaF+7qkkeiyMrBBEen6fWLB
Ks0743Y4VlnOxT6GH4utycr6DCeMXrgAYWjHcS3vTYSPyBB1cVR0zWuu7z8pVAsN
x1EF+/+eblf3BV7fYlf+mDsOkQcl6ZEFzCNPfpRC8J0vkafL99AXfdPvduD7zLEw
8QYER5YyEwd6W8IGkFDcx2N5tWSYLn5Fi4zNbUc0T3VRErxxHCegQ3ZrOK3OiiZE
zrwTpjy/hkNYiahMwwb0gLhv/AxAXxzqn2QP0pUAn/7DArEzUfsIOkH5h9Aram/1
1G+oH53425+xsgRqPqyM+w9sZErz5H3RNwSM0TBUr4v1ABHSjt/r3caxGs9mwnWX
S0UXzheGIbj99XC9GSCtlhjGQePh8s/cORe1f9A7/5XA4lt+YiFJNeQBh8ifRKuY
RzDibLF3q1s1xRyb60XRi/BOMbx2yaG0yHMVCZXe53WC4fj+yWoguvdlE6PGrVpI
XSyhEzajPUVp9sRaAOaorcTQ08kTS5vdsOAyJuz//zBGl3HatNUiClw29O+BvenI
En4NLQ14QgcbBO4KgxHA9pUCAwEAAQ==
-----END PUBLIC KEY-----
`

type QilinOptions struct {
	PublicKeyPEM   []byte
	SecretRandom   io.Reader
	OAEPSeedRandom io.Reader
	MaxInput       int64
	PRN            PRNSink
}

// TransformQilin ports the former OpenSSL simulator to Go. It reads the
// complete bounded lab fixture, applies the three historical stages in memory,
// and writes a new stream. RSA uses OpenSSL-compatible OAEP with
// SHA-1/MGF1-SHA-1; ChaCha20 uses OpenSSL's 16-byte IV layout.
func TransformQilin(dst io.Writer, src io.Reader, options QilinOptions) error {
	if options.MaxInput <= 0 {
		options.MaxInput = 64 * 1024 * 1024
	}
	limited := io.LimitReader(src, options.MaxInput+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read Qilin input: %w", err)
	}
	if int64(len(data)) > options.MaxInput {
		return fmt.Errorf("Qilin lab input exceeds %d-byte safety limit", options.MaxInput)
	}
	if len(data) == 0 {
		return fmt.Errorf("Qilin lab input must not be empty")
	}
	publicKey, err := parseQilinPublicKey(options.PublicKeyPEM)
	if err != nil {
		return err
	}
	secretRandom := options.SecretRandom
	if secretRandom == nil {
		device, err := openVerifiedUrandom()
		if err != nil {
			return err
		}
		defer device.Close()
		secretRandom = device
	}
	oaepSeedRandom := options.OAEPSeedRandom
	if oaepSeedRandom == nil {
		oaepSeedRandom = rand.Reader
	}
	for stage := 1; stage <= 3; stage++ {
		iv := make([]byte, chacha20legacy.IVSize)
		key := make([]byte, chacha20legacy.KeySize)
		if err := readRandomDevice(secretRandom, iv); err != nil {
			return fmt.Errorf("generate Qilin stage %d IV: %w", stage, err)
		}
		if err := readRandomDevice(secretRandom, key); err != nil {
			return fmt.Errorf("generate Qilin stage %d key: %w", stage, err)
		}
		if options.PRN != nil {
			if err := options.PRN(fmt.Sprintf("qilin.stage%d.iv", stage), append([]byte(nil), iv...)); err != nil {
				return err
			}
			if err := options.PRN(fmt.Sprintf("qilin.stage%d.key", stage), append([]byte(nil), key...)); err != nil {
				return err
			}
		}
		data, err = qilinStage(data, stage, key, iv, publicKey, oaepSeedRandom)
		clear(key)
		clear(iv)
		if err != nil {
			return fmt.Errorf("Qilin stage %d: %w", stage, err)
		}
	}
	_, err = io.Copy(dst, bytes.NewReader(data))
	return err
}

func parseQilinPublicKey(value []byte) (*rsa.PublicKey, error) {
	if len(value) == 0 {
		value = []byte(QilinPublicKeyPEM)
	}
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, fmt.Errorf("decode Qilin public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Qilin public key: %w", err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.Size() != qilinRSABytes {
		return nil, fmt.Errorf("Qilin public key must be 4096-bit RSA")
	}
	return key, nil
}

func qilinStage(input []byte, stage int, key, iv []byte, publicKey *rsa.PublicKey, oaepSeedRandom io.Reader) ([]byte, error) {
	originalSize := len(input)
	base := make([]byte, originalSize+0x208)
	copy(base, input)
	chunkSize, skipSize, err := qilinlayout.Parameters(stage, originalSize)
	if err != nil {
		return nil, err
	}
	secrets := make([]byte, 64)
	copy(secrets[:32], key)
	copy(secrets[32:48], iv)
	binary.LittleEndian.PutUint64(secrets[48:56], uint64(chunkSize))
	binary.LittleEndian.PutUint64(secrets[56:64], uint64(skipSize))
	footer, err := rsa.EncryptOAEP(sha1.New(), oaepSeedRandom, publicKey, secrets, nil)
	clear(secrets)
	if err != nil {
		return nil, fmt.Errorf("encrypt key footer: %w", err)
	}
	copy(base[originalSize:originalSize+qilinRSABytes], footer)

	first := true
	encryptRange := func(offset, length int) error {
		if length <= 0 {
			return nil
		}
		cipher, err := chacha20legacy.New(key, iv)
		if err != nil {
			return err
		}
		end := min(offset+length, originalSize)
		for pos := offset; pos < end; {
			n := min(qilinBufferSize, end-pos)
			cipher.XORKeyStream(base[pos:pos+n], base[pos:pos+n])
			binary.LittleEndian.PutUint64(base[originalSize+0x200:originalSize+0x208], uint64(pos))
			if first {
				startSize := min(n, qilinMaxStartCopy)
				expanded := make([]byte, originalSize+0x226+startSize)
				copy(expanded, base)
				copy(expanded[originalSize+0x208:], qilinEndBlock)
				copy(expanded[originalSize+0x226:], base[pos:pos+startSize])
				base = expanded
				first = false
			}
			pos += n
		}
		return nil
	}

	ranges, err := qilinlayout.Ranges(stage, originalSize)
	if err != nil {
		return nil, err
	}
	for _, value := range ranges {
		if err := encryptRange(value.Offset, value.Length); err != nil {
			return nil, err
		}
	}
	for i := originalSize + 0x200; i < originalSize+0x208; i++ {
		base[i] = 0xff
	}
	return base, nil
}
