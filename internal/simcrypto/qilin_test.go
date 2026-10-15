// SPDX-License-Identifier: GPL-2.0-only

package simcrypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- the compatibility contract is OAEP-SHA-1.
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/KDDIR-SEC/memento/internal/crypto/chacha20legacy"
	"github.com/KDDIR-SEC/memento/internal/crypto/qilinlayout"
)

func TestQilinRejectsEmptyInput(t *testing.T) {
	var output bytes.Buffer
	if err := TransformQilin(&output, bytes.NewReader(nil), QilinOptions{}); err == nil {
		t.Fatal("empty input was accepted")
	}
}

type recordingReader struct {
	value byte
	calls []int
	bytes int
}

func (r *recordingReader) Read(destination []byte) (int, error) {
	r.calls = append(r.calls, len(destination))
	for index := range destination {
		r.value++
		if r.value == 0 {
			r.value = 1
		}
		destination[index] = r.value
	}
	r.bytes += len(destination)
	return len(destination), nil
}

func TestQilinSeparatesSecretAndOAEPSeedRandomness(t *testing.T) {
	secretRandom := &recordingReader{}
	oaepSeedRandom := &recordingReader{value: 0x80}
	type observedPRN struct {
		operation string
		length    int
	}
	var observed []observedPRN
	var output bytes.Buffer
	err := TransformQilin(&output, bytes.NewReader([]byte("Qilin random-source separation")), QilinOptions{
		SecretRandom:   secretRandom,
		OAEPSeedRandom: oaepSeedRandom,
		PRN: func(operation string, value []byte) error {
			observed = append(observed, observedPRN{operation: operation, length: len(value)})
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantSecretCalls := []int{16, 32, 16, 32, 16, 32}
	if !slices.Equal(secretRandom.calls, wantSecretCalls) {
		t.Fatalf("secret random calls=%v, want %v", secretRandom.calls, wantSecretCalls)
	}
	if secretRandom.bytes != 144 {
		t.Fatalf("secret random bytes=%d, want 144", secretRandom.bytes)
	}
	wantOAEPCalls := []int{sha1.Size, sha1.Size, sha1.Size}
	if !slices.Equal(oaepSeedRandom.calls, wantOAEPCalls) {
		t.Fatalf("OAEP seed random calls=%v, want %v", oaepSeedRandom.calls, wantOAEPCalls)
	}
	if oaepSeedRandom.bytes != 3*sha1.Size {
		t.Fatalf("OAEP seed random bytes=%d, want %d", oaepSeedRandom.bytes, 3*sha1.Size)
	}
	wantPRNs := []observedPRN{
		{operation: "qilin.stage1.iv", length: 16},
		{operation: "qilin.stage1.key", length: 32},
		{operation: "qilin.stage2.iv", length: 16},
		{operation: "qilin.stage2.key", length: 32},
		{operation: "qilin.stage3.iv", length: 16},
		{operation: "qilin.stage3.key", length: 32},
	}
	if !slices.Equal(observed, wantPRNs) {
		t.Fatalf("PRN records=%v, want %v", observed, wantPRNs)
	}
}

func TestQilinRejectsShortSecretRead(t *testing.T) {
	var output bytes.Buffer
	err := TransformQilin(&output, bytes.NewReader([]byte("input")), QilinOptions{
		SecretRandom:   io.LimitReader(bytes.NewReader(make([]byte, 16)), 15),
		OAEPSeedRandom: bytes.NewReader(make([]byte, 3*sha1.Size)),
	})
	if err == nil || !strings.Contains(err.Error(), "short random-device read") {
		t.Fatalf("short secret read error=%v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("short secret read produced %d output bytes", output.Len())
	}
}

func TestOpenQilinUrandom(t *testing.T) {
	device, err := openVerifiedUrandom()
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	value := make([]byte, 32)
	if err := readRandomDevice(device, value); err != nil {
		t.Fatal(err)
	}
}

func TestQilinFooterUsesOpenSSLOAEPDefaults(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("OAEP footer vector")
	key := bytes.Repeat([]byte{0x31}, 32)
	iv := bytes.Repeat([]byte{0x52}, 16)
	value, err := qilinStage(plaintext, 1, key, iv, &private.PublicKey, bytes.NewReader(bytes.Repeat([]byte{0x73}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	footer := value[len(plaintext) : len(plaintext)+qilinRSABytes]
	secrets, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, private, footer, nil)
	if err != nil {
		t.Fatalf("OAEP-SHA-1 footer did not decrypt: %v", err)
	}
	if len(secrets) != 64 || !bytes.Equal(secrets[:32], key) || !bytes.Equal(secrets[32:48], iv) {
		t.Fatalf("unexpected Qilin secrets: %x", secrets)
	}
	if got := binary.LittleEndian.Uint64(secrets[48:56]); got != uint64(len(plaintext)) {
		t.Fatalf("chunk size = %d, want %d", got, len(plaintext))
	}
	if got := binary.LittleEndian.Uint64(secrets[56:64]); got != 0 {
		t.Fatalf("skip size = %d, want 0", got)
	}
}

func TestQilinShortStageSizes(t *testing.T) {
	public, err := parseQilinPublicKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1, 63, 64, 1023, 1024, 1025} {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			input := bytes.Repeat([]byte{0xa5}, size)
			value, err := qilinStage(input, 1, make([]byte, 32), make([]byte, 16), public, bytes.NewReader(bytes.Repeat([]byte{0x42}, 128)))
			if err != nil {
				t.Fatal(err)
			}
			want := size + 0x226 + min(size, qilinMaxStartCopy)
			if len(value) != want {
				t.Fatalf("size %d: got %d bytes, want %d", size, len(value), want)
			}
		})
	}
}

func TestQilinStage1ChunkBoundary(t *testing.T) {
	public, err := parseQilinPublicKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	size := qilinlayout.Stage1Chunk + 1
	input := patternedQilinInput(size)
	key := bytes.Repeat([]byte{0x31}, chacha20legacy.KeySize)
	iv := bytes.Repeat([]byte{0x52}, chacha20legacy.IVSize)
	got, err := qilinStage(input, 1, key, iv, public, bytes.NewReader(bytes.Repeat([]byte{0x73}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	wantSize, err := qilinlayout.ExpandedSize(size)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != wantSize {
		t.Fatalf("stage-1 output size=%d, want %d", len(got), wantSize)
	}
	wantPrefix := make([]byte, qilinlayout.Stage1Chunk)
	cipher, err := chacha20legacy.New(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	cipher.XORKeyStream(wantPrefix, input[:qilinlayout.Stage1Chunk])
	if !bytes.Equal(got[:qilinlayout.Stage1Chunk], wantPrefix) {
		t.Fatal("stage-1 encrypted prefix does not match the OpenSSL ChaCha20 layout")
	}
	if got[qilinlayout.Stage1Chunk] != input[qilinlayout.Stage1Chunk] {
		t.Fatal("stage-1 byte beyond the 10 MiB chunk limit was encrypted")
	}
}

func TestQilinStage2MultipleStripes(t *testing.T) {
	public, err := parseQilinPublicKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	size := qilinlayout.Stage2Chunk + 1<<20
	input := patternedQilinInput(size)
	key := bytes.Repeat([]byte{0x19}, chacha20legacy.KeySize)
	iv := bytes.Repeat([]byte{0x2a}, chacha20legacy.IVSize)
	got, err := qilinStage(input, 2, key, iv, public, bytes.NewReader(bytes.Repeat([]byte{0x4b}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := qilinlayout.Ranges(2, size)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 {
		t.Fatalf("stage-2 range count=%d, want 2", len(ranges))
	}
	wantBody := append([]byte(nil), input...)
	for _, value := range ranges {
		cipher, err := chacha20legacy.New(key, iv)
		if err != nil {
			t.Fatal(err)
		}
		cipher.XORKeyStream(wantBody[value.Offset:value.Offset+value.Length], wantBody[value.Offset:value.Offset+value.Length])
	}
	if !bytes.Equal(got[:size], wantBody) {
		t.Fatal("stage-2 stripes or skipped bytes differ from the legacy reset-per-range behavior")
	}
	wantSize, err := qilinlayout.ExpandedSize(size)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != wantSize {
		t.Fatalf("stage-2 output size=%d, want %d", len(got), wantSize)
	}
}

func patternedQilinInput(size int) []byte {
	value := make([]byte, size)
	for index := range value {
		value[index] = byte(index*131 + 17)
	}
	return value
}
