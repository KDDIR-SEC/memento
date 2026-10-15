// SPDX-License-Identifier: GPL-2.0-only

package recover

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/KDDIR-SEC/memento/internal/crypto/babukkdf"
	"github.com/KDDIR-SEC/memento/internal/crypto/sosemanuk"
)

const babukMaxEncrypted = int64(512 * 1024 * 1024)

type BabukResult struct {
	PRNIndex int
	Score    float64
}

func DecryptBabuk(inputPath, outputPath string, masterPublicKey []byte, logPaths []string) (BabukResult, error) {
	info, err := requireRegular(inputPath)
	if err != nil {
		return BabukResult{}, err
	}
	if info.Size() < 32 {
		return BabukResult{}, errors.New("Babuk ciphertext is shorter than its public-key footer")
	}
	if len(masterPublicKey) != 32 {
		return BabukResult{}, errors.New("Babuk master public key must be 32 bytes")
	}
	values, err := loadPRNs(logPaths)
	if err != nil {
		return BabukResult{}, err
	}
	input, err := os.Open(inputPath)
	if err != nil {
		return BabukResult{}, err
	}
	defer input.Close()
	previewLength := min(int64(128*1024), info.Size()-32, babukMaxEncrypted)
	preview := make([]byte, previewLength)
	if _, err := io.ReadFull(input, preview); err != nil {
		return BabukResult{}, err
	}
	footer := make([]byte, 32)
	if _, err := input.ReadAt(footer, info.Size()-32); err != nil {
		return BabukResult{}, fmt.Errorf("read Babuk public-key footer: %w", err)
	}
	best := BabukResult{PRNIndex: -1, Score: -1e100}
	var bestKey [32]byte
	for index, value := range values {
		if len(value) != 32 {
			continue
		}
		key, matched := babukCandidate(value, masterPublicKey, footer)
		if !matched {
			continue
		}
		var decrypted bytes.Buffer
		if _, err := sosemanuk.XOR(key[:], &decrypted, bytes.NewReader(preview), int64(len(preview))); err != nil {
			return BabukResult{}, err
		}
		score := ScorePlaintext(decrypted.Bytes())
		if score > best.Score {
			best = BabukResult{PRNIndex: index, Score: score}
			bestKey = key
		}
		clear(key[:])
	}
	if best.PRNIndex < 0 {
		return BabukResult{}, errors.New("no PRN candidate matched the Babuk public-key footer")
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return BabukResult{}, err
	}
	output, err := createPrivate(outputPath)
	if err != nil {
		return BabukResult{}, err
	}
	success := false
	defer func() {
		_ = output.Close()
		if !success {
			_ = os.Remove(outputPath)
		}
	}()
	originalSize := info.Size() - 32
	encryptedLength := min(originalSize, babukMaxEncrypted)
	if _, err := sosemanuk.XOR(bestKey[:], output, io.LimitReader(input, encryptedLength), encryptedLength); err != nil {
		return BabukResult{}, err
	}
	clear(bestKey[:])
	if _, err := io.CopyN(output, input, originalSize-encryptedLength); err != nil {
		return BabukResult{}, fmt.Errorf("copy Babuk plaintext tail: %w", err)
	}
	if err := output.Sync(); err != nil {
		return BabukResult{}, err
	}
	if err := output.Close(); err != nil {
		return BabukResult{}, err
	}
	success = true
	return best, nil
}

func babukCandidate(rawPRN, masterPublicKey, footer []byte) ([32]byte, bool) {
	material, err := babukkdf.Derive(rawPRN, masterPublicKey)
	if err != nil || !bytes.Equal(material.EphemeralPublic[:], footer) {
		clear(material.Key[:])
		return [32]byte{}, false
	}
	return material.Key, true
}
