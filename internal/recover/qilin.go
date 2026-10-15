// SPDX-License-Identifier: GPL-2.0-only

package recover

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/KDDIR-SEC/memento/internal/crypto/chacha20legacy"
	"github.com/KDDIR-SEC/memento/internal/crypto/qilinlayout"
	"github.com/KDDIR-SEC/memento/internal/prnlog"
)

const qilinMaxInput = 256 * 1024 * 1024

var endBlock = []byte("-----END CIPHERTEXT BLOCK-----")

type QilinResult struct {
	KeyIndexes   [3]int  `json:"key_indexes"`
	NonceIndexes [3]int  `json:"nonce_indexes"`
	Score        float64 `json:"score"`
	Heuristic    bool    `json:"heuristic"`
}

func DecryptQilin(inputPath, outputPath string, logPaths []string) (QilinResult, error) {
	info, err := requireRegular(inputPath)
	if err != nil {
		return QilinResult{}, err
	}
	if info.Size() > qilinMaxInput {
		return QilinResult{}, fmt.Errorf("Qilin ciphertext exceeds %d-byte recovery limit", qilinMaxInput)
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return QilinResult{}, err
	}
	records, err := loadPRNRecords(logPaths)
	if err != nil {
		return QilinResult{}, err
	}
	var keys, nonces [][]byte
	seenKeys, seenNonces := make(map[string]bool), make(map[string]bool)
	for _, record := range records {
		kind, accepted := qilinRecoveryRecord(record)
		if !accepted {
			continue
		}
		value, err := hex.DecodeString(record.ValueHex)
		if err != nil {
			return QilinResult{}, err
		}
		switch kind {
		case "key":
			if !seenKeys[string(value)] {
				seenKeys[string(value)] = true
				keys = append(keys, value)
			}
		case "iv":
			if !seenNonces[string(value)] {
				seenNonces[string(value)] = true
				nonces = append(nonces, value)
			}
		}
	}
	if len(keys) < 3 || len(nonces) < 3 {
		return QilinResult{}, errors.New("Qilin recovery needs at least three 32-byte keys and three 16-byte IVs")
	}
	usedKeys, usedNonces := make(map[int]bool), make(map[int]bool)
	result := QilinResult{Heuristic: true}
	for stage := 3; stage >= 2; stage-- {
		found := false
		for ki, key := range keys {
			if usedKeys[ki] {
				continue
			}
			for ni, nonce := range nonces {
				if usedNonces[ni] {
					continue
				}
				candidate, err := decryptQilinStage(data, stage, key, nonce)
				if err != nil {
					continue
				}
				if hasEndBlock(candidate) {
					data = candidate
					usedKeys[ki] = true
					usedNonces[ni] = true
					result.KeyIndexes[stage-1], result.NonceIndexes[stage-1] = ki, ni
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return QilinResult{}, fmt.Errorf("no Qilin key/IV pair matched stage %d", stage)
		}
	}
	bestScore := -1e100
	var best []byte
	for ki, key := range keys {
		if usedKeys[ki] {
			continue
		}
		for ni, nonce := range nonces {
			if usedNonces[ni] {
				continue
			}
			candidate, err := decryptQilinStage(data, 1, key, nonce)
			if err != nil {
				continue
			}
			score := ScorePlaintext(candidate[:min(len(candidate), 128*1024)])
			if score > bestScore {
				bestScore, best = score, candidate
				result.KeyIndexes[0], result.NonceIndexes[0] = ki, ni
			}
		}
	}
	if best == nil {
		return QilinResult{}, errors.New("no Qilin stage-1 candidate was available")
	}
	result.Score = bestScore
	output, err := createPrivate(outputPath)
	if err != nil {
		return QilinResult{}, err
	}
	_, writeErr := output.Write(best)
	closeErr := output.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(outputPath)
		return QilinResult{}, err
	}
	return result, nil
}

func qilinRecoveryRecord(record prnlog.Record) (string, bool) {
	if record.Truncated || record.CapturedLength != record.RequestedLength {
		return "", false
	}
	if record.Source == "syscall" {
		if record.Operation != "read" || record.Syscall == nil ||
			record.Syscall.Name != "read" || record.Syscall.Path != "/dev/urandom" {
			return "", false
		}
		switch record.CapturedLength {
		case 16:
			return "iv", true
		case 32:
			return "key", true
		default:
			return "", false
		}
	}
	if record.Source != "lab" {
		return "", false
	}
	for stage := 1; stage <= 3; stage++ {
		if record.Operation == fmt.Sprintf("qilin.stage%d.iv", stage) && record.CapturedLength == 16 {
			return "iv", true
		}
		if record.Operation == fmt.Sprintf("qilin.stage%d.key", stage) && record.CapturedLength == 32 {
			return "key", true
		}
	}
	return "", false
}

func decryptQilinStage(data []byte, stage int, key, iv []byte) ([]byte, error) {
	previous, err := previousSize(len(data))
	if err != nil {
		return nil, err
	}
	result := append([]byte(nil), data[:previous]...)
	xorRange := func(offset, length int) error {
		if length <= 0 {
			return nil
		}
		cipher, err := chacha20legacy.New(key, iv)
		if err != nil {
			return err
		}
		end := min(offset+length, len(result))
		cipher.XORKeyStream(result[offset:end], result[offset:end])
		return nil
	}
	ranges, err := qilinlayout.Ranges(stage, previous)
	if err != nil {
		return nil, err
	}
	for _, value := range ranges {
		if err := xorRange(value.Offset, value.Length); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func previousSize(size int) (int, error) {
	return qilinlayout.PreviousSize(size)
}

func hasEndBlock(data []byte) bool {
	if len(data) < len(endBlock) {
		return false
	}
	start := max(0, len(data)-0x900)
	return bytes.Contains(data[start:], endBlock)
}
