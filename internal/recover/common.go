// SPDX-License-Identifier: GPL-2.0-only

package recover

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
)

func loadPRNs(paths []string) ([][]byte, error) {
	records, err := loadPRNRecords(paths)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var values [][]byte
	for _, record := range records {
		value, err := hex.DecodeString(record.ValueHex)
		if err != nil {
			return nil, err
		}
		key := string(value)
		if !seen[key] {
			seen[key] = true
			values = append(values, value)
		}
	}
	return values, nil
}

func loadPRNRecords(paths []string) ([]prnlog.Record, error) {
	return prnlog.ReadFiles(paths)
}

func createPrivate(path string) (*os.File, error) {
	if err := os.MkdirAll(filepathDir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func filepathDir(path string) string {
	for index := len(path) - 1; index >= 0; index-- {
		if path[index] == '/' {
			if index == 0 {
				return "/"
			}
			return path[:index]
		}
	}
	return "."
}

// ScorePlaintext applies the legacy-format recovery heuristic. It is not an
// authenticity check and callers must describe its result as heuristic.
func ScorePlaintext(value []byte) float64 {
	if len(value) == 0 {
		return math.Inf(-1)
	}
	score := -entropy(value)
	for _, magic := range [][]byte{[]byte("%PDF-"), []byte("PK\x03\x04"), []byte("\x7fELF"), []byte("SQLite format 3\x00")} {
		if bytes.HasPrefix(value, magic) {
			score += 20
		}
	}
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid(trimmed) {
		score += 20
	}
	if validShebang(value) {
		score += 20
	}
	printable := 0
	for _, b := range value {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b < 0x7f) {
			printable++
		}
	}
	score += 8 * float64(printable) / float64(len(value))
	return score
}

func validShebang(value []byte) bool {
	if !bytes.HasPrefix(value, []byte("#!/")) {
		return false
	}
	line := value
	if newline := bytes.IndexByte(line, '\n'); newline >= 0 {
		line = line[:newline]
	}
	if len(line) < 4 || len(line) > 256 {
		return false
	}
	for _, character := range line {
		if character < 0x20 || character >= 0x7f {
			return false
		}
	}
	return true
}

func entropy(value []byte) float64 {
	var counts [256]int
	for _, b := range value {
		counts[b]++
	}
	var result float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(len(value))
		result -= p * math.Log2(p)
	}
	return result
}

func requireRegular(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("input must be a regular non-symlink file")
	}
	return info, nil
}
