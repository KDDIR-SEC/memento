// SPDX-License-Identifier: GPL-2.0-only

package memory

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KDDIR-SEC/memento/internal/crypto/babukkdf"
	"github.com/KDDIR-SEC/memento/internal/crypto/sosemanuk"
	"github.com/KDDIR-SEC/memento/internal/prnlog"
	"github.com/KDDIR-SEC/memento/internal/recover"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/unix"
)

const (
	defaultIdentifyAlignment     = int64(8)
	defaultIdentifyEntropy       = 4.5
	defaultIdentifyMaxCandidates = 1_000_000
	identifyPreviewLimit         = 128 * 1024
)

type IdentifyBabukOptions struct {
	DumpDirectory string
	InputPath     string
	PRNLogs       []string
	OutputPath    string
	Alignment     int64
	Threshold     float64
	MaxCandidates int
}

type BabukIdentification struct {
	Schema             string    `json:"schema"`
	CreatedAt          time.Time `json:"created_at"`
	Heuristic          bool      `json:"heuristic"`
	PublicKeyHex       string    `json:"public_key_hex"`
	Score              float64   `json:"score"`
	RunnerUpScore      *float64  `json:"runner_up_score,omitempty"`
	ScoreMargin        *float64  `json:"score_margin,omitempty"`
	CandidateCount     int       `json:"candidate_count"`
	EvaluatedCount     int       `json:"evaluated_count"`
	PRNIndex           int       `json:"prn_index"`
	SelectedDumpFile   string    `json:"selected_dump_file"`
	SelectedDumpOffset int64     `json:"selected_dump_offset"`
	SelectedAddress    string    `json:"selected_address"`
}

type identifiedCandidate struct {
	key      [32]byte
	score    float64
	dumpFile string
	offset   int64
	address  uint64
}

func IdentifyBabuk(options IdentifyBabukOptions) (BabukIdentification, error) {
	if options.Alignment <= 0 {
		options.Alignment = defaultIdentifyAlignment
	}
	if options.Threshold <= 0 {
		options.Threshold = defaultIdentifyEntropy
	}
	if options.MaxCandidates <= 0 {
		options.MaxCandidates = defaultIdentifyMaxCandidates
	}
	if options.DumpDirectory == "" || options.InputPath == "" || options.OutputPath == "" || len(options.PRNLogs) == 0 {
		return BabukIdentification{}, errors.New("Babuk identification requires dump directory, input, PRN log, and output")
	}
	if options.Alignment != 8 {
		return BabukIdentification{}, errors.New("Babuk dump candidates must use 8-byte alignment")
	}
	if options.Threshold < 0 || options.Threshold > 5 {
		return BabukIdentification{}, errors.New("Babuk candidate entropy threshold must be between 0 and 5 bits/byte")
	}

	dumpInfo, err := os.Lstat(options.DumpDirectory)
	if err != nil {
		return BabukIdentification{}, err
	}
	if !dumpInfo.IsDir() || dumpInfo.Mode()&os.ModeSymlink != 0 {
		return BabukIdentification{}, errors.New("dump directory must be a real non-symlink directory")
	}

	input, inputInfo, err := openSingleLinkRegular(options.InputPath)
	if err != nil {
		return BabukIdentification{}, fmt.Errorf("open Babuk ciphertext: %w", err)
	}
	defer input.Close()
	if inputInfo.Size() <= 32 {
		return BabukIdentification{}, errors.New("Babuk ciphertext has no non-empty encrypted body")
	}
	previewLength := min(int64(identifyPreviewLimit), inputInfo.Size()-32)
	preview := make([]byte, previewLength)
	if _, err := input.ReadAt(preview, 0); err != nil {
		return BabukIdentification{}, fmt.Errorf("read Babuk preview: %w", err)
	}
	footer := make([]byte, 32)
	if _, err := input.ReadAt(footer, inputInfo.Size()-32); err != nil {
		return BabukIdentification{}, fmt.Errorf("read Babuk footer: %w", err)
	}
	rawPRN, prnIndex, err := uniqueFooterPRN(options.PRNLogs, footer)
	if err != nil {
		return BabukIdentification{}, err
	}
	defer clear(rawPRN)

	writable, err := writablePrivateMappings(options.DumpDirectory)
	if err != nil {
		return BabukIdentification{}, err
	}
	entries, err := os.ReadDir(options.DumpDirectory)
	if err != nil {
		return BabukIdentification{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	seen := make(map[[32]byte]struct{})
	var best, runner *identifiedCandidate
	evaluated := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".dump" {
			continue
		}
		base, err := parseDumpBase(entry.Name())
		if err != nil {
			return BabukIdentification{}, err
		}
		if !writable[base] {
			continue
		}
		path := filepath.Join(options.DumpDirectory, entry.Name())
		file, info, err := openSingleLinkRegular(path)
		if err != nil {
			return BabukIdentification{}, fmt.Errorf("open dump mapping %q: %w", entry.Name(), err)
		}
		if info.Size() > int64(^uint(0)>>1) {
			file.Close()
			return BabukIdentification{}, fmt.Errorf("dump mapping %q is too large", entry.Name())
		}
		if info.Size() < 32 {
			file.Close()
			continue
		}
		mapping, err := unix.Mmap(int(file.Fd()), 0, int(info.Size()), unix.PROT_READ, unix.MAP_PRIVATE)
		if err != nil {
			file.Close()
			return BabukIdentification{}, fmt.Errorf("map dump mapping %q: %w", entry.Name(), err)
		}
		for offset := int64(0); offset+32 <= int64(len(mapping)); offset += options.Alignment {
			var key [32]byte
			copy(key[:], mapping[offset:offset+32])
			if shannon(key[:]) < options.Threshold {
				continue
			}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			if len(seen) > options.MaxCandidates {
				unix.Munmap(mapping)
				file.Close()
				return BabukIdentification{}, fmt.Errorf("Babuk candidate limit exceeded: more than %d unique values", options.MaxCandidates)
			}
			material, err := babukkdf.Derive(rawPRN, key[:])
			if err != nil {
				continue
			}
			var plaintext bytes.Buffer
			_, transformErr := sosemanuk.XOR(material.Key[:], &plaintext, bytes.NewReader(preview), int64(len(preview)))
			clear(material.Key[:])
			if transformErr != nil {
				unix.Munmap(mapping)
				file.Close()
				return BabukIdentification{}, transformErr
			}
			evaluated++
			candidate := &identifiedCandidate{key: key, score: recover.ScorePlaintext(plaintext.Bytes()), dumpFile: entry.Name(), offset: offset, address: base + uint64(offset)}
			if betterCandidate(candidate, best) {
				runner = best
				best = candidate
			} else if betterCandidate(candidate, runner) {
				runner = candidate
			}
		}
		unmapErr := unix.Munmap(mapping)
		closeErr := file.Close()
		if err := errors.Join(unmapErr, closeErr); err != nil {
			return BabukIdentification{}, err
		}
	}
	if best == nil {
		return BabukIdentification{}, errors.New("no usable Babuk master-public-key candidates were found")
	}
	result := BabukIdentification{
		Schema:             "memento.babuk-key-identification/v1",
		CreatedAt:          time.Now().UTC(),
		Heuristic:          true,
		PublicKeyHex:       hex.EncodeToString(best.key[:]),
		Score:              best.score,
		CandidateCount:     len(seen),
		EvaluatedCount:     evaluated,
		PRNIndex:           prnIndex,
		SelectedDumpFile:   best.dumpFile,
		SelectedDumpOffset: best.offset,
		SelectedAddress:    fmt.Sprintf("0x%x", best.address),
	}
	if runner != nil {
		runnerScore := runner.score
		margin := best.score - runner.score
		result.RunnerUpScore = &runnerScore
		result.ScoreMargin = &margin
	}
	if err := writeIdentificationExclusive(options.OutputPath, result); err != nil {
		return BabukIdentification{}, err
	}
	return result, nil
}

func betterCandidate(left, right *identifiedCandidate) bool {
	if left == nil {
		return false
	}
	if right == nil || left.score != right.score {
		return right == nil || left.score > right.score
	}
	return bytes.Compare(left.key[:], right.key[:]) < 0
}

func writablePrivateMappings(directory string) (map[uint64]bool, error) {
	maps, _, err := openSingleLinkRegular(filepath.Join(directory, "maps.txt"))
	if err != nil {
		return nil, fmt.Errorf("open dump maps: %w", err)
	}
	defer maps.Close()
	data, err := io.ReadAll(io.LimitReader(maps, 16*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 16*1024*1024 {
		return nil, errors.New("dump maps file exceeds 16 MiB")
	}
	result := make(map[uint64]bool)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "rw-p" {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			return nil, fmt.Errorf("invalid dump map range %q", fields[0])
		}
		start, err := strconv.ParseUint(bounds[0], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid dump map start %q", bounds[0])
		}
		result[start] = true
	}
	if len(result) == 0 {
		return nil, errors.New("dump contains no writable private mappings")
	}
	return result, nil
}

func uniqueFooterPRN(paths []string, footer []byte) ([]byte, int, error) {
	seen := make(map[string]int)
	recordIndex := 0
	for _, path := range paths {
		file, _, err := openSingleLinkRegular(path)
		if err != nil {
			return nil, -1, fmt.Errorf("open PRN log %q: %w", path, err)
		}
		records, readErr := prnlog.Read(file)
		closeErr := file.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return nil, -1, err
		}
		for _, record := range records {
			value, err := hex.DecodeString(record.ValueHex)
			if err != nil {
				return nil, -1, err
			}
			if len(value) == 32 {
				private := append([]byte(nil), value...)
				private[0] &= 248
				private[31] &= 127
				private[31] |= 64
				public, err := curve25519.X25519(private, curve25519.Basepoint)
				clear(private)
				if err == nil && bytes.Equal(public, footer) {
					key := string(value)
					if _, exists := seen[key]; !exists {
						seen[key] = recordIndex
					}
				}
			}
			recordIndex++
		}
	}
	if len(seen) != 1 {
		return nil, -1, fmt.Errorf("Babuk footer matched %d distinct PRN values, want exactly one", len(seen))
	}
	for raw, index := range seen {
		return []byte(raw), index, nil
	}
	panic("unreachable")
}

func openSingleLinkRegular(path string) (*os.File, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || stat.Nlink != 1 {
		file.Close()
		return nil, nil, errors.New("file must be a single-link regular file")
	}
	return file, info, nil
}

func writeIdentificationExclusive(path string, value BabukIdentification) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	relative := strings.TrimPrefix(abs, string(filepath.Separator))
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Mode:  0o600,
		Resolve: unix.RESOLVE_BENEATH |
			unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return fmt.Errorf("create identification result: %w", err)
	}
	file := os.NewFile(uintptr(fd), abs)
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(value)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(abs)
		return err
	}
	return nil
}
