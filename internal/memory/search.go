// SPDX-License-Identifier: GPL-2.0-only

package memory

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Candidate struct {
	DumpFile string  `json:"dump_file"`
	Offset   int64   `json:"offset"`
	Address  string  `json:"address"`
	ValueHex string  `json:"value_hex"`
	Entropy  float64 `json:"entropy"`
}

func FindBabukCandidates(dumpDirectory, outputPath string, alignment int64, threshold float64, maximum int) ([]Candidate, error) {
	if alignment <= 0 {
		alignment = 8
	}
	if threshold <= 0 {
		threshold = 4.5
	}
	if maximum <= 0 {
		maximum = 10000
	}
	entries, err := os.ReadDir(dumpDirectory)
	if err != nil {
		return nil, err
	}
	var candidates []Candidate
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".dump" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dumpDirectory, entry.Name()))
		if err != nil {
			return nil, err
		}
		base, err := parseDumpBase(entry.Name())
		if err != nil {
			return nil, err
		}
		for offset := int64(0); offset+32 <= int64(len(data)); offset += alignment {
			value := data[offset : offset+32]
			entropy := shannon(value)
			if entropy < threshold {
				continue
			}
			candidates = append(candidates, Candidate{DumpFile: entry.Name(), Offset: offset, Address: fmt.Sprintf("0x%x", base+uint64(offset)), ValueHex: hex.EncodeToString(value), Entropy: entropy})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Entropy == candidates[j].Entropy {
			return candidates[i].Address < candidates[j].Address
		}
		return candidates[i].Entropy > candidates[j].Entropy
	})
	if len(candidates) > maximum {
		candidates = candidates[:maximum]
	}
	if outputPath != "" {
		f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		encoder := json.NewEncoder(f)
		encoder.SetIndent("", "  ")
		writeErr := encoder.Encode(struct {
			Schema     string      `json:"schema"`
			Candidates []Candidate `json:"candidates"`
		}{Schema: "memento.babuk-key-candidates/v1", Candidates: candidates})
		closeErr := f.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	return candidates, nil
}

func parseDumpBase(name string) (uint64, error) {
	var value uint64
	_, err := fmt.Sscanf(strings.TrimSuffix(name, ".dump"), "%x", &value)
	return value, err
}

func shannon(value []byte) float64 {
	var counts [256]int
	for _, b := range value {
		counts[b]++
	}
	var result float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		probability := float64(count) / float64(len(value))
		result -= probability * math.Log2(probability)
	}
	return result
}
