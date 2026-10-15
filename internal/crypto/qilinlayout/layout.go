// SPDX-License-Identifier: GPL-2.0-only

// Package qilinlayout defines the legacy Qilin stage and footer layout.
package qilinlayout

import "fmt"

const (
	Stage1Chunk  = 0xA00000
	Stage2Chunk  = 0x1E00000
	MaxStartCopy = 0x400
	FooterSize   = 0x226
)

type Range struct {
	Offset int
	Length int
}

func Parameters(stage, size int) (chunk, skip int, err error) {
	if size < 0 {
		return 0, 0, fmt.Errorf("negative Qilin stage size")
	}
	switch stage {
	case 1:
		return min(size, Stage1Chunk), 0, nil
	case 2:
		return min(size, Stage2Chunk), ((size / 50) + 0xfff) &^ 0xfff, nil
	case 3:
		return size, 0, nil
	default:
		return 0, 0, fmt.Errorf("invalid Qilin stage %d", stage)
	}
}

func Ranges(stage, size int) ([]Range, error) {
	chunk, skip, err := Parameters(stage, size)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}
	if stage != 2 {
		return []Range{{Offset: 0, Length: chunk}}, nil
	}
	var ranges []Range
	for offset := 0; offset < size; offset += chunk + skip {
		ranges = append(ranges, Range{Offset: offset, Length: min(chunk, size-offset)})
	}
	return ranges, nil
}

func ExpandedSize(size int) (int, error) {
	if size <= 0 {
		return 0, fmt.Errorf("Qilin plaintext size must be positive")
	}
	return size + FooterSize + min(size, MaxStartCopy), nil
}

func PreviousSize(size int) (int, error) {
	if size < 0x208 {
		return 0, fmt.Errorf("Qilin ciphertext is too short")
	}
	threshold := MaxStartCopy + FooterSize + MaxStartCopy
	var previous int
	if size < threshold {
		previous = (size - FooterSize) / 2
	} else {
		previous = size - MaxStartCopy - FooterSize
	}
	if previous <= 0 || previous >= size {
		return 0, fmt.Errorf("invalid Qilin footer size")
	}
	expanded, err := ExpandedSize(previous)
	if err != nil || expanded != size {
		return 0, fmt.Errorf("inconsistent Qilin footer size")
	}
	return previous, nil
}
