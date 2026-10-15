// SPDX-License-Identifier: GPL-2.0-only

package qilinlayout

import "testing"

func TestExpandedSizeRoundTripBoundaries(t *testing.T) {
	for _, size := range []int{1, 2, MaxStartCopy - 1, MaxStartCopy, MaxStartCopy + 1, Stage1Chunk - 1, Stage1Chunk, Stage1Chunk + 1} {
		expanded, err := ExpandedSize(size)
		if err != nil {
			t.Fatal(err)
		}
		previous, err := PreviousSize(expanded)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if previous != size {
			t.Fatalf("size %d round trip = %d", size, previous)
		}
	}
}

func TestStage2StripeBoundaries(t *testing.T) {
	for _, size := range []int{1, Stage2Chunk - 1, Stage2Chunk, Stage2Chunk + 1, 2*Stage2Chunk + 1} {
		ranges, err := Ranges(2, size)
		if err != nil {
			t.Fatal(err)
		}
		chunk, skip, _ := Parameters(2, size)
		for index, value := range ranges {
			if value.Offset < 0 || value.Length <= 0 || value.Offset+value.Length > size || value.Length > chunk {
				t.Fatalf("size %d has invalid range %#v", size, value)
			}
			if index > 0 && value.Offset != ranges[index-1].Offset+chunk+skip {
				t.Fatalf("size %d has wrong stripe step: %#v", size, ranges)
			}
		}
	}
}

func TestRejectsInvalidLayout(t *testing.T) {
	if _, err := Ranges(4, 1); err == nil {
		t.Fatal("invalid stage was accepted")
	}
	if _, err := ExpandedSize(0); err == nil {
		t.Fatal("empty plaintext was accepted")
	}
	if _, err := PreviousSize(0x208); err == nil {
		t.Fatal("non-invertible empty layout was accepted")
	}
}
