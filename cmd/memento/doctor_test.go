// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDoctorParsingAndVDSOCheck(t *testing.T) {
	var output bytes.Buffer
	if err := runDoctor([]string{"vdso"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "vDSO getrandom") {
		t.Fatalf("unexpected doctor output: %q", output.String())
	}
	if err := runDoctor([]string{"unknown"}, &output); err == nil {
		t.Fatal("unknown doctor target was accepted")
	}
	if err := runDoctor([]string{"cpu", "extra"}, &output); err == nil {
		t.Fatal("doctor accepted an extra argument")
	}
}
