// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSosemanukLicense = `SOSEMANUK reference implementation

(c) 2005 X-CRYPT project.

This software is provided 'as-is', without any express or implied warranty.
In no event will the authors be held liable for any damages arising from the
use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to no restriction.
`

const testSosemanukSource = `/* SPDX-License-Identifier: LicenseRef-X-CRYPT-Sosemanuk */
/*
 * (c) 2005 X-CRYPT project.
 * Permission is granted to anyone to use this software for any purpose,
 */
`

func TestInspectSosemanukLicense(t *testing.T) {
	dir := t.TempDir()
	licensePath := filepath.Join(dir, "LICENSE")
	sourcePath := filepath.Join(dir, "sosemanuk.c")
	writeTestFile(t, licensePath, testSosemanukLicense)
	writeTestFile(t, sourcePath, testSosemanukSource)

	if err := inspectSosemanukLicense(licensePath, []string{sourcePath}); err != nil {
		t.Fatalf("valid Sosemanuk license rejected: %v", err)
	}
	if err := inspectSosemanukLicense(filepath.Join(dir, "missing"), []string{sourcePath}); err == nil {
		t.Fatal("missing Sosemanuk license accepted")
	}

	writeTestFile(t, sourcePath, strings.ReplaceAll(testSosemanukSource, "LicenseRef-X-CRYPT-Sosemanuk", "GPL-2.0-only"))
	if err := inspectSosemanukLicense(licensePath, []string{sourcePath}); err == nil {
		t.Fatal("incorrect Sosemanuk LicenseRef accepted")
	}
}

func TestInspectContainerBase(t *testing.T) {
	dir := t.TempDir()
	dockerfile := filepath.Join(dir, "Dockerfile")
	writeTestFile(t, dockerfile, "FROM "+ubuntuRuntimeImage+"\n")
	if err := inspectContainerBase(dockerfile); err != nil {
		t.Fatalf("pinned container base rejected: %v", err)
	}

	writeTestFile(t, dockerfile, "FROM ubuntu:24.04\n")
	if err := inspectContainerBase(dockerfile); err == nil {
		t.Fatal("unpinned container base accepted")
	}
}

func TestForbiddenDependencyMarker(t *testing.T) {
	for _, marker := range forbiddenDependencies {
		if got := forbiddenDependencyMarker([]byte("prefix " + marker + " suffix")); got != marker {
			t.Errorf("marker %q: got %q", marker, got)
		}
	}
	if got := forbiddenDependencyMarker([]byte("safe dependency")); got != "" {
		t.Fatalf("safe input returned marker %q", got)
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
