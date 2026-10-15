// SPDX-License-Identifier: GPL-2.0-only

package lab

import (
	"strings"
	"testing"
)

func validRootlessEvidence() rootlessContainerEvidence {
	return rootlessContainerEvidence{
		Marker:          "1",
		ExpectedHostUID: 1000,
		ExpectedHostGID: 1000,
		DockerMarker:    true,
		UIDMap:          "0 1000 1\n1 100000 65536\n",
		GIDMap:          "0 1000 1\n1 100000 65536\n",
		Status:          "CapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n",
		Interfaces:      []string{"lo"},
	}
}

func TestValidateRootlessContainerEvidence(t *testing.T) {
	if err := validateRootlessContainerEvidence(validRootlessEvidence()); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*rootlessContainerEvidence)
		want   string
	}{
		{"marker", func(e *rootlessContainerEvidence) { e.Marker = "" }, "marker"},
		{"docker marker", func(e *rootlessContainerEvidence) { e.DockerMarker = false }, "Docker"},
		{"host root UID", func(e *rootlessContainerEvidence) { e.UIDMap = "0 0 4294967295\n" }, "host ID 0"},
		{"host root GID", func(e *rootlessContainerEvidence) { e.GIDMap = "0 0 4294967295\n" }, "host ID 0"},
		{"wrong UID", func(e *rootlessContainerEvidence) { e.UIDMap = "0 1001 1\n1 100000 65536\n" }, "expected host ID"},
		{"wide root map", func(e *rootlessContainerEvidence) { e.UIDMap = "0 1000 2\n" }, "singly mapped"},
		{"capability", func(e *rootlessContainerEvidence) {
			e.Status = strings.Replace(e.Status, "0000000000000000", "0000000000000001", 1)
		}, "capabilities"},
		{"no new privileges", func(e *rootlessContainerEvidence) {
			e.Status = strings.Replace(e.Status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1)
		}, "no-new-privileges"},
		{"seccomp", func(e *rootlessContainerEvidence) {
			e.Status = strings.Replace(e.Status, "Seccomp:\t2", "Seccomp:\t0", 1)
		}, "seccomp"},
		{"network", func(e *rootlessContainerEvidence) { e.Interfaces = []string{"eth0", "lo"} }, "not isolated"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := validRootlessEvidence()
			test.mutate(&evidence)
			err := validateRootlessContainerEvidence(evidence)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestParsePositiveID(t *testing.T) {
	for _, value := range []string{"", "0", "-1", "not-an-id"} {
		if _, err := parsePositiveID(value, "ID"); err == nil {
			t.Fatalf("accepted invalid ID %q", value)
		}
	}
	if value, err := parsePositiveID("1000", "ID"); err != nil || value != 1000 {
		t.Fatalf("value=%d error=%v", value, err)
	}
}
