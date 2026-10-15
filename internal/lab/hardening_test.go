// SPDX-License-Identifier: GPL-2.0-only

package lab

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestValidationPRNStopRequiresAttestedRootlessBabuk(t *testing.T) {
	accepted := func() error { return nil }
	if err := validatePRNStop("babuk", 0, accepted); err != nil {
		t.Fatal(err)
	}
	if err := validatePRNStop("qilin", 0, accepted); err == nil {
		t.Fatal("Qilin validation stop was accepted")
	}
	if err := validatePRNStop("babuk", 1000, accepted); err == nil {
		t.Fatal("non-root process accepted the namespaced-root validation stop")
	}
	if err := validatePRNStop("babuk", 0, func() error { return errors.New("not isolated") }); err == nil {
		t.Fatal("unattested container accepted the validation stop")
	}
}

func TestPlanRejectsHardLinkAndSocket(t *testing.T) {
	for _, kind := range []string{"hardlink", "socket"} {
		t.Run(kind, func(t *testing.T) {
			manager := testManager(t)
			if _, err := manager.Init("safe", []string{".txt"}); err != nil {
				t.Fatal(err)
			}
			work := filepath.Join(manager.State.Lab, "safe", "work")
			switch kind {
			case "hardlink":
				original := filepath.Join(work, "original.txt")
				if err := os.WriteFile(original, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(original, filepath.Join(work, "linked.txt")); err != nil {
					t.Fatal(err)
				}
			case "socket":
				listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(work, "service.txt"), Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
			}
			if _, _, err := manager.Plan("safe", []string{".txt"}); err == nil {
				t.Fatalf("%s was accepted", kind)
			}
		})
	}
}

func TestMarkerAndManifestUseStrictJSON(t *testing.T) {
	manager := testManager(t)
	if _, err := manager.Init("safe", []string{".txt"}); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(manager.State.Lab, "safe", MarkerName)
	data, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = true
	data, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Plan("safe", []string{".txt"}); err == nil {
		t.Fatal("marker with an unknown field was accepted")
	}
}

func TestRemovedMarkerNameIsRejected(t *testing.T) {
	manager := testManager(t)
	if _, err := manager.Init("safe", []string{".memento"}); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(manager.State.Lab, "safe")
	removedMarker := "." + "ra" + "re-lab"
	if err := os.Rename(filepath.Join(root, MarkerName), filepath.Join(root, removedMarker)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Plan("safe", []string{".memento"}); err == nil {
		t.Fatal("removed marker name was accepted")
	}
}

func TestLoadManifestRejectsHardLink(t *testing.T) {
	manager := testManager(t)
	if _, err := manager.Init("safe", []string{".txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create("safe", "sample.txt"); err != nil {
		t.Fatal(err)
	}
	_, path, err := manager.Plan("safe", []string{".txt"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.LoadManifest("safe", path); err == nil {
		t.Fatal("hard-linked manifest was accepted")
	}
}

func TestLoadManifestAcceptsGeneratedAllowlistedManifest(t *testing.T) {
	manager := testManager(t)
	if _, err := manager.Init("safe", []string{".memento"}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreateCopies("safe", "sample.txt", ".memento", 1); err != nil {
		t.Fatal(err)
	}
	manifest, path, err := manager.Plan("safe", []string{".memento"})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := manager.LoadManifest("safe", path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Digest != manifest.Digest || len(loaded.Files) != 1 || loaded.Files[0].Extension != ".memento" {
		t.Fatalf("unexpected loaded manifest: %#v", loaded)
	}
	if err := manager.Revalidate("safe", loaded); err != nil {
		t.Fatal(err)
	}
}

func TestPlanSelectsOnlyLowercaseMementoFixture(t *testing.T) {
	manager := testManager(t)
	if _, err := manager.Init("safe", []string{".memento"}); err != nil {
		t.Fatal(err)
	}
	paths, err := manager.CreateCopies("safe", "sample.txt", ".memento", 1)
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Dir(paths[0])
	if err := os.WriteFile(filepath.Join(work, "not-a-target.other"), []byte("not selected"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, _, err := manager.Plan("safe", []string{".memento"})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.TotalFiles != 1 || len(manifest.Files) != 1 {
		t.Fatalf("manifest selected %d files, want exactly one: %#v", manifest.TotalFiles, manifest.Files)
	}
	if manifest.Files[0].Path != "fixture-0000.memento" || manifest.Files[0].Extension != ".memento" {
		t.Fatalf("unexpected target: %#v", manifest.Files[0])
	}
}

func TestVerifyOpenFileRejectsLateHardLink(t *testing.T) {
	manager := testManager(t)
	if _, err := manager.Init("safe", []string{".txt"}); err != nil {
		t.Fatal(err)
	}
	fixture, err := manager.Create("safe", "sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	manifest, _, err := manager.Plan("safe", []string{".txt"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(fixture, fixture+".late-link"); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := verifyOpenFile(file, manifest.Files[0]); err == nil {
		t.Fatal("late hard link was accepted immediately before transform")
	}
}

func TestManifestCannotExpandScenarioExtensionAllowlist(t *testing.T) {
	for _, operation := range []string{"load", "revalidate"} {
		t.Run(operation, func(t *testing.T) {
			manager := testManager(t)
			marker, err := manager.Init("safe", []string{".memento"})
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(manager.State.Lab, "safe")
			if err := os.WriteFile(filepath.Join(root, "work", "unapproved.txt"), []byte("not approved"), 0o600); err != nil {
				t.Fatal(err)
			}
			files, total, canonical, err := collect(filepath.Join(root, "work"), []string{".txt"})
			if err != nil {
				t.Fatal(err)
			}
			manifest := Manifest{
				Schema:             "memento.encryption-manifest/v1",
				Scenario:           "safe",
				ScenarioUUID:       marker.UUID,
				CanonicalRoot:      canonical,
				Extensions:         []string{".txt"},
				Files:              files,
				TotalFiles:         len(files),
				TotalBytes:         total,
				EncryptedOutputDir: filepath.Join(root, "encrypted"),
			}
			digest, err := manifestDigest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			manifest.Digest = digest

			switch operation {
			case "load":
				path := filepath.Join(root, "plans", "encryption-"+digest+".json")
				if err := writeJSONExclusive(path, manifest); err != nil {
					t.Fatal(err)
				}
				if _, err := manager.LoadManifest("safe", path); err == nil {
					t.Fatal("manifest expanded the scenario extension allowlist during load")
				}
			case "revalidate":
				if err := manager.Revalidate("safe", manifest); err == nil {
					t.Fatal("manifest expanded the scenario extension allowlist during revalidation")
				}
			}
		})
	}
}

func FuzzDecodeManifest(f *testing.F) {
	seed := Manifest{Schema: "memento.encryption-manifest/v1", Scenario: "safe", ScenarioUUID: "uuid"}
	encoded, _ := json.Marshal(seed)
	f.Add(encoded)
	f.Add([]byte(`{"schema":"memento.encryption-manifest/v1","unknown":true}`))
	f.Add([]byte("{}{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeManifest(bytes.NewReader(data))
	})
}
