// SPDX-License-Identifier: GPL-2.0-only

package lab

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	rootlessContainerEnv = "MEMENTO_ROOTLESS_CONTAINER"
	hostUIDEnv           = "MEMENTO_HOST_UID"
	hostGIDEnv           = "MEMENTO_HOST_GID"
)

type rootlessContainerEvidence struct {
	Marker          string
	ExpectedHostUID uint64
	ExpectedHostGID uint64
	DockerMarker    bool
	UIDMap          string
	GIDMap          string
	Status          string
	Interfaces      []string
}

type idMapRange struct {
	inside  uint64
	outside uint64
	length  uint64
}

func validateCurrentRootlessContainer() error {
	expectedUID, err := parsePositiveID(os.Getenv(hostUIDEnv), hostUIDEnv)
	if err != nil {
		return err
	}
	expectedGID, err := parsePositiveID(os.Getenv(hostGIDEnv), hostGIDEnv)
	if err != nil {
		return err
	}
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return err
	}
	gidMap, err := os.ReadFile("/proc/self/gid_map")
	if err != nil {
		return err
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return err
	}
	interfaces := make([]string, 0, len(entries))
	for _, entry := range entries {
		interfaces = append(interfaces, entry.Name())
	}
	sort.Strings(interfaces)
	_, dockerErr := os.Stat("/.dockerenv")
	return validateRootlessContainerEvidence(rootlessContainerEvidence{
		Marker:          os.Getenv(rootlessContainerEnv),
		ExpectedHostUID: expectedUID,
		ExpectedHostGID: expectedGID,
		DockerMarker:    dockerErr == nil,
		UIDMap:          string(uidMap),
		GIDMap:          string(gidMap),
		Status:          string(status),
		Interfaces:      interfaces,
	})
}

func parsePositiveID(value, name string) (uint64, error) {
	id, err := strconv.ParseUint(value, 10, 32)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("%s must identify a non-root host user", name)
	}
	return id, nil
}

func validateRootlessContainerEvidence(evidence rootlessContainerEvidence) error {
	if evidence.Marker != "1" {
		return errors.New("rootless container marker is absent")
	}
	if !evidence.DockerMarker {
		return errors.New("Docker container marker is absent")
	}
	if err := validateIDMap(evidence.UIDMap, evidence.ExpectedHostUID, "UID"); err != nil {
		return err
	}
	if err := validateIDMap(evidence.GIDMap, evidence.ExpectedHostGID, "GID"); err != nil {
		return err
	}
	status := parseStatus(evidence.Status)
	if status["CapEff"] != "0000000000000000" {
		return errors.New("effective capabilities are not empty")
	}
	if status["NoNewPrivs"] != "1" {
		return errors.New("no-new-privileges is not active")
	}
	if status["Seccomp"] != "2" {
		return errors.New("seccomp filter is not active")
	}
	if len(evidence.Interfaces) != 1 || evidence.Interfaces[0] != "lo" {
		return fmt.Errorf("container network is not isolated: interfaces=%v", evidence.Interfaces)
	}
	return nil
}

func validateIDMap(contents string, expectedHostID uint64, name string) error {
	ranges, err := parseIDMap(contents)
	if err != nil {
		return fmt.Errorf("invalid %s map: %w", name, err)
	}
	rootMappings := 0
	for _, item := range ranges {
		if item.outside == 0 {
			return fmt.Errorf("%s map reaches host ID 0", name)
		}
		if item.inside == 0 {
			rootMappings++
			if item.length != 1 || item.outside != expectedHostID {
				return fmt.Errorf("container %s 0 is not singly mapped to expected host ID", name)
			}
		}
	}
	if rootMappings != 1 {
		return fmt.Errorf("container %s 0 must have exactly one mapping", name)
	}
	return nil
}

func parseIDMap(contents string) ([]idMapRange, error) {
	var ranges []idMapRange
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 {
			return nil, fmt.Errorf("expected three fields in %q", scanner.Text())
		}
		values := make([]uint64, 3)
		for index, field := range fields {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return nil, err
			}
			values[index] = value
		}
		if values[2] == 0 {
			return nil, errors.New("zero-length mapping")
		}
		ranges = append(ranges, idMapRange{inside: values[0], outside: values[1], length: values[2]})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(ranges) == 0 {
		return nil, errors.New("empty mapping")
	}
	return ranges, nil
}

func parseStatus(contents string) map[string]string {
	status := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if found {
			status[key] = strings.TrimSpace(value)
		}
	}
	return status
}
