// SPDX-License-Identifier: GPL-2.0-only

package memory

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Section struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
	Perms string `json:"permissions"`
	Path  string `json:"path,omitempty"`
}

type DumpOptions struct {
	PID          int
	Root         string
	MaxTotalByte int64
}

func Dump(options DumpOptions) (string, error) {
	if options.PID <= 0 {
		return "", errors.New("PID must be positive")
	}
	if options.MaxTotalByte <= 0 {
		options.MaxTotalByte = 512 * 1024 * 1024
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tids, err := enumerateTIDs(options.PID)
	if err != nil {
		return "", err
	}
	attached, err := attachAll(tids)
	if err != nil {
		return "", err
	}
	defer detachAll(attached)

	sections, maps, err := readMaps(options.PID)
	if err != nil {
		return "", err
	}
	dumpRoot := filepath.Join(options.Root, strconv.Itoa(options.PID))
	if err := os.MkdirAll(dumpRoot, 0o700); err != nil {
		return "", err
	}
	directory := filepath.Join(dumpRoot, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.Mkdir(directory, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(directory, "maps.txt"), maps, 0o600); err != nil {
		return "", err
	}
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", options.PID))
	if err != nil {
		return "", fmt.Errorf("open process memory: %w", err)
	}
	defer mem.Close()
	var dumped int64
	for _, section := range sections {
		size := int64(section.End - section.Start)
		if size <= 0 || dumped+size > options.MaxTotalByte {
			slog.Warn("skipping memory section because dump limit would be exceeded", "start", fmt.Sprintf("%x", section.Start), "bytes", size)
			continue
		}
		path := filepath.Join(directory, fmt.Sprintf("%016x.dump", section.Start))
		if err := dumpSection(mem, path, section); err != nil {
			slog.Warn("memory section dump failed", "start", fmt.Sprintf("%x", section.Start), "error", err)
			continue
		}
		dumped += size
	}
	if dumped == 0 {
		return "", errors.New("no readable process sections were dumped")
	}
	return directory, nil
}

func enumerateTIDs(pid int) ([]int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, err
	}
	var tids []int
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err == nil {
			tids = append(tids, tid)
		}
	}
	sort.Ints(tids)
	return tids, nil
}

func attachAll(tids []int) ([]int, error) {
	var attached []int
	for _, tid := range tids {
		if err := syscall.PtraceAttach(tid); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				continue
			}
			detachAll(attached)
			return nil, fmt.Errorf("ptrace attach TID %d: %w", tid, err)
		}
		attached = append(attached, tid)
	}
	if len(attached) == 0 {
		return nil, errors.New("could not attach to any process thread")
	}
	for _, tid := range attached {
		deadline := time.Now().Add(3 * time.Second)
		for {
			var status syscall.WaitStatus
			waited, err := syscall.Wait4(tid, &status, syscall.WNOHANG, nil)
			if err != nil {
				detachAll(attached)
				return attached, err
			}
			if waited == tid {
				break
			}
			if time.Now().After(deadline) {
				detachAll(attached)
				return attached, fmt.Errorf("timeout waiting for TID %d to stop", tid)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	return attached, nil
}

func detachAll(tids []int) {
	for _, tid := range tids {
		if err := syscall.PtraceDetach(tid); err != nil && !errors.Is(err, syscall.ESRCH) {
			slog.Warn("ptrace detach failed", "tid", tid, "error", err)
		}
	}
}

func readMaps(pid int) ([]Section, []byte, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, nil, err
	}
	var sections []Section
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || len(fields[1]) < 1 || fields[1][0] != 'r' {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(bounds[0], 16, 64)
		end, err2 := strconv.ParseUint(bounds[1], 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}
		path := ""
		if len(fields) > 5 {
			path = strings.Join(fields[5:], " ")
		}
		if strings.HasPrefix(path, "/usr/lib/") || strings.HasPrefix(path, "/lib/") {
			continue
		}
		sections = append(sections, Section{Start: start, End: end, Perms: fields[1], Path: path})
	}
	return sections, data, scanner.Err()
}

func dumpSection(mem *os.File, path string, section Section) error {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	const pageSize = 4096
	page := make([]byte, pageSize)
	zero := make([]byte, pageSize)
	for address := section.Start; address < section.End; address += pageSize {
		n := int(min(uint64(pageSize), section.End-address))
		read, readErr := mem.ReadAt(page[:n], int64(address))
		if read < n {
			copy(page[read:n], zero[:n-read])
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, syscall.EIO) {
			return readErr
		}
		if _, err := out.Write(page[:n]); err != nil {
			return err
		}
	}
	return nil
}
