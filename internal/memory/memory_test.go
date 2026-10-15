// SPDX-License-Identifier: GPL-2.0-only

package memory

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

var dumpFixture = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

func TestFindBabukCandidates(t *testing.T) {
	root := t.TempDir()
	data := make([]byte, 64)
	copy(data[16:], dumpFixture)
	if err := os.WriteFile(filepath.Join(root, "0000000000001000.dump"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	candidates, err := FindBabukCandidates(root, "", 8, 4.9, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(dumpFixture)
	for _, candidate := range candidates {
		if candidate.ValueHex == want && candidate.Address == "0x1010" {
			return
		}
	}
	t.Fatalf("known candidate not found: %#v", candidates)
}

func TestDumpHelperProcess(t *testing.T) {
	if os.Getenv("MEMENTO_DUMP_HELPER") != "1" {
		t.Skip("helper process")
	}
	mapping, err := unix.Mmap(-1, 0, unix.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mapping)
	copy(mapping, dumpFixture)
	fmt.Printf("%d %x\n", os.Getpid(), uintptr(unsafe.Pointer(&mapping[0])))
	_, _ = io.Copy(io.Discard, os.Stdin)
	runtime.KeepAlive(mapping)
}

func TestDumpAndFindChildMemory(t *testing.T) {
	if os.Getenv("MEMENTO_RUN_PTRACE_TEST") != "1" {
		t.Skip("set MEMENTO_RUN_PTRACE_TEST=1 for the parent-child ptrace integration test")
	}
	command := exec.Command(os.Args[0], "-test.run=^TestDumpHelperProcess$")
	command.Env = append(os.Environ(), "MEMENTO_DUMP_HELPER=1")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		_ = command.Wait()
	}()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(line)
	if len(fields) != 2 {
		t.Fatalf("unexpected helper line %q", line)
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	address, err := strconv.ParseUint(fields[1], 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := Dump(DumpOptions{PID: pid, Root: t.TempDir(), MaxTotalByte: 1024 * 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := FindBabukCandidates(directory, "", 8, 4.9, 100000)
	if err != nil {
		t.Fatal(err)
	}
	wantValue := hex.EncodeToString(dumpFixture)
	wantAddress := fmt.Sprintf("0x%x", address)
	for _, candidate := range candidates {
		if candidate.ValueHex == wantValue && candidate.Address == wantAddress {
			return
		}
	}
	t.Fatalf("dumped child key not found at %s", wantAddress)
}
