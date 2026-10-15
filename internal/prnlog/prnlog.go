// SPDX-License-Identifier: GPL-2.0-only

package prnlog

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const Schema = "memento.prn/v1"

type ProcessMeta struct {
	PID     uint32 `json:"pid,omitempty"`
	TID     uint32 `json:"tid,omitempty"`
	Command string `json:"command,omitempty"`
}

type SyscallMeta struct {
	Name  string `json:"name"`
	FD    int32  `json:"fd,omitempty"`
	Flags uint32 `json:"flags,omitempty"`
	Path  string `json:"path,omitempty"`
}

type VMMeta struct {
	Sequence          uint64 `json:"sequence"`
	KtimeNS           uint64 `json:"ktime_ns"`
	VMID              uint32 `json:"vm_id"`
	VCPUID            uint32 `json:"vcpu_id"`
	GuestRIP          uint64 `json:"guest_rip"`
	GuestCR3          uint64 `json:"guest_cr3"`
	GuestRFLAGSBefore uint64 `json:"guest_rflags_before"`
	GuestRFLAGSAfter  uint64 `json:"guest_rflags_after"`
	OperandBit        uint8  `json:"operand_bits"`
	DestReg           uint8  `json:"destination_register"`
	Success           bool   `json:"success"`
	HostCPU           uint32 `json:"host_cpu"`
}

type Record struct {
	Schema          string       `json:"schema"`
	Time            time.Time    `json:"time"`
	Source          string       `json:"source"`
	Operation       string       `json:"operation"`
	ValueHex        string       `json:"value_hex"`
	CapturedLength  int          `json:"captured_length"`
	RequestedLength int          `json:"requested_length"`
	Truncated       bool         `json:"truncated"`
	Process         *ProcessMeta `json:"process,omitempty"`
	Syscall         *SyscallMeta `json:"syscall,omitempty"`
	VM              *VMMeta      `json:"vm,omitempty"`
}

func (r *Record) Normalize() error {
	if r.Schema == "" {
		r.Schema = Schema
	}
	if r.Schema != Schema {
		return fmt.Errorf("unsupported PRN schema %q", r.Schema)
	}
	r.ValueHex = strings.ToLower(strings.TrimSpace(r.ValueHex))
	value, err := hex.DecodeString(r.ValueHex)
	if err != nil {
		return fmt.Errorf("invalid PRN hex: %w", err)
	}
	if r.CapturedLength == 0 && len(value) != 0 {
		r.CapturedLength = len(value)
	}
	if r.CapturedLength != len(value) {
		return fmt.Errorf("captured_length=%d does not match %d decoded bytes", r.CapturedLength, len(value))
	}
	if r.RequestedLength < r.CapturedLength {
		return fmt.Errorf("requested_length=%d is smaller than captured_length=%d", r.RequestedLength, r.CapturedLength)
	}
	r.Truncated = r.Truncated || r.RequestedLength > r.CapturedLength
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	return nil
}

type Writer struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer
}

func NewWriter(path string) (*Writer, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	relative := strings.TrimPrefix(abs, string(filepath.Separator))
	if relative == "" {
		return nil, errors.New("PRN log path must name a file")
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root for PRN log: %w", err)
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags: unix.O_CREAT | unix.O_APPEND | unix.O_WRONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Mode:  0o600,
		Resolve: unix.RESOLVE_BENEATH |
			unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("secure-open PRN log: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("inspect PRN log: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		unix.Close(fd)
		return nil, errors.New("PRN log must be a single-link regular file")
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("secure PRN log permissions: %w", err)
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("configure PRN log descriptor: %w", err)
	}
	f := os.NewFile(uintptr(fd), abs)
	return &Writer{f: f, w: bufio.NewWriter(f)}, nil
}

func (w *Writer) Write(r Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := r.Normalize(); err != nil {
		return err
	}
	if err := json.NewEncoder(w.w).Encode(r); err != nil {
		return err
	}
	return w.w.Flush()
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	flushErr := w.w.Flush()
	closeErr := w.f.Close()
	return errors.Join(flushErr, closeErr)
}

func DecodeLine(line []byte) (Record, error) {
	var probe struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return Record{}, err
	}
	if probe.Schema == "" {
		return Record{}, errors.New("PRN record is missing a schema")
	}
	var r Record
	if err := json.Unmarshal(line, &r); err != nil {
		return Record{}, err
	}
	if err := r.Normalize(); err != nil {
		return Record{}, err
	}
	return r, nil
}

func Read(r io.Reader) ([]Record, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var records []Record
	line := 0
	for scanner.Scan() {
		line++
		if len(strings.TrimSpace(scanner.Text())) == 0 {
			continue
		}
		record, err := DecodeLine(scanner.Bytes())
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func ReadFiles(paths []string) ([]Record, error) {
	var all []Record
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		records, readErr := Read(f)
		closeErr := f.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return nil, fmt.Errorf("read %q: %w", path, err)
		}
		all = append(all, records...)
	}
	return all, nil
}

func Values(records []Record) ([][]byte, error) {
	values := make([][]byte, 0, len(records))
	for _, record := range records {
		value, err := hex.DecodeString(record.ValueHex)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}
