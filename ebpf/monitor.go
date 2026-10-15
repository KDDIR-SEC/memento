// SPDX-License-Identifier: GPL-2.0-only

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const captureLimit = 128

type readEvent struct {
	Type      int32
	PID       uint32
	TGID      uint32
	Comm      [16]byte
	FD        int32
	Count     uint64
	Basename  [128]byte
	BytesRead int64
	Buffer    [captureLimit]byte
}

type getrandomEvent struct {
	Type      int32
	PID       uint32
	TGID      uint32
	Flags     uint32
	Comm      [16]byte
	Length    uint64
	BytesRead int64
	Buffer    [captureLimit]byte
}

type Stats struct {
	Schema      string    `json:"schema"`
	Time        time.Time `json:"time"`
	ReadEvents  uint64    `json:"read_events"`
	Getrandom   uint64    `json:"getrandom_events"`
	LostSamples uint64    `json:"lost_samples"`
	Truncated   uint64    `json:"truncated_events"`
	Excluded    uint64    `json:"excluded_events"`
	PIDFiltered uint64    `json:"pid_filtered_events"`
}

type DumpTrigger func(prnlog.Record) error

type RunOptions struct {
	TargetPID uint32
	Trigger   DumpTrigger
	Excluded  map[string]struct{}
}

func Run(ctx context.Context, outputPath, statsPath string, options RunOptions) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	writer, err := prnlog.NewWriter(outputPath)
	if err != nil {
		return err
	}
	defer writer.Close()
	var stats Stats
	stats.Schema = "memento.syscall-stats/v1"
	stats.Time = time.Now().UTC()
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errCh <- runRead(ctx, writer, &stats, options); cancel() }()
	go func() { defer wg.Done(); errCh <- runGetrandom(ctx, writer, &stats, options); cancel() }()
	wg.Wait()
	close(errCh)
	var runErr error
	for err := range errCh {
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, perf.ErrClosed) {
			runErr = errors.Join(runErr, err)
		}
	}
	stats.ReadEvents = atomic.LoadUint64(&stats.ReadEvents)
	stats.Getrandom = atomic.LoadUint64(&stats.Getrandom)
	stats.LostSamples = atomic.LoadUint64(&stats.LostSamples)
	stats.Truncated = atomic.LoadUint64(&stats.Truncated)
	stats.Excluded = atomic.LoadUint64(&stats.Excluded)
	stats.PIDFiltered = atomic.LoadUint64(&stats.PIDFiltered)
	if err := writeStats(statsPath, stats); err != nil {
		runErr = errors.Join(runErr, err)
	}
	if stats.LostSamples > 0 {
		slog.Warn("eBPF perf buffer lost samples", "count", stats.LostSamples)
	}
	return runErr
}

func runRead(ctx context.Context, writer *prnlog.Writer, stats *Stats, options RunOptions) error {
	objects := readObjects{}
	if err := loadReadObjects(&objects, nil); err != nil {
		return fmt.Errorf("load read eBPF objects: %w", err)
	}
	defer objects.Close()
	entry, err := link.Tracepoint("syscalls", "sys_enter_read", objects.HandleSysEnterRead, nil)
	if err != nil {
		return err
	}
	defer entry.Close()
	exit, err := link.Tracepoint("syscalls", "sys_exit_read", objects.HandleSysExitRead, nil)
	if err != nil {
		return err
	}
	defer exit.Close()
	reader, err := perf.NewReader(objects.Events, 64*os.Getpagesize())
	if err != nil {
		return err
	}
	defer reader.Close()
	go closeOnContext(ctx, reader)
	for {
		record, err := reader.Read()
		if err != nil {
			return err
		}
		if record.LostSamples != 0 {
			atomic.AddUint64(&stats.LostSamples, record.LostSamples)
			continue
		}
		var event readEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return err
		}
		converted, err := convertRead(event)
		if err != nil {
			return err
		}
		if isPIDFiltered(converted, options.TargetPID) {
			atomic.AddUint64(&stats.PIDFiltered, 1)
			continue
		}
		if isExcluded(converted.Process.Command, options.Excluded) {
			atomic.AddUint64(&stats.Excluded, 1)
			continue
		}
		if converted.Truncated {
			atomic.AddUint64(&stats.Truncated, 1)
		}
		if err := writer.Write(converted); err != nil {
			return err
		}
		atomic.AddUint64(&stats.ReadEvents, 1)
		if options.Trigger != nil {
			if err := options.Trigger(converted); err != nil {
				return fmt.Errorf("memory dump trigger for PID %d: %w", event.TGID, err)
			}
		}
	}
}

func runGetrandom(ctx context.Context, writer *prnlog.Writer, stats *Stats, options RunOptions) error {
	objects := getrandomObjects{}
	if err := loadGetrandomObjects(&objects, nil); err != nil {
		return fmt.Errorf("load getrandom eBPF objects: %w", err)
	}
	defer objects.Close()
	entry, err := link.Tracepoint("syscalls", "sys_enter_getrandom", objects.HandleSysEnterGetrandom, nil)
	if err != nil {
		return err
	}
	defer entry.Close()
	exit, err := link.Tracepoint("syscalls", "sys_exit_getrandom", objects.HandleSysExitGetrandom, nil)
	if err != nil {
		return err
	}
	defer exit.Close()
	reader, err := perf.NewReader(objects.Events, 64*os.Getpagesize())
	if err != nil {
		return err
	}
	defer reader.Close()
	go closeOnContext(ctx, reader)
	for {
		record, err := reader.Read()
		if err != nil {
			return err
		}
		if record.LostSamples != 0 {
			atomic.AddUint64(&stats.LostSamples, record.LostSamples)
			continue
		}
		var event getrandomEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return err
		}
		converted, err := convertGetrandom(event)
		if err != nil {
			return err
		}
		if isPIDFiltered(converted, options.TargetPID) {
			atomic.AddUint64(&stats.PIDFiltered, 1)
			continue
		}
		if isExcluded(converted.Process.Command, options.Excluded) {
			atomic.AddUint64(&stats.Excluded, 1)
			continue
		}
		if converted.Truncated {
			atomic.AddUint64(&stats.Truncated, 1)
		}
		if err := writer.Write(converted); err != nil {
			return err
		}
		atomic.AddUint64(&stats.Getrandom, 1)
		if options.Trigger != nil {
			if err := options.Trigger(converted); err != nil {
				return fmt.Errorf("memory dump trigger for PID %d: %w", event.TGID, err)
			}
		}
	}
}

func convertRead(event readEvent) (prnlog.Record, error) {
	if event.BytesRead <= 0 {
		return prnlog.Record{}, errors.New("read event has no bytes")
	}
	if event.Count > uint64(^uint(0)>>1) || event.BytesRead > int64(^uint(0)>>1) {
		return prnlog.Record{}, errors.New("read event length overflows int")
	}
	captured := min(int(event.BytesRead), captureLimit)
	requested := max(int(event.Count), int(event.BytesRead))
	return prnlog.Record{Schema: prnlog.Schema, Time: time.Now().UTC(), Source: "syscall", Operation: "read", ValueHex: hex.EncodeToString(event.Buffer[:captured]), CapturedLength: captured, RequestedLength: requested, Truncated: int(event.BytesRead) > captureLimit, Process: &prnlog.ProcessMeta{PID: event.TGID, TID: event.PID, Command: cString(event.Comm[:])}, Syscall: &prnlog.SyscallMeta{Name: "read", FD: event.FD, Path: "/dev/" + cString(event.Basename[:])}}, nil
}

func convertGetrandom(event getrandomEvent) (prnlog.Record, error) {
	if event.BytesRead <= 0 {
		return prnlog.Record{}, errors.New("getrandom event has no bytes")
	}
	if event.Length > uint64(^uint(0)>>1) || event.BytesRead > int64(^uint(0)>>1) {
		return prnlog.Record{}, errors.New("getrandom event length overflows int")
	}
	captured := min(int(event.BytesRead), captureLimit)
	requested := max(int(event.Length), int(event.BytesRead))
	return prnlog.Record{Schema: prnlog.Schema, Time: time.Now().UTC(), Source: "syscall", Operation: "getrandom", ValueHex: hex.EncodeToString(event.Buffer[:captured]), CapturedLength: captured, RequestedLength: requested, Truncated: int(event.BytesRead) > captureLimit, Process: &prnlog.ProcessMeta{PID: event.TGID, TID: event.PID, Command: cString(event.Comm[:])}, Syscall: &prnlog.SyscallMeta{Name: "getrandom", Flags: event.Flags}}, nil
}

func cString(value []byte) string {
	if index := bytes.IndexByte(value, 0); index >= 0 {
		value = value[:index]
	}
	return strings.ToValidUTF8(string(value), "?")
}

func isExcluded(command string, excluded map[string]struct{}) bool {
	_, found := excluded[command]
	return found
}

func isPIDFiltered(record prnlog.Record, target uint32) bool {
	return target != 0 && (record.Process == nil || record.Process.PID != target)
}

type perfCloser interface{ Close() error }

func closeOnContext(ctx context.Context, closer perfCloser) { <-ctx.Done(); _ = closer.Close() }

func writeStats(path string, stats Stats) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	writeErr := json.NewEncoder(f).Encode(stats)
	return errors.Join(writeErr, f.Close())
}

var _ *cebpf.Map
