// SPDX-License-Identifier: GPL-2.0-only

package cpumon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
)

const (
	DefaultBufferPath = "/sys/kernel/debug/kvm_rndlog/buffer"
	DefaultStatsPath  = "/sys/kernel/debug/kvm_rndlog/stats"
)

type Stats struct {
	Schema       string            `json:"schema"`
	Time         time.Time         `json:"time"`
	Records      uint64            `json:"records_written"`
	DropCount    uint64            `json:"drop_count"`
	KernelValues map[string]uint64 `json:"kernel,omitempty"`
	KernelStart  map[string]uint64 `json:"kernel_start,omitempty"`
}

func Monitor(ctx context.Context, bufferPath, outputPath, statsPath, statsOutput string) error {
	startValues, err := ReadKernelStats(statsPath)
	if err != nil {
		return fmt.Errorf("read initial KVM statistics: %w", err)
	}
	buffer, err := os.Open(bufferPath)
	if err != nil {
		return fmt.Errorf("open KVM debugfs buffer: %w", err)
	}
	defer buffer.Close()
	writer, err := prnlog.NewWriter(outputPath)
	if err != nil {
		return err
	}
	defer writer.Close()
	var written uint64
	errCh := make(chan error, 1)
	go func() {
		errCh <- ReadPolling(ctx, buffer, func(record Record) error {
			if !record.Success {
				return nil
			}
			if err := writer.Write(record.PRN()); err != nil {
				return err
			}
			written++
			return nil
		})
	}()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	case <-ctx.Done():
		_ = buffer.Close()
		readErr := <-errCh
		if readErr != nil && !errors.Is(readErr, context.Canceled) &&
			!errors.Is(readErr, os.ErrClosed) {
			return fmt.Errorf("read KVM debugfs buffer: %w", readErr)
		}
	}
	stats := Stats{Schema: "memento.cpu-stats/v1", Time: time.Now().UTC(), Records: written,
		KernelStart: startValues}
	values, err := ReadKernelStats(statsPath)
	if err != nil {
		return fmt.Errorf("read KVM drop statistics: %w", err)
	}
	stats.KernelValues = values
	stats.DropCount, err = validateKernelAccounting(startValues, values, written)
	if statsOutput != "" {
		if writeErr := writeStats(statsOutput, stats); writeErr != nil {
			return writeErr
		}
	}
	if err != nil {
		return err
	}
	if stats.DropCount > 0 {
		return fmt.Errorf("KVM logger reported %d dropped records", stats.DropCount)
	}
	return nil
}

func validateKernelAccounting(start, end map[string]uint64, written uint64) (uint64, error) {
	required := []string{"total_records", "consumed", "drop_count", "buffer_used"}
	for _, name := range required {
		if _, found := start[name]; !found {
			return 0, fmt.Errorf("initial KVM stats do not contain %s", name)
		}
		if _, found := end[name]; !found {
			return 0, fmt.Errorf("final KVM stats do not contain %s", name)
		}
	}
	for _, name := range []string{"total_records", "consumed", "drop_count"} {
		if end[name] < start[name] {
			return 0, fmt.Errorf("KVM counter %s decreased: start=%d end=%d",
				name, start[name], end[name])
		}
	}
	if start["buffer_used"] != 0 || end["buffer_used"] != 0 {
		return 0, fmt.Errorf("KVM ring was not empty: start=%d end=%d",
			start["buffer_used"], end["buffer_used"])
	}
	total := end["total_records"] - start["total_records"]
	consumed := end["consumed"] - start["consumed"]
	dropped := end["drop_count"] - start["drop_count"]
	if total != consumed+dropped {
		return 0, fmt.Errorf("KVM accounting delta mismatch: total=%d consumed=%d dropped=%d",
			total, consumed, dropped)
	}
	if consumed != written {
		return 0, fmt.Errorf("KVM/JSONL count mismatch: consumed=%d records_written=%d",
			consumed, written)
	}
	return dropped, nil
}

func ReadKernelStats(path string) (map[string]uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		key, raw, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse KVM stat %q: %w", key, err)
		}
		values[strings.TrimSpace(key)] = value
	}
	if _, found := values["drop_count"]; !found {
		return nil, errors.New("KVM stats do not contain drop_count")
	}
	return values, nil
}

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
