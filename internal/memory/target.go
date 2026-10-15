// SPDX-License-Identifier: GPL-2.0-only

package memory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type processIdentity struct {
	PID       int
	State     byte
	StartTime uint64
}

// ProcessTarget pins a process with a pidfd and a /proc start-time snapshot so
// a recycled numeric PID can never be dumped or resumed.
type ProcessTarget struct {
	identity processIdentity
	pidfd    int
}

func OpenProcessTarget(pid int) (*ProcessTarget, error) {
	if pid <= 0 {
		return nil, errors.New("target PID must be positive")
	}
	identity, err := readProcessIdentity(pid)
	if err != nil {
		return nil, err
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("open pidfd for PID %d: %w", pid, err)
	}
	return &ProcessTarget{identity: identity, pidfd: pidfd}, nil
}

func (t *ProcessTarget) Close() error {
	if t == nil || t.pidfd < 0 {
		return nil
	}
	err := unix.Close(t.pidfd)
	t.pidfd = -1
	return err
}

func (t *ProcessTarget) PID() int { return t.identity.PID }

func (t *ProcessTarget) Verify() error {
	if t == nil || t.pidfd < 0 {
		return errors.New("process target is closed")
	}
	current, err := readProcessIdentity(t.identity.PID)
	if err != nil {
		return err
	}
	if !sameProcess(t.identity, current) {
		return fmt.Errorf("PID %d was reused: start time changed", t.identity.PID)
	}
	if err := unix.PidfdSendSignal(t.pidfd, 0, nil, 0); err != nil {
		return fmt.Errorf("verify pidfd for PID %d: %w", t.identity.PID, err)
	}
	return nil
}

func (t *ProcessTarget) WaitStopped(ctx context.Context, timeout time.Duration) error {
	if timeout <= 0 {
		return errors.New("stop-wait timeout must be positive")
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		current, err := readProcessIdentity(t.identity.PID)
		if err != nil {
			return err
		}
		if !sameProcess(t.identity, current) {
			return fmt.Errorf("PID %d was reused while waiting for stop", t.identity.PID)
		}
		if current.State == 'T' || current.State == 't' {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("PID %d did not enter stopped state within %s", t.identity.PID, timeout)
		case <-ticker.C:
		}
	}
}

func (t *ProcessTarget) Continue() error {
	if err := t.Verify(); err != nil {
		return err
	}
	if err := unix.PidfdSendSignal(t.pidfd, unix.SIGCONT, nil, 0); err != nil {
		return fmt.Errorf("resume PID %d through pidfd: %w", t.identity.PID, err)
	}
	return nil
}

func readProcessIdentity(pid int) (processIdentity, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return processIdentity{}, fmt.Errorf("read process identity for PID %d: %w", pid, err)
	}
	identity, err := parseProcessStat(string(data))
	if err != nil {
		return processIdentity{}, fmt.Errorf("parse process identity for PID %d: %w", pid, err)
	}
	if identity.PID != pid {
		return processIdentity{}, fmt.Errorf("process identity PID mismatch: got %d want %d", identity.PID, pid)
	}
	return identity, nil
}

func parseProcessStat(value string) (processIdentity, error) {
	open := strings.IndexByte(value, '(')
	close := strings.LastIndexByte(value, ')')
	if open <= 0 || close <= open || close+1 >= len(value) {
		return processIdentity{}, errors.New("malformed /proc stat line")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(value[:open]))
	if err != nil || pid <= 0 {
		return processIdentity{}, errors.New("invalid /proc stat PID")
	}
	fields := strings.Fields(value[close+1:])
	if len(fields) <= 19 || len(fields[0]) != 1 {
		return processIdentity{}, errors.New("truncated /proc stat line")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return processIdentity{}, fmt.Errorf("invalid /proc stat start time: %w", err)
	}
	return processIdentity{PID: pid, State: fields[0][0], StartTime: start}, nil
}

func sameProcess(expected, current processIdentity) bool {
	return expected.PID == current.PID && expected.StartTime == current.StartTime
}
