// SPDX-License-Identifier: GPL-2.0-only

package memory

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestParseProcessStatAndPIDReuseCheck(t *testing.T) {
	stat := "123 (worker name (nested)) T 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20"
	identity, err := parseProcessStat(stat)
	if err != nil {
		t.Fatal(err)
	}
	if identity.PID != 123 || identity.State != 'T' || identity.StartTime != 424242 {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	if !sameProcess(identity, processIdentity{PID: 123, StartTime: 424242}) {
		t.Fatal("same process identity was rejected")
	}
	if sameProcess(identity, processIdentity{PID: 123, StartTime: 424243}) {
		t.Fatal("reused PID identity was accepted")
	}
}

func TestProcessTargetWaitStoppedAndContinue(t *testing.T) {
	command := exec.Command("sh", "-c", "kill -STOP $$; exit 0")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	target, err := OpenProcessTarget(command.Process.Pid)
	if err != nil {
		_ = command.Process.Kill()
		t.Fatal(err)
	}
	defer target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := target.WaitStopped(ctx, 2*time.Second); err != nil {
		_ = command.Process.Kill()
		t.Fatal(err)
	}
	if err := target.Continue(); err != nil {
		_ = command.Process.Kill()
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenProcessTargetPinsCurrentProcess(t *testing.T) {
	target, err := OpenProcessTarget(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := target.Verify(); err != nil {
		t.Fatal(err)
	}
}
