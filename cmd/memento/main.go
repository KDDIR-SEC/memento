// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	mementoebpf "github.com/KDDIR-SEC/memento/ebpf"
	"github.com/KDDIR-SEC/memento/internal/cpumon"
	"github.com/KDDIR-SEC/memento/internal/doctor"
	"github.com/KDDIR-SEC/memento/internal/keygen"
	"github.com/KDDIR-SEC/memento/internal/lab"
	"github.com/KDDIR-SEC/memento/internal/memory"
	"github.com/KDDIR-SEC/memento/internal/prnlog"
	"github.com/KDDIR-SEC/memento/internal/recover"
	"github.com/KDDIR-SEC/memento/internal/simcrypto"
	"github.com/KDDIR-SEC/memento/internal/state"
	"github.com/KDDIR-SEC/memento/internal/verify"
	"golang.org/x/sys/unix"
)

const version = "0.1.0-dev"

type globals struct {
	stateDir string
	verbose  bool
}

type stringsFlag []string

func (v *stringsFlag) String() string         { return strings.Join(*v, ",") }
func (v *stringsFlag) Set(value string) error { *v = append(*v, value); return nil }

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		slog.Error("memento failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string, stdin *os.File, stdout, stderr io.Writer) error {
	global := flag.NewFlagSet("memento", flag.ContinueOnError)
	global.SetOutput(stderr)
	global.Usage = func() {}
	var options globals
	global.StringVar(&options.stateDir, "state-dir", "", "state directory (then MEMENTO_STATE_DIR, then ./var)")
	global.BoolVar(&options.verbose, "verbose", false, "enable debug logs")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return printHelp(stdout, nil)
		}
		return err
	}
	args = global.Args()
	if len(args) > 0 && args[0] == "help" {
		return printHelp(stdout, args[1:])
	}
	if index := helpFlagIndex(args); index >= 0 {
		if index != len(args)-1 {
			return errors.New("help flag accepts no following arguments")
		}
		return printHelp(stdout, args[:index])
	}
	if options.verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	if len(args) == 0 {
		usage(stderr)
		return errors.New("a command is required")
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return errors.New("version accepts no arguments")
		}
		fmt.Fprintln(stdout, version)
		return nil
	}
	layout, err := state.Resolve(options.stateDir)
	if err != nil {
		return err
	}
	switch args[0] {
	case "doctor":
		return runDoctor(args[1:], stdout)
	case "monitor":
		return runMonitor(args[1:], layout, stdout, stderr)
	case "dump":
		return runDump(args[1:], layout, stdout, stderr)
	case "identify":
		return runIdentify(args[1:], stdout, stderr)
	case "decrypt":
		return runDecrypt(args[1:], layout, stdin, stdout, stderr)
	case "lab":
		return runLab(args[1:], layout, stdin, stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "genkey":
		return runGenkey(args[1:], layout, stdout, stderr)
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `memento 0.1.0-dev

Usage: memento [GLOBAL OPTIONS] COMMAND [OPTIONS]

Global options:
  --state-dir DIR  state directory (then MEMENTO_STATE_DIR, then ./var)
  --verbose        enable debug logs
  -h, --help       show help and exit

Commands:
  doctor [syscall|cpu|vdso]
  monitor syscall|cpu
  dump
  identify babuk
  decrypt babuk|qilin
  lab init|create|plan-encryption|encrypt
  verify cpu
  genkey babuk
  version

Safe first checks:
  memento version
  sudo memento doctor syscall

Run "memento help COMMAND" for command-specific help.`)
}

func runDoctor(args []string, output io.Writer) error {
	target := "all"
	if len(args) > 1 {
		return errors.New("doctor accepts at most one target")
	}
	if len(args) == 1 {
		target = args[0]
	}
	if target != "all" && target != "syscall" && target != "cpu" && target != "vdso" {
		return fmt.Errorf("unknown doctor target %q", target)
	}
	failed := false
	for _, check := range doctor.Run(target) {
		status := "OK"
		if !check.OK {
			status = "WARN"
			failed = failed || !check.Warning
		}
		fmt.Fprintf(output, "[%s] %s: %s\n", status, check.Name, check.Detail)
	}
	if failed {
		return errors.New("one or more required checks failed")
	}
	return nil
}

func runMonitor(args []string, layout state.Layout, output, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("monitor requires syscall or cpu")
	}
	switch args[0] {
	case "syscall":
		flags := flag.NewFlagSet("monitor syscall", flag.ContinueOnError)
		flags.SetOutput(stderr)
		logPath := flags.String("output", filepath.Join(layout.Log, "syscall-prn.jsonl"), "PRN JSONL output")
		statsPath := flags.String("stats", filepath.Join(layout.Stats, "syscall.json"), "statistics output")
		targetPID := flags.Int("pid", 0, "record only this process TGID")
		dumpOnPRN := flags.Bool("dump-on-prn", false, "dump the selected process after the first matching PRN")
		dumpOperation := flags.String("dump-operation", "", "dump trigger operation: read or getrandom")
		dumpPath := flags.String("dump-path", "", "dump trigger syscall path")
		dumpLength := flags.Int("dump-length", 0, "dump trigger exact requested and captured length")
		dumpWaitStopped := flags.Duration("dump-wait-stopped", 0, "require the target to stop before dumping")
		resumeAfterDump := flags.Bool("resume-after-dump", false, "resume a validation-stopped target only after a successful dump")
		dumpMaxBytes := flags.Int64("dump-max-bytes", 512*1024*1024, "maximum total dump bytes")
		var excludedNames stringsFlag
		flags.Var(&excludedNames, "exclude", "process command name to exclude (repeatable)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if err := rejectPositionals(flags); err != nil {
			return err
		}
		if *targetPID < 0 || uint64(*targetPID) > uint64(^uint32(0)) {
			return errors.New("monitor PID is outside the uint32 range")
		}
		if *dumpOperation != "" && *dumpOperation != "read" && *dumpOperation != "getrandom" {
			return errors.New("--dump-operation must be read or getrandom")
		}
		if *dumpLength < 0 || *dumpMaxBytes <= 0 || *dumpWaitStopped < 0 {
			return errors.New("dump length, timeout, and byte limit must not be negative or zero where applicable")
		}
		if *dumpOnPRN && *targetPID <= 0 {
			return errors.New("--dump-on-prn requires a single --pid target")
		}
		if !*dumpOnPRN && (*dumpOperation != "" || *dumpPath != "" || *dumpLength != 0 || *dumpWaitStopped != 0 || *resumeAfterDump) {
			return errors.New("dump selector, stop-wait, and resume flags require --dump-on-prn")
		}
		if *resumeAfterDump && *dumpWaitStopped == 0 {
			return errors.New("--resume-after-dump requires --dump-wait-stopped")
		}
		if err := layout.Ensure(); err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		var target *memory.ProcessTarget
		if *targetPID > 0 {
			var err error
			target, err = memory.OpenProcessTarget(*targetPID)
			if err != nil {
				return err
			}
			defer target.Close()
		}
		var trigger mementoebpf.DumpTrigger
		if *dumpOnPRN {
			var triggerMu sync.Mutex
			triggered := false
			trigger = func(record prnlog.Record) error {
				if !matchesDumpRecord(record, *dumpOperation, *dumpPath, *dumpLength) {
					return nil
				}
				triggerMu.Lock()
				if triggered {
					triggerMu.Unlock()
					return nil
				}
				triggered = true
				triggerMu.Unlock()
				if err := target.Verify(); err != nil {
					return err
				}
				if *dumpWaitStopped > 0 {
					if err := target.WaitStopped(ctx, *dumpWaitStopped); err != nil {
						return err
					}
				}
				directory, err := memory.Dump(memory.DumpOptions{PID: target.PID(), Root: layout.Dump, MaxTotalByte: *dumpMaxBytes})
				if err != nil {
					return err
				}
				if *resumeAfterDump {
					if err := target.Continue(); err != nil {
						return err
					}
				}
				slog.Info("memory dump trigger completed", "pid", target.PID(), "directory", directory)
				return nil
			}
		}
		fmt.Fprintf(output, "writing syscall PRNs to %s\n", *logPath)
		excluded := make(map[string]struct{}, len(excludedNames))
		for _, group := range excludedNames {
			for _, name := range strings.Split(group, ",") {
				if name = strings.TrimSpace(name); name != "" {
					excluded[name] = struct{}{}
				}
			}
		}
		return mementoebpf.Run(ctx, *logPath, *statsPath, mementoebpf.RunOptions{TargetPID: uint32(*targetPID), Trigger: trigger, Excluded: excluded})
	case "cpu":
		flags := flag.NewFlagSet("monitor cpu", flag.ContinueOnError)
		flags.SetOutput(stderr)
		buffer := flags.String("buffer", cpumon.DefaultBufferPath, "KVM debugfs ring buffer")
		kernelStats := flags.String("kernel-stats", cpumon.DefaultStatsPath, "KVM debugfs statistics")
		logPath := flags.String("output", filepath.Join(layout.Log, "cpu-prn.jsonl"), "PRN JSONL output")
		statsPath := flags.String("stats", filepath.Join(layout.Stats, "cpu.json"), "statistics output")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if err := rejectPositionals(flags); err != nil {
			return err
		}
		if err := layout.Ensure(); err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		fmt.Fprintf(output, "writing CPU PRNs to %s\n", *logPath)
		return cpumon.Monitor(ctx, *buffer, *logPath, *kernelStats, *statsPath)
	default:
		return fmt.Errorf("unknown monitor %q", args[0])
	}
}

func matchesDumpRecord(record prnlog.Record, operation, path string, length int) bool {
	if operation != "" && record.Operation != operation {
		return false
	}
	if path != "" && (record.Syscall == nil || record.Syscall.Path != path) {
		return false
	}
	if length > 0 && (record.CapturedLength != length || record.RequestedLength != length) {
		return false
	}
	return !record.Truncated
}

func runDump(args []string, layout state.Layout, output, stderr io.Writer) error {
	flags := flag.NewFlagSet("dump", flag.ContinueOnError)
	flags.SetOutput(stderr)
	pid := flags.Int("pid", 0, "process ID")
	maxBytes := flags.Int64("max-bytes", 512*1024*1024, "maximum total dump bytes")
	alignment := flags.Int64("alignment", 8, "candidate alignment")
	threshold := flags.Float64("threshold", 4.5, "candidate entropy threshold")
	maximum := flags.Int("max-candidates", 10000, "maximum reported candidates")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := rejectPositionals(flags); err != nil {
		return err
	}
	if *pid <= 0 {
		return errors.New("dump requires --pid")
	}
	if err := layout.Ensure(); err != nil {
		return err
	}
	directory, err := memory.Dump(memory.DumpOptions{PID: *pid, Root: layout.Dump, MaxTotalByte: *maxBytes})
	if err != nil {
		return err
	}
	candidatePath := filepath.Join(directory, "babuk-candidates.json")
	candidates, err := memory.FindBabukCandidates(directory, candidatePath, *alignment, *threshold, *maximum)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "dump: %s\nBabuk candidates: %d (%s)\n", directory, len(candidates), candidatePath)
	return nil
}

func runIdentify(args []string, output, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "babuk" {
		return errors.New("identify requires babuk")
	}
	flags := flag.NewFlagSet("identify babuk", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dumpDirectory := flags.String("dump-dir", "", "memory dump directory")
	input := flags.String("input", "", "Babuk ciphertext")
	outputPath := flags.String("output", "", "exclusive JSON result path")
	alignment := flags.Int64("alignment", 8, "candidate alignment")
	threshold := flags.Float64("threshold", 4.5, "candidate entropy threshold")
	maximum := flags.Int("max-candidates", 1_000_000, "maximum unique candidates; exceeding the limit fails")
	var logs stringsFlag
	flags.Var(&logs, "prn-log", "PRN JSONL input (repeatable)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if err := rejectPositionals(flags); err != nil {
		return err
	}
	if *dumpDirectory == "" || *input == "" || *outputPath == "" || len(logs) == 0 {
		return errors.New("identify babuk requires --dump-dir, --input, --output, and at least one --prn-log")
	}
	result, err := memory.IdentifyBabuk(memory.IdentifyBabukOptions{
		DumpDirectory: *dumpDirectory,
		InputPath:     *input,
		PRNLogs:       logs,
		OutputPath:    *outputPath,
		Alignment:     *alignment,
		Threshold:     *threshold,
		MaxCandidates: *maximum,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Babuk master public key: %s\nscore: %.4f (heuristic; the legacy format has no authenticity tag)\ncandidates: %d evaluated: %d PRN index: %d\nresult: %s\n",
		result.PublicKeyHex, result.Score, result.CandidateCount, result.EvaluatedCount, result.PRNIndex, *outputPath)
	return nil
}

func runDecrypt(args []string, layout state.Layout, stdin *os.File, output, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("decrypt requires babuk or qilin")
	}
	family := args[0]
	if family != "babuk" && family != "qilin" {
		return fmt.Errorf("unsupported decryptor %q", family)
	}
	flags := flag.NewFlagSet("decrypt "+family, flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "encrypted regular file")
	outputPath := flags.String("output", "", "recovered output path")
	inPlace := flags.Bool("in-place", false, "replace input after a separate interactive confirmation")
	publicHex := flags.String("public-key", "", "Babuk 32-byte master public key in hex")
	var logs stringsFlag
	flags.Var(&logs, "prn-log", "PRN JSONL input (repeatable)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if err := rejectPositionals(flags); err != nil {
		return err
	}
	if *input == "" {
		return errors.New("decrypt requires --input")
	}
	if len(logs) == 0 {
		for _, candidate := range []string{filepath.Join(layout.Log, "syscall-prn.jsonl"), filepath.Join(layout.Log, "cpu-prn.jsonl"), filepath.Join(layout.Log, "lab-prn.jsonl")} {
			if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
				logs = append(logs, candidate)
			}
		}
		if len(logs) == 0 {
			return errors.New("no default PRN logs exist; provide --prn-log")
		}
	}
	if *inPlace && *outputPath != "" {
		return errors.New("--in-place and --output are mutually exclusive")
	}
	name := strings.TrimSuffix(filepath.Base(*input), map[string]string{"babuk": simcrypto.BabukSuffix, "qilin": simcrypto.QilinSuffix}[family])
	destination := *outputPath
	if destination == "" {
		destination = filepath.Join(layout.Recovered, name)
	}
	temporary := destination
	var confirmedInput os.FileInfo
	if *inPlace {
		if stdin == nil || !terminal(int(stdin.Fd())) {
			return errors.New("in-place recovery requires an interactive TTY")
		}
		absolute, err := filepath.Abs(*input)
		if err != nil {
			return err
		}
		phrase := "OVERWRITE " + absolute
		fmt.Fprintf(output, "In-place recovery will replace %s after successful recovery.\nType exactly: %s\n> ", absolute, phrase)
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil {
			return err
		}
		if strings.TrimRight(line, "\r\n") != phrase {
			return errors.New("overwrite confirmation did not match")
		}
		confirmedInput, err = os.Lstat(absolute)
		if err != nil || !confirmedInput.Mode().IsRegular() || confirmedInput.Mode()&os.ModeSymlink != 0 {
			return errors.New("confirmed input is no longer a regular file")
		}
		temporary = filepath.Join(filepath.Dir(absolute), fmt.Sprintf(".%s.memento-recovered-%d", filepath.Base(absolute), os.Getpid()))
	}
	if err := layout.Ensure(); err != nil {
		return err
	}
	if family == "babuk" {
		key := simcrypto.DefaultBabukPublicKey
		if *publicHex != "" {
			decoded, err := hex.DecodeString(*publicHex)
			if err != nil {
				return err
			}
			key = decoded
		}
		result, err := recover.DecryptBabuk(*input, temporary, key, logs)
		if err != nil {
			return err
		}
		fmt.Fprintf(output, "Babuk candidate PRN index: %d (score %.4f)\n", result.PRNIndex, result.Score)
	} else {
		result, err := recover.DecryptQilin(*input, temporary, logs)
		if err != nil {
			return err
		}
		fmt.Fprintf(output, "Qilin candidate score: %.4f (heuristic; the legacy format has no authenticity tag)\n", result.Score)
	}
	if *inPlace {
		current, err := os.Lstat(*input)
		if err != nil || !sameFileSnapshot(confirmedInput, current) {
			_ = os.Remove(temporary)
			return errors.New("input changed after overwrite confirmation")
		}
		if err := os.Rename(temporary, *input); err != nil {
			_ = os.Remove(temporary)
			return err
		}
		destination = *input
	}
	fmt.Fprintf(output, "recovered: %s\n", destination)
	return nil
}

func sameFileSnapshot(expected, current os.FileInfo) bool {
	if expected == nil || current == nil || !os.SameFile(expected, current) ||
		expected.Size() != current.Size() || !expected.ModTime().Equal(current.ModTime()) ||
		expected.Mode() != current.Mode() {
		return false
	}
	expectedStat, expectedOK := expected.Sys().(*syscall.Stat_t)
	currentStat, currentOK := current.Sys().(*syscall.Stat_t)
	if !expectedOK || !currentOK {
		return false
	}
	return expectedStat.Dev == currentStat.Dev && expectedStat.Ino == currentStat.Ino &&
		expectedStat.Nlink == 1 && currentStat.Nlink == 1 &&
		expectedStat.Ctim == currentStat.Ctim && expectedStat.Mtim == currentStat.Mtim
}

func runLab(args []string, layout state.Layout, stdin *os.File, output, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("lab requires init, create, plan-encryption, or encrypt")
	}
	manager := lab.Manager{State: layout}
	switch args[0] {
	case "init":
		flags := flag.NewFlagSet("lab init", flag.ContinueOnError)
		flags.SetOutput(stderr)
		scenario := flags.String("scenario", "", "scenario name")
		var extensions stringsFlag
		flags.Var(&extensions, "allow-ext", "allowed extension (repeatable or comma-separated)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if err := rejectPositionals(flags); err != nil {
			return err
		}
		marker, err := manager.Init(*scenario, extensions)
		if err != nil {
			return err
		}
		return printJSON(output, marker)
	case "create":
		flags := flag.NewFlagSet("lab create", flag.ContinueOnError)
		flags.SetOutput(stderr)
		scenario := flags.String("scenario", "", "scenario name")
		fixture := flags.String("fixture", "sample.txt", "managed fixture name")
		extension := flags.String("ext", "", "destination extension from the scenario allowlist")
		count := flags.Int("count", 1, "number of managed fixture copies (1-1000)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if err := rejectPositionals(flags); err != nil {
			return err
		}
		if *extension == "" {
			return errors.New("lab create requires --ext")
		}
		paths, err := manager.CreateCopies(*scenario, *fixture, *extension, *count)
		if err != nil {
			return err
		}
		for _, path := range paths {
			fmt.Fprintln(output, path)
		}
		return nil
	case "plan-encryption":
		flags := flag.NewFlagSet("lab plan-encryption", flag.ContinueOnError)
		flags.SetOutput(stderr)
		scenario := flags.String("scenario", "", "scenario name")
		var extensions stringsFlag
		flags.Var(&extensions, "ext", "target extension (repeatable or comma-separated)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if err := rejectPositionals(flags); err != nil {
			return err
		}
		manifest, path, err := manager.Plan(*scenario, extensions)
		if err != nil {
			return err
		}
		fmt.Fprintf(output, "manifest: %s\ndigest: %s\nfiles: %d\nbytes: %d\n", path, manifest.Digest, manifest.TotalFiles, manifest.TotalBytes)
		for _, file := range manifest.Files {
			fmt.Fprintf(output, "  %s (%d bytes)\n", file.Path, file.Size)
		}
		return nil
	case "encrypt":
		if len(args) < 2 {
			return errors.New("lab encrypt requires babuk or qilin")
		}
		algorithm := args[1]
		if algorithm != "babuk" && algorithm != "qilin" {
			return fmt.Errorf("unsupported simulator %q", algorithm)
		}
		flags := flag.NewFlagSet("lab encrypt "+algorithm, flag.ContinueOnError)
		flags.SetOutput(stderr)
		scenario := flags.String("scenario", "", "scenario name")
		manifestPath := flags.String("manifest", "", "approved manifest path")
		publicHex := flags.String("public-key", "", "Babuk master public key in hex")
		validationStopAfterPRN := flags.Bool("validation-stop-after-prn", false, "validation only: stop after logging the first Babuk PRN")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if err := rejectPositionals(flags); err != nil {
			return err
		}
		if *validationStopAfterPRN && algorithm != "babuk" {
			return errors.New("--validation-stop-after-prn is only valid for Babuk")
		}
		if *manifestPath == "" {
			return errors.New("lab encrypt requires --manifest")
		}
		manifest, err := manager.LoadManifest(*scenario, *manifestPath)
		if err != nil {
			return err
		}
		key := simcrypto.DefaultBabukPublicKey
		if *publicHex != "" {
			decoded, err := hex.DecodeString(*publicHex)
			if err != nil {
				return err
			}
			key = decoded
		}
		return manager.Execute(lab.ExecuteOptions{Scenario: *scenario, Manifest: manifest, Algorithm: algorithm, Input: stdin, Output: os.Stdout, Confirmation: output, PRNLogPath: filepath.Join(layout.Log, "lab-prn.jsonl"), BabukKey: key, ValidationStopAfterPRN: *validationStopAfterPRN})
	default:
		return fmt.Errorf("unknown lab command %q", args[0])
	}
}

func runVerify(args []string, output, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "cpu" {
		return errors.New("verify requires cpu")
	}
	flags := flag.NewFlagSet("verify cpu", flag.ContinueOnError)
	flags.SetOutput(stderr)
	guest := flags.String("guest-log", "", "guest binary log")
	requireThreads := flags.Uint64("require-threads", 0, "required number of guest worker threads (0 disables)")
	requireVCPUs := flags.Uint64("require-vcpus", 0, "required number of observed vCPUs (0 disables)")
	var hosts stringsFlag
	flags.Var(&hosts, "host-log", "host PRN JSONL (repeatable)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if err := rejectPositionals(flags); err != nil {
		return err
	}
	if *guest == "" || len(hosts) == 0 {
		return errors.New("verify cpu requires --guest-log and --host-log")
	}
	result, err := verify.CPU(*guest, hosts)
	if err != nil {
		return err
	}
	if err := printJSON(output, result); err != nil {
		return err
	}
	if *requireThreads != 0 && result.GuestThreads != *requireThreads {
		return fmt.Errorf("CPU verification observed %d guest threads, require %d",
			result.GuestThreads, *requireThreads)
	}
	if *requireVCPUs != 0 && result.HostVCPUs != *requireVCPUs {
		return fmt.Errorf("CPU verification observed %d vCPUs, require %d",
			result.HostVCPUs, *requireVCPUs)
	}
	if result.GuestCF0 != 0 || result.Missing != 0 || result.Extra != 0 {
		return fmt.Errorf("CPU verification failed: cf0=%d missing=%d extra=%d",
			result.GuestCF0, result.Missing, result.Extra)
	}
	return nil
}

func runGenkey(args []string, layout state.Layout, output, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "babuk" {
		return errors.New("genkey requires babuk")
	}
	flags := flag.NewFlagSet("genkey babuk", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("output", filepath.Join(layout.Keys, "babuk-"+time.Now().UTC().Format("20060102T150405Z")+".json"), "private key output")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if err := rejectPositionals(flags); err != nil {
		return err
	}
	if err := layout.Ensure(); err != nil {
		return err
	}
	key, err := keygen.Babuk(*path)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "key file (0600): %s\npublic key: %s\n", *path, key.PublicHex)
	return nil
}

func rejectPositionals(flags *flag.FlagSet) error {
	if flags.NArg() != 0 {
		return fmt.Errorf("%s accepts no positional arguments: %s", flags.Name(), strings.Join(flags.Args(), " "))
	}
	return nil
}

func printJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func terminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}
