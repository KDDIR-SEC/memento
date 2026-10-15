// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
)

const groundTruthSchema = "memento.syscall-ground-truth/v1"

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type groundTruth struct {
	Schema           string `json:"schema"`
	Sequence         uint64 `json:"sequence"`
	PID              uint32 `json:"pid"`
	TID              uint32 `json:"tid"`
	Operation        string `json:"operation"`
	API              string `json:"api"`
	Path             string `json:"path"`
	FD               int32  `json:"fd"`
	RequestedLength  int    `json:"requested_length"`
	ReturnedLength   int    `json:"returned_length"`
	CapturedLength   int    `json:"captured_length"`
	Flags            uint32 `json:"flags"`
	ValueHex         string `json:"value_hex"`
	Errno            int    `json:"errno"`
	ExpectedObserved bool   `json:"expected_observed"`
}

type identity struct {
	PID       uint32
	TID       uint32
	Operation string
}

type eventKey struct {
	Identity        identity
	Path            string
	FD              int32
	Flags           uint32
	RequestedLength int
	CapturedLength  int
	Truncated       bool
	ValueHex        string
}

type stats struct {
	Schema      string `json:"schema"`
	LostSamples uint64 `json:"lost_samples"`
}

type result struct {
	Schema             string `json:"schema"`
	GroundTruthTotal   uint64 `json:"ground_truth_total"`
	ExpectedObserved   uint64 `json:"expected_observed"`
	ExpectedSuppressed uint64 `json:"expected_suppressed"`
	MonitorTotal       uint64 `json:"monitor_total"`
	MonitorIgnored     uint64 `json:"monitor_ignored"`
	Matched            uint64 `json:"matched"`
	Missing            uint64 `json:"missing"`
	Unexpected         uint64 `json:"unexpected"`
	Extra              uint64 `json:"extra"`
	LostSamples        uint64 `json:"lost_samples"`
}

func (value result) failed() bool {
	return value.Missing != 0 || value.Unexpected != 0 ||
		value.Extra != 0 || value.LostSamples != 0
}

func loadGroundTruth(paths []string) ([]groundTruth, error) {
	var records []groundTruth
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			if strings.TrimSpace(scanner.Text()) == "" {
				continue
			}
			var record groundTruth
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				_ = file.Close()
				return nil, fmt.Errorf("%s:%d: %w", path, line, err)
			}
			if err := validateGroundTruth(record); err != nil {
				_ = file.Close()
				return nil, fmt.Errorf("%s:%d: %w", path, line, err)
			}
			records = append(records, record)
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if err := errors.Join(scanErr, closeErr); err != nil {
			return nil, err
		}
	}
	if len(records) == 0 {
		return nil, errors.New("ground-truth input is empty")
	}
	return records, nil
}

func validateGroundTruth(record groundTruth) error {
	if record.Schema != groundTruthSchema {
		return fmt.Errorf("unsupported ground-truth schema %q", record.Schema)
	}
	if record.Operation != "read" && record.Operation != "getrandom" {
		return fmt.Errorf("invalid operation %q", record.Operation)
	}
	value, err := hex.DecodeString(record.ValueHex)
	if err != nil {
		return fmt.Errorf("invalid value_hex: %w", err)
	}
	if record.CapturedLength != len(value) {
		return fmt.Errorf("captured_length=%d does not match value length %d",
			record.CapturedLength, len(value))
	}
	if record.ExpectedObserved {
		if record.ReturnedLength <= 0 || record.Errno != 0 {
			return errors.New("observable record did not report a successful syscall")
		}
		if record.CapturedLength != min(record.ReturnedLength, 128) {
			return errors.New("observable record has an invalid captured length")
		}
	}
	return nil
}

func groundIdentity(record groundTruth) identity {
	return identity{PID: record.PID, TID: record.TID, Operation: record.Operation}
}

func groundKey(record groundTruth) eventKey {
	key := eventKey{
		Identity:        groundIdentity(record),
		RequestedLength: record.RequestedLength,
		CapturedLength:  record.CapturedLength,
		Truncated:       record.ReturnedLength > 128,
		ValueHex:        strings.ToLower(record.ValueHex),
	}
	if record.Operation == "read" {
		key.Path = record.Path
		key.FD = record.FD
	} else {
		key.Flags = record.Flags
	}
	return key
}

func monitorKey(record prnlog.Record) (eventKey, error) {
	if record.Process == nil || record.Syscall == nil {
		return eventKey{}, errors.New("syscall PRN lacks process or syscall metadata")
	}
	key := eventKey{
		Identity: identity{
			PID:       record.Process.PID,
			TID:       record.Process.TID,
			Operation: record.Operation,
		},
		RequestedLength: record.RequestedLength,
		CapturedLength:  record.CapturedLength,
		Truncated:       record.Truncated,
		ValueHex:        strings.ToLower(record.ValueHex),
	}
	if record.Operation == "read" {
		key.Path = record.Syscall.Path
		key.FD = record.Syscall.FD
	} else if record.Operation == "getrandom" {
		key.Flags = record.Syscall.Flags
	} else {
		return eventKey{}, fmt.Errorf("unexpected syscall operation %q", record.Operation)
	}
	return key, nil
}

func loadStats(path string) (stats, error) {
	file, err := os.Open(path)
	if err != nil {
		return stats{}, err
	}
	defer file.Close()
	var value stats
	if err := json.NewDecoder(io.LimitReader(file, 1024*1024)).Decode(&value); err != nil {
		return stats{}, err
	}
	if value.Schema != "memento.syscall-stats/v1" {
		return stats{}, fmt.Errorf("unsupported syscall stats schema %q", value.Schema)
	}
	return value, nil
}

func compare(groundPaths, monitorPaths []string, statsPath string) (result, error) {
	ground, err := loadGroundTruth(groundPaths)
	if err != nil {
		return result{}, err
	}
	monitor, err := prnlog.ReadFiles(monitorPaths)
	if err != nil {
		return result{}, err
	}
	monitorStats, err := loadStats(statsPath)
	if err != nil {
		return result{}, err
	}

	answer := result{
		Schema:           "memento.syscall-verification/v1",
		GroundTruthTotal: uint64(len(ground)),
		LostSamples:      monitorStats.LostSamples,
	}
	expected := make(map[eventKey]uint64)
	positiveIdentities := make(map[identity]struct{})
	suppressed := make(map[identity]struct{})
	scopedIdentities := make(map[identity]struct{})
	for _, record := range ground {
		eventIdentity := groundIdentity(record)
		scopedIdentities[eventIdentity] = struct{}{}
		if record.ExpectedObserved {
			expected[groundKey(record)]++
			positiveIdentities[eventIdentity] = struct{}{}
			answer.ExpectedObserved++
		} else {
			suppressed[eventIdentity] = struct{}{}
			answer.ExpectedSuppressed++
		}
	}
	for eventIdentity := range suppressed {
		if _, ambiguous := positiveIdentities[eventIdentity]; ambiguous {
			return result{}, fmt.Errorf(
				"ground truth mixes observable and suppressed events for pid=%d tid=%d operation=%s",
				eventIdentity.PID, eventIdentity.TID, eventIdentity.Operation)
		}
	}

	for _, record := range monitor {
		if record.Source != "syscall" {
			continue
		}
		key, err := monitorKey(record)
		if err != nil {
			return result{}, err
		}
		if _, inScope := scopedIdentities[key.Identity]; !inScope {
			answer.MonitorIgnored++
			continue
		}
		answer.MonitorTotal++
		if _, forbidden := suppressed[key.Identity]; forbidden {
			answer.Unexpected++
			continue
		}
		if expected[key] != 0 {
			expected[key]--
			answer.Matched++
			continue
		}
		answer.Extra++
	}
	for _, count := range expected {
		answer.Missing += count
	}
	return answer, nil
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("syscallverify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var groundPaths stringList
	var monitorPaths stringList
	flags.Var(&groundPaths, "ground-truth", "ground-truth JSONL (repeatable)")
	flags.Var(&monitorPaths, "monitor-log", "memento syscall PRN JSONL (repeatable)")
	statsPath := flags.String("stats", "", "memento syscall statistics JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || len(groundPaths) == 0 ||
		len(monitorPaths) == 0 || *statsPath == "" {
		return errors.New("--ground-truth, --monitor-log, and --stats are required")
	}
	answer, err := compare(groundPaths, monitorPaths, *statsPath)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdout).Encode(answer); err != nil {
		return err
	}
	if answer.failed() {
		return fmt.Errorf("verification failed: missing=%d unexpected=%d extra=%d lost_samples=%d",
			answer.Missing, answer.Unexpected, answer.Extra, answer.LostSamples)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
