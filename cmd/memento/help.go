// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"fmt"
	"io"
	"strings"
)

var helpTopics = map[string]string{
	"doctor": `Usage: memento doctor [syscall|cpu|vdso]

Run read-only prerequisite checks. With no target, all checks are run.`,
	"monitor": `Usage: memento monitor syscall|cpu [OPTIONS]

Record pseudorandom values from syscall tracepoints or the modified KVM ring.
Run "memento help monitor syscall" or "memento help monitor cpu" for options.`,
	"monitor syscall": `Usage: memento monitor syscall [OPTIONS]

Record read(/dev/random), read(/dev/urandom), and getrandom events as JSONL.

Options:
  --output PATH              PRN JSONL output (default: <state-dir>/log/syscall-prn.jsonl)
  --stats PATH               statistics output (default: <state-dir>/stats/syscall.json)
  --pid PID                  record only this process TGID
  --exclude NAME             process command name to exclude; repeatable
  --dump-on-prn              dump the selected process after the first matching PRN
  --dump-operation OP        dump trigger: read or getrandom
  --dump-path PATH           dump trigger syscall path
  --dump-length BYTES        exact requested and captured trigger length
  --dump-wait-stopped TIME   require the target to stop before dumping
  --resume-after-dump        resume a validation-stopped target after a successful dump
  --dump-max-bytes BYTES     maximum total dump bytes (default: 536870912)`,
	"monitor cpu": `Usage: memento monitor cpu [OPTIONS]

Record RDRAND and RDSEED values from the modified KVM debugfs ring.

Options:
  --buffer PATH        KVM debugfs ring buffer
  --kernel-stats PATH  KVM debugfs statistics
  --output PATH        PRN JSONL output (default: <state-dir>/log/cpu-prn.jsonl)
  --stats PATH         statistics output (default: <state-dir>/stats/cpu.json)`,
	"dump": `Usage: memento dump --pid PID [OPTIONS]

Dump readable mappings from one process and report Babuk public-key candidates.

Options:
  --pid PID                 process ID (required)
  --max-bytes BYTES         maximum total dump bytes (default: 536870912)
  --alignment BYTES         candidate alignment (default: 8)
  --threshold SCORE         candidate entropy threshold (default: 4.5)
  --max-candidates COUNT    maximum reported candidates (default: 10000)`,
	"identify": `Usage: memento identify babuk [OPTIONS]

Rank Babuk master public-key candidates from a private memory dump.`,
	"identify babuk": `Usage: memento identify babuk --dump-dir DIR --input FILE --prn-log FILE --output FILE [OPTIONS]

Options:
  --dump-dir DIR            memory dump directory (required)
  --input FILE              Babuk ciphertext (required)
  --prn-log FILE            PRN JSONL input; repeatable and at least one required
  --output FILE             exclusive JSON result path (required)
  --alignment BYTES         candidate alignment (default: 8)
  --threshold SCORE         candidate entropy threshold (default: 4.5)
  --max-candidates COUNT    maximum unique candidates (default: 1000000)`,
	"decrypt": `Usage: memento decrypt babuk|qilin [OPTIONS]

Recover a ciphertext without modifying it by default.
Run "memento help decrypt babuk" or "memento help decrypt qilin" for options.`,
	"decrypt babuk": decryptHelp("babuk"),
	"decrypt qilin": decryptHelp("qilin"),
	"lab": `Usage: memento lab init|create|plan-encryption|encrypt [OPTIONS]

Manage constrained laboratory scenarios and approved encryption plans.
Use "memento help lab <command>" for command-specific options.`,
	"lab init": `Usage: memento lab init --scenario NAME --allow-ext EXT [--allow-ext EXT...]

Create an isolated scenario and its .memento-lab marker.`,
	"lab create": `Usage: memento lab create --scenario NAME --ext EXT [OPTIONS]

Copy an embedded managed fixture into the scenario work directory.

Options:
  --scenario NAME     scenario name (required)
  --fixture NAME      managed fixture name (default: sample.txt)
  --ext EXT           destination extension from the scenario allowlist (required)
  --count COUNT       number of copies, from 1 through 1000 (default: 1)`,
	"lab plan-encryption": `Usage: memento lab plan-encryption --scenario NAME --ext EXT [--ext EXT...]

Validate and list every target, then create a non-encrypting approval manifest.`,
	"lab encrypt": `Usage: memento lab encrypt babuk|qilin [OPTIONS]

Encrypt only targets in an approved scenario manifest. An interactive TTY and
an exact YES confirmation are required. The rootless container wrapper is the
recommended entry point.`,
	"lab encrypt babuk": labEncryptHelp("babuk"),
	"lab encrypt qilin": labEncryptHelp("qilin"),
	"verify": `Usage: memento verify cpu [OPTIONS]

Compare guest instruction records with host KVM PRN records.`,
	"verify cpu": `Usage: memento verify cpu --guest-log FILE --host-log FILE [OPTIONS]

Options:
  --guest-log FILE          guest binary log (required)
  --host-log FILE           host PRN JSONL; repeatable and at least one required
  --require-threads COUNT   required guest worker count; 0 disables
  --require-vcpus COUNT     required observed vCPU count; 0 disables`,
	"genkey": `Usage: memento genkey babuk [OPTIONS]

Generate private Babuk evaluation key material.`,
	"genkey babuk": `Usage: memento genkey babuk [--output FILE]

Write mode-0600 Babuk evaluation key material.
The default is <state-dir>/keys/babuk-<UTC timestamp>.json.`,
	"version": `Usage: memento version

Print the Memento version.`,
}

func decryptHelp(family string) string {
	additional := ""
	if family == "babuk" {
		additional = `
  --public-key HEX    Babuk 32-byte master public key`
	}
	return fmt.Sprintf(`Usage: memento decrypt %s --input FILE --prn-log FILE [OPTIONS]

Options:
  --input FILE        encrypted regular file (required)
  --prn-log FILE      PRN JSONL input; repeatable (defaults to existing state logs)
  --output FILE       recovered output path
  --in-place          replace the input after a separate interactive confirmation%s`, family, additional)
}

func labEncryptHelp(family string) string {
	additional := ""
	if family == "babuk" {
		additional = `
  --public-key HEX              Babuk master public key
  --validation-stop-after-prn   validation only: stop after logging the first Babuk PRN`
	}
	return fmt.Sprintf(`Usage: memento lab encrypt %s --scenario NAME --manifest FILE [OPTIONS]

Options:
  --scenario NAME               scenario name (required)
  --manifest FILE               approved manifest path (required)%s

The command lists every target and requires an exact interactive YES before
creating any ciphertext.`, family, additional)
}

func helpFlagIndex(args []string) int {
	for index, argument := range args {
		if argument == "-h" || argument == "--help" {
			return index
		}
	}
	return -1
}

func printHelp(output io.Writer, path []string) error {
	if len(path) == 0 || (len(path) == 1 && (path[0] == "-h" || path[0] == "--help")) {
		usage(output)
		return nil
	}
	topic := strings.Join(path, " ")
	text, found := helpTopics[topic]
	if !found {
		return fmt.Errorf("unknown help topic %q", topic)
	}
	_, err := fmt.Fprintln(output, text)
	return err
}
