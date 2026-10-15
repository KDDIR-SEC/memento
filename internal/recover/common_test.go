// SPDX-License-Identifier: GPL-2.0-only

package recover

import (
	"bytes"
	"testing"
)

func TestScorePlaintextDoesNotRewardInvalidShortMagic(t *testing.T) {
	readable := bytes.Repeat([]byte("Readable Babuk recovery fixture line.\n"), 4)
	readableScore := ScorePlaintext(readable)
	for name, prefix := range map[string][]byte{
		"json object": []byte(`{"`),
		"json array":  {'[', '\n'},
		"shebang":     []byte("#!"),
	} {
		t.Run(name, func(t *testing.T) {
			falsePositive := make([]byte, len(readable))
			for index := range falsePositive {
				falsePositive[index] = byte((index*73 + 19) % 256)
			}
			copy(falsePositive, prefix)
			falseScore := ScorePlaintext(falsePositive)
			if falseScore >= readableScore {
				t.Fatalf("invalid short magic score %f outranked readable plaintext score %f", falseScore, readableScore)
			}
		})
	}
}

func TestScorePlaintextRewardsValidatedTextMagic(t *testing.T) {
	validJSON := []byte(`{"memento":"validation","count":1}`)
	invalidJSON := []byte(`{"memento":not-json}`)
	if ScorePlaintext(validJSON) <= ScorePlaintext(invalidJSON)+10 {
		t.Fatal("valid JSON did not receive a discriminating magic bonus")
	}

	validShebang := []byte("#!/usr/bin/env bash\nprintf 'memento validation\\n'\n")
	invalidShebang := []byte("#!not-an-absolute-interpreter\nprintf 'memento validation\\n'\n")
	if ScorePlaintext(validShebang) <= ScorePlaintext(invalidShebang)+10 {
		t.Fatal("validated shebang did not receive a discriminating magic bonus")
	}
}
