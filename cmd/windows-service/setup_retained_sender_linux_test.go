//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"localrmm/internal/lanclientstate"
)

// Differential coverage uses the actual sender writer rather than a duplicate
// fixture encoder. These are invented local portable records, never Windows
// service state or real observations. Unacknowledged pending bytes and consumed
// but discarded sequences are legitimate retained states.
func TestSetupRetentionAcceptsActualSenderWriterWithPendingAcknowledgedAndGappedSequences(t *testing.T) {
	binding := strings.Repeat("a", 64)
	dir := filepath.Join(t.TempDir(), "sender")
	state, err := lanclientstate.Open(dir, binding)
	if err != nil {
		t.Fatal("sender fixture open failed")
	}
	defer state.Close()
	check := func(floor uint64) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
		if err != nil {
			t.Fatal("sender fixture read failed")
		}
		defer clear(raw)
		if !setupRetentionSender(raw, binding, floor) {
			t.Fatal("real canonical sender writer bytes rejected")
		}
		foreign := bytes.Replace(raw, []byte(binding), []byte(strings.Repeat("b", 64)), 1)
		defer clear(foreign)
		if setupRetentionSender(foreign, binding, floor) {
			t.Fatal("mutated writer binding accepted")
		}
	}
	for sequence := uint64(1); sequence <= 9; sequence++ {
		pending, err := state.Stage(sequence, []byte(` { "synthetic" : true } `))
		if err != nil {
			t.Fatal("sender fixture stage failed")
		}
		check(1)
		if sequence == 1 || sequence == 9 {
			if state.Acknowledge(pending.Digest) != nil {
				t.Fatal("sender fixture acknowledgment failed")
			}
		} else {
			if state.Discard(pending.Digest) != nil {
				t.Fatal("sender fixture discard failed")
			}
		}
		check(1)
	}
	// Only sequences 1 and 9 were acknowledged. The observed floor must be 9,
	// never frame count 2, and an in-flight sequence 10 remains valid.
	if _, err := state.Stage(10, []byte(`{"synthetic":"pending"}`)); err != nil {
		t.Fatal("sender pending stage failed")
	}
	check(9)
}
