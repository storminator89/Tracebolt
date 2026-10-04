package fullinventory

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCheckpointResumeEveryBoundaryAndDetach(t *testing.T) {
	for _, n := range []int{0, 1, 300} {
		m, chunks := buildFixture(t, n)
		v, _ := NewValidator(context.Background(), m)
		for i := 0; i <= len(chunks); i++ {
			raw, err := v.Checkpoint()
			if err != nil || len(raw) > MaxCheckpointBytes {
				t.Fatalf("checkpoint: %v", err)
			}
			expected, err := v.Progress()
			if err != nil {
				t.Fatal(err)
			}
			restored, err := RestoreValidatorFromTrustedCheckpoint(context.Background(), m, raw)
			if err != nil {
				t.Fatalf("restore %d/%d: %v", i, n, err)
			}
			actual, _ := restored.Progress()
			if expected != actual {
				t.Fatal("progress changed")
			}
			for j := range raw {
				raw[j] = 'x'
			}
			v = restored
			if i < len(chunks) {
				if err := v.Add(chunks[i]); err != nil {
					t.Fatal(err)
				}
			}
		}
		receipt, err := v.Finish()
		if err != nil || !receipt.Valid() {
			t.Fatal("restored completion", err)
		}
		if _, err := v.Checkpoint(); err != ErrClosed {
			t.Fatal("closed checkpoint reused")
		}
	}
}
func TestCheckpointStrictStructureAndRelationships(t *testing.T) {
	m, chunks := buildFixture(t, 300)
	v, _ := NewValidator(context.Background(), m)
	if err := v.Add(chunks[0]); err != nil {
		t.Fatal(err)
	}
	raw, _ := v.Checkpoint()
	var original checkpoint
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*checkpoint){
		"unknown version":        func(s *checkpoint) { s.Version = "future" },
		"wrong manifest":         func(s *checkpoint) { s.ManifestSHA256 = strings.Repeat("0", 64) },
		"ordinal overflow":       func(s *checkpoint) { s.NextOrdinal = ^uint32(0) },
		"rows overflow":          func(s *checkpoint) { s.ObservedCount = ^uint64(0) },
		"installed overflow":     func(s *checkpoint) { s.InstalledCount = ^uint64(0) },
		"bytes overflow":         func(s *checkpoint) { s.CanonicalRowBytes = ^uint64(0) },
		"wire overflow":          func(s *checkpoint) { s.CanonicalWireBytes = ^uint64(0) },
		"wire missing":           func(s *checkpoint) { s.CanonicalWireBytes = 0 },
		"initial counters":       func(s *checkpoint) { s.NextOrdinal = 0 },
		"bad last identity":      func(s *checkpoint) { s.LastArchitecture = "linux-any" },
		"bad previous":           func(s *checkpoint) { s.PreviousSHA256 = "" },
		"too few accepted rows":  func(s *checkpoint) { s.ObservedCount = 0 },
		"too many accepted rows": func(s *checkpoint) { s.ObservedCount = 129 },
		"too few remaining rows": func(s *checkpoint) { s.NextOrdinal = 2; s.ObservedCount = 300 },
		"state truncated":        func(s *checkpoint) { s.SHA256State = s.SHA256State[:100] },
		"state magic":            func(s *checkpoint) { s.SHA256State[3] = 2 },
		"state byte count":       func(s *checkpoint) { binary.BigEndian.PutUint64(s.SHA256State[100:], 0) },
		"final counters":         func(s *checkpoint) { s.NextOrdinal = m.ChunkCount },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s := original
			s.SHA256State = bytes.Clone(original.SHA256State)
			change(&s)
			bad, _ := json.Marshal(s)
			if got, err := RestoreValidatorFromTrustedCheckpoint(context.Background(), m, bad); err == nil || got != nil {
				t.Fatal("accepted corrupt checkpoint")
			}
		})
	}
	for _, bad := range [][]byte{
		append([]byte{' '}, raw...),
		append(bytes.Clone(raw), []byte(` {}`)...),
		bytes.Replace(raw, []byte(`"nextOrdinal":1`), []byte(`"nextOrdinal":1.0`), 1),
		bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"ignored","version":`), 1),
		bytes.Replace(raw, []byte(`"lastName"`), []byte(`"LastName"`), 1),
		bytes.Repeat([]byte{' '}, MaxCheckpointBytes+1),
	} {
		if got, err := RestoreValidatorFromTrustedCheckpoint(context.Background(), m, bad); err == nil || got != nil {
			t.Fatal("accepted noncanonical checkpoint")
		}
	}
	modified := cloneManifest(m)
	modified.CollectedAt = modified.CollectedAt.Add(time.Second)
	if got, err := RestoreValidatorFromTrustedCheckpoint(context.Background(), modified, raw); err == nil || got != nil {
		t.Fatal("reused checkpoint with changed metadata")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RestoreValidatorFromTrustedCheckpoint(ctx, m, raw); err != ErrCanceled {
		t.Fatal("canceled restore")
	}
}
func TestCheckpointInitialAndFinalHashInvariants(t *testing.T) {
	m, chunks := buildFixture(t, 2)
	v, _ := NewValidator(context.Background(), m)
	raw, _ := v.Checkpoint()
	var s checkpoint
	_ = json.Unmarshal(raw, &s)
	s.SHA256State[5] ^= 1
	bad, _ := json.Marshal(s)
	if _, err := RestoreValidatorFromTrustedCheckpoint(context.Background(), m, bad); err == nil {
		t.Fatal("altered initial hash")
	}
	if err := v.Add(chunks[0]); err != nil {
		t.Fatal(err)
	}
	raw, _ = v.Checkpoint()
	_ = json.Unmarshal(raw, &s)
	s.SHA256State[5] ^= 1
	bad, _ = json.Marshal(s)
	if _, err := RestoreValidatorFromTrustedCheckpoint(context.Background(), m, bad); err == nil {
		t.Fatal("altered final hash")
	}
	var zero Validator
	if got, err := zero.Finish(); err == nil || got.Valid() {
		t.Fatal("zero validator completed")
	}
	if _, err := zero.Checkpoint(); err == nil {
		t.Fatal("zero checkpoint")
	}
	if p, err := zero.Progress(); err == nil || !reflect.DeepEqual(p, Progress{}) {
		t.Fatal("zero progress")
	}
}
