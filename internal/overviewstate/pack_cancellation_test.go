package overviewstate

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/completeoverview"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewwire"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// One-row packs check the context at these points inside decodePack. Explicit
// checkpoints exercise cancellation inside the validator, not the frame-loop
// check immediately before it. There are no timers or scheduler dependencies.
var packValidatorCancellationPoints = []struct {
	name  string
	check int64
}{
	{"constructor", 2},
	{"append_ready", 4},
	{"append_row", 5},
	{"append_complete", 6},
	{"finish", 8},
}

type packCancellationContext struct {
	context.Context
	cancel     context.CancelFunc
	checks     atomic.Int64
	at         int64
	reason     error
	afterCheck bool
}

func newPackCancellationContext(t *testing.T, at int64, reason error, afterCheck bool) *packCancellationContext {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &packCancellationContext{Context: ctx, cancel: cancel, at: at, reason: reason, afterCheck: afterCheck}
}

func (c *packCancellationContext) Err() error {
	n := c.checks.Add(1)
	if n == c.at && !c.afterCheck {
		c.cancel()
	}
	err := c.Context.Err()
	if n == c.at && c.afterCheck {
		// Model cancellation immediately after this successful Err read. A
		// subsequent validation error must retain its own classification.
		c.cancel()
	}
	if err != nil {
		return c.reason
	}
	return nil
}

func packCancellationPayloads(t *testing.T, a Allocation, section string, n int) ([]byte, [][]byte) {
	t.Helper()
	if section == "processes" {
		return payloads(t, a, n)
	}
	source := completeoverview.Empty(a.GenerationID, a.AttemptedAt, completeoverview.ReasonReadFailed)
	count := uint64(n)
	source.Volumes = completeoverview.VolumeSection{
		Meta:  completeoverview.SectionMeta{GenerationID: a.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &count, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{NotApplicable: count}},
		Items: make([]completeoverview.Volume, n),
	}
	for i := range source.Volumes.Items {
		source.Volumes.Items[i] = completeoverview.Volume{ID: fmt.Sprintf("mount_%d", i+1), MountPoint: fmt.Sprintf("/fixture/%05d", i), Filesystem: "proc", Kind: "virtual", FilesystemGroup: "fs_0_1", CapacityScope: "agent-mount-namespace", Measurement: completeoverview.Observation{Status: completeoverview.NotApplicable, Reason: completeoverview.ReasonNotApplicable}}
	}
	m, chunks, err := overviewgeneration.Build(context.Background(), source, section, a.GenerationID, nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	rawChunks := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		rawChunks[i], err = json.Marshal(chunk)
		if err != nil {
			t.Fatal(err)
		}
	}
	return manifest, rawChunks
}

func packCancellationFixture(t *testing.T, section string, n int) (*generationPack, diskRecord) {
	t.Helper()
	generation, err := overviewwire.GenerationID(fixtureAgent, section, 1)
	if err != nil {
		t.Fatal(err)
	}
	a := Allocation{Sequence: 1, GenerationID: generation, AttemptedAt: fixtureAt}
	manifest, chunks := packCancellationPayloads(t, a, section, n)
	r := diskRecord{Section: section, Floor: a.Sequence, Generation: generation, AttemptedAt: fixtureAt.Format(time.RFC3339Nano), Count: uint32(len(chunks))}
	pack, hash, err := buildPack(context.Background(), r, manifest, chunks)
	if err != nil {
		t.Fatal(err)
	}
	r.ManifestHash = hash
	return pack, r
}

func TestDecodePackPreservesValidatorCancellation(t *testing.T) {
	for _, section := range []string{"processes", "volumes"} {
		t.Run(section, func(t *testing.T) {
			pack, record := packCancellationFixture(t, section, 1)
			for _, reason := range []error{context.Canceled, context.DeadlineExceeded} {
				t.Run(reason.Error(), func(t *testing.T) {
					for _, point := range packValidatorCancellationPoints {
						t.Run(point.name, func(t *testing.T) {
							ctx := newPackCancellationContext(t, point.check, reason, false)
							got, err := decodePack(ctx, pack.raw, record)
							if got != nil || err != ErrCanceled {
								t.Fatalf("decode returned pack=%t, error=%v; want nil, ErrCanceled", got != nil, err)
							}
							if ctx.checks.Load() != point.check || ctx.Context.Err() != context.Canceled {
								t.Fatal("cancellation did not occur at the requested validator checkpoint")
							}
							if got, err := decodePack(context.Background(), pack.raw, record); err != nil || got == nil {
								t.Fatal("cancellation changed the immutable valid pack", err)
							}
						})
					}
				})
			}
		})
	}
}

func TestDecodePackCancellationDoesNotOverrideCorruption(t *testing.T) {
	pack, record := packCancellationFixture(t, "processes", overviewgeneration.MaxChunkRows+1)
	// Both chunks are independently valid and correctly bound. Swapping them
	// reaches Validator.Add's sequence validation after its ready check.
	frames := append([][]byte(nil), pack.frames...)
	frames[1], frames[2] = frames[2], frames[1]
	raw := []byte(packMagic)
	for _, frame := range frames {
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(frame)))
		raw = append(raw, frame...)
	}
	for _, reason := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(reason.Error(), func(t *testing.T) {
			ctx := newPackCancellationContext(t, 4, reason, true)
			if got, err := decodePack(ctx, raw, record); got != nil || err != ErrCorrupt {
				t.Fatalf("invalid chunk sequence returned pack=%t, error=%v; want nil, ErrCorrupt", got != nil, err)
			}
			if ctx.checks.Load() != 4 || ctx.Context.Err() != context.Canceled {
				t.Fatal("corruption classification rechecked the canceled context")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := decodePack(ctx, []byte("invalid header"), record); got != nil || err != ErrCorrupt {
		t.Fatal("cancellation overrode invalid pack framing", err)
	}
	if got, err := decodePack(ctx, pack.raw, record); got != nil || err != ErrCanceled {
		t.Fatal("already-canceled valid pack was not canceled", err)
	}
}

func TestPackValidationErrorRequiresExactCancellation(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want error
	}{
		{"canceled", overviewgeneration.ErrCanceled, ErrCanceled},
		{"invalid", overviewgeneration.ErrInvalid, ErrCorrupt},
		{"incomplete", overviewgeneration.ErrIncomplete, ErrCorrupt},
		{"limit", overviewgeneration.ErrLimit, ErrCorrupt},
		{"closed", overviewgeneration.ErrClosed, ErrCorrupt},
		{"context_canceled", context.Canceled, ErrCorrupt},
		{"deadline", context.DeadlineExceeded, ErrCorrupt},
		{"wrapped_canceled", fmt.Errorf("validation: %w", overviewgeneration.ErrCanceled), ErrCorrupt},
		{"joined_canceled", errors.Join(overviewgeneration.ErrCanceled), ErrCorrupt},
		{"canceled_and_invalid", errors.Join(overviewgeneration.ErrCanceled, overviewgeneration.ErrInvalid), ErrCorrupt},
		{"invalid_and_canceled", errors.Join(overviewgeneration.ErrInvalid, overviewgeneration.ErrCanceled), ErrCorrupt},
		{"canceled_and_incomplete", errors.Join(overviewgeneration.ErrCanceled, overviewgeneration.ErrIncomplete), ErrCorrupt},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := packValidationError(tt.err); got != tt.want {
				t.Fatalf("validation error mapped to %v; want %v", got, tt.want)
			}
		})
	}
}

func TestStageValidatorCancellationPreservesAllocation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux private state tests")
	}
	for _, section := range []string{"processes", "volumes"} {
		for _, point := range packValidatorCancellationPoints {
			t.Run(section+"/"+point.name, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "overview")
				s, err := InitializeNew(dir, fixtureBinding, fixtureAgent, section)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				a := reserve(t, s)
				manifest, chunks := packCancellationPayloads(t, a, section, 1)
				before := directoryBytes(t, dir)
				// Stage's entry, first validator pass, and frame construction make
				// eight checks before the one-row pack's decode validation pass.
				ctx := newPackCancellationContext(t, 8+point.check, context.DeadlineExceeded, false)
				if err = s.Stage(ctx, a, manifest, chunks); err != ErrCanceled {
					t.Fatalf("Stage returned %v; want ErrCanceled", err)
				}
				if ctx.checks.Load() != 8+point.check || ctx.Context.Err() != context.Canceled {
					t.Fatal("Stage cancellation did not reach decode validation")
				}
				unchanged(t, dir, before)
				if s.inner.failed != nil || s.inner.pack != nil || !s.inner.matches(a) {
					t.Fatal("cancellation poisoned state, retained a pack, or consumed the allocation")
				}
				if floor, err := s.SequenceFloor(); err != nil || floor != a.Sequence {
					t.Fatal("cancellation changed the durable floor", err)
				}
				if err = s.Stage(context.Background(), a, manifest, chunks); err != nil {
					t.Fatal("same allocation could not be retried after cancellation", err)
				}
				original := next(t, s)
				if original.Operation != "begin" || original.Sequence != a.Sequence || original.GenerationID != a.GenerationID || !bytes.Contains(original.Body(), manifest) {
					t.Fatal("retry changed allocation identity or manifest bytes")
				}
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
				s, err = OpenExisting(dir, fixtureBinding, fixtureAgent, section)
				if err != nil {
					t.Fatal(err)
				}
				if recovered := next(t, s); !sameWork(original, recovered) || !bytes.Equal(original.Body(), recovered.Body()) {
					t.Fatal("retry was not durably published with exact bytes")
				}
			})
		}
	}
}
