package windowsstorageio

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func requestFixture() Request {
	binding := strings.Repeat("a", 64)
	return Request{Consent: Consent{SchemaVersion: ConsentVersion, Scope: Scope, SenderBinding: binding, GrantID: strings.Repeat("b", 32), Enabled: true}, SenderBinding: binding, GenerationID: "sample_" + strings.Repeat("c", 32), CollectedAt: time.Date(2026, 10, 11, 12, 34, 56, 123456789, time.UTC)}
}
func snapshotFixture() Snapshot {
	r := requestFixture()
	s := Empty(r, ErrUnavailable.Error())
	start, end := r.CollectedAt.Add(time.Second), r.CollectedAt.Add(2*time.Second)
	ms := uint64(1000)
	p := &s.PerfDisk
	p.SampleStartedAt = &start
	p.SampleEndedAt = &end
	p.IntervalMilliseconds = &ms
	for i, m := range metricPointers(p) {
		value := float64(i + 1)
		*m = Metric{Value: &value, Quality: "observed"}
	}
	summarize(p)
	return s
}
func TestCanonicalSnapshotAndConsent(t *testing.T) {
	s := snapshotFixture()
	raw, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Decode(raw); e != nil {
		t.Fatal(e)
	}
	fixture, e := os.ReadFile("testdata/snapshot.json")
	if e != nil || !bytes.Equal(raw, fixture) {
		t.Fatalf("snapshot fixture mismatch: %v", e)
	}
	c := requestFixture().Consent
	b, e := EncodeConsent(c, c.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := DecodeConsent(b, c.SenderBinding); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{nil, []byte("{}"), append(append([]byte{}, raw...), '\n'), append(append([]byte{}, raw...), raw...), bytes.Replace(raw, []byte(`"scope":`), []byte(`"other":1,"scope":`), 1), bytes.Replace(raw, []byte(`"scope":`), []byte(`"scope":"x","scope":`), 1), bytes.Replace(raw, []byte(`.123456789Z`), []byte(`.123456789+00:00`), 1), bytes.Replace(raw, []byte(`"value":1`), []byte(`"value":1.0`), 1), bytes.Repeat([]byte("x"), MaxBytes+1)} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("noncanonical snapshot accepted")
		}
	}
	for _, bad := range [][]byte{nil, append(append([]byte{}, b...), '\n'), bytes.Replace(b, []byte(`"enabled":true`), []byte(`"enabled":true,"enabled":true`), 1), bytes.Replace(b, []byte(Scope), []byte("windows-storage-context-v1"), 1)} {
		if _, e := DecodeConsent(bad, c.SenderBinding); e == nil {
			t.Fatal("noncanonical consent accepted")
		}
	}
	if _, e := DecodeConsent(b, strings.Repeat("d", 64)); e == nil {
		t.Fatal("foreign binding accepted")
	}
}
func TestSnapshotRejectsContradictoryAndUnsafeValues(t *testing.T) {
	for name, change := range map[string]func(*Snapshot){
		"negative":          func(s *Snapshot) { *s.PerfDisk.ReadBytesPerSecond.Value = -1 },
		"negative zero":     func(s *Snapshot) { *s.PerfDisk.ReadBytesPerSecond.Value = math.Copysign(0, -1) },
		"nan":               func(s *Snapshot) { *s.PerfDisk.ReadBytesPerSecond.Value = math.NaN() },
		"infinite":          func(s *Snapshot) { *s.PerfDisk.ReadBytesPerSecond.Value = math.Inf(1) },
		"observed null":     func(s *Snapshot) { s.PerfDisk.ReadBytesPerSecond.Value = nil },
		"denied value":      func(s *Snapshot) { s.PerfDisk.ReadBytesPerSecond.Quality = "denied" },
		"unknown reason":    func(s *Snapshot) { s.PerfDisk = EmptyPerfDisk("secret raw exception") },
		"false summary":     func(s *Snapshot) { s.PerfDisk.Quality = "unavailable" },
		"no window":         func(s *Snapshot) { s.PerfDisk.SampleStartedAt = nil },
		"short window":      func(s *Snapshot) { *s.PerfDisk.SampleEndedAt = s.PerfDisk.SampleStartedAt.Add(time.Millisecond) },
		"over budget":       func(s *Snapshot) { *s.PerfDisk.SampleEndedAt = s.PerfDisk.SampleStartedAt.Add(3 * time.Second) },
		"interval mismatch": func(s *Snapshot) { *s.PerfDisk.IntervalMilliseconds = 1001 },
		"pre capture":       func(s *Snapshot) { s.CollectedAt = s.PerfDisk.SampleStartedAt.Add(time.Millisecond) },
		"source spoof":      func(s *Snapshot) { s.PerfDisk.Source = "PhysicalDisk(*)" },
		"zero ops latency":  func(s *Snapshot) { *s.PerfDisk.ReadOperationsPerSecond.Value = 0 },
		"missing ops latency": func(s *Snapshot) {
			s.PerfDisk.ReadOperationsPerSecond = EmptyMetric(ErrMissing.Error())
			summarize(&s.PerfDisk)
		},
		"idle other": func(s *Snapshot) {
			s.PerfDisk.ReadBytesPerSecond = EmptyMetric(ErrIdle.Error())
			summarize(&s.PerfDisk)
		},
		"idle nonzero": func(s *Snapshot) {
			s.PerfDisk.ReadLatencySeconds = EmptyMetric(ErrIdle.Error())
			summarize(&s.PerfDisk)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := snapshotFixture()
			change(&s)
			if Validate(s) == nil {
				t.Fatal("invalid accepted")
			}
		})
	}
}
func TestIdleAndPartialAreNotInventedZeros(t *testing.T) {
	s := snapshotFixture()
	*s.PerfDisk.ReadOperationsPerSecond.Value = 0
	normalizeLatency(&s.PerfDisk)
	summarize(&s.PerfDisk)
	if Validate(s) != nil || s.PerfDisk.ReadLatencySeconds.Value != nil || s.PerfDisk.ReadLatencySeconds.Reason != ErrIdle.Error() || s.PerfDisk.Quality != "partial" || !Meaningful(s) {
		t.Fatal("idle distinction lost")
	}
	if Meaningful(Empty(requestFixture(), ErrDenied.Error())) {
		t.Fatal("empty is meaningful")
	}
	if ValidateBinding(s, s.GenerationID, s.GrantID, s.CollectedAt) != nil || ValidateBinding(s, "sample_"+strings.Repeat("d", 32), s.GrantID, s.CollectedAt) == nil {
		t.Fatal("binding failure")
	}
	b, _ := Encode(s)
	if _, e := FitBudget(s, len(b)-1); e != ErrBounds {
		t.Fatal("budget ignored")
	}
}
func TestMaximumEnvelope(t *testing.T) {
	// Longest legal per-field encoding is null/unavailable/unsupported-platform.
	// Enumerate every failure plus maximum-width observed numbers to verify that
	// claim; timestamps are maximally wide and intervalMilliseconds has four digits.
	longest := EmptyMetric(ErrUnsupported.Error())
	maxField, _ := json.Marshal(longest)
	for _, e := range []error{ErrDenied, ErrUnavailable, ErrUnsupported, ErrMetadata, ErrBounds, ErrBudget, ErrMissing, ErrReset, ErrTimebase, ErrIdle} {
		b, _ := json.Marshal(EmptyMetric(e.Error()))
		if len(b) > len(maxField) {
			t.Fatalf("longer metric %s", e)
		}
	}
	for _, v := range []float64{0, math.MaxFloat64, math.SmallestNonzeroFloat64, 1.2345678901234567e-123, 1.2345678901234567e20} {
		b, _ := json.Marshal(Metric{Value: &v, Quality: "observed"})
		if len(b) > len(maxField) {
			t.Fatal("observed metric exceeds maximum")
		}
	}
	s := Empty(requestFixture(), ErrUnsupported.Error())
	s.CollectedAt = time.Date(9999, 12, 31, 23, 59, 56, 999999999, time.UTC)
	start, end := s.CollectedAt, s.CollectedAt.Add(2*time.Second)
	ms := uint64(2000)
	s.PerfDisk.SampleStartedAt = &start
	s.PerfDisk.SampleEndedAt = &end
	s.PerfDisk.IntervalMilliseconds = &ms
	b, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("maximum canonical envelope = %d bytes; MaxBytes = %d", len(b), MaxBytes)
	// Keep this exact proof stable if the wire contract grows.
	const wantMaximum = 1385
	if wantMaximum != 0 && len(b) != wantMaximum {
		t.Fatalf("max changed: %d", len(b))
	}
	if len(b) > MaxBytes {
		t.Fatal("maximum exceeds advertised envelope")
	}
	// Partial summary is shorter than the longest unavailable summary, even if
	// replacing one of the longest metrics with any shorter status/value.
	p := s.PerfDisk
	p.Quality = "partial"
	p.Reason = ErrPartial.Error()
	pb, _ := json.Marshal(p)
	sb, _ := json.Marshal(s.PerfDisk)
	if len(pb) > len(sb) {
		t.Fatal("partial summary exceeds maximum")
	}
}
func TestCollectValidatesAuthorityAndSanitizes(t *testing.T) {
	for _, change := range []func(*Request){func(r *Request) { r.Consent.Enabled = false }, func(r *Request) { r.SenderBinding = strings.Repeat("d", 64) }, func(r *Request) { r.GenerationID = "bad" }, func(r *Request) { r.CollectedAt = time.Time{} }} {
		r := requestFixture()
		change(&r)
		called := false
		_, e := CollectWithSource(context.Background(), r, func(context.Context) (PerfDisk, error) { called = true; return PerfDisk{}, nil })
		if e == nil || called {
			t.Fatal("invalid authority invoked source")
		}
	}
	r := requestFixture()
	s, e := CollectWithSource(context.Background(), r, func(context.Context) (PerfDisk, error) { return PerfDisk{}, errorsForTest{} })
	if e != nil || s.PerfDisk.Reason != ErrUnavailable.Error() {
		t.Fatal("raw error escaped")
	}
	s, e = CollectWithSource(context.Background(), r, func(context.Context) (PerfDisk, error) { return PerfDisk{}, nil })
	if e != nil || s.PerfDisk.Reason != ErrMetadata.Error() {
		t.Fatal("invalid source accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := CollectWithSource(ctx, r, nil); e != context.Canceled {
		t.Fatal("cancellation lost")
	}
}

type errorsForTest struct{}

func (errorsForTest) Error() string { return "arbitrary private error" }
