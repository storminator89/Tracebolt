package windowsprocessmetrics

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const generation = "sample_0123456789abcdef0123456789abcdef"
const grant = "0123456789abcdef0123456789abcdef"

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func fixture(t *testing.T) Snapshot {
	t.Helper()
	at := epoch
	s := NewSamplerWithReader(func(context.Context, uint32) Reading { return Reading{Creation: 1, Memory: 123} }, func() time.Time { return at }, 4)
	v, e := s.Sample(context.Background(), []uint32{8}, generation, grant, epoch)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestContractStrict(t *testing.T) {
	s := fixture(t)
	b, _ := json.Marshal(s)
	if _, e := Decode(b); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{string(b) + " ", strings.Replace(string(b), `"scope":`, `"unknown":0,"scope":`, 1), strings.Replace(string(b), `"pid":8`, `"pid":8,"pid":8`, 1), strings.Replace(string(b), `"cpuPercent":null`, `"cpuPercent":0`, 1), strings.Replace(string(b), `"memoryBytes":"123"`, `"memoryBytes":"0123"`, 1), strings.Replace(string(b), `"rows":[`, `"rows":null,"rows":[`, 1), strings.Replace(string(b), `"truncated":false`, `"truncated":null`, 1)} {
		if _, e := Decode([]byte(raw)); e == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
func TestIntervalReuseResetDenied(t *testing.T) {
	at := epoch
	n := Reading{Creation: 1, Memory: 0}
	calls := 0
	s := NewSamplerWithReader(func(_ context.Context, p uint32) Reading {
		calls++
		if p != 42 {
			t.Fatalf("unexpected PID %d", p)
		}
		return n
	}, func() time.Time { return at }, 4)
	sample := func() Process {
		t.Helper()
		v, e := s.Sample(context.Background(), []uint32{42}, generation, grant, at)
		if e != nil {
			t.Fatal(e)
		}
		return v.Rows[0]
	}
	r := sample()
	if r.CPUQuality != "first-sample" || r.CPUPercent != nil || *r.MemoryBytes != "0" {
		t.Fatal(r)
	}
	at = at.Add(time.Second)
	n.Kernel = 15000000
	n.User = 5000000
	r = sample()
	if r.CPUQuality != "observed" || *r.CPUPercent != 200 {
		t.Fatal(r)
	}
	at = at.Add(time.Second)
	n.Creation = 2
	n.Kernel = 1
	n.User = 1
	r = sample()
	if r.CPUQuality != "reset" || r.CPUPercent != nil {
		t.Fatal(r)
	}
	at = at.Add(time.Second)
	n.Kernel = 0
	r = sample()
	if r.CPUQuality != "reset" {
		t.Fatal(r)
	}
	at = at.Add(time.Second)
	n.CPUErr = ErrDenied
	r = sample()
	if r.CPUQuality != "denied" || r.MemoryQuality != "denied" || r.MemoryBytes != nil {
		t.Fatal(r)
	}
	at = at.Add(time.Second)
	n.CPUErr = nil
	r = sample()
	if r.CPUQuality != "first-sample" {
		t.Fatal(r)
	}
	if calls != 6 {
		t.Fatal(calls)
	}
}
func TestAttributionAndStateDropped(t *testing.T) {
	at := epoch
	creation := uint64(epoch.Unix())*10000000 + 116444736000000000 + 1
	s := NewSamplerWithReader(func(context.Context, uint32) Reading { return Reading{Creation: creation} }, func() time.Time { return at }, 1)
	v, e := s.Sample(context.Background(), []uint32{1}, generation, grant, epoch)
	if e != nil || v.Rows[0].MemoryBytes != nil || v.Rows[0].CPUQuality != "unavailable" {
		t.Fatal(v, e)
	}
	creation = 1
	at = at.Add(time.Second)
	v, e = s.Sample(context.Background(), []uint32{1}, generation, grant, at)
	if e != nil || v.Rows[0].CPUQuality != "first-sample" {
		t.Fatal(v, e)
	}
	_, e = s.Sample(context.Background(), nil, generation, grant, at.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	at = at.Add(2 * time.Second)
	v, e = s.Sample(context.Background(), []uint32{1}, generation, grant, at)
	if e != nil || v.Rows[0].CPUQuality != "first-sample" {
		t.Fatal(v, e)
	}
	at = at.Add(time.Second)
	v, e = s.Sample(context.Background(), []uint32{1}, generation, strings.Repeat("b", 32), at)
	if e != nil || v.Rows[0].CPUQuality != "first-sample" {
		t.Fatal(v, e)
	}
}
func TestBoundsAndNoReadOnInvalid(t *testing.T) {
	calls := 0
	s := NewSamplerWithReader(func(context.Context, uint32) Reading { calls++; return Reading{Creation: 1, Memory: ^uint64(0)} }, func() time.Time { return epoch }, 8)
	for _, pids := range [][]uint32{{1, 1}, make([]uint32, 129)} {
		if _, e := s.Sample(context.Background(), pids, generation, grant, epoch); e == nil {
			t.Fatal("accepted invalid PIDs")
		}
	}
	if _, e := s.Sample(context.Background(), []uint32{1}, generation, "", epoch); e == nil {
		t.Fatal("accepted absent grant")
	}
	if calls != 0 {
		t.Fatal(calls)
	}
	ids := make([]uint32, 128)
	for i := range ids {
		ids[i] = uint32(128 - i)
	}
	v, e := s.Sample(context.Background(), ids, generation, grant, epoch)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(v)
	if len(b) > MaxBytes || !v.Truncated || v.ObservedCount != 128 || calls != 128 {
		t.Fatal(len(b), v.Truncated, calls)
	}
	smaller, e := FitBudget(v, 1024)
	if e != nil || len(smaller.Rows) >= len(v.Rows) || !smaller.CollectedAt.Equal(v.CollectedAt) || smaller.ObservedCount != 128 {
		t.Fatal(smaller, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = s.Sample(ctx, []uint32{1}, generation, grant, epoch); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestCPUClockAndCounterAnomalies(t *testing.T) {
	at := epoch
	n := Reading{Creation: 1}
	s := NewSamplerWithReader(func(context.Context, uint32) Reading { return n }, func() time.Time { return at }, 1)
	s.Sample(context.Background(), []uint32{1}, generation, grant, at)
	n.Kernel = 10000000
	v, e := s.Sample(context.Background(), []uint32{1}, generation, grant, at)
	if e != nil || v.Rows[0].CPUQuality != "reset" {
		t.Fatal(v, e)
	}
	at = at.Add(time.Second)
	n.Kernel = 40000000
	v, e = s.Sample(context.Background(), []uint32{1}, generation, grant, at)
	if e != nil || v.Rows[0].CPUQuality != "reset" {
		t.Fatal(v, e)
	}
}

func TestIndependentMemoryFailureAndSampleTime(t *testing.T) {
	at := epoch.Add(time.Minute)
	n := Reading{Creation: 1, MemoryErr: ErrDenied}
	s := NewSamplerWithReader(func(context.Context, uint32) Reading { return n }, func() time.Time { return at }, 2)
	v, e := s.Sample(context.Background(), []uint32{1}, generation, grant, epoch)
	if e != nil || !v.CollectedAt.Equal(at) || v.Rows[0].CPUQuality != "first-sample" || v.Rows[0].MemoryQuality != "denied" {
		t.Fatal(v, e)
	}
	at = at.Add(time.Second)
	n.User = 10000000
	v, e = s.Sample(context.Background(), []uint32{1}, generation, grant, epoch.Add(time.Second))
	if e != nil || v.Rows[0].CPUPercent == nil || *v.Rows[0].CPUPercent != 100 || v.Rows[0].MemoryBytes != nil {
		t.Fatal(v, e)
	}
}

func TestResetDropsBaselineWithoutReads(t *testing.T) {
	at := epoch
	calls := 0
	n := Reading{Creation: 1}
	s := NewSamplerWithReader(func(context.Context, uint32) Reading { calls++; return n }, func() time.Time { return at }, 1)
	if _, e := s.Sample(context.Background(), []uint32{1}, generation, grant, at); e != nil {
		t.Fatal(e)
	}
	s.Reset()
	if calls != 1 || len(s.previous) != 0 || s.grant != "" || !s.captured.IsZero() {
		t.Fatal("reset retained state or read process", calls)
	}
	at = at.Add(time.Second)
	n.User = 10000000
	v, e := s.Sample(context.Background(), []uint32{1}, generation, grant, at)
	if e != nil || v.Rows[0].CPUQuality != "first-sample" || v.Rows[0].CPUPercent != nil {
		t.Fatal(v, e)
	}
	var absent *Sampler
	absent.Reset()
}
