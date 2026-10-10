package windowsprocessmetrics

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func selfRetentionPIDs() []uint32 {
	ids := make([]uint32, MaxRows)
	for i := 1; i < len(ids); i++ {
		ids[i] = uint32(1000 + 4*i)
	}
	return ids
}

func TestSelfRetentionSamplerAndEverySmallerBudget(t *testing.T) {
	for _, rank := range []int{39, 123, 127} {
		ids := selfRetentionPIDs()
		self := ids[rank]
		at := epoch
		kernel := uint64(0)
		var reads []uint32
		read := func(_ context.Context, pid uint32) Reading {
			reads = append(reads, pid)
			if pid == self {
				return Reading{Creation: 1, Kernel: kernel, Memory: 10485760}
			}
			if pid == 0 {
				return Reading{CPUErr: ErrUnavailable}
			}
			return Reading{CPUErr: ErrDenied}
		}
		sampler := NewSamplerWithReader(read, func() time.Time { return at }, 1)
		legacySampler := NewSamplerWithReader(read, func() time.Time { return at }, 1)
		if _, err := legacySampler.Sample(context.Background(), ids, generation, grant, at); err != nil {
			t.Fatal(err)
		}
		first, err := sampler.SampleWithSelfPID(context.Background(), ids, generation, grant, at, self)
		if err != nil {
			t.Fatal(err)
		}
		var firstSelf Process
		for _, row := range first.Rows {
			if row.PID == self {
				firstSelf = row
			}
		}
		if firstSelf.CPUQuality != "first-sample" || firstSelf.CPUPercent != nil || firstSelf.MemoryBytes == nil {
			t.Fatal("first sample was promoted", firstSelf)
		}
		at = at.Add(time.Second)
		kernel = 1000
		reads = nil
		s, err := sampler.SampleWithSelfPID(context.Background(), ids, generation, grant, at, self)
		if err != nil {
			t.Fatal(err)
		}
		if len(reads) != MaxRows || reads[0] != self || s.ObservedCount != MaxRows || !s.Truncated || len(s.Rows) != 123 || !s.CollectedAt.Equal(at) {
			t.Fatal("did not exercise 128 to 123 bound or self-first single read", rank, len(reads), len(s.Rows))
		}
		remaining := append([]uint32{}, ids[:rank]...)
		remaining = append(remaining, ids[rank+1:]...)
		if !reflect.DeepEqual(reads[1:], remaining) {
			t.Fatal("nonself reads not deterministic")
		}
		legacy, err := legacySampler.Sample(context.Background(), ids, generation, grant, at)
		if err != nil || len(legacy.Rows) != 123 {
			t.Fatal("legacy fixture no longer reproduces 128 to 123 trim", err)
		}
		counts := map[string]int{}
		for _, row := range legacy.Rows {
			counts[row.CPUQuality]++
		}
		wantObserved := 0
		if rank == 39 {
			wantObserved = 1
		}
		if counts["observed"] != wantObserved || counts["denied"] != 122-wantObserved || counts["unavailable"] != 1 {
			t.Fatal("legacy fixture does not reproduce native observed/denied/unavailable counts", rank, counts)
		}
		before, _ := json.Marshal(s)
		minimum := s
		minimum.Rows = nil
		for _, row := range s.Rows {
			if row.PID == self {
				minimum.Rows = []Process{row}
			}
		}
		if len(minimum.Rows) != 1 || minimum.Rows[0].CPUPercent == nil || *minimum.Rows[0].CPUPercent != 0.01 || minimum.Rows[0].MemoryBytes == nil || *minimum.Rows[0].MemoryBytes != "10485760" {
			t.Fatal("genuine observed self lost", rank)
		}
		minimumRaw, _ := json.Marshal(minimum)
		// Walk every smaller complete-row refit, including a protected-only tail.
		for len(s.Rows) > 1 {
			raw, _ := json.Marshal(s)
			s, err = FitBudgetWithSelfPID(s, len(raw)-1, self)
			if err != nil || Validate(s) != nil || s.ObservedCount != MaxRows || !s.CollectedAt.Equal(at) || !s.Truncated {
				t.Fatal("refit lost truth", err)
			}
			found := false
			for _, row := range s.Rows {
				found = found || row.PID == self
			}
			if !found {
				t.Fatal("downstream refit lost self")
			}
		}
		if _, err = FitBudgetWithSelfPID(s, len(minimumRaw)-1, self); err == nil {
			t.Fatal("removed unfit self instead of failing closed")
		}
		if empty, err := FitBudget(s, len(minimumRaw)-1); err != nil || len(empty.Rows) != 0 {
			t.Fatal("ordinary fitting unnecessarily blocked", err)
		}
		if len(before) > MaxBytes {
			t.Fatal("sampler exceeded byte limit")
		}
		at = at.Add(time.Second)
		zero, err := sampler.SampleWithSelfPID(context.Background(), ids, generation, grant, at, self)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range zero.Rows {
			if row.PID == self && (row.CPUQuality != "observed" || row.CPUPercent == nil || *row.CPUPercent != 0) {
				t.Fatal("genuine zero was withheld", row)
			}
		}
	}
}

func TestSelfRetentionMissingDeniedAndLegacyEquality(t *testing.T) {
	ids := selfRetentionPIDs()
	for _, self := range []uint32{0, ^uint32(0), ids[len(ids)-1]} {
		for _, failure := range []error{ErrDenied, ErrUnavailable} {
			var reads []uint32
			makeSampler := func() *Sampler {
				return NewSamplerWithReader(func(_ context.Context, pid uint32) Reading {
					reads = append(reads, pid)
					return Reading{CPUErr: failure}
				}, func() time.Time { return epoch }, 1)
			}
			s, err := makeSampler().SampleWithSelfPID(context.Background(), ids, generation, grant, epoch, self)
			if err != nil || len(reads) != len(ids) {
				t.Fatal(err, reads)
			}
			if self == 0 || self == ^uint32(0) {
				if !reflect.DeepEqual(reads, ids) {
					t.Fatal("absent self inserted or reordered reads")
				}
				legacy, err := makeSampler().Sample(context.Background(), ids, generation, grant, epoch)
				if err != nil || !reflect.DeepEqual(s, legacy) {
					t.Fatal("ordinary bytes changed", err)
				}
			} else {
				row := s.Rows[len(s.Rows)-1]
				if row.PID != self || row.CPUQuality != quality(failure) || row.MemoryQuality != quality(failure) || row.CPUPercent != nil || row.MemoryBytes != nil {
					t.Fatal("self failure promoted", row)
				}
			}
			before, _ := json.Marshal(s)
			trimmed, err := FitBudgetWithSelfPID(s, 1024, self)
			after, _ := json.Marshal(s)
			if err != nil || !bytes.Equal(before, after) || len(trimmed.Rows) >= len(s.Rows) {
				t.Fatal("refit mutates input", err)
			}
		}
	}
}

func TestSelfRetentionReadPriorityWithinUnchangedBudget(t *testing.T) {
	const self uint32 = 9999
	var reads []uint32
	s := NewSamplerWithReader(func(ctx context.Context, pid uint32) Reading {
		reads = append(reads, pid)
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > collectionBudget || time.Until(deadline) < collectionBudget-time.Second {
			t.Fatal("collection budget changed")
		}
		// Simulate the first synchronous native read consuming the whole budget.
		<-ctx.Done()
		return Reading{Creation: 1, Memory: 7}
	}, func() time.Time { return epoch }, 1)
	out, err := s.SampleWithSelfPID(context.Background(), []uint32{1, 2, self}, generation, grant, epoch, self)
	if err != nil || !reflect.DeepEqual(reads, []uint32{self}) || len(out.Rows) != 3 || out.Rows[0].PID != 1 || out.Rows[1].PID != 2 || out.Rows[2].PID != self || out.Rows[2].MemoryBytes == nil {
		t.Fatal("self starved or extra read", err, reads, out)
	}
	for _, row := range out.Rows[:2] {
		if row.CPUQuality != "unavailable" || row.MemoryQuality != "unavailable" || row.CPUPercent != nil || row.MemoryBytes != nil {
			t.Fatal("exhausted budget invented data")
		}
	}
}

func TestSelfRetentionDoesNotBypassInputAndAttributionGuards(t *testing.T) {
	calls := 0
	self := uint32(9999)
	at := epoch
	creation := uint64(at.Unix())*10000000 + 116444736000000000 + 1
	s := NewSamplerWithReader(func(context.Context, uint32) Reading { calls++; return Reading{Creation: creation, Memory: 42} }, func() time.Time { return at }, 1)
	for _, pids := range [][]uint32{{self, self}, make([]uint32, MaxRows+1)} {
		if _, err := s.SampleWithSelfPID(context.Background(), pids, generation, grant, at, self); err == nil {
			t.Fatal("self preference admitted invalid PID list")
		}
	}
	if _, err := s.SampleWithSelfPID(nil, []uint32{self}, generation, grant, at, self); err == nil {
		t.Fatal("nil context admitted")
	}
	if _, err := s.SampleWithSelfPID(context.Background(), []uint32{self}, generation, "", at, self); err == nil {
		t.Fatal("absent grant admitted")
	}
	if calls != 0 {
		t.Fatal("invalid input queried a process")
	}
	out, err := s.SampleWithSelfPID(context.Background(), []uint32{self}, generation, grant, at, self)
	if err != nil || calls != 1 || out.Rows[0].CPUQuality != "unavailable" || out.Rows[0].MemoryQuality != "unavailable" || out.Rows[0].MemoryBytes != nil {
		t.Fatal("self preference bypassed creation-after-capture guard", err, out)
	}
	creation = 1
	at = at.Add(time.Second)
	out, err = s.SampleWithSelfPID(context.Background(), []uint32{self}, generation, grant, at, self)
	if err != nil || out.Rows[0].CPUQuality != "first-sample" {
		t.Fatal("withheld identity created baseline", err, out)
	}
	creation = 2
	at = at.Add(time.Second)
	out, err = s.SampleWithSelfPID(context.Background(), []uint32{self}, generation, grant, at, self)
	if err != nil || out.Rows[0].CPUQuality != "reset" || out.Rows[0].CPUPercent != nil {
		t.Fatal("self preference bypassed PID reuse reset", err, out)
	}
}
