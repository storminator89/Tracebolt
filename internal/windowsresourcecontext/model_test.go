package windowsresourcecontext

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func requestFixture() Request {
	binding := strings.Repeat("a", 64)
	return Request{Consent: Consent{ConsentVersion, Scope, binding, strings.Repeat("b", 32), true}, SenderBinding: binding, GenerationID: "sample_" + strings.Repeat("c", 32), CollectedAt: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)}
}
func processorFixture(name string) Processor {
	cores, logical := uint32(MaxProcessorCount), uint32(MaxProcessorCount)
	return Processor{observedField(name, nil), architectureField(3, nil), countField(cores, nil), countField(logical, nil)}
}
func worstSnapshot(t *testing.T, n int) Snapshot {
	t.Helper()
	s := Empty(requestFixture(), ErrUnsupported.Error())
	rows := make([]Processor, n)
	for i := range rows {
		rows[i] = processorFixture(strings.Repeat("<", MaxStringUnits))
	}
	p, e := finishProcessors(rows)
	if e != nil {
		t.Fatal(e)
	}
	s.Processors = p
	s.InstalledMemory, e = installedMemoryFromKB(^uint64(0) / 1024)
	if e != nil {
		t.Fatal(e)
	}
	s.Memory, e = memoryFromPages(^uint64(0)/1024, ^uint64(0)/1024, ^uint64(0)/1024, ^uint64(0)/1024, 1024)
	if e != nil {
		t.Fatal(e)
	}
	s.Memory.PageSizeBytes = bytesValue(1 << 30)
	big := bytesValue((^uint64(0) / (1 << 30)) * (1 << 30))
	s.Memory.CommitTotalBytes = big
	s.Memory.CommitLimitBytes = big
	s.Memory.PhysicalTotalBytes = big
	s.Memory.PhysicalAvailableBytes = big
	count := uint32(MaxPagefiles)
	s.Pagefiles = Pagefiles{Quality: "observed", Source: "EnumPageFilesW", Count: &count, TotalBytes: bytesValue(^uint64(0)), TotalInUseBytes: bytesValue(^uint64(0))}
	return s
}
func TestCanonicalWorstSnapshotBounds(t *testing.T) {
	for _, n := range []int{4, 2} {
		s := worstSnapshot(t, n)
		b, e := json.Marshal(s)
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("%d maximal processor rows: %d canonical bytes", n, len(b))
		if (Validate(s) == nil) != (len(b) <= MaxBytes) {
			t.Fatal("wire bound not enforced")
		}
	}
	for _, reason := range []string{ErrDenied.Error(), ErrUnavailable.Error(), ErrUnsupported.Error(), ErrMetadata.Error(), ErrBounds.Error(), ErrPartial.Error(), ErrBudget.Error()} {
		empty := Empty(requestFixture(), reason)
		if _, e := Encode(empty); e != nil {
			t.Fatal(e)
		}
	}
}
func TestWorstFiniteFailures(t *testing.T) {
	for _, n := range []int{4, 2} {
		s := worstSnapshot(t, n)
		for i := range s.Processors.Rows {
			s.Processors.Rows[i].Cores = CountField{Quality: "unavailable"}
			s.Processors.Rows[i].LogicalProcessors = CountField{Quality: "unavailable"}
		}
		s.Processors, _ = finishProcessors(s.Processors.Rows)
		for _, reason := range []string{ErrDenied.Error(), ErrUnavailable.Error(), ErrUnsupported.Error(), ErrMetadata.Error(), ErrBounds.Error(), ErrPartial.Error(), ErrBudget.Error()} {
			v := EmptyInstalledMemory(reason)
			a, _ := json.Marshal(v)
			b, _ := json.Marshal(s.InstalledMemory)
			if len(a) > len(b) {
				s.InstalledMemory = v
			}
			m := EmptyMemory(reason)
			a, _ = json.Marshal(m)
			b, _ = json.Marshal(s.Memory)
			if len(a) > len(b) {
				s.Memory = m
			}
			p := EmptyPagefiles(reason)
			a, _ = json.Marshal(p)
			b, _ = json.Marshal(s.Pagefiles)
			if len(a) > len(b) {
				s.Pagefiles = p
			}
		}
		b, _ := json.Marshal(s)
		t.Logf("%d maximal mixed-state rows: %d bytes", n, len(b))
		if n == MaxProcessors && (len(b) != 4932 || len(b) > MaxBytes || Validate(s) != nil) {
			t.Fatal("worst valid state exceeds bounded envelope", len(b))
		}
		if n == 4 {
			for i := range s.Processors.Rows {
				s.Processors.Rows[i].Name = observedField(strings.Repeat("<", 96), nil)
			}
			b, _ = json.Marshal(s)
			t.Logf("4x96 mixed-state rows: %d bytes", len(b))
		}
	}
}

func TestCanonicalBindingAndClosedSchema(t *testing.T) {
	s := worstSnapshot(t, 2)
	b, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(append([]byte{}, b...), '\n'), bytes.Replace(b, []byte(`"scope":`), []byte(`"unknown":true,"scope":`), 1), bytes.Replace(b, []byte(`"scope":`), []byte(`"scope":"`+Scope+`","scope":`), 1)} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("noncanonical accepted")
		}
	}
	if ValidateBinding(s, s.GenerationID, strings.Repeat("d", 32), s.CollectedAt) == nil {
		t.Fatal("foreign grant accepted")
	}
	c := requestFixture()
	raw, e := EncodeConsent(c.Consent, c.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeConsent(raw, strings.Repeat("d", 64)); e == nil {
		t.Fatal("foreign consent accepted")
	}
}
func TestProcessorFieldQualityTotalsAndBounds(t *testing.T) {
	p, e := finishProcessors([]Processor{processorFixture("CPU"), processorFixture("CPU")})
	if e != nil || *p.TotalCores != 2*MaxProcessorCount {
		t.Fatal(e)
	}
	p.Rows[0].Cores = CountField{Quality: "unavailable"}
	p, e = finishProcessors(p.Rows)
	if e != nil || p.Quality != "partial" || p.TotalCores != nil || p.TotalLogicalProcessors != nil {
		t.Fatal("partial counts exposed totals")
	}
	if _, e = finishProcessors(make([]Processor, MaxProcessors+1)); !errors.Is(e, ErrBounds) {
		t.Fatal("row cutoff")
	}
	for _, bad := range []string{strings.Repeat("😀", 65), "x\n", string([]byte{0xff}), "�"} {
		if observedField(bad, nil).Quality != "unavailable" {
			t.Fatal("invalid label")
		}
	}
	if observedField(strings.Repeat("😀", 64), nil).Quality != "observed" {
		t.Fatal("UTF16 boundary")
	}
	if architectureField(4, nil).Value != nil {
		t.Fatal("unknown architecture")
	}
	if countField(0, nil).Value != nil || countField(MaxProcessorCount+1, nil).Value != nil {
		t.Fatal("invalid count")
	}
}
func TestExactBytesAndNativeArithmetic(t *testing.T) {
	for _, v := range []string{"", "00", "01", "+1", "-1", "1.0", "1e3", "18446744073709551616"} {
		if _, ok := decimal(&v); ok {
			t.Fatal("invalid decimal", v)
		}
	}
	if n, ok := decimal(bytesValue(^uint64(0))); !ok || n != ^uint64(0) {
		t.Fatal("uint64 max")
	}
	for _, kb := range []uint64{0, ^uint64(0), ^uint64(0)/1024 + 1} {
		if _, e := installedMemoryFromKB(kb); e == nil {
			t.Fatal("installed overflow/zero")
		}
	}
	if _, e := memoryFromPages(^uint64(0), ^uint64(0), 1, 0, 4096); e == nil {
		t.Fatal("pages overflow")
	}
	if _, e := memoryFromPages(2, 1, 1, 0, 4096); e == nil {
		t.Fatal("commit contradiction")
	}
	if _, e := memoryFromPages(1, 2, 1, 2, 4096); e == nil {
		t.Fatal("physical contradiction")
	}
}
func TestPagefilesAllOrNothing(t *testing.T) {
	a := pagefileAccumulator{}
	p, e := a.finish(true, 4096)
	if e != nil || p.Count == nil || *p.Count != 0 || *p.TotalBytes != "0" {
		t.Fatal("zero complete", e)
	}
	if !a.add(100, 20) || !a.add(200, 30) {
		t.Fatal("valid pages")
	}
	p, e = a.finish(true, 4096)
	if e != nil || *p.Count != 2 || *p.TotalBytes != "1228800" || *p.TotalInUseBytes != "204800" {
		t.Fatal("wrong aggregate", e)
	}
	if _, e = a.finish(false, 4096); e != ErrPartial {
		t.Fatal("partial retained")
	}
	for a.count < MaxPagefiles {
		if !a.add(1, 0) {
			t.Fatal("cap")
		}
	}
	if a.add(1, 0) {
		t.Fatal("33rd callback accepted")
	}
	if _, e = a.finish(true, 4096); e != ErrBounds {
		t.Fatal("cutoff retained")
	}
	a = pagefileAccumulator{}
	if a.add(1, 2) || a.err != ErrMetadata {
		t.Fatal("used exceeds size")
	}
	a = pagefileAccumulator{}
	if !a.add(^uint64(0), 0) || a.add(1, 0) {
		t.Fatal("sum overflow")
	}
	a = pagefileAccumulator{}
	a.add(^uint64(0), 0)
	if _, e = a.finish(true, 4096); e == nil {
		t.Fatal("byte overflow")
	}
}
func TestIndependentSourcesAndOversizedCPU(t *testing.T) {
	r := requestFixture()
	bad := worstSnapshot(t, 4)
	called := 0
	s, e := CollectWithSources(context.Background(), r, func(context.Context) (Processors, error) { called++; return Processors{}, ErrBounds }, func(context.Context) (InstalledMemory, error) { called++; return bad.InstalledMemory, nil }, func(context.Context) (Memory, error) { called++; return bad.Memory, nil }, func(context.Context) (Pagefiles, error) { called++; return bad.Pagefiles, nil })
	if e != nil || called != 4 || s.Processors.Reason != ErrBounds.Error() || s.InstalledMemory.Quality != "observed" || s.Memory.Quality != "observed" || s.Pagefiles.Quality != "observed" {
		t.Fatal("whole CPU failure erased memory", e)
	}
	r.Consent.Enabled = false
	called = 0
	if _, e = CollectWithSources(context.Background(), r, func(context.Context) (Processors, error) { called++; return Processors{}, nil }, nil, nil, nil); e != ErrDisabled || called != 0 {
		t.Fatal("disabled native")
	}
	r = requestFixture()
	s, e = CollectWithSources(context.Background(), r, func(context.Context) (Processors, error) { return Processors{}, errors.New("private details") }, nil, func(context.Context) (Memory, error) { return bad.Memory, nil }, nil)
	if e != nil || s.Processors.Reason != ErrUnavailable.Error() || s.Memory.Quality != "observed" {
		t.Fatal("independence")
	}
}

// Shared TS/Go fixture is synthetic and includes an integer above2^53.
func TestCrossLanguageCanonicalFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(s)
	if err != nil || !bytes.Equal(raw, encoded) {
		t.Fatal("cross-language canonical fixture", err)
	}
}
