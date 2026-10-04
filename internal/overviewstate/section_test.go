package overviewstate

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/completeoverview"
	"localrmm/internal/overviewgeneration"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFixedSectionDomainsRejectCrossWorkAndSpools(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux state")
	}
	root := t.TempDir()
	pd, vd := filepath.Join(root, "processes"), filepath.Join(root, "volumes")
	p, e := InitializeNew(pd, fixtureBinding, fixtureAgent, "processes")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	v, e := InitializeNew(vd, fixtureBinding, fixtureAgent, "volumes")
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	pa, e := p.Allocate(context.Background(), fixtureAt)
	if e != nil {
		t.Fatal(e)
	}
	va, e := v.Allocate(context.Background(), fixtureAt)
	if e != nil {
		t.Fatal(e)
	}
	if pa.Sequence != 1 || va.Sequence != 1 || pa.GenerationID == va.GenerationID {
		t.Fatal("section identity collision")
	}
	if p.StageFailure(context.Background(), pa, "collection_failed") != nil || v.StageFailure(context.Background(), va, "source_missing") != nil {
		t.Fatal("stage")
	}
	pw, vw := next(t, p), next(t, v)
	if e = p.Acknowledge(vw, receipt(t, vw)); !errors.Is(e, ErrAcknowledgment) {
		t.Fatal("cross-section work acknowledged", e)
	}
	if e = p.Acknowledge(pw, receipt(t, vw)); !errors.Is(e, ErrAcknowledgment) {
		t.Fatal("cross-section receipt acknowledged", e)
	}
	if e = p.Acknowledge(pw, receipt(t, pw)); e != nil {
		t.Fatal(e)
	}
	if a, e := p.Allocate(context.Background(), fixtureAt); e != nil || a.Sequence != 2 {
		t.Fatal("process sequence")
	}
	if n, e := v.SequenceFloor(); e != nil || n != 1 {
		t.Fatal("volume sequence coupled")
	}
	p.Close()
	v.Close()
	if s, e := OpenExisting(pd, fixtureBinding, fixtureAgent, "volumes"); !errors.Is(e, ErrBinding) {
		if s != nil {
			s.Close()
		}
		t.Fatal("wrong section binding", e)
	}
	if e = os.Rename(pd, pd+"-swap"); e != nil {
		t.Fatal(e)
	}
	os.Rename(vd, pd)
	os.Rename(pd+"-swap", vd)
	if e = ValidateExisting(pd, fixtureBinding, fixtureAgent, "processes"); !errors.Is(e, ErrBinding) {
		t.Fatal("swapped domain accepted", e)
	}
}
func TestVolumeSpoolKeepsOriginalCaptureContextAndEmptyComplete(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux state")
	}
	dir := filepath.Join(t.TempDir(), "volumes")
	s, e := InitializeNew(dir, fixtureBinding, fixtureAgent, "volumes")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	a, e := s.Allocate(context.Background(), fixtureAt)
	if e != nil {
		t.Fatal(e)
	}
	captureID := "sample_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	source := completeoverview.Empty(captureID, fixtureAt, completeoverview.ReasonPermissionDenied)
	count := uint64(0)
	source.Volumes = completeoverview.VolumeSection{Meta: completeoverview.SectionMeta{GenerationID: captureID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &count, CountExact: true}, Items: []completeoverview.Volume{}}
	m, chunks, e := overviewgeneration.Build(context.Background(), source, "volumes", a.GenerationID, nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(m)
	if len(chunks) != 0 || s.Stage(context.Background(), a, raw, nil) != nil {
		t.Fatal("empty completed volume stage")
	}
	s.Close()
	s, e = OpenExisting(dir, fixtureBinding, fixtureAgent, "volumes")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for _, op := range []string{"begin", "finalize"} {
		w := next(t, s)
		if w.Operation != op || w.Section != "volumes" {
			t.Fatal("wrong work")
		}
		if e = s.Acknowledge(w, receipt(t, w)); e != nil {
			t.Fatal(e)
		}
	}
	if at, e := s.LastAttemptedAt(); e != nil || !at.Equal(fixtureAt) {
		t.Fatal("original capture time lost")
	}
}
