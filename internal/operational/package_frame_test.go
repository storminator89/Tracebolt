package operational

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func packageFrameDense(t *testing.T) Snapshot {
	t.Helper()
	s := Empty(testNow(), ReasonNotSupported)
	s.DurationMS = 123
	s.Sections.Software = available[Software](s.CollectedAt, SoftwareLimit)
	for i := range 160 {
		s.Sections.Software.Items = append(s.Sections.Software.Items, Software{Name: fmt.Sprintf("package-%03d", i), Version: "1." + strings.Repeat("1", 170), Architecture: "amd64", Manager: "dpkg"})
	}
	s.Sections.Software.Meta.ObservedCount = 160
	stampGeneration(&s)
	if Validate(s) != nil {
		t.Fatal("invalid dense fixture")
	}
	raw, _ := json.Marshal(s)
	if len(raw) <= MaxPackageFrameSnapshotBytes {
		t.Fatal("fixture not dense enough")
	}
	return s
}

func TestTrimForPackageFramePreservesOriginalAndProvenance(t *testing.T) {
	s := packageFrameDense(t)
	before, _ := json.Marshal(s)
	bounded, err := TrimForPackageFrame(s)
	if err != nil || Validate(bounded) != nil {
		t.Fatal("trim rejected valid snapshot", err)
	}
	raw, _ := json.Marshal(bounded)
	after, _ := json.Marshal(s)
	if len(raw) > MaxPackageFrameSnapshotBytes || !bytes.Equal(before, after) || bounded.GenerationID != s.GenerationID || !bounded.CollectedAt.Equal(s.CollectedAt) || bounded.DurationMS != s.DurationMS || bounded.CollectionProfile != CollectionProfile {
		t.Fatal("budget, input ownership or capture provenance changed")
	}
	m := bounded.Sections.Software.Meta
	if m.ObservedCount != 160 || !m.CountExact || m.Complete || !m.Truncated || m.Reason != ReasonByteLimit || len(bounded.Sections.Software.Items) >= 160 {
		t.Fatal("omitted rows not explicit or counts rewritten")
	}
	second, err := TrimForPackageFrame(s)
	secondRaw, _ := json.Marshal(second)
	if err != nil || !bytes.Equal(raw, secondRaw) {
		t.Fatal("trim not deterministic")
	}
	bounded.Sections.Software.Items[0].Name = "changed"
	if s.Sections.Software.Items[0].Name == "changed" {
		t.Fatal("slice aliases input")
	}
}

func TestTrimForPackageFrameClonesNestedPointers(t *testing.T) {
	s := Empty(testNow(), ReasonNotSupported)
	s.Sections.Processes = available[Process](s.CollectedAt, ProcessLimit)
	s.Sections.Processes.Meta.ObservedCount = 1
	s.Sections.Processes.Items = []Process{{PID: 1, ParentPID: pointer(uint64(0)), Name: "fixture", State: "running", RSSBytes: pointer(uint64(1)), CPUTimeSeconds: pointer(float64(1)), Threads: pointer(uint64(1))}}
	stampGeneration(&s)
	bounded, err := TrimForPackageFrame(s)
	if err != nil {
		t.Fatal(err)
	}
	*bounded.Sections.Processes.Items[0].RSSBytes = 999
	if *s.Sections.Processes.Items[0].RSSBytes != 1 {
		t.Fatal("nested pointer aliases input")
	}
}

func TestTrimForPackageFrameFailsClosedAndCanDropAllRows(t *testing.T) {
	s := packageFrameDense(t)
	minimal := s
	minimal.Sections.Software.Items = []Software{}
	partial(&minimal.Sections.Software.Meta, ReasonByteLimit, true)
	minimal.Sections.Software.Meta.Quality = Unknown
	raw, _ := json.Marshal(minimal)
	out, err := trimForPackageFrame(s, len(raw))
	if err != nil || len(out.Sections.Software.Items) != 0 || out.Sections.Software.Meta.ObservedCount != 160 || !out.Sections.Software.Meta.CountExact || out.Sections.Software.Meta.Complete || !out.Sections.Software.Meta.Truncated || out.Sections.Software.Meta.Quality != Unknown {
		t.Fatal("empty bounded envelope lost partial counts", err)
	}
	if _, err := trimForPackageFrame(s, len(raw)-1); err == nil {
		t.Fatal("minimal envelope overflow accepted")
	}
	for _, budget := range []int{0, -1, MaxPackageFrameSnapshotBytes + 1} {
		if _, err := trimForPackageFrame(s, budget); err == nil {
			t.Fatal("invalid budget accepted")
		}
	}
	s.CollectionProfile = "managed-operations-v2"
	if _, err := TrimForPackageFrame(s); err == nil {
		t.Fatal("relabeled operational snapshot accepted")
	}
}
