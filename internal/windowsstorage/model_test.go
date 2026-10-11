package windowsstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func requestFixture() Request {
	b := strings.Repeat("a", 64)
	return Request{Consent: Consent{ConsentVersion, Scope, b, strings.Repeat("b", 32), true}, SenderBinding: b, GenerationID: "sample_" + strings.Repeat("c", 32), CollectedAt: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
}
func snapshotFixture() Snapshot {
	s := Empty(requestFixture(), ErrUnavailable.Error())
	guid := `\\?\Volume{11111111-1111-1111-1111-111111111111}\`
	s.Drives = Drives{Quality: "observed", Rows: []Drive{{Letter: "C:", DriveType: "fixed", VolumeGUID: &guid, Quality: "observed"}}, ObservedCount: 1, CountExact: true, Complete: true}
	name := "Fixture SSD"
	zero := uint16(0)
	bus := uint16(17)
	size := "18446744073709551615"
	s.Disks = Disks{Quality: "partial", Reason: ErrPartial.Error(), Rows: []Disk{{Index: 0, DeviceID: Field{Quality: "empty"}, FriendlyName: Field{&name, "observed"}, HealthStatus: &zero, OperationalStatus: []uint16{2}, BusType: &bus, SizeBytes: &size}}, ObservedCount: 1, CountExact: true, Complete: true}
	return s
}
func TestStorageCanonicalBoundsAndMeaning(t *testing.T) {
	s := snapshotFixture()
	raw, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(raw); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"disks":`), []byte(`"smartHealth":"good","disks":`), 1), bytes.Replace(raw, []byte(`"sizeBytes":"18446744073709551615"`), []byte(`"sizeBytes":"18446744073709551616"`), 1), bytes.Replace(raw, []byte(`"healthStatus":0`), []byte(`"healthStatus":-1`), 1), bytes.Replace(raw, []byte(`"operationalStatus":[2]`), []byte(`"operationalStatus":[2,2]`), 1)} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("invalid storage accepted", string(bad))
		}
	}
	for _, mutate := range []func(*Snapshot){func(s *Snapshot) { s.Drives.Rows[0].VolumeGUID = nil }, func(s *Snapshot) { s.Drives.Rows[0].DriveType = "remote" }, func(s *Snapshot) { s.Disks.Rows[0].Index = 2 }, func(s *Snapshot) { s.Disks.Rows[0].OperationalStatus = nil }, func(s *Snapshot) { s.Disks.Truncated = true }, func(s *Snapshot) { s.Disks.ObservedCount = 65 }} {
		copy := snapshotFixture()
		mutate(&copy)
		if Validate(copy) == nil {
			t.Fatal("contradictory storage accepted")
		}
	}
	// Unknown provider values and absent counters remain unknown, never fabricated health.
	future := uint16(65535)
	s.Disks.Rows[0].HealthStatus = &future
	s.Disks.Rows[0].SizeBytes = nil
	if Validate(s) != nil {
		t.Fatal("future provider status should stay visible")
	}
}
func TestStorageFitKeepsCountGrantAndOriginalAge(t *testing.T) {
	s := snapshotFixture()
	for i := 1; i < MaxDiskRows; i++ {
		row := s.Disks.Rows[0]
		row.Index = i
		s.Disks.Rows = append(s.Disks.Rows, row)
	}
	s.Disks.ObservedCount = MaxDiskRows
	raw, _ := json.Marshal(s)
	fit, e := FitBudget(s, len(raw)-100)
	if e != nil || Validate(fit) != nil || !fit.Disks.Truncated || fit.Disks.Complete || fit.Disks.ObservedCount != MaxDiskRows || fit.GrantID != s.GrantID || !fit.CollectedAt.Equal(s.CollectedAt) {
		t.Fatal("trim lost evidence", e)
	}
	if _, e := FitBudget(s, 1); e != ErrBounds {
		t.Fatal("impossible budget", e)
	}
}
func TestStorageDefaultOffAndIndependentSources(t *testing.T) {
	r := requestFixture()
	calls := 0
	source := func(context.Context) (Drives, error) { calls++; return Drives{}, ErrDenied }
	r.Consent.Enabled = false
	if _, e := CollectWithSources(context.Background(), r, source, nil); e != ErrDisabled || calls != 0 {
		t.Fatal("disabled read")
	}
	r.Consent.Enabled = true
	s, e := CollectWithSources(context.Background(), r, source, func(context.Context) (Disks, error) { return snapshotFixture().Disks, nil })
	if e != nil || s.Drives.Quality != "denied" || len(s.Disks.Rows) != 1 {
		t.Fatal("sibling source lost", e)
	}
	r.Consent.Scope = "windows-visible-volumes-v1"
	if _, e := CollectWithSources(context.Background(), r, source, nil); e == nil || calls != 1 {
		t.Fatal("old grant promoted")
	}
}

type fakeDriveAPI struct {
	remoteCalls int
	bad         bool
}

func (f *fakeDriveAPI) mask() (uint32, error) { return (1 << 2) | (1 << 3) | (1 << 25), nil }
func (f *fakeDriveAPI) driveType(l byte) (uint32, error) {
	if l == 'Z' {
		return 4, nil
	}
	return 3, nil
}
func (f *fakeDriveAPI) volume(l byte) (string, error) {
	if l == 'Z' {
		f.remoteCalls++
		return "", ErrDenied
	}
	if l == 'D' {
		return "", ErrDenied
	}
	if f.bad {
		return `C:\private`, nil
	}
	return `\\?\VOLUME{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}\`, nil
}
func TestDriveMappingExactRootsSkipsRemoteAndKeepsDenied(t *testing.T) {
	f := &fakeDriveAPI{}
	s, e := collectDrives(context.Background(), f)
	if e != nil || !validDrives(s) || len(s.Rows) != 2 || s.Rows[0].Letter != "C:" || s.Rows[0].VolumeGUID == nil || *s.Rows[0].VolumeGUID != `\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\` || s.Rows[1].Quality != "denied" || f.remoteCalls != 0 || !s.Complete || s.Quality != "partial" {
		t.Fatalf("mapping %+v %v", s, e)
	}
	f.bad = true
	s, e = collectDrives(context.Background(), f)
	if e != nil || s.Rows[0].VolumeGUID != nil || s.Rows[0].Reason != ErrMetadata.Error() {
		t.Fatal("path masqueraded as GUID")
	}
}

func TestStorageNativeMaximumFitsBoundedWireWithoutChangingMeaning(t *testing.T) {
	s := snapshotFixture()
	name := strings.Repeat("界", 128)
	id := strings.Repeat("界", 64)
	s.Disks.Rows = nil
	for i := 0; i < MaxDiskRows; i++ {
		r := snapshotFixture().Disks.Rows[0]
		r.Index = i
		r.DeviceID = Field{&id, "observed"}
		r.FriendlyName = Field{&name, "observed"}
		s.Disks.Rows = append(s.Disks.Rows, r)
	}
	s.Disks.ObservedCount = MaxDiskRows
	fit, e := FitBudget(s, MaxBytes)
	if e != nil || Validate(fit) != nil || !fit.Disks.Truncated || len(fit.Disks.Rows) >= MaxDiskRows || fit.Disks.ObservedCount != MaxDiskRows || fit.GenerationID != s.GenerationID {
		t.Fatal("wire bound lost native truth", e)
	}
}
