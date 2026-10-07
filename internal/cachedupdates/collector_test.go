package cachedupdates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const sample = "sample_0123456789abcdef0123456789abcdef"

var at = time.Date(2026, 10, 5, 4, 0, 0, 0, time.UTC)

func stringPtr(s string) *string { return &s }
func testConsent() LocalConsent {
	return LocalConsent{SchemaVersion: ConsentVersion, ExtensionVersion: SchemaVersion, Scope: Scope, SenderBinding: strings.Repeat("a", 64), Acknowledged: true}
}

type fixtureSource struct {
	release    linuxpackages.ReleaseFields
	packages   []installedPackage
	candidates map[string]string
	oldest     time.Time
	failure    error
	calls      []string
}

func fixture(distro string) *fixtureSource {
	version, codename := "13", "trixie"
	if distro == "ubuntu" {
		version, codename = "24.04", "noble"
	}
	return &fixtureSource{release: linuxpackages.ReleaseFields{ID: stringPtr(distro), VersionID: &version, VersionCodename: &codename}, packages: []installedPackage{{"curl", "amd64", "1:8.14.1-2", false}, {"held-package", "amd64", "2.0~rc1-1", true}}, candidates: map[string]string{"curl:amd64": "1:8.14.1-2+deb13u1", "held-package:amd64": "2.0-1"}, oldest: at.Add(-time.Hour)}
}
func (f *fixtureSource) inventory(_ context.Context, g string, a time.Time) (fullinventory.SourceInventory, error) {
	f.calls = append(f.calls, "inventory")
	if f.failure != nil {
		return fullinventory.SourceInventory{}, f.failure
	}
	rows := []linuxpackages.PackageRow{}
	for _, p := range f.packages {
		rows = append(rows, linuxpackages.PackageRow{Name: p.name, Architecture: p.architecture, Version: p.version, SourcePackage: p.name, SourceVersion: p.version, SourceMapping: "binary-default", InstallState: "installed"})
	}
	return fullinventory.SourceInventory{GenerationID: g, CollectedAt: a, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Fields: f.release}, Rows: rows}, nil
}
func (f *fixtureSource) metadata(context.Context) (time.Time, error) {
	f.calls = append(f.calls, "metadata")
	return f.oldest, nil
}
func (f *fixtureSource) holds(context.Context) (map[string]installedPackage, error) {
	f.calls = append(f.calls, "holds")
	out := map[string]installedPackage{}
	for _, p := range f.packages {
		out[p.key()] = p
	}
	return out, nil
}
func (f *fixtureSource) policy(_ context.Context, p []installedPackage) (map[string]string, error) {
	f.calls = append(f.calls, "policy")
	out := map[string]string{}
	for _, row := range p {
		if v, ok := f.candidates[row.key()]; ok {
			out[row.key()] = v
		}
	}
	return out, nil
}
func (f *fixtureSource) recheck(context.Context) error {
	f.calls = append(f.calls, "recheck")
	return nil
}
func (f *fixtureSource) close() { f.calls = append(f.calls, "close") }
func collectFixture(t *testing.T, f *fixtureSource) Snapshot {
	t.Helper()
	s, e := collectWith(context.Background(), sample, at, testConsent(), strings.Repeat("a", 64), &atomic.Bool{}, func() (nativeSource, error) { return f, nil })
	if e != nil {
		t.Fatal(e)
	}
	if e = Validate(s); e != nil {
		t.Fatalf("invalid snapshot: %v %+v", e, s)
	}
	raw, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeStrict(raw); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestSupportedDebianAndUbuntuCandidatesAndHolds(t *testing.T) {
	for _, d := range []string{"debian", "ubuntu"} {
		t.Run(d, func(t *testing.T) {
			f := fixture(d)
			s := collectFixture(t, f)
			if s.Coverage != "complete" || *s.CandidateCount != 2 || *s.HeldCount != 1 || *s.CheckedCount != 2 || len(s.Items) != 2 || s.Items[1].State != "held" || s.Items[0].Installability != "not_evaluated" || s.Metadata.Freshness != "unknown" {
				t.Fatalf("wrong candidate semantics: %+v", s)
			}
			if strings.Join(f.calls, ",") != "inventory,metadata,holds,policy,recheck,close" {
				t.Fatal(f.calls)
			}
		})
	}
	t.Run("arm64-with-foreign-and-all-packages", func(t *testing.T) {
		// pi-gen's 64-bit image enables foreign armhf packages too. Keeping them
		// in the package inventory does not add a 32-bit agent runtime target.
		f := fixture("debian")
		f.packages = []installedPackage{
			{"shared-package", "arm64", "1.0-1", false},
			{"shared-package", "armhf", "1.0-1", true},
			{"common-data", "all", "1.0-1", false},
		}
		f.candidates = map[string]string{
			"shared-package:arm64": "2.0-1",
			"shared-package:armhf": "2.0-1",
			"common-data:all":      "1.0-1",
		}
		s := collectFixture(t, f)
		if s.Coverage != "complete" || *s.InstalledCount != 3 || *s.CheckedCount != 3 || *s.CandidateCount != 2 || *s.HeldCount != 1 || len(s.Items) != 2 {
			t.Fatal("ARM64 multiarch inventory counts")
		}
		if s.Items[0].Architecture != "arm64" || s.Items[0].State != "candidate_only" || s.Items[1].Architecture != "armhf" || s.Items[1].State != "held" {
			t.Fatal("multiarch candidates or holds conflated")
		}
		if strings.Join(f.calls, ",") != "inventory,metadata,holds,policy,policy,policy,recheck,close" {
			t.Fatal("APT policy was not batched by architecture")
		}
	})
}
func TestStaleSourceAgeIsNotRefreshedByRead(t *testing.T) {
	f := fixture("debian")
	f.oldest = at.Add(-7 * 24 * time.Hour)
	s := collectFixture(t, f)
	if s.Metadata.Freshness != "stale" || *s.Metadata.AgeSeconds != 7*86400 || !s.Metadata.OldestIndexModifiedAt.Equal(f.oldest) {
		t.Fatal(s.Metadata)
	}
}
func TestUnknownCandidateAndCompleteZeroRemainDistinct(t *testing.T) {
	f := fixture("ubuntu")
	f.candidates = map[string]string{"curl:amd64": "1:8.14.1-2"}
	s := collectFixture(t, f)
	if s.Coverage != "partial" || s.Reason != ReasonCandidateUnknown || *s.CandidateCount != 0 || *s.UnknownCount != 1 {
		t.Fatal(s)
	}
	f.candidates["held-package:amd64"] = "2.0~rc1-1"
	s = collectFixture(t, f)
	if s.Coverage != "complete" || *s.CandidateCount != 0 || *s.UnknownCount != 0 {
		t.Fatal(s)
	}
}
func TestFailureAndUnsupportedNeverProduceZeroCounts(t *testing.T) {
	for _, r := range []Reason{ReasonSourceMissing, ReasonCacheMissing, ReasonPermissionDenied, ReasonReadFailed, ReasonSourceChanged, ReasonTimeout} {
		f := fixture("debian")
		f.failure = sourceFailure(r)
		s := collectFixture(t, f)
		if s.Coverage != "unavailable" || s.CandidateCount != nil || s.InstalledCount != nil {
			t.Fatal(s)
		}
	}
	for _, d := range []string{"linuxmint", "debian12", "windows"} {
		f := fixture(d)
		s := collectFixture(t, f)
		if s.Reason != ReasonNotSupported || len(f.calls) != 2 {
			t.Fatal(s, f.calls)
		}
	}
}
func TestNoSourceAccessWithoutConsentOrIdentity(t *testing.T) {
	for _, mutate := range []func(*LocalConsent){func(c *LocalConsent) { c.Acknowledged = false }, func(c *LocalConsent) { c.Scope = "other" }, func(c *LocalConsent) { c.SenderBinding = strings.Repeat("b", 64) }} {
		c := testConsent()
		mutate(&c)
		called := false
		_, e := collectWith(context.Background(), sample, at, c, strings.Repeat("a", 64), &atomic.Bool{}, func() (nativeSource, error) { called = true; return fixture("debian"), nil })
		if !errors.Is(e, ErrInvalidInput) || called {
			t.Fatal("unconsented source access")
		}
	}
}
func TestBusyAndCanceledDoNotOpenSource(t *testing.T) {
	slot := &atomic.Bool{}
	slot.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []context.Context{context.Background(), ctx} {
		called := false
		s, e := collectWith(c, sample, at, testConsent(), strings.Repeat("a", 64), slot, func() (nativeSource, error) { called = true; return nil, nil })
		if e != nil || called || s.CandidateCount != nil {
			t.Fatal(s, e, called)
		}
	}
}
func TestPreviewBoundRetainsExactCounts(t *testing.T) {
	f := fixture("debian")
	f.packages = nil
	f.candidates = map[string]string{}
	for i := 0; i < 50; i++ {
		p := installedPackage{fmt.Sprintf("fixture-package-%03d", i), "amd64", "1.0-1", i%2 == 0}
		f.packages = append(f.packages, p)
		f.candidates[p.key()] = "2.0-1"
	}
	s := collectFixture(t, f)
	if !s.Truncated || s.Coverage != "partial" || *s.CandidateCount != 50 || *s.HeldCount != 25 || len(s.Items) >= 50 {
		t.Fatal(s)
	}
	raw, _ := json.Marshal(s)
	if len(raw) > MaxSnapshotBytes {
		t.Fatal(len(raw))
	}
}
func TestVersionEpochAndTildeNativeSemantics(t *testing.T) {
	f := fixture("debian")
	f.packages = []installedPackage{{"epoch-test", "amd64", "1:10.0-1", false}, {"tilde-test", "amd64", "2.0~rc1-1", false}}
	f.candidates = map[string]string{"epoch-test:amd64": "2:1.0-1", "tilde-test:amd64": "2.0-1"}
	s := collectFixture(t, f)
	if *s.CandidateCount != 2 {
		t.Fatal(s)
	}
}
func TestStrictSnapshotRejectsContradictionsAndExtraFields(t *testing.T) {
	s := collectFixture(t, fixture("debian"))
	raw, _ := Encode(s)
	bad := [][]byte{append(raw[:len(raw)-1], []byte(`,"cveCount":0}`)...), []byte(strings.Replace(string(raw), `"coverage":"complete"`, `"coverage":"complete","coverage":"complete"`, 1)), []byte(strings.Replace(string(raw), `"freshness":"unknown"`, `"freshness":"fresh"`, 1)), []byte(strings.Replace(string(raw), `"candidateCount":2`, `"candidateCount":0`, 1)), []byte(strings.Replace(string(raw), `"items":[`, `"items":null,"other":[`, 1))}
	for _, b := range bad {
		if _, e := DecodeStrict(b); e == nil {
			t.Fatalf("accepted malformed report: %s", b)
		}
	}
}

func TestMetadataAgeDoesNotSaturateAcrossRFC3339Range(t *testing.T) {
	oldest := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	far := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	if metadataAgeSeconds(far, oldest) != uint64(far.Unix()-oldest.Unix()) {
		t.Fatal("duration saturation")
	}
	if metadataAgeSeconds(at, at.Add(-time.Second).Add(time.Nanosecond)) != 0 {
		t.Fatal("subsecond age rounded upward")
	}
}
