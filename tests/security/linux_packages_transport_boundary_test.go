package security_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/operational"
	"strings"
	"testing"
	"time"
)

// Entirely synthetic values: no collector, live source read, credentials or I/O.
func packageReviewFrame() (lanstore.Frame, time.Time) {
	p := packageReviewSnapshot(2)
	at := p.CollectedAt
	op := operational.Empty(at, operational.ReasonNotImplemented)
	p.GenerationID = op.GenerationID
	m := model.Metric{Unit: "%", Quality: "unknown", Source: "Synthetic fixture", CollectedAt: at}
	d := model.Device{ID: "sandbox-local", Name: "Local sandbox", Platform: "linux", OS: "Synthetic OS",
		Site: "Cloud sandbox", Group: "Local observations", Status: "unknown", Source: "sandbox", LastSeen: at,
		AgentVersion: "fixture", CPU: m, Memory: m, Disk: m, Uptime: "unknown", Tags: []string{},
		Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
	b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "fixture", GeneratedAt: at,
		Platform: "linux", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: d}
	return lanstore.Frame{SchemaVersion: lanstore.FramePackagesVersion, Sequence: 1, Observation: b, Operational: &op, Packages: &p}, at
}

func TestIndependentPackageFrameExactSchemaAndProfileMatrix(t *testing.T) {
	profiles := []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages}
	versions := []string{lanstore.FrameVersion, lanstore.FrameOperationalVersion, lanstore.FramePackagesVersion}
	for i, version := range versions {
		f, at := packageReviewFrame()
		f.SchemaVersion = version
		if i < 2 {
			f.Packages = nil
		}
		if i == 0 {
			f.Operational = nil
		}
		raw := packageReviewJSON(t, f)
		decoded, err := lanstore.ValidateFrame(raw, at)
		if err != nil {
			t.Fatal("known legacy/new schema rejected", version)
		}
		for j, profile := range profiles {
			if lanstore.FrameMatchesCollectionProfile(decoded, profile) != (i == j) {
				t.Fatal("schema/profile authority matrix expanded")
			}
		}
		if i < 2 {
			extra := append([]byte(`{"packages":null,`), raw[1:]...)
			if _, err := lanstore.ValidateFrame(extra, at); err == nil {
				t.Fatal("legacy exact shape accepted even null package metadata")
			}
		}
	}
	for name, change := range map[string]func(*lanstore.Frame){
		"missing package":    func(f *lanstore.Frame) { f.Packages = nil },
		"missing operations": func(f *lanstore.Frame) { f.Operational = nil },
		"relabel operations": func(f *lanstore.Frame) { f.Operational.CollectionProfile = enrollmentcrypto.CollectionProfilePackages },
		"old generation":     func(f *lanstore.Frame) { f.Packages.GenerationID = "sample_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
		"old package time":   func(f *lanstore.Frame) { f.Packages.CollectedAt = f.Packages.CollectedAt.Add(-time.Nanosecond) },
		"unsafe sequence":    func(f *lanstore.Frame) { f.Sequence = operational.MaxSafeInteger + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			f, at := packageReviewFrame()
			change(&f)
			if _, err := lanstore.ValidateFrame(packageReviewJSON(t, f), at); err == nil {
				t.Fatal("invalid synthetic frame accepted")
			}
		})
	}
}

func TestIndependentPackageFrameRawCanonicalAndAgeBounds(t *testing.T) {
	f, at := packageReviewFrame()
	raw := packageReviewJSON(t, f)
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		t.Fatal("synthetic fields")
	}
	for field, limit := range map[string]int{"observation": 16 << 10, "operational": 32 << 10, "packages": 16 << 10} {
		needle := []byte(`"` + field + `":{`)
		padded := bytes.Replace(raw, needle, append(bytes.Clone(needle), bytes.Repeat([]byte(" "), limit-len(members[field]))...), 1)
		if _, err := lanstore.ValidateFrame(padded, at); err != nil {
			t.Fatal("exact raw component cap rejected", field)
		}
		over := bytes.Replace(padded, needle, append(bytes.Clone(needle), ' '), 1)
		if _, err := lanstore.ValidateFrame(over, at); err == nil {
			t.Fatal("one-byte raw component overflow accepted", field)
		}
	}
	padded := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), lanstore.MaxFrameBytes-len(raw))...)
	if _, err := lanstore.ValidateFrame(padded, at); err != nil {
		t.Fatal("exact outer cap rejected")
	}
	if _, err := lanstore.ValidateFrame(append(padded, ' '), at); err == nil {
		t.Fatal("outer overflow accepted")
	}
	for _, now := range []time.Time{at.Add(2 * time.Minute), at.Add(-30 * time.Second)} {
		if _, err := lanstore.ValidateFrame(raw, now); err != nil {
			t.Fatal("exact age/skew boundary rejected")
		}
	}
	for _, now := range []time.Time{at.Add(2*time.Minute + time.Nanosecond), at.Add(-30*time.Second - time.Nanosecond)} {
		if _, err := lanstore.ValidateFrame(raw, now); err != lanstore.ErrStale {
			t.Fatal("source age/skew boundary not enforced")
		}
	}
	// A short raw string can expand in canonical encoding; raw fit is not enough.
	f.Observation.Privacy = []string{strings.Repeat("<", 3000)}
	compact := bytes.ReplaceAll(packageReviewJSON(t, f), []byte(`\u003c`), []byte("<"))
	if _, err := lanstore.ValidateFrame(compact, at); err == nil {
		t.Fatal("canonical basic cap ignored")
	}
	f, at = packageReviewFrame()
	for _, replacement := range []string{
		`"scope":"agent-visible-dpkg","sc\u006fpe":"agent-visible-dpkg"`,
		`"scope":"agent-visible-dpkg","trusted":true`,
		`"scope":null`,
	} {
		invalid := bytes.Replace(packageReviewJSON(t, f), []byte(`"scope":"agent-visible-dpkg"`), []byte(replacement), 1)
		if _, err := lanstore.ValidateFrame(invalid, at); err == nil {
			t.Fatal("package strict decoder bypassed by enclosing frame")
		}
	}
}

func TestIndependentPackageOperationalTrimOwnsPointersAndCounts(t *testing.T) {
	s := operationalBoundaryFixture()
	s.DurationMS = 17
	v := &s.Sections.Software
	v.Items = []operational.Software{}
	for i := 0; i < 140; i++ {
		v.Items = append(v.Items, operational.Software{Name: fmt.Sprintf("review-dense-%03d", i), Version: "1." + strings.Repeat("1", 170), Architecture: "amd64", Manager: "dpkg"})
	}
	v.Meta.ObservedCount = 140
	before := packageReviewJSON(t, s)
	if len(before) <= 32<<10 || len(before) > 48<<10 || operational.Validate(s) != nil {
		t.Fatal("synthetic snapshot does not distinguish old/new budgets")
	}
	bounded, err := operational.TrimForPackageFrame(s)
	if err != nil || operational.Validate(bounded) != nil || len(packageReviewJSON(t, bounded)) > 32<<10 ||
		bounded.GenerationID != s.GenerationID || bounded.CollectedAt != s.CollectedAt || bounded.DurationMS != s.DurationMS || bounded.CollectionProfile != operational.CollectionProfile {
		t.Fatal("new-only reservation corrupted validated snapshot")
	}
	meta := bounded.Sections.Software.Meta
	if meta.ObservedCount != 140 || !meta.CountExact || meta.Complete || !meta.Truncated || meta.Reason != operational.ReasonByteLimit {
		t.Fatal("trim hid source scope or rewrote counts")
	}
	again, err := operational.TrimForPackageFrame(bounded)
	if err != nil || !bytes.Equal(packageReviewJSON(t, again), packageReviewJSON(t, bounded)) {
		t.Fatal("clone trim is not idempotent")
	}
	*bounded.Sections.Volumes.Items[0].TotalBytes = 999
	*bounded.Sections.Network.Items[0].MTU = 999
	*bounded.Sections.Processes.Items[0].RSSBytes = 999
	bounded.Sections.Software.Items[0].Name = "changed"
	bounded.Sections.Services.Items[0].Name = "changed.service"
	bounded.Sections.Events.Items[0].Unit = "changed.service"
	if !bytes.Equal(before, packageReviewJSON(t, s)) || !s.Sections.Software.Meta.Complete || len(s.Sections.Software.Items) != 140 {
		t.Fatal("new reservation mutated original v1 data or shared members")
	}
	// Validation must precede trimming, even for a malformed trailing row.
	s.Sections.Software.Items[139].Version = "invalid"
	if _, err := operational.TrimForPackageFrame(s); err == nil {
		t.Fatal("trim erased invalid trailing source row")
	}
}
