package collector

import (
	"os"
	"testing"
	"time"

	"localrmm/internal/model"
)

func TestWindowsOSEvidenceMatchesExistingProducer(t *testing.T) {
	for _, p := range []windowsFixture{validWindowsFixture(), {}, {versionErr: os.ErrPermission}} {
		d := snapshotWindows(p, nativeFixtureTime)
		e := findEvidence(t, d, "local-windows-os")
		if !ValidWindowsOSEvidence(e, d.OS, d.LastSeen) {
			t.Fatal("existing collector evidence rejected")
		}
	}
	d := snapshotWindows(validWindowsFixture(), nativeFixtureTime)
	original := findEvidence(t, d, "local-windows-os")
	for name, change := range map[string]func(*model.Evidence){
		"id":                 func(e *model.Evidence) { e.ID = "other" },
		"source":             func(e *model.Evidence) { e.Source = "registry UBR" },
		"title":              func(e *model.Evidence) { e.Title = "private" },
		"detail":             func(e *model.Evidence) { e.Detail += " private" },
		"profile":            func(e *model.Evidence) { e.CollectionProfile = "basic-readonly-v1" },
		"synthetic":          func(e *model.Evidence) { e.Synthetic = true },
		"stale":              func(e *model.Evidence) { e.Quality = "stale" },
		"unknown-with-value": func(e *model.Evidence) { e.Quality = "unknown" },
		"denied-with-value":  func(e *model.Evidence) { e.Quality = "denied" },
		"value":              func(e *model.Evidence) { e.Value = "other" },
		"zero-time":          func(e *model.Evidence) { e.CollectedAt = time.Time{} },
		"future-time":        func(e *model.Evidence) { e.CollectedAt = d.LastSeen.Add(time.Nanosecond) },
		"non-utc":            func(e *model.Evidence) { e.CollectedAt = e.CollectedAt.In(time.FixedZone("fixture", 0)) },
	} {
		t.Run(name, func(t *testing.T) {
			e := original
			change(&e)
			if ValidWindowsOSEvidence(e, d.OS, d.LastSeen) {
				t.Fatal("out-of-contract evidence accepted")
			}
		})
	}
	for _, value := range []string{"Windows NT 10.0 (build 26100.1)", "Windows NT 010.0 (build 26100)", "Windows NT +10.0 (build 26100)", "Windows NT 0.0 (build 26100)", "Windows NT 10.0 (build 0)", "Windows NT 4294967296.0 (build 26100)", "Windows NT 10.0 (build 26100) suffix", "Windows (version unavailable)", "private\nvalue"} {
		e := original
		e.Value = value
		if ValidWindowsOSEvidence(e, value, d.LastSeen) {
			t.Fatal("unsupported OS format accepted")
		}
	}
	e := original
	e.Value = "Windows NT 4294967295.4294967295 (build 4294967295)"
	if !ValidWindowsOSEvidence(e, e.Value, d.LastSeen) {
		t.Fatal("valid uint32 producer boundary rejected")
	}
}
