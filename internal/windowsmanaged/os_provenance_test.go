package windowsmanaged

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"localrmm/internal/bundle"
	"localrmm/internal/model"
)

func osEvidenceFixture(at time.Time, quality string) model.Evidence {
	value := "Windows NT 10.0 (build 26100)"
	if quality != "healthy" {
		value = "Windows (version unavailable)"
	}
	return model.Evidence{ID: "local-windows-os", Title: "Windows NT version", Source: "ntdll.RtlGetVersion; numeric NT version and build", Quality: quality, CollectedAt: at, Value: value, Detail: "NT major/minor/build only, without inferring a marketing release or edition. Application compatibility can affect RtlGetVersion. nativeVerification: target-acceptance-unverified."}
}
func TestWindowsManagedOSProvenancePreservesExistingEvidenceAndLegacyReport(t *testing.T) {
	for _, quality := range []string{"healthy", "unknown", "denied"} {
		t.Run(quality, func(t *testing.T) {
			r := fixtureReport()
			e := osEvidenceFixture(r.CollectedAt.Add(-time.Millisecond), quality)
			r.OS, r.OSEvidence = e.Value, &e
			before, _ := json.Marshal(r)
			s, d, err := FromReport(r, fixtureGeneration)
			if err != nil || len(d.Evidence) != 4 || d.Evidence[0] != e || d.OS != e.Value || !d.LastSeen.Equal(r.CPU.CollectedAt) || bundle.ValidateObservation(d) != nil {
				t.Fatal("managed adapter lost existing OS provenance", err)
			}
			after, _ := json.Marshal(r)
			if !bytes.Equal(before, after) {
				t.Fatal("adapter mutated input JSON")
			}
			r.OSEvidence = nil
			legacyS, legacyD, err := FromReport(r, fixtureGeneration)
			if err != nil || !reflect.DeepEqual(s, legacyS) || len(legacyD.Evidence) != 3 {
				t.Fatal("base inventory or legacy evidence changed", err)
			}
			e.Source = "mutated"
			if d.Evidence[0].Source == "mutated" {
				t.Fatal("adapter aliases report metadata")
			}
			d.Evidence = d.Evidence[1:]
			if !reflect.DeepEqual(d, legacyD) {
				t.Fatal("OS preservation changed unrelated device fields")
			}
		})
	}
}
func TestWindowsManagedOSProvenanceRejectsUntrustedMetadata(t *testing.T) {
	for name, change := range map[string]func(*model.Evidence){
		"id":      func(e *model.Evidence) { e.ID = "other" },
		"source":  func(e *model.Evidence) { e.Source = "registry UBR" },
		"detail":  func(e *model.Evidence) { e.Detail = "private" },
		"value":   func(e *model.Evidence) { e.Value = "other" },
		"profile": func(e *model.Evidence) { e.CollectionProfile = CollectionProfile },
		"quality": func(e *model.Evidence) { e.Quality = "healthy-looking" },
		"time":    func(e *model.Evidence) { e.CollectedAt = e.CollectedAt.Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			r := fixtureReport()
			e := osEvidenceFixture(r.CollectedAt, "healthy")
			r.OSEvidence = &e
			change(&e)
			s, d, err := FromReport(r, fixtureGeneration)
			if !errors.Is(err, ErrInvalidReport) || len(d.Evidence) != 0 || s.GenerationID != "" {
				t.Fatal("malformed OS metadata accepted")
			}
		})
	}
}
