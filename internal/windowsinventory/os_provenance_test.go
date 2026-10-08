package windowsinventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"localrmm/internal/model"
)

type osEvidenceProviderFixture struct {
	fixture
	device model.Device
}

func (p *osEvidenceProviderFixture) system() model.Device { p.called("system"); return p.device }
func osEvidenceFixture(at time.Time, quality string) model.Evidence {
	value := "Windows NT 10.0 (build 26100)"
	if quality != "healthy" {
		value = "Windows (version unavailable)"
	}
	return model.Evidence{ID: "local-windows-os", Title: "Windows NT version", Source: "ntdll.RtlGetVersion; numeric NT version and build", Quality: quality, CollectedAt: at, Value: value, Detail: "NT major/minor/build only, without inferring a marketing release or edition. Application compatibility can affect RtlGetVersion. nativeVerification: target-acceptance-unverified."}
}
func TestWindowsOSProvenanceUsesOneExistingReadAndNoStandaloneFields(t *testing.T) {
	at := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	for _, quality := range []string{"healthy", "unknown", "denied"} {
		t.Run(quality, func(t *testing.T) {
			e := osEvidenceFixture(at.Add(-time.Millisecond), quality)
			p := &osEvidenceProviderFixture{device: model.Device{OS: e.Value, Uptime: "Unknown", LastSeen: at, Evidence: []model.Evidence{{ID: "unrelated", Value: "private-do-not-copy"}, e}}}
			r, err := collect(context.Background(), p, noWait)
			if err != nil || r.OSEvidence == nil || *r.OSEvidence != e {
				t.Fatal("OS source, original age or quality lost", err)
			}
			if !reflect.DeepEqual(p.calls, []string{"system", "cpu", "cpu", "hostname", "processes", "services", "software", "network"}) {
				t.Fatal("collection call set changed")
			}
			with, err := Encode(r)
			if err != nil {
				t.Fatal(err)
			}
			original := r.OSEvidence
			r.OSEvidence = nil
			without, err := Encode(r)
			if err != nil || !bytes.Equal(with, without) || bytes.Contains(with, []byte("private-do-not-copy")) {
				t.Fatal("internal provenance changed standalone v1 JSON")
			}
			var decoded Report
			if json.Unmarshal(with, &decoded) != nil || decoded.OSEvidence != nil {
				t.Fatal("standalone JSON manufactured native provenance")
			}
			p.device.Evidence[1].Value = "mutated"
			if original.Value != e.Value {
				t.Fatal("report aliases provider evidence")
			}
		})
	}
}
func TestWindowsOSProvenanceRejectsMalformedAndDuplicateSource(t *testing.T) {
	at := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	for _, kind := range []string{"source", "mismatch", "future", "duplicate"} {
		e := osEvidenceFixture(at, "healthy")
		p := &osEvidenceProviderFixture{device: model.Device{OS: e.Value, LastSeen: at, Evidence: []model.Evidence{e}}}
		switch kind {
		case "source":
			p.device.Evidence[0].Source = "private-do-not-copy"
		case "mismatch":
			p.device.OS = "different"
		case "future":
			p.device.Evidence[0].CollectedAt = at.Add(time.Second)
		case "duplicate":
			p.device.Evidence = append(p.device.Evidence, e)
		}
		r, err := collect(context.Background(), p, noWait)
		if !errors.Is(err, ErrInvalidOSEvidence) || r.OSEvidence != nil || r.OS != "" || !reflect.DeepEqual(p.calls, []string{"system"}) {
			t.Fatal("invalid source metadata escaped or extra reads occurred", kind)
		}
	}
	p := &fixture{}
	r, err := collect(context.Background(), p, noWait)
	if err != nil || r.OSEvidence != nil {
		t.Fatal("legacy report acquired fabricated provenance")
	}
}
