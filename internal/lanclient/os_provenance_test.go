package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
)

func osProvenanceReport(at time.Time, quality string) windowsinventory.Report {
	r := syntheticWindowsReport(at)
	r.OS = "Windows NT 10.0 (build 26100)"
	if quality != "healthy" {
		r.OS = "Windows (version unavailable)"
	}
	r.OSEvidence = &model.Evidence{ID: "local-windows-os", Title: "Windows NT version", Source: "ntdll.RtlGetVersion; numeric NT version and build", Quality: quality, CollectedAt: at.Add(-time.Millisecond), Value: r.OS, Detail: "NT major/minor/build only, without inferring a marketing release or edition. Application compatibility can affect RtlGetVersion. nativeVerification: target-acceptance-unverified."}
	return r
}
func TestWindowsOSProvenanceUsesExistingStrictWireAndRetainsLegacy(t *testing.T) {
	for _, quality := range []string{"healthy", "unknown", "denied", "legacy"} {
		t.Run(quality, func(t *testing.T) {
			r := osProvenanceReport(time.Now().UTC().Add(-time.Second), quality)
			if quality == "legacy" {
				r.OSEvidence = nil
			}
			calls := 0
			c := windowsConfig(Config{})
			f, raw, err := collectWindowsFrame(context.Background(), c, 1, func(_ context.Context, id string) (windowsmanaged.Snapshot, model.Device, error) {
				calls++
				return windowsmanaged.FromReport(r, id)
			})
			if err != nil || calls != 1 || f.SchemaVersion != FrameWindowsInventoryVersion {
				t.Fatal("existing sender path rejected provenance", err)
			}
			if _, err := decodeFrameForConfig(raw, 1, c); err != nil {
				t.Fatal(err)
			}
			stored, err := lanstore.ValidateFrame(raw, time.Now().UTC())
			if err != nil {
				t.Fatal("manager rejected existing-shape frame", err)
			}
			evidence := stored.Observation.Observation.Evidence
			if quality == "legacy" {
				if len(evidence) != 3 {
					t.Fatal("legacy frame acquired invented evidence")
				}
				return
			}
			if len(evidence) != 4 || evidence[0] != *r.OSEvidence {
				t.Fatal("wire changed source, capture time or failure quality")
			}
			if bytes.Contains(raw, []byte(`"osEvidence"`)) || bytes.Contains(raw, []byte(`"OSEvidence"`)) {
				t.Fatal("internal carrier leaked onto wire")
			}
			for name, alter := range map[string]func([]byte) []byte{
				"unknown": func(b []byte) []byte {
					return bytes.Replace(b, []byte(`"id":"local-windows-os"`), []byte(`"id":"local-windows-os","ubr":123`), 1)
				},
				"duplicate": func(b []byte) []byte {
					return bytes.Replace(b, []byte(`"id":"local-windows-os"`), []byte(`"id":"local-windows-os","id":"local-windows-os"`), 1)
				},
				"missing": func(b []byte) []byte { return bytes.Replace(b, []byte(`"title":"Windows NT version",`), nil, 1) },
			} {
				bad := alter(raw)
				if bytes.Equal(bad, raw) {
					t.Fatal("ineffective mutation", name)
				}
				if _, err := decodeFrameForConfig(bad, 1, c); err == nil {
					t.Fatal("sender strict validation weakened", name)
				}
				if _, err := lanstore.ValidateFrame(bad, time.Now().UTC()); err == nil {
					t.Fatal("manager strict validation weakened", name)
				}
			}
			f.Observation.Observation.Evidence[0].CollectedAt = f.Observation.Observation.LastSeen.Add(time.Second)
			bad, _ := json.Marshal(f)
			if _, err := decodeFrameForConfig(bad, 1, c); err == nil {
				t.Fatal("sender accepted refreshed OS capture")
			}
			if _, err := lanstore.ValidateFrame(bad, time.Now().UTC()); err == nil {
				t.Fatal("manager accepted refreshed OS capture")
			}
		})
	}
}
