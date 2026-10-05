package bundle

import (
	"encoding/json"
	"localrmm/internal/model"
	"strings"
	"testing"
)

func valid() model.Device {
	m := model.Metric{Unit: "%", Quality: "unknown"}
	return model.Device{ID: "sandbox-local", Name: "Local sandbox", Site: "Cloud sandbox", Group: "Local observations", Source: "sandbox", Platform: "linux", Status: "unknown", CPU: m, Memory: m, Disk: m, Evidence: []model.Evidence{{ID: "cpu", Quality: "unknown"}}}
}
func TestSafeEnvelope(t *testing.T) {
	d := valid()
	b, e := Encode(d)
	if e != nil {
		t.Fatal(e)
	}
	var got Bundle
	if e = json.Unmarshal(b, &got); e != nil {
		t.Fatal(e)
	}
	if got.SchemaVersion != SchemaVersion || got.Scope != "single-read-only-local-observation" {
		t.Fatal(got)
	}
	if got.Observation.Tags == nil || got.Observation.Capabilities == nil || got.Observation.Trend == nil || got.Observation.CaseIDs == nil {
		t.Fatal("nil arrays violate schema")
	}
	if len(b) > MaxBytes {
		t.Fatal("byte cap")
	}
}
func TestRejectUnexpectedData(t *testing.T) {
	cases := []struct {
		name   string
		change func(*model.Device)
	}{
		{"operator certificate metadata", func(d *model.Device) { d.AgentCertificate = &model.AgentCertificate{} }},
		{"hostname field", func(d *model.Device) { d.Name = "private-hostname" }},
		{"account field", func(d *model.Device) { d.Site = "private-account" }},
		{"arbitrary tag", func(d *model.Device) { d.Tags = []string{"private-value"} }},
		{"role mismatch", func(d *model.Device) { d.Platform = "windows" }},
		{"evidence field bound", func(d *model.Device) { d.Evidence[0].Detail = strings.Repeat("x", 4097) }},
		{"invalid capability state", func(d *model.Device) { d.Capabilities = []model.Capability{{Status: "invented"}} }},
		{"valid quality missing metric", func(d *model.Device) { d.CPU.Quality = "healthy" }},
		{"health claim", func(d *model.Device) { d.Status = "healthy" }},
		{"platform", func(d *model.Device) { d.Platform = "plan9" }},
		{"metric quality", func(d *model.Device) { d.CPU.Quality = "invalid" }},
		{"unavailable metric value", func(d *model.Device) { v := 50.0; d.CPU.Value = &v }},
		{"metric bounds", func(d *model.Device) { v := 101.0; d.CPU.Value = &v; d.CPU.Quality = "healthy" }},
		{"invented history", func(d *model.Device) { d.Trend = []float64{1} }},
		{"synthetic", func(d *model.Device) { d.Synthetic = true }},
		{"address", func(d *model.Device) { s := "192.0.2.1"; d.IP = &s }},
		{"identity", func(d *model.Device) { d.ID = "machine-identifier" }},
		{"case", func(d *model.Device) { d.CaseIDs = []string{"case"} }},
		{"source", func(d *model.Device) { d.Source = "remote" }},
		{"duplicate evidence", func(d *model.Device) { d.Evidence = append(d.Evidence, d.Evidence[0]) }},
		{"large", func(d *model.Device) { d.Evidence[0].Detail = strings.Repeat("x", MaxBytes) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := valid()
			c.change(&d)
			if _, e := Encode(d); e == nil {
				t.Fatal("unexpected data accepted")
			}
		})
	}
}

func TestValidateObservationLeavesInputUnchanged(t *testing.T) {
	d := valid()
	before, _ := json.Marshal(d)
	for range 100 {
		if err := ValidateObservation(d); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := json.Marshal(d)
	if string(before) != string(after) {
		t.Fatal("policy validation changed observation")
	}
}
