package profile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFiniteSelection(t *testing.T) {
	for _, s := range []Selection{BasicTLS(), InventoryTLS(), {"windows-inventory-v1", "http-test"}} {
		if s.Validate() != nil || s.EnrollmentPrefix() == "" || s.TelemetryPath() == "" || s.Inventory() != (s.CollectionProfile == "windows-inventory-v1") || s.HTTPTest() != (s.Transport == "http-test") {
			t.Fatal("valid selection rejected")
		}
	}
	for _, s := range []Selection{{}, {"basic-readonly-v1", "http-test"}, {"managed-operations-v3", "tls"}, {"windows-inventory-v1", ""}, {"", "tls"}, {"windows-inventory-v1", "TLS"}, {"windows-inventory-v1", "http"}} {
		if s.Validate() == nil || s.EnrollmentPrefix() != "" || s.TelemetryPath() != "" || s.Inventory() || s.HTTPTest() {
			t.Fatal("unsupported selection admitted")
		}
	}
}

func TestFiniteObservationQualities(t *testing.T) {
	z := ZeroObservation()
	if z.Validate() != nil || z.Usable() || (Observation{}).Validate() == nil {
		t.Fatal("zero observation contract changed")
	}
	h := Observation{Frames: 1, CPU: "healthy", Memory: "partial", Disk: "healthy", Hostname: "healthy", Processes: "partial", Services: "healthy", Software: "healthy", Interfaces: "healthy"}
	if h.Validate() != nil || !h.Usable() {
		t.Fatal("usable observation rejected")
	}
	for _, q := range []string{"denied", "unavailable"} {
		o := h
		o.CPU = q
		if o.Validate() != nil || o.Usable() {
			t.Fatal("missing metric considered usable")
		}
	}
	for _, q := range []string{"", "not_run", "unknown", "HEALTHY", "healthy ", "hostname=example"} {
		o := h
		o.Interfaces = q
		if o.Validate() == nil || o.Usable() {
			t.Fatal("nonfinite quality admitted")
		}
	}
	for _, frames := range []uint64{0, 65, ^uint64(0)} {
		o := h
		o.Frames = frames
		if o.Validate() == nil || o.Usable() {
			t.Fatal("invalid count/quality pair admitted")
		}
	}
	z.CPU = "healthy"
	if z.Validate() == nil {
		t.Fatal("zero count acquired quality")
	}
	z = ZeroObservation()
	z.Frames = 1
	if z.Validate() == nil {
		t.Fatal("positive count has not-run quality")
	}
	raw, err := json.Marshal(h)
	if err != nil || strings.Contains(string(raw), "CPU") || !strings.Contains(string(raw), `"interfaces":"healthy"`) {
		t.Fatal("quality JSON changed")
	}
}
