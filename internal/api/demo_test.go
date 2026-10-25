package api

import (
	"encoding/json"
	"localrmm/internal/model"
	"localrmm/internal/telemetry"
	"net/http"
	"strings"
	"testing"
)

func TestDemoOnlyDoesNotAdoptLocalOrDeveloperTelemetry(t *testing.T) {
	base := setup(t)
	s, err := NewDemoOnly(base.store, base.port, base.web)
	if err != nil {
		t.Fatal(err)
	}
	s.SetSample(model.Device{ID: "forbidden-local-device", Source: "local"})
	s.EnableManagedPreview(telemetry.NewState())
	if s.sampleDevice().ID != "" || s.managedPreviewEnabled() {
		t.Fatal("demo mode adopted a local sample or transport")
	}
	for _, path := range []string{"/api/devices", "/api/overview"} {
		w := request(s, "GET", path, "", nil)
		var value struct {
			Items   []model.Device
			Devices []model.Device
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &value) != nil {
			t.Fatalf("%s: %d", path, w.Code)
		}
		devices := append(value.Items, value.Devices...)
		if len(devices) != 7 {
			t.Fatalf("%s: got %d devices", path, len(devices))
		}
		for _, d := range devices {
			if !d.Synthetic || d.Source != "synthetic" {
				t.Fatal("non-synthetic row in demo response")
			}
		}
	}
	if w := request(s, "GET", "/api/devices/forbidden-local-device", "", nil); w.Code != 404 {
		t.Fatal("hidden local sample remains addressable")
	}
	for _, route := range []struct{ method, path string }{{"GET", "/api/dev/telemetry/status"}, {"POST", "/api/dev/telemetry"}} {
		if w := request(s, route.method, route.path, `{}`, nil); w.Code != 404 {
			t.Fatal("developer telemetry enabled in demo mode")
		}
	}
	w := request(s, "GET", "/api/capabilities", "", nil)
	var capabilities struct {
		DemoOnly, RemoteEnrollment, ShellExecution, AIConfigured bool
		RealCollector                                            string
		Limitations                                              []string
	}
	if json.Unmarshal(w.Body.Bytes(), &capabilities) != nil || !capabilities.DemoOnly || capabilities.RemoteEnrollment || capabilities.ShellExecution || capabilities.AIConfigured || !strings.HasPrefix(capabilities.RealCollector, "Disabled:") || !strings.Contains(capabilities.Limitations[2], "no local collection") {
		t.Fatal("demo capabilities misrepresent collection or authority")
	}
	if w := request(s, "GET", "/api/overview", "", func(r *http.Request) { r.RemoteAddr = "192.0.2.1:1234" }); w.Code != 403 {
		t.Fatal("demo relaxed loopback boundary")
	}
	if w := request(s, "POST", "/api/cases/case-demo-win-01-service/notes", `{"text":"fixture"}`, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }); w.Code != 403 {
		t.Fatal("demo relaxed mutation protection")
	}
}

func TestDemoOnlyRejectsMixedStateWithoutChangingIt(t *testing.T) {
	for _, kind := range []string{"device", "case"} {
		t.Run(kind, func(t *testing.T) {
			base := setup(t)
			var devices []model.Device
			var cases []model.Case
			if kind == "device" {
				devices = []model.Device{{ID: "existing-real", Source: "local"}}
			} else {
				cases = []model.Case{{ID: "existing-real", Synthetic: false}}
			}
			if err := base.store.Seed(devices, cases); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDemoOnly(base.store, base.port, base.web); err == nil {
				t.Fatal("mixed state accepted as a pure demonstration")
			}
			if kind == "device" {
				rows, _ := base.store.Devices()
				if len(rows) != 8 {
					t.Fatal("rejection changed existing devices")
				}
			} else {
				if _, err := base.store.Case("existing-real"); err != nil {
					t.Fatal("rejection removed an existing case")
				}
			}
		})
	}
}
