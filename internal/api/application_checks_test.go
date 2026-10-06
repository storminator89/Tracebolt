package api

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/applicationcheck"
	"localrmm/internal/model"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const applicationCheckStatusPath = "/api/application-checks/status"

func TestApplicationCheckStatusDefaultOffAndAuthentication(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	if r, _ := o.call(t, "GET", applicationCheckStatusPath, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous application check status readable")
	}
	login, session := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	if login.StatusCode != 200 {
		t.Fatal("named fixture login failed")
	}
	r, view := o.call(t, "GET", applicationCheckStatusPath, nil, "", nil)
	items, ok := view["items"].([]any)
	if r.StatusCode != 200 || view["enabled"] != false || view["schemaVersion"] != applicationcheck.SchemaVersion || view["vantage"] != "management_server" || !ok || len(items) != 0 {
		t.Fatal("default status is not explicitly disabled", r.StatusCode, view)
	}
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("application observations could be cached")
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if r, _ := o.call(t, method, applicationCheckStatusPath, map[string]bool{"enabled": true}, session["csrfToken"].(string), nil); r.StatusCode != 403 {
			t.Fatal("named read gate permitted a status mutation", method, r.StatusCode)
		}
	}
	if r, _ := o.call(t, "HEAD", applicationCheckStatusPath, nil, "", nil); r.StatusCode != 405 {
		t.Fatal("non-GET read reached status")
	}
	if r, _ := o.call(t, "GET", "/api/application-checks/run", nil, "", nil); r.StatusCode != 404 {
		t.Fatal("unrequested check trigger route exists")
	}
	if r, _ := o.call(t, "POST", "/api/auth/logout", map[string]any{}, session["csrfToken"].(string), nil); r.StatusCode != 200 {
		t.Fatal("fixture logout failed")
	}
	o.client.Jar = nil
	if r, _ := o.call(t, "GET", applicationCheckStatusPath, nil, "", func(r *http.Request) { r.AddCookie(login.Cookies()[0]) }); r.StatusCode != 401 {
		t.Fatal("logged-out status session reused")
	}
	legacy := newOperatorFixture(t, 0)
	_, shared := legacy.login(t)
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "HEAD"} {
		if r, _ := legacy.call(t, method, applicationCheckStatusPath, map[string]any{}, shared["csrfToken"].(string), nil); r.StatusCode != 405 {
			t.Fatal("shared operator gained check mutation", method, r.StatusCode)
		}
	}
}

func TestApplicationCheckStatusOriginHostAndCrossSiteBoundary(t *testing.T) {
	o := newOperatorFixture(t, 0)
	o.login(t)
	for name, change := range map[string]func(*http.Request){
		"foreign origin": func(r *http.Request) { r.Header.Set("Origin", "https://other.example.test") },
		"foreign host":   func(r *http.Request) { r.Host = "other.example.test" },
		"cross site":     func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"multiple origins": func(r *http.Request) {
			r.Header.Add("Origin", o.server.URL)
			r.Header.Add("Origin", "https://other.example.test")
		},
	} {
		t.Run(name, func(t *testing.T) {
			if r, _ := o.call(t, "GET", applicationCheckStatusPath, nil, "", change); r.StatusCode != 403 {
				t.Fatal("application check status bypassed operator boundary", r.StatusCode)
			}
		})
	}
	if r, _ := o.call(t, "GET", applicationCheckStatusPath+"?target=other", nil, "", nil); r.StatusCode != 400 {
		t.Fatal("query parameter could alter status scope")
	}
}

func TestApplicationCheckStatusRechecksSession(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelled {
			cancel()
		}
		ctx = context.WithValue(ctx, operatorRequestKey{}, operatorRequest{active: func() bool { return cancelled }})
		r := httptest.NewRequest("GET", applicationCheckStatusPath, nil).WithContext(ctx)
		w := httptest.NewRecorder()
		(&operatorHandler{}).applicationCheckStatus(w, r)
		cancel()
		if w.Code != 401 {
			t.Fatal("status did not recheck revoked or cancelled session", w.Code)
		}
	}
}

func applicationCheckMonitorFixture(t *testing.T, managerID, origin, profile string) *applicationcheck.Monitor {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("protected file support is Linux-only")
	}
	path := filepath.Join(t.TempDir(), "application-checks.json")
	raw, err := json.Marshal(map[string]any{
		"schemaVersion": applicationcheck.ConfigSchemaVersion, "enabled": true,
		"managerInstanceId": managerID, "operatorOrigin": origin, "profile": profile,
		"intervalSeconds": 60, "checksFromManagerAcknowledged": true,
		"targets": []any{map[string]any{"id": "fixture", "url": "https://app.example.test/status", "allowedAddresses": []string{"8.8.8.8"}, "allowPrivateLAN": false, "plaintextHTTPAcknowledged": false}},
	})
	if err != nil || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("protected application check fixture failed")
	}
	config, err := applicationcheck.Load(path, managerID, origin, profile)
	if err != nil {
		t.Fatal(err)
	}
	return applicationcheck.New(config)
}

func TestApplicationCheckStatusIsAnInertRedactedSnapshot(t *testing.T) {
	o := newOperatorFixture(t, 0)
	monitor := applicationCheckMonitorFixture(t, "", o.server.URL, "tls")
	before := monitor.Status()
	existing := o.server.Config.Handler.(*operatorHandler)
	handler, err := NewLANOperatorHandler(o.app, LANOperatorConfig{
		ApplicationChecks: monitor, Origin: o.server.URL, Auth: existing.auth, Registry: o.registry,
		Devices: func() ([]model.Device, error) { return []model.Device{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Replace the fixture handler before its first request. Never run the enabled
	// worker: the synthetic target is configuration-only, not a network fixture.
	o.server.Config.Handler = handler
	o.login(t)
	for i := 0; i < 3; i++ {
		r, view := o.call(t, "GET", applicationCheckStatusPath, nil, "", nil)
		items, ok := view["items"].([]any)
		if r.StatusCode != 200 || view["enabled"] != true || !ok || len(items) != 1 {
			t.Fatal("configured snapshot unavailable", r.StatusCode, view)
		}
		raw, _ := json.Marshal(view)
		for _, private := range []string{"app.example.test", "8.8.8.8", "allowedAddresses", "operatorOrigin", "managerInstanceId", "https://"} {
			if strings.Contains(string(raw), private) {
				t.Fatal("status exposed private startup configuration", private)
			}
		}
	}
	after := monitor.Status()
	if !reflect.DeepEqual(before.Items, after.Items) {
		t.Fatal("status requests changed observations or ran a check")
	}
	if o.app.health != nil {
		t.Fatal("application checks initialized endpoint health")
	}
}

func TestApplicationCheckOperatorConstructorRejectsMismatchedBinding(t *testing.T) {
	o := newOperatorFixture(t, 0)
	existing := o.server.Config.Handler.(*operatorHandler)
	for _, mismatch := range []string{"instance", "origin", "profile"} {
		t.Run(mismatch, func(t *testing.T) {
			managerID, origin, profile := "", o.server.URL, "tls"
			switch mismatch {
			case "instance":
				managerID = "manager_11111111111111111111111111111111"
			case "origin":
				origin = "https://other.example.test"
			case "profile":
				origin = strings.Replace(o.server.URL, "https://", "http://", 1)
				profile = "http-test"
			}
			monitor := applicationCheckMonitorFixture(t, managerID, origin, profile)
			app := setup(t)
			handler, err := NewLANOperatorHandler(app, LANOperatorConfig{
				ApplicationChecks: monitor, Origin: o.server.URL, Auth: existing.auth, Registry: o.registry,
				Devices: func() ([]model.Device, error) { return []model.Device{}, nil },
			})
			if handler != nil || !errors.Is(err, applicationcheck.ErrConfiguration) {
				t.Fatal("operator adopted monitor for a different binding", err)
			}
			if app.lanOnly || app.lanDevices != nil || app.sample.ID != "sandbox-local" {
				t.Fatal("rejected monitor modified server state")
			}
		})
	}
}

func TestApplicationCheckStatusIsNotADevelopmentRoute(t *testing.T) {
	app := setup(t)
	w := request(app, "GET", applicationCheckStatusPath, "", nil)
	if w.Code != 404 {
		t.Fatal("application checks exposed on development server", w.Code)
	}
}
