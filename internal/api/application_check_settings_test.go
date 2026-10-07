package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/applicationcheck"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const applicationCheckSettingsPath = "/api/application-checks/settings"

func applicationCheckSettingsFixture(t *testing.T, named, granted bool) (operatorFixture, *applicationcheck.Settings) {
	t.Helper()
	o := newOperatorFixture(t, 0)
	h := o.server.Config.Handler.(*operatorHandler)
	if named {
		caps := []operatorauth.Capability{operatorauth.Read, operatorauth.PlanUpdates, operatorauth.ExecuteUpdates, operatorauth.RestartService, operatorauth.ManageAlarms}
		if granted {
			caps = append(caps, operatorauth.ManageApplicationChecks)
		}
		auth, err := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: caps}}})
		if err != nil {
			t.Fatal(err)
		}
		h.auth = auth
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := applicationcheck.NewSettings(dir, "", o.server.URL, "tls", applicationcheck.Config{})
	if err != nil {
		t.Fatal(err)
	}
	h.applicationCheckSettings = s
	return o, s
}

func applicationCheckSaveInput(revision string) map[string]any {
	return map[string]any{"expectedRevision": revision, "operation": "save", "intervalSeconds": 60, "targets": []any{
		map[string]any{"kind": "http", "id": "fixture", "url": "https://private-fixture.example.test/status", "allowedAddresses": []string{"8.8.8.8"}, "allowPrivateLAN": false, "plaintextHTTPAcknowledged": false},
	}}
}

func TestApplicationCheckSettingsPermissionConfidentialityAndExplicitEnable(t *testing.T) {
	for _, mode := range []string{"shared", "named-other-grants", "named-check-admin"} {
		t.Run(mode, func(t *testing.T) {
			o, s := applicationCheckSettingsFixture(t, mode != "shared", mode == "named-check-admin")
			if r, _ := o.call(t, "GET", applicationCheckSettingsPath, nil, "", nil); r.StatusCode != 401 {
				t.Fatal("anonymous settings readable")
			}
			var session map[string]any
			if mode == "shared" {
				_, session = o.login(t)
			} else {
				_, session = o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
			}
			csrf := session["csrfToken"].(string)
			r, v := o.call(t, "GET", applicationCheckSettingsPath, nil, "", nil)
			in := applicationCheckSaveInput(s.View().Revision)
			if mode == "named-other-grants" {
				if r.StatusCode != 403 || v["targets"] != nil || v["revision"] != nil {
					t.Fatal("unrelated grants exposed check configuration", r.StatusCode)
				}
				if r, _ = o.call(t, "POST", applicationCheckSettingsPath, in, csrf, nil); r.StatusCode != 403 {
					t.Fatal("unrelated grants changed configuration", r.StatusCode)
				}
				if r, _ = o.call(t, "GET", applicationCheckStatusPath, nil, "", nil); r.StatusCode != 200 {
					t.Fatal("read-only status became privileged")
				}
				return
			}
			if r.StatusCode != 200 || v["mode"] != "managed" || v["configured"] != false || v["enabled"] != false || len(v["targets"].([]any)) != 0 {
				t.Fatal("default is not empty and disabled", r.StatusCode)
			}
			r, v = o.call(t, "POST", applicationCheckSettingsPath, in, csrf, nil)
			if r.StatusCode != 200 || v["configured"] != true || v["enabled"] != false || len(v["targets"].([]any)) != 1 || v["revision"] == in["expectedRevision"] {
				t.Fatal("save implicitly enabled or did not persist draft", r.StatusCode)
			}
			if s.Status().Enabled {
				t.Fatal("saving draft enabled monitor")
			}
			if r, _ = o.call(t, "POST", applicationCheckSettingsPath, in, csrf, nil); r.StatusCode != 409 {
				t.Fatal("stale draft replaced saved configuration", r.StatusCode)
			}
			enable := map[string]any{"expectedRevision": v["revision"], "operation": "enable", "checksFromManagerAcknowledged": true, "destinationsAcknowledged": false}
			if r, _ = o.call(t, "POST", applicationCheckSettingsPath, enable, csrf, nil); r.StatusCode != 400 {
				t.Fatal("unreviewed targets enabled")
			}
			enable["destinationsAcknowledged"] = true
			r, v = o.call(t, "POST", applicationCheckSettingsPath, enable, csrf, nil)
			if r.StatusCode != 200 || v["enabled"] != true {
				t.Fatal("explicit enable failed", r.StatusCode)
			}
			// No supervisor is run in this fixture. Settings and status requests
			// must remain inert even when the explicit desired state is enabled.
			r, status := o.call(t, "GET", applicationCheckStatusPath, nil, "", nil)
			raw, _ := json.Marshal(status)
			if r.StatusCode != 200 || strings.Contains(string(raw), "private-fixture") || strings.Contains(string(raw), "8.8.8.8") || strings.Contains(string(raw), "allowedAddresses") {
				t.Fatal("status leaked private configuration")
			}
			for _, item := range status["items"].([]any) {
				if item.(map[string]any)["observedAt"] != nil {
					t.Fatal("settings request performed a target probe")
				}
			}
			r, v = o.call(t, "POST", applicationCheckSettingsPath, map[string]any{"expectedRevision": v["revision"], "operation": "disable"}, csrf, nil)
			if r.StatusCode != 200 || v["enabled"] != false || v["configured"] != true || len(v["targets"].([]any)) != 1 {
				t.Fatal("disable did not retain inert draft", r.StatusCode)
			}
			if r, _ = o.call(t, "POST", "/api/auth/logout", map[string]any{}, csrf, nil); r.StatusCode != 200 {
				t.Fatal("logout failed")
			}
			if r, _ = o.call(t, "GET", applicationCheckSettingsPath, nil, "", nil); r.StatusCode != 401 {
				t.Fatal("logged-out settings readable")
			}
		})
	}
}

func TestApplicationCheckSettingsStrictShapesAndGuards(t *testing.T) {
	o, s := applicationCheckSettingsFixture(t, true, true)
	_, session := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	csrf := session["csrfToken"].(string)
	revision := s.View().Revision
	valid, _ := json.Marshal(applicationCheckSaveInput(revision))
	for name, body := range map[string]string{
		"duplicate":                      strings.Replace(string(valid), `"operation":"save"`, `"operation":"save","operation":"save"`, 1),
		"unknown":                        strings.Replace(string(valid), `"operation":"save"`, `"operation":"save","actor":"forged"`, 1),
		"null":                           strings.Replace(string(valid), `"intervalSeconds":60`, `"intervalSeconds":null`, 1),
		"case alias":                     strings.Replace(string(valid), `"operation"`, `"Operation"`, 1),
		"save acknowledgement":           strings.Replace(string(valid), `"operation":"save"`, `"operation":"save","destinationsAcknowledged":false`, 1),
		"interval zero":                  strings.Replace(string(valid), `"intervalSeconds":60`, `"intervalSeconds":0`, 1),
		"interval fraction":              strings.Replace(string(valid), `"intervalSeconds":60`, `"intervalSeconds":60.5`, 1),
		"interval high":                  strings.Replace(string(valid), `"intervalSeconds":60`, `"intervalSeconds":3601`, 1),
		"unrelated target field":         strings.Replace(string(valid), `"kind":"http"`, `"kind":"http","host":"secret.invalid"`, 1),
		"duplicate target field":         strings.Replace(string(valid), `"kind":"http"`, `"kind":"http","kind":"http"`, 1),
		"null target":                    `{"expectedRevision":"` + revision + `","operation":"save","intervalSeconds":60,"targets":[null]}`,
		"empty targets":                  `{"expectedRevision":"` + revision + `","operation":"save","intervalSeconds":60,"targets":[]}`,
		"disable extra false":            `{"expectedRevision":"` + revision + `","operation":"disable","plaintextAcknowledged":false}`,
		"enable targets":                 `{"expectedRevision":"` + revision + `","operation":"enable","checksFromManagerAcknowledged":true,"destinationsAcknowledged":true,"targets":[]}`,
		"enable missing acknowledgement": `{"expectedRevision":"` + revision + `","operation":"enable","checksFromManagerAcknowledged":true}`,
		"trailing object":                string(valid) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			r, v := o.call(t, "POST", applicationCheckSettingsPath, nil, csrf, func(r *http.Request) {
				r.Body = io.NopCloser(strings.NewReader(body))
				r.ContentLength = int64(len(body))
				r.Header.Set("Content-Type", "application/json")
			})
			raw, _ := json.Marshal(v)
			if r.StatusCode != 400 || strings.Contains(string(raw), "private-fixture") || strings.Contains(string(raw), "secret.invalid") {
				t.Fatal("invalid request accepted or echoed destination", r.StatusCode)
			}
		})
	}
	for name, modify := range map[string]func(*http.Request){
		"csrf":       func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"origin":     func(r *http.Request) { r.Header.Set("Origin", "https://other.example.test") },
		"host":       func(r *http.Request) { r.Host = "other.example.test" },
		"cross site": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
	} {
		t.Run(name, func(t *testing.T) {
			if r, _ := o.call(t, "POST", applicationCheckSettingsPath, applicationCheckSaveInput(revision), csrf, modify); r.StatusCode != 403 {
				t.Fatal("mutation guard bypass", r.StatusCode)
			}
		})
	}
	if r, _ := o.call(t, "GET", applicationCheckSettingsPath+"?target=other", nil, "", nil); r.StatusCode != 400 {
		t.Fatal("query accepted")
	}
	if r, _ := o.call(t, "GET", applicationCheckSettingsPath, map[string]any{}, "", nil); r.StatusCode != 400 {
		t.Fatal("read body accepted")
	}
	for _, method := range []string{"PUT", "DELETE", "PATCH", "HEAD"} {
		if r, _ := o.call(t, method, applicationCheckSettingsPath, nil, csrf, nil); r.StatusCode != 405 {
			t.Fatal("unsupported method accepted", method, r.StatusCode)
		}
	}
	if r, _ := o.call(t, "POST", applicationCheckSettingsPath, nil, csrf, func(r *http.Request) {
		raw := strings.Repeat(" ", applicationCheckSettingsBodyLimit+1)
		r.Body = io.NopCloser(strings.NewReader(raw))
		r.ContentLength = int64(len(raw))
		r.Header.Set("Content-Type", "application/json")
	}); r.StatusCode != 413 {
		t.Fatal("body limit missing", r.StatusCode)
	}
	if s.View().Configured || s.View().Revision != revision {
		t.Fatal("invalid requests mutated state")
	}
}

func TestApplicationCheckSettingsBodyReadDoesNotHoldSessionGate(t *testing.T) {
	o, s := applicationCheckSettingsFixture(t, true, true)
	h := o.server.Config.Handler.(*operatorHandler)
	session, err := h.auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(applicationCheckSaveInput(s.View().Revision))
	body := &gatedAlarmBody{started: make(chan struct{}), allow: make(chan struct{}), reader: strings.NewReader(string(raw))}
	r := httptest.NewRequest("POST", o.server.URL+applicationCheckSettingsPath, body)
	r.Header.Set("Origin", o.server.URL)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", session.CSRFToken)
	active := func() bool { _, err := h.auth.Lookup(session.Token); return err == nil }
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{session: session, origin: o.server.URL, active: active}))
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.applicationCheckSettingsAPI(w, r); close(done) }()
	<-body.started
	logout := make(chan struct{})
	go func() { h.auth.Logout(session.Token); close(logout) }()
	select {
	case <-logout:
	case <-time.After(time.Second):
		close(body.allow)
		<-done
		t.Fatal("slow body blocked logout")
	}
	close(body.allow)
	<-done
	if w.Code != 401 || s.View().Configured {
		t.Fatal("revoked slow body changed settings", w.Code)
	}
}

func TestApplicationCheckSettingsUnavailableExternalAndConstructorBinding(t *testing.T) {
	o := newOperatorFixture(t, 0)
	_, session := o.login(t)
	r, v := o.call(t, "GET", applicationCheckSettingsPath, nil, "", nil)
	if r.StatusCode != 200 || v["mode"] != "unavailable" {
		t.Fatal("unavailable settings hidden", r.StatusCode)
	}
	if r, _ = o.call(t, "POST", applicationCheckSettingsPath, applicationCheckSaveInput(strings.Repeat("a", 32)), session["csrfToken"].(string), nil); r.StatusCode != 503 {
		t.Fatal("unavailable changed", r.StatusCode)
	}
	app := setup(t)
	if w := request(app, "GET", applicationCheckSettingsPath, "", nil); w.Code != 404 {
		t.Fatal("development settings authority", w.Code)
	}
	h := o.server.Config.Handler.(*operatorHandler)
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	path := filepath.Join(dir, "external.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"tracebolt.application-checks-config.v2","enabled":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	external, err := applicationcheck.Load(path, "", o.server.URL, "tls")
	if err != nil {
		t.Fatal(err)
	}
	s, err := applicationcheck.NewSettings(dir, "", o.server.URL, "tls", external)
	if err != nil {
		t.Fatal(err)
	}
	h.applicationCheckSettings = s
	r, v = o.call(t, "GET", applicationCheckSettingsPath, nil, "", nil)
	if r.StatusCode != 200 || v["mode"] != "external" || v["enabled"] != false {
		t.Fatal("disabled external configuration was adopted", r.StatusCode)
	}
	if r, _ = o.call(t, "POST", applicationCheckSettingsPath, map[string]any{"expectedRevision": v["revision"], "operation": "disable"}, session["csrfToken"].(string), nil); r.StatusCode != 503 {
		t.Fatal("external configuration became mutable", r.StatusCode)
	}
	for _, mismatch := range []string{"manager", "origin", "profile", "both"} {
		t.Run(mismatch, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.Chmod(dir, 0700)
			manager, origin, profile := "", o.server.URL, "tls"
			switch mismatch {
			case "manager":
				manager = "manager_11111111111111111111111111111111"
			case "origin":
				origin = "https://other.example.test"
			case "profile":
				origin = "http://other.example.test"
				profile = "http-test"
			}
			s, err := applicationcheck.NewSettings(dir, manager, origin, profile, applicationcheck.Config{})
			if err != nil {
				t.Fatal(err)
			}
			c := LANOperatorConfig{ApplicationCheckSettings: s, Origin: o.server.URL, Auth: h.auth, Registry: o.registry, Devices: func() ([]model.Device, error) { return []model.Device{}, nil }}
			if mismatch == "both" {
				c.ApplicationChecks = applicationcheck.New(applicationcheck.Config{})
			}
			if handler, err := NewLANOperatorHandler(setup(t), c); handler != nil || !errors.Is(err, applicationcheck.ErrConfiguration) {
				t.Fatal("contradictory controller binding accepted", err)
			}
		})
	}
}

func TestApplicationCheckSettingsRejectsExpiredAdministrator(t *testing.T) {
	o, s := applicationCheckSettingsFixture(t, true, true)
	h := o.server.Config.Handler.(*operatorHandler)
	now := time.Now().UTC()
	auth, err := operatorauth.New(operatorauth.Config{Now: func() time.Time { return now }, Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageApplicationChecks}}}})
	if err != nil {
		t.Fatal(err)
	}
	h.auth = auth
	_, session := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	csrf := session["csrfToken"].(string)
	now = now.Add(operatorauth.DefaultTTL)
	if r, _ := o.call(t, "GET", applicationCheckSettingsPath, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("expired settings were readable", r.StatusCode)
	}
	if r, _ := o.call(t, "POST", applicationCheckSettingsPath, applicationCheckSaveInput(s.View().Revision), csrf, nil); r.StatusCode != 401 {
		t.Fatal("expired settings were mutable", r.StatusCode)
	}
	if s.View().Configured {
		t.Fatal("expired session changed settings")
	}
}
