package api

import (
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/operatorauth"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func alarmSettingsOperatorFixture(t *testing.T, named, granted bool) (operatorFixture, *alarmdelivery.Settings) {
	t.Helper()
	o := newOperatorFixture(t, 0)
	h := o.server.Config.Handler.(*operatorHandler)
	if named {
		caps := []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}
		if granted {
			caps = append(caps, operatorauth.ManageAlarms)
		}
		auth, e := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: caps}}})
		if e != nil {
			t.Fatal(e)
		}
		h.auth = auth
	}
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	settings, e := alarmdelivery.NewSettings(o.app.store, dir, "manager-fixture", "tls", alarmdelivery.Config{})
	if e != nil {
		t.Fatal(e)
	}
	h.alarmSettings = settings
	return o, settings
}
func alarmSettingsInput(rev string) map[string]any {
	return map[string]any{"expectedRevision": rev, "operation": "replace", "endpoint": "https://receiver.example.test/secret-fixture-path?key=secret-fixture-query", "payloadSharingAcknowledged": true, "plaintextAcknowledged": false}
}
func TestAlarmSettingsHTTPPermissionAndExplicitSendBoundary(t *testing.T) {
	for _, mode := range []string{"shared", "named-reader", "named-alarm-admin"} {
		t.Run(mode, func(t *testing.T) {
			o, s := alarmSettingsOperatorFixture(t, mode != "shared", mode == "named-alarm-admin")
			if r, _ := o.call(t, "GET", "/api/alerts/settings", nil, "", nil); r.StatusCode != 401 {
				t.Fatal("anonymous settings")
			}
			var session map[string]any
			if mode == "shared" {
				_, session = o.login(t)
			} else {
				_, session = o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
			}
			r, v := o.call(t, "GET", "/api/alerts/settings", nil, "", nil)
			if r.StatusCode != 200 || v["mode"] != "managed" || v["enabled"] != false {
				t.Fatal(r.StatusCode, v)
			}
			csrf := session["csrfToken"].(string)
			in := alarmSettingsInput(v["revision"].(string))
			r, v = o.call(t, "POST", "/api/alerts/settings", in, csrf, nil)
			if mode == "named-reader" {
				if r.StatusCode != 403 {
					t.Fatal("reader gained alarm admin", r.StatusCode)
				}
				return
			}
			if r.StatusCode != 200 || v["enabled"] != true || v["destinationHost"] != "receiver.example.test" || v["test"] != nil {
				t.Fatal(r.StatusCode, v)
			}
			raw, _ := json.Marshal(v)
			if strings.Contains(string(raw), "secret-fixture") || strings.Contains(string(raw), "endpoint") {
				t.Fatal("secret readback")
			}
			status, e := o.app.store.AlarmStatus(context.Background())
			if e != nil || status.Queued != 0 || status.ProviderAccepted != 0 {
				t.Fatal("saving sent or backfilled", status, e)
			}
			test := map[string]any{"expectedRevision": v["revision"], "requestId": strings.Repeat("a", 32), "testAcknowledged": false}
			if r, _ = o.call(t, "POST", "/api/alerts/test", test, csrf, nil); r.StatusCode != 400 {
				t.Fatal("implicit test allowed")
			}
			test["testAcknowledged"] = true
			if r, v = o.call(t, "POST", "/api/alerts/test", test, csrf, nil); r.StatusCode != 200 {
				t.Fatal("explicit test not queued", r.StatusCode, v)
			}
			testView := v["test"].(map[string]any)
			if testView["state"] != "queued" {
				t.Fatal("queue mislabeled delivered")
			}
			if r, v = o.call(t, "POST", "/api/alerts/test", test, csrf, nil); r.StatusCode != 200 || v["test"].(map[string]any)["eventId"] != testView["eventId"] {
				t.Fatal("duplicate test requeued")
			}
			status, _ = o.app.store.AlarmStatus(context.Background())
			if status.Queued != 1 || status.InFlight != 0 || status.ProviderAccepted != 0 {
				t.Fatal("test handler performed external send", status)
			}
			_, _ = s.View(context.Background()) // readback remains inert
			test["requestId"] = strings.Repeat("b", 32)
			if r, _ = o.call(t, "POST", "/api/alerts/test", test, csrf, nil); r.StatusCode != 429 {
				t.Fatal("test limit missing")
			}
			if r, _ = o.call(t, "POST", "/api/alerts/settings", in, csrf, nil); r.StatusCode != 409 {
				t.Fatal("stale destination approval applied")
			}
			if r, _ = o.call(t, "POST", "/api/auth/logout", map[string]any{}, csrf, nil); r.StatusCode != 200 {
				t.Fatal("logout")
			}
			if r, _ = o.call(t, "POST", "/api/alerts/test", test, csrf, nil); r.StatusCode != 401 {
				t.Fatal("revoked session queued test")
			}
		})
	}
}
func TestAlarmSettingsHTTPExactGuards(t *testing.T) {
	o, _ := alarmSettingsOperatorFixture(t, false, false)
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	_, v := o.call(t, "GET", "/api/alerts/settings", nil, "", nil)
	in := alarmSettingsInput(v["revision"].(string))
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{"missing csrf", func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 403},
		{"duplicate csrf", func(r *http.Request) { r.Header.Add("X-CSRF-Token", csrf) }, 403},
		{"origin", func(r *http.Request) { r.Header.Set("Origin", "https://other.example.test") }, 403},
		{"content type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		{"query", func(r *http.Request) { r.URL.RawQuery = "endpoint=private" }, 400},
		{"force query", func(r *http.Request) { r.URL.ForceQuery = true }, 400},
		{"unknown field", func(r *http.Request) {
			raw, _ := json.Marshal(in)
			raw = append(raw[:len(raw)-1], []byte(`,"actor":"admin"}`)...)
			r.Body = io.NopCloser(strings.NewReader(string(raw)))
			r.ContentLength = int64(len(raw))
		}, 400},
		{"duplicate field", func(r *http.Request) {
			raw, _ := json.Marshal(in)
			raw = append(raw[:len(raw)-1], []byte(`,"endpoint":"https://other.example.test"}`)...)
			r.Body = io.NopCloser(strings.NewReader(string(raw)))
			r.ContentLength = int64(len(raw))
		}, 400},
		{"oversize", func(r *http.Request) {
			raw := strings.Repeat(" ", 6145)
			r.Body = io.NopCloser(strings.NewReader(raw))
			r.ContentLength = int64(len(raw))
		}, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r, _ := o.call(t, "POST", "/api/alerts/settings", in, csrf, tc.mutate); r.StatusCode != tc.status {
				t.Fatal(r.StatusCode)
			}
		})
	}
	for _, method := range []string{"PUT", "DELETE", "PATCH", "HEAD"} {
		if r, _ := o.call(t, method, "/api/alerts/settings", nil, csrf, nil); r.StatusCode != 405 {
			t.Fatal(method, r.StatusCode)
		}
	}
	if r, _ := o.call(t, "GET", "/api/alerts/test", nil, "", nil); r.StatusCode != 405 {
		t.Fatal("GET sends test")
	}
	status, _ := o.app.store.AlarmStatus(context.Background())
	if status.Enabled || status.Queued != 0 {
		t.Fatal("invalid requests mutated state")
	}
}

type gatedAlarmBody struct {
	once    sync.Once
	started chan struct{}
	allow   chan struct{}
	reader  io.Reader
}

func (b *gatedAlarmBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.allow
	return b.reader.Read(p)
}
func (*gatedAlarmBody) Close() error { return nil }
func TestAlarmSettingsBodyReadDoesNotHoldSessionGate(t *testing.T) {
	o, s := alarmSettingsOperatorFixture(t, false, false)
	h := o.server.Config.Handler.(*operatorHandler)
	session, e := h.auth.Login(context.Background(), "127.0.0.1", operatorFixturePassword)
	if e != nil {
		t.Fatal(e)
	}
	v, _ := s.View(context.Background())
	raw, _ := json.Marshal(alarmSettingsInput(v.Revision))
	body := &gatedAlarmBody{started: make(chan struct{}), allow: make(chan struct{}), reader: strings.NewReader(string(raw))}
	r := httptest.NewRequest("POST", o.server.URL+"/api/alerts/settings", body)
	r.Header.Set("Origin", o.server.URL)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", session.CSRFToken)
	active := func() bool { _, e := h.auth.Lookup(session.Token); return e == nil }
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{session: session, origin: o.server.URL, active: active}))
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.alarmSettingsAPI(w, r); close(done) }()
	<-body.started
	logout := make(chan struct{})
	go func() { h.auth.Logout(session.Token); close(logout) }()
	select {
	case <-logout:
	case <-time.After(time.Second):
		close(body.allow)
		<-done
		t.Fatal("slow request body blocked logout")
	}
	close(body.allow)
	<-done
	if w.Code != 401 {
		t.Fatal("revoked body authorized config", w.Code)
	}
	v, _ = s.View(context.Background())
	if v.Enabled {
		t.Fatal("revoked body changed settings")
	}
}
func TestAlarmSettingsUnavailableAndDevelopmentHaveNoAuthority(t *testing.T) {
	o := newOperatorFixture(t, 0)
	_, session := o.login(t)
	r, v := o.call(t, "GET", "/api/alerts/settings", nil, "", nil)
	if r.StatusCode != 200 || v["mode"] != "unavailable" {
		t.Fatal(r.StatusCode, v)
	}
	if r, _ = o.call(t, "POST", "/api/alerts/settings", alarmSettingsInput(strings.Repeat("a", 32)), session["csrfToken"].(string), nil); r.StatusCode != 503 {
		t.Fatal("unavailable modified", r.StatusCode)
	}
	s := setup(t)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "http://localhost:8787/api/alerts/settings", nil))
	if w.Code == 200 {
		t.Fatal("development settings API exposed")
	}
}

func TestAlarmStatusDoesNotClaimEnabledAfterBlockedSettings(t *testing.T) {
	o := newOperatorFixture(t, 0)
	h := o.server.Config.Handler.(*operatorHandler)
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	settings, e := alarmdelivery.NewSettings(o.app.store, dir, "manager-fixture", "tls", alarmdelivery.Config{})
	if e != nil {
		t.Fatal(e)
	}
	h.alarmSettings = settings
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	_, v := o.call(t, "GET", "/api/alerts/settings", nil, "", nil)
	r, v := o.call(t, "POST", "/api/alerts/settings", alarmSettingsInput(v["revision"].(string)), csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	if r, v = o.call(t, "GET", "/api/alerts/status", nil, "", nil); r.StatusCode != 200 || v["enabled"] != true {
		t.Fatal(r.StatusCode, v)
	}
	// Simulate a protected-file failure after approval. No provider worker runs.
	if e = os.Chmod(dir+"/"+alarmdelivery.SettingsFile, 0644); e != nil {
		t.Fatal(e)
	}
	current, _ := settings.View(context.Background())
	e = settings.Change(context.Background(), alarmdelivery.SettingsChange{ExpectedRevision: current.Revision, Operation: "disable"}, "shared-administrator")
	if e != alarmdelivery.ErrSettingsUnavailable {
		t.Fatal(e)
	}
	// Model a failed emergency DB suppression while the controller stays blocked.
	// The authenticated API must mask the stale DB flag downward independently.
	staleBinding := alarmdelivery.Binding{ManagerInstanceID: "manager-fixture", Profile: "tls", DestinationID: "fixture", Generation: "stale", Fingerprint: strings.Repeat("a", 64)}
	if e = o.app.store.ConfigureAlarms(context.Background(), &staleBinding, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	stale, _ := o.app.store.AlarmStatus(context.Background())
	if !stale.Enabled {
		t.Fatal("fixture did not restore stale enabled flag")
	}
	if r, v = o.call(t, "GET", "/api/alerts/status", nil, "", nil); r.StatusCode != 200 || v["enabled"] != false {
		t.Fatal("blocked sender labeled enabled", r.StatusCode, v)
	}
	if r, v = o.call(t, "GET", "/api/alerts/settings", nil, "", nil); r.StatusCode != 200 || v["blocked"] != true || v["enabled"] != false {
		t.Fatal("blocked state lost", r.StatusCode, v)
	}
}
