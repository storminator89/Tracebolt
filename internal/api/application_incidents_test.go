package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"localrmm/internal/applicationcheck"
	"localrmm/internal/health"
	"localrmm/internal/operatorauth"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const applicationIncidentsPath = "/api/application-checks/incidents"

func applicationIncidentFixture(t *testing.T, named, granted bool) (operatorFixture, *applicationcheck.Settings, string) {
	t.Helper()
	o, _ := applicationCheckSettingsFixture(t, named, granted)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := applicationcheck.NewSettings(dir, "", o.server.URL, "tls", applicationcheck.Config{}, o.app.store)
	if err != nil {
		t.Fatal(err)
	}
	o.server.Config.Handler.(*operatorHandler).applicationCheckSettings = s
	var login map[string]any
	if named {
		_, login = o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	} else {
		_, login = o.login(t)
	}
	// Existing separately authorized setup, never its supervisor/probe lifecycle.
	in := applicationCheckSaveInput(s.View().Revision)
	raw, _ := json.Marshal(in)
	var save applicationcheck.SettingsChange
	if json.Unmarshal(raw, &save) != nil {
		t.Fatal("fixture")
	}
	if err := s.Change(context.Background(), save, "shared-administrator"); err != nil {
		t.Fatal(err)
	}
	if err := s.Change(context.Background(), applicationcheck.SettingsChange{ExpectedRevision: s.View().Revision, Operation: "enable", ChecksFromManagerAcknowledged: true, DestinationsAcknowledged: true}, "shared-administrator"); err != nil {
		t.Fatal(err)
	}
	return o, s, login["csrfToken"].(string)
}
func incidentAPICommand(view map[string]any, n int, op string, incident any) map[string]any {
	c := map[string]any{"requestId": fmt.Sprintf("apprequest_%032x", n), "expectedRevision": view["revision"], "operation": op, "sourceToken": view["currentSource"].(map[string]any)["token"], "targetIds": []string{}, "consecutiveFailures": 0, "incidentId": incident, "retentionAcknowledged": false}
	if op == "enable" {
		c["targetIds"] = []string{"fixture"}
		c["consecutiveFailures"] = 2
		c["retentionAcknowledged"] = true
	}
	return c
}
func feedIncidentAPI(t *testing.T, o operatorFixture, s *applicationcheck.Settings, state, reason string, status *int) {
	t.Helper()
	if !s.WithIncidentSource(func(src applicationcheck.IncidentSource) {
		at := src.Now().UTC()
		r := applicationcheck.IncidentObservation{TargetID: "fixture", Kind: "http", Scheme: "https", State: state, Reason: reason, HTTPStatus: status, ObservedAt: at, CompletedAt: at}
		if err := o.app.store.ObserveApplicationResult(context.Background(), src, r); err != nil {
			t.Fatal(err)
		}
	}) {
		t.Fatal("source lease")
	}
}
func TestApplicationIncidentsAPIWholeLifecycleAndRealDTO(t *testing.T) {
	o, s, csrf := applicationIncidentFixture(t, false, false)
	response, v := o.call(t, "GET", applicationIncidentsPath, nil, "", nil)
	if response.StatusCode != 200 || v["revision"] != "0" || v["policy"].(map[string]any)["enabled"] != false {
		t.Fatal(response.StatusCode, v)
	}
	enable := incidentAPICommand(v, 1, "enable", nil)
	response, v = o.call(t, "POST", applicationIncidentsPath, enable, csrf, nil)
	if response.StatusCode != 200 || v["revision"] != "1" {
		t.Fatal(response.StatusCode, v)
	}
	response, replay := o.call(t, "POST", applicationIncidentsPath, enable, csrf, nil)
	if response.StatusCode != 200 || replay["revision"] != "1" {
		t.Fatal("exact reconcile", replay)
	}
	failure := 503
	feedIncidentAPI(t, o, s, "http_error", "http_status", &failure)
	feedIncidentAPI(t, o, s, "http_error", "http_status", &failure)
	response, v = o.call(t, "GET", applicationIncidentsPath, nil, "", nil)
	incidents := v["incidents"].([]any)
	if response.StatusCode != 200 || len(incidents) != 1 || incidents[0].(map[string]any)["state"] != "open" || v["revision"] != "1" {
		t.Fatal("opening/revision", v)
	}
	raw, _ := json.Marshal(v)
	t.Log("APPLICATION_INCIDENT_FIXTURE=" + string(raw))
	for _, forbidden := range []string{"private-fixture", "8.8.8.8", "SourceKey", "PolicyKey", "allowedAddresses", "certificate", "provider"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("private field escaped", forbidden)
		}
	}
	id := incidents[0].(map[string]any)["id"]
	ack := incidentAPICommand(v, 2, "acknowledge", id)
	response, v = o.call(t, "POST", applicationIncidentsPath, ack, csrf, nil)
	if response.StatusCode != 200 || v["incidents"].([]any)[0].(map[string]any)["acknowledgedAt"] == nil {
		t.Fatal("seen", v)
	}
	ok := 200
	feedIncidentAPI(t, o, s, "ok", "http_2xx", &ok)
	feedIncidentAPI(t, o, s, "unknown", "destination_blocked", nil)
	_, v = o.call(t, "GET", applicationIncidentsPath, nil, "", nil)
	if v["incidents"].([]any)[0].(map[string]any)["state"] != "open" {
		t.Fatal("unknown recovered")
	}
	feedIncidentAPI(t, o, s, "ok", "http_2xx", &ok)
	feedIncidentAPI(t, o, s, "ok", "http_2xx", &ok)
	_, v = o.call(t, "GET", applicationIncidentsPath, nil, "", nil)
	if v["incidents"].([]any)[0].(map[string]any)["state"] != "recovered" {
		t.Fatal("recovery", v)
	}
	disable := incidentAPICommand(v, 3, "disable", nil)
	response, v = o.call(t, "POST", applicationIncidentsPath, disable, csrf, nil)
	if response.StatusCode != 200 || v["policy"].(map[string]any)["enabled"] != false {
		t.Fatal("disable", v)
	}
	if response, _ = o.call(t, "POST", applicationIncidentsPath, ack, csrf, nil); response.StatusCode != 409 {
		t.Fatal("stale ack accepted")
	}
}
func TestApplicationIncidentsAPISourceReplacementAndReadPermission(t *testing.T) {
	for _, mode := range []string{"shared", "named-read", "named-app-admin"} {
		t.Run(mode, func(t *testing.T) {
			o, s, csrf := applicationIncidentFixture(t, mode != "shared", mode == "named-app-admin")
			response, v := o.call(t, "GET", applicationIncidentsPath, nil, "", nil)
			can := mode != "named-read"
			if response.StatusCode != 200 || v["canManage"] != can {
				t.Fatal("read", v)
			}
			enable := incidentAPICommand(v, 1, "enable", nil)
			response, v = o.call(t, "POST", applicationIncidentsPath, enable, csrf, nil)
			if !can {
				if response.StatusCode != 403 {
					t.Fatal("ungranted write")
				}
				return
			}
			if response.StatusCode != 200 {
				t.Fatal(response.StatusCode, v)
			}
			failure := 503
			feedIncidentAPI(t, o, s, "http_error", "http_status", &failure)
			feedIncidentAPI(t, o, s, "http_error", "http_status", &failure)
			if err := s.Change(context.Background(), applicationcheck.SettingsChange{ExpectedRevision: s.View().Revision, Operation: "disable"}, "shared-administrator"); err != nil {
				t.Fatal(err)
			}
			response, v = o.call(t, "GET", applicationIncidentsPath, nil, "", nil)
			source := v["currentSource"].(map[string]any)
			row := v["incidents"].([]any)[0].(map[string]any)
			if response.StatusCode != 200 || len(source["targets"].([]any)) != 0 || source["intervalSeconds"] != float64(0) || v["policy"].(map[string]any)["enabled"] != false || row["state"] != "monitoring_stopped" || row["sourceCurrent"] != false {
				t.Fatal("source retirement", v)
			}
			if response, _ = o.call(t, "POST", applicationIncidentsPath, enable, csrf, nil); response.StatusCode != 409 {
				t.Fatal("stale source retry admitted")
			}
		})
	}
}
func TestApplicationIncidentsAPIStrictBoundary(t *testing.T) {
	o, _, csrf := applicationIncidentFixture(t, false, false)
	_, v := o.call(t, "GET", applicationIncidentsPath, nil, "", nil)
	valid, _ := json.Marshal(incidentAPICommand(v, 1, "enable", nil))
	base := string(valid)
	for _, raw := range []string{strings.Replace(base, `"expectedRevision":"0"`, `"expectedRevision":"00"`, 1), strings.Replace(base, `"incidentId":null`, `"incidentId":null,"extra":true`, 1), strings.Replace(base, `"requestId":`, `"requestId":"apprequest_11111111111111111111111111111111","requestId":`, 1), strings.Replace(base, `"targetIds":["fixture"]`, `"targetIds":null`, 1), base + ` {}`, strings.Repeat(" ", 4097) + base} {
		response, _ := o.call(t, "POST", applicationIncidentsPath, nil, csrf, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(raw))
			r.ContentLength = int64(len(raw))
		})
		want := 400
		if len(raw) > 4096 {
			want = 413
		}
		if response.StatusCode != want {
			t.Fatal("framing", response.StatusCode, raw)
		}
	}
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{{"HEAD", applicationIncidentsPath, nil, 405}, {"GET", applicationIncidentsPath + "?x=1", nil, 400}, {"GET", applicationIncidentsPath, map[string]string{}, 400}, {"GET", applicationIncidentsPath + "/extra", nil, 404}} {
		response, _ := o.call(t, tc.method, tc.path, tc.body, "", nil)
		if response.StatusCode != tc.want {
			t.Fatal(tc, response.StatusCode)
		}
	}
	if response, _ := o.call(t, "POST", applicationIncidentsPath, incidentAPICommand(v, 1, "enable", nil), "bad", nil); response.StatusCode != 403 {
		t.Fatal("csrf")
	}
	entered, done, released := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		s := o.server.Config.Handler.(*operatorHandler).applicationCheckSettings
		s.WithIncidentSource(func(applicationcheck.IncidentSource) { close(entered); <-done })
		close(released)
	}()
	<-entered
	response, _ := o.call(t, "GET", applicationIncidentsPath, nil, "", nil)
	close(done)
	if response.StatusCode != 503 {
		t.Fatal("busy lease")
	}
	<-released
	if response, _ := o.call(t, "GET", applicationIncidentsPath, nil, "", nil); response.StatusCode != 200 {
		t.Fatal("lease not released")
	}
	if w := request(setup(t), "GET", applicationIncidentsPath, "", nil); w.Code != 404 {
		t.Fatal("development exposure", w.Code, w.Body.String())
	}
}

func TestApplicationIncidentsAPIExpiryBeforeSerializedCommit(t *testing.T) {
	o, s, _ := applicationIncidentFixture(t, false, false)
	now := time.Now().UTC()
	var authNow atomic.Int64
	authNow.Store(now.UnixNano())
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: testOperatorHash(), TTL: time.Minute, Now: func() time.Time { return time.Unix(0, authNow.Load()).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	o.server.Config.Handler.(*operatorHandler).auth = auth
	_, login := o.login(t)
	_, v := o.call(t, "GET", applicationIncidentsPath, nil, "", nil)
	command := incidentAPICommand(v, 1, "enable", nil)
	entered, release := make(chan struct{}), make(chan struct{})
	held := make(chan error, 1)
	go func() {
		_, err := o.app.store.UpdateHealth(context.Background(), "agent_incident_fixture", func(*health.State) error { close(entered); <-release; return nil })
		held <- err
	}()
	<-entered
	result := make(chan int, 1)
	go func() {
		response, _ := o.call(t, "POST", applicationIncidentsPath, command, login["csrfToken"].(string), nil)
		result <- response.StatusCode
	}()
	deadline := time.Now().Add(time.Second)
	leased := false
	for time.Now().Before(deadline) {
		if !s.WithIncidentSource(func(applicationcheck.IncidentSource) {}) {
			leased = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !leased {
		close(release)
		t.Fatal("mutation never admitted source")
	}
	authNow.Store(now.Add(time.Minute).UnixNano())
	close(release)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if status := <-result; status != 401 {
		t.Fatal("expired mutation", status)
	}
	s.WithIncidentSource(func(source applicationcheck.IncidentSource) {
		view, err := o.app.store.ApplicationIncidents(context.Background(), source, true)
		if err != nil || view.Revision != 0 || view.Policy.Enabled {
			t.Fatal("expired session wrote policy", err, view)
		}
	})
}

func TestApplicationIncidentsAPIRequiresWiredCompletionSink(t *testing.T) {
	o, _ := applicationCheckSettingsFixture(t, false, false)
	o.login(t)
	response, _ := o.call(t, "GET", applicationIncidentsPath, nil, "", nil)
	if response.StatusCode != 503 {
		t.Fatal("unwired component pretended availability", response.StatusCode)
	}
}
