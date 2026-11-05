package api

import (
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowsfullprocesses"
	watch "localrmm/internal/windowsprocesswatch"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type processWatchSourceFixture struct {
	*groupServiceFixture
	complete           *windowsfullprocesses.Complete
	count, unavailable int
	failGuard          bool
	reads              int
}

func (f *processWatchSourceFixture) WithWindowsProcessWatchAuthority(ctx context.Context, id string, names []string, fn func(watch.Input, func(time.Time) error) error) error {
	base := f.inputs[0]
	if id != base.DeviceID {
		return watch.ErrInvalid
	}
	in := watch.Input{DeviceID: id, InvitationID: base.InvitationID, CertificateHash: base.CertificateHash, CurrentLeaf: base.CertificateHash, AuthorityUntil: base.AuthorityUntil}
	if len(names) > 0 && f.complete != nil {
		f.reads++
		in.Complete = f.complete
		in.Counts = map[string]int{}
		in.UnavailableNames = f.unavailable
		for _, n := range names {
			if n == "FixtureProcess.exe" {
				in.Counts[n] = f.count
			} else {
				in.Counts[n] = 0
			}
		}
	}
	return fn(in, func(time.Time) error {
		if f.failGuard || !in.Authorized(f.now) {
			return watch.ErrInvalid
		}
		return nil
	})
}
func processWatchHandlerFixture(t *testing.T) (*operatorHandler, *processWatchSourceFixture, operatorRequest, string) {
	h, base, op, _ := groupServiceHandlerFixture(t)
	device := base.inputs[0].DeviceID
	name := "FixtureProcess.exe"
	c := windowsfullprocesses.Consent{SchemaVersion: windowsfullprocesses.ConsentVersion, Scope: windowsfullprocesses.Scope, SenderBinding: strings.Repeat("2", 64), GrantID: strings.Repeat("3", 32), Revision: 1, Enabled: true, ChangedAt: base.now}
	messages, e := windowsfullprocesses.Build(device, c, 1, windowsfullprocesses.Capture{StartedAt: base.now, FinishedAt: base.now, Complete: true, Rows: []windowsfullprocesses.Row{{PID: 0, Name: &name, NameQuality: "observed"}}})
	if e != nil {
		t.Fatal(e)
	}
	f := &processWatchSourceFixture{groupServiceFixture: base, complete: &windowsfullprocesses.Complete{Manifest: *messages[0].Manifest, ManifestSHA256: messages[0].ManifestSHA256, ReceivedAt: base.now}, count: 1}
	h.app.windowsCapacity.source = f
	return h, f, op, "/api/devices/" + device + "/windows-process-watches"
}
func processWatchRequest(h *operatorHandler, op operatorRequest, method, path string, body any, change ...func(*http.Request)) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "https://maintenance.invalid"+path, strings.NewReader(string(raw)))
	r.Header.Set("Origin", op.origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", op.session.CSRFToken)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, op))
	for _, f := range change {
		f(r)
	}
	w := httptest.NewRecorder()
	h.windowsProcessWatchesAPI(w, r)
	return w
}
func TestWindowsProcessWatchRecorderConsentPresenceAndDisable(t *testing.T) {
	h, f, op, path := processWatchHandlerFixture(t)
	w := processWatchRequest(h, op, "GET", path, nil)
	var disabled watch.View
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &disabled) != nil || disabled.Policy.Enabled || disabled.Status != "disabled" || f.reads != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	r := watch.Request{Enabled: true, Names: []string{"FixtureProcess.exe"}, Consent: true, Source: f.complete}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, func(r *http.Request) { r.Header.Set("Origin", "https://wrong.invalid") }} {
		if w = processWatchRequest(h, op, "POST", path+"/policy", r, change); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	w = processWatchRequest(h, op, "POST", path+"/policy", r)
	var current watch.View
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &current) != nil || current.Checks[0].Status != "present" {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = processWatchRequest(h, op, "POST", path+"/policy", r); w.Code != 409 {
		t.Fatal("replayed mutation", w.Code)
	}
	f.count = 0
	w = processWatchRequest(h, op, "GET", path, nil)
	var absent watch.View
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &absent) != nil || absent.Checks[0].Status != "not_observed" {
		t.Fatal(w.Code, w.Body.String())
	}
	f.unavailable = 1
	w = processWatchRequest(h, op, "GET", path, nil)
	var unknown watch.View
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &unknown) != nil || unknown.Checks[0].Status != "unknown" || unknown.Checks[0].Matches != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	if output := os.Getenv("TRACEBOLT_WINDOWS_PROCESS_WATCH_FIXTURE"); output != "" {
		raw, _ := json.Marshal(map[string]watch.View{"disabled": disabled, "current": current, "absent": absent, "unknown": unknown})
		if e := os.WriteFile(output, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	f.complete = nil
	w = processWatchRequest(h, op, "POST", path+"/policy", watch.Request{Names: []string{}, ExpectedRevision: 1})
	if w.Code != 200 {
		t.Fatal("disable with explicit null source", w.Code, w.Body.String())
	}
}
func TestWindowsProcessWatchRecorderReadOnlyAndFinalGuards(t *testing.T) {
	for _, kind := range []string{"named", "no-consent", "stale", "final-guard", "logout", "query", "method"} {
		t.Run(kind, func(t *testing.T) {
			h, f, op, path := processWatchHandlerFixture(t)
			r := watch.Request{Enabled: true, Names: []string{"FixtureProcess.exe"}, Consent: true, Source: f.complete}
			method := "POST"
			url := path + "/policy"
			switch kind {
			case "named":
				auth, e := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}}}})
				if e != nil {
					t.Fatal(e)
				}
				op.session, e = auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
				if e != nil {
					t.Fatal(e)
				}
			case "no-consent":
				r.Consent = false
			case "stale":
				f.now = f.now.Add(5 * time.Minute)
			case "final-guard":
				f.failGuard = true
			case "logout":
				op.active = func() bool { return false }
			case "query":
				url += "?name=private"
			case "method":
				method = "GET"
			}
			w := processWatchRequest(h, op, method, url, r)
			if w.Code == 200 {
				t.Fatal("unsafe mutation accepted", w.Body.String())
			}
			state, e := h.app.store.WindowsProcessWatchState(context.Background(), f.inputs[0].DeviceID)
			if e != nil || state.DeviceID != "" {
				t.Fatal("failed mutation wrote state", e)
			}
		})
	}
}
func TestWindowsProcessWatchStrictRequestFields(t *testing.T) {
	h, f, op, path := processWatchHandlerFixture(t)
	valid, _ := json.Marshal(watch.Request{Enabled: true, Names: []string{"FixtureProcess.exe"}, Consent: true, Source: f.complete})
	for _, raw := range []string{strings.Replace(string(valid), `"consent":true`, `"consent":true,"consent":true`, 1), strings.Replace(string(valid), `"enabled":true`, `"enabled":null`, 1), strings.Replace(string(valid), `"consent":true,`, "", 1), strings.Replace(string(valid), `"enabled":true`, `"enabled":true,"unexpected":1`, 1)} {
		w := processWatchRequest(h, op, "POST", path+"/policy", nil, func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(raw)) })
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

func TestWindowsProcessWatchResponseLeaseIncludesSessionExpiry(t *testing.T) {
	h, f, op, path := processWatchHandlerFixture(t)
	op.session.ExpiresAt = f.now.Add(time.Second)
	w := processWatchRequest(h, op, "GET", path, nil)
	var v watch.View
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || !v.ExpiresAt.Equal(op.session.ExpiresAt) {
		t.Fatal(w.Code, w.Body.String())
	}
}
