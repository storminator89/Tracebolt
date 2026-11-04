package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/applicationcheck"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func historyAccept(r *http.Request) { r.Header.Set("Accept", applicationcheck.HistoryMediaType) }
func TestApplicationCheckHistoryRepresentationPreservesStatus(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	if r, _ := o.call(t, "GET", applicationCheckStatusPath, nil, "", historyAccept); r.StatusCode != 401 {
		t.Fatal("anonymous history accessible")
	}
	_, session := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	r, v := o.call(t, "GET", applicationCheckStatusPath, nil, "", historyAccept)
	if r.StatusCode != 200 || v["schemaVersion"] != applicationcheck.HistorySchema || v["enabled"] != false || r.Header.Get("Content-Type") != applicationcheck.HistoryMediaType || r.Header.Get("Cache-Control") != "no-store" || !strings.Contains(r.Header.Get("Vary"), "Accept") {
		t.Fatal("history representation invalid", r.StatusCode, v, r.Header)
	}
	if items, ok := v["items"].([]any); !ok || len(items) != 0 {
		t.Fatal("disabled history contains samples")
	}
	r, status := o.call(t, "GET", applicationCheckStatusPath, nil, "", nil)
	if r.StatusCode != 200 || status["schemaVersion"] != applicationcheck.SchemaVersion || len(status) != 7 {
		t.Fatal("default strict status contract changed", status)
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if r, _ := o.call(t, method, applicationCheckStatusPath, map[string]bool{"enabled": true}, session["csrfToken"].(string), historyAccept); r.StatusCode != 403 {
			t.Fatal("history allowed named mutation", method, r.StatusCode)
		}
	}
	if r, _ := o.call(t, "GET", applicationCheckStatusPath+"?history=true", nil, "", historyAccept); r.StatusCode != 400 {
		t.Fatal("history changed query boundary")
	}
	if r, _ := o.call(t, "HEAD", applicationCheckStatusPath, nil, "", historyAccept); r.StatusCode != 405 {
		t.Fatal("HEAD history accepted")
	}
}
func TestApplicationCheckHistoryOriginAndFinalSessionBoundaries(t *testing.T) {
	o := newOperatorFixture(t, 0)
	o.login(t)
	for _, change := range []func(*http.Request){func(r *http.Request) { historyAccept(r); r.Header.Set("Origin", "https://foreign.example") }, func(r *http.Request) { historyAccept(r); r.Host = "foreign.example" }, func(r *http.Request) { historyAccept(r); r.Header.Set("Sec-Fetch-Site", "cross-site") }} {
		if r, _ := o.call(t, "GET", applicationCheckStatusPath, nil, "", change); r.StatusCode != 403 {
			t.Fatal("history escaped operator boundary", r.StatusCode)
		}
	}
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		}
		ctx = context.WithValue(ctx, operatorRequestKey{}, operatorRequest{active: func() bool { return canceled }})
		r := httptest.NewRequest("GET", applicationCheckStatusPath, nil).WithContext(ctx)
		historyAccept(r)
		w := httptest.NewRecorder()
		(&operatorHandler{}).applicationCheckStatus(w, r)
		cancel()
		if w.Code != 401 {
			t.Fatal("history published after session loss", w.Code)
		}
	}
}
func TestApplicationCheckHistoryConfiguredSourceIsInertAndRedacted(t *testing.T) {
	o := newOperatorFixture(t, 0)
	m := applicationCheckMonitorFixture(t, "", o.server.URL, "tls")
	o.server.Config.Handler.(*operatorHandler).applicationChecks = m
	o.login(t)
	for range 3 {
		r, v := o.call(t, "GET", applicationCheckStatusPath, nil, "", historyAccept)
		if r.StatusCode != 200 || v["enabled"] != true {
			t.Fatal("configured history unavailable", r.StatusCode, v)
		}
		items := v["items"].([]any)
		if len(items) != 1 || len(items[0].(map[string]any)["samples"].([]any)) != 0 {
			t.Fatal("inert read invented completed checks")
		}
		if strings.Contains(v["schemaVersion"].(string), "example") {
			t.Fatal("configuration leaked")
		}
	}
	if m.Status().Items[0].ObservedAt != nil {
		t.Fatal("history read triggered collection")
	}
}

type historySlowWriter struct {
	*httptest.ResponseRecorder
	deadline time.Time
	entered  chan struct{}
}

func (w *historySlowWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}
func (w *historySlowWriter) Write(raw []byte) (int, error) {
	close(w.entered)
	<-time.After(time.Until(w.deadline))
	return 0, os.ErrDeadlineExceeded
}
func TestApplicationCheckHistorySlowReaderBoundsConfigurationLease(t *testing.T) {
	o, s := applicationCheckSettingsFixture(t, false, false)
	h := o.server.Config.Handler.(*operatorHandler)
	w := &historySlowWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{})}
	r := httptest.NewRequest("GET", applicationCheckStatusPath, nil)
	historyAccept(r)
	started := time.Now()
	done := make(chan struct{})
	go func() { h.applicationCheckStatus(w, r); close(done) }()
	<-w.entered
	if w.deadline.IsZero() || w.deadline.After(started.Add(2100*time.Millisecond)) {
		t.Fatal("history lacks short write deadline")
	}
	if s.WithHistory(func(applicationcheck.HistoryView) { t.Error("queued reader admitted") }) {
		t.Fatal("history readers queue behind slow write")
	}
	change := applicationcheck.SettingsChange{ExpectedRevision: s.View().Revision, Operation: "save", IntervalSeconds: 60, Targets: []json.RawMessage{json.RawMessage(`{"kind":"dns","id":"fixture","host":"private-fixture.example","allowedAddresses":["8.8.8.8"],"allowPrivateLAN":false}`)}}
	changed := make(chan error, 1)
	go func() { changed <- s.Change(context.Background(), change, "shared-administrator") }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("slow response did not finish within bound")
	}
	select {
	case err := <-changed:
		if err != nil {
			t.Fatal("configuration remained blocked", err)
		}
	case <-time.After(time.Second):
		t.Fatal("configuration lease not released")
	}
	if w.deadline.IsZero() {
		t.Fatal("history reset server write deadline")
	}
}
