package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"localrmm/internal/managerstatus"
	"localrmm/internal/operatorauth"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagerStatusIsPrivateCachedAndNotProcessLiveness(t *testing.T) {
	o := newOperatorFixture(t, 0)
	h := o.server.Config.Handler.(*operatorHandler)
	var calls atomic.Int64
	var fail atomic.Bool
	m, err := managerstatus.New([]managerstatus.Check{{Component: managerstatus.AppStorage, Probe: func(context.Context) managerstatus.ProbeResult {
		calls.Add(1)
		if fail.Load() {
			return managerstatus.ProbeResult{State: managerstatus.Full}
		}
		return managerstatus.ProbeResult{State: managerstatus.OK}
	}}}, nil)
	if err != nil {
		t.Fatal("fixture monitor rejected")
	}
	h.managerStatus = m
	o.server.Config.Handler = m.Wrap(managerstatus.Operator, h)
	if r, v := o.call(t, "GET", "/livez", nil, "", nil); r.StatusCode != 200 || v["live"] != true || len(v) != 1 {
		t.Fatal("minimal liveness requires unrelated state")
	}
	for _, path := range []string{"/api/manager/readiness", "/api/manager/metrics"} {
		if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
			t.Fatal("anonymous operational diagnostics admitted")
		}
	}
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	if r, v := o.call(t, "GET", "/api/manager/readiness", nil, "", nil); r.StatusCode != 503 || v["ready"] != false || v["state"] != "starting" {
		t.Fatal("process startup alone was reported ready")
	}
	if err = m.Refresh(context.Background()); err != nil {
		t.Fatal("fixture sample failed")
	}
	if r, v := o.call(t, "GET", "/api/manager/readiness", nil, "", nil); r.StatusCode != 200 || v["ready"] != true {
		t.Fatal("validated healthy sample was not ready")
	}
	for i := 0; i < 3; i++ {
		if r, _ := o.call(t, "GET", "/api/manager/metrics", nil, "", nil); r.StatusCode != 200 {
			t.Fatal("cached metrics unavailable")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("HTTP status reads triggered storage work")
	}
	for _, path := range []string{"/api/manager/readiness", "/api/manager/metrics"} {
		if r, _ := o.call(t, "POST", path, map[string]any{}, csrf, nil); r.StatusCode != 405 {
			t.Fatal("unsupported operational method admitted")
		}
		if r, _ := o.call(t, "GET", path+"?device=private-device-sentinel", nil, "", nil); r.StatusCode != 400 {
			t.Fatal("query-bearing metric labels admitted")
		}
	}
	fail.Store(true)
	if err = m.Refresh(context.Background()); err != nil {
		t.Fatal("failed sample did not complete")
	}
	if r, v := o.call(t, "GET", "/api/manager/readiness", nil, "", nil); r.StatusCode != 503 || v["ready"] != false {
		t.Fatal("failed storage sample appeared ready")
	}
	if r, v := o.call(t, "GET", "/livez", nil, "", nil); r.StatusCode != 200 || v["live"] != true {
		t.Fatal("storage failure changed process liveness")
	}
	r, v := o.call(t, "GET", "/api/manager/metrics", nil, "", nil)
	if r.StatusCode != 200 {
		t.Fatal("unready diagnostic metrics were hidden")
	}
	raw, _ := json.Marshal(v)
	for _, secret := range []string{csrf, testOperatorHash(), operatorFixturePassword, "private-device-sentinel", "/api/manager/metrics", "/livez"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("metrics exposed request/authentication data")
		}
	}
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("operational metrics cacheable")
	}
	if r, _ := o.call(t, "POST", "/api/auth/logout", map[string]any{}, csrf, nil); r.StatusCode != 200 {
		t.Fatal("fixture logout failed")
	}
	if r, _ := o.call(t, "GET", "/api/manager/metrics", nil, "", nil); r.StatusCode != 401 {
		t.Fatal("revoked session read diagnostics")
	}
}

func TestManagerStatusAbsentSurfaceTransportAndHostStayFailClosed(t *testing.T) {
	o := newOperatorFixture(t, 0)
	o.login(t)
	if r, _ := o.call(t, "GET", "/api/manager/readiness", nil, "", nil); r.StatusCode != 404 {
		t.Fatal("missing manager source was invented")
	}
	if r, _ := o.call(t, "GET", "/livez", nil, "", func(r *http.Request) { r.Host = "wrong-authority.invalid" }); r.StatusCode == 200 {
		t.Fatal("liveness bypassed exact Host")
	}
	if r, _ := o.call(t, "POST", "/livez", map[string]any{}, "", nil); r.StatusCode != 405 {
		t.Fatal("liveness accepted unsupported method")
	}
	if r, _ := o.call(t, "GET", "/livez?label=not-allowed", nil, "", nil); r.StatusCode != 400 {
		t.Fatal("liveness accepted dynamic labels")
	}
}

func TestManagerStatusFinalSessionExpiryBeforeResponse(t *testing.T) {
	for _, path := range []string{"/api/manager/readiness", "/api/manager/metrics"} {
		t.Run(path, func(t *testing.T) {
			o := newOperatorFixture(t, 0)
			h := o.server.Config.Handler.(*operatorHandler)
			base := time.Now()
			var calls atomic.Int64
			var armed atomic.Bool
			auth, err := operatorauth.New(operatorauth.Config{PasswordHash: testOperatorHash(), Now: func() time.Time {
				if armed.Load() && calls.Add(1) >= 4 {
					return base.Add(operatorauth.DefaultTTL)
				}
				return base
			}})
			if err != nil {
				t.Fatal("auth fixture failed")
			}
			h.auth = auth
			session, err := auth.Login(context.Background(), "127.0.0.1", operatorFixturePassword)
			if err != nil {
				t.Fatal("fixture session failed")
			}
			monitor, _ := managerstatus.New([]managerstatus.Check{{Component: managerstatus.AppStorage, Probe: func(context.Context) managerstatus.ProbeResult {
				return managerstatus.ProbeResult{State: managerstatus.OK}
			}}}, nil)
			_ = monitor.Refresh(context.Background())
			h.managerStatus = monitor
			armed.Store(true)
			r, v := o.call(t, "GET", path, nil, "", sessionCookie(session))
			if r.StatusCode != 401 || v["components"] != nil || v["snapshot"] != nil {
				t.Fatal("final exact expiry allowed operational response")
			}
		})
	}
}

func TestManagerStatusRevocationDuringSnapshotAndTransportGuards(t *testing.T) {
	o := newOperatorFixture(t, 0)
	h := o.server.Config.Handler.(*operatorHandler)
	session, err := h.auth.Login(context.Background(), "127.0.0.1", operatorFixturePassword)
	if err != nil {
		t.Fatal("fixture login failed")
	}
	var armed atomic.Bool
	revoked := make(chan struct{})
	monitor, err := managerstatus.New([]managerstatus.Check{{Component: managerstatus.AppStorage, Probe: func(context.Context) managerstatus.ProbeResult {
		return managerstatus.ProbeResult{State: managerstatus.OK}
	}}}, func() time.Time {
		if armed.CompareAndSwap(true, false) {
			go func() { h.auth.Logout(session.Token); close(revoked) }()
			<-session.Lifetime().Done()
		}
		return time.Now()
	})
	if err != nil {
		t.Fatal("monitor fixture failed")
	}
	_ = monitor.Refresh(context.Background())
	h.managerStatus = monitor
	if r, _ := o.call(t, "GET", "/api/manager/readiness", nil, "", func(r *http.Request) {
		sessionCookie(session)(r)
		r.Header.Set("Origin", "https://wrong-origin.invalid")
	}); r.StatusCode != 403 {
		t.Fatal("diagnostics bypassed Origin")
	}
	r := httptest.NewRequest(http.MethodGet, o.server.URL+"/api/manager/readiness", nil)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS12, HandshakeComplete: true}
	sessionCookie(session)(r)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("diagnostics bypassed TLS13")
	}
	armed.Store(true)
	response, view := o.call(t, "GET", "/api/manager/readiness", nil, "", sessionCookie(session))
	if response.StatusCode != 401 || view["components"] != nil {
		t.Fatal("revocation during admitted snapshot leaked response")
	}
	select {
	case <-revoked:
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot held revocation barrier after completion")
	}
}
