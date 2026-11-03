package api

import (
	"context"
	"localrmm/internal/managerreadiness"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagerReadinessAuthenticatedReadOnlyBoundary(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	h := o.server.Config.Handler.(*operatorHandler)
	var calls atomic.Int32
	h.managerReadiness = func(ctx context.Context) managerreadiness.View {
		calls.Add(1)
		return managerreadiness.NewView(time.Now(), []managerreadiness.Component{{Component: "fixture", State: "ready"}})
	}
	if response, _ := o.call(t, "GET", "/api/manager/readiness", nil, "", nil); response.StatusCode != 401 || calls.Load() != 0 {
		t.Fatal("anonymous request reached source")
	}
	if response, _ := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil); response.StatusCode != 200 {
		t.Fatal("named login")
	}
	response, v := o.call(t, "GET", "/api/manager/readiness", nil, "", nil)
	if response.StatusCode != 200 || v["status"] != "ready" || v["scope"] != "core_reads_and_last_worker_steps" || response.Header.Get("Cache-Control") != "no-store" || calls.Load() != 1 {
		t.Fatal("authenticated read unavailable", response.StatusCode, v)
	}
	for _, method := range []string{"HEAD", "POST", "DELETE"} {
		response, _ := o.call(t, method, "/api/manager/readiness", nil, "", nil)
		if response.StatusCode != 405 && response.StatusCode != 403 || calls.Load() != 1 {
			t.Fatal("non-GET invoked probe", method, response.StatusCode)
		}
	}
	for _, path := range []string{"/api/manager/readiness?refresh=true", "/api/manager/readiness?", "/api/manager/%72eadiness"} {
		response, _ := o.call(t, "GET", path, nil, "", nil)
		if response.StatusCode != 400 || calls.Load() != 1 {
			t.Fatal("noncanonical read reached source", path, response.StatusCode)
		}
	}
	response, _ = o.call(t, "GET", "/api/manager/readiness", nil, "", func(r *http.Request) { r.Header.Set("Origin", "https://foreign.invalid") })
	if response.StatusCode != 403 || calls.Load() != 1 {
		t.Fatal("foreign origin reached source")
	}
	h.managerReadiness = nil
	response, v = o.call(t, "GET", "/api/manager/readiness", nil, "", nil)
	if response.StatusCode != 503 || v["status"] != "unavailable" {
		t.Fatal("missing provider looked ready")
	}
	if response, _ = o.call(t, "GET", "/api/health", nil, "", nil); response.StatusCode != 200 {
		t.Fatal("static liveness coupled to readiness")
	}
}

func TestManagerReadinessRechecksSessionAfterProbe(t *testing.T) {
	o := newOperatorFixture(t, 0)
	h := o.server.Config.Handler.(*operatorHandler)
	o.login(t)
	u, _ := url.Parse(o.server.URL)
	cookies := o.client.Jar.Cookies(u)
	h.managerReadiness = func(ctx context.Context) managerreadiness.View {
		for _, cookie := range cookies {
			if cookie.Name == h.cookieName {
				h.auth.Logout(cookie.Value)
			}
		}
		return managerreadiness.NewView(time.Now(), []managerreadiness.Component{{Component: "fixture", State: "ready"}})
	}
	response, v := o.call(t, "GET", "/api/manager/readiness", nil, "", nil)
	if response.StatusCode != 401 || v["components"] != nil {
		t.Fatal("revoked session received probe result", response.StatusCode, v)
	}
}
