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
	if response.StatusCode != 401 || v["components"] != nil || v["certificateLifetimes"] != nil {
		t.Fatal("revoked session received probe result", response.StatusCode, v)
	}
}

func TestManagerReadinessCertificateLifetimesRemainPrivateReadOnlyEvidence(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	h := o.server.Config.Handler.(*operatorHandler)
	at := time.Now().UTC().Truncate(time.Second)
	from, until := at.Add(-time.Hour), at.Add(7*24*time.Hour)
	h.managerReadiness = func(context.Context) managerreadiness.View {
		v := managerreadiness.NewView(at, []managerreadiness.Component{{Component: "server_certificate", State: "ready"}})
		v.CertificateLifetimes = []managerreadiness.CertificateLifetime{
			{Role: "server_chain", State: "within_7_days", ValidFrom: &from, ValidUntil: &until},
			{Role: "enrollment_issuer", State: "not_configured"},
			{Role: "enrollment_root", State: "not_configured"},
		}
		return v
	}
	if response, _ := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil); response.StatusCode != 200 {
		t.Fatal("named read login")
	}
	response, v := o.call(t, "GET", "/api/manager/readiness", nil, "", nil)
	if response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store" || v["status"] != "ready" {
		t.Fatal("expiry warning changed existing readiness or private response", response.StatusCode, v)
	}
	items, ok := v["certificateLifetimes"].([]any)
	if !ok || len(items) != 3 {
		t.Fatal("missing versioned lifetime evidence", v)
	}
	server, ok := items[0].(map[string]any)
	if !ok || len(server) != 4 || server["role"] != "server_chain" || server["state"] != "within_7_days" || server["validFrom"] != from.Format(time.RFC3339) || server["validUntil"] != until.Format(time.RFC3339) {
		t.Fatal("dates or fixed role changed", server)
	}
	for _, item := range items[1:] {
		row, ok := item.(map[string]any)
		if !ok || len(row) != 2 || row["state"] != "not_configured" {
			t.Fatal("disabled authority had invented certificate dates", item)
		}
	}
	// The same private route still has no renewal/mutation method.
	if response, _ = o.call(t, "POST", "/api/manager/readiness", nil, "", nil); response.StatusCode != 405 && response.StatusCode != 403 {
		t.Fatal("certificate visibility admitted a mutation", response.StatusCode)
	}
}
