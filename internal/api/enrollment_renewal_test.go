package api

import (
	"context"
	"crypto/tls"
	"localrmm/internal/enrollmentservice"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRenewalIngressRejectsHTTPAndOldTLSExplicitly(t *testing.T) {
	for _, windows := range []bool{false, true} {
		for _, mode := range []string{"http", "signed-http", "tls12"} {
			t.Run(mode+map[bool]string{false: "-linux", true: "-windows"}[windows], func(t *testing.T) {
				native := &operatorHandler{enrollment: &enrollmentservice.Service{}, insecureHTTPTest: mode == "signed-http"}
				h := native
				path := "/v2/enrollment/renewal/challenge"
				if windows {
					h = &operatorHandler{windowsEnrollment: native}
					path = "/v2/windows/enrollment/renewal/challenge"
				}
				r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
				r.Header.Set("Content-Type", "application/json")
				if mode == "tls12" {
					r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS12}
				}
				w := httptest.NewRecorder()
				if windows {
					h.windowsEnrollmentClient(w, r)
				} else {
					h.enrollmentClient(w, r)
				}
				if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "renewal_tls_required") {
					t.Fatalf("transport did not fail explicitly: %d %s", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestRenewalOperatorReadSuppliesSeparateDisableRevision(t *testing.T) {
	f := newWindowsEventOperatorFixtureWithIssuerLifetime(t, false, 24*time.Hour, true)
	path := "/api/windows/enrollment/" + f.snap.InvitationID + "/renewal"
	r, raw := f.call(t, http.MethodGet, path, nil, "", nil)
	if r.StatusCode != http.StatusOK {
		t.Fatal("renewal read unavailable", r.StatusCode, raw)
	}
	view := windowsEventOperatorDecode[enrollmentservice.RenewalEnvelope](t, raw)
	if view.Revision != f.snap.Revision || !view.Enabled || view.IdentityGeneration == "" || view.Status != "blocked" {
		t.Fatal("missing revision or issuer exhaustion status")
	}
	request := "request_" + strings.Repeat("9", 32)
	r, raw = f.call(t, http.MethodPost, "/api/windows/enrollment/"+f.snap.InvitationID+"/disable-renewal", map[string]any{"requestId": request, "expectedRevision": view.Revision}, f.csrf, nil)
	if r.StatusCode != http.StatusOK {
		t.Fatal("disable from read revision failed", r.StatusCode, raw)
	}
	r, raw = f.call(t, http.MethodGet, path, nil, "", nil)
	after := windowsEventOperatorDecode[enrollmentservice.RenewalEnvelope](t, raw)
	if r.StatusCode != http.StatusOK || after.Enabled || after.Revision <= view.Revision || after.Status != "blocked" {
		t.Fatal("disable read is stale", r.StatusCode)
	}
	snapshot, e := f.store.Get(context.Background(), f.snap.InvitationID)
	if e != nil || snapshot != f.snap {
		t.Fatal("operator renewal read or disable relabeled anchor", e)
	}
	f.client.Jar = nil
	r, _ = f.call(t, http.MethodGet, path, nil, "", nil)
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatal("renewal operator read escaped session auth", r.StatusCode)
	}
}
