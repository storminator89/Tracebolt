package api

import (
	"crypto/tls"
	"encoding/json"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/windowssetup"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWindowsSetupCapabilitiesExactPublicGuardedTLSContract(t *testing.T) {
	for _, kind := range []string{"exact", "wrong-host", "missing-tls", "old-tls", "http", "disabled", "post", "body", "cookie", "authorization", "forwarded", "query", "escaped", "limit"} {
		t.Run(kind, func(t *testing.T) {
			b := downloadFixtureBootstrap()
			b.Profile = "tls"
			b.EnrollmentOrigin = "https://127.0.0.1:8787"
			b.AgentOrigin = "https://127.0.0.1:8788"
			b.CollectionProfile = "windows-inventory-v1"
			h := &operatorHandler{authority: "127.0.0.1:8787", origin: b.EnrollmentOrigin, windowsEnrollment: &operatorHandler{enrollment: &enrollmentservice.Service{}, enrollmentBootstrap: b}}
			r := httptest.NewRequest(http.MethodGet, h.origin+windowssetup.CapabilitiesPath, nil)
			r.RemoteAddr = "127.0.0.1:1234"
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
			switch kind {
			case "wrong-host":
				r.Host = "wrong.example"
			case "missing-tls":
				r.TLS = nil
			case "old-tls":
				r.TLS.Version = tls.VersionTLS12
			case "http":
				h.insecureHTTPTest = true
				r.TLS = nil
				b.Profile = "http-test"
				b.EnrollmentOrigin = "http://127.0.0.1:8787"
				b.AgentOrigin = "http://127.0.0.1:8788"
				h.origin = b.EnrollmentOrigin
				h.windowsEnrollment.enrollmentBootstrap = b
				r.URL.Scheme = "http"
			case "disabled":
				h.windowsEnrollment = nil
			case "post":
				r.Method = "POST"
			case "body":
				r.Body = http.NoBody
				r.ContentLength = 1
			case "cookie":
				r.Header.Set("Cookie", "fixture")
			case "authorization":
				r.Header.Set("Authorization", "fixture")
			case "forwarded":
				r.Header.Set("Forwarded", "for=127.0.0.1")
			case "query":
				r.URL.RawQuery = "x=1"
			case "escaped":
				r.URL.RawPath = "/v1/windows/%73etup-capabilities"
			case "limit":
				for i := 0; i < 30; i++ {
					h.ServeHTTP(httptest.NewRecorder(), r)
				}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if kind != "exact" && kind != "http" {
				if w.Code < 400 {
					t.Fatal("invalid public request accepted", w.Code)
				}
				return
			}
			want, _ := json.Marshal(windowssetup.Expected(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin))
			if w.Code != 200 || string(want) != w.Body.String() || w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("wrong public contract")
			}
			if strings.Contains(w.Body.String(), "invitation") {
				t.Fatal("invitation exposed")
			}
		})
	}
}
func TestWindowsSetupCapabilitiesAbsentOnDeveloper(t *testing.T) {
	if request(setup(t), http.MethodGet, windowssetup.CapabilitiesPath, "", nil).Code != 404 {
		t.Fatal("developer exposes setup capability")
	}
}
