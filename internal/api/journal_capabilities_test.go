package api

import (
	"crypto/tls"
	"encoding/json"
	"localrmm/internal/enrollmentservice"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJournalCapabilitiesPublicStaticBoundedAndGuarded(t *testing.T) {
	for _, tlsMode := range []bool{false, true} {
		for _, kind := range []string{"exact", "wrong-host", "wrong-transport", "post", "body", "cookie", "authorization", "forwarded", "query", "escaped", "disabled", "limit"} {
			t.Run(kind+map[bool]string{false: "-http", true: "-tls"}[tlsMode], func(t *testing.T) {
				h := &operatorHandler{authority: "127.0.0.1:8787", origin: "http://127.0.0.1:8787", insecureHTTPTest: !tlsMode, enrollment: &enrollmentservice.Service{}, enrollmentBootstrap: downloadFixtureBootstrap()}
				r := httptest.NewRequest("GET", h.origin+journalCapabilitiesPath, nil)
				r.RemoteAddr = "127.0.0.1:1234"
				if tlsMode {
					r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
				}
				switch kind {
				case "wrong-host":
					r.Host = "wrong.example"
				case "wrong-transport":
					if tlsMode {
						r.TLS = nil
					} else {
						r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
					}
				case "post":
					r.Method = "POST"
				case "body":
					r = httptest.NewRequest("GET", h.origin+journalCapabilitiesPath, strings.NewReader("x"))
					r.RemoteAddr = "127.0.0.1:1234"
					if tlsMode {
						r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
					}
				case "cookie":
					r.Header.Set("Cookie", "fixture")
				case "authorization":
					r.Header.Set("Authorization", "fixture")
				case "forwarded":
					r.Header.Set("X-Forwarded-For", "127.0.0.1")
				case "query":
					r.URL.RawQuery = "x=1"
				case "escaped":
					r.URL.RawPath = "/v3/journal/%63apabilities"
				case "disabled":
					h.enrollment = nil
				case "limit":
					for i := 0; i < 30; i++ {
						w := httptest.NewRecorder()
						h.ServeHTTP(w, r)
						if w.Code != 200 {
							t.Fatal("budget consumed too early")
						}
					}
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if kind != "exact" {
					if w.Code < 400 {
						t.Fatal("invalid capability request accepted")
					}
					return
				}
				var got map[string]any
				if w.Code != 200 || len(w.Body.Bytes()) > 2048 || json.Unmarshal(w.Body.Bytes(), &got) != nil || len(got) != 5 || got["schemaVersion"] != "tracebolt.journal-manager-capabilities.v1" || got["agentOrigin"] != h.enrollmentBootstrap.AgentOrigin || got["generationReport"] != "tracebolt.journal-generation-report.v2" || got["request"] != "tracebolt.journal-request.v2" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Access-Control-Allow-Origin") != "" {
					t.Fatal("unexpected static capability body")
				}
				scopes, ok := got["serviceAuthorization"].([]any)
				if !ok || len(scopes) != 2 || scopes[0] != "exact-units" || scopes[1] != "all-system-services" {
					t.Fatal("scope contract")
				}
				if w.Header().Get("Set-Cookie") != "" {
					t.Fatal("public route created credentials")
				}
			})
		}
	}
}
func TestJournalCapabilitiesUnavailableOnDeveloperSurface(t *testing.T) {
	w := request(setup(t), http.MethodGet, journalCapabilitiesPath, "", nil)
	if w.Code != 404 {
		t.Fatal("development exposed public capability route")
	}
}
