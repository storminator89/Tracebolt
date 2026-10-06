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

func TestSocketOwnerCapabilitiesPublicStaticBoundedAndGuarded(t *testing.T) {
	for _, tlsMode := range []bool{false, true} {
		for _, kind := range []string{"exact", "wrong-host", "wrong-transport", "post", "body", "cookie", "authorization", "forwarded", "query", "escaped", "disabled", "limit"} {
			t.Run(kind+map[bool]string{false: "-http", true: "-tls"}[tlsMode], func(t *testing.T) {
				h := &operatorHandler{authority: "127.0.0.1:8787", origin: "http://127.0.0.1:8787", insecureHTTPTest: !tlsMode, enrollment: &enrollmentservice.Service{}, enrollmentBootstrap: downloadFixtureBootstrap()}
				r := httptest.NewRequest("GET", h.origin+socketOwnerCapabilitiesPath, nil)
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
					r = httptest.NewRequest("GET", h.origin+socketOwnerCapabilitiesPath, strings.NewReader("x"))
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
					r.URL.RawPath = "/v4/system/%63apabilities"
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
				if w.Code != 200 || len(w.Body.Bytes()) > 2048 || json.Unmarshal(w.Body.Bytes(), &got) != nil || len(got) != 5 || got["schemaVersion"] != "tracebolt.system-manager-capabilities.v1" || got["agentOrigin"] != h.enrollmentBootstrap.AgentOrigin || got["systemFrame"] != "tracebolt.agent-system-inventory.v4" || got["socketOwnerSource"] != "tracebolt.socket-owner-source.v1" || got["socketOwnerScope"] != "systemd-pid1-local-tcp-udp-socket-owners" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Access-Control-Allow-Origin") != "" {
					t.Fatal("unexpected static capability body")
				}
				if w.Header().Get("Set-Cookie") != "" {
					t.Fatal("public route created credentials")
				}
			})
		}
	}
}
func TestSocketOwnerCapabilitiesUnavailableOnDeveloperSurface(t *testing.T) {
	w := request(setup(t), http.MethodGet, socketOwnerCapabilitiesPath, "", nil)
	if w.Code != 404 {
		t.Fatal("development exposed public capability route")
	}
}

func TestSocketOwnerCapabilitiesSharesPublicMetadataBudget(t *testing.T) {
	h := &operatorHandler{authority: "127.0.0.1:8787", origin: "http://127.0.0.1:8787", insecureHTTPTest: true, enrollment: &enrollmentservice.Service{}, enrollmentBootstrap: downloadFixtureBootstrap()}
	for i := 0; i < 31; i++ {
		path := socketOwnerCapabilitiesPath
		if i%2 == 1 {
			path = journalCapabilitiesPath
		}
		r := httptest.NewRequest(http.MethodGet, h.origin+path, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if i < 30 && w.Code != 200 || i == 30 && w.Code != 429 {
			t.Fatalf("shared public budget request %d returned %d", i, w.Code)
		}
	}
}
