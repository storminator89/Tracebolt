package api

import (
	"crypto/tls"
	"io"
	"localrmm/internal/enrollmentservice"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicBootstrapActualListenerRoutingBothProfiles(t *testing.T) {
	for _, tlsMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "http-test", true: "tls"}[tlsMode], func(t *testing.T) {
			// The production operator handler is exercised through a real ephemeral
			// listener. The no-lookup route never dereferences this inert service handle.
			h := &operatorHandler{insecureHTTPTest: !tlsMode, enrollment: &enrollmentservice.Service{}, enrollmentBootstrap: downloadFixtureBootstrap()}
			server := httptest.NewUnstartedServer(h)
			scheme := "http"
			if tlsMode {
				scheme = "https"
				h.enrollmentBootstrap.Profile = "tls"
			}
			h.authority = server.Listener.Addr().String()
			h.origin = scheme + "://" + h.authority
			h.enrollmentBootstrap.EnrollmentOrigin = h.origin
			if tlsMode {
				server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			client := server.Client()
			for _, kind := range []string{"exact", "wrong-host", "cookie", "authorization", "forwarded", "query", "escaped", "post", "head"} {
				t.Run(kind, func(t *testing.T) {
					r, _ := http.NewRequest(http.MethodGet, server.URL+publicBootstrapPrefix+downloadFixtureID, nil)
					switch kind {
					case "wrong-host":
						r.Host = "wrong.example"
					case "cookie":
						r.Header.Set("Cookie", "fixture")
					case "authorization":
						r.Header.Set("Authorization", "fixture")
					case "forwarded":
						r.Header.Set("X-Forwarded-For", "127.0.0.1")
					case "query":
						r.URL.RawQuery = "x=1"
					case "escaped":
						r.URL.RawPath = strings.Replace(r.URL.Path, "invite", "%69nvite", 1)
					case "post":
						r.Method = "POST"
					case "head":
						r.Method = "HEAD"
					}
					response, e := client.Do(r)
					if e != nil {
						t.Fatal(e)
					}
					raw, e := io.ReadAll(response.Body)
					response.Body.Close()
					if e != nil {
						t.Fatal(e)
					}
					if kind == "exact" {
						want, _, _ := publicBootstrapBytes(h.enrollmentBootstrap, downloadFixtureID)
						if response.StatusCode != 200 || string(raw) != string(want) || response.Header.Get("Access-Control-Allow-Origin") != "" || response.Header.Get("Cache-Control") != "no-store" {
							t.Fatal("public download routing/bytes mismatch")
						}
					} else if response.StatusCode < 400 {
						t.Fatal("invalid route request accepted", kind)
					}
				})
			}
		})
	}
}
func TestPublicBootstrapDisabledAndWrongActualTransportFailClosed(t *testing.T) {
	for _, kind := range []string{"disabled", "missing-tls", "unexpected-tls", "incomplete-handshake", "obsolete-tls"} {
		t.Run(kind, func(t *testing.T) {
			h := &operatorHandler{authority: "127.0.0.1:8787", origin: "http://127.0.0.1:8787", insecureHTTPTest: true, enrollment: &enrollmentservice.Service{}, enrollmentBootstrap: downloadFixtureBootstrap()}
			r := httptest.NewRequest("GET", h.origin+publicBootstrapPrefix+downloadFixtureID, nil)
			r.RemoteAddr = "127.0.0.1:1234"
			switch kind {
			case "disabled":
				h.enrollment = nil
			case "missing-tls":
				h.insecureHTTPTest = false
			case "unexpected-tls":
				r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
			case "incomplete-handshake":
				h.insecureHTTPTest = false
				r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
			case "obsolete-tls":
				h.insecureHTTPTest = false
				r.TLS = &tls.ConnectionState{Version: tls.VersionTLS12, HandshakeComplete: true}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || h.bootstrapAdmission.global.count != 0 {
				t.Fatal("disabled/wrong transport reached public route")
			}
		})
	}
}

func TestPublicBootstrapUnavailableOnDevelopmentSurface(t *testing.T) {
	app := setup(t)
	w := request(app, "GET", publicBootstrapPrefix+downloadFixtureID, "", nil)
	if w.Code != 404 || strings.Contains(w.Body.String(), "serverCaPem") {
		t.Fatal("development surface exposed bootstrap")
	}
}
