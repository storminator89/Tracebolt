package fixture

import (
	"context"
	"crypto/tls"
	"localrmm/internal/windowsacceptance/profile"
	"localrmm/internal/windowssetup"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSetupCapabilitiesRequestBoundary(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		s := profile.Selection{CollectionProfile: "windows-inventory-v1", Transport: transport}
		scheme := "https"
		if s.HTTPTest() {
			scheme = "http"
		}
		origin := scheme + "://127.0.0.1:8443"
		r := httptest.NewRequest("GET", origin+windowssetup.CapabilitiesPath, nil)
		r.RemoteAddr = "127.0.0.1:54321"
		r.RequestURI = windowssetup.CapabilitiesPath
		if !s.HTTPTest() {
			r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
		}
		if !setupCapabilitiesRequest(r, origin, s) {
			t.Fatal("public contract rejected", transport)
		}
		for _, header := range []string{"Authorization", "Cookie", "X-Forwarded-Host", "X-Tracebolt-Signature"} {
			r.Header.Set(header, "not-accepted")
			if setupCapabilitiesRequest(r, origin, s) {
				t.Fatal("secret/forwarding header accepted")
			}
			r.Header.Del(header)
		}
		r.Method = "POST"
		if setupCapabilitiesRequest(r, origin, s) {
			t.Fatal("mutation method")
		}
	}
}

func TestSetupCapabilitiesFixtureSharesAdmissionAndOutage(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		selection := profile.Selection{CollectionProfile: "windows-inventory-v1", Transport: transport}
		scheme := "https"
		if selection.HTTPTest() {
			scheme = "http"
		}
		origin := scheme + "://127.0.0.1:8443"
		f, err := newFixtureSelected(context.Background(), origin, scheme+"://127.0.0.1:8444", time.Now, selection)
		if err != nil {
			t.Fatal("fixture construction")
		}
		defer f.Close()
		f.state.expanded = true
		request := func() *http.Request {
			r := httptest.NewRequest("GET", origin+windowssetup.CapabilitiesPath, nil)
			r.RemoteAddr = "127.0.0.1:54321"
			r.RequestURI = windowssetup.CapabilitiesPath
			if !selection.HTTPTest() {
				r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
			}
			return r
		}
		response := httptest.NewRecorder()
		f.serve(response, request(), false)
		b := f.Bootstrap()
		if response.Code != 200 || windowssetup.Match(response.Body.Bytes(), windowssetup.Expected(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)) != nil {
			t.Fatal("public fixture contract")
		}
		before := f.Snapshot()
		f.ToggleUnavailable(true)
		response = httptest.NewRecorder()
		f.serve(response, request(), false)
		if response.Code != 503 || f.Evidence().UnavailableRequests != 1 || f.Snapshot() != before {
			t.Fatal("outage changed identity or bypassed counter")
		}
		f.ToggleUnavailable(false)
		f.state.expanded = false
		response = httptest.NewRecorder()
		f.serve(response, request(), false)
		if response.Code != 400 {
			t.Fatal("legacy fixture unexpectedly exposes setup")
		}
	}
}
