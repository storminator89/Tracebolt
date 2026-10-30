package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWindowsSelfBootstrapRequiresTLSAndNoBrowserCredentials(t *testing.T) {
	f := newWindowsEventOperatorFixture(t)
	h := f.server.Config.Handler.(*operatorHandler)
	for _, tc := range []struct {
		name    string
		version uint16
		cookie  bool
		status  int
	}{
		{"tls13", tls.VersionTLS13, false, 200},
		{"tls12", tls.VersionTLS12, false, 404},
		{"cookie", tls.VersionTLS13, true, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"invitationId":"invite_` + strings.Repeat("a", 32) + `"}`
			r := httptest.NewRequest("POST", "/v2/windows/enrollment/self-bootstrap", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "127.0.0.1:12345"
			r.TLS = &tls.ConnectionState{Version: tc.version, HandshakeComplete: true}
			if tc.cookie {
				r.Header.Set("Cookie", "session=fixture")
			}
			w := httptest.NewRecorder()
			h.windowsEnrollmentClient(w, r)
			if w.Code != tc.status {
				t.Fatalf("got %d: %s", w.Code, w.Body.String())
			}
			if tc.status == 200 {
				var bootstrap EnrollmentBootstrap
				if json.Unmarshal(w.Body.Bytes(), &bootstrap) != nil || bootstrap.InvitationID != "invite_"+strings.Repeat("a", 32) || bootstrap.Profile != "tls" || bootstrap.CollectionProfile != "windows-inventory-v1" {
					t.Fatal("bootstrap binding mismatch")
				}
				if bytes.Contains(w.Body.Bytes(), []byte("invitationSecret")) {
					t.Fatal("bootstrap exposes secret")
				}
			}
		})
	}
}

func TestWindowsSelfBootstrapRealTLSHasNoSessionRequirement(t *testing.T) {
	f := newWindowsEventOperatorFixture(t)
	client := *f.client
	client.Jar = nil
	r, err := http.NewRequest("POST", f.server.URL+"/v2/windows/enrollment/self-bootstrap", strings.NewReader(`{"invitationId":"invite_`+strings.Repeat("b", 32)+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 {
		t.Fatalf("public server-authenticated TLS bootstrap failed: %d %s", response.StatusCode, raw)
	}
}

func TestAutomaticBootstrapRequiresScopeAndCreatesNoInvitation(t *testing.T) {
	f := newWindowsEventOperatorFixture(t)
	before, err := f.service.Snapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, platform string
		acknowledge    bool
		status         int
	}{
		{"/api/windows/enrollment/automatic-bootstrap", "windows", false, 400},
		{"/api/windows/enrollment/automatic-bootstrap", "windows", true, 200},
		{"/api/enrollment/automatic-bootstrap", "linux", false, 200},
	} {
		body := map[string]any{"requestId": "request_" + strings.Repeat("c", 32), "platform": tc.platform}
		if tc.platform == "windows" {
			body["collectionAcknowledged"] = tc.acknowledge
			body["insecureHTTPAcknowledged"] = false
		}
		response, result := f.call(t, "POST", tc.path, body, f.csrf, nil)
		if response.StatusCode != tc.status {
			t.Fatalf("%s: %d %+v", tc.path, response.StatusCode, result)
		}
		if tc.status == 200 {
			if result["schemaVersion"] != "tracebolt.enrollment-bootstrap.auto.v1" || result["invitationSecret"] != nil {
				t.Fatal("invalid public automatic bootstrap")
			}
		}
	}
	after, err := f.service.Snapshots(context.Background())
	if err != nil || len(before) != len(after) {
		t.Fatal("bootstrap created durable invitation", err)
	}
}

// The wrapper must reach its configured child, without taking a platform from
// client JSON. Cryptographic Darwin profile admission is tested in the service.
func TestMacOSAutomaticRoutesDelegateConfiguredDomain(t *testing.T) {
	f := newWindowsEventOperatorFixture(t)
	h := f.server.Config.Handler.(*operatorHandler)
	h.macosEnrollment = h
	h.macosInventoryEnrollment = h
	for _, path := range []string{"/v2/macos/enrollment/self-bootstrap", "/v2/macos-inventory/enrollment/self-bootstrap"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"invitationId":"invite_`+strings.Repeat("d", 32)+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "127.0.0.1:12345"
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
		w := httptest.NewRecorder()
		if strings.Contains(path, "macos-inventory") {
			h.macosInventoryEnrollmentClient(w, r)
		} else {
			h.macosEnrollmentClient(w, r)
		}
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
}
