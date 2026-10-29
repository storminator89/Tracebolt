package api

import (
	"bytes"
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
