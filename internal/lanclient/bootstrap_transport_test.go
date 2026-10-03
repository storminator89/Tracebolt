//go:build linux

package lanclient

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

func TestBootstrapTransportUsesExplicitServerTrustWithoutClientIdentity(t *testing.T) {
	fixture := integrationFixture(t, "tls", nil)
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.PeerCertificates) != 0 {
			t.Error("bootstrap transport identity mismatch")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	}))
	server.TLS = &tls.Config{Certificates: fixture.server.TLS.Certificates, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	ca, e := os.ReadFile(fixture.material.config.ServerCAFile)
	if e != nil {
		t.Fatal("public fixture CA")
	}
	client, e := NewBootstrapHTTPClient(server.URL, "tls", ca)
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	request, _ := http.NewRequest("POST", server.URL+"/v2/enrollment/challenge", bytes.NewReader([]byte(`{}`)))
	request.Header.Set("Content-Type", "application/json")
	response, e := client.Do(request)
	if e != nil {
		t.Fatal("explicit trust handshake failed")
	}
	response.Body.Close()
	if response.StatusCode != 200 || calls.Load() != 1 {
		t.Fatal("request not delivered")
	}
	if _, e = NewBootstrapHTTPClient(server.URL, "tls", nil); e == nil {
		t.Fatal("ambient root fallback")
	}
}
func TestBootstrapTransportPinsOriginPathAndRejectsRedirect(t *testing.T) {
	var calls, elsewhere atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, target.URL+"/v2/enrollment/claim", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client, e := NewBootstrapHTTPClient(source.URL, "http-test", nil)
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	request, _ := http.NewRequest("POST", source.URL+"/v2/enrollment/challenge", bytes.NewReader([]byte(`{}`)))
	response, e := client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 307 || calls.Load() != 1 || elsewhere.Load() != 0 {
		t.Fatal("redirect followed")
	}
	for _, destination := range []string{target.URL + "/v2/enrollment/claim", source.URL + "/api/auth/login", source.URL + "/v2/enrollment/status?", source.URL + "/v2/enrollment/status?secret=x", source.URL + "/v2/enrollment/%73tatus"} {
		request, _ := http.NewRequest("POST", destination, bytes.NewReader([]byte(`{}`)))
		if response, e := client.Do(request); e == nil {
			response.Body.Close()
			t.Fatal("invalid destination/path delivered")
		}
	}
	request, _ = http.NewRequest("POST", source.URL+"/v2/enrollment/claim", bytes.NewReader([]byte(`{}`)))
	request.Header.Set("Cookie", "fixture-only")
	if response, e := client.Do(request); e == nil {
		response.Body.Close()
		t.Fatal("browser credential accepted")
	}
	if calls.Load() != 1 || elsewhere.Load() != 0 {
		t.Fatal("rejected request reached a listener")
	}
	if _, e := NewBootstrapHTTPClient("http://8.8.8.8", "http-test", nil); e == nil {
		t.Fatal("public HTTP test target accepted")
	}
}
