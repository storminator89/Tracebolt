package main

import (
	"crypto/tls"
	"encoding/json"
	"localrmm/internal/rustcompat"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestCompatibilityGETDoesNotEnterEnrollment(t *testing.T) {
	// A nil engine/signer and empty directory prove metadata cannot create an
	// invitation, challenge, certificate, pending record, or fixture output.
	p := &peer{directory: t.TempDir(), origin: "https://127.0.0.1:8787", agentOrigin: "https://127.0.0.1:8788"}
	for _, kind := range []string{"exact", "post", "cookie", "query", "http", "wrong-host"} {
		r := httptest.NewRequest(http.MethodGet, p.origin+rustcompat.Path, nil)
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
		switch kind {
		case "post":
			r.Method = http.MethodPost
		case "cookie":
			r.Header.Set("Cookie", "fixture")
		case "query":
			r.URL.RawQuery = "x=1"
		case "http":
			r.TLS = nil
		case "wrong-host":
			r.Host = "wrong.example"
		}
		w := httptest.NewRecorder()
		p.enroll(w, r)
		if kind == "exact" {
			want, _ := json.Marshal(rustcompat.Expected(p.origin, p.agentOrigin, true))
			if w.Code != 200 || w.Body.String() != string(want) {
				t.Fatal("wrong fixture contract", w.Code)
			}
		} else if w.Code < 400 {
			t.Fatal("invalid fixture request accepted", kind)
		}
	}
	entries, err := os.ReadDir(p.directory)
	if err != nil || len(entries) != 0 || len(p.challenges) != 0 || p.invitation != "" || p.reports != 0 {
		t.Fatal("metadata mutated fixture")
	}
}
