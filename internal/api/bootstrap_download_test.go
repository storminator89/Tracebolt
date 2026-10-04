package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const downloadFixtureID = "invite_00000000000000000000000000000001"

func downloadFixtureBootstrap() EnrollmentBootstrap {
	return EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: "manager_00000000000000000000000000000001", Profile: "http-test", EnrollmentOrigin: "http://127.0.0.1:8787", AgentOrigin: "http://127.0.0.1:8788", CollectionProfile: "basic-readonly-v1", IssuerRootPEM: "public root fixture", IssuerPEM: "public issuer fixture"}
}
func TestPublicBootstrapByteContractStableNoLookup(t *testing.T) {
	b := downloadFixtureBootstrap()
	raw, sum, err := publicBootstrapBytes(b, downloadFixtureID)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	if sum != hex.EncodeToString(h[:]) || strings.HasSuffix(string(raw), "\n") {
		t.Fatal("non-exact checksum contract")
	}
	var parsed EnrollmentBootstrap
	if json.Unmarshal(raw, &parsed) != nil || parsed.InvitationID != downloadFixtureID || b.InvitationID != "" {
		t.Fatal("ID mutation")
	}
	a := &bootstrapAdmission{}
	for _, id := range []string{downloadFixtureID, "invite_00000000000000000000000000000002", downloadFixtureID} {
		r := httptest.NewRequest("GET", publicBootstrapPrefix+id, nil)
		r.RemoteAddr = "127.0.0.1:45678"
		w := httptest.NewRecorder()
		servePublicBootstrap(w, r, b, a)
		expected, _, _ := publicBootstrapBytes(b, id)
		if w.Code != 200 || w.Body.String() != string(expected) || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
			t.Fatal("public byte response changed")
		}
		for _, forbidden := range []string{"invitationSecret", "snapshot", "serverNow", "revision", "state", "keyFingerprint"} {
			if strings.Contains(w.Body.String(), forbidden) {
				t.Fatal("non-public field exposed")
			}
		}
	}
}
func TestPublicBootstrapRejectsCredentialsMethodsAndFraming(t *testing.T) {
	for _, kind := range []string{"post", "head", "id", "path", "query", "force-query", "body", "chunked", "cookie", "origin", "authorization", "csrf", "forwarded", "range", "encoding", "content-type"} {
		t.Run(kind, func(t *testing.T) {
			r := httptest.NewRequest("GET", publicBootstrapPrefix+downloadFixtureID, nil)
			r.RemoteAddr = "127.0.0.1:45678"
			switch kind {
			case "post":
				r.Method = "POST"
			case "head":
				r.Method = "HEAD"
			case "id":
				r.URL.Path = publicBootstrapPrefix + "secret"
			case "path":
				r.URL.Path += "/"
			case "query":
				r.URL.RawQuery = "x=1"
			case "force-query":
				r.URL.ForceQuery = true
			case "body":
				r.ContentLength = 1
			case "chunked":
				r.TransferEncoding = []string{"chunked"}
			case "cookie":
				r.Header.Set("Cookie", "fixture")
			case "origin":
				r.Header.Set("Origin", "http://127.0.0.1:8787")
			case "authorization":
				r.Header.Set("Authorization", "fixture")
			case "csrf":
				r.Header.Set("X-CSRF-Token", "fixture")
			case "forwarded":
				r.Header.Set("Forwarded", "fixture")
			case "range":
				r.Header.Set("Range", "bytes=0-1")
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
			case "content-type":
				r.Header.Set("Content-Type", "application/json")
			}
			a := &bootstrapAdmission{}
			w := httptest.NewRecorder()
			servePublicBootstrap(w, r, downloadFixtureBootstrap(), a)
			if w.Code < 400 || a.global.count != 0 {
				t.Fatal("invalid public request admitted")
			}
		})
	}
}
func TestBootstrapAdmissionBoundedAndFailClosedClock(t *testing.T) {
	now := time.Now()
	a := &bootstrapAdmission{}
	for i := 0; i < 30; i++ {
		if !a.allow("127.0.0.1:1000", now) {
			t.Fatal("expected admission")
		}
	}
	if a.allow("127.0.0.1:2000", now) || a.allow("127.0.0.2:1000", now.Add(-time.Second)) {
		t.Fatal("peer or reverse clock bypass")
	}
	for i := 0; i < 90; i++ {
		if !a.allow(fmt.Sprintf("127.0.1.%d:1000", i+1), now) {
			t.Fatal("global budget early")
		}
	}
	if a.allow("127.0.2.1:1000", now) || len(a.peers) > 256 {
		t.Fatal("global budget unbounded")
	}
	if !a.allow("127.0.0.1:1000", now.Add(time.Minute)) || len(a.peers) != 1 {
		t.Fatal("bounded windows not expired")
	}
	for _, peer := range []string{"host:80", "127.0.0.1", "[fe80::1%eth0]:80"} {
		if a.allow(peer, now.Add(time.Minute)) {
			t.Fatal("invalid peer accepted")
		}
	}
}
func TestPublicBootstrapAdmissionSaturationReturns429(t *testing.T) {
	a := &bootstrapAdmission{}
	for i := 0; i < 31; i++ {
		r := httptest.NewRequest(http.MethodGet, publicBootstrapPrefix+downloadFixtureID, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		servePublicBootstrap(w, r, downloadFixtureBootstrap(), a)
		if i < 30 && w.Code != 200 || i == 30 && (w.Code != 429 || w.Header().Get("Retry-After") != "60") {
			t.Fatal("unbounded download budget")
		}
	}
}

func TestPublicBootstrapRejectsNoncanonicalCredentialHeaderMapKeys(t *testing.T) {
	for _, name := range []string{"cookie", "aUtHoRiZaTiOn", "x-forwarded-for", "X-FoRwArDeD-Proto", "X-Real-IP", "oRiGiN", "forwarded", "X-CSRF-TOKEN", "iF-mAtCh", "if-unmodified-since", "IF-RANGE"} {
		r := httptest.NewRequest("GET", publicBootstrapPrefix+downloadFixtureID, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header = map[string][]string{name: {"fixture"}}
		a := &bootstrapAdmission{}
		w := httptest.NewRecorder()
		servePublicBootstrap(w, r, downloadFixtureBootstrap(), a)
		if w.Code != 400 || a.global.count != 0 {
			t.Fatal("raw credential header admitted", name)
		}
	}
}

func TestPublicBootstrapRejectsBodyWithMisstatedZeroLength(t *testing.T) {
	r := httptest.NewRequest("GET", publicBootstrapPrefix+downloadFixtureID, nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Body = io.NopCloser(strings.NewReader("unexpected"))
	r.ContentLength = 0
	a := &bootstrapAdmission{}
	w := httptest.NewRecorder()
	servePublicBootstrap(w, r, downloadFixtureBootstrap(), a)
	if w.Code != 400 || a.global.count != 0 {
		t.Fatal("nonempty body with zero length admitted")
	}
}
