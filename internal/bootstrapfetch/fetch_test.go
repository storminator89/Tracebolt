package bootstrapfetch

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"localrmm/internal/enrollmentclient"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const fixtureInvite = "invite_00000000000000000000000000000001"

func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func certPEM(raw []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
}

type fetchFixture struct {
	request   Request
	raw       []byte
	bootstrap enrollmentclient.Bootstrap
	calls     atomic.Int32
	serve     func(http.ResponseWriter, *http.Request)
}

func newFetchFixture(t *testing.T, tlsMode bool) *fetchFixture {
	t.Helper()
	now := time.Now()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ephemeral bootstrap test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("bootstrap-root")}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	root, e = x509.ParseCertificate(rootDER)
	if e != nil {
		t.Fatal(e)
	}
	issuerPub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Ephemeral bootstrap test issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("bootstrap-issuer")}
	issuerDER, e := x509.CreateCertificate(rand.Reader, issuer, root, issuerPub, key)
	if e != nil {
		t.Fatal(e)
	}
	f := &fetchFixture{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/v2/enrollment/bootstrap/"+fixtureInvite || r.ContentLength != 0 || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Encoding") != "" {
			t.Error("unexpected request")
		}
		if f.serve != nil {
			f.serve(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(f.raw)
	}))
	profile, origin, ca := "http-test", "http://"+server.Listener.Addr().String(), ""
	if tlsMode {
		profile, origin, ca = "tls", "https://"+server.Listener.Addr().String(), certPEM(rootDER)
		serverPub, serverKey, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		leafDER, e := x509.CreateCertificate(rand.Reader, leaf, root, serverPub, key)
		if e != nil {
			t.Fatal(e)
		}
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: serverKey}}}
	}
	f.bootstrap = enrollmentclient.Bootstrap{SchemaVersion: enrollmentclient.BootstrapVersion, ManagerInstanceID: "manager_00000000000000000000000000000001", Profile: profile, EnrollmentOrigin: origin, AgentOrigin: origin, CollectionProfile: "basic-readonly-v1", InvitationID: fixtureInvite, ServerCAPEM: ca, IssuerRootPEM: certPEM(rootDER), IssuerPEM: certPEM(issuerDER)}
	f.raw, e = json.Marshal(f.bootstrap)
	if e != nil {
		t.Fatal(e)
	}
	f.request = Request{ManagerOrigin: origin, InvitationID: fixtureInvite, ExpectedSHA256: digest(f.raw), InsecureHTTPTest: !tlsMode}
	if tlsMode {
		f.request.ServerCABase64 = base64.StdEncoding.EncodeToString([]byte(ca))
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return f
}
func TestFetchVerifiedPublicBootstrapBothProfiles(t *testing.T) {
	for _, tlsMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "http-test", true: "tls"}[tlsMode], func(t *testing.T) {
			f := newFetchFixture(t, tlsMode)
			raw, e := Fetch(context.Background(), f.request)
			if e != nil || string(raw) != string(f.raw) || f.calls.Load() != 1 {
				t.Fatal("verified fetch failed", e)
			}
		})
	}
}
func TestFetchRejectsUnexpectedBytesFramingAndBinding(t *testing.T) {
	for _, kind := range []string{"hash", "oversize", "chunked-oversize", "type", "encoding", "redirect", "status", "unknown-field", "duplicate-field", "wrong-origin", "wrong-invite", "wrong-ca", "wrong-profile"} {
		t.Run(kind, func(t *testing.T) {
			f := newFetchFixture(t, false)
			switch kind {
			case "hash":
				f.request.ExpectedSHA256 = strings.Repeat("a", 64)
			case "oversize", "chunked-oversize":
				f.serve = func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if kind == "chunked-oversize" {
						w.(http.Flusher).Flush()
					}
					io.WriteString(w, strings.Repeat("x", MaxBootstrapBytes+1))
				}
			case "type":
				f.serve = func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					w.Write(f.raw)
				}
			case "encoding":
				f.serve = func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Content-Encoding", "gzip")
					w.Write(f.raw)
				}
			case "redirect":
				f.serve = func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, "/v2/enrollment/bootstrap/"+fixtureInvite, 307)
				}
			case "status":
				f.serve = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }
			default:
				b := f.bootstrap
				switch kind {
				case "wrong-origin":
					b.EnrollmentOrigin = "http://127.0.0.1:9999"
				case "wrong-invite":
					b.InvitationID = "invite_00000000000000000000000000000002"
				case "wrong-ca":
					b.ServerCAPEM = b.IssuerRootPEM
				case "wrong-profile":
					b.Profile = "tls"
				}
				f.raw, _ = json.Marshal(b)
				if kind == "unknown-field" {
					f.raw = []byte(strings.TrimSuffix(string(f.raw), "}") + `,"extra":true}`)
				}
				if kind == "duplicate-field" {
					f.raw = []byte(strings.TrimSuffix(string(f.raw), "}") + `,"profile":"http-test"}`)
				}
				f.request.ExpectedSHA256 = digest(f.raw)
			}
			if raw, e := Fetch(context.Background(), f.request); e == nil || raw != nil {
				t.Fatal("unverified bytes accepted")
			}
			if f.calls.Load() != 1 {
				t.Fatal("retry/redirect or missing bounded request")
			}
		})
	}
}
func TestFetchRejectsInvalidInputsBeforeNetwork(t *testing.T) {
	f := newFetchFixture(t, false)
	for _, kind := range []string{"ack", "ca", "id", "hash", "zero", "query", "fragment", "path", "credentials", "metadata", "public-http"} {
		t.Run(kind, func(t *testing.T) {
			r := f.request
			switch kind {
			case "ack":
				r.InsecureHTTPTest = false
			case "ca":
				r.ServerCABase64 = "Zg=="
			case "id":
				r.InvitationID = "one-time-secret"
			case "hash":
				r.ExpectedSHA256 = strings.Repeat("A", 64)
			case "zero":
				r.ExpectedSHA256 = strings.Repeat("0", 64)
			case "query":
				r.ManagerOrigin += "?x=1"
			case "fragment":
				r.ManagerOrigin += "#x"
			case "path":
				r.ManagerOrigin += "/"
			case "credentials":
				r.ManagerOrigin = "http://user@127.0.0.1"
			case "metadata":
				r.ManagerOrigin = "http://169.254.169.254"
			case "public-http":
				r.ManagerOrigin = "http://8.8.8.8"
			}
			if _, e := Fetch(context.Background(), r); e == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	if f.calls.Load() != 0 {
		t.Fatal("invalid request opened connection")
	}
}
func TestFetchTLSRejectsWrongTrustHostnameAndNoncanonicalCA(t *testing.T) {
	f := newFetchFixture(t, true)
	other := newFetchFixture(t, true)
	for _, kind := range []string{"missing", "untrusted", "hostname", "base64-newline", "base64-junk", "private-key"} {
		t.Run(kind, func(t *testing.T) {
			r := f.request
			switch kind {
			case "missing":
				r.ServerCABase64 = ""
			case "untrusted":
				r.ServerCABase64 = other.request.ServerCABase64
			case "hostname":
				r.ManagerOrigin = strings.Replace(r.ManagerOrigin, "127.0.0.1", "localhost", 1)
			case "base64-newline":
				r.ServerCABase64 += "\n"
			case "base64-junk":
				r.ServerCABase64 = "!"
			case "private-key":
				r.ServerCABase64 = base64.StdEncoding.EncodeToString([]byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"))
			}
			if _, e := Fetch(context.Background(), r); e == nil {
				t.Fatal("TLS trust bypass")
			}
		})
	}
	if f.calls.Load() != 0 || other.calls.Load() != 0 {
		t.Fatal("untrusted request delivered")
	}
}
func TestFetchDoesNotUseEnvironmentProxy(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxied.Add(1); w.WriteHeader(500) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	f := newFetchFixture(t, false)
	if _, e := Fetch(context.Background(), f.request); e != nil || proxied.Load() != 0 {
		t.Fatal("environment proxy affected fetch", e)
	}
}
