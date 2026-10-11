package windowsusersoftwarewire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"localrmm/internal/journalwire"
	"localrmm/internal/lantrust"
)

type publicFixture struct {
	calls  int
	failAt int
}

func (a *publicFixture) AuthorizePublicCertificate([]byte) (lantrust.Agent, error) {
	a.calls++
	if a.failAt > 0 && a.calls >= a.failAt {
		return lantrust.Agent{}, lantrust.ErrRegistryUnavailable
	}
	return lantrust.Agent{}, nil
}
func wirePair(t *testing.T) tls.Certificate {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral synthetic wire fixture"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, c, c, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func TestIndependentSignaturePurposeActionBodyIdentityAndFraming(t *testing.T) {
	pair := wirePair(t)
	auth := &publicFixture{}
	v, e := New(Config{Origin: "http://manager.test", Registry: auth})
	if e != nil {
		t.Fatal(e)
	}
	request := func() *http.Request {
		r, e := NewSignedRequest(context.Background(), "http://manager.test", pair, "scope", 1, time.Now().UTC(), []byte("{}"))
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	got, e := v.Verify(request())
	if e != nil || !bytes.Equal(got.Body, []byte("{}")) || got.Sequence != 1 || auth.calls != 2 {
		t.Fatal("valid proof not verified twice")
	}
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
	}{
		{"cross action", func(r *http.Request) { r.URL.Path = (PathPrefix + "chunk") }},
		{"body changed", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("[]")) }},
		{"sequence changed", func(r *http.Request) { r.Header.Set(SequenceHeader, "2") }},
		{"noncanonical sequence", func(r *http.Request) { r.Header.Set(SequenceHeader, "01") }},
		{"sequence overflow", func(r *http.Request) { r.Header.Set(SequenceHeader, "18446744073709551616") }},
		{"other authority", func(r *http.Request) { r.Host = "other.test" }},
		{"TLS fallback", func(r *http.Request) { r.TLS = &tls.ConnectionState{} }},
		{"duplicate certificate", func(r *http.Request) { r.Header.Add(CertificateHeader, r.Header.Get(CertificateHeader)) }},
		{"case-folded duplicate", func(r *http.Request) {
			r.Header[strings.ToLower(CertificateHeader)] = []string{r.Header.Get(CertificateHeader)}
		}},
		{"query", func(r *http.Request) { r.URL.RawQuery = "q=1" }},
		{"forced query", func(r *http.Request) { r.URL.ForceQuery = true }},
		{"fragment", func(r *http.Request) { r.URL.Fragment = "x" }},
		{"raw path", func(r *http.Request) { r.URL.RawPath = r.URL.Path }},
		{"wrong URI", func(r *http.Request) { r.RequestURI = (PathPrefix + "chunk") }},
		{"chunked", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }},
		{"trailers", func(r *http.Request) { r.Trailer = http.Header{"Content-Type": []string{"application/json"}} }},
		{"compressed", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"short framing", func(r *http.Request) { r.ContentLength = 1 }},
		{"oversized metadata", func(r *http.Request) { r.ContentLength = MaxBodyBytes + 1 }},
		{"cookie", func(r *http.Request) { r.Header.Set("Cookie", "synthetic=1") }},
		{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "synthetic") }},
		{"browser origin", func(r *http.Request) { r.Header.Set("Origin", "http://manager.test") }},
		{"forwarded", func(r *http.Request) { r.Header.Set("Forwarded", "for=192.0.2.1") }},
		{"fetch metadata", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") }},
		{"wrong content type", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }},
		{"duplicate content type", func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }},
		{"missing proof", func(r *http.Request) { r.Header.Del(SignatureHeader) }},
		{"padded signature", func(r *http.Request) { r.Header.Set(SignatureHeader, r.Header.Get(SignatureHeader)+"=") }},
		{"invalid signature", func(r *http.Request) {
			r.Header.Set(SignatureHeader, base64.RawStdEncoding.EncodeToString(make([]byte, 64)))
		}},
		{"unexpected transfer header", func(r *http.Request) { r.Header.Set("Transfer-Encoding", "identity") }},
		{"expect", func(r *http.Request) { r.Header.Set("Expect", "100-continue") }},
		{"oversized headers", func(r *http.Request) { r.Header.Set("User-Agent", strings.Repeat("x", MaxHeaderBytes)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request()
			tc.change(r)
			if _, e := v.Verify(r); e == nil {
				t.Fatal("altered proof/framing accepted")
			}
		})
	}
	// Translating all Linux proof headers and the route cannot turn its purpose
	// into selected-account Windows software authority.
	other, e := journalwire.NewSignedRequest(context.Background(), "http://manager.test", journalwire.PeekPath, pair, 1, time.Now().UTC(), []byte("{}"))
	if e != nil {
		t.Fatal(e)
	}
	for _, keys := range [][2]string{{journalwire.CertificateHeader, CertificateHeader}, {journalwire.SequenceHeader, SequenceHeader}, {journalwire.SignedAtHeader, SignedAtHeader}, {journalwire.SignatureHeader, SignatureHeader}} {
		other.Header.Set(keys[1], other.Header.Get(keys[0]))
		other.Header.Del(keys[0])
	}
	other.URL.Path = (PathPrefix + "scope")
	if _, e := v.Verify(other); e == nil {
		t.Fatal("Linux proof promoted to Windows authority")
	}
}
func TestIndependentSignatureOriginalTimeExpiryAndStatelessReplayBoundary(t *testing.T) {
	pair := wirePair(t)
	at := time.Now().UTC()
	now := at
	verifier, e := New(Config{Origin: "http://manager.test", Registry: &publicFixture{}, Now: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	request := func() *http.Request {
		r, e := NewSignedRequest(context.Background(), "http://manager.test", pair, "scope", 1, at, []byte("{}"))
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	// Proof only: these identical proofs must both verify before the separate
	// durable action/capability transaction enforces consume-once/retry semantics.
	if _, e := verifier.Verify(request()); e != nil {
		t.Fatal(e)
	}
	if _, e := verifier.Verify(request()); e != nil {
		t.Fatal(e)
	}
	now = at.Add(MaxAge + time.Nanosecond)
	if _, e := verifier.Verify(request()); e == nil {
		t.Fatal("old proof replay accepted")
	}
	now = at.Add(-ClockSkew - time.Nanosecond)
	if _, e := verifier.Verify(request()); e == nil {
		t.Fatal("future proof accepted")
	}
	now = at
	r := request()
	r.Header.Set(SignedAtHeader, at.Add(time.Second).Format(time.RFC3339Nano))
	if _, e := verifier.Verify(r); e == nil {
		t.Fatal("proof freshness refreshed without resigning")
	}
	// Canonical SignedAt is mandatory even if it denotes the same instant.
	r = request()
	r.Header.Set(SignedAtHeader, at.Format("2006-01-02T15:04:05.999999999-07:00"))
	if _, e := verifier.Verify(r); e == nil {
		t.Fatal("noncanonical time accepted")
	}
}

type changeOnRead struct {
	read   io.Reader
	change func()
}

func (r *changeOnRead) Read(p []byte) (int, error) { r.change(); return r.read.Read(p) }
func (r *changeOnRead) Close() error               { return nil }
func TestIndependentSlowBodyRechecksTimeAndAuthorization(t *testing.T) {
	pair := wirePair(t)
	at := time.Now().UTC()
	now := at
	req := func() *http.Request {
		r, e := NewSignedRequest(context.Background(), "http://manager.test", pair, "scope", 1, at, []byte("{}"))
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	verifier, e := New(Config{Origin: "http://manager.test", Registry: &publicFixture{}, Now: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	r := req()
	r.Body = &changeOnRead{strings.NewReader("{}"), func() { now = at.Add(MaxAge + time.Second) }}
	if _, e := verifier.Verify(r); e == nil {
		t.Fatal("body crossed proof expiry")
	}
	auth := &publicFixture{failAt: 2}
	verifier, e = New(Config{Origin: "http://manager.test", Registry: auth})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := verifier.Verify(req()); !errors.Is(e, ErrUnavailable) || auth.calls != 2 {
		t.Fatal("revocation/trust change not rechecked")
	}
}
func TestIndependentOriginAndTLSShapeFailClosed(t *testing.T) {
	for _, origin := range []string{"", "https://manager.test", "http://manager.test/", "http://Manager.test", "http://manager.test:80", "http://manager.test:080", "http://manager.test?", "http://user@manager.test", "http://manager.test#x", "http://-manager.test", "http://manager..test", "http://manager.test:0", "http://[fe80::1%25eth0]", "http://[0:0:0:0:0:0:0:1]"} {
		if _, e := New(Config{Origin: origin, Registry: &publicFixture{}}); e == nil {
			t.Fatal("noncanonical origin accepted")
		}
	}
	var nilAuth *publicFixture
	if _, e := New(Config{Origin: "http://manager.test", Registry: nilAuth}); e == nil {
		t.Fatal("typed nil authorizer")
	}
	for _, origin := range []string{"http://manager.test", "http://manager.test:8080", "http://127.0.0.1", "http://[::1]:8080"} {
		if _, e := New(Config{Origin: origin, Registry: &publicFixture{}}); e != nil {
			t.Fatal("canonical origin rejected")
		}
	}
	r, e := http.NewRequest(http.MethodPost, "https://manager.test"+(PathPrefix+"scope"), strings.NewReader("{}"))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	r.TLS = &tls.ConnectionState{}
	if ValidateShape(r, "manager.test", "tls") != nil {
		t.Fatal("TLS shape rejected")
	}
	r.Header.Set(SignatureHeader, "not-an-mtls-fallback")
	if ValidateShape(r, "manager.test", "tls") == nil {
		t.Fatal("TLS accepted HTTP test proof header")
	}
	if ValidateShape(r, "manager.test", "unknown") == nil {
		t.Fatal("unknown profile accepted")
	}
	if !ValidPath(PathPrefix+"scope") || !ValidPath(PathPrefix+"chunk") || !ValidPath(PathPrefix+"failure") {
		t.Fatal("route budget mismatch")
	}
}
