package packagewire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"

	"localrmm/internal/actionwire"
	"localrmm/internal/lantrust"
	"localrmm/internal/systemwire"
	"math/big"
	"net/http"

	"testing"
	"time"
)

type publicFixture struct {
	agent lantrust.Agent
	calls int
}

func (a *publicFixture) AuthorizePublicCertificate([]byte) (lantrust.Agent, error) {
	a.calls++
	return a.agent, nil
}
func wirePair(t *testing.T) tls.Certificate {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral fixture"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, c, c, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func TestPackageSignaturePurposePathAndFraming(t *testing.T) {
	pair := wirePair(t)
	a := &publicFixture{}
	v, e := New(Config{Origin: "http://manager.test", Registry: a})
	if e != nil {
		t.Fatal(e)
	}
	request := func() *http.Request {
		r, e := NewSignedRequest(context.Background(), "http://manager.test", PeekPath, pair, 1, time.Now().UTC(), []byte("{}"))
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	r := request()
	got, e := v.Verify(r)
	if e != nil || !bytes.Equal(got.Body, []byte("{}")) || a.calls != 2 {
		t.Fatal("proof not verified twice")
	}
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
	}{
		{"different action", func(r *http.Request) { r.URL.Path = ClaimPath }},
		{"wrong purpose headers", func(r *http.Request) { r.Header.Set(systemwire.CertificateHeader, r.Header.Get(CertificateHeader)) }},
		{"wrong host", func(r *http.Request) { r.Host = "other.test" }},
		{"TLS cannot fallback", func(r *http.Request) { r.TLS = &tls.ConnectionState{} }},
		{"duplicate certificate", func(r *http.Request) { r.Header.Add(CertificateHeader, r.Header.Get(CertificateHeader)) }},
		{"trailing query", func(r *http.Request) { r.URL.RawQuery = "secret=1" }},
		{"chunked", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }},
		{"compressed", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"short framing", func(r *http.Request) { r.ContentLength = 1 }},
		{"oversize metadata", func(r *http.Request) { r.ContentLength = BodyLimit(PeekPath) + 1 }},
		{"cookie", func(r *http.Request) { r.Header.Set("Cookie", "secret=redacted") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request()
			tc.change(r)
			if _, e := v.Verify(r); e == nil {
				t.Fatal("invalid wire accepted")
			}
		})
	}
	// An otherwise valid system-purpose signature remains invalid after all four
	// header names and the HTTP path are translated to action's proof fields.
	sys, e := systemwire.NewSignedRequest(context.Background(), "http://manager.test", pair, 1, time.Now().UTC(), []byte("{}"))
	if e != nil {
		t.Fatal(e)
	}
	for _, names := range [][2]string{{systemwire.CertificateHeader, CertificateHeader}, {systemwire.SequenceHeader, SequenceHeader}, {systemwire.SignedAtHeader, SignedAtHeader}, {systemwire.SignatureHeader, SignatureHeader}} {
		sys.Header.Set(names[1], sys.Header.Get(names[0]))
		sys.Header.Del(names[0])
	}
	sys.URL.Path = PeekPath
	if _, e = v.Verify(sys); e == nil {
		t.Fatal("cross-purpose proof accepted")
	}
}

func TestActionTLSShapeNeverAcceptsProofFallback(t *testing.T) {
	request := func() *http.Request {
		r, e := http.NewRequest(http.MethodPost, "https://manager.test"+PeekPath, bytes.NewReader([]byte("{}")))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		r.TLS = &tls.ConnectionState{}
		return r
	}
	r := request()
	if e := ValidateShape(r, "manager.test", "tls"); e != nil {
		t.Fatal(e)
	}
	r.Header.Set(SignatureHeader, "proof")
	if e := ValidateShape(r, "manager.test", "tls"); e == nil {
		t.Fatal("HTTP proof accepted on TLS")
	}
	r = request()
	r.TLS = nil
	if e := ValidateShape(r, "manager.test", "tls"); e == nil {
		t.Fatal("missing TLS accepted")
	}
}

func TestServiceSignatureCannotBecomePackageAuthority(t *testing.T) {
	pair := wirePair(t)
	v, e := New(Config{Origin: "http://manager.test", Registry: &publicFixture{}})
	if e != nil {
		t.Fatal(e)
	}
	req, e := actionwire.NewSignedRequest(context.Background(), "http://manager.test", actionwire.PeekPath, pair, 1, time.Now().UTC(), []byte("{}"))
	if e != nil {
		t.Fatal(e)
	}
	for _, names := range [][2]string{{actionwire.CertificateHeader, CertificateHeader}, {actionwire.SequenceHeader, SequenceHeader}, {actionwire.SignedAtHeader, SignedAtHeader}, {actionwire.SignatureHeader, SignatureHeader}} {
		req.Header.Set(names[1], req.Header.Get(names[0]))
		req.Header.Del(names[0])
	}
	req.URL.Path = PeekPath
	if _, e = v.Verify(req); e == nil {
		t.Fatal("service signature crossed native package domain")
	}
	if BodyLimit(ResultPath) != 1<<20 || actionwire.BodyLimit(actionwire.ResultPath) >= BodyLimit(ResultPath) {
		t.Fatal("package bounds not isolated")
	}
}
