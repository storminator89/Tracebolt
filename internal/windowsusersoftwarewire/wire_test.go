package windowsusersoftwarewire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"localrmm/internal/lantrust"
	"localrmm/internal/windowsfullsoftwarewire"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func serviceWireFixture(t *testing.T) (tls.Certificate, *lantrust.Registry) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(der)
	leafPub, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, leafPub, key)
	if e != nil {
		t.Fatal(e)
	}
	registry, e := lantrust.NewRegistry(context.Background(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), lantrust.NewMemoryStore())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = registry.Approve(context.Background(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), "invented fixture"); e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, registry
}
func TestUserSoftwareHTTPProofIsPurposeAndBodyBound(t *testing.T) {
	pair, registry := serviceWireFixture(t)
	verifier, e := New(Config{Origin: "http://fixture.invalid", Registry: registry})
	if e != nil {
		t.Fatal(e)
	}
	makeRequest := func() *http.Request {
		r, e := NewSignedRequest(context.Background(), "http://fixture.invalid", pair, "scope", 1, time.Now().UTC(), []byte(`{"invented":"scope"}`))
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	verified, e := verifier.Verify(makeRequest())
	if e != nil || verified.Sequence != 1 {
		t.Fatal(e)
	}
	for _, mutate := range []func(*http.Request){func(r *http.Request) { r.URL.Path = PathPrefix + "chunk" }, func(r *http.Request) { r.URL.Path = "/v1/windows/agent/telemetry" }, func(r *http.Request) { r.Header.Set(SequenceHeader, "2") }, func(r *http.Request) { r.Header.Add(SignatureHeader, r.Header.Get(SignatureHeader)) }, func(r *http.Request) { r.Header.Set("Origin", "http://fixture.invalid") }, func(r *http.Request) { r.TLS = &tls.ConnectionState{} }, func(r *http.Request) { r.ContentLength++ }, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, func(r *http.Request) { r.URL.RawQuery = "private=label" }} {
		r := makeRequest()
		mutate(r)
		if _, e := verifier.Verify(r); e == nil {
			t.Fatal("invalid purpose/framing accepted")
		}
	}
	if _, e := NewSignedRequest(context.Background(), "http://fixture.invalid", pair, "begin", 1, time.Now().UTC(), []byte(`{}`)); e == nil {
		t.Fatal("old overview purpose admitted")
	}
	if _, e := NewSignedRequest(context.Background(), "http://fixture.invalid", pair, "scope", 1, time.Now().UTC(), bytes.Repeat([]byte("x"), MaxBodyBytes+1)); e == nil {
		t.Fatal("oversized body admitted")
	}
	if !strings.Contains(domain, "selected-account Windows software") || strings.Contains(domain, "overview") {
		t.Fatal("signature domain copied unchanged")
	}
}

func TestMachineSoftwareSignatureCannotAuthorizeSelectedAccount(t *testing.T) {
	pair, registry := serviceWireFixture(t)
	verifier, e := New(Config{Origin: "http://fixture.invalid", Registry: registry})
	if e != nil {
		t.Fatal(e)
	}
	req, e := windowsfullsoftwarewire.NewSignedRequest(context.Background(), "http://fixture.invalid", pair, "scope", 1, time.Now().UTC(), []byte(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	req.URL.Path = PathPrefix + "scope"
	for old, next := range map[string]string{windowsfullsoftwarewire.CertificateHeader: CertificateHeader, windowsfullsoftwarewire.SequenceHeader: SequenceHeader, windowsfullsoftwarewire.SignedAtHeader: SignedAtHeader, windowsfullsoftwarewire.SignatureHeader: SignatureHeader} {
		value := req.Header.Get(old)
		req.Header.Del(old)
		req.Header.Set(next, value)
	}
	if _, e = verifier.Verify(req); e == nil {
		t.Fatal("machine software signature accepted by selected-account purpose")
	}
}
