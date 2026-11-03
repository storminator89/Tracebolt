package managerreadiness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

func lifetimeCertificate(t *testing.T, from, until time.Time) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "private-fixture-subject"}, DNSNames: []string{"private-fixture.invalid"}, NotBefore: from, NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCertificateLifetimeExactBoundaries(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	until := now.Add(60 * 24 * time.Hour)
	der := lifetimeCertificate(t, now, until)
	for _, test := range []struct {
		at    time.Time
		state string
	}{
		{now.Add(-time.Nanosecond), "not_yet_valid"},
		{now, "valid"},
		{until.Add(-30*24*time.Hour - time.Nanosecond), "valid"},
		{until.Add(-30 * 24 * time.Hour), "within_30_days"},
		{until.Add(-7*24*time.Hour - time.Nanosecond), "within_30_days"},
		{until.Add(-7 * 24 * time.Hour), "within_7_days"},
		{until.Add(-time.Nanosecond), "within_7_days"},
		{until, "expired"},
		{until.Add(time.Second), "expired"},
	} {
		v := CertificateLifetimes(test.at, true, [][]byte{der}, false, nil, nil)[0]
		if v.State != test.state || v.ValidFrom == nil || !v.ValidFrom.Equal(now) || v.ValidUntil == nil || !v.ValidUntil.Equal(until) {
			t.Fatalf("at %v: %+v", test.at, v)
		}
	}
}

func TestCertificateLifetimeChainIntersectionAndIndependentRoles(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	leaf := lifetimeCertificate(t, now.Add(-24*time.Hour), now.Add(90*24*time.Hour))
	intermediate := lifetimeCertificate(t, now.Add(-time.Hour), now.Add(2*24*time.Hour))
	root := lifetimeCertificate(t, now.Add(-time.Hour), now.Add(20*24*time.Hour))
	view := CertificateLifetimes(now, true, [][]byte{leaf, intermediate}, true, leaf, root)
	if len(view) != 3 || view[0].Role != "server_chain" || view[0].State != "within_7_days" || !view[0].ValidFrom.Equal(now.Add(-time.Hour)) || !view[0].ValidUntil.Equal(now.Add(2*24*time.Hour)) || view[1].Role != "enrollment_issuer" || view[1].State != "valid" || view[2].Role != "enrollment_root" || view[2].State != "within_30_days" {
		t.Fatal("chain or independent authority deadline lost", view)
	}
	view = CertificateLifetimes(now.Add(20*24*time.Hour), true, [][]byte{leaf}, true, leaf, root)
	if view[1].State != "valid" || view[2].State != "expired" {
		t.Fatal("issuer lifetime concealed expired root", view)
	}
	raw, err := json.Marshal(view)
	if err != nil || bytes.Contains(raw, []byte("private-fixture")) || bytes.Contains(raw, leaf) || bytes.Contains(raw, root) || bytes.Contains(raw, []byte("fingerprint")) {
		t.Fatal("certificate identity or bytes exposed")
	}
}

func TestCertificateLifetimeUnavailableIsNeverDisabledOrPartial(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	valid := lifetimeCertificate(t, now.Add(-time.Hour), now.Add(time.Hour))
	future := lifetimeCertificate(t, now.Add(2*time.Hour), now.Add(3*time.Hour))
	for _, chain := range [][][]byte{nil, {}, {nil}, {[]byte("private-bad-der")}, {valid, []byte("bad")}, {valid, future}, {make([]byte, 65537)}, {valid, make([]byte, 65536)}, make([][]byte, 65)} {
		v := CertificateLifetimes(now, true, chain, true, nil, nil)
		for _, item := range v {
			if item.State != "unavailable" || item.ValidFrom != nil || item.ValidUntil != nil {
				t.Fatal("invalid material supplied successful or partial dates", item)
			}
		}
	}
	for _, at := range []time.Time{{}, time.Date(1969, 12, 31, 0, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		for _, item := range CertificateLifetimes(at, true, [][]byte{valid}, true, valid, valid) {
			if item.State != "unavailable" || item.ValidFrom != nil || item.ValidUntil != nil {
				t.Fatal("invalid clock produced lifetime confidence", item)
			}
		}
	}
	for _, item := range CertificateLifetimes(now, false, [][]byte{valid}, false, valid, valid) {
		if item.State != "not_configured" || item.ValidFrom != nil || item.ValidUntil != nil {
			t.Fatal("disabled role consumed stale or unrelated material", item)
		}
	}
}

func TestCertificateLifetimeDoesNotPromoteReadinessOrRefreshDates(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	der := lifetimeCertificate(t, now.Add(-time.Hour), now.Add(time.Hour))
	view := NewView(now, []Component{{Component: "server_certificate", State: "failed"}})
	view.CertificateLifetimes = CertificateLifetimes(now, true, [][]byte{der}, false, nil, nil)
	if view.Status != "unavailable" || view.CertificateLifetimes[0].State != "within_7_days" {
		t.Fatal("date report changed independent source validation", view)
	}
	first := *view.CertificateLifetimes[0].ValidUntil
	der[0] ^= 1
	if !view.CertificateLifetimes[0].ValidUntil.Equal(first) {
		t.Fatal("returned metadata retained mutable source material")
	}
	if fallback := NewView(now, nil); fallback.Status != "unavailable" || len(fallback.CertificateLifetimes) != 0 {
		t.Fatal("missing runtime invented configured certificate evidence")
	}
}
