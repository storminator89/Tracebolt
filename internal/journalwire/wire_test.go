package journalwire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"localrmm/internal/lantrust"
	"localrmm/internal/systemwire"
	"math/big"
	"net/http"
	"strings"
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
func TestJournalSignaturePurposePathAndFraming(t *testing.T) {
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
		{"oversize metadata", func(r *http.Request) { r.ContentLength = 4097 }},
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
	// header names and the HTTP path are translated to journal's proof fields.
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
func TestJournalCanonicalObjectsAndBoundedSnapshots(t *testing.T) {
	id := journalrequest.Identity{ID: "journal_" + strings.Repeat("1", 32), Sequence: 1, QueryDigest: "sha256:" + strings.Repeat("a", 64)}
	claim := journalrequest.Claim{Identity: id, PolicyDigest: "sha256:" + strings.Repeat("b", 64)}
	raw, e := EncodeClaim(claim)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := DecodeClaim(raw); e != nil || got != claim {
		t.Fatal("claim roundtrip")
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"identity":`), []byte(`"Identity":`), 1), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":"1","sequence":"1"`), 1), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":null`), 1), append(bytes.Clone(raw), []byte("{}")...)} {
		if _, e := DecodeClaim(bad); e == nil {
			t.Fatal("ambiguous claim accepted")
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	q := journalview.Query{Unit: "invented.service", Start: now.Add(-time.Minute), End: now, MaxPriority: 7}
	snap := journalview.Snapshot{SchemaVersion: journalview.SchemaVersion, Scope: journalview.Scope, Query: q, ObservedAt: now, Coverage: journalview.Complete, Reason: journalview.ReasonNone, Rows: []journalview.Row{{Timestamp: now, Unit: q.Unit, Priority: 3, Message: "invented harmless text"}}, ObservedCount: 1, CountExact: true, RedactionWarning: journalview.RedactionWarning}
	body, e := EncodeResult(Result{Claim: claim, Snapshot: snap})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeResult(body); e != nil {
		t.Fatal("valid result rejected")
	}
	snap.Rows[0].Message = strings.Repeat("x", journalview.MaxMessageBytes+1)
	if _, e = EncodeResult(Result{Claim: claim, Snapshot: snap}); e == nil {
		t.Fatal("oversize row encoded")
	}
	var altered map[string]any
	_ = json.Unmarshal(body, &altered)
	altered["command"] = "not supported"
	body, _ = json.Marshal(altered)
	if _, e = DecodeResult(body); e == nil {
		t.Fatal("unknown result hook")
	}
}
